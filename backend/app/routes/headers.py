"""Web Security Header Analyzer REST API routes."""

import time
from collections import defaultdict
from typing import Dict, List
from fastapi import APIRouter, Depends, HTTPException, Request, status
import httpx
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.user import User
from app.models.web_security import WebSecurityResult
from app.schemas.web_security import (
    HeaderAnalysisRequest,
    HeaderAnalysisResponse,
)
from app.security.dependencies import require_analyst, require_viewer
from app.security.ssrf import (
    InvalidTargetURLError,
    SSRFProtectionError,
    validate_target_url,
)
from app.services.header_analyzer import HeaderAnalyzerService
from app.utils.audit_helper import get_client_ip, get_user_agent, record_audit_log

router = APIRouter(prefix="/headers", tags=["Web Security Headers"])

# In-memory sliding window rate limiter: max 15 analyses per 60 seconds per user
RATE_LIMIT_MAX_REQUESTS = 15
RATE_LIMIT_WINDOW_SECONDS = 60
_user_request_timestamps: Dict[str, List[float]] = defaultdict(list)


def check_rate_limit(user_id: str) -> None:
    """Enforce rate limits per user to prevent abuse of the backend as an open proxy."""
    now = time.time()
    cutoff = now - RATE_LIMIT_WINDOW_SECONDS

    # Filter timestamps within active window
    active_times = [ts for ts in _user_request_timestamps[user_id] if ts > cutoff]
    _user_request_timestamps[user_id] = active_times

    if len(active_times) >= RATE_LIMIT_MAX_REQUESTS:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=(
                f"Rate limit exceeded: Maximum {RATE_LIMIT_MAX_REQUESTS} "
                "analyses per minute allowed."
            ),
        )

    _user_request_timestamps[user_id].append(now)


@router.post(
    "/analyze",
    response_model=HeaderAnalysisResponse,
    status_code=status.HTTP_200_OK,
    summary="Perform authorized web security header assessment",
)
def analyze_security_headers(
    payload: HeaderAnalysisRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
) -> HeaderAnalysisResponse:
    """Analyze HTTP response security headers on an authorized web asset.

    Enforces mandatory SSRF protection and TOCTOU defense.
    Integrates directly with Findings Engine to record hardening gaps.

    Access: Analyst, Admin.
    """
    client_ip = get_client_ip(request)
    user_agent = get_user_agent(request)

    # 1. Mandatory Authorization Scope Confirmation
    if not payload.authorization_confirmed:
        record_audit_log(
            db=db,
            action="HEADER_ANALYSIS_REJECTED",
            resource_type="WEB_SECURITY",
            status_code=status.HTTP_400_BAD_REQUEST,
            ip_address=client_ip,
            user_id=current_user.id,
            user_agent=user_agent,
            details={
                "target_url": payload.url,
                "reason": "Missing explicit authorization acknowledgement",
            },
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Explicit authorization confirmation is required to analyze targets.",
        )

    # 2. Rate Limiting Check
    try:
        check_rate_limit(current_user.id)
    except HTTPException as exc:
        record_audit_log(
            db=db,
            action="HEADER_ANALYSIS_REJECTED",
            resource_type="WEB_SECURITY",
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            ip_address=client_ip,
            user_id=current_user.id,
            user_agent=user_agent,
            details={"target_url": payload.url, "reason": "Rate limit exceeded"},
        )
        raise exc

    # 3. Pre-flight SSRF and Target Syntax Validation
    try:
        validate_target_url(payload.url)
    except (InvalidTargetURLError, SSRFProtectionError) as sec_err:
        record_audit_log(
            db=db,
            action="HEADER_ANALYSIS_REJECTED",
            resource_type="WEB_SECURITY",
            status_code=status.HTTP_400_BAD_REQUEST,
            ip_address=client_ip,
            user_id=current_user.id,
            user_agent=user_agent,
            details={"target_url": payload.url, "reason": str(sec_err)},
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Target rejected by defensive security policy: {sec_err}",
        )

    # 4. Audit Log: Analysis Started
    record_audit_log(
        db=db,
        action="HEADER_ANALYSIS_STARTED",
        resource_type="WEB_SECURITY",
        status_code=status.HTTP_200_OK,
        ip_address=client_ip,
        user_id=current_user.id,
        user_agent=user_agent,
        details={"target_url": payload.url},
    )

    # 5. Execute Analysis & Finding Generation
    try:
        result = HeaderAnalyzerService.analyze_target(
            db=db,
            target_url=payload.url,
            current_user=current_user,
            request=request,
        )
    except SSRFProtectionError as ssrf_err:
        record_audit_log(
            db=db,
            action="HEADER_ANALYSIS_REJECTED",
            resource_type="WEB_SECURITY",
            status_code=status.HTTP_400_BAD_REQUEST,
            ip_address=client_ip,
            user_id=current_user.id,
            user_agent=user_agent,
            details={"target_url": payload.url, "reason": str(ssrf_err)},
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Target rejected by SSRF protection: {ssrf_err}",
        )
    except httpx.TimeoutException:
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail="Connection to target timed out. Ensure target web service is reachable.",
        )
    except (httpx.ConnectError, httpx.RequestError) as req_err:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Failed to connect to target web service: {req_err}",
        )

    # 6. Audit Log: Analysis Completed
    record_audit_log(
        db=db,
        action="HEADER_ANALYSIS_COMPLETED",
        resource_type="WEB_SECURITY",
        resource_id=result.id,
        status_code=status.HTTP_200_OK,
        ip_address=client_ip,
        user_id=current_user.id,
        user_agent=user_agent,
        details={
            "target_url": result.target_url,
            "final_url": result.final_url,
            "grade": result.grade,
            "score": result.score,
            "status_code": result.status_code,
            "findings_count": result.created_findings_count,
        },
    )

    return result


@router.get(
    "/history",
    response_model=List[dict],
    status_code=status.HTTP_200_OK,
    summary="Get recent web security header assessment history",
)
def get_analysis_history(
    db: Session = Depends(get_db),
    _current_user: User = Depends(require_viewer),
) -> List[dict]:
    """Retrieve history of recent security header assessments.

    Access: Viewer, Analyst, Admin.
    """
    records = (
        db.query(WebSecurityResult).order_by(WebSecurityResult.created_at.desc()).limit(20).all()
    )

    return [
        {
            "id": r.id,
            "target_url": r.target_url,
            "grade": r.grade,
            "score": r.score,
            "missing_count": len(r.headers_missing) if isinstance(r.headers_missing, list) else 0,
            "created_at": r.created_at.isoformat(),
        }
        for r in records
    ]

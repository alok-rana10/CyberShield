"""Authorized Network Scanner REST API routes."""

import math
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.user import User
from app.schemas.scan import (
    ScanCreateRequest,
    ScanListResponse,
    ScanPortResult,
    ScanResponse,
    ScanScopeResponse,
    ScanSummaryResponse,
)
from app.security.dependencies import require_analyst, require_viewer
from app.security.scan_target import (
    InvalidPortConfigurationError,
    InvalidScanTargetError,
    UnauthorizedScanTargetError,
)
from app.services.scanner_service import (
    NetworkScannerService,
    ScanExecutionError,
    ScanRateLimitError,
)

router = APIRouter(prefix="/scans", tags=["Authorized Network Scanner"])


@router.post(
    "",
    response_model=ScanResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Execute an authorized TCP network scan",
)
def run_network_scan(
    payload: ScanCreateRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
) -> ScanResponse:
    """Execute a defensive, non-destructive TCP connect scan against an authorized target.

    Enforces:
    - Mandatory operator authorization confirmation.
    - Server-side target validation against SCAN_ALLOWED_TARGETS policy.
    - Server-side port bounding and limit enforcement.
    - Sliding window rate limiting per operator.
    - Automatic correlation with Security Findings Engine for confirmed insecure protocols.
    - Tamper-evident audit logging.

    Access: Analyst, Admin.
    """
    try:
        return NetworkScannerService.execute_scan(
            db=db,
            payload=payload,
            current_user=current_user,
            request=request,
        )
    except UnauthorizedScanTargetError as exc:
        raise HTTPException(
            status_code=(
                status.HTTP_403_FORBIDDEN
                if "explicit authorization" not in str(exc).lower()
                else status.HTTP_400_BAD_REQUEST
            ),
            detail=str(exc),
        )
    except InvalidScanTargetError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )
    except InvalidPortConfigurationError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )
    except ScanRateLimitError as exc:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=str(exc),
        )
    except ScanExecutionError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        )


@router.get(
    "",
    response_model=ScanListResponse,
    status_code=status.HTTP_200_OK,
    summary="List paginated historical network scans",
)
def list_network_scans(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_viewer),
    page: int = Query(1, ge=1, description="Page number"),
    size: int = Query(20, ge=1, le=100, description="Items per page"),
) -> ScanListResponse:
    """Retrieve historical scan records.

    Access: Viewer, Analyst, Admin.
    """
    records, total = NetworkScannerService.list_scans(
        db=db,
        current_user=current_user,
        page=page,
        size=size,
    )

    items = []
    for r in records:
        port_results = [
            ScanPortResult(
                port=p.get("port", 0),
                status=p.get("status", "closed"),
                service=p.get("service"),
            )
            for p in (r.port_details or [])
        ]
        items.append(
            ScanResponse(
                id=r.id,
                user_id=r.user_id,
                target_host=r.target_host,
                scan_type=r.scan_type,
                status=r.status,
                open_ports=r.open_ports or [],
                scanned_ports=r.scanned_ports or [],
                port_details=port_results,
                total_ports_scanned=r.total_ports_scanned or 0,
                open_ports_count=r.open_ports_count or 0,
                scan_duration_ms=r.scan_duration_ms,
                authorization_confirmed=r.authorization_confirmed,
                created_at=r.created_at,
                created_findings_count=0,
                created_finding_ids=[],
            )
        )

    return ScanListResponse(
        items=items,
        total=total,
        page=page,
        size=size,
        pages=math.ceil(total / size) if size > 0 else 0,
    )


@router.get(
    "/summary",
    response_model=ScanSummaryResponse,
    status_code=status.HTTP_200_OK,
    summary="Get aggregated network scanner summary KPIs",
)
def get_network_scan_summary(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_viewer),
) -> ScanSummaryResponse:
    """Retrieve aggregated metrics for network scanner operations.

    Access: Viewer, Analyst, Admin.
    """
    return NetworkScannerService.get_scan_summary(
        db=db,
        current_user=current_user,
    )


@router.get(
    "/scope",
    response_model=ScanScopeResponse,
    status_code=status.HTTP_200_OK,
    summary="Get enforced authorized targets and operational bounds",
)
def get_network_scan_scope(
    current_user: User = Depends(require_viewer),
) -> ScanScopeResponse:
    """Retrieve server-enforced allowed target policy and operational limitations.

    Access: Viewer, Analyst, Admin.
    """
    return NetworkScannerService.get_scan_scope()


@router.get(
    "/{scan_id}",
    response_model=ScanResponse,
    status_code=status.HTTP_200_OK,
    summary="Get details of a specific scan by ID",
)
def get_network_scan_by_id(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_viewer),
) -> ScanResponse:
    """Retrieve full port breakdown and results of a specific scan.

    Access: Viewer, Analyst, Admin.
    """
    record = NetworkScannerService.get_scan_by_id(
        db=db,
        scan_id=scan_id,
        current_user=current_user,
    )
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan record with ID '{scan_id}' not found.",
        )

    port_results = [
        ScanPortResult(
            port=p.get("port", 0),
            status=p.get("status", "closed"),
            service=p.get("service"),
        )
        for p in (record.port_details or [])
    ]

    return ScanResponse(
        id=record.id,
        user_id=record.user_id,
        target_host=record.target_host,
        scan_type=record.scan_type,
        status=record.status,
        open_ports=record.open_ports or [],
        scanned_ports=record.scanned_ports or [],
        port_details=port_results,
        total_ports_scanned=record.total_ports_scanned or 0,
        open_ports_count=record.open_ports_count or 0,
        scan_duration_ms=record.scan_duration_ms,
        authorization_confirmed=record.authorization_confirmed,
        created_at=record.created_at,
        created_findings_count=0,
        created_finding_ids=[],
    )

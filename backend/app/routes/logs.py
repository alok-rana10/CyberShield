"""Defensive Log Analyzer REST API routes."""

import math
from typing import Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import get_db
from app.models.user import User
from app.schemas.log_event import (
    LogAnalysisRequest,
    LogAnalysisResponse,
    LogEventListResponse,
    LogEventResponse,
    LogStatusSummaryResponse,
)
from app.security.dependencies import require_analyst, require_viewer
from app.security.log_path import (
    InvalidLogPathStructureError,
    LogFileTooLargeError,
    UnauthorizedLogPathError,
)
from app.services.log_service import LogService, LogServiceError

router = APIRouter(prefix="/logs", tags=["Log Analyzer"])


@router.post(
    "/analyze",
    response_model=LogAnalysisResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyze an authorized log file",
)
def analyze_log_file(
    payload: LogAnalysisRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
) -> LogAnalysisResponse:
    """Analyze authorized log file, normalize security events, and correlate findings.

    Enforces:
    - Path containment within configured authorized log roots (LOG_ALLOWED_ROOTS).
    - Defends against path traversal, symlink escape, and prefix confusion.
    - Rejects directories (regular files only).
    - Correlates brute force and reconnaissance patterns into Security Findings.
    - Access: Analyst, Admin.
    """
    try:
        result = LogService.analyze_log_file(
            db=db,
            raw_path=payload.path,
            current_user=current_user,
            request=request,
        )
        return LogAnalysisResponse(
            source_file=result["source_file"],
            file_name=result["file_name"],
            lines_read=result["lines_read"],
            events_parsed_count=result["events_parsed_count"],
            created_findings_count=result["created_findings_count"],
            created_finding_ids=result["created_finding_ids"],
            events=[LogEventResponse.model_validate(e) for e in result["events"]],
        )
    except UnauthorizedLogPathError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(exc),
        )
    except InvalidLogPathStructureError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )
    except FileNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        )
    except LogFileTooLargeError as exc:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=str(exc),
        )
    except LogServiceError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )


@router.get(
    "/events",
    response_model=LogEventListResponse,
    status_code=status.HTTP_200_OK,
    summary="List paginated ingested log events",
)
def list_log_events(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_viewer),
    severity: Optional[str] = Query(None),
    category: Optional[str] = Query(None, alias="category"),
    source_type: Optional[str] = Query(None),
    source_file: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
) -> LogEventListResponse:
    """Retrieve normalized security log events with filtering.

    Access: Viewer, Analyst, Admin.
    """
    events, total = LogService.list_events(
        db=db,
        current_user=current_user,
        severity=severity,
        event_category=category,
        source_type=source_type,
        source_file=source_file,
        search=search,
        page=page,
        size=size,
    )
    pages = math.ceil(total / size) if total > 0 else 1

    return LogEventListResponse(
        items=[LogEventResponse.model_validate(e) for e in events],
        total=total,
        page=page,
        size=size,
        pages=pages,
    )


@router.get(
    "/events/{event_id}",
    response_model=LogEventResponse,
    status_code=status.HTTP_200_OK,
    summary="Get single log event by ID",
)
def get_log_event(
    event_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_viewer),
) -> LogEventResponse:
    """Retrieve details of a single ingested log event.

    Access: Viewer, Analyst, Admin.
    """
    event = LogService.get_event_by_id(db=db, event_id=event_id, current_user=current_user)
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Log event with ID '{event_id}' not found.",
        )
    return LogEventResponse.model_validate(event)


@router.get(
    "/summary",
    response_model=LogStatusSummaryResponse,
    status_code=status.HTTP_200_OK,
    summary="Get log analyzer status and event metrics",
)
def get_log_summary(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_viewer),
) -> LogStatusSummaryResponse:
    """Retrieve aggregated log metrics, severity breakdowns, and authorized roots.

    Access: Viewer, Analyst, Admin.
    """
    summary = LogService.get_status_summary(db=db, current_user=current_user)
    return LogStatusSummaryResponse(
        total_events=summary["total_events"],
        severity_counts=summary["severity_counts"],
        category_counts=summary["category_counts"],
        allowed_roots=summary["allowed_roots"],
        last_analyzed_at=summary["last_analyzed_at"],
    )


@router.get(
    "/roots",
    response_model=Dict[str, List[str]],
    status_code=status.HTTP_200_OK,
    summary="Get configured authorized log roots",
)
def get_log_roots(
    _current_user: User = Depends(require_viewer),
) -> Dict[str, List[str]]:
    """Return the list of directories authorized for log analysis.

    Access: Viewer, Analyst, Admin.
    """
    settings = get_settings()
    return {"allowed_roots": settings.log_allowed_roots_list}

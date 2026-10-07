"""File Integrity Monitor (FIM) REST API routes."""

import math
from typing import Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import get_db
from app.models.user import User
from app.schemas.fim import (
    FIMBaselineRequest,
    FIMBaselineResponse,
    FIMCheckRequest,
    FIMCheckResponse,
    FIMRecordListResponse,
    FIMRecordResponse,
    FIMStatusSummaryResponse,
)
from app.security.dependencies import require_analyst, require_viewer
from app.security.fim_path import (
    InvalidPathStructureError,
    UnauthorizedPathError,
)
from app.services.fim_service import (
    FIMProcessingError,
    FIMService,
    FileLimitExceededError,
    FileTooLargeError,
)

router = APIRouter(prefix="/fim", tags=["File Integrity Monitor"])


@router.post(
    "/baselines",
    response_model=FIMBaselineResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create cryptographic baseline for an authorized path",
)
def create_fim_baseline(
    payload: FIMBaselineRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
) -> FIMBaselineResponse:
    """Create or update SHA-256 cryptographic baseline for an authorized directory or file.

    Enforces authorized monitoring root restrictions and defends against symlink escapes.
    Access: Analyst, Admin.
    """
    try:
        return FIMService.create_baseline(
            db=db,
            raw_path=payload.path,
            current_user=current_user,
            request=request,
        )
    except UnauthorizedPathError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(exc),
        )
    except (InvalidPathStructureError, FileLimitExceededError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )
    except FileNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        )
    except FileTooLargeError as exc:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=str(exc),
        )
    except FIMProcessingError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )


@router.post(
    "/check",
    response_model=FIMCheckResponse,
    status_code=status.HTTP_200_OK,
    summary="Execute integrity check against existing baseline",
)
def check_fim_integrity(
    payload: FIMCheckRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
) -> FIMCheckResponse:
    """Compare current files against baseline to detect modified, added, or deleted files.

    Automatically integrates with Findings Engine to record security findings.
    Access: Analyst, Admin.
    """
    try:
        return FIMService.check_integrity(
            db=db,
            raw_path=payload.path,
            current_user=current_user,
            request=request,
        )
    except UnauthorizedPathError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(exc),
        )
    except (InvalidPathStructureError, FileLimitExceededError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )
    except FileNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        )
    except FileTooLargeError as exc:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=str(exc),
        )
    except FIMProcessingError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )


@router.get(
    "/status",
    response_model=FIMStatusSummaryResponse,
    status_code=status.HTTP_200_OK,
    summary="Get FIM status summary and monitored counts",
)
def get_fim_status(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_viewer),
) -> FIMStatusSummaryResponse:
    """Retrieve aggregated integrity statistics and allowed monitoring roots.

    Access: Viewer, Analyst, Admin.
    """
    return FIMService.get_status_summary(db=db, current_user=current_user)


@router.get(
    "/records",
    response_model=FIMRecordListResponse,
    status_code=status.HTTP_200_OK,
    summary="List paginated FIM records",
)
def list_fim_records(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_viewer),
    status_filter: Optional[str] = Query(None, alias="status"),
    path: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
) -> FIMRecordListResponse:
    """List monitored files with their SHA-256 baseline and current verification status.

    Access: Viewer, Analyst, Admin.
    """
    records, total = FIMService.list_records(
        db=db,
        current_user=current_user,
        status_filter=status_filter,
        path_search=path,
        page=page,
        size=size,
    )
    pages = math.ceil(total / size) if total > 0 else 1

    return FIMRecordListResponse(
        items=[FIMRecordResponse.model_validate(r) for r in records],
        total=total,
        page=page,
        size=size,
        pages=pages,
    )


@router.get(
    "/roots",
    response_model=Dict[str, List[str]],
    status_code=status.HTTP_200_OK,
    summary="Get configured authorized monitoring roots",
)
def get_fim_roots(
    _current_user: User = Depends(require_viewer),
) -> Dict[str, List[str]]:
    """Return the list of directories authorized for integrity monitoring.

    Access: Viewer, Analyst, Admin.
    """
    settings = get_settings()
    return {"allowed_roots": settings.fim_allowed_roots_list}

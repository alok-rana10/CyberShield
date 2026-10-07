"""Security Findings REST API routes."""

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.user import User
from app.schemas.finding import (
    FindingCreate,
    FindingListResponse,
    FindingResponse,
    FindingStatusUpdate,
    FindingUpdate,
)
from app.security.dependencies import require_admin, require_analyst, require_viewer
from app.services.finding_service import FindingService

router = APIRouter(prefix="/findings", tags=["Security Findings"])


@router.get(
    "",
    response_model=FindingListResponse,
    status_code=status.HTTP_200_OK,
    summary="List security findings with filtering and pagination",
)
def list_findings(
    page: int = Query(default=1, ge=1, description="Page number"),
    size: int = Query(default=20, ge=1, le=100, description="Items per page"),
    severity: Optional[str] = Query(default=None, description="Filter by severity"),
    status_filter: Optional[str] = Query(
        default=None, alias="status", description="Filter by status"
    ),
    category: Optional[str] = Query(default=None, description="Filter by category"),
    source_module: Optional[str] = Query(default=None, description="Filter by source module"),
    search: Optional[str] = Query(
        default=None, description="Keyword search across title/asset/description"
    ),
    db: Session = Depends(get_db),
    _current_user: User = Depends(require_viewer),
) -> FindingListResponse:
    """List paginated findings matching defensive filter criteria.

    Access: Viewer, Analyst, Admin.
    """
    return FindingService.list_findings(
        db=db,
        page=page,
        size=size,
        severity=severity,
        status=status_filter,
        category=category,
        source_module=source_module,
        search=search,
    )


@router.get(
    "/{finding_id}",
    response_model=FindingResponse,
    status_code=status.HTTP_200_OK,
    summary="Retrieve single security finding details",
)
def get_finding(
    finding_id: str,
    db: Session = Depends(get_db),
    _current_user: User = Depends(require_viewer),
) -> FindingResponse:
    """Fetch details and remediation guidance for a specific finding.

    Access: Viewer, Analyst, Admin.
    """
    finding = FindingService.get_finding_by_id(db=db, finding_id=finding_id)
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Security finding not found.",
        )
    return FindingResponse.model_validate(finding)


@router.post(
    "",
    response_model=FindingResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new security finding",
)
def create_finding(
    payload: FindingCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
) -> FindingResponse:
    """Create a new security finding with remediation steps and audit tracking.

    Access: Analyst, Admin.
    """
    db_finding = FindingService.create_finding(
        db=db,
        finding_in=payload,
        current_user=current_user,
        request=request,
    )
    return FindingResponse.model_validate(db_finding)


@router.patch(
    "/{finding_id}/status",
    response_model=FindingResponse,
    status_code=status.HTTP_200_OK,
    summary="Transition finding lifecycle status",
)
def update_finding_status(
    finding_id: str,
    payload: FindingStatusUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
) -> FindingResponse:
    """Update lifecycle status (open, resolved, accepted) with audit log.

    Access: Analyst, Admin.
    """
    finding = FindingService.get_finding_by_id(db=db, finding_id=finding_id)
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Security finding not found.",
        )

    updated = FindingService.update_status(
        db=db,
        finding=finding,
        status_in=payload,
        current_user=current_user,
        request=request,
    )
    return FindingResponse.model_validate(updated)


@router.patch(
    "/{finding_id}",
    response_model=FindingResponse,
    status_code=status.HTTP_200_OK,
    summary="Update finding details",
)
def update_finding(
    finding_id: str,
    payload: FindingUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
) -> FindingResponse:
    """Update editable finding fields with audit tracking.

    Access: Analyst, Admin.
    """
    finding = FindingService.get_finding_by_id(db=db, finding_id=finding_id)
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Security finding not found.",
        )

    updated = FindingService.update_finding(
        db=db,
        finding=finding,
        update_in=payload,
        current_user=current_user,
        request=request,
    )
    return FindingResponse.model_validate(updated)


@router.delete(
    "/{finding_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Permanently delete a security finding",
)
def delete_finding(
    finding_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> None:
    """Permanently delete a finding.

    Access: Admin only.
    """
    finding = FindingService.get_finding_by_id(db=db, finding_id=finding_id)
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Security finding not found.",
        )

    FindingService.delete_finding(
        db=db,
        finding=finding,
        current_user=current_user,
        request=request,
    )

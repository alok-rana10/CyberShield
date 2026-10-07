"""Security Dashboard REST API routes."""

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.user import User
from app.schemas.dashboard import DashboardSummaryResponse
from app.security.dependencies import require_viewer
from app.services.finding_service import FindingService

router = APIRouter(prefix="/dashboard", tags=["Security Dashboard"])


@router.get(
    "/summary",
    response_model=DashboardSummaryResponse,
    status_code=status.HTTP_200_OK,
    summary="Get aggregated security dashboard metrics and recent findings",
)
def get_dashboard_summary(
    db: Session = Depends(get_db),
    _current_user: User = Depends(require_viewer),
) -> DashboardSummaryResponse:
    """Retrieve defensive cybersecurity posture metrics, severity breakdown, and recent findings.

    Access: Viewer, Analyst, Admin.
    """
    return FindingService.get_dashboard_summary(db=db)

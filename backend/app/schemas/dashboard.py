"""Pydantic schemas for Security Dashboard metrics."""

from typing import Dict, List
from pydantic import BaseModel, Field
from app.schemas.finding import FindingResponse


class SeverityCounts(BaseModel):
    critical: int = Field(default=0, description="Number of critical severity findings")
    high: int = Field(default=0, description="Number of high severity findings")
    medium: int = Field(default=0, description="Number of medium severity findings")
    low: int = Field(default=0, description="Number of low severity findings")
    informational: int = Field(default=0, description="Number of informational findings")


class StatusCounts(BaseModel):
    open: int = Field(default=0, description="Number of open findings")
    resolved: int = Field(default=0, description="Number of resolved findings")
    accepted: int = Field(default=0, description="Number of accepted risk findings")


class DashboardSummaryResponse(BaseModel):
    total_findings: int = Field(..., description="Total count of security findings")
    severity_counts: SeverityCounts
    status_counts: StatusCounts
    recent_findings: List[FindingResponse]
    by_category: Dict[str, int] = Field(
        default_factory=dict, description="Finding counts grouped by category"
    )
    by_source: Dict[str, int] = Field(
        default_factory=dict, description="Finding counts grouped by source module"
    )
    posture_score: int = Field(
        ...,
        ge=0,
        le=100,
        description="Overall defensive security posture index (0-100, higher is better)",
    )

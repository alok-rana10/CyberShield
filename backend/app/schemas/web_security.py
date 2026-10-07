"""Pydantic schemas for Web Security Header Analyzer."""

from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field


class HeaderAnalysisRequest(BaseModel):
    """Request payload to initiate a defensive web security header analysis."""

    url: str = Field(
        ...,
        min_length=4,
        max_length=2048,
        description="Target HTTP/HTTPS URL to evaluate for defensive security headers",
        examples=["https://example.com"],
    )
    authorization_confirmed: bool = Field(
        ...,
        description="Mandatory operator acknowledgment confirming explicit testing authorization",
    )


class HeaderEvaluationDetail(BaseModel):
    """Detailed evaluation result for a single security header."""

    name: str = Field(..., description="HTTP Header name")
    status: str = Field(..., description="Evaluation outcome: present, missing, or weak")
    value: Optional[str] = Field(default=None, description="Observed header value")
    severity: str = Field(..., description="Defensive severity classification")
    description: str = Field(..., description="Purpose and impact of the header")
    recommendation: str = Field(..., description="Actionable configuration advice")


class HeaderAnalysisResponse(BaseModel):
    """Structured response detailing security headers analysis and generated findings."""

    id: str = Field(..., description="Record identifier")
    target_url: str = Field(..., description="Initial target URL tested")
    final_url: str = Field(..., description="Final URL reached after any safe redirects")
    status_code: int = Field(..., description="HTTP response status code")
    is_https: bool = Field(..., description="True if final destination utilizes TLS/HTTPS")
    redirect_count: int = Field(..., description="Number of HTTP redirects followed")
    grade: str = Field(..., description="Letter grade summary (A+, A, B, C, D, F)")
    score: int = Field(..., ge=0, le=100, description="Numerical hardening score (0-100)")
    headers: List[HeaderEvaluationDetail] = Field(
        ..., description="Evaluation of all 6 security headers"
    )
    created_findings_count: int = Field(
        ..., description="Number of defensive findings added to registry"
    )
    created_finding_ids: List[str] = Field(
        default_factory=list, description="IDs of created findings"
    )
    analyzed_at: datetime = Field(..., description="Timestamp of completed evaluation")

    model_config = ConfigDict(from_attributes=True)

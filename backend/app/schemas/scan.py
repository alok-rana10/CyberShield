"""Pydantic schemas for Authorized Network Scanner."""

from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field


class ScanPortResult(BaseModel):
    """Result for an individual port probe."""

    port: int = Field(..., ge=1, le=65535, description="Port number")
    status: str = Field(
        ...,
        description="Probe state: 'open', 'closed', or 'filtered_or_unreachable'",
    )
    service: Optional[str] = Field(None, description="Identified standard service name")


class ScanCreateRequest(BaseModel):
    """Payload to initiate an authorized network scan."""

    target: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="Target IP address or hostname to probe",
    )
    ports: Optional[List[int]] = Field(
        None,
        description="Explicit list of port numbers to check",
    )
    port_preset: Optional[str] = Field(
        "common",
        description="Predefined port profile: 'common', 'web', 'database', or 'custom'",
    )
    authorization_confirmed: bool = Field(
        False,
        description="Mandatory operator confirmation of explicit authorization",
    )


class ScanResponse(BaseModel):
    """Response schema for completed or recorded network scan."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    user_id: str
    target_host: str
    scan_type: str
    status: str
    open_ports: List[int] = Field(default_factory=list)
    scanned_ports: List[int] = Field(default_factory=list)
    port_details: List[ScanPortResult] = Field(default_factory=list)
    total_ports_scanned: int = 0
    open_ports_count: int = 0
    scan_duration_ms: Optional[int] = None
    authorization_confirmed: bool
    created_at: datetime
    created_findings_count: int = 0
    created_finding_ids: List[str] = Field(default_factory=list)


class ScanListResponse(BaseModel):
    """Paginated scan result history."""

    items: List[ScanResponse]
    total: int
    page: int
    size: int
    pages: int


class ScanSummaryResponse(BaseModel):
    """Aggregated network scanner metrics."""

    total_scans: int
    total_ports_checked: int
    total_open_ports: int
    recent_scans: List[ScanResponse] = Field(default_factory=list)


class ScanScopeResponse(BaseModel):
    """Current server-enforced network scanner configuration boundaries."""

    allowed_targets: List[str]
    max_ports_per_scan: int
    connect_timeout_seconds: float
    rate_limit_per_minute: int

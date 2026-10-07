"""Pydantic schemas for File Integrity Monitor (FIM)."""

from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class FIMStatus(str, Enum):
    """Integrity verification states for monitored files."""

    BASELINE = "baseline"
    UNCHANGED = "unchanged"
    MODIFIED = "modified"
    ADDED = "added"
    DELETED = "deleted"


class FIMBaselineRequest(BaseModel):
    """Request payload to establish an integrity baseline on a path."""

    path: str = Field(
        ...,
        min_length=1,
        max_length=1024,
        description="Authorized directory or file path to establish baseline for.",
    )


class FIMCheckRequest(BaseModel):
    """Request payload to execute an integrity check against existing baseline."""

    path: str = Field(
        ...,
        min_length=1,
        max_length=1024,
        description="Authorized path to verify against existing cryptographic baseline.",
    )


class FIMRecordResponse(BaseModel):
    """Detailed file integrity record response."""

    id: str
    user_id: str
    monitored_path: str
    file_name: str
    baseline_hash: str
    current_hash: Optional[str] = None
    file_size_bytes: int
    status: str
    file_modified_at: Optional[datetime] = None
    last_verified_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class FIMBaselineResponse(BaseModel):
    """Summary response for completed baseline operation."""

    path: str
    files_baselined_count: int
    total_size_bytes: int
    created_at: datetime
    records: List[FIMRecordResponse]


class FIMCheckResponse(BaseModel):
    """Summary response for completed integrity check."""

    path: str
    checked_at: datetime
    total_files: int
    unchanged_count: int
    modified_count: int
    added_count: int
    deleted_count: int
    created_findings_count: int
    created_finding_ids: List[str]
    records: List[FIMRecordResponse]


class FIMStatusSummaryResponse(BaseModel):
    """Overall FIM health and posture summary."""

    total_monitored_files: int
    status_counts: Dict[str, int]
    allowed_roots: List[str]
    last_check_at: Optional[datetime] = None


class FIMRecordListResponse(BaseModel):
    """Paginated list response for FIM records."""

    items: List[FIMRecordResponse]
    total: int
    page: int
    size: int
    pages: int

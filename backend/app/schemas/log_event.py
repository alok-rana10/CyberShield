"""Pydantic schemas for Defensive Log Analyzer."""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class LogAnalysisRequest(BaseModel):
    """Request payload to initiate defensive log analysis on an authorized file."""

    path: str = Field(
        ...,
        min_length=1,
        max_length=1024,
        description="Authorized path to log file to analyze.",
    )


class LogEventResponse(BaseModel):
    """Normalized security log event response."""

    id: str
    user_id: str
    source_type: str
    source_file: Optional[str] = None
    raw_message: str
    parsed_event: Optional[Dict[str, Any]] = None
    severity: str
    source_ip: Optional[str] = None
    username: Optional[str] = None
    message_summary: Optional[str] = None
    event_category: str
    event_timestamp: Optional[datetime] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class LogAnalysisResponse(BaseModel):
    """Summary response for completed log file analysis."""

    source_file: str
    file_name: str
    lines_read: int
    events_parsed_count: int
    created_findings_count: int
    created_finding_ids: List[str]
    events: List[LogEventResponse]


class LogEventListResponse(BaseModel):
    """Paginated list response for ingested log events."""

    items: List[LogEventResponse]
    total: int
    page: int
    size: int
    pages: int


class LogStatusSummaryResponse(BaseModel):
    """Aggregated status and metrics summary for log analysis."""

    total_events: int
    severity_counts: Dict[str, int]
    category_counts: Dict[str, int]
    allowed_roots: List[str]
    last_analyzed_at: Optional[datetime] = None

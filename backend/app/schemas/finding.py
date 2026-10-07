"""Pydantic schemas for Security Findings Engine."""

from datetime import datetime
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field


class FindingSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class FindingStatus(str, Enum):
    OPEN = "open"
    RESOLVED = "resolved"
    ACCEPTED = "accepted"


class FindingBase(BaseModel):
    title: str = Field(..., min_length=3, max_length=255, description="Brief summary of finding")
    description: str = Field(..., min_length=5, description="Detailed explanation of finding")
    severity: FindingSeverity = Field(
        default=FindingSeverity.MEDIUM, description="Calculated finding severity"
    )
    category: str = Field(
        default="general", max_length=100, description="Defensive vulnerability classification"
    )
    source_module: str = Field(
        default="manual", max_length=50, description="Originating defensive engine/module"
    )
    affected_resource: Optional[str] = Field(
        default=None, max_length=255, description="Target host, file, or URL"
    )
    remediation: str = Field(..., min_length=5, description="Actionable hardening steps")
    evidence: Optional[str] = Field(
        default=None, description="Diagnostic output, snippet, or header"
    )
    cwe_id: Optional[str] = Field(
        default=None, max_length=50, description="Common Weakness Enumeration ID"
    )


class FindingCreate(FindingBase):
    status: FindingStatus = Field(
        default=FindingStatus.OPEN, description="Initial lifecycle status"
    )


class FindingUpdate(BaseModel):
    title: Optional[str] = Field(default=None, min_length=3, max_length=255)
    description: Optional[str] = Field(default=None, min_length=5)
    severity: Optional[FindingSeverity] = None
    category: Optional[str] = Field(default=None, max_length=100)
    affected_resource: Optional[str] = Field(default=None, max_length=255)
    remediation: Optional[str] = Field(default=None, min_length=5)
    evidence: Optional[str] = None
    cwe_id: Optional[str] = Field(default=None, max_length=50)


class FindingStatusUpdate(BaseModel):
    status: FindingStatus = Field(..., description="Target lifecycle state")
    resolution_notes: Optional[str] = Field(
        default=None, max_length=1000, description="Context for status change"
    )


class FindingResponse(BaseModel):
    id: str
    user_id: str
    source_module: str
    title: str
    description: str
    severity: str
    category: str
    affected_resource: Optional[str] = None
    remediation: str
    evidence: Optional[str] = None
    cwe_id: Optional[str] = None
    status: str
    created_at: datetime
    updated_at: datetime
    resolved_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class FindingListResponse(BaseModel):
    items: List[FindingResponse]
    total: int
    page: int
    size: int
    pages: int

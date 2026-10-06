"""ScanResult ORM model."""

import uuid
from datetime import datetime, timezone
from typing import Any, List
from sqlalchemy import String, Integer, Boolean, DateTime, ForeignKey, JSON, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ScanResult(Base):
    """Represents an authorized network scan job and results."""

    __tablename__ = "scan_results"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    user_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    target_host: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    scan_type: Mapped[str] = mapped_column(
        String(50),
        default="QUICK_CONNECT",
        nullable=False,
    )
    status: Mapped[str] = mapped_column(
        String(20),
        default="PENDING",
        nullable=False,
        index=True,
    )
    open_ports: Mapped[List[Any]] = mapped_column(
        JSON,
        default=list,
        nullable=False,
    )
    scan_duration_ms: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )
    authorization_confirmed: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )

    # Relationships
    user = relationship("User", back_populates="scans")

    __table_args__ = (Index("ix_scans_user_created", "user_id", "created_at"),)

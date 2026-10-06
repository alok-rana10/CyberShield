"""LogEvent ORM model."""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict
from sqlalchemy import String, Text, DateTime, ForeignKey, JSON, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class LogEvent(Base):
    """Represents a defensive event record parsed from ingested security logs."""

    __tablename__ = "log_events"

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
    source_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )
    raw_message: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    parsed_event: Mapped[Dict[str, Any] | None] = mapped_column(
        JSON,
        default=dict,
        nullable=True,
    )
    severity: Mapped[str] = mapped_column(
        String(20),
        default="INFO",
        nullable=False,
    )
    source_ip: Mapped[str | None] = mapped_column(
        String(45),
        nullable=True,
    )
    event_category: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
    )
    event_timestamp: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )

    # Relationships
    user = relationship("User", back_populates="log_events")

    __table_args__ = (Index("ix_logevents_user_sev", "user_id", "severity"),)

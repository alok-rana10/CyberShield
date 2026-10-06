"""WebSecurityResult ORM model."""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List
from sqlalchemy import String, Integer, DateTime, ForeignKey, JSON, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class WebSecurityResult(Base):
    """Represents an evaluation of HTTP security headers and cookies."""

    __tablename__ = "web_security_results"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    user_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    target_url: Mapped[str] = mapped_column(
        String(2048),
        nullable=False,
    )
    grade: Mapped[str] = mapped_column(
        String(5),
        nullable=False,
    )
    score: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )
    headers_present: Mapped[Dict[str, Any]] = mapped_column(
        JSON,
        default=dict,
        nullable=False,
    )
    headers_missing: Mapped[List[str]] = mapped_column(
        JSON,
        default=list,
        nullable=False,
    )
    cookies_analysis: Mapped[List[Any] | None] = mapped_column(
        JSON,
        default=list,
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )

    # Relationships
    user = relationship("User", back_populates="web_security_results")

    __table_args__ = (Index("ix_websec_target_url", "target_url"),)

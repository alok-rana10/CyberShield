"""User ORM model."""

import uuid
from datetime import datetime, timezone
from sqlalchemy import String, Boolean, DateTime
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


def utc_now() -> datetime:
    """Return current UTC timestamp with timezone."""
    return datetime.now(timezone.utc)


class User(Base):
    """Represents a platform operator or analyst."""

    __tablename__ = "users"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    email: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
        index=True,
    )
    hashed_password: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    full_name: Mapped[str | None] = mapped_column(
        String(150),
        nullable=True,
    )
    role: Mapped[str] = mapped_column(
        String(30),
        default="analyst",
        nullable=False,
        index=True,
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )
    last_login_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Relationships
    scans = relationship("ScanResult", back_populates="user", cascade="all, delete-orphan")
    web_security_results = relationship(
        "WebSecurityResult", back_populates="user", cascade="all, delete-orphan"
    )
    file_integrity_records = relationship(
        "FileIntegrityRecord", back_populates="user", cascade="all, delete-orphan"
    )
    log_events = relationship("LogEvent", back_populates="user", cascade="all, delete-orphan")
    findings = relationship("SecurityFinding", back_populates="user", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="user")
    reports = relationship("Report", back_populates="user", cascade="all, delete-orphan")

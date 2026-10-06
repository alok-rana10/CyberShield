"""FileIntegrityRecord ORM model."""

import uuid
from datetime import datetime, timezone
from sqlalchemy import String, BigInteger, DateTime, ForeignKey, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class FileIntegrityRecord(Base):
    """Represents a monitored file or directory with cryptographic baseline."""

    __tablename__ = "file_integrity_records"

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
    monitored_path: Mapped[str] = mapped_column(
        String(1024),
        nullable=False,
    )
    baseline_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    current_hash: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )
    file_size_bytes: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
    )
    status: Mapped[str] = mapped_column(
        String(30),
        default="VERIFIED",
        nullable=False,
        index=True,
    )
    last_verified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )

    # Relationships
    user = relationship("User", back_populates="file_integrity_records")

    __table_args__ = (Index("ix_fim_user_path", "user_id", "monitored_path"),)

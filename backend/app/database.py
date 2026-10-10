"""Database configuration and session management for CyberShield."""

from pathlib import Path
from typing import Generator
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker, Session

from app.config import get_settings

settings = get_settings()


def normalize_database_url(url: str) -> str:
    """Normalize database URL for driver and dialect compatibility.

    Rewrites legacy 'postgres://' or driver-less 'postgresql://' to
    'postgresql+psycopg2://' to guarantee compatibility with Render and SQLAlchemy 2.0.
    Normalizes local SQLite paths relative to project root.
    """
    if url.startswith("postgres://"):
        return url.replace("postgres://", "postgresql+psycopg2://", 1)
    if url.startswith("postgresql://") and "+psycopg2" not in url and "+psycopg" not in url:
        return url.replace("postgresql://", "postgresql+psycopg2://", 1)
    if url.startswith("sqlite"):
        if "///./data/" in url or "///data/" in url:
            root_dir = Path(__file__).resolve().parent.parent.parent
            data_dir = root_dir / "data"
            data_dir.mkdir(parents=True, exist_ok=True)
            db_file = data_dir / "cybershield.db"
            return f"sqlite:///{db_file.as_posix()}"
    return url


db_url = normalize_database_url(settings.DATABASE_URL)
connect_args = {}

if db_url.startswith("sqlite"):
    connect_args["check_same_thread"] = False

engine = create_engine(
    db_url,
    connect_args=connect_args,
    echo=False,
    future=True,
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
    expire_on_commit=False,
)

Base = declarative_base()


def get_db() -> Generator[Session, None, None]:
    """Dependency that provides a database session and handles cleanup."""
    db = SessionLocal()
    try:
        yield db
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()

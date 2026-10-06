"""Database configuration and schema verification tests."""

from sqlalchemy import inspect
from app.database import engine, SessionLocal, Base
import app.models  # noqa: F401

EXPECTED_TABLES = {
    "users",
    "scan_results",
    "web_security_results",
    "file_integrity_records",
    "log_events",
    "security_findings",
    "audit_logs",
    "reports",
}


def test_database_engine_connection():
    """Verify that the database engine connects successfully."""
    with engine.connect() as connection:
        assert connection is not None


def test_database_session_lifecycle():
    """Verify that a session can be acquired and closed cleanly."""
    session = SessionLocal()
    try:
        assert session.is_active
    finally:
        session.close()


def test_metadata_has_all_8_models():
    """Verify that Base.metadata tracks all 8 expected domain tables."""
    metadata_tables = set(Base.metadata.tables.keys())
    for expected in EXPECTED_TABLES:
        assert expected in metadata_tables, f"Table {expected} missing from metadata"


def test_database_schema_has_all_8_tables():
    """Verify that all 8 tables exist in the persistent database schema."""
    inspector = inspect(engine)
    db_tables = set(inspector.get_table_names())
    for expected in EXPECTED_TABLES:
        assert expected in db_tables, f"Table {expected} missing from database"

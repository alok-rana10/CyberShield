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


def test_normalize_database_url_postgresql_schemes():
    """Verify that PostgreSQL connection URIs are safely rewritten for Render and SQLAlchemy 2.0."""
    from app.database import normalize_database_url

    # Render legacy postgres://
    raw_render = (
        "postgres://cybershield_user:secret123@dpg-xxx.oregon-postgres.render.com:5432/cybershield"
    )
    normalized = normalize_database_url(raw_render)
    assert normalized.startswith("postgresql+psycopg2://")
    assert "cybershield_user:secret123@" in normalized

    # Standard postgresql:// without driver
    raw_standard = "postgresql://user:pass@localhost:5432/mydb"
    normalized_standard = normalize_database_url(raw_standard)
    assert normalized_standard.startswith("postgresql+psycopg2://")

    # Already explicit driver preserved
    explicit_psycopg2 = "postgresql+psycopg2://user:pass@localhost:5432/mydb"
    assert normalize_database_url(explicit_psycopg2) == explicit_psycopg2

    explicit_psycopg = "postgresql+psycopg://user:pass@localhost:5432/mydb"
    assert normalize_database_url(explicit_psycopg) == explicit_psycopg


def test_normalize_database_url_sqlite_relative_data_path():
    """Verify that local SQLite relative paths are resolved to absolute root data directory."""
    from app.database import normalize_database_url

    sqlite_raw = "sqlite:///./data/cybershield.db"
    normalized = normalize_database_url(sqlite_raw)
    assert normalized.startswith("sqlite:///")
    assert normalized.endswith("/data/cybershield.db")
    assert "./" not in normalized

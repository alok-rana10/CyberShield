"""Comprehensive unit tests for Security Dashboard summary metrics."""

import uuid
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import SessionLocal
from app.main import app
from app.models.user import User
from app.security.hashing import hash_password

client = TestClient(app)
settings = get_settings()

TEST_PASSWORD = "CyberShield#2026!Dashboard"


def get_viewer_token() -> str:
    """Helper to get a viewer token."""
    email = f"viewer_{uuid.uuid4().hex[:8]}@example.com"
    db: Session = SessionLocal()
    try:
        user = User(
            email=email,
            hashed_password=hash_password(TEST_PASSWORD),
            role="viewer",
            is_active=True,
            full_name="Dashboard Viewer",
        )
        db.add(user)
        db.commit()
    finally:
        db.close()

    res = client.post(
        f"{settings.API_V1_PREFIX}/auth/login",
        json={"email": email, "password": TEST_PASSWORD},
    )
    return res.json()["access_token"]


def get_analyst_token() -> str:
    """Helper to get an analyst token."""
    email = f"analyst_{uuid.uuid4().hex[:8]}@example.com"
    db: Session = SessionLocal()
    try:
        user = User(
            email=email,
            hashed_password=hash_password(TEST_PASSWORD),
            role="analyst",
            is_active=True,
            full_name="Dashboard Analyst",
        )
        db.add(user)
        db.commit()
    finally:
        db.close()

    res = client.post(
        f"{settings.API_V1_PREFIX}/auth/login",
        json={"email": email, "password": TEST_PASSWORD},
    )
    return res.json()["access_token"]


def test_dashboard_unauthenticated_rejected():
    """Ensure dashboard summary endpoint rejects unauthenticated access with 401."""
    res = client.get(f"{settings.API_V1_PREFIX}/dashboard/summary")
    assert res.status_code == 401


def test_dashboard_summary_metrics():
    """Verify aggregated dashboard metrics, severity counts, and posture score calculation."""
    analyst_token = get_analyst_token()
    headers = {"Authorization": f"Bearer {analyst_token}"}

    # Fetch baseline summary
    base_res = client.get(
        f"{settings.API_V1_PREFIX}/dashboard/summary",
        headers=headers,
    )
    assert base_res.status_code == 200
    base_data = base_res.json()
    assert "total_findings" in base_data
    assert "severity_counts" in base_data
    assert "status_counts" in base_data
    assert "recent_findings" in base_data
    assert "posture_score" in base_data
    assert 0 <= base_data["posture_score"] <= 100

    prev_total = base_data["total_findings"]
    prev_critical = base_data["severity_counts"]["critical"]
    prev_open = base_data["status_counts"]["open"]

    # Create a critical open finding
    create_res = client.post(
        f"{settings.API_V1_PREFIX}/findings",
        json={
            "title": "Dashboard Aggregation Critical Test",
            "description": "Critical issue affecting metrics test.",
            "severity": "critical",
            "category": "dashboard_test",
            "source_module": "scanner",
            "affected_resource": "db.internal.lan:5432",
            "remediation": "Apply critical security update.",
            "status": "open",
        },
        headers=headers,
    )
    assert create_res.status_code == 201

    # Fetch updated summary
    updated_res = client.get(
        f"{settings.API_V1_PREFIX}/dashboard/summary",
        headers=headers,
    )
    assert updated_res.status_code == 200
    updated_data = updated_res.json()

    assert updated_data["total_findings"] == prev_total + 1
    assert updated_data["severity_counts"]["critical"] == prev_critical + 1
    assert updated_data["status_counts"]["open"] == prev_open + 1
    assert len(updated_data["recent_findings"]) > 0
    assert updated_data["recent_findings"][0]["title"] == "Dashboard Aggregation Critical Test"
    assert "dashboard_test" in updated_data["by_category"]
    assert "scanner" in updated_data["by_source"]

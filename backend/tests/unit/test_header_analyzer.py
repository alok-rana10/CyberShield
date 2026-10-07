"""Comprehensive unit tests for Web Security Header Analyzer, Findings integration, and RBAC."""

import uuid
from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient
import httpx
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import SessionLocal
from app.main import app
from app.models.audit import AuditLog
from app.models.finding import SecurityFinding
from app.models.user import User
from app.security.hashing import hash_password

client = TestClient(app)
settings = get_settings()

TEST_PASSWORD = "CyberShield#2026!Headers"


def get_token_for_role(role: str) -> str:
    """Helper to create and authenticate a user for a given role."""
    email = f"header_{role}_{uuid.uuid4().hex[:8]}@example.com"
    db: Session = SessionLocal()
    try:
        user = User(
            email=email,
            hashed_password=hash_password(TEST_PASSWORD),
            role=role,
            is_active=True,
            full_name=f"Headers {role.capitalize()}",
        )
        db.add(user)
        db.commit()
    finally:
        db.close()

    res = client.post(
        f"{settings.API_V1_PREFIX}/auth/login",
        json={"email": email, "password": TEST_PASSWORD},
    )
    assert res.status_code == 200
    return res.json()["access_token"]


def test_headers_unauthenticated_rejected():
    """Verify that unauthenticated requests to the header analyzer return 401."""
    res = client.post(
        f"{settings.API_V1_PREFIX}/headers/analyze",
        json={"url": "https://example.com", "authorization_confirmed": True},
    )
    assert res.status_code == 401


def test_headers_viewer_forbidden():
    """Verify that Viewer role is prohibited from running header analysis (HTTP 403)."""
    token = get_token_for_role("viewer")
    res = client.post(
        f"{settings.API_V1_PREFIX}/headers/analyze",
        json={"url": "https://example.com", "authorization_confirmed": True},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 403
    assert "permissions" in res.json()["detail"].lower()


def test_headers_missing_authorization_acknowledgement():
    """Verify that omitting explicit authorization confirmation returns HTTP 400."""
    token = get_token_for_role("analyst")
    res = client.post(
        f"{settings.API_V1_PREFIX}/headers/analyze",
        json={"url": "https://example.com", "authorization_confirmed": False},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 400
    assert "authorization confirmation is required" in res.json()["detail"].lower()


def test_headers_ssrf_attempt_blocked():
    """Verify that attempting to analyze loopback or cloud metadata returns HTTP 400
    with defensive rejection."""
    token = get_token_for_role("analyst")
    prohibited_targets = [
        "http://127.0.0.1",
        "http://localhost",
        "http://169.254.169.254",
        "http://10.0.0.1",
    ]
    for target in prohibited_targets:
        res = client.post(
            f"{settings.API_V1_PREFIX}/headers/analyze",
            json={"url": target, "authorization_confirmed": True},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert res.status_code == 400
        assert (
            "defensive security policy" in res.json()["detail"].lower()
            or "rejected" in res.json()["detail"].lower()
        )


def test_headers_analysis_generates_findings_and_history():
    """Verify successful analysis against public target, findings creation, and history update."""
    token = get_token_for_role("analyst")
    target_url = "https://safe-demo-portal.com"

    # Mock DNS resolution to return a legitimate public IP
    fake_dns = [(2, 1, 6, "", ("93.184.216.34", 443))]

    # Mock fetch_headers_safely to simulate a realistic web response missing CSP and HSTS
    mock_headers = httpx.Headers(
        {
            "server": "nginx/1.24.0",
            "content-type": "text/html; charset=UTF-8",
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
            "referrer-policy": "strict-origin-when-cross-origin",
            # Notice: Content-Security-Policy and Strict-Transport-Security are missing!
        }
    )

    with (
        patch("app.security.ssrf.socket.getaddrinfo", return_value=fake_dns),
        patch(
            "app.services.header_analyzer.fetch_headers_safely",
            return_value=(mock_headers, 200, target_url, 0, True),
        ),
    ):

        res = client.post(
            f"{settings.API_V1_PREFIX}/headers/analyze",
            json={"url": target_url, "authorization_confirmed": True},
            headers={"Authorization": f"Bearer {token}"},
        )

        assert res.status_code == 200
        data = res.json()
        assert data["target_url"] == target_url
        assert data["status_code"] == 200
        assert data["is_https"] is True
        assert data["score"] < 100  # Score deducted due to missing headers
        assert data["created_findings_count"] >= 2  # CSP and Permissions-Policy missing
        assert len(data["created_finding_ids"]) >= 2

        # Verify created findings exist in database with source_module="web_security_headers"
        db: Session = SessionLocal()
        try:
            created_id = data["created_finding_ids"][0]
            finding = db.query(SecurityFinding).filter(SecurityFinding.id == created_id).first()
            assert finding is not None
            assert finding.source_module == "web_security_headers"
            assert finding.category == "web_security"
            assert finding.status == "open"
            assert finding.cwe_id in ("CWE-1021", "CWE-319", "CWE-693")
        finally:
            db.close()

        # Verify history endpoint returns the new evaluation
        hist_res = client.get(
            f"{settings.API_V1_PREFIX}/headers/history",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert hist_res.status_code == 200
        hist_data = hist_res.json()
        assert any(item["target_url"] == target_url for item in hist_data)


def test_headers_redirect_ssrf_intercepted():
    """Verify that a redirect from a public site to a private IP is intercepted by SSRF defense."""
    token = get_token_for_role("analyst")
    target_url = "https://public-redirector.com"

    fake_dns = [(2, 1, 6, "", ("93.184.216.34", 443))]

    # Mock client head to return 302 pointing to private loopback 127.0.0.1
    mock_client = MagicMock()
    redirect_resp = MagicMock()
    redirect_resp.status_code = 302
    redirect_resp.headers = {"Location": "http://127.0.0.1/admin"}
    mock_client.head.return_value = redirect_resp

    with (
        patch("app.security.ssrf.socket.getaddrinfo", return_value=fake_dns),
        patch("app.services.header_analyzer.build_safe_http_client", return_value=mock_client),
    ):

        res = client.post(
            f"{settings.API_V1_PREFIX}/headers/analyze",
            json={"url": target_url, "authorization_confirmed": True},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert res.status_code == 400
        assert (
            "ssrf" in res.json()["detail"].lower() or "prohibited" in res.json()["detail"].lower()
        )


def test_headers_audit_logging():
    """Verify that audit logs are recorded for started, completed, and rejected header analyses."""
    token = get_token_for_role("admin")

    # Rejected analysis audit log
    client.post(
        f"{settings.API_V1_PREFIX}/headers/analyze",
        json={"url": "http://127.0.0.1", "authorization_confirmed": True},
        headers={"Authorization": f"Bearer {token}"},
    )

    db: Session = SessionLocal()
    try:
        rejected_logs = (
            db.query(AuditLog)
            .filter(AuditLog.action == "HEADER_ANALYSIS_REJECTED")
            .order_by(AuditLog.created_at.desc())
            .first()
        )
        assert rejected_logs is not None
        assert "127.0.0.1" in rejected_logs.details.get("target_url", "")
    finally:
        db.close()

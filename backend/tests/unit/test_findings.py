"""Comprehensive unit tests for Security Findings Engine, RBAC, and Audit Logging."""

import uuid
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import SessionLocal
from app.main import app
from app.models.audit import AuditLog
from app.models.user import User
from app.security.hashing import hash_password

client = TestClient(app)
settings = get_settings()

TEST_PASSWORD = "CyberShield#2026!Finding"


def get_auth_token_for_role(role: str) -> str:
    """Helper to create and authenticate a user for a given role."""
    email = f"{role}_{uuid.uuid4().hex[:8]}@example.com"
    db: Session = SessionLocal()
    try:
        user = User(
            email=email,
            hashed_password=hash_password(TEST_PASSWORD),
            role=role,
            is_active=True,
            full_name=f"Test {role.capitalize()}",
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


def test_findings_unauthenticated_rejected():
    """Ensure all findings endpoints require valid bearer authentication."""
    url = f"{settings.API_V1_PREFIX}/findings"
    assert client.get(url).status_code == 401
    assert client.post(url, json={}).status_code == 401
    assert client.get(f"{url}/some-id").status_code == 401
    assert client.patch(f"{url}/some-id", json={}).status_code == 401
    assert client.delete(f"{url}/some-id").status_code == 401


def test_findings_create_and_retrieve():
    """Verify finding creation, normalization, and retrieval by Analyst."""
    token = get_auth_token_for_role("analyst")
    headers = {"Authorization": f"Bearer {token}"}

    payload = {
        "title": "Missing Content-Security-Policy Header",
        "description": (
            "The web server response does not contain a Content-Security-Policy (CSP) header."
        ),
        "severity": "high",
        "category": "web_security",
        "source_module": "header_analyzer",
        "affected_resource": "https://internal-portal.local",
        "remediation": "Configure web server or proxy to send Content-Security-Policy directive.",
        "evidence": "HTTP/1.1 200 OK\nServer: nginx\nContent-Type: text/html",
        "cwe_id": "CWE-1021",
        "status": "open",
    }

    create_res = client.post(
        f"{settings.API_V1_PREFIX}/findings",
        json=payload,
        headers=headers,
    )
    assert create_res.status_code == 201
    created_data = create_res.json()
    assert created_data["title"] == payload["title"]
    assert created_data["severity"] == "high"
    assert created_data["status"] == "open"
    assert created_data["category"] == "web_security"
    assert created_data["affected_resource"] == payload["affected_resource"]
    assert created_data["id"] is not None
    assert created_data["resolved_at"] is None

    # Retrieve by ID
    get_res = client.get(
        f"{settings.API_V1_PREFIX}/findings/{created_data['id']}",
        headers=headers,
    )
    assert get_res.status_code == 200
    fetched_data = get_res.json()
    assert fetched_data["id"] == created_data["id"]
    assert fetched_data["remediation"] == payload["remediation"]


def test_findings_list_and_filtering():
    """Verify paginated listing, severity filter, status filter, and keyword search."""
    token = get_auth_token_for_role("analyst")
    headers = {"Authorization": f"Bearer {token}"}

    # Create two findings with distinct severities
    f1 = client.post(
        f"{settings.API_V1_PREFIX}/findings",
        json={
            "title": "Open Port 21 FTP Insecure Service",
            "description": "Cleartext FTP service detected running on port 21.",
            "severity": "critical",
            "category": "network",
            "source_module": "scanner",
            "affected_resource": "192.168.1.50:21",
            "remediation": "Disable FTP daemon and switch to SFTP/SSH.",
            "status": "open",
        },
        headers=headers,
    ).json()

    f2 = client.post(
        f"{settings.API_V1_PREFIX}/findings",
        json={
            "title": "Server Tokens Banner Leaked",
            "description": "Server header leaks exact software version.",
            "severity": "low",
            "category": "configuration",
            "source_module": "header_analyzer",
            "affected_resource": "https://api.internal.local",
            "remediation": "Set server_tokens off in nginx.",
            "status": "open",
        },
        headers=headers,
    ).json()

    # List all findings
    list_res = client.get(
        f"{settings.API_V1_PREFIX}/findings?page=1&size=50",
        headers=headers,
    )
    assert list_res.status_code == 200
    list_data = list_res.json()
    assert list_data["total"] >= 2
    assert "items" in list_data

    # Filter by severity=critical
    crit_res = client.get(
        f"{settings.API_V1_PREFIX}/findings?severity=critical",
        headers=headers,
    )
    assert crit_res.status_code == 200
    crit_items = crit_res.json()["items"]
    assert all(item["severity"] == "critical" for item in crit_items)
    assert any(item["id"] == f1["id"] for item in crit_items)

    # Search keyword
    search_res = client.get(
        f"{settings.API_V1_PREFIX}/findings?search=192.168.1.50",
        headers=headers,
    )
    assert search_res.status_code == 200
    search_items = search_res.json()["items"]
    assert any(item["id"] == f1["id"] for item in search_items)
    assert not any(item["id"] == f2["id"] for item in search_items)


def test_finding_status_lifecycle_and_resolved_at():
    """Verify status transitions between Open, Resolved, and Accepted."""
    token = get_auth_token_for_role("analyst")
    headers = {"Authorization": f"Bearer {token}"}

    create_res = client.post(
        f"{settings.API_V1_PREFIX}/findings",
        json={
            "title": "Weak Cipher Suite Enabled",
            "description": "TLS 1.0 support detected.",
            "severity": "medium",
            "category": "crypto",
            "remediation": "Enforce TLSv1.2 and TLSv1.3 only.",
        },
        headers=headers,
    )
    finding_id = create_res.json()["id"]
    assert create_res.json()["status"] == "open"
    assert create_res.json()["resolved_at"] is None

    # Transition 1: Open -> Resolved
    resolve_res = client.patch(
        f"{settings.API_V1_PREFIX}/findings/{finding_id}/status",
        json={"status": "resolved", "resolution_notes": "Upgraded TLS config and restarted proxy"},
        headers=headers,
    )
    assert resolve_res.status_code == 200
    resolved_data = resolve_res.json()
    assert resolved_data["status"] == "resolved"
    assert resolved_data["resolved_at"] is not None

    # Transition 2: Resolved -> Open (re-opened)
    reopen_res = client.patch(
        f"{settings.API_V1_PREFIX}/findings/{finding_id}/status",
        json={"status": "open", "resolution_notes": "Regression detected during re-scan"},
        headers=headers,
    )
    assert reopen_res.status_code == 200
    reopened_data = reopen_res.json()
    assert reopened_data["status"] == "open"
    assert reopened_data["resolved_at"] is None

    # Transition 3: Open -> Accepted
    accept_res = client.patch(
        f"{settings.API_V1_PREFIX}/findings/{finding_id}/status",
        json={
            "status": "accepted",
            "resolution_notes": "Compensating controls approved by security officer",
        },
        headers=headers,
    )
    assert accept_res.status_code == 200
    assert accept_res.json()["status"] == "accepted"


def test_findings_rbac_viewer_cannot_modify():
    """Verify that Viewer role has read-only access and cannot create, modify, or delete."""
    analyst_token = get_auth_token_for_role("analyst")
    viewer_token = get_auth_token_for_role("viewer")

    # Analyst creates a finding first
    create_res = client.post(
        f"{settings.API_V1_PREFIX}/findings",
        json={
            "title": "Viewer Read-Only Test Finding",
            "description": "Used to test that viewer cannot modify this entity.",
            "severity": "low",
            "category": "rbac_test",
            "remediation": "No action required.",
        },
        headers={"Authorization": f"Bearer {analyst_token}"},
    )
    finding_id = create_res.json()["id"]

    viewer_headers = {"Authorization": f"Bearer {viewer_token}"}

    # 1. Viewer CAN list findings
    assert (
        client.get(f"{settings.API_V1_PREFIX}/findings", headers=viewer_headers).status_code == 200
    )

    # 2. Viewer CAN get single finding
    assert (
        client.get(
            f"{settings.API_V1_PREFIX}/findings/{finding_id}", headers=viewer_headers
        ).status_code
        == 200
    )

    # 3. Viewer CANNOT create finding
    forbidden_create = client.post(
        f"{settings.API_V1_PREFIX}/findings",
        json={
            "title": "Attempted Viewer Finding",
            "description": "Should be blocked by RBAC.",
            "severity": "low",
            "remediation": "Mitigate according to defensive baseline.",
        },
        headers=viewer_headers,
    )
    assert forbidden_create.status_code == 403

    # 4. Viewer CANNOT update status
    forbidden_status = client.patch(
        f"{settings.API_V1_PREFIX}/findings/{finding_id}/status",
        json={"status": "resolved"},
        headers=viewer_headers,
    )
    assert forbidden_status.status_code == 403

    # 5. Viewer CANNOT update finding fields
    forbidden_update = client.patch(
        f"{settings.API_V1_PREFIX}/findings/{finding_id}",
        json={"title": "Hacked Title"},
        headers=viewer_headers,
    )
    assert forbidden_update.status_code == 403

    # 6. Viewer CANNOT delete finding
    forbidden_delete = client.delete(
        f"{settings.API_V1_PREFIX}/findings/{finding_id}",
        headers=viewer_headers,
    )
    assert forbidden_delete.status_code == 403


def test_findings_rbac_analyst_cannot_delete():
    """Verify that Analyst can create and update, but CANNOT delete findings."""
    analyst_token = get_auth_token_for_role("analyst")
    headers = {"Authorization": f"Bearer {analyst_token}"}

    create_res = client.post(
        f"{settings.API_V1_PREFIX}/findings",
        json={
            "title": "Analyst Delete Restriction Test",
            "description": "Testing that analyst cannot execute hard deletion.",
            "severity": "low",
            "remediation": "Remediation guidance placeholder.",
        },
        headers=headers,
    )
    finding_id = create_res.json()["id"]

    # Analyst attempt to delete must be forbidden (403)
    delete_res = client.delete(
        f"{settings.API_V1_PREFIX}/findings/{finding_id}",
        headers=headers,
    )
    assert delete_res.status_code == 403


def test_findings_rbac_admin_full_management():
    """Verify that Admin can create, modify, and delete findings."""
    admin_token = get_auth_token_for_role("admin")
    headers = {"Authorization": f"Bearer {admin_token}"}

    create_res = client.post(
        f"{settings.API_V1_PREFIX}/findings",
        json={
            "title": "Admin Lifecycle Test Finding",
            "description": "Full lifecycle testing with admin permissions.",
            "severity": "critical",
            "remediation": "Mitigate immediately.",
        },
        headers=headers,
    )
    assert create_res.status_code == 201
    finding_id = create_res.json()["id"]

    # Admin delete finding
    delete_res = client.delete(
        f"{settings.API_V1_PREFIX}/findings/{finding_id}",
        headers=headers,
    )
    assert delete_res.status_code == 204

    # Verify 404 on subsequent get
    assert (
        client.get(f"{settings.API_V1_PREFIX}/findings/{finding_id}", headers=headers).status_code
        == 404
    )


def test_findings_audit_logging():
    """Verify that security audit log records are created for finding lifecycle operations."""
    admin_token = get_auth_token_for_role("admin")
    headers = {"Authorization": f"Bearer {admin_token}"}

    # 1. Create finding
    create_res = client.post(
        f"{settings.API_V1_PREFIX}/findings",
        json={
            "title": "Audit Trail Verification Finding",
            "description": "Verify audit log records created, updated, status_changed, deleted.",
            "severity": "high",
            "category": "audit_verification",
            "remediation": "Test remediation steps.",
        },
        headers=headers,
    )
    finding_id = create_res.json()["id"]

    # 2. Update status
    client.patch(
        f"{settings.API_V1_PREFIX}/findings/{finding_id}/status",
        json={"status": "resolved", "resolution_notes": "Audit verification note"},
        headers=headers,
    )

    # 3. Delete finding
    client.delete(
        f"{settings.API_V1_PREFIX}/findings/{finding_id}",
        headers=headers,
    )

    # Inspect database audit log table
    db: Session = SessionLocal()
    try:
        logs = (
            db.query(AuditLog)
            .filter(AuditLog.resource_id == finding_id)
            .order_by(AuditLog.created_at.asc())
            .all()
        )
        actions = [log.action for log in logs]
        assert "FINDING_CREATED" in actions
        assert "FINDING_STATUS_CHANGED" in actions
        assert "FINDING_DELETED" in actions

        # Verify no passwords or tokens were recorded
        for log in logs:
            if log.details:
                for k, v in log.details.items():
                    assert "password" not in k.lower()
                    assert "token" not in k.lower()
    finally:
        db.close()

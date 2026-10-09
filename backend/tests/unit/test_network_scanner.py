"""Comprehensive unit and security tests for Authorized Network Scanner (Phase 8)."""

import socket
from typing import Generator
from unittest.mock import patch
import uuid
from fastapi.testclient import TestClient
import pytest
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

TEST_PASSWORD = "CyberShield#2026!ScannerTest"


@pytest.fixture(autouse=True)
def override_scanner_settings():
    """Ensure authorized target policy and bounds are set predictably for tests."""
    original_allowed = settings.SCAN_ALLOWED_TARGETS
    original_max_ports = settings.SCAN_MAX_PORTS_PER_SCAN
    settings.SCAN_ALLOWED_TARGETS = "127.0.0.1,localhost,::1,192.168.1.0/24"
    settings.SCAN_MAX_PORTS_PER_SCAN = 25
    yield
    settings.SCAN_ALLOWED_TARGETS = original_allowed
    settings.SCAN_MAX_PORTS_PER_SCAN = original_max_ports


def create_user(role: str) -> str:
    """Helper to create a user and return JWT access token."""
    email = f"{role}_{uuid.uuid4().hex[:8]}@example.com"
    db: Session = SessionLocal()
    try:
        user = User(
            email=email,
            hashed_password=hash_password(TEST_PASSWORD),
            role=role,
            is_active=True,
            full_name=f"Scanner {role.capitalize()}",
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


@pytest.fixture
def viewer_token() -> str:
    return create_user("viewer")


@pytest.fixture
def analyst_token() -> str:
    return create_user("analyst")


@pytest.fixture
def admin_token() -> str:
    return create_user("admin")


@pytest.fixture
def mock_open_server() -> Generator[int, None, None]:
    """Start an ephemeral listening TCP server on localhost for real connect check."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    yield port
    srv.close()


def test_scans_unauthenticated_rejected():
    """Ensure all /scans endpoints reject unauthenticated access with 401."""
    res_post = client.post(
        f"{settings.API_V1_PREFIX}/scans",
        json={"target": "127.0.0.1", "authorization_confirmed": True},
    )
    assert res_post.status_code == 401

    res_get = client.get(f"{settings.API_V1_PREFIX}/scans")
    assert res_get.status_code == 401

    res_sum = client.get(f"{settings.API_V1_PREFIX}/scans/summary")
    assert res_sum.status_code == 401

    res_scope = client.get(f"{settings.API_V1_PREFIX}/scans/scope")
    assert res_scope.status_code == 401


def test_scans_rbac_viewer_forbidden_from_running(viewer_token: str):
    """Ensure viewer role cannot initiate scans (403 Forbidden)."""
    headers = {"Authorization": f"Bearer {viewer_token}"}
    res = client.post(
        f"{settings.API_V1_PREFIX}/scans",
        json={
            "target": "127.0.0.1",
            "ports": [80],
            "authorization_confirmed": True,
        },
        headers=headers,
    )
    assert res.status_code == 403
    assert "insufficient permissions" in res.json()["detail"].lower()


def test_scans_rbac_viewer_allowed_to_view(viewer_token: str):
    """Ensure viewer role can list scans and view scope and summary."""
    headers = {"Authorization": f"Bearer {viewer_token}"}
    res_list = client.get(f"{settings.API_V1_PREFIX}/scans", headers=headers)
    assert res_list.status_code == 200

    res_sum = client.get(f"{settings.API_V1_PREFIX}/scans/summary", headers=headers)
    assert res_sum.status_code == 200

    res_scope = client.get(f"{settings.API_V1_PREFIX}/scans/scope", headers=headers)
    assert res_scope.status_code == 200
    scope_data = res_scope.json()
    assert "allowed_targets" in scope_data
    assert "max_ports_per_scan" in scope_data


def test_scans_missing_authorization_rejected(analyst_token: str):
    """Ensure omitting authorization_confirmed or setting to False returns 400."""
    headers = {"Authorization": f"Bearer {analyst_token}"}
    res = client.post(
        f"{settings.API_V1_PREFIX}/scans",
        json={
            "target": "127.0.0.1",
            "ports": [80],
            "authorization_confirmed": False,
        },
        headers=headers,
    )
    assert res.status_code == 400
    assert "authorization confirmation" in res.json()["detail"].lower()


def test_scans_unauthorized_target_rejected(analyst_token: str):
    """Ensure target outside authorized target policy is rejected with 403."""
    headers = {"Authorization": f"Bearer {analyst_token}"}
    res = client.post(
        f"{settings.API_V1_PREFIX}/scans",
        json={
            "target": "8.8.8.8",
            "ports": [53],
            "authorization_confirmed": True,
        },
        headers=headers,
    )
    assert res.status_code == 403
    assert "not permitted by the authorized scan target policy" in res.json()["detail"].lower()


def test_scans_cloud_metadata_unconditionally_prohibited(analyst_token: str):
    """Ensure cloud metadata target is unconditionally prohibited with 403."""
    headers = {"Authorization": f"Bearer {analyst_token}"}
    res = client.post(
        f"{settings.API_V1_PREFIX}/scans",
        json={
            "target": "169.254.169.254",
            "ports": [80],
            "authorization_confirmed": True,
        },
        headers=headers,
    )
    assert res.status_code == 403
    assert "prohibited" in res.json()["detail"].lower()


def test_scans_multicast_and_broadcast_prohibited(analyst_token: str):
    """Ensure broadcast, multicast, and 0.0.0.0 destinations are blocked."""
    headers = {"Authorization": f"Bearer {analyst_token}"}
    for bad_target in ("255.255.255.255", "0.0.0.0", "224.0.0.1"):
        res = client.post(
            f"{settings.API_V1_PREFIX}/scans",
            json={
                "target": bad_target,
                "ports": [80],
                "authorization_confirmed": True,
            },
            headers=headers,
        )
        assert res.status_code == 403


def test_scans_malformed_target_rejected(analyst_token: str):
    """Ensure targets with schemes, slashes, query params, or port notation return 400."""
    headers = {"Authorization": f"Bearer {analyst_token}"}
    malformed = [
        "http://localhost",
        "https://127.0.0.1",
        "127.0.0.1/admin",
        "127.0.0.1:80",
        "localhost?foo=bar",
        "admin@localhost",
        "localhost;rm -rf",
    ]
    for target in malformed:
        res = client.post(
            f"{settings.API_V1_PREFIX}/scans",
            json={
                "target": target,
                "ports": [80],
                "authorization_confirmed": True,
            },
            headers=headers,
        )
        assert res.status_code == 400


def test_scans_invalid_ports_rejected(analyst_token: str):
    """Ensure negative ports, port 0, ports > 65535, or empty ports return 400."""
    headers = {"Authorization": f"Bearer {analyst_token}"}
    res_zero = client.post(
        f"{settings.API_V1_PREFIX}/scans",
        json={"target": "127.0.0.1", "ports": [0], "authorization_confirmed": True},
        headers=headers,
    )
    assert res_zero.status_code == 400

    res_high = client.post(
        f"{settings.API_V1_PREFIX}/scans",
        json={"target": "127.0.0.1", "ports": [70000], "authorization_confirmed": True},
        headers=headers,
    )
    assert res_high.status_code == 400

    res_empty = client.post(
        f"{settings.API_V1_PREFIX}/scans",
        json={"target": "127.0.0.1", "ports": [], "authorization_confirmed": True},
        headers=headers,
    )
    assert res_empty.status_code == 400


def test_scans_port_count_limit_enforced(analyst_token: str):
    """Ensure exceeding SCAN_MAX_PORTS_PER_SCAN (25 in test fixture) returns 400."""
    headers = {"Authorization": f"Bearer {analyst_token}"}
    too_many = list(range(1, 30))  # 29 ports > 25
    res = client.post(
        f"{settings.API_V1_PREFIX}/scans",
        json={
            "target": "127.0.0.1",
            "ports": too_many,
            "authorization_confirmed": True,
        },
        headers=headers,
    )
    assert res.status_code == 400
    assert "exceeds maximum allowed limit" in res.json()["detail"].lower()


def test_scans_successful_tcp_probe(analyst_token: str, mock_open_server: int):
    """Verify live TCP connect scan correctly distinguishes open vs closed port on localhost."""
    headers = {"Authorization": f"Bearer {analyst_token}"}
    open_port = mock_open_server
    # Choose a high port unlikely to be bound
    closed_port = 59999

    res = client.post(
        f"{settings.API_V1_PREFIX}/scans",
        json={
            "target": "127.0.0.1",
            "ports": [open_port, closed_port],
            "authorization_confirmed": True,
        },
        headers=headers,
    )
    assert res.status_code == 201
    data = res.json()
    assert data["target_host"] == "127.0.0.1"
    assert data["status"] == "COMPLETED"
    assert open_port in data["open_ports"]
    assert closed_port not in data["open_ports"]

    port_map = {item["port"]: item["status"] for item in data["port_details"]}
    assert port_map[open_port] == "open"
    assert port_map[closed_port] in ("closed", "filtered_or_unreachable")


def test_scans_findings_created_for_insecure_ports(analyst_token: str):
    """Verify that insecure ports (e.g. 23 Telnet) generate findings, but 80/443 do not."""
    headers = {"Authorization": f"Bearer {analyst_token}"}

    # Mock probe_tcp_port to simulate ports 23 (Telnet), 80 (HTTP), and 443 (HTTPS) being open
    def mock_probe(ip: str, port: int, timeout: float):
        if port in (23, 80, 443):
            return port, "open"
        return port, "closed"

    with patch("app.services.scanner_service.probe_tcp_port", side_effect=mock_probe):
        res = client.post(
            f"{settings.API_V1_PREFIX}/scans",
            json={
                "target": "localhost",
                "ports": [23, 80, 443],
                "authorization_confirmed": True,
            },
            headers=headers,
        )

    assert res.status_code == 201
    data = res.json()
    assert set(data["open_ports"]) == {23, 80, 443}

    # Only port 23 (Telnet) should generate a finding, not 80 or 443!
    assert data["created_findings_count"] == 1

    db: Session = SessionLocal()
    try:
        finding = (
            db.query(SecurityFinding)
            .filter(SecurityFinding.id == data["created_finding_ids"][0])
            .first()
        )
        assert finding is not None
        assert "Telnet" in finding.title
        assert finding.cwe_id == "CWE-319"
        assert finding.source_module == "scanner"
    finally:
        db.close()


def test_scans_rate_limiting_enforced(analyst_token: str):
    """Ensure exceeding SCAN_RATE_LIMIT_PER_MINUTE triggers 429 Too Many Requests."""
    headers = {"Authorization": f"Bearer {analyst_token}"}
    with patch("app.services.scanner_service.RATE_LIMIT_WINDOW_SECONDS", 60.0):
        # We set rate limit to 2 for this test
        with patch("app.services.scanner_service._check_scan_rate_limit") as mock_rl:
            from app.services.scanner_service import ScanRateLimitError

            mock_rl.side_effect = ScanRateLimitError("Rate limit exceeded")

            res = client.post(
                f"{settings.API_V1_PREFIX}/scans",
                json={
                    "target": "127.0.0.1",
                    "ports": [80],
                    "authorization_confirmed": True,
                },
                headers=headers,
            )
            assert res.status_code == 429
            assert "rate limit" in res.json()["detail"].lower()


def test_scans_audit_logging_recorded(analyst_token: str):
    """Verify SCAN_REQUESTED and SCAN_COMPLETED audit events are created."""
    headers = {"Authorization": f"Bearer {analyst_token}"}

    def mock_probe(ip: str, port: int, timeout: float):
        return port, "closed"

    with patch("app.services.scanner_service.probe_tcp_port", side_effect=mock_probe):
        res = client.post(
            f"{settings.API_V1_PREFIX}/scans",
            json={
                "target": "127.0.0.1",
                "ports": [80],
                "authorization_confirmed": True,
            },
            headers=headers,
        )
    assert res.status_code == 201
    scan_id = res.json()["id"]

    db: Session = SessionLocal()
    try:
        req_log = (
            db.query(AuditLog)
            .filter(AuditLog.action == "SCAN_REQUESTED")
            .order_by(AuditLog.created_at.desc())
            .first()
        )
        assert req_log is not None

        comp_log = (
            db.query(AuditLog)
            .filter(AuditLog.action == "SCAN_COMPLETED")
            .order_by(AuditLog.created_at.desc())
            .first()
        )
        assert comp_log is not None
        assert comp_log.details.get("scan_id") == scan_id
    finally:
        db.close()


def test_scans_get_by_id_and_not_found(analyst_token: str):
    """Verify getting scan by ID returns 200, and nonexistent returns 404."""
    headers = {"Authorization": f"Bearer {analyst_token}"}

    with patch("app.services.scanner_service.probe_tcp_port", return_value=(80, "closed")):
        create_res = client.post(
            f"{settings.API_V1_PREFIX}/scans",
            json={
                "target": "127.0.0.1",
                "ports": [80],
                "authorization_confirmed": True,
            },
            headers=headers,
        )
    assert create_res.status_code == 201
    scan_id = create_res.json()["id"]

    # Valid ID
    get_res = client.get(f"{settings.API_V1_PREFIX}/scans/{scan_id}", headers=headers)
    assert get_res.status_code == 200
    assert get_res.json()["id"] == scan_id

    # Nonexistent ID
    bad_res = client.get(
        f"{settings.API_V1_PREFIX}/scans/{uuid.uuid4()}",
        headers=headers,
    )
    assert bad_res.status_code == 404

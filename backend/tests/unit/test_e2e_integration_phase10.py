"""Phase 10: End-to-End Integration, Security Boundary, and Evidence Verification Test Suite.

Validates:
1. Full authentication lifecycle (Register, Login, Token Expiry, Inactive, /auth/me).
2. Complete RBAC matrix across Admin, Analyst, and Viewer roles across all 6 engines.
3. Boundary enforcement: SSRF, path traversal, unauthorized scopes, bounded ports.
4. Engine findings correlation and real evidence verification for FIM, Logs, and Scanner.
5. Non-disclosure: password hashes never exposed, audit logs sanitized.
"""

from pathlib import Path
import uuid
from fastapi.testclient import TestClient
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

VALID_PASSWORD = "CyberShield#2026!Phase10"


def random_email() -> str:
    """Generate a unique email for test isolation."""
    return f"p10_{uuid.uuid4().hex[:8]}@example.com"


def create_user_with_role(role: str, is_active: bool = True) -> tuple[User, str]:
    """Create a test user directly in DB and return (User, bearer_token)."""
    email = random_email()
    db: Session = SessionLocal()
    try:
        user = User(
            email=email,
            hashed_password=hash_password(VALID_PASSWORD),
            full_name=f"Phase 10 {role.title()}",
            role=role,
            is_active=is_active,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
    finally:
        db.close()

    if not is_active:
        return user, ""

    res = client.post(
        f"{settings.API_V1_PREFIX}/auth/login",
        json={"email": email, "password": VALID_PASSWORD},
    )
    assert res.status_code == 200
    token = res.json()["access_token"]
    return user, token


# ==============================================================================
# SECTION 1: AUTHENTICATION LIFECYCLE & TOKEN BOUNDARIES
# ==============================================================================


def test_auth_e2e_registration_and_login_lifecycle():
    """Verify registration, login, profile fetch, duplicate rejection, and inactive lock."""
    email = random_email()

    # 1. Successful self-registration as analyst
    reg_res = client.post(
        f"{settings.API_V1_PREFIX}/auth/register",
        json={
            "email": email,
            "password": VALID_PASSWORD,
            "full_name": "E2E Operator",
            "role": "analyst",
        },
    )
    assert reg_res.status_code == 201
    user_data = reg_res.json()
    assert user_data["email"] == email
    assert user_data["role"] == "analyst"
    assert "password" not in user_data
    assert "hashed_password" not in user_data

    # 2. Duplicate registration rejected with 409
    dup_res = client.post(
        f"{settings.API_V1_PREFIX}/auth/register",
        json={
            "email": email,
            "password": VALID_PASSWORD,
            "role": "viewer",
        },
    )
    assert dup_res.status_code == 409

    # 3. Registration cannot create admin account (403)
    admin_reg = client.post(
        f"{settings.API_V1_PREFIX}/auth/register",
        json={
            "email": random_email(),
            "password": VALID_PASSWORD,
            "role": "admin",
        },
    )
    assert admin_reg.status_code == 403

    # 4. Successful login
    login_res = client.post(
        f"{settings.API_V1_PREFIX}/auth/login",
        json={"email": email, "password": VALID_PASSWORD},
    )
    assert login_res.status_code == 200
    token_data = login_res.json()
    token = token_data["access_token"]
    assert token_data["token_type"] == "bearer"
    assert token_data["expires_in"] > 0

    # 5. Fetch profile via /auth/me
    me_res = client.get(
        f"{settings.API_V1_PREFIX}/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert me_res.status_code == 200
    assert me_res.json()["email"] == email

    # 6. Invalid password returns 401 without user enumeration
    bad_pw = client.post(
        f"{settings.API_V1_PREFIX}/auth/login",
        json={"email": email, "password": "WrongPassword#999!"},
    )
    assert bad_pw.status_code == 401
    assert bad_pw.json()["detail"] == "Invalid email or password."

    # 7. Non-existent email returns same generic 401
    no_user = client.post(
        f"{settings.API_V1_PREFIX}/auth/login",
        json={"email": "nobody@example.com", "password": VALID_PASSWORD},
    )
    assert no_user.status_code == 401
    assert no_user.json()["detail"] == "Invalid email or password."

    # 8. Deactivated account login returns 403
    inactive_user, _ = create_user_with_role("analyst", is_active=False)
    inactive_login = client.post(
        f"{settings.API_V1_PREFIX}/auth/login",
        json={"email": inactive_user.email, "password": VALID_PASSWORD},
    )
    assert inactive_login.status_code == 403
    assert "deactivated" in inactive_login.json()["detail"].lower()


# ==============================================================================
# SECTION 2: COMPLETE RBAC MATRIX ACROSS ALL 6 DEFENSIVE ENGINES
# ==============================================================================


def test_rbac_viewer_can_read_all_modules_but_mutate_none():
    """Verify Viewer can query all 6 defensive modules but cannot mutate any state."""
    _, viewer_token = create_user_with_role("viewer")
    v_headers = {"Authorization": f"Bearer {viewer_token}"}

    # 1. Dashboard summary read -> 200
    dash_res = client.get(f"{settings.API_V1_PREFIX}/dashboard/summary", headers=v_headers)
    assert dash_res.status_code == 200
    assert "total_findings" in dash_res.json()

    # 2. Findings list -> 200
    findings_list = client.get(f"{settings.API_V1_PREFIX}/findings", headers=v_headers)
    assert findings_list.status_code == 200
    assert "items" in findings_list.json()

    # 3. Web Security Headers history -> 200
    headers_hist = client.get(f"{settings.API_V1_PREFIX}/headers/history", headers=v_headers)
    assert headers_hist.status_code == 200

    # 4. FIM status, records, roots -> 200
    fim_sum = client.get(f"{settings.API_V1_PREFIX}/fim/status", headers=v_headers)
    assert fim_sum.status_code == 200
    fim_recs = client.get(f"{settings.API_V1_PREFIX}/fim/records", headers=v_headers)
    assert fim_recs.status_code == 200
    fim_roots = client.get(f"{settings.API_V1_PREFIX}/fim/roots", headers=v_headers)
    assert fim_roots.status_code == 200

    # 5. Logs summary, events, roots -> 200
    log_sum = client.get(f"{settings.API_V1_PREFIX}/logs/summary", headers=v_headers)
    assert log_sum.status_code == 200
    log_evs = client.get(f"{settings.API_V1_PREFIX}/logs/events", headers=v_headers)
    assert log_evs.status_code == 200
    log_roots = client.get(f"{settings.API_V1_PREFIX}/logs/roots", headers=v_headers)
    assert log_roots.status_code == 200

    # 6. Scans summary, history, scope -> 200
    scan_sum = client.get(f"{settings.API_V1_PREFIX}/scans/summary", headers=v_headers)
    assert scan_sum.status_code == 200
    scan_list = client.get(f"{settings.API_V1_PREFIX}/scans", headers=v_headers)
    assert scan_list.status_code == 200
    scan_scope = client.get(f"{settings.API_V1_PREFIX}/scans/scope", headers=v_headers)
    assert scan_scope.status_code == 200

    # --- ATTEMPT MUTATIONS (Must all return 403 Forbidden) ---
    # Create finding -> 403
    assert (
        client.post(
            f"{settings.API_V1_PREFIX}/findings",
            headers=v_headers,
            json={
                "title": "Unauthorized Finding",
                "description": "Defensive finding description",
                "severity": "low",
                "category": "misc",
                "remediation": "Apply fix properly",
            },
        ).status_code
        == 403
    )

    # Header analysis -> 403
    assert (
        client.post(
            f"{settings.API_V1_PREFIX}/headers/analyze",
            headers=v_headers,
            json={"url": "https://example.com", "authorization_confirmed": True},
        ).status_code
        == 403
    )

    # FIM baseline -> 403
    assert (
        client.post(
            f"{settings.API_V1_PREFIX}/fim/baselines",
            headers=v_headers,
            json={"path": "./monitored"},
        ).status_code
        == 403
    )

    # Log analyze -> 403
    assert (
        client.post(
            f"{settings.API_V1_PREFIX}/logs/analyze",
            headers=v_headers,
            json={"path": "./logs/test.log"},
        ).status_code
        == 403
    )

    # Scan run -> 403
    assert (
        client.post(
            f"{settings.API_V1_PREFIX}/scans",
            headers=v_headers,
            json={"target": "127.0.0.1", "ports": [80], "authorization_confirmed": True},
        ).status_code
        == 403
    )


def test_rbac_analyst_can_operate_but_cannot_delete_findings():
    """Verify Analyst can create and update findings, but is forbidden from deleting findings."""
    _, analyst_token = create_user_with_role("analyst")
    _, admin_token = create_user_with_role("admin")
    a_headers = {"Authorization": f"Bearer {analyst_token}"}
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    # 1. Analyst creates a finding -> 201
    create_res = client.post(
        f"{settings.API_V1_PREFIX}/findings",
        headers=a_headers,
        json={
            "title": "E2E RBAC Finding Test",
            "description": "Created by analyst during E2E verification",
            "severity": "medium",
            "category": "network",
            "asset": "127.0.0.1",
            "remediation": "Patch and secure system endpoint",
        },
    )
    assert create_res.status_code == 201
    finding_id = create_res.json()["id"]

    # 2. Analyst updates finding status -> 200
    status_res = client.patch(
        f"{settings.API_V1_PREFIX}/findings/{finding_id}/status",
        headers=a_headers,
        json={"status": "resolved"},
    )
    assert status_res.status_code == 200
    assert status_res.json()["status"] == "resolved"

    # 3. Analyst tries to DELETE finding -> 403 Forbidden!
    del_res = client.delete(
        f"{settings.API_V1_PREFIX}/findings/{finding_id}",
        headers=a_headers,
    )
    assert del_res.status_code == 403
    assert "Insufficient permissions" in del_res.json()["detail"]

    # 4. Admin DELETES finding -> 204 No Content
    admin_del = client.delete(
        f"{settings.API_V1_PREFIX}/findings/{finding_id}",
        headers=admin_headers,
    )
    assert admin_del.status_code == 204


# ==============================================================================
# SECTION 3: BOUNDARY CONTROLS & DEFENSIVE PROTECTIONS
# ==============================================================================


def test_ssrf_boundary_protection_rejections():
    """Verify SSRF boundaries reject loopback, private ranges, metadata, and invalid schemes."""
    _, analyst_token = create_user_with_role("analyst")
    a_headers = {"Authorization": f"Bearer {analyst_token}"}

    # Missing authorization checkbox -> 400
    res_no_auth = client.post(
        f"{settings.API_V1_PREFIX}/headers/analyze",
        headers=a_headers,
        json={"url": "https://example.com", "authorization_confirmed": False},
    )
    assert res_no_auth.status_code == 400
    assert "explicit authorization" in res_no_auth.json()["detail"].lower()

    # Loopback target on port 80 -> 400 SSRF blocked
    res_loopback = client.post(
        f"{settings.API_V1_PREFIX}/headers/analyze",
        headers=a_headers,
        json={"url": "http://127.0.0.1:80/test", "authorization_confirmed": True},
    )
    assert res_loopback.status_code == 400
    assert "prohibited" in res_loopback.json()["detail"].lower()

    # Non-standard port -> 400 rejected by port policy
    res_bad_port = client.post(
        f"{settings.API_V1_PREFIX}/headers/analyze",
        headers=a_headers,
        json={"url": "http://example.com:8080/test", "authorization_confirmed": True},
    )
    assert res_bad_port.status_code == 400
    assert "not permitted" in res_bad_port.json()["detail"].lower()

    # Cloud metadata target -> 400 SSRF blocked
    res_meta = client.post(
        f"{settings.API_V1_PREFIX}/headers/analyze",
        headers=a_headers,
        json={"url": "http://169.254.169.254/latest/meta-data", "authorization_confirmed": True},
    )
    assert res_meta.status_code == 400
    assert "prohibited" in res_meta.json()["detail"].lower()

    # Private RFC1918 target -> 400 SSRF blocked
    res_priv = client.post(
        f"{settings.API_V1_PREFIX}/headers/analyze",
        headers=a_headers,
        json={"url": "http://192.168.1.1:80", "authorization_confirmed": True},
    )
    assert res_priv.status_code == 400
    assert "prohibited" in res_priv.json()["detail"].lower()

    # Non-HTTP scheme -> 400
    res_scheme = client.post(
        f"{settings.API_V1_PREFIX}/headers/analyze",
        headers=a_headers,
        json={"url": "ftp://example.com", "authorization_confirmed": True},
    )
    assert res_scheme.status_code == 400


def test_fim_path_boundary_rejections():
    """Verify FIM rejects path traversal and unauthorized roots."""
    _, analyst_token = create_user_with_role("analyst")
    a_headers = {"Authorization": f"Bearer {analyst_token}"}

    # Path traversal attempt
    traversal_res = client.post(
        f"{settings.API_V1_PREFIX}/fim/baselines",
        headers=a_headers,
        json={"path": "../../etc/shadow"},
    )
    assert traversal_res.status_code in [400, 403, 404]

    # Absolute path outside configured authorized roots
    outside_res = client.post(
        f"{settings.API_V1_PREFIX}/fim/baselines",
        headers=a_headers,
        json={"path": "C:/Windows/System32" if Path("C:/").exists() else "/etc"},
    )
    assert outside_res.status_code in [400, 403, 404]


def test_log_analyzer_path_boundary_rejections():
    """Verify Log Analyzer rejects path traversal and non-regular files."""
    _, analyst_token = create_user_with_role("analyst")
    a_headers = {"Authorization": f"Bearer {analyst_token}"}

    # Path traversal attempt
    traversal_res = client.post(
        f"{settings.API_V1_PREFIX}/logs/analyze",
        headers=a_headers,
        json={"path": "../../var/log/auth.log"},
    )
    assert traversal_res.status_code in [400, 403, 404]

    # Directory instead of file
    dir_res = client.post(
        f"{settings.API_V1_PREFIX}/logs/analyze",
        headers=a_headers,
        json={"path": "./logs"},
    )
    assert dir_res.status_code == 400


def test_scanner_scope_and_boundary_rejections():
    """Verify scanner rejects unconfirmed auth, unapproved targets, and over-limit ports."""
    _, analyst_token = create_user_with_role("analyst")
    a_headers = {"Authorization": f"Bearer {analyst_token}"}

    # 1. Missing authorization confirmation -> 400
    unconfirmed = client.post(
        f"{settings.API_V1_PREFIX}/scans",
        headers=a_headers,
        json={"target": "127.0.0.1", "ports": [80], "authorization_confirmed": False},
    )
    assert unconfirmed.status_code == 400
    assert "explicit authorization" in unconfirmed.json()["detail"].lower()

    # 2. Unauthorized public target (not in SCAN_ALLOWED_TARGETS) -> 400 or 403
    unauth_target = client.post(
        f"{settings.API_V1_PREFIX}/scans",
        headers=a_headers,
        json={"target": "8.8.8.8", "ports": [53], "authorization_confirmed": True},
    )
    assert unauth_target.status_code in [400, 403]
    assert "not permitted" in unauth_target.json()["detail"].lower()

    # 3. Cloud metadata target -> 400 unconditionally
    metadata_scan = client.post(
        f"{settings.API_V1_PREFIX}/scans",
        headers=a_headers,
        json={"target": "169.254.169.254", "ports": [80], "authorization_confirmed": True},
    )
    assert metadata_scan.status_code in [400, 403]

    # 4. Excess port count (>100) -> 400
    too_many_ports = client.post(
        f"{settings.API_V1_PREFIX}/scans",
        headers=a_headers,
        json={
            "target": "127.0.0.1",
            "ports": list(range(1, 150)),
            "authorization_confirmed": True,
        },
    )
    assert too_many_ports.status_code == 400
    assert "maximum" in too_many_ports.json()["detail"].lower()

    # 5. Invalid port number -> 422
    bad_port = client.post(
        f"{settings.API_V1_PREFIX}/scans",
        headers=a_headers,
        json={"target": "127.0.0.1", "ports": [70000], "authorization_confirmed": True},
    )
    assert bad_port.status_code in [400, 422]


# ==============================================================================
# SECTION 4: EVIDENCE CORRELATION FOR FIM, LOGS, AND NETWORK SCANNER
# ==============================================================================


def test_fim_evidence_correlation_on_file_tampering():
    """Verify FIM generates a SecurityFinding with accurate evidence when a file is altered."""
    _, analyst_token = create_user_with_role("analyst")
    a_headers = {"Authorization": f"Bearer {analyst_token}"}

    # Create test directory inside authorized root (./monitored)
    monitored_root = Path("./monitored")
    monitored_root.mkdir(parents=True, exist_ok=True)
    test_dir = monitored_root / f"e2e_test_{uuid.uuid4().hex[:6]}"
    test_dir.mkdir(parents=True, exist_ok=True)
    test_file = test_dir / "critical_config.json"
    test_file.write_text('{"setting": "secure_value"}', encoding="utf-8")

    try:
        # Step 1: Create Baseline
        base_res = client.post(
            f"{settings.API_V1_PREFIX}/fim/baselines",
            headers=a_headers,
            json={"path": str(test_dir)},
        )
        assert base_res.status_code == 201
        assert base_res.json()["files_baselined_count"] >= 1

        # Step 2: Tamper with the file
        test_file.write_text('{"setting": "tampered_by_malicious_actor"}', encoding="utf-8")

        # Step 3: Run FIM check
        check_res = client.post(
            f"{settings.API_V1_PREFIX}/fim/check",
            headers=a_headers,
            json={"path": str(test_dir)},
        )
        assert check_res.status_code == 200
        check_data = check_res.json()
        assert check_data["modified_count"] >= 1
        assert check_data["created_findings_count"] >= 1

        # Step 4: Verify the correlated finding exists in Findings Registry
        db: Session = SessionLocal()
        try:
            finding = (
                db.query(SecurityFinding)
                .filter(SecurityFinding.source_module == "fim")
                .order_by(SecurityFinding.created_at.desc())
                .first()
            )
            assert finding is not None
            assert "critical_config.json" in finding.title or "Modified" in finding.title
            assert finding.severity in ["high", "medium"]
            assert finding.evidence is not None
            assert "SHA-256" in finding.evidence or "hash" in finding.evidence.lower()
        finally:
            db.close()
    finally:
        # Cleanup test fixture
        if test_file.exists():
            test_file.unlink()
        if test_dir.exists():
            test_dir.rmdir()


def test_log_analyzer_evidence_correlation_on_brute_force():
    """Verify Log Analyzer generates a correlated finding with actual IP and evidence lines."""
    _, analyst_token = create_user_with_role("analyst")
    a_headers = {"Authorization": f"Bearer {analyst_token}"}

    # Create authorized test log file
    logs_root = Path("./logs")
    logs_root.mkdir(parents=True, exist_ok=True)
    test_log = logs_root / f"e2e_auth_{uuid.uuid4().hex[:6]}.log"

    attacker_ip = "203.0.113.88"
    log_lines = []
    # Write 6 failed SSH login attempts within 60 seconds (exceeding threshold of 5)
    for i in range(6):
        log_lines.append(
            f"2026-10-09T10:0{i}:00Z sshd[1234]: "
            f"Failed password for root from {attacker_ip} port 45123 ssh2\n"
        )
    test_log.write_text("".join(log_lines), encoding="utf-8")

    try:
        # Analyze log file
        res = client.post(
            f"{settings.API_V1_PREFIX}/logs/analyze",
            headers=a_headers,
            json={"path": str(test_log)},
        )
        assert res.status_code == 200
        data = res.json()
        assert data["lines_read"] == 6
        assert data["created_findings_count"] >= 1

        # Verify correlated finding in database
        db: Session = SessionLocal()
        try:
            finding = (
                db.query(SecurityFinding)
                .filter(SecurityFinding.source_module == "log_analyzer")
                .filter(SecurityFinding.affected_resource == attacker_ip)
                .order_by(SecurityFinding.created_at.desc())
                .first()
            )
            assert finding is not None
            assert "Brute-Force" in finding.title or "Authentication" in finding.title
            assert finding.severity == "high"
            assert finding.evidence is not None
            assert attacker_ip in finding.evidence
        finally:
            db.close()
    finally:
        if test_log.exists():
            test_log.unlink()


def test_network_scanner_valid_execution_on_authorized_localhost():
    """Verify Network Scanner executes against localhost with valid closed port evidence."""
    _, analyst_token = create_user_with_role("analyst")
    a_headers = {"Authorization": f"Bearer {analyst_token}"}

    # Probe port 54321 on 127.0.0.1 (likely closed)
    scan_res = client.post(
        f"{settings.API_V1_PREFIX}/scans",
        headers=a_headers,
        json={
            "target": "127.0.0.1",
            "ports": [54321],
            "authorization_confirmed": True,
        },
    )
    assert scan_res.status_code == 201
    scan_data = scan_res.json()
    assert scan_data["target_host"] == "127.0.0.1"
    assert scan_data["status"].upper() == "COMPLETED"
    assert len(scan_data["port_details"]) == 1
    assert scan_data["port_details"][0]["port"] == 54321
    # Evidence matches actual probe
    assert scan_data["port_details"][0]["status"] in ["closed", "filtered_or_unreachable"]


# ==============================================================================
# SECTION 5: AUDIT LOG SANITIZATION & SECURITY REVIEWS
# ==============================================================================


def test_audit_logs_contain_no_sensitive_credentials():
    """Verify all audit logs in database have redacted sensitive fields."""
    db: Session = SessionLocal()
    try:
        logs = db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(50).all()
        for log in logs:
            assert log.action is not None
            assert log.status_code is not None
            if log.details:
                for k, v in log.details.items():
                    if any(
                        s in k.lower()
                        for s in ["password", "token", "secret", "credential", "hash"]
                    ):
                        assert v == "[REDACTED]", f"Key {k} was not redacted!"
    finally:
        db.close()

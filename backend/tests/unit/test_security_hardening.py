"""Comprehensive test suite for Phase 9 Security Hardening & Production Readiness."""

import uuid
from datetime import datetime, timedelta, timezone
from fastapi.testclient import TestClient
import jwt
import pytest
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.database import SessionLocal
from app.main import app
from app.models.audit import AuditLog
from app.models.user import User
from app.security.hashing import hash_password

client = TestClient(app)
settings = get_settings()

VALID_PASSWORD = "CyberShield#2026!Hardened"


def random_email() -> str:
    """Generate a unique test email address."""
    return f"harden_{uuid.uuid4().hex[:8]}@example.com"


def create_test_user(role: str) -> tuple[User, str]:
    """Helper to create and log in a user with a specified role."""
    email = random_email()
    db: Session = SessionLocal()
    try:
        user = User(
            email=email,
            hashed_password=hash_password(VALID_PASSWORD),
            full_name=f"Test {role.title()}",
            role=role,
            is_active=True,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
    finally:
        db.close()

    res = client.post(
        f"{settings.API_V1_PREFIX}/auth/login",
        json={"email": email, "password": VALID_PASSWORD},
    )
    assert res.status_code == 200
    token = res.json()["access_token"]
    return user, token


# ==============================================================================
# 1. Configuration & Production Readiness Validation Tests
# ==============================================================================


def test_production_config_rejects_debug_true():
    """Verify Settings rejects DEBUG=True in production environments."""
    with pytest.raises(ValueError, match="DEBUG must be False in production"):
        Settings(
            APP_ENV="production",
            DEBUG=True,
            JWT_SECRET_KEY="f8b09341b52a79c941e7dc6016e1654878a9c370c9eb37492c",
        )


def test_production_config_rejects_short_secret():
    """Verify Settings rejects JWT_SECRET_KEY < 32 chars in production."""
    with pytest.raises(ValueError, match="at least 32 characters"):
        Settings(
            APP_ENV="production",
            DEBUG=False,
            JWT_SECRET_KEY="short-secret-key-12345",
        )


def test_production_config_rejects_insecure_default_secret():
    """Verify Settings rejects default / placeholder secret keys in production."""
    with pytest.raises(ValueError, match="Insecure or default JWT_SECRET_KEY"):
        Settings(
            APP_ENV="production",
            DEBUG=False,
            JWT_SECRET_KEY="cybershield-dev-secret-key-change-in-production-min-32-chars",
        )


def test_production_config_rejects_wildcard_cors():
    """Verify Settings rejects wildcard CORS origins in production."""
    with pytest.raises(ValueError, match="CORS_ORIGINS cannot contain wildcard"):
        Settings(
            APP_ENV="production",
            DEBUG=False,
            CORS_ORIGINS="*",
            JWT_SECRET_KEY="f8b09341b52a79c941e7dc6016e1654878a9c370c9eb37492c",
        )


def test_valid_production_config_accepted():
    """Verify Settings accepts valid production configuration."""
    valid_cfg = Settings(
        APP_ENV="production",
        DEBUG=False,
        CORS_ORIGINS="https://cybershield.corp.internal,https://admin.corp.internal",
        JWT_SECRET_KEY="f8b09341b52a79c941e7dc6016e1654878a9c370c9eb37492c",
    )
    assert valid_cfg.APP_ENV == "production"
    assert valid_cfg.DEBUG is False
    assert len(valid_cfg.cors_origins_list) == 2


def test_cors_origins_normalizes_trailing_slashes():
    """Verify that cors_origins_list strips trailing slashes from origins."""
    cfg = Settings(
        CORS_ORIGINS="https://cybershield-frontend-dj4s.onrender.com/, http://localhost:5173/ "
    )
    assert cfg.cors_origins_list == [
        "https://cybershield-frontend-dj4s.onrender.com",
        "http://localhost:5173",
    ]


def test_production_config_rejects_wildcard_cors_regex():
    """Verify Settings rejects overly permissive wildcard CORS_ORIGIN_REGEX in production."""
    with pytest.raises(ValueError, match="CORS_ORIGIN_REGEX cannot be a permissive wildcard"):
        Settings(
            APP_ENV="production",
            DEBUG=False,
            JWT_SECRET_KEY="f8b09341b52a79c941e7dc6016e1654878a9c370c9eb37492c",
            CORS_ORIGIN_REGEX=".*",
        )


def test_production_config_rejects_broad_shared_hosting_wildcard_regex():
    """Verify Settings rejects broad multi-tenant onrender wildcard regex in production."""
    with pytest.raises(
        ValueError,
        match="cannot use unconstrained wildcard subdomains on shared multi-tenant platforms",
    ):
        Settings(
            APP_ENV="production",
            DEBUG=False,
            JWT_SECRET_KEY="f8b09341b52a79c941e7dc6016e1654878a9c370c9eb37492c",
            CORS_ORIGIN_REGEX=r"^https:\/\/.*\.onrender\.com$",
        )


def test_production_config_accepts_scoped_project_cors_regex():
    """Verify Settings accepts project-scoped preview regex in production."""
    cfg = Settings(
        APP_ENV="production",
        DEBUG=False,
        JWT_SECRET_KEY="f8b09341b52a79c941e7dc6016e1654878a9c370c9eb37492c",
        CORS_ORIGINS="https://cybershield-frontend-dj4s.onrender.com",
        CORS_ORIGIN_REGEX=r"^https:\/\/cybershield-frontend-[a-z0-9]+\.onrender\.com$",
    )
    assert cfg.CORS_ORIGIN_REGEX == r"^https:\/\/cybershield-frontend-[a-z0-9]+\.onrender\.com$"


# ==============================================================================
# 2. JWT Lifecycle, Expiration, and Signature Tampering Tests
# ==============================================================================


def test_expired_jwt_rejected_with_401_and_header():
    """Verify expired JWT returns 401 with WWW-Authenticate header and logs audit event."""
    user, _ = create_test_user("viewer")

    # Manually craft an expired token
    past_time = datetime.now(timezone.utc) - timedelta(minutes=5)
    expired_payload = {
        "sub": user.id,
        "email": user.email,
        "role": user.role,
        "iat": past_time - timedelta(minutes=30),
        "exp": past_time,
        "jti": str(uuid.uuid4()),
    }
    expired_token = jwt.encode(
        expired_payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM
    )

    res = client.get(
        f"{settings.API_V1_PREFIX}/auth/me",
        headers={"Authorization": f"Bearer {expired_token}"},
    )
    assert res.status_code == 401
    assert "Bearer" in res.headers.get("WWW-Authenticate", "")
    assert "expired" in res.json()["detail"].lower()

    # Check audit log for token expired action
    db: Session = SessionLocal()
    try:
        log_entry = (
            db.query(AuditLog)
            .filter(AuditLog.action == "AUTH_TOKEN_EXPIRED")
            .order_by(AuditLog.created_at.desc())
            .first()
        )
        assert log_entry is not None
        assert log_entry.status_code == 401
    finally:
        db.close()


def test_invalid_signature_jwt_rejected_with_401():
    """Verify that a JWT signed with an untrusted key is rejected with 401."""
    user, _ = create_test_user("analyst")

    fake_secret = "unauthorized-malicious-key-for-forgery-testing-32-chars"
    now = datetime.now(timezone.utc)
    forged_payload = {
        "sub": user.id,
        "email": user.email,
        "role": "admin",  # attempted privilege escalation
        "iat": now,
        "exp": now + timedelta(minutes=30),
        "jti": str(uuid.uuid4()),
    }
    forged_token = jwt.encode(forged_payload, fake_secret, algorithm=settings.JWT_ALGORITHM)

    res = client.get(
        f"{settings.API_V1_PREFIX}/auth/me",
        headers={"Authorization": f"Bearer {forged_token}"},
    )
    assert res.status_code == 401
    assert "Bearer" in res.headers.get("WWW-Authenticate", "")

    # Check audit log for token invalid action
    db: Session = SessionLocal()
    try:
        log_entry = (
            db.query(AuditLog)
            .filter(AuditLog.action == "AUTH_TOKEN_INVALID")
            .order_by(AuditLog.created_at.desc())
            .first()
        )
        assert log_entry is not None
        assert log_entry.status_code == 401
    finally:
        db.close()


def test_token_missing_subject_claim_rejected():
    """Verify that a token missing the 'sub' claim returns HTTP 401."""
    now = datetime.now(timezone.utc)
    payload_no_sub = {
        "email": "test@example.com",
        "role": "analyst",
        "iat": now,
        "exp": now + timedelta(minutes=30),
        "jti": str(uuid.uuid4()),
    }
    bad_token = jwt.encode(
        payload_no_sub, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM
    )

    res = client.get(
        f"{settings.API_V1_PREFIX}/auth/me",
        headers={"Authorization": f"Bearer {bad_token}"},
    )
    assert res.status_code == 401
    assert "Bearer" in res.headers.get("WWW-Authenticate", "")


# ==============================================================================
# 3. Data Protection: No Password Hash In API Responses
# ==============================================================================


def test_password_hashes_never_exposed_in_responses():
    """Verify that password hashes or raw passwords are never returned in auth endpoints."""
    email = random_email()

    # 1. Register endpoint
    reg_res = client.post(
        f"{settings.API_V1_PREFIX}/auth/register",
        json={"email": email, "password": VALID_PASSWORD, "role": "analyst"},
    )
    assert reg_res.status_code == 201
    reg_json = reg_res.json()
    assert "password" not in reg_json
    assert "hashed_password" not in reg_json

    # 2. Login endpoint
    login_res = client.post(
        f"{settings.API_V1_PREFIX}/auth/login",
        json={"email": email, "password": VALID_PASSWORD},
    )
    assert login_res.status_code == 200
    login_json = login_res.json()
    assert "password" not in login_json
    assert "hashed_password" not in login_json
    assert "password" not in login_json["user"]
    assert "hashed_password" not in login_json["user"]

    # 3. /auth/me endpoint
    token = login_json["access_token"]
    me_res = client.get(
        f"{settings.API_V1_PREFIX}/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert me_res.status_code == 200
    me_json = me_res.json()
    assert "password" not in me_json
    assert "hashed_password" not in me_json


# ==============================================================================
# 4. Strict RBAC Protection across ALL Operational Modules
# ==============================================================================


def test_viewer_role_locked_out_from_all_operational_endpoints():
    """Verify that Viewer role is strictly rejected with 403 on state-changing endpoints."""
    _, viewer_token = create_test_user("viewer")
    viewer_headers = {"Authorization": f"Bearer {viewer_token}"}

    # 1. Findings: Create finding
    finding_res = client.post(
        f"{settings.API_V1_PREFIX}/findings",
        headers=viewer_headers,
        json={
            "title": "Test Finding",
            "description": "Defensive finding description",
            "severity": "medium",
            "category": "headers",
            "asset": "example.com",
            "remediation_guidance": "Add security headers",
        },
    )
    assert finding_res.status_code == 403

    # 2. Findings: Status update
    dummy_id = str(uuid.uuid4())
    status_res = client.patch(
        f"{settings.API_V1_PREFIX}/findings/{dummy_id}/status",
        headers=viewer_headers,
        json={"status": "resolved"},
    )
    assert status_res.status_code == 403

    # 3. Findings: General update
    update_res = client.patch(
        f"{settings.API_V1_PREFIX}/findings/{dummy_id}",
        headers=viewer_headers,
        json={"title": "Updated Title"},
    )
    assert update_res.status_code == 403

    # 4. Findings: Delete finding
    del_res = client.delete(
        f"{settings.API_V1_PREFIX}/findings/{dummy_id}",
        headers=viewer_headers,
    )
    assert del_res.status_code == 403

    # 5. Web Security Headers: Run analysis
    header_res = client.post(
        f"{settings.API_V1_PREFIX}/headers/analyze",
        headers=viewer_headers,
        json={"url": "http://example.com", "confirm_authorization": True},
    )
    assert header_res.status_code == 403

    # 6. File Integrity Monitor: Create baseline
    fim_base_res = client.post(
        f"{settings.API_V1_PREFIX}/fim/baselines",
        headers=viewer_headers,
        json={"path": "./monitored"},
    )
    assert fim_base_res.status_code == 403

    # 7. File Integrity Monitor: Run check
    fim_check_res = client.post(
        f"{settings.API_V1_PREFIX}/fim/check",
        headers=viewer_headers,
        json={"path": "./monitored"},
    )
    assert fim_check_res.status_code == 403

    # 8. Defensive Log Analyzer: Run analysis
    log_res = client.post(
        f"{settings.API_V1_PREFIX}/logs/analyze",
        headers=viewer_headers,
        json={"path": "./logs/test.log"},
    )
    assert log_res.status_code == 403

    # 9. Network Scanner: Run scan
    scan_res = client.post(
        f"{settings.API_V1_PREFIX}/scans",
        headers=viewer_headers,
        json={
            "target": "127.0.0.1",
            "ports": [80],
            "confirm_authorization": True,
        },
    )
    assert scan_res.status_code == 403


def test_analyst_cannot_delete_findings():
    """Verify that an Analyst cannot delete security findings (Admin only)."""
    _, analyst_token = create_test_user("analyst")
    dummy_id = str(uuid.uuid4())

    del_res = client.delete(
        f"{settings.API_V1_PREFIX}/findings/{dummy_id}",
        headers={"Authorization": f"Bearer {analyst_token}"},
    )
    assert del_res.status_code == 403
    assert "Insufficient permissions" in del_res.json()["detail"]


# ==============================================================================
# 5. Audit Log Non-Disclosure Verification
# ==============================================================================


def test_audit_logs_redact_sensitive_keys():
    """Verify that sensitive keys are always redacted in audit log details."""
    from app.utils.audit_helper import sanitize_audit_details

    dirty_details = {
        "username": "admin_user",
        "password": "SuperSecretPassword123!",
        "access_token": "bearer.ey...secret",
        "api_key": "secret-key-abc",
        "credential": "private-cert-material",
        "nested": {
            "password_hash": "$argon2id$...secret",
            "normal_field": "safe_value",
        },
    }

    cleaned = sanitize_audit_details(dirty_details)
    assert cleaned["username"] == "admin_user"
    assert cleaned["password"] == "[REDACTED]"
    assert cleaned["access_token"] == "[REDACTED]"
    assert cleaned["api_key"] == "[REDACTED]"
    assert cleaned["credential"] == "[REDACTED]"
    assert cleaned["nested"]["password_hash"] == "[REDACTED]"
    assert cleaned["nested"]["normal_field"] == "safe_value"

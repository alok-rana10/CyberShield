"""Comprehensive authentication, RBAC, and audit logging test suite."""

import uuid
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.main import app
from app.config import get_settings
from app.database import SessionLocal
from app.models.user import User
from app.models.audit import AuditLog
from app.security.hashing import hash_password

client = TestClient(app)
settings = get_settings()

VALID_PASSWORD = "CyberShield#2026!Secure"


def random_email() -> str:
    """Generate a random email to ensure test isolation."""
    return f"user_{uuid.uuid4().hex[:8]}@example.com"


def test_successful_registration():
    """Verify that a new user can register and password is encrypted with Argon2id."""
    email = random_email()
    response = client.post(
        f"{settings.API_V1_PREFIX}/auth/register",
        json={
            "email": email,
            "password": VALID_PASSWORD,
            "full_name": "Security Analyst",
            "role": "analyst",
        },
    )
    assert response.status_code == 201
    data = response.json()
    assert data["email"] == email
    assert data["role"] == "analyst"
    assert data["is_active"] is True
    assert "password" not in data
    assert "hashed_password" not in data

    # Verify password hash format in database
    db: Session = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email).first()
        assert user is not None
        assert user.hashed_password.startswith("$argon2id$")
        assert VALID_PASSWORD not in user.hashed_password
    finally:
        db.close()


def test_duplicate_registration_rejected():
    """Verify that registering with an existing email returns HTTP 409 Conflict."""
    email = random_email()
    payload = {
        "email": email,
        "password": VALID_PASSWORD,
        "full_name": "Test User",
        "role": "viewer",
    }
    first_res = client.post(f"{settings.API_V1_PREFIX}/auth/register", json=payload)
    assert first_res.status_code == 201

    second_res = client.post(f"{settings.API_V1_PREFIX}/auth/register", json=payload)
    assert second_res.status_code == 409
    assert "already exists" in second_res.json()["detail"]


def test_registration_cannot_create_admin_account():
    """Verify that user-controlled input cannot self-register an elevated admin account."""
    email = random_email()
    response = client.post(
        f"{settings.API_V1_PREFIX}/auth/register",
        json={
            "email": email,
            "password": VALID_PASSWORD,
            "role": "admin",
        },
    )
    assert response.status_code == 403
    assert "prohibited" in response.json()["detail"]


def test_weak_password_registration_rejected():
    """Verify that weak passwords that fail complexity rules are rejected with HTTP 422."""
    weak_passwords = ["short", "alllowercase1!", "ALLUPPERCASE1!", "NoDigitsHere!", "NoSpecial123"]
    for weak_pw in weak_passwords:
        email = random_email()
        response = client.post(
            f"{settings.API_V1_PREFIX}/auth/register",
            json={"email": email, "password": weak_pw, "role": "viewer"},
        )
        assert response.status_code == 422, f"Expected 422 for password {weak_pw}"


def test_successful_login():
    """Verify user authentication issues a valid JWT access token."""
    email = random_email()
    reg_res = client.post(
        f"{settings.API_V1_PREFIX}/auth/register",
        json={"email": email, "password": VALID_PASSWORD, "role": "analyst"},
    )
    assert reg_res.status_code == 201

    login_res = client.post(
        f"{settings.API_V1_PREFIX}/auth/login",
        json={"email": email, "password": VALID_PASSWORD},
    )
    assert login_res.status_code == 200
    token_data = login_res.json()
    assert "access_token" in token_data
    assert token_data["token_type"] == "bearer"
    assert token_data["expires_in"] > 0
    assert token_data["user"]["email"] == email


def test_login_invalid_password():
    """Verify that incorrect password returns generic HTTP 401 error."""
    email = random_email()
    client.post(
        f"{settings.API_V1_PREFIX}/auth/register",
        json={"email": email, "password": VALID_PASSWORD, "role": "analyst"},
    )

    login_res = client.post(
        f"{settings.API_V1_PREFIX}/auth/login",
        json={"email": email, "password": "WrongPassword#999"},
    )
    assert login_res.status_code == 401
    assert login_res.json()["detail"] == "Invalid email or password."


def test_login_nonexistent_user():
    """Verify that login with non-existent email returns generic HTTP 401 error."""
    login_res = client.post(
        f"{settings.API_V1_PREFIX}/auth/login",
        json={"email": "nonexistent_operator@example.com", "password": VALID_PASSWORD},
    )
    assert login_res.status_code == 401
    assert login_res.json()["detail"] == "Invalid email or password."


def test_auth_me_endpoint():
    """Verify GET /api/v1/auth/me returns the profile of the authenticated user."""
    email = random_email()
    client.post(
        f"{settings.API_V1_PREFIX}/auth/register",
        json={
            "email": email,
            "password": VALID_PASSWORD,
            "full_name": "Alice Analyst",
            "role": "analyst",
        },
    )
    login_res = client.post(
        f"{settings.API_V1_PREFIX}/auth/login",
        json={"email": email, "password": VALID_PASSWORD},
    )
    token = login_res.json()["access_token"]

    me_res = client.get(
        f"{settings.API_V1_PREFIX}/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert me_res.status_code == 200
    me_data = me_res.json()
    assert me_data["email"] == email
    assert me_data["full_name"] == "Alice Analyst"
    assert me_data["role"] == "analyst"


def test_unauthorized_requests_rejected():
    """Verify that missing or malformed JWT tokens result in HTTP 401."""
    # Missing token
    no_token_res = client.get(f"{settings.API_V1_PREFIX}/auth/me")
    assert no_token_res.status_code == 401

    # Malformed / fake token
    fake_token_res = client.get(
        f"{settings.API_V1_PREFIX}/auth/me",
        headers={"Authorization": "Bearer not.a.valid.jwt.token"},
    )
    assert fake_token_res.status_code == 401


def test_role_based_access_control():
    """Verify RBAC access permissions across admin, analyst, and viewer roles."""
    tokens = {}

    # Provision admin account directly in database (simulating system bootstrap/admin provisioning)
    admin_email = f"admin_{uuid.uuid4().hex[:6]}@example.com"
    db: Session = SessionLocal()
    try:
        admin_user = User(
            email=admin_email,
            hashed_password=hash_password(VALID_PASSWORD),
            role="admin",
            is_active=True,
        )
        db.add(admin_user)
        db.commit()
    finally:
        db.close()

    admin_login = client.post(
        f"{settings.API_V1_PREFIX}/auth/login",
        json={"email": admin_email, "password": VALID_PASSWORD},
    )
    tokens["admin"] = admin_login.json()["access_token"]

    # Register analyst and viewer via standard self-registration
    for r in ["analyst", "viewer"]:
        email = f"{r}_{uuid.uuid4().hex[:6]}@example.com"
        client.post(
            f"{settings.API_V1_PREFIX}/auth/register",
            json={"email": email, "password": VALID_PASSWORD, "role": r},
        )
        res = client.post(
            f"{settings.API_V1_PREFIX}/auth/login",
            json={"email": email, "password": VALID_PASSWORD},
        )
        tokens[r] = res.json()["access_token"]

    # 1. Admin can access admin, analyst, and viewer endpoints
    for endpoint in ["admin-only", "analyst-only", "viewer-only"]:
        res = client.get(
            f"{settings.API_V1_PREFIX}/auth/test/{endpoint}",
            headers={"Authorization": f"Bearer {tokens['admin']}"},
        )
        assert res.status_code == 200, f"Admin should have access to {endpoint}"

    # 2. Analyst can access analyst and viewer endpoints, but NOT admin
    res_admin = client.get(
        f"{settings.API_V1_PREFIX}/auth/test/admin-only",
        headers={"Authorization": f"Bearer {tokens['analyst']}"},
    )
    assert res_admin.status_code == 403

    res_analyst = client.get(
        f"{settings.API_V1_PREFIX}/auth/test/analyst-only",
        headers={"Authorization": f"Bearer {tokens['analyst']}"},
    )
    assert res_analyst.status_code == 200

    res_viewer = client.get(
        f"{settings.API_V1_PREFIX}/auth/test/viewer-only",
        headers={"Authorization": f"Bearer {tokens['analyst']}"},
    )
    assert res_viewer.status_code == 200

    # 3. Viewer can access ONLY viewer endpoint
    res_v_admin = client.get(
        f"{settings.API_V1_PREFIX}/auth/test/admin-only",
        headers={"Authorization": f"Bearer {tokens['viewer']}"},
    )
    assert res_v_admin.status_code == 403

    res_v_analyst = client.get(
        f"{settings.API_V1_PREFIX}/auth/test/analyst-only",
        headers={"Authorization": f"Bearer {tokens['viewer']}"},
    )
    assert res_v_analyst.status_code == 403

    res_v_viewer = client.get(
        f"{settings.API_V1_PREFIX}/auth/test/viewer-only",
        headers={"Authorization": f"Bearer {tokens['viewer']}"},
    )
    assert res_v_viewer.status_code == 200


def test_audit_logs_persisted_for_security_events():
    """Verify audit log records are created for security events without storing credentials."""
    db: Session = SessionLocal()
    try:
        # Check that various audit events were logged
        actions = [log.action for log in db.query(AuditLog).all()]
        assert "USER_REGISTER_SUCCESS" in actions
        assert "LOGIN_SUCCESS" in actions
        assert "LOGIN_FAILED_PASSWORD_MISMATCH" in actions
        assert "AUTHORIZATION_DENIED" in actions

        # Verify no passwords or tokens were logged in audit details
        all_logs = db.query(AuditLog).all()
        for entry in all_logs:
            details_str = str(entry.details).lower()
            assert VALID_PASSWORD.lower() not in details_str
            if "password" in entry.details:
                assert entry.details["password"] == "[REDACTED]"
            if "token" in entry.details:
                assert entry.details["token"] == "[REDACTED]"
    finally:
        db.close()

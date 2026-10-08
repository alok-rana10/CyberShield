import uuid
from unittest.mock import PropertyMock, patch
from fastapi.testclient import TestClient
import pytest
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.database import SessionLocal
from app.main import app
from app.models.audit import AuditLog
from app.models.finding import SecurityFinding
from app.models.user import User
from app.security.hashing import hash_password
from app.security.log_path import (
    InvalidLogPathStructureError,
    validate_and_resolve_log_path,
)

client = TestClient(app)
settings = get_settings()

TEST_PASSWORD = "CyberShield#2026!LogPass"


def get_token_for_role(role: str) -> str:
    """Helper to create and authenticate a user for a given role."""
    email = f"log_{role}_{uuid.uuid4().hex[:8]}@example.com"
    db: Session = SessionLocal()
    try:
        user = User(
            email=email,
            hashed_password=hash_password(TEST_PASSWORD),
            role=role,
            is_active=True,
            full_name=f"Log {role.capitalize()}",
        )
        db.add(user)
        db.commit()

        login_res = client.post(
            f"{settings.API_V1_PREFIX}/auth/login",
            json={"email": email, "password": TEST_PASSWORD},
        )
        assert login_res.status_code == 200, "Login failed in test setup"
        return login_res.json()["access_token"]
    finally:
        db.close()


def test_logs_unauthenticated_rejected():
    """Verify unauthenticated requests to log endpoints return HTTP 401."""
    res = client.post(
        f"{settings.API_V1_PREFIX}/logs/analyze",
        json={"path": "/some/log.txt"},
    )
    assert res.status_code == 401


def test_logs_viewer_forbidden_from_analyze():
    """Verify viewer cannot initiate log analysis (HTTP 403)."""
    token = get_token_for_role("viewer")
    res = client.post(
        f"{settings.API_V1_PREFIX}/logs/analyze",
        headers={"Authorization": f"Bearer {token}"},
        json={"path": "./logs/auth.log"},
    )
    assert res.status_code == 403
    assert "Insufficient permissions" in res.json()["detail"]


def test_logs_viewer_allowed_to_view_events_and_summary():
    """Verify viewer role can inspect events, summary, and roots."""
    token = get_token_for_role("viewer")
    headers = {"Authorization": f"Bearer {token}"}

    res_events = client.get(f"{settings.API_V1_PREFIX}/logs/events", headers=headers)
    assert res_events.status_code == 200
    assert "items" in res_events.json()

    res_summary = client.get(f"{settings.API_V1_PREFIX}/logs/summary", headers=headers)
    assert res_summary.status_code == 200
    assert "total_events" in res_summary.json()

    res_roots = client.get(f"{settings.API_V1_PREFIX}/logs/roots", headers=headers)
    assert res_roots.status_code == 200
    assert "allowed_roots" in res_roots.json()


def test_logs_unauthorized_path_rejected(tmp_path):
    """Verify target log path outside authorized roots is rejected (HTTP 403)."""
    token = get_token_for_role("analyst")
    headers = {"Authorization": f"Bearer {token}"}

    allowed_dir = tmp_path / "allowed_logs"
    allowed_dir.mkdir()
    unauthorized_file = tmp_path / "secret_system.log"
    unauthorized_file.write_text("system event", encoding="utf-8")

    with patch.object(
        Settings,
        "log_allowed_roots_list",
        new_callable=PropertyMock,
        return_value=[str(allowed_dir.resolve())],
    ):
        res = client.post(
            f"{settings.API_V1_PREFIX}/logs/analyze",
            headers=headers,
            json={"path": str(unauthorized_file)},
        )
        assert res.status_code == 403
        assert "outside authorized log roots" in res.json()["detail"]


def test_logs_path_traversal_rejected(tmp_path):
    """Verify path traversal sequence attempting escape is rejected."""
    token = get_token_for_role("analyst")
    headers = {"Authorization": f"Bearer {token}"}

    allowed_dir = tmp_path / "allowed_logs"
    allowed_dir.mkdir()
    secret_file = tmp_path / "outside.log"
    secret_file.write_text("top secret", encoding="utf-8")

    traversal_path = str(allowed_dir / ".." / "outside.log")

    with patch.object(
        Settings,
        "log_allowed_roots_list",
        new_callable=PropertyMock,
        return_value=[str(allowed_dir.resolve())],
    ):
        res = client.post(
            f"{settings.API_V1_PREFIX}/logs/analyze",
            headers=headers,
            json={"path": traversal_path},
        )
        assert res.status_code == 403
        assert "outside authorized log roots" in res.json()["detail"]


def test_logs_prefix_confusion_rejected(tmp_path):
    """Verify prefix confusion (e.g. /logs vs /logs_evil) is strictly prevented."""
    token = get_token_for_role("analyst")
    headers = {"Authorization": f"Bearer {token}"}

    allowed_dir = tmp_path / "allowed_logs"
    allowed_dir.mkdir()
    evil_dir = tmp_path / "allowed_logs_evil"
    evil_dir.mkdir()
    evil_file = evil_dir / "injected.log"
    evil_file.write_text("evil log line", encoding="utf-8")

    with patch.object(
        Settings,
        "log_allowed_roots_list",
        new_callable=PropertyMock,
        return_value=[str(allowed_dir.resolve())],
    ):
        res = client.post(
            f"{settings.API_V1_PREFIX}/logs/analyze",
            headers=headers,
            json={"path": str(evil_file)},
        )
        assert res.status_code == 403
        assert "outside authorized log roots" in res.json()["detail"]


def test_logs_symlink_escape_rejected(tmp_path):
    """Verify symlink pointing outside authorized root is rejected."""
    token = get_token_for_role("analyst")
    headers = {"Authorization": f"Bearer {token}"}

    allowed_dir = tmp_path / "allowed_logs"
    allowed_dir.mkdir()
    external_secret = tmp_path / "sensitive.log"
    external_secret.write_text("unauthorized data", encoding="utf-8")

    link_path = allowed_dir / "symlink.log"
    try:
        link_path.symlink_to(external_secret)
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation not supported in current environment.")

    with patch.object(
        Settings,
        "log_allowed_roots_list",
        new_callable=PropertyMock,
        return_value=[str(allowed_dir.resolve())],
    ):
        res = client.post(
            f"{settings.API_V1_PREFIX}/logs/analyze",
            headers=headers,
            json={"path": str(link_path)},
        )
        assert res.status_code == 403
        assert "outside authorized log roots" in res.json()["detail"]


def test_logs_directory_passed_as_file_rejected(tmp_path):
    """Verify directory path is rejected when regular log file is required (HTTP 400)."""
    token = get_token_for_role("analyst")
    headers = {"Authorization": f"Bearer {token}"}

    allowed_dir = tmp_path / "allowed_logs"
    allowed_dir.mkdir()
    sub_dir = allowed_dir / "directory_target"
    sub_dir.mkdir()

    with patch.object(
        Settings,
        "log_allowed_roots_list",
        new_callable=PropertyMock,
        return_value=[str(allowed_dir.resolve())],
    ):
        res = client.post(
            f"{settings.API_V1_PREFIX}/logs/analyze",
            headers=headers,
            json={"path": str(sub_dir)},
        )
        assert res.status_code == 400
        assert "is a directory" in res.json()["detail"]


def test_logs_nonexistent_file_rejected(tmp_path):
    """Verify nonexistent log file returns HTTP 404."""
    token = get_token_for_role("analyst")
    headers = {"Authorization": f"Bearer {token}"}

    allowed_dir = tmp_path / "allowed_logs"
    allowed_dir.mkdir()
    missing_file = allowed_dir / "does_not_exist.log"

    with patch.object(
        Settings,
        "log_allowed_roots_list",
        new_callable=PropertyMock,
        return_value=[str(allowed_dir.resolve())],
    ):
        res = client.post(
            f"{settings.API_V1_PREFIX}/logs/analyze",
            headers=headers,
            json={"path": str(missing_file)},
        )
        assert res.status_code == 404
        assert "does not exist" in res.json()["detail"]


def test_logs_invalid_path_structure():
    """Verify null bytes or control characters in path are rejected."""
    with pytest.raises(InvalidLogPathStructureError, match="null bytes"):
        validate_and_resolve_log_path(
            raw_path="/logs/auth\0.log",
            allowed_roots=["/logs"],
            must_exist=False,
        )


def test_logs_oversized_file_rejected(tmp_path):
    """Verify files exceeding maximum size bound are rejected with HTTP 413."""
    token = get_token_for_role("analyst")
    headers = {"Authorization": f"Bearer {token}"}

    allowed_dir = tmp_path / "allowed_logs"
    allowed_dir.mkdir()
    large_file = allowed_dir / "huge.log"
    large_file.write_text("A" * 1000, encoding="utf-8")

    with (
        patch.object(
            Settings,
            "log_allowed_roots_list",
            new_callable=PropertyMock,
            return_value=[str(allowed_dir.resolve())],
        ),
        patch.object(get_settings(), "LOG_MAX_FILE_SIZE_BYTES", 500),
    ):
        res = client.post(
            f"{settings.API_V1_PREFIX}/logs/analyze",
            headers=headers,
            json={"path": str(large_file)},
        )
        assert res.status_code == 413
        assert "exceeds maximum allowed size" in res.json()["detail"]


def test_logs_long_line_handled_safely(tmp_path):
    """Verify that very long log lines are bounded safely without memory exhaustion."""
    token = get_token_for_role("analyst")
    headers = {"Authorization": f"Bearer {token}"}

    allowed_dir = tmp_path / "allowed_logs"
    allowed_dir.mkdir()
    test_file = allowed_dir / "long_line.log"

    # Line of 10,000 characters
    long_line = "2026-10-08 09:00:00 [INFO] User admin logged in " + ("X" * 10000) + "\n"
    test_file.write_text(long_line, encoding="utf-8")

    with patch.object(
        Settings,
        "log_allowed_roots_list",
        new_callable=PropertyMock,
        return_value=[str(allowed_dir.resolve())],
    ):
        res = client.post(
            f"{settings.API_V1_PREFIX}/logs/analyze",
            headers=headers,
            json={"path": str(test_file)},
        )
        assert res.status_code == 200
        data = res.json()
        assert data["lines_read"] == 1
        assert data["events_parsed_count"] == 1
        # Raw message in event is safely capped at 500 characters
        assert len(data["events"][0]["raw_message"]) <= 500


def test_logs_malformed_lines_handled_safely(tmp_path):
    """Verify that corrupt lines and empty lines are handled without error."""
    token = get_token_for_role("analyst")
    headers = {"Authorization": f"Bearer {token}"}

    allowed_dir = tmp_path / "allowed_logs"
    allowed_dir.mkdir()
    test_file = allowed_dir / "corrupted.log"

    content = (
        "\n\n   \n"
        "Random unparseable garbage !!!@@@###$$$%%%\n"
        "2026-10-08 09:10:00 [ERROR] Authentication failure for user 'alice': invalid password\n"
        "More non-standard text\n"
    )
    test_file.write_text(content, encoding="utf-8")

    with patch.object(
        Settings,
        "log_allowed_roots_list",
        new_callable=PropertyMock,
        return_value=[str(allowed_dir.resolve())],
    ):
        res = client.post(
            f"{settings.API_V1_PREFIX}/logs/analyze",
            headers=headers,
            json={"path": str(test_file)},
        )
        assert res.status_code == 200
        data = res.json()
        assert data["lines_read"] == 6
        assert data["events_parsed_count"] >= 1


def test_logs_detect_brute_force_and_generate_finding(tmp_path):
    """Verify repeated failed authentication attempts trigger High finding (CWE-307)."""
    token = get_token_for_role("analyst")
    headers = {"Authorization": f"Bearer {token}"}

    allowed_dir = tmp_path / "allowed_logs"
    allowed_dir.mkdir()
    auth_log = allowed_dir / "auth.log"

    # 6 failed SSH password attempts from same IP (threshold is 5)
    lines = [
        f"Oct  8 09:00:0{i} server sshd[100{i}]: Failed password for invalid user admin "
        f"from 198.51.100.25 port {40000 + i} ssh2\n"
        for i in range(6)
    ]
    auth_log.write_text("".join(lines), encoding="utf-8")

    with patch.object(
        Settings,
        "log_allowed_roots_list",
        new_callable=PropertyMock,
        return_value=[str(allowed_dir.resolve())],
    ):
        res = client.post(
            f"{settings.API_V1_PREFIX}/logs/analyze",
            headers=headers,
            json={"path": str(auth_log)},
        )
        assert res.status_code == 200
        data = res.json()
        assert data["events_parsed_count"] == 6
        assert data["created_findings_count"] >= 1

        finding_id = data["created_finding_ids"][0]
        db: Session = SessionLocal()
        try:
            finding = db.query(SecurityFinding).filter(SecurityFinding.id == finding_id).first()
            assert finding is not None
            assert finding.severity == "high"
            assert finding.category == "authentication"
            assert finding.source_module == "log_analyzer"
            assert finding.cwe_id == "CWE-307"
            assert "198.51.100.25" in finding.title
        finally:
            db.close()


def test_logs_detect_web_probing_and_generate_finding(tmp_path):
    """Verify reconnaissance web path probes trigger Medium finding (CWE-200)."""
    token = get_token_for_role("analyst")
    headers = {"Authorization": f"Bearer {token}"}

    allowed_dir = tmp_path / "allowed_logs"
    allowed_dir.mkdir()
    access_log = allowed_dir / "access.log"

    lines = (
        '192.0.2.75 - - [08/Oct/2026:09:01:00 +0000] "GET /.env HTTP/1.1" 404 150\n'
        '192.0.2.75 - - [08/Oct/2026:09:01:02 +0000] "GET /wp-admin/setup.php HTTP/1.1" 404 150\n'
        '192.0.2.75 - - [08/Oct/2026:09:01:04 +0000] "GET /.git/config HTTP/1.1" 404 150\n'
    )
    access_log.write_text(lines, encoding="utf-8")

    with patch.object(
        Settings,
        "log_allowed_roots_list",
        new_callable=PropertyMock,
        return_value=[str(allowed_dir.resolve())],
    ):
        res = client.post(
            f"{settings.API_V1_PREFIX}/logs/analyze",
            headers=headers,
            json={"path": str(access_log)},
        )
        assert res.status_code == 200
        data = res.json()
        assert data["events_parsed_count"] == 3
        assert data["created_findings_count"] >= 1

        db: Session = SessionLocal()
        try:
            finding = (
                db.query(SecurityFinding)
                .filter(SecurityFinding.id.in_(data["created_finding_ids"]))
                .first()
            )
            assert finding is not None
            assert finding.severity == "medium"
            assert finding.category == "reconnaissance"
            assert finding.source_module == "log_analyzer"
            assert finding.cwe_id == "CWE-200"
            assert "192.0.2.75" in finding.title
        finally:
            db.close()


def test_logs_detect_access_denied_events(tmp_path):
    """Verify repeated permission denied events trigger Medium finding (CWE-285)."""
    token = get_token_for_role("analyst")
    headers = {"Authorization": f"Bearer {token}"}

    allowed_dir = tmp_path / "allowed_logs"
    allowed_dir.mkdir()
    sys_log = allowed_dir / "system.log"

    lines = (
        "2026-10-08 09:05:01 [WARNING] Access denied: user 'bob' attempted unauthorized action\n"
        "2026-10-08 09:05:02 [WARNING] Permission denied: user 'bob' tried reading /etc/shadow\n"
        "2026-10-08 09:05:03 [WARNING] Access denied: user 'charlie' tried /admin/portal\n"
    )
    sys_log.write_text(lines, encoding="utf-8")

    with patch.object(
        Settings,
        "log_allowed_roots_list",
        new_callable=PropertyMock,
        return_value=[str(allowed_dir.resolve())],
    ):
        res = client.post(
            f"{settings.API_V1_PREFIX}/logs/analyze",
            headers=headers,
            json={"path": str(sys_log)},
        )
        assert res.status_code == 200
        data = res.json()
        assert data["events_parsed_count"] == 3
        assert data["created_findings_count"] >= 1

        db: Session = SessionLocal()
        try:
            finding = (
                db.query(SecurityFinding)
                .filter(SecurityFinding.id.in_(data["created_finding_ids"]))
                .first()
            )
            assert finding is not None
            assert finding.severity == "medium"
            assert finding.category == "access_control"
            assert finding.cwe_id == "CWE-285"
        finally:
            db.close()


def test_logs_audit_logging_recorded(tmp_path):
    """Verify audit logs are persisted for log analysis actions."""
    token = get_token_for_role("analyst")
    headers = {"Authorization": f"Bearer {token}"}

    allowed_dir = tmp_path / "allowed_logs"
    allowed_dir.mkdir()
    sample_log = allowed_dir / "test.log"
    sample_log.write_text("2026-10-08 09:00:00 [INFO] System booted\n", encoding="utf-8")

    with patch.object(
        Settings,
        "log_allowed_roots_list",
        new_callable=PropertyMock,
        return_value=[str(allowed_dir.resolve())],
    ):
        res = client.post(
            f"{settings.API_V1_PREFIX}/logs/analyze",
            headers=headers,
            json={"path": str(sample_log)},
        )
        assert res.status_code == 200

        db: Session = SessionLocal()
        try:
            started_audit = (
                db.query(AuditLog)
                .filter(AuditLog.action == "LOG_ANALYSIS_STARTED")
                .order_by(AuditLog.created_at.desc())
                .first()
            )
            completed_audit = (
                db.query(AuditLog)
                .filter(AuditLog.action == "LOG_ANALYSIS_COMPLETED")
                .order_by(AuditLog.created_at.desc())
                .first()
            )
            assert started_audit is not None
            assert completed_audit is not None
            assert completed_audit.details.get("lines_read") == 1
        finally:
            db.close()


def test_logs_get_single_event_and_not_found(tmp_path):
    """Verify GET /events/{id} returns 200 for existing event and 404 for missing."""
    token = get_token_for_role("analyst")
    headers = {"Authorization": f"Bearer {token}"}

    allowed_dir = tmp_path / "allowed_logs"
    allowed_dir.mkdir()
    sample_log = allowed_dir / "single.log"
    sample_log.write_text("2026-10-08 09:00:00 [INFO] Test single event\n", encoding="utf-8")

    with patch.object(
        Settings,
        "log_allowed_roots_list",
        new_callable=PropertyMock,
        return_value=[str(allowed_dir.resolve())],
    ):
        res = client.post(
            f"{settings.API_V1_PREFIX}/logs/analyze",
            headers=headers,
            json={"path": str(sample_log)},
        )
        assert res.status_code == 200
        event_id = res.json()["events"][0]["id"]

        # Fetch existing
        res_single = client.get(
            f"{settings.API_V1_PREFIX}/logs/events/{event_id}",
            headers=headers,
        )
        assert res_single.status_code == 200
        assert res_single.json()["id"] == event_id

        # Fetch missing
        fake_id = str(uuid.uuid4())
        res_missing = client.get(
            f"{settings.API_V1_PREFIX}/logs/events/{fake_id}",
            headers=headers,
        )
        assert res_missing.status_code == 404

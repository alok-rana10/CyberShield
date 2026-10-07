"""Comprehensive unit tests for File Integrity Monitor (FIM), path security, and RBAC."""

import hashlib
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
from app.security.fim_path import (
    InvalidPathStructureError,
    UnauthorizedPathError,
    validate_and_resolve_fim_path,
)
from app.security.hashing import hash_password

client = TestClient(app)
settings = get_settings()

TEST_PASSWORD = "CyberShield#2026!FimPass"


def get_token_for_role(role: str) -> str:
    """Helper to create and authenticate a user for a given role."""
    email = f"fim_{role}_{uuid.uuid4().hex[:8]}@example.com"
    db: Session = SessionLocal()
    try:
        user = User(
            email=email,
            hashed_password=hash_password(TEST_PASSWORD),
            role=role,
            is_active=True,
            full_name=f"FIM {role.capitalize()}",
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


def test_fim_unauthenticated_rejected():
    """Verify that unauthenticated requests to FIM endpoints return HTTP 401."""
    res = client.post(
        f"{settings.API_V1_PREFIX}/fim/baselines",
        json={"path": "/some/path"},
    )
    assert res.status_code == 401


def test_fim_viewer_forbidden_from_baselines_and_checks(tmp_path):
    """Verify that Viewer role cannot create baselines or execute checks (HTTP 403)."""
    token = get_token_for_role("viewer")
    headers = {"Authorization": f"Bearer {token}"}

    res_base = client.post(
        f"{settings.API_V1_PREFIX}/fim/baselines",
        json={"path": str(tmp_path)},
        headers=headers,
    )
    assert res_base.status_code == 403

    res_check = client.post(
        f"{settings.API_V1_PREFIX}/fim/check",
        json={"path": str(tmp_path)},
        headers=headers,
    )
    assert res_check.status_code == 403


def test_fim_viewer_allowed_to_view_status_and_records():
    """Verify that Viewer role has read-only access to view FIM status and records."""
    token = get_token_for_role("viewer")
    headers = {"Authorization": f"Bearer {token}"}

    res_status = client.get(
        f"{settings.API_V1_PREFIX}/fim/status",
        headers=headers,
    )
    assert res_status.status_code == 200
    assert "total_monitored_files" in res_status.json()

    res_records = client.get(
        f"{settings.API_V1_PREFIX}/fim/records",
        headers=headers,
    )
    assert res_records.status_code == 200
    assert "items" in res_records.json()

    res_roots = client.get(
        f"{settings.API_V1_PREFIX}/fim/roots",
        headers=headers,
    )
    assert res_roots.status_code == 200
    assert "allowed_roots" in res_roots.json()


def test_fim_unauthorized_path_rejected(tmp_path):
    """Verify that paths outside configured authorized roots are rejected with HTTP 403."""
    token = get_token_for_role("analyst")
    allowed_root = tmp_path / "authorized_dir"
    allowed_root.mkdir()

    outside_dir = tmp_path / "outside_dir"
    outside_dir.mkdir()

    with patch.object(
        Settings,
        "fim_allowed_roots_list",
        new_callable=PropertyMock,
        return_value=[str(allowed_root)],
    ):
        res = client.post(
            f"{settings.API_V1_PREFIX}/fim/baselines",
            json={"path": str(outside_dir)},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert res.status_code == 403
        assert "outside authorized monitoring roots" in res.json()["detail"].lower()


def test_fim_path_traversal_rejected(tmp_path):
    """Verify that path traversal using '..' pointing outside allowed root is blocked."""
    token = get_token_for_role("analyst")
    allowed_root = tmp_path / "authorized_dir"
    allowed_root.mkdir()

    traversal_path = str(allowed_root) + "/../secret.txt"

    with patch.object(
        Settings,
        "fim_allowed_roots_list",
        new_callable=PropertyMock,
        return_value=[str(allowed_root)],
    ):
        res = client.post(
            f"{settings.API_V1_PREFIX}/fim/baselines",
            json={"path": traversal_path},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert res.status_code in (403, 404)


def test_fim_prefix_confusion_rejected():
    """Verify that prefix confusion (/root vs /root_evil) is strictly prevented."""
    allowed_root = "/var/log/cybershield"
    evil_path = "/var/log/cybershield_evil"

    with pytest.raises(UnauthorizedPathError):
        validate_and_resolve_fim_path(evil_path, allowed_roots=[allowed_root])


def test_fim_invalid_path_structure():
    """Verify that paths with null bytes or empty strings are rejected."""
    with pytest.raises(InvalidPathStructureError):
        validate_and_resolve_fim_path("", allowed_roots=["/some/root"])

    with pytest.raises(InvalidPathStructureError):
        validate_and_resolve_fim_path("/path/\0/evil", allowed_roots=["/some/root"])


def test_fim_baseline_creation_and_unchanged_check(tmp_path):
    """Verify baseline creation and clean integrity verification for unchanged files."""
    token = get_token_for_role("analyst")
    headers = {"Authorization": f"Bearer {token}"}

    # Setup files in allowed root
    root_dir = tmp_path / "monitored_area"
    root_dir.mkdir()
    file_a = root_dir / "config.ini"
    file_a.write_text("setting=value_1", encoding="utf-8")
    file_b = root_dir / "app.py"
    file_b.write_text("print('hello')", encoding="utf-8")

    expected_hash_a = hashlib.sha256(b"setting=value_1").hexdigest()

    with patch.object(
        Settings,
        "fim_allowed_roots_list",
        new_callable=PropertyMock,
        return_value=[str(root_dir)],
    ):
        # 1. Create baseline
        res_base = client.post(
            f"{settings.API_V1_PREFIX}/fim/baselines",
            json={"path": str(root_dir)},
            headers=headers,
        )
        assert res_base.status_code == 201
        data = res_base.json()
        assert data["files_baselined_count"] == 2
        assert data["total_size_bytes"] > 0
        assert len(data["records"]) == 2

        # Verify hash of file_a in records
        rec_a = next(r for r in data["records"] if "config.ini" in r["monitored_path"])
        assert rec_a["baseline_hash"] == expected_hash_a
        assert rec_a["status"] == "baseline"

        # 2. Run integrity check without modifying files
        res_check = client.post(
            f"{settings.API_V1_PREFIX}/fim/check",
            json={"path": str(root_dir)},
            headers=headers,
        )
        assert res_check.status_code == 200
        check_data = res_check.json()
        assert check_data["total_files"] == 2
        assert check_data["unchanged_count"] == 2
        assert check_data["modified_count"] == 0
        assert check_data["added_count"] == 0
        assert check_data["deleted_count"] == 0
        assert check_data["created_findings_count"] == 0


def test_fim_detect_modified_file_and_generate_finding(tmp_path):
    """Verify modifying a baselined file triggers 'modified' state & High finding."""
    token = get_token_for_role("analyst")
    headers = {"Authorization": f"Bearer {token}"}

    root_dir = tmp_path / "monitored_area"
    root_dir.mkdir()
    file_a = root_dir / "protected.conf"
    file_a.write_text("original_content", encoding="utf-8")

    with patch.object(
        Settings,
        "fim_allowed_roots_list",
        new_callable=PropertyMock,
        return_value=[str(root_dir)],
    ):
        # Baseline
        client.post(
            f"{settings.API_V1_PREFIX}/fim/baselines",
            json={"path": str(root_dir)},
            headers=headers,
        )

        # Modify file
        file_a.write_text("tampered_content_malicious", encoding="utf-8")

        # Check
        res_check = client.post(
            f"{settings.API_V1_PREFIX}/fim/check",
            json={"path": str(root_dir)},
            headers=headers,
        )
        assert res_check.status_code == 200
        check_data = res_check.json()
        assert check_data["modified_count"] == 1
        assert check_data["created_findings_count"] >= 1

        rec = check_data["records"][0]
        assert rec["status"] == "modified"
        assert rec["current_hash"] != rec["baseline_hash"]

        # Verify Finding was generated in database
        db = SessionLocal()
        try:
            finding_id = check_data["created_finding_ids"][0]
            f = db.query(SecurityFinding).filter(SecurityFinding.id == finding_id).first()
            assert f is not None
            assert f.category == "file_integrity"
            assert f.source_module == "fim"
            assert f.severity.lower() == "high"
            assert "protected.conf" in f.title
        finally:
            db.close()


def test_fim_detect_added_file_and_generate_finding(tmp_path):
    """Verify that creating a new unbaselined file triggers 'added' state and Medium finding."""
    token = get_token_for_role("analyst")
    headers = {"Authorization": f"Bearer {token}"}

    root_dir = tmp_path / "monitored_area"
    root_dir.mkdir()
    file_a = root_dir / "existing.txt"
    file_a.write_text("baseline_text", encoding="utf-8")

    with patch.object(
        Settings,
        "fim_allowed_roots_list",
        new_callable=PropertyMock,
        return_value=[str(root_dir)],
    ):
        # Baseline
        client.post(
            f"{settings.API_V1_PREFIX}/fim/baselines",
            json={"path": str(root_dir)},
            headers=headers,
        )

        # Introduce unexpected file
        file_new = root_dir / "unauthorized_script.sh"
        file_new.write_text("#!/bin/sh\necho test", encoding="utf-8")

        # Check
        res_check = client.post(
            f"{settings.API_V1_PREFIX}/fim/check",
            json={"path": str(root_dir)},
            headers=headers,
        )
        assert res_check.status_code == 200
        check_data = res_check.json()
        assert check_data["added_count"] == 1

        added_rec = next(
            r for r in check_data["records"] if "unauthorized_script.sh" in r["monitored_path"]
        )
        assert added_rec["status"] == "added"


def test_fim_detect_deleted_file_and_generate_finding(tmp_path):
    """Verify that deleting a baselined file triggers 'deleted' state and High severity finding."""
    token = get_token_for_role("analyst")
    headers = {"Authorization": f"Bearer {token}"}

    root_dir = tmp_path / "monitored_area"
    root_dir.mkdir()
    file_a = root_dir / "critical.key"
    file_a.write_text("dummy_key_data", encoding="utf-8")

    with patch.object(
        Settings,
        "fim_allowed_roots_list",
        new_callable=PropertyMock,
        return_value=[str(root_dir)],
    ):
        # Baseline
        client.post(
            f"{settings.API_V1_PREFIX}/fim/baselines",
            json={"path": str(root_dir)},
            headers=headers,
        )

        # Delete file
        file_a.unlink()

        # Check
        res_check = client.post(
            f"{settings.API_V1_PREFIX}/fim/check",
            json={"path": str(root_dir)},
            headers=headers,
        )
        assert res_check.status_code == 200
        check_data = res_check.json()
        assert check_data["deleted_count"] == 1

        del_rec = check_data["records"][0]
        assert del_rec["status"] == "deleted"
        assert del_rec["current_hash"] is None


def test_fim_file_too_large_rejected(tmp_path):
    """Verify that files exceeding the configured size limit are rejected with HTTP 413."""
    token = get_token_for_role("analyst")
    headers = {"Authorization": f"Bearer {token}"}

    root_dir = tmp_path / "monitored_area"
    root_dir.mkdir()
    large_file = root_dir / "oversized.bin"
    large_file.write_bytes(b"A" * 1024)

    # Set artificial cap of 500 bytes
    with patch.object(
        Settings,
        "fim_allowed_roots_list",
        new_callable=PropertyMock,
        return_value=[str(root_dir)],
    ):
        with patch.object(
            get_settings(),
            "FIM_MAX_FILE_SIZE_BYTES",
            500,
        ):
            res = client.post(
                f"{settings.API_V1_PREFIX}/fim/baselines",
                json={"path": str(large_file)},
                headers=headers,
            )
            assert res.status_code == 413
            assert "exceeds maximum allowed size" in res.json()["detail"].lower()


def test_fim_audit_logging(tmp_path):
    """Verify that FIM operations record appropriate AuditLog entries in the database."""
    token = get_token_for_role("analyst")
    headers = {"Authorization": f"Bearer {token}"}

    root_dir = tmp_path / "monitored_area"
    root_dir.mkdir()
    sample_file = root_dir / "audit_test.txt"
    sample_file.write_text("audit_check", encoding="utf-8")

    with patch.object(
        Settings,
        "fim_allowed_roots_list",
        new_callable=PropertyMock,
        return_value=[str(root_dir)],
    ):
        # Baseline
        client.post(
            f"{settings.API_V1_PREFIX}/fim/baselines",
            json={"path": str(root_dir)},
            headers=headers,
        )

        # Check
        client.post(
            f"{settings.API_V1_PREFIX}/fim/check",
            json={"path": str(root_dir)},
            headers=headers,
        )

        # Unauthorized attempt
        client.post(
            f"{settings.API_V1_PREFIX}/fim/baselines",
            json={"path": "/unauthorized/system/etc"},
            headers=headers,
        )

    db = SessionLocal()
    try:
        actions = {
            a[0] for a in db.query(AuditLog.action).filter(AuditLog.resource_type == "FIM").all()
        }
        assert "FIM_BASELINE_CREATED" in actions
        assert "FIM_CHECK_STARTED" in actions
        assert "FIM_CHECK_COMPLETED" in actions
        assert "FIM_UNAUTHORIZED_PATH_REJECTED" in actions
    finally:
        db.close()

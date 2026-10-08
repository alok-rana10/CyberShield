"""Authorized Path Restriction and Validation for Defensive Log Analyzer."""

from pathlib import Path
from typing import List


class LogPathSecurityError(Exception):
    """Base exception for Log path security violations."""

    pass


class UnauthorizedLogPathError(LogPathSecurityError):
    """Raised when target log path lies outside configured authorized roots."""

    pass


class InvalidLogPathStructureError(LogPathSecurityError):
    """Raised when path syntax, traversal sequences, or directories are detected."""

    pass


class LogFileTooLargeError(LogPathSecurityError):
    """Raised when target log file exceeds the configured maximum byte limit."""

    pass


def validate_and_resolve_log_path(
    raw_path: str,
    allowed_roots: List[str],
    max_file_size_bytes: int = 52428800,
    must_exist: bool = True,
) -> Path:
    """Validate, canonicalize, and verify containment of log files within authorized roots.

    Security Guarantees:
    - Rejects empty paths, null bytes, and control characters.
    - Resolves canonical real path (normalizing '.', '..', and symlinks).
    - Verifies canonical path is strictly inside at least one authorized log root (is_relative_to).
    - Defeats prefix confusion (e.g., /logs vs /logs_evil).
    - Defeats symlink escape attacks: symlinks pointing outside roots are rejected.
    - Enforces regular file validation: directories are strictly rejected with an explicit error.
    - Enforces file existence and maximum file size bounds.
    """
    if not raw_path or not isinstance(raw_path, str):
        raise InvalidLogPathStructureError("Path must be a non-empty string.")

    cleaned = raw_path.strip()

    # Reject null bytes or control characters
    if "\0" in cleaned or any(ord(c) < 32 for c in cleaned):
        raise InvalidLogPathStructureError(
            "Path contains null bytes or invalid control characters."
        )

    if not allowed_roots:
        raise UnauthorizedLogPathError("No authorized log monitoring roots configured on system.")

    # Canonicalize candidate path
    try:
        resolved_candidate = Path(cleaned).resolve()
    except Exception as exc:
        raise InvalidLogPathStructureError(f"Failed to resolve path structure: {exc}")

    # Verify containment against allowed roots using true Path hierarchy (not string prefix)
    is_authorized = False
    for root_str in allowed_roots:
        try:
            resolved_root = Path(root_str).resolve()
            if resolved_candidate.is_relative_to(resolved_root):
                is_authorized = True
                break
        except (ValueError, OSError):
            continue

    if not is_authorized:
        raise UnauthorizedLogPathError(
            f"Access denied: Path '{cleaned}' is outside authorized log roots."
        )

    # Check existence if required
    if must_exist:
        if not resolved_candidate.exists():
            raise FileNotFoundError(f"Log file does not exist on filesystem: '{cleaned}'")

        # Explicitly reject directories when a file is expected
        if resolved_candidate.is_dir():
            raise InvalidLogPathStructureError(
                f"Path '{cleaned}' is a directory; a regular log file is required."
            )

        # Ensure it is a regular file (reject sockets, pipes, devices)
        if not resolved_candidate.is_file():
            raise InvalidLogPathStructureError(f"Path '{cleaned}' is not a regular file.")

        # Check maximum file size bound
        try:
            file_size = resolved_candidate.stat().st_size
            if file_size > max_file_size_bytes:
                raise LogFileTooLargeError(
                    f"Log file '{cleaned}' ({file_size} bytes) exceeds maximum "
                    f"allowed size of {max_file_size_bytes} bytes."
                )
        except OSError as exc:
            raise InvalidLogPathStructureError(f"Unable to read file metadata: {exc}")

    return resolved_candidate

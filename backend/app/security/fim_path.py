"""Authorized Path Restriction and Validation for File Integrity Monitoring."""

from pathlib import Path
from typing import List


class FIMPathSecurityError(Exception):
    """Base exception for FIM path security violations."""

    pass


class UnauthorizedPathError(FIMPathSecurityError):
    """Raised when target path lies outside configured authorized roots."""

    pass


class InvalidPathStructureError(FIMPathSecurityError):
    """Raised when path syntax, traversal sequences, or null bytes are detected."""

    pass


def validate_and_resolve_fim_path(
    raw_path: str,
    allowed_roots: List[str],
    must_exist: bool = False,
) -> Path:
    """Validate, canonicalize, and verify containment within authorized roots.

    Guarantees:
    - Rejection of empty paths, null bytes, and control characters.
    - Resolution of canonical real path (normalizing '.', '..', and symlinks).
    - Verification that canonical path is strictly inside at least one authorized root.
    - True path hierarchy containment to prevent prefix confusion (e.g., /root vs /root_evil).
    - Symlink escape prevention: resolved destination must be relative to authorized root.
    """
    if not raw_path or not isinstance(raw_path, str):
        raise InvalidPathStructureError("Path must be a non-empty string.")

    cleaned = raw_path.strip()

    # Reject null bytes or control characters
    if "\0" in cleaned or any(ord(c) < 32 for c in cleaned):
        raise InvalidPathStructureError("Path contains null bytes or invalid control characters.")

    if not allowed_roots:
        raise UnauthorizedPathError("No authorized monitoring roots configured on system.")

    # Canonicalize candidate path
    try:
        resolved_candidate = Path(cleaned).resolve()
    except Exception as exc:
        raise InvalidPathStructureError(f"Failed to resolve path structure: {exc}")

    # Check existence if required
    if must_exist and not resolved_candidate.exists():
        raise FileNotFoundError(f"Path does not exist on filesystem: '{cleaned}'")

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
        raise UnauthorizedPathError(
            f"Access denied: Path '{cleaned}' is outside authorized monitoring roots."
        )

    return resolved_candidate

"""Audit logging utility for non-repudiation and defensive compliance."""

import re
from typing import Any, Dict
from sqlalchemy.orm import Session
from fastapi import Request

from app.models.audit import AuditLog

# Sensitive keys that must NEVER be persisted in audit log details
SENSITIVE_KEY_PATTERN = re.compile(
    r"(password|token|secret|authorization|credential|api_key|hash)",
    re.IGNORECASE,
)


def sanitize_audit_details(details: Dict[str, Any] | None) -> Dict[str, Any]:
    """Sanitize details dictionary to redact any sensitive credentials or tokens."""
    if not details:
        return {}

    sanitized: Dict[str, Any] = {}
    for key, value in details.items():
        if SENSITIVE_KEY_PATTERN.search(key):
            sanitized[key] = "[REDACTED]"
        elif isinstance(value, dict):
            sanitized[key] = sanitize_audit_details(value)
        else:
            sanitized[key] = value

    return sanitized


def get_client_ip(request: Request) -> str:
    """Extract client IP address safely from request headers or socket."""
    # Check X-Forwarded-For header
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client and request.client.host:
        return request.client.host
    return "127.0.0.1"


def get_user_agent(request: Request) -> str:
    """Extract User-Agent safely with length cap."""
    ua = request.headers.get("user-agent", "Unknown")
    return ua[:500] if ua else "Unknown"


def record_audit_log(
    db: Session,
    action: str,
    resource_type: str,
    status_code: int,
    ip_address: str,
    user_id: str | None = None,
    resource_id: str | None = None,
    user_agent: str | None = None,
    details: Dict[str, Any] | None = None,
) -> AuditLog:
    """Record an immutable audit log entry into the database.

    Guarantees no plaintext credentials or sensitive secrets are stored.
    """
    clean_details = sanitize_audit_details(details)

    audit_entry = AuditLog(
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        ip_address=ip_address,
        user_agent=user_agent,
        status_code=status_code,
        details=clean_details,
    )
    db.add(audit_entry)
    db.commit()
    db.refresh(audit_entry)
    return audit_entry

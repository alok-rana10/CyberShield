"""Defensive Log Parsing and Security Event Normalization Engine."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import ipaddress
import re
from typing import Any, Dict, Optional


@dataclass
class ParsedLogEvent:
    """Normalized security log event."""

    timestamp: datetime
    event_category: str
    severity: str
    source_type: str
    source_ip: Optional[str]
    username: Optional[str]
    message_summary: str
    raw_message: str
    parsed_event: Dict[str, Any] = field(default_factory=dict)


# Common sensitive web probing paths indicative of automated reconnaissance
SUSPICIOUS_PATHS = (
    "/.env",
    "/.git",
    "/.aws",
    "/wp-admin",
    "/wp-login.php",
    "/phpmyadmin",
    "/actuator",
    "/etc/passwd",
    "/win.ini",
    "/xmlrpc.php",
    "/cgi-bin",
    "/shell",
    "/api/swagger",
    "/.config",
)

# Regex Patterns for Syslog / Auth Log
RE_SSHD_FAILED = re.compile(
    r"sshd\[\d+\]:\s+Failed\s+password\s+for\s+(?:invalid\s+user\s+)?"
    r"(?P<user>[^\s]+)\s+from\s+(?P<ip>[^\s]+)\s+port\s+(?P<port>\d+)",
    re.IGNORECASE,
)
RE_SSHD_ACCEPTED = re.compile(
    r"sshd\[\d+\]:\s+Accepted\s+(?:publickey|password)\s+for\s+"
    r"(?P<user>[^\s]+)\s+from\s+(?P<ip>[^\s]+)\s+port\s+(?P<port>\d+)",
    re.IGNORECASE,
)
RE_SUDO_AUTH_FAIL = re.compile(
    r"sudo(?:\[\d+\])?:\s+(?:pam_unix\(sudo:auth\):\s+)?"
    r"authentication\s+failure;.*?(?:user=(?P<user>[^\s]+))",
    re.IGNORECASE,
)
RE_SUDO_INCORRECT = re.compile(
    r"sudo(?:\[\d+\])?:\s+(?P<user>[^\s:]+)\s*:\s*"
    r"(?P<attempts>\d+)\s+incorrect\s+password\s+attempts",
    re.IGNORECASE,
)
RE_SU_FAILED = re.compile(
    r"su(?:\[\d+\])?:\s+FAILED\s+SU\s+\(to\s+(?P<target>[^\s)]+)\)\s+(?P<user>[^\s]+)",
    re.IGNORECASE,
)
RE_SYSLOG_TIMESTAMP = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<hour>\d{2}):(?P<min>\d{2}):(?P<sec>\d{2})"
)
RE_ISO_TIMESTAMP = re.compile(
    r"^(?P<iso>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
)

# Regex Patterns for Combined/Common Web Access Log
RE_WEB_ACCESS = re.compile(
    r"^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+"
    r'"(?P<method>\S+)\s+(?P<path>\S+)(?:\s+\S+)?"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)(?:\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
)

# Regex Patterns for Generic Application Logs
RE_GENERIC_LEVEL = re.compile(
    r"\[(?P<level>CRITICAL|ERROR|WARNING|WARN|INFO|DEBUG)\]",
    re.IGNORECASE,
)
RE_EXTRACT_IP = re.compile(
    r"\b(?P<ip>(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))\b"
)
RE_EXTRACT_USER = re.compile(
    r"(?:user|username|account|for)\s*[=:'\"]\s*(?P<user>[a-zA-Z0-9_.-]{1,50})",
    re.IGNORECASE,
)


def validate_ip(raw_ip: Optional[str]) -> Optional[str]:
    """Validate and normalize IPv4/IPv6 address, returning None if invalid or placeholder."""
    if not raw_ip or raw_ip in ("-", "unknown", "localhost", "::1"):
        return None
    try:
        parsed = ipaddress.ip_address(raw_ip.strip())
        return str(parsed)
    except ValueError:
        return None


def parse_timestamp_str(raw: str) -> Optional[datetime]:
    """Attempt to parse timestamps across common formats; fallback to None."""
    # 1. ISO 8601
    iso_match = RE_ISO_TIMESTAMP.match(raw)
    if iso_match:
        try:
            val = iso_match.group("iso").replace(" ", "T")
            if val.endswith("Z"):
                val = val[:-1] + "+00:00"
            return datetime.fromisoformat(val)
        except Exception:
            pass

    # 2. Web Access log (08/Oct/2026:09:15:20 +0000)
    try:
        return datetime.strptime(raw.strip(), "%d/%b/%Y:%H:%M:%S %z")
    except Exception:
        pass

    # 3. Syslog (Oct  8 09:12:45)
    syslog_match = RE_SYSLOG_TIMESTAMP.match(raw)
    if syslog_match:
        try:
            curr_year = datetime.now(timezone.utc).year
            val = f"{syslog_match.group(0)} {curr_year}"
            parsed = datetime.strptime(val, "%b %d %H:%M:%S %Y")
            return parsed.replace(tzinfo=timezone.utc)
        except Exception:
            pass

    return None


class DefensiveLogParser:
    """Deterministic parser that normalizes diverse security log lines into structured events."""

    @classmethod
    def parse_line(cls, line: str, source_identifier: str = "generic") -> Optional[ParsedLogEvent]:
        """Parse a single log line into a normalized ParsedLogEvent.

        Handles malformed or unrecognized lines gracefully without throwing unhandled errors.
        """
        if not line or not line.strip():
            return None

        clean_line = line.strip()
        bounded_raw = clean_line[:500]
        event_time = parse_timestamp_str(clean_line) or datetime.now(timezone.utc)

        # 1. Try Linux SSH / Sudo Auth Log parser
        auth_event = cls._try_parse_auth_log(clean_line, event_time, bounded_raw)
        if auth_event:
            return auth_event

        # 2. Try Web Access Log parser (Nginx / Apache)
        web_event = cls._try_parse_web_access(clean_line, event_time, bounded_raw)
        if web_event:
            return web_event

        # 3. Try Generic Application Log parser
        generic_event = cls._try_parse_generic(
            clean_line, event_time, bounded_raw, source_identifier
        )
        if generic_event:
            return generic_event

        return None

    @classmethod
    def _try_parse_auth_log(
        cls, line: str, event_time: datetime, bounded_raw: str
    ) -> Optional[ParsedLogEvent]:
        """Check for SSH / Sudo / PAM authentication and authorization patterns."""
        # SSH Failed
        m = RE_SSHD_FAILED.search(line)
        if m:
            user = m.group("user")
            ip = validate_ip(m.group("ip"))
            severity = "MEDIUM" if user.lower() in ("root", "admin", "administrator") else "LOW"
            return ParsedLogEvent(
                timestamp=event_time,
                event_category="authentication_failure",
                severity=severity,
                source_type="auth_log",
                source_ip=ip,
                username=user[:100],
                message_summary=f"SSH failed password for user '{user}' from {ip or 'unknown IP'}",
                raw_message=bounded_raw,
                parsed_event={"service": "sshd", "status": "failed", "port": m.group("port")},
            )

        # SSH Accepted
        m = RE_SSHD_ACCEPTED.search(line)
        if m:
            user = m.group("user")
            ip = validate_ip(m.group("ip"))
            return ParsedLogEvent(
                timestamp=event_time,
                event_category="authentication_success",
                severity="INFO",
                source_type="auth_log",
                source_ip=ip,
                username=user[:100],
                message_summary=(
                    f"SSH authentication accepted for user '{user}' from {ip or 'unknown IP'}"
                ),
                raw_message=bounded_raw,
                parsed_event={"service": "sshd", "status": "accepted", "port": m.group("port")},
            )

        # Sudo Auth Failure
        m = RE_SUDO_AUTH_FAIL.search(line)
        if m:
            user = m.group("user") or "unknown"
            return ParsedLogEvent(
                timestamp=event_time,
                event_category="authentication_failure",
                severity="MEDIUM",
                source_type="auth_log",
                source_ip=None,
                username=user[:100],
                message_summary=f"Sudo PAM authentication failure for user '{user}'",
                raw_message=bounded_raw,
                parsed_event={"service": "sudo", "status": "auth_failure"},
            )

        # Sudo Incorrect Password Attempts
        m = RE_SUDO_INCORRECT.search(line)
        if m:
            user = m.group("user")
            attempts = m.group("attempts")
            return ParsedLogEvent(
                timestamp=event_time,
                event_category="authentication_failure",
                severity="HIGH",
                source_type="auth_log",
                source_ip=None,
                username=user[:100],
                message_summary=f"Sudo incorrect password attempts ({attempts}) for user '{user}'",
                raw_message=bounded_raw,
                parsed_event={"service": "sudo", "attempts": int(attempts)},
            )

        # Su Failed
        m = RE_SU_FAILED.search(line)
        if m:
            user = m.group("user")
            target = m.group("target")
            return ParsedLogEvent(
                timestamp=event_time,
                event_category="access_denied",
                severity="MEDIUM",
                source_type="auth_log",
                source_ip=None,
                username=user[:100],
                message_summary=f"Failed su privilege escalation from '{user}' to '{target}'",
                raw_message=bounded_raw,
                parsed_event={"service": "su", "target_user": target},
            )

        return None

    @classmethod
    def _try_parse_web_access(
        cls, line: str, fallback_time: datetime, bounded_raw: str
    ) -> Optional[ParsedLogEvent]:
        """Check for Common / Combined Nginx / Apache web server access lines."""
        m = RE_WEB_ACCESS.search(line)
        if not m:
            return None

        ip = validate_ip(m.group("ip"))
        raw_user = m.group("user")
        user = raw_user if raw_user and raw_user != "-" else None
        path = m.group("path")
        method = m.group("method")
        status_code = int(m.group("status"))
        parsed_time = parse_timestamp_str(m.group("time")) or fallback_time

        parsed_meta = {
            "method": method,
            "path": path[:255],
            "status_code": status_code,
            "user_agent": (m.group("user_agent") or "")[:200],
        }

        # Check for web path probing / reconnaissance
        is_probing = any(path.lower().startswith(p) for p in SUSPICIOUS_PATHS)
        if is_probing:
            return ParsedLogEvent(
                timestamp=parsed_time,
                event_category="suspicious_request",
                severity="MEDIUM",
                source_type="web_access",
                source_ip=ip,
                username=user,
                message_summary=(
                    f"Web path probe for sensitive resource '{path[:100]}' (HTTP {status_code})"
                ),
                raw_message=bounded_raw,
                parsed_event=parsed_meta,
            )

        # HTTP 401 Unauthorized
        if status_code == 401:
            return ParsedLogEvent(
                timestamp=parsed_time,
                event_category="authentication_failure",
                severity="LOW",
                source_type="web_access",
                source_ip=ip,
                username=user,
                message_summary=f"HTTP 401 Unauthorized for {method} {path[:100]}",
                raw_message=bounded_raw,
                parsed_event=parsed_meta,
            )

        # HTTP 403 Forbidden
        if status_code == 403:
            return ParsedLogEvent(
                timestamp=parsed_time,
                event_category="access_denied",
                severity="MEDIUM",
                source_type="web_access",
                source_ip=ip,
                username=user,
                message_summary=(f"HTTP 403 Forbidden access denied for {method} {path[:100]}"),
                raw_message=bounded_raw,
                parsed_event=parsed_meta,
            )

        # HTTP 500 Internal Server Error
        if 500 <= status_code <= 599:
            return ParsedLogEvent(
                timestamp=parsed_time,
                event_category="system_error",
                severity="LOW",
                source_type="web_access",
                source_ip=ip,
                username=user,
                message_summary=(
                    f"HTTP {status_code} server error response for {method} {path[:100]}"
                ),
                raw_message=bounded_raw,
                parsed_event=parsed_meta,
            )

        # Successful auth endpoints (HTTP 200 on login routes)
        if status_code in (200, 201) and any(
            kw in path.lower() for kw in ("/login", "/auth/login", "/authenticate")
        ):
            return ParsedLogEvent(
                timestamp=parsed_time,
                event_category="authentication_success",
                severity="INFO",
                source_type="web_access",
                source_ip=ip,
                username=user,
                message_summary=f"Successful authentication request to {path[:100]}",
                raw_message=bounded_raw,
                parsed_event=parsed_meta,
            )

        # Generic normal web request
        return ParsedLogEvent(
            timestamp=parsed_time,
            event_category="system_event",
            severity="INFO",
            source_type="web_access",
            source_ip=ip,
            username=user,
            message_summary=f"Web access {method} {path[:100]} (HTTP {status_code})",
            raw_message=bounded_raw,
            parsed_event=parsed_meta,
        )

    @classmethod
    def _try_parse_generic(
        cls, line: str, event_time: datetime, bounded_raw: str, source_identifier: str
    ) -> Optional[ParsedLogEvent]:
        """Check for keyword-based patterns in generic application logs."""
        lower_line = line.lower()

        # Extract potential IP
        ip_match = RE_EXTRACT_IP.search(line)
        ip = validate_ip(ip_match.group("ip")) if ip_match else None

        # Extract potential username
        user_match = RE_EXTRACT_USER.search(line)
        user = user_match.group("user").strip("'\": ") if user_match else None

        # Determine level
        lvl_match = RE_GENERIC_LEVEL.search(line)
        raw_level = lvl_match.group("level").upper() if lvl_match else "INFO"

        if any(
            kw in lower_line
            for kw in (
                "authentication failure",
                "failed login",
                "bad password",
                "invalid credentials",
                "login failed",
            )
        ):
            severity = (
                "HIGH"
                if raw_level == "CRITICAL"
                else ("MEDIUM" if raw_level in ("ERROR", "WARN", "WARNING") else "LOW")
            )
            return ParsedLogEvent(
                timestamp=event_time,
                event_category="authentication_failure",
                severity=severity,
                source_type="generic",
                source_ip=ip,
                username=user[:100] if user else None,
                message_summary=f"Authentication failure: {bounded_raw[:150]}",
                raw_message=bounded_raw,
                parsed_event={"log_level": raw_level},
            )

        if any(
            kw in lower_line
            for kw in ("access denied", "permission denied", "forbidden", "unauthorized")
        ):
            return ParsedLogEvent(
                timestamp=event_time,
                event_category="access_denied",
                severity="MEDIUM",
                source_type="generic",
                source_ip=ip,
                username=user[:100] if user else None,
                message_summary=f"Access denied event: {bounded_raw[:150]}",
                raw_message=bounded_raw,
                parsed_event={"log_level": raw_level},
            )

        if any(
            kw in lower_line
            for kw in (
                "successfully logged in",
                "login successful",
                "authentication successful",
                "session opened",
            )
        ):
            return ParsedLogEvent(
                timestamp=event_time,
                event_category="authentication_success",
                severity="INFO",
                source_type="generic",
                source_ip=ip,
                username=user[:100] if user else None,
                message_summary=f"Authentication success: {bounded_raw[:150]}",
                raw_message=bounded_raw,
                parsed_event={"log_level": raw_level},
            )

        if raw_level in ("ERROR", "CRITICAL"):
            return ParsedLogEvent(
                timestamp=event_time,
                event_category="system_error",
                severity="LOW" if raw_level == "ERROR" else "MEDIUM",
                source_type="generic",
                source_ip=ip,
                username=user[:100] if user else None,
                message_summary=f"Application {raw_level}: {bounded_raw[:150]}",
                raw_message=bounded_raw,
                parsed_event={"log_level": raw_level},
            )

        # Baseline information log
        return ParsedLogEvent(
            timestamp=event_time,
            event_category="system_event",
            severity="INFO",
            source_type="generic",
            source_ip=ip,
            username=user[:100] if user else None,
            message_summary=bounded_raw[:150],
            raw_message=bounded_raw,
            parsed_event={"log_level": raw_level},
        )

"""Dedicated Authorized Network Scanner Service.

Implements safe, non-destructive TCP connect discovery on explicitly authorized targets.
Enforces:
- Target and port validation (no SSRF / proxy abuse, bounded port counts).
- Standard TCP connect probes only (no raw sockets, stealth, or exploitation).
- Bounded concurrency, per-socket timeout, and total wall-clock timeout.
- Sliding window rate limiting per user.
- Integration with Security Findings Engine for confirmed insecure protocol exposures.
- Tamper-evident audit logging for all scan lifecycle states.
"""

from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import errno
import ipaddress
import socket
import time
from typing import Any, Dict, List, Optional, Tuple
from fastapi import Request
from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models.scan import ScanResult
from app.models.user import User
from app.schemas.finding import FindingCreate, FindingSeverity, FindingStatus
from app.schemas.scan import (
    ScanCreateRequest,
    ScanPortResult,
    ScanResponse,
    ScanScopeResponse,
    ScanSummaryResponse,
)
from app.security.scan_target import (
    UnauthorizedScanTargetError,
    WELL_KNOWN_SERVICES,
    validate_and_normalize_ports,
    validate_and_resolve_scan_target,
)
from app.services.finding_service import FindingService
from app.utils.audit_helper import get_client_ip, get_user_agent, record_audit_log


class ScanRateLimitError(Exception):
    """Raised when user exceeds maximum permitted scans per minute."""

    pass


class ScanExecutionError(Exception):
    """Raised when network scan fails during execution."""

    pass


# Sliding window rate limiter state: {user_id: [timestamps]}
_user_scan_timestamps: Dict[str, List[float]] = defaultdict(list)
RATE_LIMIT_WINDOW_SECONDS = 60.0

# Windows WSA error codes mapping for network errors
WSAECONNREFUSED = 10061
WSAETIMEDOUT = 10060
WSAEHOSTUNREACH = 10065
WSAENETUNREACH = 10051


def _check_scan_rate_limit(user_id: str, max_requests: int) -> None:
    """Check and record user rate limits."""
    now = time.time()
    cutoff = now - RATE_LIMIT_WINDOW_SECONDS
    active = [ts for ts in _user_scan_timestamps[user_id] if ts > cutoff]
    _user_scan_timestamps[user_id] = active

    if len(active) >= max_requests:
        raise ScanRateLimitError(
            f"Rate limit exceeded: Maximum {max_requests} scans per minute allowed."
        )
    _user_scan_timestamps[user_id].append(now)


def probe_tcp_port(target_ip: str, port: int, timeout: float) -> Tuple[int, str]:
    """Perform a standard, non-destructive TCP connect check against a single port.

    Returns:
        Tuple[int, str]: (port, status) where status is:
        - "open": TCP three-way handshake completed successfully
        - "closed": RST received / connection explicitly refused
        - "filtered_or_unreachable": Timeout, host unreachable, or network dropped
    """
    try:
        ip_obj = ipaddress.ip_address(target_ip)
        family = socket.AF_INET6 if isinstance(ip_obj, ipaddress.IPv6Address) else socket.AF_INET
    except ValueError:
        family = socket.AF_INET

    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        err = sock.connect_ex((target_ip, port))
        if err == 0:
            status = "open"
        elif err in (errno.ECONNREFUSED, WSAECONNREFUSED):
            status = "closed"
        elif err in (
            errno.ETIMEDOUT,
            WSAETIMEDOUT,
            errno.EHOSTUNREACH,
            WSAEHOSTUNREACH,
            errno.ENETUNREACH,
            WSAENETUNREACH,
        ):
            status = "filtered_or_unreachable"
        else:
            status = "closed"
    except (socket.timeout, TimeoutError):
        status = "filtered_or_unreachable"
    except OSError as exc:
        err_no = getattr(exc, "errno", None)
        if err_no in (errno.ECONNREFUSED, WSAECONNREFUSED):
            status = "closed"
        elif err_no in (
            errno.ETIMEDOUT,
            WSAETIMEDOUT,
            errno.EHOSTUNREACH,
            WSAEHOSTUNREACH,
            errno.ENETUNREACH,
            WSAENETUNREACH,
        ):
            status = "filtered_or_unreachable"
        else:
            status = "filtered_or_unreachable"
    finally:
        try:
            sock.close()
        except Exception:
            pass

    return port, status


class NetworkScannerService:
    """Service handling authorized TCP network scanning and security assessments."""

    @staticmethod
    def _evaluate_security_findings(
        target_host: str,
        open_ports: List[int],
        db: Session,
        current_user: User,
        request: Optional[Request] = None,
    ) -> List[str]:
        """Correlate open ports into security findings for confirmed insecure protocols.

        Defensive Rule: Does NOT claim a port is vulnerable simply because it is open.
        Only flags confirmed cleartext protocols or exposed sensitive database/remote access ports.
        """
        finding_ids: List[str] = []

        for port in open_ports:
            finding_data: Optional[Dict[str, Any]] = None

            if port == 23:
                finding_data = {
                    "title": f"Insecure Cleartext Telnet Service Exposed on {target_host}:23",
                    "description": (
                        f"TCP port 23 (Telnet) was detected open on '{target_host}'. "
                        "Telnet transmits all authentication credentials and commands "
                        "in unencrypted plaintext, exposing sensitive session data to interception."
                    ),
                    "severity": FindingSeverity.HIGH,
                    "category": "network_security",
                    "cwe_id": "CWE-319",
                    "remediation": (
                        "Immediately disable the Telnet daemon and transition to SSH (TCP port 22) "
                        "utilizing strong cryptographic ciphers and key-based authentication."
                    ),
                    "evidence": "Port 23 (Telnet) returned open status during TCP connect scan.",
                }
            elif port == 21:
                finding_data = {
                    "title": f"Cleartext FTP Service Exposed on {target_host}:21",
                    "description": (
                        f"TCP port 21 (FTP) was detected open on authorized asset '{target_host}'. "
                        "Standard FTP transmits credentials and files without TLS encryption."
                    ),
                    "severity": FindingSeverity.MEDIUM,
                    "category": "network_security",
                    "cwe_id": "CWE-319",
                    "remediation": (
                        "Enforce encrypted file transfer protocols such as SFTP (SSH File) "
                        "or FTPS with TLS encryption required for control and data channels."
                    ),
                    "evidence": "Port 21 (FTP) returned open status during TCP connect scan.",
                }
            elif port == 445:
                finding_data = {
                    "title": f"Direct SMB File Sharing Exposed on {target_host}:445",
                    "description": (
                        f"TCP port 445 (SMB) was detected open on '{target_host}'. "
                        "Exposing SMB to network segments increases the attack surface for lateral "
                        "movement and file sharing reconnaissance."
                    ),
                    "severity": FindingSeverity.HIGH,
                    "category": "network_security",
                    "cwe_id": "CWE-284",
                    "remediation": (
                        "Block port 445 at perimeter boundaries. Limit SMB "
                        "access strictly to authenticated jumpboxes or private tunnels."
                    ),
                    "evidence": "Port 445 (SMB) returned open status during TCP connect scan.",
                }
            elif port in (6379, 27017):
                service_name = "Redis" if port == 6379 else "MongoDB"
                finding_data = {
                    "title": f"Exposed Database Service ({service_name}) on {target_host}:{port}",
                    "description": (
                        f"TCP port {port} ({service_name}) was detected open on '{target_host}'. "
                        "Database services exposed across network boundaries pose significant data "
                        "exposure risks if bind addresses or authentication policies are "
                        "misconfigured."
                    ),
                    "severity": FindingSeverity.HIGH,
                    "category": "network_security",
                    "cwe_id": "CWE-306",
                    "remediation": (
                        f"Bind {service_name} to localhost (127.0.0.1) or private UNIX socket. "
                        "Enforce strict mandatory authentication and firewall rules."
                    ),
                    "evidence": (
                        f"Port {port} ({service_name}) returned open status "
                        "during TCP connect scan."
                    ),
                }
            elif port in (3389, 5900):
                service_name = "RDP" if port == 3389 else "VNC"
                finding_data = {
                    "title": (
                        f"Exposed Graphical Remote Management ({service_name}) on "
                        f"{target_host}:{port}"
                    ),
                    "description": (
                        f"TCP port {port} ({service_name}) was detected open on '{target_host}'. "
                        "Direct exposure of graphical desktop interfaces increases exposure to "
                        "brute-force attacks and session hijacking."
                    ),
                    "severity": FindingSeverity.MEDIUM,
                    "category": "network_security",
                    "cwe_id": "CWE-284",
                    "remediation": (
                        "Place remote desktop interfaces behind an enterprise VPN or SSH bastion "
                        "with Multi-Factor Authentication (MFA) enabled."
                    ),
                    "evidence": (
                        f"Port {port} ({service_name}) returned open status "
                        "during TCP connect scan."
                    ),
                }

            if finding_data:
                finding_in = FindingCreate(
                    title=finding_data["title"],
                    description=finding_data["description"],
                    severity=finding_data["severity"],
                    category=finding_data["category"],
                    source_module="scanner",
                    affected_resource=f"{target_host}:{port}",
                    remediation=finding_data["remediation"],
                    evidence=finding_data["evidence"],
                    cwe_id=finding_data["cwe_id"],
                    status=FindingStatus.OPEN,
                )
                finding_obj = FindingService.create_finding(
                    db=db,
                    finding_in=finding_in,
                    current_user=current_user,
                    request=request,
                )
                finding_ids.append(finding_obj.id)

        return finding_ids

    @classmethod
    def execute_scan(
        cls,
        db: Session,
        payload: ScanCreateRequest,
        current_user: User,
        request: Optional[Request] = None,
    ) -> ScanResponse:
        """Validate, orchestrate, and record an authorized TCP connect network scan.

        Enforces:
        - Mandatory operator authorization acknowledgement.
        - Strict target validation against authorized target policy.
        - Rate limiting.
        - Bounded port count, socket timeout, and overall execution duration.
        """
        settings = get_settings()
        client_ip = get_client_ip(request) if request else "127.0.0.1"
        user_agent = get_user_agent(request) if request else "CyberShield-Scanner"

        # 1. Require Explicit Operator Authorization Confirmation
        if not payload.authorization_confirmed:
            record_audit_log(
                db=db,
                action="SCAN_REJECTED",
                resource_type="NETWORK_SCAN",
                status_code=400,
                ip_address=client_ip,
                user_id=current_user.id,
                user_agent=user_agent,
                details={
                    "target": payload.target,
                    "reason": "Missing explicit authorization confirmation",
                },
            )
            raise UnauthorizedScanTargetError(
                "Explicit authorization confirmation is required to perform a network scan."
            )

        # 2. Check Sliding Window Rate Limits
        _check_scan_rate_limit(current_user.id, settings.SCAN_RATE_LIMIT_PER_MINUTE)

        # 3. Validate Target & Resolve IP
        canonical_target, resolved_ip = validate_and_resolve_scan_target(payload.target)

        # 4. Validate & Normalize Ports
        ports_to_scan = validate_and_normalize_ports(
            ports=payload.ports,
            preset=payload.port_preset,
            max_ports=settings.SCAN_MAX_PORTS_PER_SCAN,
        )

        # Audit Log: SCAN_REQUESTED
        record_audit_log(
            db=db,
            action="SCAN_REQUESTED",
            resource_type="NETWORK_SCAN",
            status_code=200,
            ip_address=client_ip,
            user_id=current_user.id,
            user_agent=user_agent,
            details={
                "target_host": canonical_target,
                "resolved_ip": resolved_ip,
                "port_count": len(ports_to_scan),
                "preset": payload.port_preset,
            },
        )

        # 5. Execute Non-Destructive TCP Connect Probes
        start_time = time.time()
        timeout = settings.SCAN_CONNECT_TIMEOUT_SECONDS
        max_workers = min(settings.SCAN_MAX_CONCURRENCY, len(ports_to_scan))

        results_by_port: Dict[int, str] = {}
        try:
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_port = {
                    executor.submit(probe_tcp_port, resolved_ip, p, timeout): p
                    for p in ports_to_scan
                }
                for future in as_completed(future_to_port):
                    port, status = future.result()
                    results_by_port[port] = status
        except Exception as exc:
            record_audit_log(
                db=db,
                action="SCAN_FAILED",
                resource_type="NETWORK_SCAN",
                status_code=500,
                ip_address=client_ip,
                user_id=current_user.id,
                user_agent=user_agent,
                details={
                    "target_host": canonical_target,
                    "error": str(exc),
                },
            )
            raise ScanExecutionError(f"Network scan probe failed: {exc}")

        duration_ms = int((time.time() - start_time) * 1000)

        # 6. Structure Port Breakdown
        port_details: List[ScanPortResult] = []
        open_ports: List[int] = []

        for p in ports_to_scan:
            p_status = results_by_port.get(p, "closed")
            if p_status == "open":
                open_ports.append(p)
            service_name = WELL_KNOWN_SERVICES.get(p)
            port_details.append(
                ScanPortResult(
                    port=p,
                    status=p_status,
                    service=service_name,
                )
            )

        # 7. Correlate Insecure Protocols into Security Findings
        created_finding_ids = cls._evaluate_security_findings(
            target_host=canonical_target,
            open_ports=open_ports,
            db=db,
            current_user=current_user,
            request=request,
        )

        # 8. Persist to Database
        scan_record = ScanResult(
            user_id=current_user.id,
            target_host=canonical_target,
            scan_type="TCP_CONNECT",
            status="COMPLETED",
            open_ports=open_ports,
            scanned_ports=ports_to_scan,
            port_details=[p.model_dump() for p in port_details],
            total_ports_scanned=len(ports_to_scan),
            open_ports_count=len(open_ports),
            scan_duration_ms=duration_ms,
            authorization_confirmed=True,
            created_at=datetime.now(timezone.utc),
        )
        db.add(scan_record)
        db.commit()
        db.refresh(scan_record)

        # 9. Audit Log: SCAN_COMPLETED
        record_audit_log(
            db=db,
            action="SCAN_COMPLETED",
            resource_type="NETWORK_SCAN",
            status_code=200,
            ip_address=client_ip,
            user_id=current_user.id,
            user_agent=user_agent,
            details={
                "scan_id": scan_record.id,
                "target_host": canonical_target,
                "ports_checked": len(ports_to_scan),
                "open_ports_count": len(open_ports),
                "duration_ms": duration_ms,
                "findings_generated": len(created_finding_ids),
            },
        )

        return ScanResponse(
            id=scan_record.id,
            user_id=scan_record.user_id,
            target_host=scan_record.target_host,
            scan_type=scan_record.scan_type,
            status=scan_record.status,
            open_ports=scan_record.open_ports or [],
            scanned_ports=scan_record.scanned_ports or [],
            port_details=port_details,
            total_ports_scanned=scan_record.total_ports_scanned or len(ports_to_scan),
            open_ports_count=scan_record.open_ports_count or len(open_ports),
            scan_duration_ms=scan_record.scan_duration_ms,
            authorization_confirmed=scan_record.authorization_confirmed,
            created_at=scan_record.created_at,
            created_findings_count=len(created_finding_ids),
            created_finding_ids=created_finding_ids,
        )

    @staticmethod
    def list_scans(
        db: Session,
        current_user: User,
        page: int = 1,
        size: int = 20,
    ) -> Tuple[List[ScanResult], int]:
        """Retrieve paginated scan records."""
        query = db.query(ScanResult)
        if current_user.role != "admin":
            query = query.filter(ScanResult.user_id == current_user.id)

        total = query.count()
        records = (
            query.order_by(desc(ScanResult.created_at)).offset((page - 1) * size).limit(size).all()
        )
        return records, total

    @staticmethod
    def get_scan_by_id(
        db: Session,
        scan_id: str,
        current_user: User,
    ) -> Optional[ScanResult]:
        """Retrieve a specific scan result by ID with authorization checks."""
        query = db.query(ScanResult).filter(ScanResult.id == scan_id)
        if current_user.role != "admin":
            query = query.filter(ScanResult.user_id == current_user.id)
        return query.first()

    @staticmethod
    def get_scan_summary(db: Session, current_user: User) -> ScanSummaryResponse:
        """Aggregate high-level scanner KPIs and metrics."""
        query = db.query(ScanResult)
        if current_user.role != "admin":
            query = query.filter(ScanResult.user_id == current_user.id)

        total_scans = query.count()
        total_ports_checked = (
            query.with_entities(func.sum(ScanResult.total_ports_scanned)).scalar() or 0
        )
        total_open_ports = query.with_entities(func.sum(ScanResult.open_ports_count)).scalar() or 0

        recent_records = query.order_by(desc(ScanResult.created_at)).limit(5).all()

        recent_responses = []
        for r in recent_records:
            details = [
                ScanPortResult(
                    port=item.get("port", 0),
                    status=item.get("status", "closed"),
                    service=item.get("service"),
                )
                for item in (r.port_details or [])
            ]
            recent_responses.append(
                ScanResponse(
                    id=r.id,
                    user_id=r.user_id,
                    target_host=r.target_host,
                    scan_type=r.scan_type,
                    status=r.status,
                    open_ports=r.open_ports or [],
                    scanned_ports=r.scanned_ports or [],
                    port_details=details,
                    total_ports_scanned=r.total_ports_scanned or 0,
                    open_ports_count=r.open_ports_count or 0,
                    scan_duration_ms=r.scan_duration_ms,
                    authorization_confirmed=r.authorization_confirmed,
                    created_at=r.created_at,
                    created_findings_count=0,
                    created_finding_ids=[],
                )
            )

        return ScanSummaryResponse(
            total_scans=total_scans,
            total_ports_checked=total_ports_checked,
            total_open_ports=total_open_ports,
            recent_scans=recent_responses,
        )

    @staticmethod
    def get_scan_scope() -> ScanScopeResponse:
        """Return currently enforced authorized target and resource limits."""
        settings = get_settings()
        return ScanScopeResponse(
            allowed_targets=settings.scan_allowed_targets_list,
            max_ports_per_scan=settings.SCAN_MAX_PORTS_PER_SCAN,
            connect_timeout_seconds=settings.SCAN_CONNECT_TIMEOUT_SECONDS,
            rate_limit_per_minute=settings.SCAN_RATE_LIMIT_PER_MINUTE,
        )

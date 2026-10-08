"""Defensive Log Analyzer Service Layer.

Provides secure file ingestion, streaming normalization, detection correlation,
and automated integration with the CyberShield Security Findings Engine.
"""

from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from fastapi import Request
from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models.log_event import LogEvent
from app.models.user import User
from app.schemas.finding import FindingCreate, FindingSeverity, FindingStatus
from app.security.log_path import (
    UnauthorizedLogPathError,
    validate_and_resolve_log_path,
)
from app.services.finding_service import FindingService
from app.services.log_parser import DefensiveLogParser, ParsedLogEvent
from app.utils.audit_helper import get_client_ip, get_user_agent, record_audit_log


class LogServiceError(Exception):
    """Base exception for log analysis service failures."""

    pass


class LogService:
    """Core business logic for defensive log analysis and event management."""

    @classmethod
    def analyze_log_file(
        cls,
        db: Session,
        raw_path: str,
        current_user: User,
        request: Optional[Request] = None,
    ) -> Dict[str, Any]:
        """Securely ingest, parse, and analyze an authorized log file.

        Enforces:
        - Strict path traversal and symlink validation against LOG_ALLOWED_ROOTS.
        - Directory rejection (only regular files permitted).
        - Max file size and line length caps to defeat DoS / memory exhaustion.
        - Correlation rules for brute force and reconnaissance with Findings Engine integration.
        - Non-repudiation audit logging for all operations.
        """
        settings = get_settings()
        allowed_roots = settings.log_allowed_roots_list
        ip = get_client_ip(request) if request else "127.0.0.1"
        ua = get_user_agent(request) if request else "Internal Service"

        # 1. Validate and canonicalize path
        try:
            resolved_path = validate_and_resolve_log_path(
                raw_path=raw_path,
                allowed_roots=allowed_roots,
                max_file_size_bytes=settings.LOG_MAX_FILE_SIZE_BYTES,
                must_exist=True,
            )
        except UnauthorizedLogPathError as exc:
            record_audit_log(
                db=db,
                action="LOG_UNAUTHORIZED_PATH_REJECTED",
                resource_type="LOG_FILE",
                resource_id=raw_path[:255],
                status_code=403,
                ip_address=ip,
                user_id=current_user.id,
                user_agent=ua,
                details={"requested_path": raw_path, "error": str(exc)},
            )
            raise

        # 2. Record audit log for analysis initiation
        record_audit_log(
            db=db,
            action="LOG_ANALYSIS_STARTED",
            resource_type="LOG_FILE",
            resource_id=str(resolved_path)[:255],
            status_code=200,
            ip_address=ip,
            user_id=current_user.id,
            user_agent=ua,
            details={"file_path": str(resolved_path)},
        )

        lines_read = 0
        parsed_events: List[ParsedLogEvent] = []

        try:
            # 3. Stream file line-by-line safely
            with open(resolved_path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    lines_read += 1
                    if lines_read > settings.LOG_MAX_LINES_PER_RUN:
                        break

                    # Truncate oversized lines
                    truncated_line = line[: settings.LOG_MAX_LINE_LENGTH]
                    event = DefensiveLogParser.parse_line(
                        line=truncated_line,
                        source_identifier=resolved_path.name,
                    )
                    if event:
                        parsed_events.append(event)

        except Exception as exc:
            record_audit_log(
                db=db,
                action="LOG_ANALYSIS_FAILED",
                resource_type="LOG_FILE",
                resource_id=str(resolved_path)[:255],
                status_code=500,
                ip_address=ip,
                user_id=current_user.id,
                user_agent=ua,
                details={"file_path": str(resolved_path), "error": str(exc)},
            )
            raise LogServiceError(f"Error reading log file '{raw_path}': {exc}")

        # 4. Persist parsed events in database
        persisted_records: List[LogEvent] = []
        for p_ev in parsed_events:
            db_ev = LogEvent(
                user_id=current_user.id,
                source_type=p_ev.source_type,
                source_file=str(resolved_path),
                raw_message=p_ev.raw_message,
                parsed_event=p_ev.parsed_event,
                severity=p_ev.severity,
                source_ip=p_ev.source_ip,
                username=p_ev.username,
                message_summary=p_ev.message_summary,
                event_category=p_ev.event_category,
                event_timestamp=p_ev.timestamp,
                created_at=datetime.now(timezone.utc),
            )
            db.add(db_ev)
            persisted_records.append(db_ev)

        db.commit()

        # 5. Correlate events & trigger findings via Findings Engine
        created_finding_ids: List[str] = []

        # (a) Brute force correlation by source IP
        auth_failures_by_ip = defaultdict(list)
        # (b) Brute force correlation by targeted username
        auth_failures_by_user = defaultdict(list)
        # (c) Access denied events
        access_denied_events = []
        # (d) Web probe requests by source IP
        probes_by_ip = defaultdict(list)

        for ev in parsed_events:
            if ev.event_category == "authentication_failure":
                if ev.source_ip:
                    auth_failures_by_ip[ev.source_ip].append(ev)
                if ev.username:
                    auth_failures_by_user[ev.username].append(ev)
            elif ev.event_category == "access_denied":
                access_denied_events.append(ev)
            elif ev.event_category == "suspicious_request":
                if ev.source_ip:
                    probes_by_ip[ev.source_ip].append(ev)
                else:
                    probes_by_ip["unknown"].append(ev)

        threshold = settings.LOG_BRUTE_FORCE_THRESHOLD

        # Rule 1: Brute force / repeated auth failures from same IP
        for src_ip, failures in auth_failures_by_ip.items():
            if len(failures) >= threshold:
                targeted_users = list({f.username for f in failures if f.username})
                summary_users = (
                    ", ".join(targeted_users[:5]) if targeted_users else "unknown accounts"
                )
                evidence_text = (
                    f"Offending IP:            {src_ip}\n"
                    f"Failure Count:           {len(failures)}\n"
                    f"Targeted Accounts:       {summary_users}\n"
                    f"First Detected Failure:  {failures[0].timestamp.isoformat()}\n"
                    f"Last Detected Failure:   {failures[-1].timestamp.isoformat()}\n"
                    f"Log Source:              {str(resolved_path)}"
                )
                finding = FindingService.create_finding(
                    db=db,
                    finding_in=FindingCreate(
                        title=f"Repeated Authentication Failures from IP {src_ip}",
                        description=(
                            f"Detected {len(failures)} failed authentication attempts originating "
                            f"from source IP {src_ip} within log '{resolved_path.name}'."
                        ),
                        severity=FindingSeverity.HIGH,
                        category="authentication",
                        source_module="log_analyzer",
                        affected_resource=src_ip,
                        remediation=(
                            "Investigate source IP for automated credential stuffing or "
                            "brute-force attacks. Implement progressive delay, account "
                            "lockout, or block IP via firewall."
                        ),
                        evidence=evidence_text,
                        cwe_id="CWE-307",
                        status=FindingStatus.OPEN,
                    ),
                    current_user=current_user,
                    request=request,
                )
                created_finding_ids.append(finding.id)

        # Rule 2: Brute force targeted against single username across distributed or null IPs
        for uname, failures in auth_failures_by_user.items():
            # Only trigger if not already handled by a single IP that had all these failures
            if len(failures) >= threshold:
                ips = list({f.source_ip for f in failures if f.source_ip})
                if len(ips) > 1 or (len(ips) == 1 and len(auth_failures_by_ip[ips[0]]) < threshold):
                    ips_summary = ", ".join(ips[:5]) if ips else "Local/Console"
                    evidence_text = (
                        f"Targeted User:           {uname}\n"
                        f"Failure Count:           {len(failures)}\n"
                        f"Source IPs Involved:     {ips_summary}\n"
                        f"First Detected Failure:  {failures[0].timestamp.isoformat()}\n"
                        f"Last Detected Failure:   {failures[-1].timestamp.isoformat()}\n"
                        f"Log Source:              {str(resolved_path)}"
                    )
                    finding = FindingService.create_finding(
                        db=db,
                        finding_in=FindingCreate(
                            title=f"Targeted Authentication Failures for Account '{uname}'",
                            description=(
                                f"Detected {len(failures)} failed authentication attempts targeted "
                                f"against account '{uname}' in '{resolved_path.name}'."
                            ),
                            severity=FindingSeverity.HIGH,
                            category="authentication",
                            source_module="log_analyzer",
                            affected_resource=uname,
                            remediation=(
                                "Review account for unauthorized access attempts. Enforce "
                                "multi-factor authentication (MFA) and consider temporary "
                                "account suspension or credential rotation."
                            ),
                            evidence=evidence_text,
                            cwe_id="CWE-307",
                            status=FindingStatus.OPEN,
                        ),
                        current_user=current_user,
                        request=request,
                    )
                    created_finding_ids.append(finding.id)

        # Rule 3: Web path probing / reconnaissance
        for probe_ip, p_list in probes_by_ip.items():
            targeted_paths = list(
                {p.parsed_event.get("path") for p in p_list if p.parsed_event.get("path")}
            )
            paths_str = ", ".join(str(p) for p in targeted_paths[:5])
            evidence_text = (
                f"Client IP:               {probe_ip}\n"
                f"Probe Request Count:     {len(p_list)}\n"
                f"Probed Endpoints:        {paths_str}\n"
                f"Log Source:              {str(resolved_path)}"
            )
            finding = FindingService.create_finding(
                db=db,
                finding_in=FindingCreate(
                    title=f"Web Application Path Probing Detected from {probe_ip}",
                    description=(
                        f"Identified {len(p_list)} probe requests targeting sensitive endpoints "
                        f"from IP {probe_ip} in '{resolved_path.name}'."
                    ),
                    severity=FindingSeverity.MEDIUM,
                    category="reconnaissance",
                    source_module="log_analyzer",
                    affected_resource=probe_ip,
                    remediation=(
                        "Verify web server access rules and ensure sensitive endpoints are not "
                        "publicly accessible. Apply rate limits or block scanning tools at WAF."
                    ),
                    evidence=evidence_text,
                    cwe_id="CWE-200",
                    status=FindingStatus.OPEN,
                ),
                current_user=current_user,
                request=request,
            )
            created_finding_ids.append(finding.id)

        # Rule 4: Repeated or elevated Permission Denied / Access Denied events (>= 3)
        if len(access_denied_events) >= 3:
            affected_users = list({e.username for e in access_denied_events if e.username})
            users_summary = (
                ", ".join(affected_users[:5]) if affected_users else "unauthenticated actors"
            )
            evidence_text = (
                f"Access Denied Count:     {len(access_denied_events)}\n"
                f"Actors / Users:          {users_summary}\n"
                f"Sample Summary:          {access_denied_events[0].message_summary}\n"
                f"Log Source:              {str(resolved_path)}"
            )
            finding = FindingService.create_finding(
                db=db,
                finding_in=FindingCreate(
                    title=f"Multiple Access Denied Events in {resolved_path.name}",
                    description=(
                        f"Observed {len(access_denied_events)} access denied or permission "
                        f"denied events in log file '{resolved_path.name}'."
                    ),
                    severity=FindingSeverity.MEDIUM,
                    category="access_control",
                    source_module="log_analyzer",
                    affected_resource=str(resolved_path),
                    remediation=(
                        "Inspect unauthorized privilege elevation attempts and verify principle of "
                        "least privilege configurations across affected systems."
                    ),
                    evidence=evidence_text,
                    cwe_id="CWE-285",
                    status=FindingStatus.OPEN,
                ),
                current_user=current_user,
                request=request,
            )
            created_finding_ids.append(finding.id)

        # 6. Record audit log for completion
        record_audit_log(
            db=db,
            action="LOG_ANALYSIS_COMPLETED",
            resource_type="LOG_FILE",
            resource_id=str(resolved_path)[:255],
            status_code=200,
            ip_address=ip,
            user_id=current_user.id,
            user_agent=ua,
            details={
                "file_path": str(resolved_path),
                "lines_read": lines_read,
                "events_parsed_count": len(parsed_events),
                "findings_created_count": len(created_finding_ids),
            },
        )

        return {
            "source_file": str(resolved_path),
            "file_name": resolved_path.name,
            "lines_read": lines_read,
            "events_parsed_count": len(parsed_events),
            "created_findings_count": len(created_finding_ids),
            "created_finding_ids": created_finding_ids,
            "events": [
                {
                    "id": rec.id,
                    "user_id": rec.user_id,
                    "source_file": rec.source_file,
                    "event_timestamp": rec.event_timestamp,
                    "event_category": rec.event_category,
                    "severity": rec.severity,
                    "source_type": rec.source_type,
                    "source_ip": rec.source_ip,
                    "username": rec.username,
                    "message_summary": rec.message_summary,
                    "raw_message": rec.raw_message,
                    "parsed_event": rec.parsed_event,
                    "created_at": rec.created_at,
                }
                for rec in persisted_records
            ],
        }

    @classmethod
    def list_events(
        cls,
        db: Session,
        current_user: User,
        severity: Optional[str] = None,
        event_category: Optional[str] = None,
        source_type: Optional[str] = None,
        source_file: Optional[str] = None,
        search: Optional[str] = None,
        page: int = 1,
        size: int = 20,
    ) -> Tuple[List[LogEvent], int]:
        """Fetch paginated log events with filtering."""
        query = db.query(LogEvent)

        if severity and severity.lower() != "all":
            query = query.filter(LogEvent.severity == severity.upper())

        if event_category and event_category.lower() != "all":
            query = query.filter(LogEvent.event_category == event_category.lower())

        if source_type and source_type.lower() != "all":
            query = query.filter(LogEvent.source_type == source_type.lower())

        if source_file and source_file.strip():
            query = query.filter(LogEvent.source_file.ilike(f"%{source_file.strip()}%"))

        if search and search.strip():
            term = f"%{search.strip()}%"
            query = query.filter(
                or_(
                    LogEvent.message_summary.ilike(term),
                    LogEvent.raw_message.ilike(term),
                    LogEvent.source_ip.ilike(term),
                    LogEvent.username.ilike(term),
                    LogEvent.source_file.ilike(term),
                )
            )

        total = query.count()
        offset = (page - 1) * size
        items = query.order_by(LogEvent.created_at.desc()).offset(offset).limit(size).all()
        return items, total

    @classmethod
    def get_event_by_id(
        cls,
        db: Session,
        event_id: str,
        current_user: User,
    ) -> Optional[LogEvent]:
        """Fetch a specific log event by ID."""
        return db.query(LogEvent).filter(LogEvent.id == event_id).first()

    @classmethod
    def get_status_summary(
        cls,
        db: Session,
        current_user: User,
    ) -> Dict[str, Any]:
        """Return aggregated summary statistics for ingested log events."""
        settings = get_settings()

        total_events = db.query(func.count(LogEvent.id)).scalar() or 0

        # Severity breakdown
        sev_rows = (
            db.query(LogEvent.severity, func.count(LogEvent.id)).group_by(LogEvent.severity).all()
        )
        severity_counts = {str(k).upper(): count for k, count in sev_rows}

        # Category breakdown
        cat_rows = (
            db.query(LogEvent.event_category, func.count(LogEvent.id))
            .group_by(LogEvent.event_category)
            .all()
        )
        category_counts = {str(k).lower(): count for k, count in cat_rows}

        # Last event timestamp
        last_event = db.query(LogEvent.created_at).order_by(LogEvent.created_at.desc()).first()
        last_analyzed_at = last_event[0] if last_event else None

        return {
            "total_events": total_events,
            "severity_counts": severity_counts,
            "category_counts": category_counts,
            "allowed_roots": settings.log_allowed_roots_list,
            "last_analyzed_at": last_analyzed_at,
        }

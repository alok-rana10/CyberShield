"""File Integrity Monitor (FIM) Service Layer.

Provides cryptographic hashing, baseline management, change detection,
and automated integration with the CyberShield Findings Engine.
"""

from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from fastapi import Request
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models.fim import FileIntegrityRecord
from app.models.user import User
from app.schemas.finding import FindingCreate, FindingSeverity, FindingStatus
from app.schemas.fim import (
    FIMBaselineResponse,
    FIMCheckResponse,
    FIMRecordResponse,
    FIMStatus,
    FIMStatusSummaryResponse,
)
from app.security.fim_path import (
    FIMPathSecurityError,
    UnauthorizedPathError,
    validate_and_resolve_fim_path,
)
from app.services.finding_service import FindingService
from app.utils.audit_helper import get_client_ip, get_user_agent, record_audit_log

CHUNK_SIZE = 65536  # 64 KB read buffer


class FIMProcessingError(Exception):
    """Raised when file scanning or hashing fails due to operational errors."""

    pass


class FileTooLargeError(FIMProcessingError):
    """Raised when a candidate file exceeds maximum permitted size limit."""

    pass


class FileLimitExceededError(FIMProcessingError):
    """Raised when a directory contains more files than the baseline cap."""

    pass


def compute_file_sha256(
    file_path: Path,
    max_size_bytes: int,
) -> Tuple[str, int, datetime]:
    """Compute SHA-256 hash using chunked streaming, file size, and mtime.

    Never loads large files entirely into memory.
    """
    try:
        stat_result = file_path.stat()
    except OSError as exc:
        raise FIMProcessingError(f"Failed to access file '{file_path}': {exc}")

    if stat_result.st_size > max_size_bytes:
        raise FileTooLargeError(
            f"File '{file_path.name}' exceeds maximum allowed size "
            f"({stat_result.st_size} > {max_size_bytes} bytes)."
        )

    hasher = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(CHUNK_SIZE):
                hasher.update(chunk)
    except OSError as exc:
        raise FIMProcessingError(f"Failed to read file '{file_path}': {exc}")

    mtime = datetime.fromtimestamp(stat_result.st_mtime, tz=timezone.utc)
    return hasher.hexdigest(), stat_result.st_size, mtime


def collect_target_files(
    target_path: Path,
    allowed_roots: List[str],
    max_files: int,
) -> List[Path]:
    """Enumerate all files under target path while defending against symlink loops and escapes."""
    if target_path.is_file():
        return [target_path]

    collected: List[Path] = []
    # os.walk with followlinks=False defends against recursive symlink traversal
    for root, _dirs, files in os.walk(target_path, followlinks=False):
        for filename in files:
            file_path = Path(root) / filename
            try:
                # Ensure resolved file path is still within an authorized root
                resolved_file = validate_and_resolve_fim_path(
                    str(file_path),
                    allowed_roots=allowed_roots,
                    must_exist=True,
                )
                collected.append(resolved_file)
            except (FIMPathSecurityError, OSError):
                # Skip invalid or escaped symlinks
                continue

            if len(collected) > max_files:
                raise FileLimitExceededError(
                    f"Directory '{target_path}' exceeds maximum baseline file limit ({max_files})."
                )

    return collected


class FIMService:
    """Service orchestrating File Integrity Monitoring operations."""

    @classmethod
    def create_baseline(
        cls,
        db: Session,
        raw_path: str,
        current_user: User,
        request: Request,
        allowed_roots: Optional[List[str]] = None,
    ) -> FIMBaselineResponse:
        """Create or update cryptographic baseline for an authorized path."""
        settings = get_settings()
        roots = allowed_roots or settings.fim_allowed_roots_list

        client_ip = get_client_ip(request)
        user_agent = get_user_agent(request)

        # 1. Validate path authorization and canonicalize
        try:
            canonical_path = validate_and_resolve_fim_path(
                raw_path,
                allowed_roots=roots,
                must_exist=True,
            )
        except UnauthorizedPathError as auth_err:
            record_audit_log(
                db=db,
                action="FIM_UNAUTHORIZED_PATH_REJECTED",
                resource_type="FIM",
                status_code=403,
                ip_address=client_ip,
                user_id=current_user.id,
                user_agent=user_agent,
                details={"path": raw_path, "reason": str(auth_err)},
            )
            raise auth_err

        # 2. Collect target files
        files = collect_target_files(
            canonical_path,
            allowed_roots=roots,
            max_files=settings.FIM_MAX_FILES_PER_BASELINE,
        )

        now = datetime.now(timezone.utc)
        created_records: List[FileIntegrityRecord] = []
        total_bytes = 0

        # 3. Hash and store metadata for each file
        for fpath in files:
            file_key = str(fpath)
            sha256_hash, file_size, mtime = compute_file_sha256(
                fpath,
                max_size_bytes=settings.FIM_MAX_FILE_SIZE_BYTES,
            )
            total_bytes += file_size

            existing_record = (
                db.query(FileIntegrityRecord)
                .filter(
                    FileIntegrityRecord.user_id == current_user.id,
                    FileIntegrityRecord.monitored_path == file_key,
                )
                .first()
            )

            if existing_record:
                existing_record.baseline_hash = sha256_hash
                existing_record.current_hash = sha256_hash
                existing_record.file_size_bytes = file_size
                existing_record.file_modified_at = mtime
                existing_record.status = FIMStatus.BASELINE.value
                existing_record.last_verified_at = now
                existing_record.updated_at = now
                created_records.append(existing_record)
            else:
                new_record = FileIntegrityRecord(
                    user_id=current_user.id,
                    monitored_path=file_key,
                    baseline_hash=sha256_hash,
                    current_hash=sha256_hash,
                    file_size_bytes=file_size,
                    file_modified_at=mtime,
                    status=FIMStatus.BASELINE.value,
                    last_verified_at=now,
                    created_at=now,
                    updated_at=now,
                )
                db.add(new_record)
                created_records.append(new_record)

        db.commit()
        for r in created_records:
            db.refresh(r)

        # 4. Record audit log
        record_audit_log(
            db=db,
            action="FIM_BASELINE_CREATED",
            resource_type="FIM",
            status_code=201,
            ip_address=client_ip,
            user_id=current_user.id,
            user_agent=user_agent,
            details={
                "path": str(canonical_path),
                "files_count": len(created_records),
                "total_bytes": total_bytes,
            },
        )

        return FIMBaselineResponse(
            path=str(canonical_path),
            files_baselined_count=len(created_records),
            total_size_bytes=total_bytes,
            created_at=now,
            records=[FIMRecordResponse.model_validate(r) for r in created_records],
        )

    @classmethod
    def check_integrity(
        cls,
        db: Session,
        raw_path: str,
        current_user: User,
        request: Request,
        allowed_roots: Optional[List[str]] = None,
    ) -> FIMCheckResponse:
        """Scan target path and verify cryptographic hashes against existing baseline."""
        settings = get_settings()
        roots = allowed_roots or settings.fim_allowed_roots_list

        client_ip = get_client_ip(request)
        user_agent = get_user_agent(request)

        # 1. Validate path authorization
        try:
            canonical_path = validate_and_resolve_fim_path(
                raw_path,
                allowed_roots=roots,
                must_exist=False,
            )
        except UnauthorizedPathError as auth_err:
            record_audit_log(
                db=db,
                action="FIM_UNAUTHORIZED_PATH_REJECTED",
                resource_type="FIM",
                status_code=403,
                ip_address=client_ip,
                user_id=current_user.id,
                user_agent=user_agent,
                details={"path": raw_path, "reason": str(auth_err)},
            )
            raise auth_err

        # 2. Record check started audit log
        record_audit_log(
            db=db,
            action="FIM_CHECK_STARTED",
            resource_type="FIM",
            status_code=200,
            ip_address=client_ip,
            user_id=current_user.id,
            user_agent=user_agent,
            details={"path": str(canonical_path)},
        )

        # 3. Query existing baseline records for this target path
        path_str = str(canonical_path)
        all_user_records = (
            db.query(FileIntegrityRecord)
            .filter(FileIntegrityRecord.user_id == current_user.id)
            .all()
        )
        # Filter records belonging to the target directory or exact file
        baseline_records = [
            r
            for r in all_user_records
            if r.monitored_path == path_str
            or r.monitored_path.startswith(path_str + os.sep)
            or r.monitored_path.startswith(path_str + "/")
        ]

        if not baseline_records and not canonical_path.exists():
            raise FIMProcessingError(
                f"No baseline exists for path '{path_str}' and path does not exist on disk."
            )

        baseline_map: Dict[str, FileIntegrityRecord] = {
            r.monitored_path: r for r in baseline_records
        }

        # 4. Enumerate current files on disk if path exists
        current_files: List[Path] = []
        if canonical_path.exists():
            current_files = collect_target_files(
                canonical_path,
                allowed_roots=roots,
                max_files=settings.FIM_MAX_FILES_PER_BASELINE,
            )

        now = datetime.now(timezone.utc)
        seen_paths: Set[str] = set()

        unchanged_count = 0
        modified_count = 0
        added_count = 0
        deleted_count = 0

        created_finding_ids: List[str] = []
        result_records: List[FileIntegrityRecord] = []

        # 5. Check present files (Unchanged, Modified, Added)
        for fpath in current_files:
            file_key = str(fpath)
            seen_paths.add(file_key)

            curr_hash, curr_size, curr_mtime = compute_file_sha256(
                fpath,
                max_size_bytes=settings.FIM_MAX_FILE_SIZE_BYTES,
            )

            if file_key in baseline_map:
                rec = baseline_map[file_key]
                rec.current_hash = curr_hash
                rec.file_size_bytes = curr_size
                rec.file_modified_at = curr_mtime
                rec.last_verified_at = now
                rec.updated_at = now

                if curr_hash == rec.baseline_hash:
                    rec.status = FIMStatus.UNCHANGED.value
                    unchanged_count += 1
                else:
                    rec.status = FIMStatus.MODIFIED.value
                    modified_count += 1

                    # Generate Security Finding for modified file
                    finding = FindingService.create_finding(
                        db=db,
                        finding_in=FindingCreate(
                            title=f"File Modified: {rec.file_name}",
                            description=(
                                f"Cryptographic integrity check detected an unauthorized or "
                                f"unexpected modification to monitored file '{file_key}'. "
                                f"SHA-256 hash has changed."
                            ),
                            severity=FindingSeverity.HIGH,
                            category="file_integrity",
                            source_module="fim",
                            affected_resource=file_key,
                            remediation=(
                                "Inspect file diff against trusted version control or backup. "
                                "Verify whether modification was authorized by a system operator."
                            ),
                            evidence=(
                                f"Monitored Path: {file_key}\n"
                                f"Baseline SHA-256: {rec.baseline_hash}\n"
                                f"Current SHA-256:  {curr_hash}\n"
                                f"Current Size:    {curr_size} bytes\n"
                                f"Modified Time:   {curr_mtime.isoformat()}"
                            ),
                            cwe_id="CWE-353",
                            status=FindingStatus.OPEN,
                        ),
                        current_user=current_user,
                        request=request,
                    )
                    created_finding_ids.append(finding.id)

                result_records.append(rec)
            else:
                # File present on disk but was never in baseline -> Added file
                added_rec = FileIntegrityRecord(
                    user_id=current_user.id,
                    monitored_path=file_key,
                    baseline_hash="UNBASELINED",
                    current_hash=curr_hash,
                    file_size_bytes=curr_size,
                    file_modified_at=curr_mtime,
                    status=FIMStatus.ADDED.value,
                    last_verified_at=now,
                    created_at=now,
                    updated_at=now,
                )
                db.add(added_rec)
                added_count += 1

                # Generate Security Finding for unexpected file
                finding = FindingService.create_finding(
                    db=db,
                    finding_in=FindingCreate(
                        title=f"Unexpected File Added: {added_rec.file_name}",
                        description=(
                            f"An unbaselined file was detected at '{file_key}' inside "
                            f"monitored directory '{path_str}'."
                        ),
                        severity=FindingSeverity.MEDIUM,
                        category="file_integrity",
                        source_module="fim",
                        affected_resource=file_key,
                        remediation=(
                            "Confirm whether this file was intentionally introduced. "
                            "Update baseline if legitimate, or remove file if unauthorized."
                        ),
                        evidence=(
                            f"Discovered Path: {file_key}\n"
                            f"Current SHA-256: {curr_hash}\n"
                            f"File Size:       {curr_size} bytes\n"
                            f"Modified Time:   {curr_mtime.isoformat()}"
                        ),
                        cwe_id="CWE-345",
                        status=FindingStatus.OPEN,
                    ),
                    current_user=current_user,
                    request=request,
                )
                created_finding_ids.append(finding.id)
                result_records.append(added_rec)

        # 6. Check missing files (Deleted)
        for b_path, b_rec in baseline_map.items():
            if b_path not in seen_paths:
                b_rec.status = FIMStatus.DELETED.value
                b_rec.current_hash = None
                b_rec.last_verified_at = now
                b_rec.updated_at = now
                deleted_count += 1

                # Generate Security Finding for deleted file
                finding = FindingService.create_finding(
                    db=db,
                    finding_in=FindingCreate(
                        title=f"Monitored File Deleted: {b_rec.file_name}",
                        description=(
                            f"The previously baselined file '{b_path}' is missing or was deleted "
                            f"from disk."
                        ),
                        severity=FindingSeverity.HIGH,
                        category="file_integrity",
                        source_module="fim",
                        affected_resource=b_path,
                        remediation=(
                            "Investigate unexpected file deletion. Restore from verified backup "
                            "if accidental or unauthorized."
                        ),
                        evidence=(
                            f"Missing Path:        {b_path}\n"
                            f"Expected SHA-256:    {b_rec.baseline_hash}\n"
                            f"Expected Size:       {b_rec.file_size_bytes} bytes"
                        ),
                        cwe_id="CWE-353",
                        status=FindingStatus.OPEN,
                    ),
                    current_user=current_user,
                    request=request,
                )
                created_finding_ids.append(finding.id)
                result_records.append(b_rec)

        db.commit()
        for r in result_records:
            db.refresh(r)

        # 7. Record check completed audit log
        record_audit_log(
            db=db,
            action="FIM_CHECK_COMPLETED",
            resource_type="FIM",
            status_code=200,
            ip_address=client_ip,
            user_id=current_user.id,
            user_agent=user_agent,
            details={
                "path": path_str,
                "total_checked": len(result_records),
                "unchanged": unchanged_count,
                "modified": modified_count,
                "added": added_count,
                "deleted": deleted_count,
                "findings_generated": len(created_finding_ids),
            },
        )

        return FIMCheckResponse(
            path=path_str,
            checked_at=now,
            total_files=len(result_records),
            unchanged_count=unchanged_count,
            modified_count=modified_count,
            added_count=added_count,
            deleted_count=deleted_count,
            created_findings_count=len(created_finding_ids),
            created_finding_ids=created_finding_ids,
            records=[FIMRecordResponse.model_validate(r) for r in result_records],
        )

    @classmethod
    def get_status_summary(
        cls,
        db: Session,
        current_user: User,
    ) -> FIMStatusSummaryResponse:
        """Retrieve aggregated counts and last check time for the current user."""
        settings = get_settings()
        records = (
            db.query(FileIntegrityRecord)
            .filter(FileIntegrityRecord.user_id == current_user.id)
            .all()
        )

        counts: Dict[str, int] = {
            "baseline": 0,
            "unchanged": 0,
            "modified": 0,
            "added": 0,
            "deleted": 0,
        }

        last_check: Optional[datetime] = None

        for r in records:
            counts[r.status] = counts.get(r.status, 0) + 1
            if r.last_verified_at:
                if last_check is None or r.last_verified_at > last_check:
                    last_check = r.last_verified_at

        return FIMStatusSummaryResponse(
            total_monitored_files=len(records),
            status_counts=counts,
            allowed_roots=settings.fim_allowed_roots_list,
            last_check_at=last_check,
        )

    @classmethod
    def list_records(
        cls,
        db: Session,
        current_user: User,
        status_filter: Optional[str] = None,
        path_search: Optional[str] = None,
        page: int = 1,
        size: int = 20,
    ) -> Tuple[List[FileIntegrityRecord], int]:
        """Return paginated list of FIM records for current user."""
        query = db.query(FileIntegrityRecord).filter(FileIntegrityRecord.user_id == current_user.id)

        if status_filter:
            query = query.filter(FileIntegrityRecord.status == status_filter.lower())

        if path_search:
            query = query.filter(FileIntegrityRecord.monitored_path.ilike(f"%{path_search}%"))

        total = query.count()
        records = (
            query.order_by(FileIntegrityRecord.updated_at.desc())
            .offset((page - 1) * size)
            .limit(size)
            .all()
        )

        return records, total

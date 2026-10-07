"""Web Security Header Analysis Engine with defensive SSRF protections."""

from datetime import datetime, timezone
import urllib.parse
from typing import Any, Dict, List, Tuple
from fastapi import Request
import httpcore
import httpx
from sqlalchemy.orm import Session

from app.models.user import User
from app.models.web_security import WebSecurityResult
from app.schemas.finding import FindingCreate, FindingSeverity, FindingStatus
from app.schemas.web_security import (
    HeaderAnalysisResponse,
    HeaderEvaluationDetail,
)
from app.security.ssrf import (
    SSRFProtectionError,
    SSRFSafeNetworkBackend,
    validate_target_url,
)
from app.services.finding_service import FindingService

MAX_REDIRECTS = 5
MAX_BODY_BYTES = 65536  # 64 KB limit
REQUEST_TIMEOUT_SECONDS = 5.0

# Target security headers specification
SECURITY_HEADERS_SPEC = {
    "content-security-policy": {
        "display_name": "Content-Security-Policy",
        "cwe_id": "CWE-1021",
        "default_severity": FindingSeverity.MEDIUM,
        "description": "Restricts sources of executable scripts, stylesheets, images, and frames.",
        "remediation": (
            "Configure web server or proxy to send a strict Content-Security-Policy directive."
        ),
    },
    "strict-transport-security": {
        "display_name": "Strict-Transport-Security",
        "cwe_id": "CWE-319",
        "default_severity": FindingSeverity.MEDIUM,
        "description": (
            "Enforces HTTPS connections and blocks SSL stripping or cleartext downgrades."
        ),
        "remediation": (
            "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to "
            "HTTPS responses."
        ),
    },
    "x-content-type-options": {
        "display_name": "X-Content-Type-Options",
        "cwe_id": "CWE-704",
        "default_severity": FindingSeverity.LOW,
        "description": (
            "Prevents MIME-type sniffing where browsers execute files as unexpected formats."
        ),
        "remediation": (
            "Configure 'X-Content-Type-Options: nosniff' header across all HTTP responses."
        ),
    },
    "x-frame-options": {
        "display_name": "X-Frame-Options",
        "cwe_id": "CWE-1021",
        "default_severity": FindingSeverity.MEDIUM,
        "description": (
            "Defends against clickjacking by controlling whether the site may be framed."
        ),
        "remediation": "Send 'X-Frame-Options: DENY' or 'SAMEORIGIN' (or use CSP frame-ancestors).",
    },
    "referrer-policy": {
        "display_name": "Referrer-Policy",
        "cwe_id": "CWE-200",
        "default_severity": FindingSeverity.LOW,
        "description": (
            "Protects against leaking sensitive URL paths in Referer headers upon navigation."
        ),
        "remediation": (
            "Configure 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'."
        ),
    },
    "permissions-policy": {
        "display_name": "Permissions-Policy",
        "cwe_id": "CWE-693",
        "default_severity": FindingSeverity.LOW,
        "description": (
            "Controls browser hardware features (camera, microphone, geolocation, payment)."
        ),
        "remediation": "Define 'Permissions-Policy' to restrict access to sensitive client APIs.",
    },
}


def build_safe_http_client() -> httpx.Client:
    """Instantiate httpx.Client armed with SSRFSafeNetworkBackend and strict timeouts."""
    pool = httpcore.ConnectionPool(
        network_backend=SSRFSafeNetworkBackend(),
        max_connections=10,
        max_keepalive_connections=2,
    )
    transport = httpx.HTTPTransport(verify=True)
    transport._pool = pool

    return httpx.Client(
        transport=transport,
        timeout=httpx.Timeout(
            connect=REQUEST_TIMEOUT_SECONDS,
            read=REQUEST_TIMEOUT_SECONDS,
            write=REQUEST_TIMEOUT_SECONDS,
            pool=REQUEST_TIMEOUT_SECONDS,
        ),
        follow_redirects=False,  # Redirects manually validated per hop
        headers={
            "User-Agent": "CyberShield-SecurityAnalyzer/1.0 (Defensive-Audit; Authorized-Only)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        },
    )


def fetch_headers_safely(target_url: str) -> Tuple[httpx.Headers, int, str, int, bool]:
    """Execute safe HTTP probe with per-hop SSRF validation and redirect bounding.

    Returns (headers, status_code, final_url, redirect_count, is_https).
    """
    client = build_safe_http_client()

    current_url = target_url
    redirect_count = 0

    try:
        while True:
            # Validate every hop before making connection
            parsed = validate_target_url(current_url)
            is_https = parsed.scheme.lower() == "https"

            # Prefer HEAD request to minimize bandwidth and processing
            try:
                response = client.head(current_url)
                if response.status_code in (405, 501):  # Method Not Allowed / Not Implemented
                    # Safely fallback to GET with bounded body read
                    with client.stream("GET", current_url) as stream_resp:
                        # Read at most MAX_BODY_BYTES
                        _ = stream_resp.read(MAX_BODY_BYTES)
                        response = stream_resp
            except (httpcore.NetworkError, httpx.RequestError) as exc:
                # If HEAD fails with protocol issue, try GET
                try:
                    with client.stream("GET", current_url) as stream_resp:
                        _ = stream_resp.read(MAX_BODY_BYTES)
                        response = stream_resp
                except Exception:
                    raise exc

            # Check for HTTP redirect
            if response.status_code in (301, 302, 303, 307, 308):
                location = response.headers.get("Location")
                if not location:
                    break  # Malformed redirect without Location header

                # Compute target hop URL
                next_url = urllib.parse.urljoin(current_url, location)
                redirect_count += 1

                if redirect_count > MAX_REDIRECTS:
                    raise SSRFProtectionError(
                        f"Redirect chain exceeded defensive limit ({MAX_REDIRECTS} hops)."
                    )

                current_url = next_url
                continue

            # Non-redirect response reached
            return (
                response.headers,
                response.status_code,
                current_url,
                redirect_count,
                is_https,
            )
    finally:
        client.close()


class HeaderAnalyzerService:
    """Service for orchestrating web security headers assessment and finding creation."""

    @staticmethod
    def evaluate_headers(
        headers: httpx.Headers,
        is_https: bool,
    ) -> Tuple[List[HeaderEvaluationDetail], int, str, Dict[str, Any], List[str]]:
        """Evaluate raw HTTP headers against defensive cybersecurity benchmarks.

        Returns (evaluation_details, score, grade, present_dict, missing_list).
        """
        details: List[HeaderEvaluationDetail] = []
        headers_present: Dict[str, Any] = {}
        headers_missing: List[str] = []

        # Case-insensitive header dictionary
        raw_headers = {k.lower(): v for k, v in headers.items()}

        score = 100

        # 1. Content-Security-Policy
        csp_val = raw_headers.get("content-security-policy")
        if csp_val:
            headers_present["content-security-policy"] = csp_val
            is_weak = "'unsafe-inline'" in csp_val or "'unsafe-eval'" in csp_val
            details.append(
                HeaderEvaluationDetail(
                    name="Content-Security-Policy",
                    status="weak" if is_weak else "present",
                    value=csp_val[:300],
                    severity="low" if is_weak else "none",
                    description=SECURITY_HEADERS_SPEC["content-security-policy"]["description"],
                    recommendation=(
                        "Refactor script execution to eliminate 'unsafe-inline' and "
                        "'unsafe-eval' directives."
                        if is_weak
                        else "CSP directives configured."
                    ),
                )
            )
            if is_weak:
                score -= 10
        else:
            headers_missing.append("content-security-policy")
            details.append(
                HeaderEvaluationDetail(
                    name="Content-Security-Policy",
                    status="missing",
                    value=None,
                    severity="medium",
                    description=SECURITY_HEADERS_SPEC["content-security-policy"]["description"],
                    recommendation=SECURITY_HEADERS_SPEC["content-security-policy"]["remediation"],
                )
            )
            score -= 25

        # 2. Strict-Transport-Security (HSTS)
        hsts_val = raw_headers.get("strict-transport-security")
        if not is_https:
            headers_missing.append("strict-transport-security")
            details.append(
                HeaderEvaluationDetail(
                    name="Strict-Transport-Security",
                    status="missing",
                    value=None,
                    severity="medium",
                    description=(
                        "HSTS is unavailable because the endpoint communicates over "
                        "cleartext HTTP."
                    ),
                    recommendation="Migrate target web service to HTTPS to enable HSTS protection.",
                )
            )
            score -= 25
        elif hsts_val:
            headers_present["strict-transport-security"] = hsts_val
            is_weak = "max-age" not in hsts_val.lower() or "max-age=0" in hsts_val.lower()
            details.append(
                HeaderEvaluationDetail(
                    name="Strict-Transport-Security",
                    status="weak" if is_weak else "present",
                    value=hsts_val[:300],
                    severity="low" if is_weak else "none",
                    description=SECURITY_HEADERS_SPEC["strict-transport-security"]["description"],
                    recommendation=(
                        "Set HSTS max-age to at least 31536000 (1 year) with includeSubDomains."
                        if is_weak
                        else "HSTS policy successfully enforced."
                    ),
                )
            )
            if is_weak:
                score -= 10
        else:
            headers_missing.append("strict-transport-security")
            details.append(
                HeaderEvaluationDetail(
                    name="Strict-Transport-Security",
                    status="missing",
                    value=None,
                    severity="medium",
                    description=SECURITY_HEADERS_SPEC["strict-transport-security"]["description"],
                    recommendation=SECURITY_HEADERS_SPEC["strict-transport-security"][
                        "remediation"
                    ],
                )
            )
            score -= 20

        # 3. X-Content-Type-Options
        xcto_val = raw_headers.get("x-content-type-options")
        if xcto_val:
            headers_present["x-content-type-options"] = xcto_val
            is_valid = xcto_val.lower().strip() == "nosniff"
            details.append(
                HeaderEvaluationDetail(
                    name="X-Content-Type-Options",
                    status="present" if is_valid else "weak",
                    value=xcto_val,
                    severity="none" if is_valid else "low",
                    description=SECURITY_HEADERS_SPEC["x-content-type-options"]["description"],
                    recommendation=(
                        "Header active with 'nosniff'."
                        if is_valid
                        else "Ensure header value is strictly set to 'nosniff'."
                    ),
                )
            )
            if not is_valid:
                score -= 5
        else:
            headers_missing.append("x-content-type-options")
            details.append(
                HeaderEvaluationDetail(
                    name="X-Content-Type-Options",
                    status="missing",
                    value=None,
                    severity="low",
                    description=SECURITY_HEADERS_SPEC["x-content-type-options"]["description"],
                    recommendation=SECURITY_HEADERS_SPEC["x-content-type-options"]["remediation"],
                )
            )
            score -= 15

        # 4. X-Frame-Options
        xfo_val = raw_headers.get("x-frame-options")
        csp_frame_ancestors = csp_val and "frame-ancestors" in csp_val.lower()

        if xfo_val:
            headers_present["x-frame-options"] = xfo_val
            is_valid = xfo_val.lower().strip() in ("deny", "sameorigin")
            details.append(
                HeaderEvaluationDetail(
                    name="X-Frame-Options",
                    status="present" if is_valid else "weak",
                    value=xfo_val,
                    severity="none" if is_valid else "low",
                    description=SECURITY_HEADERS_SPEC["x-frame-options"]["description"],
                    recommendation=(
                        "Clickjacking protection configured."
                        if is_valid
                        else "Use 'DENY' or 'SAMEORIGIN' for X-Frame-Options."
                    ),
                )
            )
            if not is_valid:
                score -= 5
        elif csp_frame_ancestors:
            details.append(
                HeaderEvaluationDetail(
                    name="X-Frame-Options",
                    status="present",
                    value="Handled via CSP frame-ancestors",
                    severity="none",
                    description="Clickjacking mitigated via CSP frame-ancestors directive.",
                    recommendation="Modern framing restriction active via CSP.",
                )
            )
        else:
            headers_missing.append("x-frame-options")
            details.append(
                HeaderEvaluationDetail(
                    name="X-Frame-Options",
                    status="missing",
                    value=None,
                    severity="medium",
                    description=SECURITY_HEADERS_SPEC["x-frame-options"]["description"],
                    recommendation=SECURITY_HEADERS_SPEC["x-frame-options"]["remediation"],
                )
            )
            score -= 15

        # 5. Referrer-Policy
        ref_val = raw_headers.get("referrer-policy")
        if ref_val:
            headers_present["referrer-policy"] = ref_val
            is_weak = ref_val.lower().strip() == "unsafe-url"
            details.append(
                HeaderEvaluationDetail(
                    name="Referrer-Policy",
                    status="weak" if is_weak else "present",
                    value=ref_val,
                    severity="low" if is_weak else "none",
                    description=SECURITY_HEADERS_SPEC["referrer-policy"]["description"],
                    recommendation=(
                        "Replace 'unsafe-url' with 'strict-origin-when-cross-origin' "
                        "or 'no-referrer'."
                        if is_weak
                        else "Referrer-Policy configured."
                    ),
                )
            )
            if is_weak:
                score -= 10
        else:
            headers_missing.append("referrer-policy")
            details.append(
                HeaderEvaluationDetail(
                    name="Referrer-Policy",
                    status="missing",
                    value=None,
                    severity="low",
                    description=SECURITY_HEADERS_SPEC["referrer-policy"]["description"],
                    recommendation=SECURITY_HEADERS_SPEC["referrer-policy"]["remediation"],
                )
            )
            score -= 15

        # 6. Permissions-Policy
        perm_val = raw_headers.get("permissions-policy") or raw_headers.get("feature-policy")
        if perm_val:
            headers_present["permissions-policy"] = perm_val
            details.append(
                HeaderEvaluationDetail(
                    name="Permissions-Policy",
                    status="present",
                    value=perm_val[:300],
                    severity="none",
                    description=SECURITY_HEADERS_SPEC["permissions-policy"]["description"],
                    recommendation="Client hardware API restrictions active.",
                )
            )
        else:
            headers_missing.append("permissions-policy")
            details.append(
                HeaderEvaluationDetail(
                    name="Permissions-Policy",
                    status="missing",
                    value=None,
                    severity="low",
                    description=SECURITY_HEADERS_SPEC["permissions-policy"]["description"],
                    recommendation=SECURITY_HEADERS_SPEC["permissions-policy"]["remediation"],
                )
            )
            score -= 10

        # Bound score
        score = max(0, min(100, score))

        # Assign letter grade
        if score >= 90:
            grade = "A+"
        elif score >= 80:
            grade = "A"
        elif score >= 65:
            grade = "B"
        elif score >= 50:
            grade = "C"
        elif score >= 35:
            grade = "D"
        else:
            grade = "F"

        return details, score, grade, headers_present, headers_missing

    @classmethod
    def analyze_target(
        cls,
        db: Session,
        target_url: str,
        current_user: User,
        request: Request | None = None,
    ) -> HeaderAnalysisResponse:
        """Probe authorized web target, evaluate headers, and record findings in registry."""
        # 1. Fetch headers through SSRF-safe client
        (
            headers,
            status_code,
            final_url,
            redirect_count,
            is_https,
        ) = fetch_headers_safely(target_url)

        # 2. Evaluate security posture
        (
            eval_details,
            score,
            grade,
            headers_present,
            headers_missing,
        ) = cls.evaluate_headers(headers, is_https)

        # 3. Persist WebSecurityResult entity
        web_sec_record = WebSecurityResult(
            user_id=current_user.id,
            target_url=target_url,
            grade=grade,
            score=score,
            headers_present=headers_present,
            headers_missing=headers_missing,
            cookies_analysis=[],
            created_at=datetime.now(timezone.utc),
        )
        db.add(web_sec_record)
        db.commit()
        db.refresh(web_sec_record)

        # 4. Integrate with Findings Engine: generate findings for missing or weak headers
        created_finding_ids: List[str] = []

        evidence_snippet = (
            f"HTTP Response Status: {status_code}\nFinal URL: {final_url}\n"
            + "\n".join(
                f"{k}: {v}" for k, v in headers.items() if not k.lower().startswith("set-cookie")
            )
        )

        for detail in eval_details:
            if detail.status in ("missing", "weak"):
                spec = SECURITY_HEADERS_SPEC.get(detail.name.lower(), {})
                sev = spec.get("default_severity", FindingSeverity.LOW)

                netloc = urllib.parse.urlparse(final_url).netloc
                finding_title = f"{detail.status.capitalize()} {detail.name} Header on {netloc}"
                finding_desc = (
                    f"The web application response at '{final_url}' is {detail.status} the "
                    f"'{detail.name}' security header. {detail.description}"
                )

                created_finding = FindingService.create_finding(
                    db=db,
                    finding_in=FindingCreate(
                        title=finding_title,
                        description=finding_desc,
                        severity=sev,
                        category="web_security",
                        source_module="web_security_headers",
                        affected_resource=final_url,
                        remediation=detail.recommendation,
                        evidence=evidence_snippet[:1500],
                        cwe_id=spec.get("cwe_id"),
                        status=FindingStatus.OPEN,
                    ),
                    current_user=current_user,
                    request=request,
                )
                created_finding_ids.append(created_finding.id)

        return HeaderAnalysisResponse(
            id=web_sec_record.id,
            target_url=target_url,
            final_url=final_url,
            status_code=status_code,
            is_https=is_https,
            redirect_count=redirect_count,
            grade=grade,
            score=score,
            headers=eval_details,
            created_findings_count=len(created_finding_ids),
            created_finding_ids=created_finding_ids,
            analyzed_at=web_sec_record.created_at,
        )

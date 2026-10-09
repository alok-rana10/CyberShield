"""Target and Port Security Validation for Authorized Network Scanner.

Enforces strict defense-in-depth:
- Rejects malformed targets, URL schemes, path traversal, and port syntax in host.
- Unconditionally blocks cloud metadata, broadcast, multicast, and 0.0.0.0.
- Restricts target scope to configured authorized target policy (SCAN_ALLOWED_TARGETS).
- Validates and bounds port counts to prevent resource exhaustion / abuse.
"""

import ipaddress
import re
import socket
from typing import Dict, List, Optional, Set, Tuple

from app.config import get_settings


class ScanSecurityError(Exception):
    """Base exception for network scanner security violations."""

    pass


class UnauthorizedScanTargetError(ScanSecurityError):
    """Raised when target violates the authorized target policy or contacts prohibited networks."""

    pass


class InvalidScanTargetError(ScanSecurityError):
    """Raised when target host format is malformed or unresolvable."""

    pass


class InvalidPortConfigurationError(ScanSecurityError):
    """Raised when requested ports are invalid, empty, or exceed configured limits."""

    pass


# Unconditionally blocked hostnames (cloud metadata, internal control planes)
UNCONDITIONALLY_BLOCKED_HOSTNAMES: Set[str] = {
    "metadata.google.internal",
    "metadata.goog",
    "instance-data",
    "169.254.169.254",
    "100.100.100.200",
}

# Unconditionally blocked IP networks / addresses
UNCONDITIONALLY_BLOCKED_NETWORKS = [
    ipaddress.ip_network("169.254.169.254/32"),  # Cloud metadata
    ipaddress.ip_network("100.100.100.200/32"),  # Alibaba cloud metadata
    ipaddress.ip_network("0.0.0.0/8"),  # Current network / unspecified
    ipaddress.ip_network("255.255.255.255/32"),  # Broadcast
    ipaddress.ip_network("224.0.0.0/4"),  # Multicast IPv4
    ipaddress.ip_network("ff00::/8"),  # Multicast IPv6
    ipaddress.ip_network("::/128"),  # Unspecified IPv6
]

# Standard Presets
COMMON_PORTS: List[int] = [
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    143,
    443,
    445,
    993,
    995,
    1433,
    1521,
    3306,
    3389,
    5432,
    6379,
    8080,
    8443,
]

WEB_PORTS: List[int] = [80, 443, 8000, 8080, 8443, 8888, 9000]

DATABASE_PORTS: List[int] = [1433, 1521, 3306, 5432, 6379, 27017]

PORT_PRESETS: Dict[str, List[int]] = {
    "common": COMMON_PORTS,
    "web": WEB_PORTS,
    "database": DATABASE_PORTS,
}

# Well-known service port mappings
WELL_KNOWN_SERVICES: Dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8000: "HTTP-Dev",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    8888: "HTTP-Alt",
    9000: "HTTP-Alt",
    27017: "MongoDB",
}

# Valid hostname RFC 1123 regex (no schemes, ports, or paths)
HOSTNAME_REGEX = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)" r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)


def is_ip_unconditionally_prohibited(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> Tuple[bool, str]:
    """Check if an IP address violates unconditional security boundaries."""
    # Unpack IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped

    for net in UNCONDITIONALLY_BLOCKED_NETWORKS:
        if isinstance(net, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
            try:
                if ip in net:
                    return True, f"Target IP {ip} belongs to prohibited network range {net}."
            except TypeError:
                continue

    return False, ""


def matches_authorized_policy(
    target_str: str,
    ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address,
    allowed_entries: List[str],
) -> bool:
    """Check whether a target string or IP address matches the configured policy."""
    lower_target = target_str.lower().strip()

    for entry in allowed_entries:
        entry_clean = entry.strip().lower()
        if not entry_clean:
            continue

        # Exact string match (e.g. "localhost", "127.0.0.1")
        if lower_target == entry_clean:
            return True

        # Check if entry is CIDR or single IP
        try:
            if "/" in entry_clean:
                net = ipaddress.ip_network(entry_clean, strict=False)
                # Compare IP versions
                if (
                    isinstance(ip_obj, ipaddress.IPv4Address)
                    and isinstance(net, ipaddress.IPv4Network)
                ) or (
                    isinstance(ip_obj, ipaddress.IPv6Address)
                    and isinstance(net, ipaddress.IPv6Network)
                ):
                    if ip_obj in net:
                        return True
            else:
                entry_ip = ipaddress.ip_address(entry_clean)
                if ip_obj == entry_ip:
                    return True
        except ValueError:
            # Entry is not an IP/CIDR; compare as hostname or domain suffix
            if lower_target == entry_clean:
                return True
            if lower_target.endswith(f".{entry_clean}"):
                return True

    return False


def validate_and_resolve_scan_target(target: str) -> Tuple[str, str]:
    """Validate, sanitize, and resolve target host.

    Returns:
        Tuple[str, str]: (sanitized_target_host, primary_resolved_ip_str)

    Raises:
        InvalidScanTargetError: If syntax is invalid or DNS resolution fails.
        UnauthorizedScanTargetError: If target is not authorized or is in blocked ranges.
    """
    settings = get_settings()

    if not target or not isinstance(target, str):
        raise InvalidScanTargetError("Target host cannot be empty.")

    target = target.strip()
    if not target:
        raise InvalidScanTargetError("Target host cannot be empty.")

    # 1. Reject dangerous control characters, null bytes, whitespace
    if any(c in target for c in ("\x00", "\r", "\n", "\t", " ", "'", '"', ";")):
        raise InvalidScanTargetError("Target contains invalid or dangerous characters.")

    # 2. Reject URI schemes, path separators, query parameters, userinfo
    if "://" in target or "/" in target or "\\" in target or "?" in target or "#" in target:
        raise InvalidScanTargetError(
            "Target host must be an IP address or hostname, not a URL or path."
        )
    if "@" in target:
        raise InvalidScanTargetError("Target cannot contain user credentials (@).")

    # 3. Reject port notation in hostname field (e.g. host:80)
    # Check for IPv4/hostname with colon port suffix
    if ":" in target and not target.startswith("["):
        # Could be an IPv6 address or host:port
        # If it contains only hex digits and colons, it might be an IPv6 address
        try:
            ipaddress.ip_address(target)
        except ValueError:
            # Check if someone typed host:port or [ipv6]:port
            raise InvalidScanTargetError(
                "Target host cannot contain port numbers. Specify ports in the ports parameter."
            )
    elif target.startswith("[") and "]:" in target:
        raise InvalidScanTargetError(
            "Target host cannot contain port numbers. Specify ports in the ports parameter."
        )

    # Check unconditionally blocked hostnames
    if target.lower() in UNCONDITIONALLY_BLOCKED_HOSTNAMES:
        raise UnauthorizedScanTargetError(
            f"Target '{target}' is an unconditionally prohibited destination."
        )

    # 4. Resolve IP or Hostname
    resolved_ips: List[ipaddress.IPv4Address | ipaddress.IPv6Address] = []

    try:
        # Check direct IP
        ip_obj = ipaddress.ip_address(target.strip("[]"))
        resolved_ips.append(ip_obj)
        canonical_target = str(ip_obj)
    except ValueError:
        # Hostname format validation
        clean_host = target.lower()
        if not HOSTNAME_REGEX.match(clean_host):
            raise InvalidScanTargetError(f"Invalid hostname format: '{target}'.")

        canonical_target = clean_host
        try:
            # Resolve DNS
            addr_info = socket.getaddrinfo(clean_host, None)
            for item in addr_info:
                sockaddr = item[4]
                ip_str = sockaddr[0]
                try:
                    resolved_ips.append(ipaddress.ip_address(ip_str))
                except ValueError:
                    continue
        except (socket.gaierror, socket.herror) as exc:
            raise InvalidScanTargetError(f"Failed to resolve target hostname '{clean_host}': {exc}")

    if not resolved_ips:
        raise InvalidScanTargetError(f"No valid IP addresses resolved for target '{target}'.")

    # 5. Check unconditional prohibitions on every resolved IP
    for ip in resolved_ips:
        prohibited, reason = is_ip_unconditionally_prohibited(ip)
        if prohibited:
            raise UnauthorizedScanTargetError(reason)

    # 6. Enforce Configured Authorized Target Policy
    allowed_entries = settings.scan_allowed_targets_list
    if not allowed_entries:
        raise UnauthorizedScanTargetError("No authorized scan targets are configured on server.")

    # Check if target or any resolved IP matches the authorized policy
    authorized = False
    for ip in resolved_ips:
        if matches_authorized_policy(canonical_target, ip, allowed_entries):
            authorized = True
            break

    if not authorized:
        raise UnauthorizedScanTargetError(
            f"Target '{canonical_target}' ({resolved_ips[0]}) is not permitted by "
            f"the authorized scan target policy. Allowed targets: "
            f"{', '.join(allowed_entries)}"
        )

    return canonical_target, str(resolved_ips[0])


def validate_and_normalize_ports(
    ports: Optional[List[int]] = None,
    preset: Optional[str] = "common",
    max_ports: Optional[int] = None,
) -> List[int]:
    """Validate, normalize, and bound requested ports.

    Raises:
        InvalidPortConfigurationError: If ports are invalid, empty, or exceed max_ports.
    """
    settings = get_settings()
    effective_max = max_ports if max_ports is not None else settings.SCAN_MAX_PORTS_PER_SCAN

    resolved_ports: List[int] = []

    if ports is not None:
        if not isinstance(ports, list):
            raise InvalidPortConfigurationError("Ports parameter must be a list of integers.")
        if len(ports) == 0:
            raise InvalidPortConfigurationError("Port list cannot be empty.")
        for p in ports:
            try:
                port_int = int(p)
            except (ValueError, TypeError):
                raise InvalidPortConfigurationError(f"Invalid port value: '{p}'.")
            if port_int < 1 or port_int > 65535:
                raise InvalidPortConfigurationError(
                    f"Port {port_int} out of valid range (1 - 65535)."
                )
            resolved_ports.append(port_int)
    elif preset:
        preset_key = preset.strip().lower()
        if preset_key not in PORT_PRESETS:
            raise InvalidPortConfigurationError(
                f"Unknown port preset: '{preset}'. Available: {', '.join(PORT_PRESETS.keys())}."
            )
        resolved_ports = list(PORT_PRESETS[preset_key])
    else:
        resolved_ports = list(COMMON_PORTS)

    if not resolved_ports:
        raise InvalidPortConfigurationError("Port list cannot be empty.")

    # Deduplicate and sort
    unique_ports = sorted(list(set(resolved_ports)))

    if len(unique_ports) > effective_max:
        raise InvalidPortConfigurationError(
            f"Requested port count ({len(unique_ports)}) exceeds maximum "
            f"allowed limit of {effective_max} ports per scan."
        )

    return unique_ports

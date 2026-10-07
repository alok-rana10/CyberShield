"""Mandatory SSRF Protection and DNS Rebinding Prevention Module.

Ensures CyberShield only contacts explicitly authorized, public web targets.
Blocks loopback, private RFC1918, link-local, cloud metadata, multicast,
unspecified, and internal network boundaries with TOCTOU/DNS rebinding defense.
"""

import ipaddress
import socket
import urllib.parse
from typing import List, Set, Tuple
import httpcore


class SSRFProtectionError(Exception):
    """Raised when an outbound request destination violates SSRF safety boundaries."""

    pass


class InvalidTargetURLError(Exception):
    """Raised when target URL structure, scheme, or port violates security policy."""

    pass


# Allowed web schemes
ALLOWED_SCHEMES: Set[str] = {"http", "https"}

# Allowed ports (Strict defensive policy: standard HTTP and HTTPS ports only)
ALLOWED_PORTS: Set[int] = {80, 443}

# Suffixes and names identifying internal/private networks
INTERNAL_HOST_SUFFIXES: Tuple[str, ...] = (
    ".local",
    ".internal",
    ".lan",
    ".home",
    ".corp",
    ".intranet",
    ".private",
    ".test",
    ".example",
    ".invalid",
    ".localhost",
)

EXPLICIT_BLOCKED_HOSTNAMES: Set[str] = {
    "localhost",
    "metadata.google.internal",
    "metadata.goog",
    "instance-data",
}

# Explicit cloud metadata addresses and special CIDR blocks
ADDITIONAL_BLOCKED_NETWORKS = [
    ipaddress.ip_network("100.64.0.0/10"),  # Carrier-grade NAT
    ipaddress.ip_network("198.18.0.0/15"),  # Network benchmark tests
    ipaddress.ip_network("192.0.2.0/24"),  # TEST-NET-1
    ipaddress.ip_network("198.51.100.0/24"),  # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),  # TEST-NET-3
    ipaddress.ip_network("240.0.0.0/4"),  # Reserved / Future use
    ipaddress.ip_network("0.0.0.0/8"),  # Current network
    ipaddress.ip_network("255.255.255.255/32"),  # Broadcast
]

EXPLICIT_BLOCKED_IPS: Set[str] = {
    "169.254.169.254",  # AWS/GCP/Azure/OpenStack metadata
    "100.100.100.200",  # Alibaba cloud metadata
}


def is_ip_disallowed(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> Tuple[bool, str]:
    """Check if an IP address belongs to any private, loopback, or reserved range.

    Handles IPv4, IPv6, and IPv4-mapped IPv6 addresses.
    """
    # Unpack IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped

    ip_str = str(ip)

    if ip_str in EXPLICIT_BLOCKED_IPS:
        return True, f"Explicit cloud metadata address {ip_str} is prohibited."

    if ip.is_loopback:
        return True, f"Loopback address {ip_str} is prohibited."

    if ip.is_private:
        return True, f"Private address range {ip_str} is prohibited."

    if ip.is_link_local:
        return True, f"Link-local address {ip_str} is prohibited."

    if ip.is_multicast:
        return True, f"Multicast address {ip_str} is prohibited."

    if ip.is_unspecified:
        return True, f"Unspecified address {ip_str} is prohibited."

    if ip.is_reserved:
        return True, f"Reserved address range {ip_str} is prohibited."

    for net in ADDITIONAL_BLOCKED_NETWORKS:
        if ip in net:
            return True, f"Address {ip_str} in restricted network {net} is prohibited."

    return False, ""


def resolve_and_validate_hostname(hostname: str, port: int) -> List[str]:
    """Resolve DNS for hostname and validate EVERY resolved IP address against SSRF rules.

    Raises SSRFProtectionError if ANY resolved IP is in a forbidden range.
    """
    # Check if host is a raw IP literal
    try:
        raw_ip = ipaddress.ip_address(hostname.strip("[]"))
        disallowed, reason = is_ip_disallowed(raw_ip)
        if disallowed:
            raise SSRFProtectionError(f"Target destination rejected: {reason}")
        return [str(raw_ip)]
    except ValueError:
        pass  # Host is a domain name

    # Check hostname patterns
    lower_host = hostname.lower().strip()
    if lower_host in EXPLICIT_BLOCKED_HOSTNAMES:
        raise SSRFProtectionError(f"Target host '{hostname}' is an internal reserved hostname.")

    if any(lower_host.endswith(suffix) for suffix in INTERNAL_HOST_SUFFIXES):
        raise SSRFProtectionError(
            f"Target host '{hostname}' resolves to an internal network domain."
        )

    # DNS Resolution
    try:
        addr_info = socket.getaddrinfo(
            lower_host,
            port,
            proto=socket.IPPROTO_TCP,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        raise SSRFProtectionError(f"DNS resolution failed for target host '{hostname}': {exc}")

    if not addr_info:
        raise SSRFProtectionError(f"No DNS records returned for target host '{hostname}'.")

    validated_ips: List[str] = []
    for _family, _type, _proto, _canonname, sockaddr in addr_info:
        ip_str = sockaddr[0]
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            raise SSRFProtectionError(f"Malformed IP returned by DNS: '{ip_str}'")

        disallowed, reason = is_ip_disallowed(ip_obj)
        if disallowed:
            raise SSRFProtectionError(
                f"Target host '{hostname}' resolved to prohibited IP {ip_str}: {reason}"
            )
        if ip_str not in validated_ips:
            validated_ips.append(ip_str)

    if not validated_ips:
        raise SSRFProtectionError(
            f"No valid public IP addresses found for target host '{hostname}'."
        )

    return validated_ips


def validate_target_url(raw_url: str) -> urllib.parse.ParseResult:
    """Validate target URL scheme, port, format, and SSRF security boundaries."""
    if not raw_url or not isinstance(raw_url, str):
        raise InvalidTargetURLError("Target URL must be a non-empty string.")

    cleaned_url = raw_url.strip()

    # Reject whitespace or control characters
    if any(c in cleaned_url for c in (" ", "\t", "\r", "\n")):
        raise InvalidTargetURLError("Target URL contains invalid whitespace characters.")

    try:
        parsed = urllib.parse.urlparse(cleaned_url)
    except Exception as exc:
        raise InvalidTargetURLError(f"Malformed URL structure: {exc}")

    # 1. Scheme Check
    if not parsed.scheme or parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise InvalidTargetURLError(
            f"Unsupported URL scheme '{parsed.scheme}'. Only http:// and https:// are permitted."
        )

    # 2. Hostname Check
    if not parsed.hostname:
        raise InvalidTargetURLError("Target URL is missing a valid hostname.")

    # 3. Credentials Check
    if parsed.username or parsed.password:
        raise InvalidTargetURLError("Target URL must not contain embedded user credentials.")

    # 4. Port Check
    port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    if port not in ALLOWED_PORTS:
        raise InvalidTargetURLError(
            f"Port {port} is not permitted. Only standard web ports (80, 443) are allowed."
        )

    # 5. DNS and IP SSRF Validation
    resolve_and_validate_hostname(parsed.hostname, port)

    return parsed


class SSRFSafeNetworkBackend(httpcore.SyncBackend):
    """Network backend that enforces pre-connection IP verification and pins the socket.

    Guarantees that the IP actually connected to is identical to the verified IP,
    completely preventing DNS rebinding / TOCTOU vulnerabilities.
    """

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options=None,
    ) -> httpcore.NetworkStream:
        """Resolve, validate against SSRF boundaries, and connect directly to the validated IP."""
        if port not in ALLOWED_PORTS:
            raise SSRFProtectionError(f"Connection to port {port} rejected by defensive policy.")

        # Resolve host and validate every candidate IP
        validated_ips = resolve_and_validate_hostname(host, port)
        target_ip = validated_ips[0]

        # Connect directly to target_ip (so no secondary DNS lookup occurs)
        return super().connect_tcp(
            host=target_ip,
            port=port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )

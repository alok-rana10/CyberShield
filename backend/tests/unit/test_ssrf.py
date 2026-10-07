"""Comprehensive unit tests for mandatory SSRF protection and URL validation."""

import pytest
from unittest.mock import patch
import socket

from app.security.ssrf import (
    InvalidTargetURLError,
    SSRFProtectionError,
    resolve_and_validate_hostname,
    validate_target_url,
)


def test_reject_unsupported_schemes():
    """Verify that only http and https schemes are permitted."""
    prohibited_schemes = [
        "file:///etc/passwd",
        "file:///C:/Windows/win.ini",
        "ftp://public-mirror.com/file",
        "gopher://gopher.floodgap.com",
        "data:text/plain;base64,SGVsbG8=",
        "javascript:alert(1)",
        "dict://dict.org",
        "ldap://ldap.internal",
    ]
    for url in prohibited_schemes:
        with pytest.raises(InvalidTargetURLError) as exc_info:
            validate_target_url(url)
        assert "scheme" in str(exc_info.value).lower()


def test_reject_embedded_credentials():
    """Verify that URLs containing embedded user credentials are rejected."""
    credentials_urls = [
        "https://admin:secret123@example.com",
        "http://user@example.com",
        "https://root:toor@1.1.1.1",
    ]
    for url in credentials_urls:
        with pytest.raises(InvalidTargetURLError) as exc_info:
            validate_target_url(url)
        assert "credentials" in str(exc_info.value).lower()


def test_reject_unsafe_ports():
    """Verify that ports other than standard web ports (80, 443) are rejected."""
    unsafe_ports_urls = [
        "http://example.com:22",  # SSH
        "http://example.com:25",  # SMTP
        "http://example.com:3306",  # MySQL
        "http://example.com:6379",  # Redis
        "http://example.com:27017",  # MongoDB
        "http://example.com:8000",  # Internal dev port
        "https://example.com:8443",  # Non-standard TLS
    ]
    for url in unsafe_ports_urls:
        with pytest.raises(InvalidTargetURLError) as exc_info:
            validate_target_url(url)
        assert "port" in str(exc_info.value).lower()


def test_reject_internal_domain_names():
    """Verify that internal domain names and suffixes are blocked before DNS lookup."""
    internal_hosts = [
        "http://localhost",
        "https://localhost:443",
        "http://service.local",
        "http://k8s.internal",
        "http://router.lan",
        "http://server.corp",
        "http://nas.home",
        "http://metadata.google.internal",
        "http://metadata.goog",
        "http://instance-data",
    ]
    for url in internal_hosts:
        with pytest.raises(SSRFProtectionError) as exc_info:
            validate_target_url(url)
        assert (
            "internal" in str(exc_info.value).lower() or "reserved" in str(exc_info.value).lower()
        )


def test_reject_direct_private_and_loopback_ips():
    """Verify that direct IP destinations in loopback, RFC1918, link-local,
    and metadata ranges are blocked."""
    prohibited_ips = [
        "http://127.0.0.1",
        "http://127.0.0.2",
        "http://10.0.0.1",
        "http://10.254.0.1",
        "http://172.16.0.1",
        "http://172.31.255.255",
        "http://192.168.0.1",
        "http://192.168.1.254",
        "http://169.254.169.254",  # AWS/Cloud metadata
        "http://100.100.100.200",  # Alibaba metadata
        "http://100.64.0.1",  # Carrier-grade NAT
        "http://0.0.0.0",  # Unspecified
        "http://255.255.255.255",  # Broadcast
        "http://[::1]",  # IPv6 loopback
        "http://[fc00::1]",  # IPv6 ULA private
        "http://[fe80::1]",  # IPv6 link-local
        "http://[::ffff:127.0.0.1]",  # IPv4-mapped loopback
        "http://[::ffff:169.254.169.254]",  # IPv4-mapped metadata
    ]
    for url in prohibited_ips:
        with pytest.raises(SSRFProtectionError) as exc_info:
            validate_target_url(url)
        assert (
            "prohibited" in str(exc_info.value).lower() or "rejected" in str(exc_info.value).lower()
        )


def test_reject_dns_resolving_to_private_ip():
    """Verify that hostnames that resolve to private or loopback IP addresses are blocked."""
    # Mock DNS resolution to return a private IP
    fake_addrinfo = [
        (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("192.168.1.100", 80))
    ]

    with patch("socket.getaddrinfo", return_value=fake_addrinfo):
        with pytest.raises(SSRFProtectionError) as exc_info:
            resolve_and_validate_hostname("legitimate-looking-name.com", 80)
        assert "prohibited" in str(exc_info.value).lower()


def test_reject_dns_resolving_to_loopback_ip():
    """Verify that hostnames that resolve to 127.0.0.1 are blocked."""
    fake_addrinfo = [
        (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", 80))
    ]

    with patch("socket.getaddrinfo", return_value=fake_addrinfo):
        with pytest.raises(SSRFProtectionError) as exc_info:
            resolve_and_validate_hostname("rebind-to-localhost.example.org", 80)
        assert "loopback" in str(exc_info.value).lower()


def test_reject_dns_returning_mixed_ips_with_one_private():
    """Verify that if ANY resolved IP in a multi-homed response is private,
    the target is rejected."""
    fake_addrinfo = [
        (
            socket.AF_INET,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
            "",
            ("93.184.216.34", 80),
        ),  # Public
        (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("10.0.0.5", 80)),  # Private
    ]

    with patch("socket.getaddrinfo", return_value=fake_addrinfo):
        with pytest.raises(SSRFProtectionError) as exc_info:
            resolve_and_validate_hostname("split-dns.attacker.com", 80)
        assert "prohibited" in str(exc_info.value).lower()


def test_allow_valid_public_target():
    """Verify that valid public web targets with legitimate public IPs pass validation."""
    fake_addrinfo = [
        (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", 443))
    ]

    with patch("socket.getaddrinfo", return_value=fake_addrinfo):
        parsed = validate_target_url("https://example.com/login")
        assert parsed.scheme == "https"
        assert parsed.hostname == "example.com"


def test_reject_dns_resolution_failure():
    """Verify that hostnames that fail DNS resolution raise SSRFProtectionError."""
    with patch("socket.getaddrinfo", side_effect=socket.gaierror("Name or service not known")):
        with pytest.raises(SSRFProtectionError) as exc_info:
            resolve_and_validate_hostname("nonexistent-domain-12345.xyz", 80)
        assert "dns resolution failed" in str(exc_info.value).lower()

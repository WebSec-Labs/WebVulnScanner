import ipaddress
import socket

import pytest

from app.scanner.scope import (
    InvalidTargetUrlError,
    RedirectScopeViolationError,
    ScopePolicy,
    SSRFProhibitedError,
    TargetNotAuthorizedError,
    TargetScope,
    _sort_ip_addresses,
    is_prohibited_ip,
    normalize_url,
)


def test_normalize_url_basic():
    """Verify standard URL normalization rules."""
    assert normalize_url("HTTP://EXAMPLE.COM") == "http://example.com/"
    assert normalize_url("https://example.com:443/test#frag") == "https://example.com/test"
    assert normalize_url("http://example.com:80/path?q=1#top") == "http://example.com/path?q=1"
    assert normalize_url("https://example.com:8443/api") == "https://example.com:8443/api"
    assert normalize_url("   https://example.com/   ") == "https://example.com/"


def test_normalize_url_unsupported_schemes():
    """Verify rejection of non-HTTP schemes."""
    invalid_schemes = [
        "ftp://example.com/file",
        "file:///etc/passwd",
        "javascript:alert(1)",
        "gopher://example.com",
        "ssh://git@github.com",
        "ws://example.com/socket",
    ]
    for url in invalid_schemes:
        with pytest.raises(InvalidTargetUrlError):
            normalize_url(url)


def test_normalize_url_malformed():
    """Verify rejection of empty, whitespace, and malformed inputs."""
    with pytest.raises(InvalidTargetUrlError):
        normalize_url("")
    with pytest.raises(InvalidTargetUrlError):
        normalize_url("   ")
    with pytest.raises(InvalidTargetUrlError):
        normalize_url("not_a_valid_url")
    with pytest.raises(InvalidTargetUrlError):
        normalize_url("http://")


def test_normalize_url_rejects_non_canonical_ips():
    """Verify non-canonical IPv4 representations (decimal, octal, hex, abbreviated) are rejected."""
    non_canonical_urls = [
        "http://2130706433/",  # Decimal integer representation of 127.0.0.1
        "http://0177.0.0.1/",  # Octal notation with leading zeros
        "http://127.1/",  # Abbreviated notation (2 octets)
        "http://10.1.1/",  # Abbreviated notation (3 octets)
        "http://0x7f000001/",  # Hexadecimal representation
        "http://0x7f.0.0.1/",  # Mixed hex-dotted representation
    ]
    for url in non_canonical_urls:
        with pytest.raises(InvalidTargetUrlError):
            normalize_url(url)


def test_trailing_dot_hostname_normalization():
    """Verify trailing dot FQDNs are normalized and validated consistently."""
    assert normalize_url("http://localhost./") == "http://localhost/"
    assert normalize_url("https://example.com./test") == "https://example.com/test"

    # Trailing dot localhost triggers SSRF protection
    scope = TargetScope(allowed_hosts={"localhost"})
    policy = ScopePolicy(scope, dns_resolver=lambda _: ["127.0.0.1"])
    with pytest.raises(SSRFProhibitedError):
        policy.validate_url("http://localhost./")

    # Trailing dot authorized host matches allowed scope
    allowed_scope = TargetScope(allowed_hosts={"example.com"})
    allowed_policy = ScopePolicy(allowed_scope, dns_resolver=lambda _: ["93.184.216.34"])
    assert allowed_policy.validate_url("https://example.com./api") == "https://example.com/api"


def test_ipv4_mapped_ipv6_prohibitions():
    """Verify IPv4-mapped IPv6 addresses are checked against prohibited ranges."""
    # CGNAT
    assert is_prohibited_ip(ipaddress.ip_address("::ffff:100.64.0.1")) is True
    # Cloud metadata
    assert is_prohibited_ip(ipaddress.ip_address("::ffff:169.254.169.254")) is True
    # Loopback
    assert is_prohibited_ip(ipaddress.ip_address("::ffff:127.0.0.1")) is True
    # RFC 1918 Private
    assert is_prohibited_ip(ipaddress.ip_address("::ffff:192.168.1.1")) is True
    assert is_prohibited_ip(ipaddress.ip_address("::ffff:10.0.0.1")) is True
    assert is_prohibited_ip(ipaddress.ip_address("::ffff:172.16.0.1")) is True
    # Public IP should not be prohibited
    assert is_prohibited_ip(ipaddress.ip_address("::ffff:8.8.8.8")) is False


def test_scope_policy_authorized_hosts():
    """Verify in-scope and out-of-scope host decisions."""
    scope = TargetScope(allowed_hosts={"example.com"})
    policy = ScopePolicy(scope, dns_resolver=lambda _: ["93.184.216.34"])

    # In scope
    assert policy.validate_url("https://example.com/index.html") == "https://example.com/index.html"
    assert policy.validate_url("http://EXAMPLE.COM/api") == "http://example.com/api"

    # Out of scope
    with pytest.raises(TargetNotAuthorizedError):
        policy.validate_url("https://attacker.com/steal")

    with pytest.raises(TargetNotAuthorizedError):
        policy.validate_url("https://sub.example.com/test")


def test_scope_policy_subdomains_option():
    """Verify subdomain policy enforcement."""
    scope = TargetScope(allowed_hosts={"example.com"}, allow_subdomains=True)
    policy = ScopePolicy(scope, dns_resolver=lambda _: ["93.184.216.34"])

    assert policy.validate_url("https://api.example.com/v1") == "https://api.example.com/v1"
    assert (
        policy.validate_url("https://staging.internal.example.com/")
        == "https://staging.internal.example.com/"
    )

    with pytest.raises(TargetNotAuthorizedError):
        policy.validate_url("https://notexample.com/")


def test_scope_policy_unauthorized_ports():
    """Verify port restriction enforcement."""
    scope = TargetScope(allowed_hosts={"example.com"}, allowed_ports={80, 443})
    policy = ScopePolicy(scope, dns_resolver=lambda _: ["93.184.216.34"])

    assert policy.validate_url("https://example.com/") == "https://example.com/"

    with pytest.raises(TargetNotAuthorizedError):
        policy.validate_url("https://example.com:8443/")


def test_ssrf_prohibitions_ip_literals():
    """Verify hard blocking of loopback, private, link-local, and metadata IPs."""
    scope = TargetScope(allowed_hosts={"127.0.0.1", "10.0.0.1", "169.254.169.254", "192.168.1.1"})
    policy = ScopePolicy(scope)

    blocked_targets = [
        "http://127.0.0.1/",
        "http://10.0.0.1/",
        "http://192.168.1.1/",
        "http://172.16.0.1/",
        "http://169.254.169.254/latest/meta-data/",  # Cloud metadata
        "http://100.64.0.1/",  # CGNAT
        "http://[::1]/",  # IPv6 loopback
        "http://[::ffff:127.0.0.1]/",  # IPv4-mapped loopback
        "http://[::ffff:169.254.169.254]/",  # IPv4-mapped metadata
    ]

    for target in blocked_targets:
        with pytest.raises(SSRFProhibitedError):
            policy.validate_url(target)


def test_ssrf_prohibitions_reserved_hostnames():
    """Verify hard blocking of localhost and internal hostnames."""
    scope = TargetScope(allowed_hosts={"localhost", "service.local", "metadata.google.internal"})
    policy = ScopePolicy(scope)

    with pytest.raises(SSRFProhibitedError):
        policy.validate_url("http://localhost:8000/")

    with pytest.raises(SSRFProhibitedError):
        policy.validate_url("http://service.local/")

    with pytest.raises(SSRFProhibitedError):
        policy.validate_url("http://metadata.google.internal/")


def test_dns_resolution_mixed_public_and_private_rejected():
    """Verify hostnames returning mixed public and private addresses are rejected."""
    scope = TargetScope(allowed_hosts={"mixed.example.com"})

    # Resolver returns one public IP and one private/loopback IP
    def mixed_resolver(host: str) -> list[str]:
        return ["93.184.216.34", "127.0.0.1"]

    policy = ScopePolicy(scope, dns_resolver=mixed_resolver)

    with pytest.raises(SSRFProhibitedError):
        policy.validate_url("https://mixed.example.com/")


def test_dns_resolution_failure_rejected():
    """Verify that DNS resolution failures cause conservative request rejection."""
    scope = TargetScope(allowed_hosts={"nonexistent.example.com"})

    def failing_resolver(host: str) -> list[str]:
        raise socket.gaierror(-2, "Name or service not known")

    policy = ScopePolicy(scope, dns_resolver=failing_resolver)

    with pytest.raises(InvalidTargetUrlError):
        policy.validate_url("https://nonexistent.example.com/")


def test_controlled_local_lab_targets():
    """Verify controlled opt-in allows local lab testing without weakening default."""
    lab_scope = TargetScope(
        allowed_hosts={"127.0.0.1", "localhost"},
        allowed_ports={8000, 8080},
        allow_local_lab_targets=True,
    )
    policy = ScopePolicy(lab_scope, dns_resolver=lambda _: ["127.0.0.1"])

    assert policy.validate_url("http://127.0.0.1:8000/app") == "http://127.0.0.1:8000/app"
    assert policy.validate_url("http://localhost:8080/test") == "http://localhost:8080/test"


def test_redirect_scope_revalidation():
    """Verify redirect destinations are revalidated before following."""
    scope = TargetScope(allowed_hosts={"example.com"})
    policy = ScopePolicy(scope, dns_resolver=lambda _: ["93.184.216.34"])

    # Valid relative redirect
    resolved = policy.validate_redirect("https://example.com/login", "/dashboard")
    assert resolved == "https://example.com/dashboard"

    # Valid absolute redirect within scope
    resolved = policy.validate_redirect("https://example.com/old", "https://example.com/new")
    assert resolved == "https://example.com/new"

    # Out-of-scope redirect rejected
    with pytest.raises(RedirectScopeViolationError):
        policy.validate_redirect("https://example.com/login", "https://attacker.com/steal")

    # Redirect to internal IP rejected
    with pytest.raises(RedirectScopeViolationError):
        policy.validate_redirect("https://example.com/page", "http://169.254.169.254/latest")

    # Empty Location rejected
    with pytest.raises(RedirectScopeViolationError):
        policy.validate_redirect("https://example.com/", "")


def test_ip_address_deterministic_sorting():
    """Verify IP addresses are deduplicated and sorted deterministically (IPv4 first, then IPv6)."""
    ips = {
        "2606:4700:4700::1111",
        "93.184.216.34",
        "198.51.100.1",
        "2001:db8::1",
        "93.184.216.34",  # duplicate
    }
    sorted_ips = _sort_ip_addresses(ips)
    # IPv4 addresses must come first, sorted numerically
    assert sorted_ips[0] == "93.184.216.34"
    assert sorted_ips[1] == "198.51.100.1"
    # Followed by IPv6 addresses
    assert sorted_ips[2] == "2001:db8::1"
    assert sorted_ips[3] == "2606:4700:4700::1111"
    assert len(sorted_ips) == 4


@pytest.mark.asyncio
async def test_async_dns_resolution_and_validation():
    """Verify async DNS resolution validates destinations without blocking the event loop."""
    scope = TargetScope(allowed_hosts={"example.com"})

    def blocking_resolver(host: str) -> list[str]:
        return ["93.184.216.34"]

    policy = ScopePolicy(scope, dns_resolver=blocking_resolver)
    normalized = await policy.validate_url_async("https://example.com/api")
    assert normalized == "https://example.com/api"

    pinned_ip = await policy.resolve_and_validate_destination_async("example.com", 443)
    assert pinned_ip == "93.184.216.34"


@pytest.mark.asyncio
async def test_async_dns_mixed_public_and_private_rejected():
    """Verify async DNS resolution rejects mixed public and private IP responses."""
    scope = TargetScope(allowed_hosts={"mixed.example.com"})
    policy = ScopePolicy(scope, dns_resolver=lambda _: ["93.184.216.34", "127.0.0.1"])

    with pytest.raises(SSRFProhibitedError):
        await policy.validate_url_async("https://mixed.example.com/")

    with pytest.raises(SSRFProhibitedError):
        await policy.resolve_and_validate_destination_async("mixed.example.com", 443)


@pytest.mark.asyncio
async def test_async_dns_failure_rejected():
    """Verify async DNS resolution failure raises InvalidTargetUrlError."""
    scope = TargetScope(allowed_hosts={"nonexistent.example.com"})

    def failing_resolver(host: str) -> list[str]:
        raise socket.gaierror(-2, "Name or service not known")

    policy = ScopePolicy(scope, dns_resolver=failing_resolver)
    with pytest.raises(InvalidTargetUrlError):
        await policy.validate_url_async("https://nonexistent.example.com/")

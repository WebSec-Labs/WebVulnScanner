"""Unit tests for crawler URL normalization and same-origin validation."""

from unittest.mock import patch

import pytest

from app.scanner.crawler.normalizer import (
    MAX_URL_LENGTH,
    get_effective_origin,
    is_same_origin,
    normalize_crawler_url,
    remove_dot_segments,
    resolve_and_normalize_url,
)
from app.scanner.scope import (
    InvalidTargetUrlError,
    TargetNotAuthorizedError,
)


def test_remove_dot_segments():
    """Verify RFC 3986 5.2.4 dot segment removal preserving encoding and trailing slashes."""
    cases = [
        ("/a/b/../c", "/a/c"),
        ("/a/b/./c", "/a/b/c"),
        ("/a/b/../", "/a/"),
        ("/a/b/..", "/a/"),
        ("/..", "/"),
        ("/../../", "/"),
        ("/", "/"),
        ("", "/"),
        ("/path/to/file.html", "/path/to/file.html"),
        ("/dir/", "/dir/"),
        ("/foo%20bar/../baz", "/baz"),
        ("/foo%2Fbar/sub", "/foo%2Fbar/sub"),
    ]
    for raw, expected in cases:
        assert remove_dot_segments(raw) == expected


def test_resolve_relative_and_absolute_references():
    """Verify relative URL resolution against a base URL."""
    base = "https://example.com/app/index.html"

    # Same directory
    assert (
        resolve_and_normalize_url("dashboard.html", base)
        == "https://example.com/app/dashboard.html"
    )
    # Root relative
    assert resolve_and_normalize_url("/api/v1/users", base) == "https://example.com/api/v1/users"
    # Parent relative with dot segments
    assert (
        resolve_and_normalize_url("../settings/profile", base)
        == "https://example.com/settings/profile"
    )
    # Current directory dot segment
    assert resolve_and_normalize_url("./details", base) == "https://example.com/app/details"
    # Absolute URL
    assert (
        resolve_and_normalize_url("https://example.com/logout", base)
        == "https://example.com/logout"
    )


def test_resolve_protocol_relative_reference():
    """Verify resolution of protocol-relative references inheriting base scheme."""
    base = "https://example.com/home"
    assert (
        resolve_and_normalize_url("//example.com/assets/img.png", base)
        == "https://example.com/assets/img.png"
    )

    http_base = "http://example.com:8080/home"
    assert (
        resolve_and_normalize_url("//example.com:8080/other", http_base)
        == "http://example.com:8080/other"
    )


def test_resolve_fragments_stripped():
    """Verify that URI fragments are stripped from resolved URLs."""
    base = "https://example.com/docs/"
    assert resolve_and_normalize_url("#section-1", base) == "https://example.com/docs/"
    assert resolve_and_normalize_url("/api#method-get", base) == "https://example.com/api"
    assert (
        resolve_and_normalize_url("page.html?v=1#heading", base)
        == "https://example.com/docs/page.html?v=1"
    )


def test_query_strings_semantically_distinct():
    """Verify query strings are preserved without sorting or collapsing parameters."""
    base = "https://example.com/"
    url_a = resolve_and_normalize_url("?b=2&a=1", base)
    url_b = resolve_and_normalize_url("?a=1&b=2", base)
    url_c = resolve_and_normalize_url("?a=1&a=2", base)

    assert url_a == "https://example.com/?b=2&a=1"
    assert url_b == "https://example.com/?a=1&b=2"
    assert url_c == "https://example.com/?a=1&a=2"
    assert url_a != url_b  # Query order preserved to maintain exact semantics


def test_empty_reference_resolves_to_base():
    """Verify empty string reference resolves to the normalized base URL."""
    base = "https://example.com/path/to/page"
    assert resolve_and_normalize_url("", base) == "https://example.com/path/to/page"
    assert resolve_and_normalize_url("   ", base) == "https://example.com/path/to/page"


def test_trailing_dot_hosts_normalized():
    """Verify hostnames with trailing FQDN dots are normalized."""
    assert normalize_crawler_url("https://example.com./path") == "https://example.com/path"
    assert normalize_crawler_url("https://sub.EXAMPLE.COM.:443/") == "https://sub.example.com/"


def test_default_ports_omitted_non_default_preserved():
    """Verify default ports (80/443) are omitted while custom ports are retained."""
    assert normalize_crawler_url("http://example.com:80/") == "http://example.com/"
    assert normalize_crawler_url("https://example.com:443/") == "https://example.com/"
    assert normalize_crawler_url("http://example.com:8080/") == "http://example.com:8080/"
    assert normalize_crawler_url("https://example.com:8443/") == "https://example.com:8443/"


def test_userinfo_credentials_rejected():
    """Verify that credentials in URLs are rejected for safety."""
    with pytest.raises(InvalidTargetUrlError, match="Userinfo credentials"):
        normalize_crawler_url("http://user:pass@example.com/")

    with pytest.raises(InvalidTargetUrlError, match="Userinfo credentials"):
        normalize_crawler_url("http://admin@example.com/admin")

    with pytest.raises(InvalidTargetUrlError, match="Userinfo credentials"):
        normalize_crawler_url("http://@example.com/")

    with pytest.raises(InvalidTargetUrlError, match="Userinfo credentials"):
        resolve_and_normalize_url("http://user:pass@example.com/leak", "https://example.com/")


def test_non_http_schemes_rejected():
    """Verify that non-HTTP/HTTPS schemes raise InvalidTargetUrlError."""
    base = "https://example.com/"
    for ref in (
        "javascript:alert(1)",
        "mailto:admin@example.com",
        "data:text/html,<h1>Test</h1>",
        "tel:+1234567890",
        "ftp://example.com/file",
        "file:///etc/passwd",
        "blob:https://example.com/uuid",
    ):
        with pytest.raises(InvalidTargetUrlError, match="Unsupported scheme"):
            resolve_and_normalize_url(ref, base)


def test_unsupported_and_invalid_ports_rejected():
    """Verify that unauthorized ports or ports out of 1-65535 are rejected."""
    # Port not in default allowed ports (80, 443, 8080, 8443)
    with pytest.raises(InvalidTargetUrlError, match="Port 22 is not authorized"):
        normalize_crawler_url("http://example.com:22/")

    # Invalid port syntax
    with pytest.raises(InvalidTargetUrlError, match="Invalid host or port"):
        normalize_crawler_url("http://example.com:notaport/")


def test_ipv4_and_ipv6_literals():
    """Verify handling of standard IPv4 and IPv6 bracket notation."""
    assert normalize_crawler_url("http://192.0.2.1:8080/test") == "http://192.0.2.1:8080/test"
    assert (
        normalize_crawler_url("http://[2001:db8::1]:8080/test") == "http://[2001:db8::1]:8080/test"
    )
    assert normalize_crawler_url("http://[::1]:80/status") == "http://[::1]/status"


def test_non_canonical_ipv4_rejected():
    """Verify rejection of non-canonical IPv4 representations."""
    # Integer format
    with pytest.raises(InvalidTargetUrlError, match="Non-canonical integer IPv4"):
        normalize_crawler_url("http://2130706433/")

    # Octal format
    with pytest.raises(InvalidTargetUrlError, match="Octal-style IP"):
        normalize_crawler_url("http://0177.0.0.1/")

    # Hexadecimal format
    with pytest.raises(InvalidTargetUrlError, match="Hexadecimal IP"):
        normalize_crawler_url("http://0x7f000001/")

    # Abbreviated format
    with pytest.raises(InvalidTargetUrlError, match="Abbreviated IPv4"):
        normalize_crawler_url("http://127.1/")


def test_url_maximum_length_exceeded():
    """Verify rejection of URLs exceeding MAX_URL_LENGTH characters."""
    oversized = "https://example.com/" + ("a" * (MAX_URL_LENGTH + 10))
    with pytest.raises(InvalidTargetUrlError, match="exceeds maximum limit"):
        normalize_crawler_url(oversized)


def test_encoded_paths_preserved():
    """Verify that percent-encoded characters are not decoded arbitrarily."""
    base = "https://example.com/"
    assert resolve_and_normalize_url("/search%20term", base) == "https://example.com/search%20term"
    assert (
        resolve_and_normalize_url("/folder%2Fsubfolder", base)
        == "https://example.com/folder%2Fsubfolder"
    )


def test_same_origin_comparison():
    """Verify strict same-origin comparison using scheme, hostname, and effective port."""
    # Same origin
    assert is_same_origin("http://example.com", "http://example.com:80") is True
    assert is_same_origin("https://example.com", "https://example.com:443") is True
    assert is_same_origin("https://EXAMPLE.com./", "https://example.com") is True
    assert is_same_origin("http://example.com:8080/a", "http://example.com:8080/b") is True
    assert is_same_origin("http://[::1]:80/a", "http://[::1]/b") is True

    # Different schemes
    assert is_same_origin("http://example.com", "https://example.com") is False
    # Different hosts
    assert is_same_origin("https://example.com", "https://sub.example.com") is False
    assert is_same_origin("https://example.com", "https://other.com") is False
    # Different ports
    assert is_same_origin("http://example.com:8080", "http://example.com:8081") is False
    assert is_same_origin("http://example.com:8080", "http://example.com") is False
    # Malformed inputs fail closed
    assert is_same_origin("not a url", "https://example.com") is False
    assert is_same_origin("https://example.com", "") is False


def test_resolve_with_same_origin_only_flag():
    """Verify same_origin_only flag in resolve_and_normalize_url."""
    base = "https://example.com/app/"

    # In-origin link succeeds
    assert (
        resolve_and_normalize_url("/app/dash", base, same_origin_only=True)
        == "https://example.com/app/dash"
    )

    # Cross-origin link raises TargetNotAuthorizedError
    with pytest.raises(TargetNotAuthorizedError, match="does not match origin"):
        resolve_and_normalize_url("https://external.com/page", base, same_origin_only=True)

    with pytest.raises(TargetNotAuthorizedError, match="does not match origin"):
        resolve_and_normalize_url("//subdomain.example.com/page", base, same_origin_only=True)


def test_get_effective_origin():
    """Verify get_effective_origin extracts tuple with effective port."""
    origin_http = get_effective_origin("http://example.com/test")
    assert origin_http.scheme == "http"
    assert origin_http.hostname == "example.com"
    assert origin_http.effective_port == 80

    origin_https = get_effective_origin("https://example.com/test")
    assert origin_https.scheme == "https"
    assert origin_https.hostname == "example.com"
    assert origin_https.effective_port == 443

    origin_custom = get_effective_origin("https://example.com:8443/test")
    assert origin_custom.effective_port == 8443


def test_normalizer_no_network_or_dns_lookups():
    """Prove that normalizer performs zero network or DNS lookups."""
    with (
        patch("socket.getaddrinfo") as mock_dns,
        patch("socket.socket") as mock_sock,
    ):
        result = resolve_and_normalize_url("/api/data?test=1#frag", "https://example.com/base/")
        assert result == "https://example.com/api/data?test=1"
        mock_dns.assert_not_called()
        mock_sock.assert_not_called()

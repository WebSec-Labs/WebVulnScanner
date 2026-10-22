"""URL normalization, relative link resolution, and same-origin validation for crawlers.

Reuses and aligns with app.scanner.scope normalization policies while adding:
- RFC 3986 dot-segment resolution (removing '.' and '..' without altering path encodings)
- Strict same-origin evaluation (scheme, normalized hostname, effective port)
- Rejection of userinfo credentials, non-HTTP/HTTPS schemes, and oversized URLs
- Preservation of query string semantics (no sorting or parameter collapsing)
- Purely deterministic, offline execution with zero DNS or network operations
"""

from typing import NamedTuple
from urllib.parse import urljoin, urlsplit, urlunsplit

from app.scanner.scope import (
    InvalidTargetUrlError,
    ScopeError,
    TargetNotAuthorizedError,
)

MAX_URL_LENGTH = 2048
DEFAULT_ALLOWED_PORTS = frozenset({80, 443, 8080, 8443})
DEFAULT_PORT_MAP = {"http": 80, "https": 443}


class CrawlerUrlError(ScopeError):
    """Base exception for crawler URL resolution and normalization errors."""


class EffectiveOrigin(NamedTuple):
    """Immutable representation of an effective HTTP/HTTPS origin."""

    scheme: str
    hostname: str
    effective_port: int


def remove_dot_segments(path: str) -> str:
    """Resolve and remove '.' and '..' dot segments per RFC 3986 Section 5.2.4.

    Preserves path percent-encodings, query strings, and trailing slashes.
    """
    if not path or path == "/":
        return "/"

    segments: list[str] = []
    ends_with_slash = path.endswith("/") or path.endswith("/.") or path.endswith("/..")

    for seg in path.split("/"):
        if seg == "." or seg == "":
            continue
        if seg == "..":
            if segments:
                segments.pop()
        else:
            segments.append(seg)

    normalized = "/" + "/".join(segments)
    if ends_with_slash and not normalized.endswith("/"):
        normalized += "/"
    return normalized


def get_effective_port(scheme: str, port: int | None) -> int:
    """Return explicit port or standard default port for HTTP/HTTPS scheme."""
    if port is not None:
        return port
    return DEFAULT_PORT_MAP.get(scheme.lower(), 0)


def get_effective_origin(url: str) -> EffectiveOrigin:
    """Extract and validate the effective origin (scheme, normalized host, effective port).

    Raises:
        InvalidTargetUrlError: If the URL is malformed, lacks host, or has invalid scheme.
    """
    if not url or not isinstance(url, str):
        raise InvalidTargetUrlError("URL must be a non-empty string")

    stripped = url.strip()
    if not stripped:
        raise InvalidTargetUrlError("URL cannot be whitespace only")

    try:
        parts = urlsplit(stripped)
    except Exception as exc:
        raise InvalidTargetUrlError(f"Malformed URL: {exc}") from exc

    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        raise InvalidTargetUrlError(
            f"Unsupported scheme '{parts.scheme}'. Only 'http' and 'https' are allowed."
        )

    try:
        hostname = parts.hostname
        port = parts.port
    except ValueError as exc:
        raise InvalidTargetUrlError(f"Invalid host or port in URL: {exc}") from exc

    if not hostname:
        raise InvalidTargetUrlError("URL is missing a valid hostname")

    clean_hostname = hostname.rstrip(".").lower()
    effective_port = get_effective_port(scheme, port)

    if effective_port < 1 or effective_port > 65535:
        raise InvalidTargetUrlError(f"Port {effective_port} is out of valid range (1-65535)")

    return EffectiveOrigin(
        scheme=scheme,
        hostname=clean_hostname,
        effective_port=effective_port,
    )


def is_same_origin(url_a: str, url_b: str) -> bool:
    """Return True if both URLs share the exact same scheme, normalized host, and effective port.

    Fails closed and returns False if either URL is malformed.
    """
    try:
        origin_a = get_effective_origin(url_a)
        origin_b = get_effective_origin(url_b)
        return origin_a == origin_b
    except Exception:
        return False


def normalize_crawler_url(
    url: str,
    allowed_ports: set[int] | frozenset[int] | None = None,
    max_length: int = MAX_URL_LENGTH,
) -> str:
    """Normalize and validate an absolute URL for crawler operations.

    Enforces:
    - Maximum character length cap
    - Rejection of userinfo credentials (user:pass@)
    - Scheme must be strictly 'http' or 'https'
    - Hostname downcasing and trailing-dot removal
    - Rejection of non-canonical IPv4 representations (octal, hex, integer, abbreviated)
    - Port authorization against allowed_ports
    - IPv6 bracket notation
    - Default port omission from netloc
    - RFC 3986 dot-segment resolution on paths
    - Stripping of URI fragments (#...)
    - Preservation of query strings without parameter reordering

    Raises:
        InvalidTargetUrlError: If URL fails validation or exceeds bounds.
    """
    if not url or not isinstance(url, str):
        raise InvalidTargetUrlError("URL must be a non-empty string")

    stripped = url.strip()
    if not stripped:
        raise InvalidTargetUrlError("URL cannot be whitespace only")

    if len(stripped) > max_length:
        raise InvalidTargetUrlError(
            f"URL length ({len(stripped)}) exceeds maximum limit of {max_length} characters"
        )

    try:
        parts = urlsplit(stripped)
    except Exception as exc:
        raise InvalidTargetUrlError(f"Malformed URL: {exc}") from exc

    # Reject userinfo credentials
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        raise InvalidTargetUrlError("Userinfo credentials in URL are not allowed")

    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        raise InvalidTargetUrlError(
            f"Unsupported scheme '{parts.scheme}'. Only 'http' and 'https' are allowed."
        )

    if not parts.netloc:
        raise InvalidTargetUrlError("URL is missing a valid host / netloc")

    try:
        hostname = parts.hostname
        port = parts.port
    except ValueError as exc:
        raise InvalidTargetUrlError(f"Invalid host or port in URL: {exc}") from exc

    if not hostname:
        raise InvalidTargetUrlError("URL is missing a valid hostname")

    # Normalize trailing dots for FQDNs
    clean_hostname = hostname.rstrip(".").lower()

    # Reject non-canonical IPv4 representations (integer, octal, hex, abbreviated)
    if clean_hostname.isdigit():
        raise InvalidTargetUrlError(
            f"Non-canonical integer IPv4 representation '{hostname}' is not allowed"
        )

    host_parts = clean_hostname.split(".")
    if any(p.lower().startswith("0x") for p in host_parts):
        raise InvalidTargetUrlError(f"Hexadecimal IP representation '{hostname}' is not allowed")
    if any(p.startswith("0") and len(p) > 1 for p in host_parts):
        raise InvalidTargetUrlError(
            f"Octal-style IP representation with leading zeros '{hostname}' is not allowed"
        )
    if 1 < len(host_parts) < 4 and all(p.isdigit() for p in host_parts):
        raise InvalidTargetUrlError(
            f"Abbreviated IPv4 address representation '{hostname}' is not allowed"
        )

    # Validate destination port against allowed ports
    effective_port = get_effective_port(scheme, port)
    if effective_port < 1 or effective_port > 65535:
        raise InvalidTargetUrlError(f"Port {effective_port} is out of valid range (1-65535)")

    permitted_ports = allowed_ports if allowed_ports is not None else DEFAULT_ALLOWED_PORTS
    if effective_port not in permitted_ports:
        raise InvalidTargetUrlError(
            f"Port {effective_port} is not authorized. Allowed ports: {sorted(permitted_ports)}"
        )

    # Canonical netloc representation
    if ":" in clean_hostname and not clean_hostname.startswith("["):
        host_repr = f"[{clean_hostname}]"
    else:
        host_repr = clean_hostname

    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443) or port is None:
        netloc = host_repr
    else:
        netloc = f"{host_repr}:{port}"

    # Path normalization: remove dot segments while preserving encoding and trailing slash
    raw_path = parts.path or "/"
    path = remove_dot_segments(raw_path)

    # Fragment stripped; query string preserved as-is
    return urlunsplit((scheme, netloc, path, parts.query, ""))


def resolve_and_normalize_url(
    reference: str,
    base_url: str,
    allowed_ports: set[int] | frozenset[int] | None = None,
    max_length: int = MAX_URL_LENGTH,
    same_origin_only: bool = False,
) -> str:
    """Resolve a relative or absolute URL reference against base_url and normalize it.

    Args:
        reference: Target reference (relative path, protocol-relative, absolute, or empty).
        base_url: Authoritative current page URL serving as resolution base.
        allowed_ports: Explicit set of permitted destination ports.
        max_length: Maximum allowed character length for the resolved URL.
        same_origin_only: If True, raises TargetNotAuthorizedError on cross-origin destinations.

    Returns:
        Canonical, normalized absolute URL.

    Raises:
        InvalidTargetUrlError: If base_url or resolved reference is malformed/unsupported.
        TargetNotAuthorizedError: If same_origin_only=True and resolved URL is cross-origin.
    """
    if reference is None or not isinstance(reference, str):
        raise InvalidTargetUrlError("URL reference must be a string")

    # Validate and normalize base URL first
    normalized_base = normalize_crawler_url(
        base_url,
        allowed_ports=allowed_ports,
        max_length=max_length,
    )

    stripped_ref = reference.strip()

    # urljoin handles empty string, relative paths, dot segments, and protocol-relative URLs
    try:
        resolved = urljoin(normalized_base, stripped_ref)
    except Exception as exc:
        raise InvalidTargetUrlError(
            f"Failed to resolve URL reference '{reference}': {exc}"
        ) from exc

    # Normalize the resolved absolute URL
    normalized_url = normalize_crawler_url(
        resolved,
        allowed_ports=allowed_ports,
        max_length=max_length,
    )

    if same_origin_only and not is_same_origin(normalized_base, normalized_url):
        raise TargetNotAuthorizedError(
            f"Resolved URL '{normalized_url}' does not match origin of base '{normalized_base}'"
        )

    return normalized_url

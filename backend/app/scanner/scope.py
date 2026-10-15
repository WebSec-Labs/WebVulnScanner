"""Target-scope enforcement, URL normalization, and SSRF prevention."""

import asyncio
import inspect
import ipaddress
import socket
from collections.abc import Callable
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit

from pydantic import BaseModel, Field


class ScopeError(Exception):
    """Base exception for scope policy violations."""


class InvalidTargetUrlError(ScopeError):
    """Raised when a URL is malformed, has unsupported scheme, or cannot be parsed."""


class TargetNotAuthorizedError(ScopeError):
    """Raised when a destination is outside the explicitly authorized target scope."""


class SSRFProhibitedError(ScopeError):
    """Raised when a destination resolves to a private, loopback, or non-public address."""


class RedirectScopeViolationError(ScopeError):
    """Raised when an HTTP redirect attempts to escape the authorized scope."""


# Shared Address Space (RFC 6598) and standard documentation ranges
CARRIER_GRADE_NAT = ipaddress.ip_network("100.64.0.0/10")
TEST_NET_1 = ipaddress.ip_network("192.0.2.0/24")
TEST_NET_2 = ipaddress.ip_network("198.51.100.0/24")
TEST_NET_3 = ipaddress.ip_network("203.0.113.0/24")

PROHIBITED_HOSTNAMES = {
    "localhost",
    "metadata.google.internal",
    "instance-data",
}


def is_prohibited_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Return True if an IP address belongs to private, loopback, or cloud metadata ranges.

    Correctly handles IPv4-mapped IPv6 addresses (e.g. ::ffff:100.64.0.1) by unwrapping.
    """
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return is_prohibited_ip(ip.ipv4_mapped)

    if (
        ip.is_loopback
        or ip.is_private
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    ):
        return True

    if isinstance(ip, ipaddress.IPv4Address):
        if (
            ip in CARRIER_GRADE_NAT
            or ip in TEST_NET_1
            or ip in TEST_NET_2
            or ip in TEST_NET_3
            or ip == ipaddress.IPv4Address("255.255.255.255")
        ):
            return True

    return False


def normalize_url(url: str) -> str:
    """Normalize and sanitize target URL.

    - Strips surrounding whitespace.
    - Ensures scheme is strictly http or https.
    - Rejects non-canonical IPv4 representations (decimal, octal, hex, abbreviated).
    - Normalizes trailing dot hostnames.
    - Lowercases scheme and hostname.
    - Strips default ports (80 for http, 443 for https).
    - Removes URI fragments.
    - Normalizes empty path to '/'.
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

    if not parts.netloc:
        raise InvalidTargetUrlError("URL is missing a valid host / netloc")

    # Extract hostname and port
    try:
        hostname = parts.hostname
        port = parts.port
    except ValueError as exc:
        raise InvalidTargetUrlError(f"Invalid host or port in URL: {exc}") from exc

    if not hostname:
        raise InvalidTargetUrlError("URL is missing a valid hostname")

    # Normalize trailing dots for FQDNs
    hostname = hostname.rstrip(".").lower()

    # Reject non-canonical IPv4 representations (integer, octal, hex, abbreviated)
    if hostname.isdigit():
        raise InvalidTargetUrlError(
            f"Non-canonical integer IPv4 representation '{hostname}' is not allowed"
        )

    host_parts = hostname.split(".")
    if any(p.startswith("0") and len(p) > 1 for p in host_parts):
        raise InvalidTargetUrlError(
            f"Octal-style IP representation with leading zeros '{hostname}' is not allowed"
        )
    if any(p.lower().startswith("0x") for p in host_parts):
        raise InvalidTargetUrlError(f"Hexadecimal IP representation '{hostname}' is not allowed")
    if 1 < len(host_parts) < 4 and all(p.isdigit() for p in host_parts):
        raise InvalidTargetUrlError(
            f"Abbreviated IPv4 address representation '{hostname}' is not allowed"
        )

    # Reconstruct netloc with proper IPv6 bracket notation and without default ports
    if ":" in hostname and not hostname.startswith("["):
        host_repr = f"[{hostname}]"
    else:
        host_repr = hostname

    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443) or port is None:
        netloc = host_repr
    else:
        netloc = f"{host_repr}:{port}"

    # Path normalization: empty path becomes "/"
    path = parts.path or "/"

    # Omit fragments (#...) as they are not transmitted to the server
    return urlunsplit((scheme, netloc, path, parts.query, ""))


def _sort_ip_addresses(ips: set[str] | list[str]) -> list[str]:
    """Sort and canonicalize IP addresses deterministically (IPv4 first, then IPv6)."""
    parsed: list[tuple[int, int, str]] = []
    for ip_str in set(ips):
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            family_order = 0 if ip_obj.version == 4 else 1
            parsed.append((family_order, int(ip_obj), str(ip_obj)))
        except ValueError:
            parsed.append((2, 0, ip_str))
    parsed.sort()
    return [item[2] for item in parsed]


def default_dns_resolver(host: str) -> list[str]:
    """Resolve all IPv4 and IPv6 addresses for a given hostname, sorted deterministically."""
    clean_host = host.strip("[]")
    try:
        addr_info = socket.getaddrinfo(clean_host, None, proto=socket.IPPROTO_TCP)
        raw_ips = {info[4][0] for info in addr_info}
        if not raw_ips:
            raise InvalidTargetUrlError(f"DNS resolution returned no addresses for '{host}'")
        return _sort_ip_addresses(raw_ips)
    except socket.gaierror as exc:
        raise InvalidTargetUrlError(f"DNS resolution failed for '{host}': {exc}") from exc


async def async_default_dns_resolver(host: str) -> list[str]:
    """Resolve DNS asynchronously in a worker thread to keep the asyncio loop unblocked."""
    return await asyncio.to_thread(default_dns_resolver, host)


class TargetScope(BaseModel):
    """Explicitly authorized boundary for scanner operations."""

    allowed_hosts: set[str] = Field(
        ...,
        description="Set of explicitly permitted hostnames or domain names (e.g. {'example.com'})",
    )
    allowed_schemes: set[str] = Field(
        default_factory=lambda: {"http", "https"},
        description="Allowed protocols. Must be a subset of {'http', 'https'}",
    )
    allowed_ports: set[int] = Field(
        default_factory=lambda: {80, 443, 8080, 8443},
        description="Explicitly allowed destination ports",
    )
    allow_subdomains: bool = Field(
        default=False,
        description="If True, permits subdomains of any allowed_hosts (e.g., api.example.com)",
    )
    allow_local_lab_targets: bool = Field(
        default=False,
        description=(
            "Controlled configuration permitting local/private IP assessment. "
            "STRICTLY False by default to prevent accidental SSRF."
        ),
    )

    @classmethod
    def for_url(cls, target_url: str, **kwargs) -> "TargetScope":
        """Convenience constructor extracting hostname from a normalized target URL.

        NOTE: For test fixtures and CLI helpers only. Do not use alone as proof
        of authorization for user-submitted URLs without verifying caller authority.
        """
        normalized = normalize_url(target_url)
        parsed = urlsplit(normalized)
        if not parsed.hostname:
            raise InvalidTargetUrlError("Cannot extract hostname from target URL")
        return cls(allowed_hosts={parsed.hostname.rstrip(".").lower()}, **kwargs)


class ScopePolicy:
    """Enforces target authorization and SSRF guardrails on target URLs and redirects."""

    def __init__(
        self,
        scope: TargetScope,
        dns_resolver: Callable[[str], list[str]] | None = None,
        async_dns_resolver: Callable[[str], Any] | None = None,
    ):
        self.scope = scope
        self.dns_resolver = dns_resolver if dns_resolver is not None else default_dns_resolver
        self.async_dns_resolver = async_dns_resolver

    async def resolve_dns_async(self, host: str) -> list[str]:
        """Resolve DNS asynchronously, ensuring non-blocking execution on event loops."""
        if self.async_dns_resolver is not None:
            res = self.async_dns_resolver(host)
            if inspect.isawaitable(res):
                return await res
            return res
        if inspect.iscoroutinefunction(self.dns_resolver):
            return await self.dns_resolver(host)
        # Offload sync resolver to thread pool to avoid blocking the event loop
        return await asyncio.to_thread(self.dns_resolver, host)

    def _validate_resolved_ips(self, clean_hostname: str, resolved_ips: list[str]) -> None:
        """Validate all resolved addresses conservatively against prohibited ranges."""
        if not resolved_ips:
            raise InvalidTargetUrlError(
                f"DNS resolution returned no addresses for '{clean_hostname}'"
            )
        for ip_str in resolved_ips:
            try:
                resolved_ip = ipaddress.ip_address(ip_str)
                if not self.scope.allow_local_lab_targets and is_prohibited_ip(resolved_ip):
                    raise SSRFProhibitedError(
                        f"Hostname '{clean_hostname}' resolved to prohibited IP '{ip_str}'"
                    )
            except ValueError:
                raise InvalidTargetUrlError(
                    f"DNS resolved invalid IP '{ip_str}' for '{clean_hostname}'"
                )

    def validate_url(self, raw_url: str) -> str:
        """Validate and return normalized URL, or raise explicit ScopeError."""
        normalized = normalize_url(raw_url)
        parsed = urlsplit(normalized)
        scheme = parsed.scheme
        hostname = parsed.hostname
        port = parsed.port or (443 if scheme == "https" else 80)

        # 1. Scheme check
        if scheme not in self.scope.allowed_schemes:
            raise TargetNotAuthorizedError(
                f"Scheme '{scheme}' is not authorized. Allowed: {self.scope.allowed_schemes}"
            )

        assert hostname is not None  # Guaranteed by normalize_url
        clean_hostname = hostname.rstrip(".").lower()

        # 2. Check for prohibited hostnames (SSRF prevention)
        if not self.scope.allow_local_lab_targets:
            if (
                clean_hostname in PROHIBITED_HOSTNAMES
                or clean_hostname.endswith(".localhost")
                or clean_hostname.endswith(".local")
                or clean_hostname.endswith(".internal")
            ):
                raise SSRFProhibitedError(
                    f"Target hostname '{hostname}' is reserved, local, or an internal endpoint"
                )

        # 3. Check if hostname is an IP literal (SSRF prevention)
        try:
            ip_obj = ipaddress.ip_address(clean_hostname.strip("[]"))
            is_ip = True
        except ValueError:
            is_ip = False

        if is_ip:
            if not self.scope.allow_local_lab_targets and is_prohibited_ip(ip_obj):
                raise SSRFProhibitedError(
                    f"Target IP '{hostname}' belongs to a private, loopback, or non-public range"
                )

        # 4. Port check
        if port not in self.scope.allowed_ports:
            raise TargetNotAuthorizedError(
                f"Port {port} is not authorized. Allowed ports: {self.scope.allowed_ports}"
            )

        # 5. Check authorization against allowed_hosts in scope
        authorized = False
        allowed_normalized = {h.rstrip(".").lower() for h in self.scope.allowed_hosts}

        if clean_hostname in allowed_normalized:
            authorized = True
        elif self.scope.allow_subdomains:
            for allowed in allowed_normalized:
                if clean_hostname.endswith("." + allowed):
                    authorized = True
                    break

        if not authorized:
            raise TargetNotAuthorizedError(
                f"Hostname '{hostname}' is not within the authorized scope: {allowed_normalized}"
            )

        # 6. DNS resolution validation (SSRF and DNS Rebinding protection in normal runtime)
        if not is_ip and not self.scope.allow_local_lab_targets:
            try:
                resolved_ips = self.dns_resolver(clean_hostname)
            except ScopeError:
                raise
            except Exception as exc:
                raise InvalidTargetUrlError(
                    f"DNS resolution failed for '{clean_hostname}': {exc}"
                ) from exc

            self._validate_resolved_ips(clean_hostname, resolved_ips)

        return normalized

    async def validate_url_async(self, raw_url: str) -> str:
        """Asynchronously validate and normalize URL, offloading DNS to keep loop unblocked."""
        normalized = normalize_url(raw_url)
        parsed = urlsplit(normalized)
        scheme = parsed.scheme
        hostname = parsed.hostname
        port = parsed.port or (443 if scheme == "https" else 80)

        # 1. Scheme check
        if scheme not in self.scope.allowed_schemes:
            raise TargetNotAuthorizedError(
                f"Scheme '{scheme}' is not authorized. Allowed: {self.scope.allowed_schemes}"
            )

        assert hostname is not None
        clean_hostname = hostname.rstrip(".").lower()

        # 2. Check for prohibited hostnames
        if not self.scope.allow_local_lab_targets:
            if (
                clean_hostname in PROHIBITED_HOSTNAMES
                or clean_hostname.endswith(".localhost")
                or clean_hostname.endswith(".local")
                or clean_hostname.endswith(".internal")
            ):
                raise SSRFProhibitedError(
                    f"Target hostname '{hostname}' is reserved, local, or an internal endpoint"
                )

        # 3. Check if hostname is an IP literal
        try:
            ip_obj = ipaddress.ip_address(clean_hostname.strip("[]"))
            is_ip = True
        except ValueError:
            is_ip = False

        if is_ip:
            if not self.scope.allow_local_lab_targets and is_prohibited_ip(ip_obj):
                raise SSRFProhibitedError(
                    f"Target IP '{hostname}' belongs to a private, loopback, or non-public range"
                )

        # 4. Port check
        if port not in self.scope.allowed_ports:
            raise TargetNotAuthorizedError(
                f"Port {port} is not authorized. Allowed ports: {self.scope.allowed_ports}"
            )

        # 5. Check authorization against allowed_hosts in scope
        authorized = False
        allowed_normalized = {h.rstrip(".").lower() for h in self.scope.allowed_hosts}

        if clean_hostname in allowed_normalized:
            authorized = True
        elif self.scope.allow_subdomains:
            for allowed in allowed_normalized:
                if clean_hostname.endswith("." + allowed):
                    authorized = True
                    break

        if not authorized:
            raise TargetNotAuthorizedError(
                f"Hostname '{hostname}' is not within the authorized scope: {allowed_normalized}"
            )

        # 6. Async DNS resolution validation
        if not is_ip and not self.scope.allow_local_lab_targets:
            try:
                resolved_ips = await self.resolve_dns_async(clean_hostname)
            except ScopeError:
                raise
            except Exception as exc:
                raise InvalidTargetUrlError(
                    f"DNS resolution failed for '{clean_hostname}': {exc}"
                ) from exc

            self._validate_resolved_ips(clean_hostname, resolved_ips)

        return normalized

    def resolve_and_validate_destination(self, host: str, port: int) -> str:
        """Resolve and validate destination host strictly at connection time.

        Eliminates TOCTOU DNS rebinding gap by returning the validated IP address
        to which the socket must connect.
        """
        clean_host = host.strip("[]").rstrip(".").lower()

        # Check if already IP literal
        try:
            ip_obj = ipaddress.ip_address(clean_host)
            if not self.scope.allow_local_lab_targets and is_prohibited_ip(ip_obj):
                raise SSRFProhibitedError(f"Destination IP '{clean_host}' is private or prohibited")
            return clean_host
        except ValueError:
            pass

        # Check prohibited hostnames
        if not self.scope.allow_local_lab_targets:
            if (
                clean_host in PROHIBITED_HOSTNAMES
                or clean_host.endswith(".localhost")
                or clean_host.endswith(".local")
                or clean_host.endswith(".internal")
            ):
                raise SSRFProhibitedError(
                    f"Destination hostname '{clean_host}' is reserved, local, or internal"
                )

        try:
            resolved_ips = self.dns_resolver(clean_host)
        except ScopeError:
            raise
        except Exception as exc:
            raise InvalidTargetUrlError(f"DNS resolution failed for '{clean_host}': {exc}") from exc

        self._validate_resolved_ips(clean_host, resolved_ips)
        # Return the deterministically sorted validated IP address to pin socket connection
        return resolved_ips[0]

    async def resolve_and_validate_destination_async(self, host: str, port: int) -> str:
        """Asynchronously resolve and validate destination host strictly at connection time."""
        clean_host = host.strip("[]").rstrip(".").lower()

        # Check if already IP literal
        try:
            ip_obj = ipaddress.ip_address(clean_host)
            if not self.scope.allow_local_lab_targets and is_prohibited_ip(ip_obj):
                raise SSRFProhibitedError(f"Destination IP '{clean_host}' is private or prohibited")
            return clean_host
        except ValueError:
            pass

        # Check prohibited hostnames
        if not self.scope.allow_local_lab_targets:
            if (
                clean_host in PROHIBITED_HOSTNAMES
                or clean_host.endswith(".localhost")
                or clean_host.endswith(".local")
                or clean_host.endswith(".internal")
            ):
                raise SSRFProhibitedError(
                    f"Destination hostname '{clean_host}' is reserved, local, or internal"
                )

        try:
            resolved_ips = await self.resolve_dns_async(clean_host)
        except ScopeError:
            raise
        except Exception as exc:
            raise InvalidTargetUrlError(f"DNS resolution failed for '{clean_host}': {exc}") from exc

        self._validate_resolved_ips(clean_host, resolved_ips)
        # Return the deterministically sorted validated IP address to pin socket connection
        return resolved_ips[0]

    def validate_redirect(self, current_url: str, location_header: str) -> str:
        """Validate redirect destination against authorized scope."""
        if not location_header or not location_header.strip():
            raise RedirectScopeViolationError("Empty or missing Location header in redirect")

        # Resolve relative redirect URLs against current URL
        try:
            resolved = urljoin(current_url, location_header.strip())
        except Exception as exc:
            raise RedirectScopeViolationError(
                f"Failed to resolve redirect destination '{location_header}': {exc}"
            ) from exc

        try:
            return self.validate_url(resolved)
        except ScopeError as exc:
            raise RedirectScopeViolationError(
                f"Redirect destination '{resolved}' violates target scope: {exc}"
            ) from exc

    async def validate_redirect_async(self, current_url: str, location_header: str) -> str:
        """Asynchronously validate redirect destination against authorized scope."""
        if not location_header or not location_header.strip():
            raise RedirectScopeViolationError("Empty or missing Location header in redirect")

        # Resolve relative redirect URLs against current URL
        try:
            resolved = urljoin(current_url, location_header.strip())
        except Exception as exc:
            raise RedirectScopeViolationError(
                f"Failed to resolve redirect destination '{location_header}': {exc}"
            ) from exc

        try:
            return await self.validate_url_async(resolved)
        except ScopeError as exc:
            raise RedirectScopeViolationError(
                f"Redirect destination '{resolved}' violates target scope: {exc}"
            ) from exc

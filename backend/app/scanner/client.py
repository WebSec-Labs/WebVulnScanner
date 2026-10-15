"""Safe, bounded HTTP client abstraction for scanner checks."""

import asyncio
from types import TracebackType
from typing import Any
from urllib.parse import urlsplit

import httpcore
import httpx

from app.scanner.scope import ScopeError, ScopePolicy, SSRFProhibitedError


class ScannerClientError(Exception):
    """Base exception for scanner HTTP client failures."""


class RequestLimitExceededError(ScannerClientError):
    """Raised when the maximum number of requests for a scan session is reached."""


class ResponseSizeExceededError(ScannerClientError):
    """Raised when a server response exceeds the maximum allowed byte limit."""


class MaxRedirectsExceededError(ScannerClientError):
    """Raised when a request chain exceeds the maximum allowed redirects."""


class ScannerTimeoutError(ScannerClientError):
    """Raised when an HTTP operation exceeds configured timeouts."""


class ScannerNetworkError(ScannerClientError):
    """Raised for network-level connection and transport failures."""


class ScannerResponse:
    """Bounded, safe representation of an HTTP response."""

    def __init__(
        self,
        status_code: int,
        headers: httpx.Headers,
        url: str,
        content: bytes,
        history: list[str] | None = None,
    ):
        self.status_code = status_code
        self.headers = headers
        self.url = url
        self.content = content
        self.history = history or []

    @property
    def text(self) -> str:
        """Decode response body safely as UTF-8, replacing invalid sequences."""
        return self.content.decode("utf-8", errors="replace")


class SafeNetworkBackend(httpcore.AsyncNetworkBackend):
    """Network backend connecting strictly to pre-validated IP addresses.

    Eliminates TOCTOU DNS rebinding gaps by preventing secondary unpinned DNS queries.
    Preserves original Host header, TLS SNI, and certificate hostname verification.
    """

    def __init__(
        self,
        scope_policy: ScopePolicy,
        base_backend: httpcore.AsyncNetworkBackend | None = None,
    ):
        self.scope_policy = scope_policy
        self._backend = base_backend or httpcore.AnyIOBackend()

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Any = None,
    ) -> httpcore.AsyncNetworkStream:
        # Resolve and validate host immediately before socket creation (asynchronously)
        validated_ip = await self.scope_policy.resolve_and_validate_destination_async(host, port)
        # Connect socket directly to the validated IP
        return await self._backend.connect_tcp(
            validated_ip,
            port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Any = None,
    ) -> httpcore.AsyncNetworkStream:
        raise SSRFProhibitedError("Unix domain socket connections are prohibited")

    async def sleep(self, seconds: float) -> None:
        await self._backend.sleep(seconds)


class SafeHTTPTransport(httpx.AsyncHTTPTransport):
    """Custom HTTPX transport integrating SafeNetworkBackend into the connection pool."""

    def __init__(
        self,
        scope_policy: ScopePolicy,
        verify: bool = True,
        base_backend: httpcore.AsyncNetworkBackend | None = None,
        **kwargs: Any,
    ):
        super().__init__(verify=verify, **kwargs)
        self.scope_policy = scope_policy
        self.safe_backend = SafeNetworkBackend(
            scope_policy=scope_policy,
            base_backend=base_backend,
        )
        # Re-initialize pool with public APIs without accessing private _ssl_context
        ssl_context = httpx.create_ssl_context(verify=verify)
        self._pool = httpcore.AsyncConnectionPool(
            network_backend=self.safe_backend,
            ssl_context=ssl_context,
        )


def create_safe_transport(
    scope_policy: ScopePolicy,
    verify: bool = True,
    base_backend: httpcore.AsyncNetworkBackend | None = None,
) -> httpx.AsyncHTTPTransport:
    """Create an HTTPX transport bound to a DNS-pinned SafeNetworkBackend."""
    return SafeHTTPTransport(
        scope_policy=scope_policy,
        verify=verify,
        base_backend=base_backend,
    )


class ScannerHttpClient:
    """Reusable, security-constrained HTTP client for scanner checks.

    Guardrails:
    - Pre-flight scope validation before EVERY outbound request.
    - Connection-time IP pinning preventing DNS rebinding TOCTOU gaps.
    - Atomic request counting across concurrent coroutines and redirects.
    - No automatic redirect following; every hop is re-validated against TargetScope.
    - Sensitive header stripping on cross-origin redirects.
    - Strict connection and read/write timeouts.
    - Hard limit on response payload size to prevent memory exhaustion.
    - Hard cap on total requests allowed in a scan session.
    """

    def __init__(
        self,
        scope_policy: ScopePolicy,
        timeout: float = 10.0,
        connect_timeout: float = 5.0,
        max_redirects: int = 5,
        max_response_bytes: int = 1_000_000,
        max_requests: int = 50,
        transport: httpx.AsyncBaseTransport | None = None,
    ):
        self.scope_policy = scope_policy
        self.timeout = timeout
        self.connect_timeout = connect_timeout
        self.max_redirects = max_redirects
        self.max_response_bytes = max_response_bytes
        self.max_requests = max_requests
        self.request_count = 0
        self._lock = asyncio.Lock()

        # If transport not provided, construct secure transport with connection-time IP pinning
        active_transport = transport or create_safe_transport(self.scope_policy)

        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(timeout, connect=connect_timeout),
            transport=active_transport,
            follow_redirects=False,
            headers={"User-Agent": "WebVulnScanner/0.1.0 (+https://github.com/WebSec-Labs)"},
        )

    async def __aenter__(self) -> "ScannerHttpClient":
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        await self.close()

    async def close(self) -> None:
        """Close the underlying HTTP client session and release resources."""
        await self._client.aclose()

    async def _acquire_request_slot(self) -> None:
        """Atomically check and increment the request counter."""
        async with self._lock:
            if self.request_count >= self.max_requests:
                raise RequestLimitExceededError(
                    f"Scan request limit of {self.max_requests} exceeded"
                )
            self.request_count += 1

    async def request(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        **kwargs: Any,
    ) -> ScannerResponse:
        """Execute an HTTP request with strict scope validation and redirect re-checking."""
        # Pre-flight scope check BEFORE ANY request is issued (asynchronously)
        current_url = await self.scope_policy.validate_url_async(url)
        current_method = method.upper()
        current_headers = dict(headers) if headers else None
        history: list[str] = []

        for redirect_count in range(self.max_redirects + 1):
            # Atomic request budget check & increment
            await self._acquire_request_slot()

            try:
                request = self._client.build_request(
                    current_method,
                    current_url,
                    headers=current_headers,
                    **kwargs,
                )
                response = await self._client.send(request, stream=True)
            except httpx.TimeoutException as exc:
                raise ScannerTimeoutError(f"Request to '{current_url}' timed out: {exc}") from exc
            except httpx.NetworkError as exc:
                raise ScannerNetworkError(f"Connection failed for '{current_url}': {exc}") from exc
            except ScopeError:
                raise
            except Exception as exc:
                raise ScannerClientError(f"HTTP request failed for '{current_url}': {exc}") from exc

            # Read bounded response stream
            try:
                body_chunks: list[bytes] = []
                bytes_received = 0
                async for chunk in response.aiter_bytes():
                    bytes_received += len(chunk)
                    if bytes_received > self.max_response_bytes:
                        raise ResponseSizeExceededError(
                            f"Response from '{current_url}' exceeded limit of "
                            f"{self.max_response_bytes} bytes"
                        )
                    body_chunks.append(chunk)
                content = b"".join(body_chunks)
            finally:
                await response.aclose()

            # Handle redirects manually to enforce scope on every hop
            if response.status_code in (301, 302, 303, 307, 308):
                location = response.headers.get("location")
                if not location:
                    return ScannerResponse(
                        status_code=response.status_code,
                        headers=response.headers,
                        url=current_url,
                        content=content,
                        history=history,
                    )

                if redirect_count >= self.max_redirects:
                    raise MaxRedirectsExceededError(
                        f"Redirect limit of {self.max_redirects} exceeded at '{current_url}'"
                    )

                # Validate redirect destination strictly against scope policy (asynchronously)
                next_url = await self.scope_policy.validate_redirect_async(current_url, location)

                # Cross-origin sensitive header stripping
                curr_parts = urlsplit(current_url)
                next_parts = urlsplit(next_url)
                if (curr_parts.scheme, curr_parts.hostname, curr_parts.port) != (
                    next_parts.scheme,
                    next_parts.hostname,
                    next_parts.port,
                ):
                    if current_headers:
                        current_headers = {
                            k: v
                            for k, v in current_headers.items()
                            if k.lower() not in ("authorization", "cookie", "proxy-authorization")
                        }

                history.append(current_url)
                current_url = next_url

                # RFC 7231 / 9110 redirect method semantics
                if response.status_code == 303 or (
                    response.status_code in (301, 302) and current_method != "GET"
                ):
                    current_method = "GET"
                    kwargs.pop("content", None)
                    kwargs.pop("json", None)
                    kwargs.pop("data", None)

                continue

            return ScannerResponse(
                status_code=response.status_code,
                headers=response.headers,
                url=current_url,
                content=content,
                history=history,
            )

        raise MaxRedirectsExceededError(f"Redirect limit of {self.max_redirects} exceeded")

    async def get(self, url: str, **kwargs: Any) -> ScannerResponse:
        """Perform a GET request."""
        return await self.request("GET", url, **kwargs)

    async def head(self, url: str, **kwargs: Any) -> ScannerResponse:
        """Perform a HEAD request."""
        return await self.request("HEAD", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> ScannerResponse:
        """Perform a POST request."""
        return await self.request("POST", url, **kwargs)

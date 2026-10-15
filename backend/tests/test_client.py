"""Unit tests for ScannerHttpClient using mocked HTTP transports."""

import asyncio

import httpcore
import httpx
import pytest

from app.scanner.client import (
    MaxRedirectsExceededError,
    RequestLimitExceededError,
    ResponseSizeExceededError,
    SafeNetworkBackend,
    ScannerHttpClient,
    ScannerNetworkError,
    ScannerTimeoutError,
    create_safe_transport,
)
from app.scanner.scope import (
    RedirectScopeViolationError,
    ScopeError,
    ScopePolicy,
    SSRFProhibitedError,
    TargetScope,
)


@pytest.mark.asyncio
async def test_rejected_target_causes_no_outbound_request():
    """Prove that an out-of-scope or prohibited target issues zero outbound HTTP requests."""
    network_called = False

    def mock_handler(request: httpx.Request) -> httpx.Response:
        nonlocal network_called
        network_called = True
        return httpx.Response(200, text="OK")

    transport = httpx.MockTransport(mock_handler)
    scope = TargetScope(allowed_hosts={"example.com"})
    policy = ScopePolicy(scope, dns_resolver=lambda _: ["93.184.216.34"])

    async with ScannerHttpClient(scope_policy=policy, transport=transport) as client:
        # 1. Out-of-scope host
        with pytest.raises(ScopeError):
            await client.get("https://unauthorized-domain.com/")
        assert network_called is False

        # 2. SSRF target (loopback)
        with pytest.raises(ScopeError):
            await client.get("http://127.0.0.1:8000/")
        assert network_called is False

        # 3. Cloud metadata target
        with pytest.raises(ScopeError):
            await client.get("http://169.254.169.254/latest/meta-data/")
        assert network_called is False


@pytest.mark.asyncio
async def test_client_successful_request():
    """Verify that in-scope requests succeed and return bounded response."""

    def mock_handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == "https://example.com/api/test"
        return httpx.Response(
            200,
            text='{"status": "ok"}',
            headers={"Content-Type": "application/json"},
        )

    transport = httpx.MockTransport(mock_handler)
    scope = TargetScope(allowed_hosts={"example.com"})
    policy = ScopePolicy(scope, dns_resolver=lambda _: ["93.184.216.34"])

    async with ScannerHttpClient(scope_policy=policy, transport=transport) as client:
        response = await client.get("https://example.com/api/test")
        assert response.status_code == 200
        assert response.text == '{"status": "ok"}'
        assert response.headers["Content-Type"] == "application/json"
        assert client.request_count == 1


@pytest.mark.asyncio
async def test_client_request_limit_enforced():
    """Verify hard limit on total requests allowed in a scan session."""

    def mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="OK")

    transport = httpx.MockTransport(mock_handler)
    scope = TargetScope(allowed_hosts={"example.com"})
    policy = ScopePolicy(scope, dns_resolver=lambda _: ["93.184.216.34"])

    async with ScannerHttpClient(
        scope_policy=policy,
        transport=transport,
        max_requests=2,
    ) as client:
        await client.get("https://example.com/1")
        await client.get("https://example.com/2")
        assert client.request_count == 2

        with pytest.raises(RequestLimitExceededError):
            await client.get("https://example.com/3")


@pytest.mark.asyncio
async def test_client_concurrent_requests_strict_budget_enforcement():
    """Prove atomic accounting prevents request limits from being exceeded."""
    actual_requests = 0

    def mock_handler(request: httpx.Request) -> httpx.Response:
        nonlocal actual_requests
        actual_requests += 1
        return httpx.Response(200, text="OK")

    transport = httpx.MockTransport(mock_handler)
    scope = TargetScope(allowed_hosts={"example.com"})
    policy = ScopePolicy(scope, dns_resolver=lambda _: ["93.184.216.34"])

    budget = 10
    total_coroutines = 30

    async with ScannerHttpClient(
        scope_policy=policy,
        transport=transport,
        max_requests=budget,
    ) as client:

        async def make_request(i: int):
            try:
                await client.get(f"https://example.com/page/{i}")
            except RequestLimitExceededError:
                pass

        tasks = [make_request(i) for i in range(total_coroutines)]
        await asyncio.gather(*tasks)

        assert actual_requests == budget
        assert client.request_count == budget


@pytest.mark.asyncio
async def test_safe_network_backend_pins_ip_and_blocks_rebinding():
    """Verify SafeNetworkBackend validates destination and pins socket to validated IP."""
    connected_ip = None

    class MockBaseBackend(httpcore.AsyncNetworkBackend):
        async def connect_tcp(
            self, host, port, timeout=None, local_address=None, socket_options=None
        ):
            nonlocal connected_ip
            connected_ip = host
            return None  # Connection intercepted

    scope = TargetScope(allowed_hosts={"public.example.com", "rebind.attacker.com"})

    # 1. Host resolving to loopback is blocked at connection time
    policy_rebind = ScopePolicy(scope, dns_resolver=lambda _: ["127.0.0.1"])
    backend_rebind = SafeNetworkBackend(scope_policy=policy_rebind, base_backend=MockBaseBackend())

    with pytest.raises(SSRFProhibitedError):
        await backend_rebind.connect_tcp("rebind.attacker.com", 443)
    assert connected_ip is None

    # 2. Host resolving to public IP connects directly to the pinned IP address
    policy_public = ScopePolicy(scope, dns_resolver=lambda _: ["93.184.216.34"])
    backend_public = SafeNetworkBackend(scope_policy=policy_public, base_backend=MockBaseBackend())

    await backend_public.connect_tcp("public.example.com", 443)
    assert connected_ip == "93.184.216.34"


@pytest.mark.asyncio
async def test_client_response_size_limit_enforced():
    """Verify response size bounding to prevent memory exhaustion."""
    large_payload = b"A" * 5000

    def mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=large_payload)

    transport = httpx.MockTransport(mock_handler)
    scope = TargetScope(allowed_hosts={"example.com"})
    policy = ScopePolicy(scope, dns_resolver=lambda _: ["93.184.216.34"])

    async with ScannerHttpClient(
        scope_policy=policy,
        transport=transport,
        max_response_bytes=1000,
    ) as client:
        with pytest.raises(ResponseSizeExceededError) as exc_info:
            await client.get("https://example.com/large")
        assert "exceeded limit of 1000 bytes" in str(exc_info.value)


@pytest.mark.asyncio
async def test_client_timeout_handling():
    """Verify that transport timeouts map to ScannerTimeoutError."""

    def mock_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("Read timed out")

    transport = httpx.MockTransport(mock_handler)
    scope = TargetScope(allowed_hosts={"example.com"})
    policy = ScopePolicy(scope, dns_resolver=lambda _: ["93.184.216.34"])

    async with ScannerHttpClient(scope_policy=policy, transport=transport) as client:
        with pytest.raises(ScannerTimeoutError):
            await client.get("https://example.com/slow")


@pytest.mark.asyncio
async def test_client_network_error_handling():
    """Verify that connection failures map to ScannerNetworkError."""

    def mock_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("Failed to establish connection")

    transport = httpx.MockTransport(mock_handler)
    scope = TargetScope(allowed_hosts={"example.com"})
    policy = ScopePolicy(scope, dns_resolver=lambda _: ["93.184.216.34"])

    async with ScannerHttpClient(scope_policy=policy, transport=transport) as client:
        with pytest.raises(ScannerNetworkError):
            await client.get("https://example.com/down")


@pytest.mark.asyncio
async def test_client_redirect_within_scope():
    """Verify redirects are followed when destination remains within authorized scope."""

    def mock_handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == "https://example.com/start":
            return httpx.Response(302, headers={"Location": "/final"})
        if str(request.url) == "https://example.com/final":
            return httpx.Response(200, text="Destination Reached")
        return httpx.Response(404)

    transport = httpx.MockTransport(mock_handler)
    scope = TargetScope(allowed_hosts={"example.com"})
    policy = ScopePolicy(scope, dns_resolver=lambda _: ["93.184.216.34"])

    async with ScannerHttpClient(scope_policy=policy, transport=transport) as client:
        response = await client.get("https://example.com/start")
        assert response.status_code == 200
        assert response.text == "Destination Reached"
        assert response.url == "https://example.com/final"
        assert response.history == ["https://example.com/start"]
        assert client.request_count == 2


@pytest.mark.asyncio
async def test_client_redirect_out_of_scope_blocked():
    """Verify redirect to out-of-scope host is blocked before issuing outbound request."""
    evil_called = False

    def mock_handler(request: httpx.Request) -> httpx.Response:
        nonlocal evil_called
        if "evil.com" in str(request.url):
            evil_called = True
            return httpx.Response(200, text="Evil")
        return httpx.Response(302, headers={"Location": "https://evil.com/trap"})

    transport = httpx.MockTransport(mock_handler)
    scope = TargetScope(allowed_hosts={"example.com"})
    policy = ScopePolicy(scope, dns_resolver=lambda _: ["93.184.216.34"])

    async with ScannerHttpClient(scope_policy=policy, transport=transport) as client:
        with pytest.raises(RedirectScopeViolationError):
            await client.get("https://example.com/start")
        assert evil_called is False


@pytest.mark.asyncio
async def test_client_redirect_sensitive_header_stripping_cross_origin():
    """Verify auth/cookie headers are stripped across cross-origin redirects."""
    observed_headers = {}

    def mock_handler(request: httpx.Request) -> httpx.Response:
        nonlocal observed_headers
        url_str = str(request.url)
        if "auth.example.com" in url_str:
            return httpx.Response(302, headers={"Location": "https://public.example.com/dashboard"})
        if "public.example.com" in url_str:
            observed_headers = dict(request.headers)
            return httpx.Response(200, text="Welcome")
        return httpx.Response(404)

    transport = httpx.MockTransport(mock_handler)
    scope = TargetScope(allowed_hosts={"example.com"}, allow_subdomains=True)
    policy = ScopePolicy(scope, dns_resolver=lambda _: ["93.184.216.34"])

    async with ScannerHttpClient(scope_policy=policy, transport=transport) as client:
        headers = {
            "Authorization": "Bearer secret-token",
            "Cookie": "session=secret-session",
            "X-Custom-Header": "safe-value",
        }
        response = await client.get("https://auth.example.com/login", headers=headers)
        assert response.status_code == 200
        assert "authorization" not in observed_headers
        assert "cookie" not in observed_headers
        assert observed_headers.get("x-custom-header") == "safe-value"


@pytest.mark.asyncio
async def test_client_max_redirects_exceeded():
    """Verify infinite or excessive redirect loops are terminated safely."""

    def mock_handler(request: httpx.Request) -> httpx.Response:
        # Loop between /a and /b
        current = str(request.url)
        next_path = "/b" if current.endswith("/a") else "/a"
        return httpx.Response(302, headers={"Location": next_path})

    transport = httpx.MockTransport(mock_handler)
    scope = TargetScope(allowed_hosts={"example.com"})
    policy = ScopePolicy(scope, dns_resolver=lambda _: ["93.184.216.34"])

    async with ScannerHttpClient(
        scope_policy=policy,
        transport=transport,
        max_redirects=3,
    ) as client:
        with pytest.raises(MaxRedirectsExceededError):
            await client.get("https://example.com/a")


@pytest.mark.asyncio
async def test_client_redirect_sensitive_headers_preserved_same_origin():
    """Verify auth/cookie headers are preserved across same-origin redirects."""
    observed_requests = []

    def mock_handler(request: httpx.Request) -> httpx.Response:
        observed_requests.append((str(request.url), dict(request.headers)))
        if str(request.url) == "https://example.com/login":
            return httpx.Response(302, headers={"Location": "/dashboard"})
        if str(request.url) == "https://example.com/dashboard":
            return httpx.Response(200, text="Welcome Dashboard")
        return httpx.Response(404)

    transport = httpx.MockTransport(mock_handler)
    scope = TargetScope(allowed_hosts={"example.com"})
    policy = ScopePolicy(scope, dns_resolver=lambda _: ["93.184.216.34"])

    async with ScannerHttpClient(scope_policy=policy, transport=transport) as client:
        headers = {
            "Authorization": "Bearer secret-token",
            "Cookie": "session=secret-session",
            "X-Custom-Header": "safe-value",
        }
        response = await client.get("https://example.com/login", headers=headers)
        assert response.status_code == 200
        assert len(observed_requests) == 2
        # First hop contains sensitive headers
        assert observed_requests[0][1].get("authorization") == "Bearer secret-token"
        assert observed_requests[0][1].get("cookie") == "session=secret-session"
        # Second same-origin hop retains sensitive headers
        assert observed_requests[1][1].get("authorization") == "Bearer secret-token"
        assert observed_requests[1][1].get("cookie") == "session=secret-session"
        assert observed_requests[1][1].get("x-custom-header") == "safe-value"
        assert client.request_count == 2


@pytest.mark.asyncio
async def test_safe_transport_end_to_end_pins_ip_to_local_server():
    """End-to-end integration test proving socket connection uses pinned IP on real TCP loopback."""
    received_host_headers = []

    async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        await reader.readline()
        while True:
            line = await reader.readline()
            if not line or line == b"\r\n":
                break
            if line.lower().startswith(b"host:"):
                received_host_headers.append(line.decode().strip())

        response = b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\nPINNED_OK"
        writer.write(response)
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(handle_client, "127.0.0.1", 0)
    server_port = server.sockets[0].getsockname()[1]

    connected_destinations = []

    class InstrumentedBackend(httpcore.AsyncNetworkBackend):
        def __init__(self):
            self._real = httpcore.AnyIOBackend()

        async def connect_tcp(
            self, host, port, timeout=None, local_address=None, socket_options=None
        ):
            connected_destinations.append((host, port))
            return await self._real.connect_tcp(
                host,
                port,
                timeout=timeout,
                local_address=local_address,
                socket_options=socket_options,
            )

        async def connect_unix_socket(self, path, timeout=None, socket_options=None):
            return await self._real.connect_unix_socket(
                path, timeout=timeout, socket_options=socket_options
            )

        async def sleep(self, seconds: float):
            await self._real.sleep(seconds)

    scope = TargetScope(
        allowed_hosts={"myservice.authorized.local"},
        allowed_ports={server_port},
        allow_local_lab_targets=True,
    )
    policy = ScopePolicy(scope, dns_resolver=lambda _: ["127.0.0.1"])
    transport = create_safe_transport(policy, base_backend=InstrumentedBackend())

    try:
        async with ScannerHttpClient(scope_policy=policy, transport=transport) as client:
            resp = await client.get(f"http://myservice.authorized.local:{server_port}/test")
            assert resp.status_code == 200
            assert resp.text == "PINNED_OK"

            # Assert socket connected to the pinned IP (127.0.0.1)
            assert connected_destinations == [("127.0.0.1", server_port)]
            # Assert HTTP Host header sent over the wire remained the authorized hostname
            assert len(received_host_headers) == 1
            assert received_host_headers[0] == f"Host: myservice.authorized.local:{server_port}"
    finally:
        server.close()
        await server.wait_closed()


def test_transport_dependency_contract():
    """Verify that required public interfaces in httpcore and httpx exist."""
    assert hasattr(httpcore, "AnyIOBackend")
    assert issubclass(httpcore.AnyIOBackend, httpcore.AsyncNetworkBackend)
    assert hasattr(httpcore, "AsyncConnectionPool")
    assert hasattr(httpx, "create_ssl_context")

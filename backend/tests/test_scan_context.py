"""Unit tests for ScanContext baseline response accessor, concurrency, and caching."""

import asyncio

import httpx
import pytest

from app.scanner.check import ScanContext
from app.scanner.client import (
    RequestLimitExceededError,
    ScannerHttpClient,
    ScannerTimeoutError,
)
from app.scanner.scope import ScopePolicy, TargetScope


@pytest.mark.asyncio
async def test_baseline_concurrent_callers_share_single_request():
    """Verify that multiple concurrent callers receive the same response from 1 network request."""
    request_count = 0

    def mock_handler(request: httpx.Request) -> httpx.Response:
        nonlocal request_count
        request_count += 1
        return httpx.Response(
            200,
            text="<html><head><title>Test</title></head></html>",
            headers={"Content-Type": "text/html"},
        )

    transport = httpx.MockTransport(mock_handler)
    scope = TargetScope(allowed_hosts={"example.com"})
    policy = ScopePolicy(scope, dns_resolver=lambda _: ["93.184.216.34"])

    async with ScannerHttpClient(scope_policy=policy, transport=transport) as client:
        context = ScanContext(
            target_url="https://example.com/",
            scope=scope,
            client=client,
        )

        assert context.has_baseline_response is False
        assert context.cached_baseline_response is None

        # Execute 5 concurrent calls to get_baseline_response
        tasks = [context.get_baseline_response() for _ in range(5)]
        responses = await asyncio.gather(*tasks)

        # All 5 callers must receive the exact same response instance
        assert len(responses) == 5
        first_resp = responses[0]
        for resp in responses[1:]:
            assert resp is first_resp

        # Exactly 1 request must have been sent to the network backend
        assert request_count == 1
        assert client.request_count == 1
        assert context.has_baseline_response is True
        assert context.cached_baseline_response is first_resp


@pytest.mark.asyncio
async def test_baseline_sequential_callers_reuse_cached_response():
    """Verify that sequential calls after initial resolution do not issue extra requests."""
    request_count = 0

    def mock_handler(request: httpx.Request) -> httpx.Response:
        nonlocal request_count
        request_count += 1
        return httpx.Response(200, text="OK")

    transport = httpx.MockTransport(mock_handler)
    scope = TargetScope(allowed_hosts={"example.com"})
    policy = ScopePolicy(scope, dns_resolver=lambda _: ["93.184.216.34"])

    async with ScannerHttpClient(scope_policy=policy, transport=transport) as client:
        context = ScanContext(
            target_url="https://example.com/",
            scope=scope,
            client=client,
        )

        # First call initiates the request
        resp1 = await context.get_baseline_response()
        assert request_count == 1

        # Second and third calls reuse the cached response without calling transport
        resp2 = await context.get_baseline_response()
        resp3 = await context.get_baseline_response()

        assert resp1 is resp2
        assert resp2 is resp3
        assert request_count == 1
        assert client.request_count == 1


@pytest.mark.asyncio
async def test_baseline_concurrent_callers_share_failure():
    """Verify that concurrent callers share the same failure without repeated requests."""
    request_count = 0

    def mock_handler(request: httpx.Request) -> httpx.Response:
        nonlocal request_count
        request_count += 1
        raise httpx.ReadTimeout("Connection read timeout")

    transport = httpx.MockTransport(mock_handler)
    scope = TargetScope(allowed_hosts={"example.com"})
    policy = ScopePolicy(scope, dns_resolver=lambda _: ["93.184.216.34"])

    async with ScannerHttpClient(scope_policy=policy, transport=transport) as client:
        context = ScanContext(
            target_url="https://example.com/",
            scope=scope,
            client=client,
        )

        async def _call():
            return await context.get_baseline_response()

        tasks = [_call() for _ in range(3)]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # All 3 callers must have received ScannerTimeoutError
        assert len(results) == 3
        for res in results:
            assert isinstance(res, ScannerTimeoutError)
            assert "Connection read timeout" in str(res)

        # Exactly 1 request was attempted
        assert request_count == 1

        # Subsequent call also immediately raises the same error without retrying
        with pytest.raises(ScannerTimeoutError):
            await context.get_baseline_response()
        assert request_count == 1


@pytest.mark.asyncio
async def test_baseline_request_budget_exhaustion_propagates():
    """Verify that scan session request limit exhaustion propagates properly."""

    def mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="OK")

    transport = httpx.MockTransport(mock_handler)
    scope = TargetScope(allowed_hosts={"example.com"})
    policy = ScopePolicy(scope, dns_resolver=lambda _: ["93.184.216.34"])

    # Limit to 1 request
    async with ScannerHttpClient(
        scope_policy=policy,
        transport=transport,
        max_requests=1,
    ) as client:
        context = ScanContext(
            target_url="https://example.com/",
            scope=scope,
            client=client,
        )

        # 1. Baseline request succeeds using the 1 available slot
        resp = await context.get_baseline_response()
        assert resp.status_code == 200
        assert client.request_count == 1

        # 2. Subsequent baseline accessor calls still succeed using cached response
        cached = await context.get_baseline_response()
        assert cached is resp

        # 3. Any additional non-cached request fails due to budget exhaustion
        with pytest.raises(RequestLimitExceededError):
            await client.get("https://example.com/extra")


@pytest.mark.asyncio
async def test_baseline_cancellation_does_not_corrupt_context():
    """Verify that cancellation of in-flight baseline request cleans up properly."""
    in_flight = asyncio.Event()

    def mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="OK")

    transport = httpx.MockTransport(mock_handler)
    scope = TargetScope(allowed_hosts={"example.com"})
    policy = ScopePolicy(scope, dns_resolver=lambda _: ["93.184.216.34"])

    async with ScannerHttpClient(scope_policy=policy, transport=transport) as client:
        context = ScanContext(
            target_url="https://example.com/",
            scope=scope,
            client=client,
        )

        async def _slow_call():
            in_flight.set()
            await asyncio.sleep(5.0)
            return await context.get_baseline_response()

        task = asyncio.create_task(_slow_call())
        await in_flight.wait()
        task.cancel()

        with pytest.raises(asyncio.CancelledError):
            await task

        # Ensure the lock is not stuck acquired and context can still be used if needed
        assert context._baseline_lock.locked() is False
        assert context._baseline_error is None


@pytest.mark.asyncio
async def test_baseline_pre_populated_response():
    """Verify that pre-populated baseline_response is returned without any network calls."""
    network_called = False

    def mock_handler(request: httpx.Request) -> httpx.Response:
        nonlocal network_called
        network_called = True
        return httpx.Response(200, text="Network")

    transport = httpx.MockTransport(mock_handler)
    scope = TargetScope(allowed_hosts={"example.com"})
    policy = ScopePolicy(scope, dns_resolver=lambda _: ["93.184.216.34"])

    # Create dummy pre-populated response
    mock_response = httpx.Response(200, text="PrePopulated")
    from app.scanner.client import ScannerResponse

    scanner_resp = ScannerResponse(
        status_code=200,
        headers=mock_response.headers,
        url="https://example.com/",
        content=b"PrePopulated",
    )

    async with ScannerHttpClient(scope_policy=policy, transport=transport) as client:
        context = ScanContext(
            target_url="https://example.com/",
            scope=scope,
            client=client,
            baseline_response=scanner_resp,
        )

        assert context.has_baseline_response is True
        resp = await context.get_baseline_response()
        assert resp.text == "PrePopulated"
        assert network_called is False
        assert client.request_count == 0

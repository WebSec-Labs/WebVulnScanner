"""Unit and integration tests for POST /api/v1/scans endpoint."""

import asyncio
from collections.abc import AsyncGenerator
from unittest.mock import patch

import httpx
import pytest
from httpx import ASGITransport, AsyncClient

from app.api.v1.endpoints.scans import (
    get_async_dns_resolver,
    get_dns_resolver,
    get_scan_semaphore,
    get_scan_transport,
)
from app.main import app
from app.scanner.client import ScannerTimeoutError
from app.scanner.engine import ScannerEngine
from app.scanner.models import ScanResult, ScanStatus


@pytest.fixture
def mock_target_transport() -> httpx.MockTransport:
    """Mock transport returning simulated HTTP response for scanner checks."""

    def handler(request: httpx.Request) -> httpx.Response:
        headers = {
            "Content-Type": "text/html; charset=utf-8",
            "Access-Control-Allow-Origin": "*",
            "Set-Cookie": "session_id=VAL123; Path=/",
        }
        return httpx.Response(200, headers=headers, text="<html><body>Welcome</body></html>")

    return httpx.MockTransport(handler)


@pytest.fixture
def mock_dns_resolver():
    """Mock DNS resolver returning a valid public IP."""
    return lambda host: ["93.184.216.34"]


@pytest.fixture
async def scan_client(
    mock_target_transport: httpx.MockTransport,
    mock_dns_resolver,
) -> AsyncGenerator[AsyncClient, None]:
    """Client fixture with scanner transport and DNS resolver dependency overrides."""
    app.dependency_overrides[get_scan_transport] = lambda: mock_target_transport
    app.dependency_overrides[get_dns_resolver] = lambda: mock_dns_resolver
    app.dependency_overrides[get_async_dns_resolver] = lambda: None

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client

    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_scan_successful_with_findings(scan_client: AsyncClient):
    """Verify that a valid target URL triggers registered checks and returns structured findings."""
    payload = {"target_url": "https://example.com"}
    response = await scan_client.post("/api/v1/scans", json=payload)

    assert response.status_code == 200
    data = response.json()

    assert data["target_url"] == "https://example.com/"
    assert data["status"] == ScanStatus.COMPLETED.value
    assert isinstance(data["findings"], list)
    assert len(data["findings"]) > 0

    for finding in data["findings"]:
        assert "check_id" in finding
        assert "title" in finding
        assert "severity" in finding
        assert "evidence" in finding
        assert "recommendation" in finding

    assert set(data["executed_checks"]) == {
        "cookie_security",
        "cors_security",
        "https_configuration",
        "security_headers",
    }
    assert data["total_requests"] == 1
    assert data["duration_seconds"] >= 0.0


@pytest.mark.asyncio
async def test_scan_successful_zero_findings():
    """Verify that a target with defensive headers configured returns zero findings cleanly."""

    def compliant_handler(request: httpx.Request) -> httpx.Response:
        headers = {
            "Content-Type": "text/html; charset=utf-8",
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "geolocation=()",
            "Set-Cookie": "auth=abc; Path=/; Secure; HttpOnly; SameSite=Strict",
        }
        return httpx.Response(200, headers=headers, text="OK")

    app.dependency_overrides[get_scan_transport] = lambda: httpx.MockTransport(compliant_handler)
    app.dependency_overrides[get_dns_resolver] = lambda: lambda host: ["93.184.216.34"]
    app.dependency_overrides[get_async_dns_resolver] = lambda: None

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post("/api/v1/scans", json={"target_url": "https://example.com"})

    app.dependency_overrides.clear()

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == ScanStatus.COMPLETED.value
    assert data["findings"] == []


@pytest.mark.asyncio
async def test_scan_selective_checks(scan_client: AsyncClient):
    """Verify that specifying check_ids runs strictly the requested checks."""
    payload = {
        "target_url": "https://example.com",
        "check_ids": ["cors_security"],
    }
    response = await scan_client.post("/api/v1/scans", json=payload)

    assert response.status_code == 200
    data = response.json()
    assert data["executed_checks"] == ["cors_security"]


@pytest.mark.asyncio
async def test_scan_malformed_url(scan_client: AsyncClient):
    """Verify that malformed URLs are rejected with HTTP 400."""
    response = await scan_client.post("/api/v1/scans", json={"target_url": "not-a-valid-url"})
    assert response.status_code == 400
    assert "Invalid target URL" in response.json()["detail"]


@pytest.mark.asyncio
async def test_scan_empty_whitespace_url(scan_client: AsyncClient):
    """Verify that empty or whitespace URLs fail request validation."""
    response = await scan_client.post("/api/v1/scans", json={"target_url": "   "})
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_scan_unsupported_scheme(scan_client: AsyncClient):
    """Verify that non-HTTP/HTTPS schemes are rejected with HTTP 400."""
    schemes = ["ftp://example.com", "file:///etc/passwd", "javascript:alert(1)"]
    for url in schemes:
        response = await scan_client.post("/api/v1/scans", json={"target_url": url})
        assert response.status_code == 400
        assert "Invalid target URL" in response.json()["detail"]


@pytest.mark.asyncio
async def test_scan_prohibited_loopback(scan_client: AsyncClient):
    """Verify that loopback targets are rejected by SSRF guardrails with sanitized HTTP 422."""
    targets = ["http://127.0.0.1", "http://127.0.0.1:8000", "http://[::1]"]
    for target in targets:
        response = await scan_client.post("/api/v1/scans", json={"target_url": target})
        assert response.status_code == 422
        assert (
            response.json()["detail"] == "Target destination is prohibited by SSRF security policy"
        )


@pytest.mark.asyncio
async def test_scan_prohibited_private_ip(scan_client: AsyncClient):
    """Verify that RFC 1918 private IP destinations are blocked with sanitized HTTP 422."""
    private_targets = ["http://10.0.0.1", "http://192.168.1.1", "http://172.16.0.1"]
    for target in private_targets:
        response = await scan_client.post("/api/v1/scans", json={"target_url": target})
        assert response.status_code == 422
        assert (
            response.json()["detail"] == "Target destination is prohibited by SSRF security policy"
        )


@pytest.mark.asyncio
async def test_scan_prohibited_cloud_metadata(scan_client: AsyncClient):
    """Verify that cloud metadata IPs and hostnames are rejected with sanitized HTTP 422."""
    metadata_targets = [
        "http://169.254.169.254",
        "http://metadata.google.internal",
        "http://instance-data",
    ]
    for target in metadata_targets:
        response = await scan_client.post("/api/v1/scans", json={"target_url": target})
        assert response.status_code == 422
        assert (
            response.json()["detail"] == "Target destination is prohibited by SSRF security policy"
        )


@pytest.mark.asyncio
async def test_scan_prohibited_localhost_hostname(scan_client: AsyncClient):
    """Verify that localhost hostnames are rejected with sanitized HTTP 422."""
    targets = ["http://localhost", "http://localhost:8000", "http://test.localhost"]
    for target in targets:
        response = await scan_client.post("/api/v1/scans", json={"target_url": target})
        assert response.status_code == 422
        assert (
            response.json()["detail"] == "Target destination is prohibited by SSRF security policy"
        )


@pytest.mark.asyncio
async def test_ssrf_error_does_not_leak_resolved_ip():
    """Verify that a hostname resolving to a private/SSRF IP does not leak the resolved IP."""
    app.dependency_overrides[get_dns_resolver] = lambda: lambda host: ["10.0.0.1"]
    app.dependency_overrides[get_async_dns_resolver] = lambda: None

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/api/v1/scans",
            json={"target_url": "http://internal-destination.corp"},
        )

    app.dependency_overrides.clear()
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert detail == "Target destination is prohibited by SSRF security policy"
    # Ensure internal IP 10.0.0.1 is NEVER leaked in response body or text
    assert "10.0.0.1" not in response.text


@pytest.mark.asyncio
async def test_scan_unknown_check_id(scan_client: AsyncClient):
    """Verify that requesting an unregistered check ID is rejected with HTTP 400."""
    payload = {
        "target_url": "https://example.com",
        "check_ids": ["invalid_check_id"],
    }
    response = await scan_client.post("/api/v1/scans", json=payload)
    assert response.status_code == 400
    assert "Unknown check IDs" in response.json()["detail"]


@pytest.mark.asyncio
async def test_scan_dns_failure_returns_400():
    """Verify that DNS resolution failures on non-IP hostnames return HTTP 400."""

    def failing_dns(host: str):
        raise httpx.ConnectError("NXDOMAIN")

    app.dependency_overrides[get_dns_resolver] = lambda: failing_dns
    app.dependency_overrides[get_async_dns_resolver] = lambda: None

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/api/v1/scans",
            json={"target_url": "https://nonexistent.invalid"},
        )

    app.dependency_overrides.clear()
    assert response.status_code == 400
    assert "DNS resolution failed" in response.json()["detail"]


@pytest.mark.asyncio
async def test_scan_internal_server_error_sanitized():
    """Verify that unexpected engine failures produce sanitized 500 without leaking internals."""
    app.dependency_overrides[get_dns_resolver] = lambda: lambda host: ["93.184.216.34"]
    app.dependency_overrides[get_async_dns_resolver] = lambda: None

    with patch.object(
        ScannerEngine,
        "run_scan",
        side_effect=RuntimeError("Unexpected internal crash with sensitive_key=12345"),
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://testserver") as client:
            response = await client.post(
                "/api/v1/scans",
                json={"target_url": "https://example.com"},
            )

    app.dependency_overrides.clear()
    assert response.status_code == 500
    detail = response.json()["detail"]
    assert "internal error" in detail.lower()
    assert "sensitive_key" not in detail
    assert "RuntimeError" not in detail


@pytest.mark.asyncio
async def test_scan_timeout_returns_504():
    """Verify that top-level scanner timeout produces a sanitized 504 Gateway Timeout."""
    app.dependency_overrides[get_dns_resolver] = lambda: lambda host: ["93.184.216.34"]
    app.dependency_overrides[get_async_dns_resolver] = lambda: None

    with patch.object(
        ScannerEngine,
        "run_scan",
        side_effect=ScannerTimeoutError("Connection timed out to 93.184.216.34"),
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://testserver") as client:
            response = await client.post(
                "/api/v1/scans",
                json={"target_url": "https://example.com"},
            )

    app.dependency_overrides.clear()
    assert response.status_code == 504
    assert response.json()["detail"] == "Scan execution timed out against target host"


@pytest.mark.asyncio
async def test_scan_rejects_unsupported_options_and_scope_tampering(scan_client: AsyncClient):
    """Verify that callers cannot inject options to disable SSRF protection or exceed caps."""
    res1 = await scan_client.post(
        "/api/v1/scans",
        json={"target_url": "https://example.com", "allow_subdomains": True},
    )
    assert res1.status_code == 422

    res2 = await scan_client.post(
        "/api/v1/scans",
        json={"target_url": "https://example.com", "allow_local_lab_targets": True},
    )
    assert res2.status_code == 422

    res3 = await scan_client.post(
        "/api/v1/scans",
        json={"target_url": "https://example.com", "max_concurrency": 50},
    )
    assert res3.status_code == 422

    res4 = await scan_client.post(
        "/api/v1/scans",
        json={"target_url": "https://example.com", "timeout_seconds": 999.0},
    )
    assert res4.status_code == 422


@pytest.mark.asyncio
async def test_scan_rejects_overlong_target_url(scan_client: AsyncClient):
    """Verify that target URLs exceeding 2048 characters are rejected with 422."""
    overlong_url = "https://example.com/" + "a" * 2050
    response = await scan_client.post("/api/v1/scans", json={"target_url": overlong_url})
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_scan_rejects_overlong_check_id_item(scan_client: AsyncClient):
    """Verify that check IDs exceeding 100 characters are rejected with 422."""
    payload = {
        "target_url": "https://example.com",
        "check_ids": ["a" * 101],
    }
    response = await scan_client.post("/api/v1/scans", json=payload)
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_scan_rejects_oversized_check_ids_list(scan_client: AsyncClient):
    """Verify that check_ids lists with more than 50 items are rejected with 422."""
    payload = {
        "target_url": "https://example.com",
        "check_ids": [f"check_{i}" for i in range(51)],
    }
    response = await scan_client.post("/api/v1/scans", json=payload)
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_concurrency_limiter_waits_when_saturated():
    """Verify that concurrent scans wait for permits when the semaphore limit is reached."""
    limiter = asyncio.Semaphore(1)
    app.dependency_overrides[get_scan_semaphore] = lambda: limiter
    app.dependency_overrides[get_dns_resolver] = lambda: lambda host: ["93.184.216.34"]
    app.dependency_overrides[get_async_dns_resolver] = lambda: None

    gate = asyncio.Event()

    async def paused_run_scan(self, config, scope, transport):
        await gate.wait()
        return ScanResult(target_url=config.target_url, status=ScanStatus.COMPLETED)

    with patch.object(ScannerEngine, "run_scan", new=paused_run_scan):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://testserver") as client:
            task1 = asyncio.create_task(
                client.post("/api/v1/scans", json={"target_url": "https://example.com"})
            )
            await asyncio.sleep(0.05)
            assert limiter.locked()

            task2 = asyncio.create_task(
                client.post("/api/v1/scans", json={"target_url": "https://example.com"})
            )
            await asyncio.sleep(0.05)
            assert not task2.done()

            gate.set()
            res1 = await task1
            res2 = await task2

    app.dependency_overrides.clear()
    assert res1.status_code == 200
    assert res2.status_code == 200


@pytest.mark.asyncio
async def test_concurrency_limiter_releases_on_failure_and_cancellation():
    """Verify that failed or cancelled scans release their concurrency permit."""
    limiter = asyncio.Semaphore(1)
    app.dependency_overrides[get_scan_semaphore] = lambda: limiter
    app.dependency_overrides[get_dns_resolver] = lambda: lambda host: ["93.184.216.34"]
    app.dependency_overrides[get_async_dns_resolver] = lambda: None

    # 1. Failure release
    with patch.object(ScannerEngine, "run_scan", side_effect=RuntimeError("Engine failure")):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://testserver") as client:
            res = await client.post("/api/v1/scans", json={"target_url": "https://example.com"})
            assert res.status_code == 500
            assert limiter._value == 1  # Permit was safely restored

    # 2. Cancellation release
    pause_event = asyncio.Event()

    async def cancellable_run_scan(self, config, scope, transport):
        await pause_event.wait()

    with patch.object(ScannerEngine, "run_scan", new=cancellable_run_scan):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://testserver") as client:
            task = asyncio.create_task(
                client.post("/api/v1/scans", json={"target_url": "https://example.com"})
            )
            await asyncio.sleep(0.05)
            assert limiter.locked()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            assert limiter._value == 1  # Permit was safely restored after cancellation

    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_concurrency_limiter_does_not_accumulate_event_loops():
    """Verify app.state.scan_semaphore is bound directly to app.state without loop dictionaries."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        app.dependency_overrides[get_dns_resolver] = lambda: lambda host: ["93.184.216.34"]
        app.dependency_overrides[get_async_dns_resolver] = lambda: None
        await client.post("/api/v1/scans", json={"target_url": "http://127.0.0.1"})
        app.dependency_overrides.clear()

    assert hasattr(app.state, "scan_semaphore")
    assert isinstance(app.state.scan_semaphore, asyncio.Semaphore)


@pytest.mark.asyncio
async def test_existing_health_and_root_endpoints(async_client: AsyncClient):
    """Verify that mounting API v1 routes did not regress root and health endpoints."""
    res_root = await async_client.get("/")
    assert res_root.status_code == 200

    res_health1 = await async_client.get("/health")
    assert res_health1.status_code == 200
    assert res_health1.json()["status"] == "ok"

    res_health2 = await async_client.get("/api/v1/health")
    assert res_health2.status_code == 200
    assert res_health2.json()["status"] == "ok"

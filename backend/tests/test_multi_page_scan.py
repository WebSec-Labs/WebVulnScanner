"""Integration tests for multi-page scanner engine and passive check orchestration."""

import asyncio

import httpx
import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app
from app.scanner.check import BaseCheck, CheckMetadata, ScanContext
from app.scanner.checks.cookies import CookieSecurityCheck
from app.scanner.checks.headers import SecurityHeadersCheck
from app.scanner.engine import ScannerEngine
from app.scanner.models import Finding, ScanConfig, ScanStatus, Severity
from app.scanner.registry import CheckRegistry
from app.scanner.scope import TargetScope


@pytest.fixture
def mock_dns_resolver():
    """Mock DNS resolver returning a valid public IP."""
    return lambda host: ["93.184.216.34"]


class DummyPageFindingCheck(BaseCheck):
    """Emits a finding for every page with page URL in finding."""

    @property
    def metadata(self) -> CheckMetadata:
        return CheckMetadata(
            check_id="page_finding_check",
            name="Page Finding Check",
            description="Reports page-level diagnostic finding.",
            severity=Severity.LOW,
        )

    async def run(self, context: ScanContext) -> list[Finding]:
        response = await context.get_baseline_response()
        return [
            self.create_finding(
                url=response.url,
                evidence=f"Observed page with status {response.status_code}",
                recommendation="No action needed",
            )
        ]


class FlakyCheckOnSpecificPage(BaseCheck):
    """Fails on a specific subpage but succeeds on others."""

    @property
    def metadata(self) -> CheckMetadata:
        return CheckMetadata(
            check_id="flaky_check",
            name="Flaky Check",
            description="Fails specifically on /faulty URL.",
            severity=Severity.MEDIUM,
        )

    async def run(self, context: ScanContext) -> list[Finding]:
        if "faulty" in context.target_url:
            raise RuntimeError("Intentional failure on faulty page")
        return [
            self.create_finding(
                url=context.target_url,
                evidence="Check completed cleanly",
                recommendation="No action needed",
            )
        ]


class DuplicateFindingCheck(BaseCheck):
    """Emits duplicate findings to test deterministic deduplication."""

    @property
    def metadata(self) -> CheckMetadata:
        return CheckMetadata(
            check_id="duplicate_check",
            name="Duplicate Check",
            description="Emits identical findings on the same page.",
            severity=Severity.INFO,
        )

    async def run(self, context: ScanContext) -> list[Finding]:
        # Emits two identical findings for the same URL
        f1 = self.create_finding(
            url=context.target_url,
            evidence="Identical evidence",
            recommendation="Review configuration",
        )
        f2 = self.create_finding(
            url=context.target_url,
            evidence="Identical evidence",
            recommendation="Review configuration",
        )
        return [f1, f2]


@pytest.mark.asyncio
async def test_single_page_scan_preserves_existing_behavior(mock_dns_resolver):
    """Verify crawl_enabled=False executes standard single-page scan."""
    registry = CheckRegistry()
    registry.register(DummyPageFindingCheck)

    transport = httpx.MockTransport(
        lambda req: httpx.Response(
            200,
            headers={"Content-Type": "text/html"},
            text='<html><body><a href="/discovered">Discovered</a></body></html>',
        )
    )

    engine = ScannerEngine(registry=registry)
    config = ScanConfig(
        target_url="https://example.com/",
        crawl_enabled=False,
    )
    scope = TargetScope(allowed_hosts={"example.com"})

    result = await engine.run_scan(
        config=config,
        scope=scope,
        transport=transport,
        dns_resolver=mock_dns_resolver,
    )

    assert result.status == ScanStatus.COMPLETED
    assert result.scanned_pages == ["https://example.com/"]
    assert len(result.findings) == 1
    assert result.findings[0].url == "https://example.com/"
    assert result.total_requests == 1


@pytest.mark.asyncio
async def test_multi_page_scan_discovers_and_scans_multiple_pages(mock_dns_resolver):
    """Verify that crawl_enabled=True discovers same-origin pages and runs checks on all."""
    responses: dict[str, tuple[int, dict[str, str], str]] = {
        "https://example.com/": (
            200,
            {"Content-Type": "text/html; charset=utf-8"},
            '<html><body><a href="/page1">P1</a><a href="/page2">P2</a></body></html>',
        ),
        "https://example.com/page1": (
            200,
            {"Content-Type": "text/html; charset=utf-8"},
            '<html><body><a href="/page3">P3</a></body></html>',
        ),
        "https://example.com/page2": (
            200,
            {"Content-Type": "text/html; charset=utf-8"},
            "<html><body>Page 2 body</body></html>",
        ),
        "https://example.com/page3": (
            200,
            {"Content-Type": "text/html; charset=utf-8"},
            "<html><body>Page 3 body</body></html>",
        ),
    }

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url in responses:
            code, headers, body = responses[url]
            return httpx.Response(code, headers=headers, text=body)
        return httpx.Response(404, text="Not Found")

    transport = httpx.MockTransport(handler)

    registry = CheckRegistry()
    registry.register(DummyPageFindingCheck)

    engine = ScannerEngine(registry=registry)
    config = ScanConfig(
        target_url="https://example.com/",
        crawl_enabled=True,
        max_depth=2,
        max_pages=5,
    )
    scope = TargetScope(allowed_hosts={"example.com"})

    result = await engine.run_scan(
        config=config,
        scope=scope,
        transport=transport,
        dns_resolver=mock_dns_resolver,
    )

    assert result.status == ScanStatus.COMPLETED
    assert len(result.scanned_pages) == 4
    assert "https://example.com/" in result.scanned_pages
    assert "https://example.com/page1" in result.scanned_pages
    assert "https://example.com/page2" in result.scanned_pages
    assert "https://example.com/page3" in result.scanned_pages

    # 4 distinct findings for 4 distinct pages
    assert len(result.findings) == 4
    finding_urls = {f.url for f in result.findings}
    assert finding_urls == {
        "https://example.com/",
        "https://example.com/page1",
        "https://example.com/page2",
        "https://example.com/page3",
    }
    # Request count equals total crawler fetches, checks reuse cached response
    assert result.total_requests == 4


@pytest.mark.asyncio
async def test_real_passive_checks_run_across_discovered_pages(mock_dns_resolver):
    """Verify that real registered passive checks analyze discovered pages with cached responses."""
    responses = {
        "https://example.com/": (
            200,
            {
                "Content-Type": "text/html; charset=utf-8",
                "Set-Cookie": "session=ABC; Secure; HttpOnly; SameSite=Lax",
                "Content-Security-Policy": "default-src 'self'",
            },
            '<html><body><a href="/insecure-page">Next</a></body></html>',
        ),
        "https://example.com/insecure-page": (
            200,
            {
                "Content-Type": "text/html; charset=utf-8",
                "Set-Cookie": "insecure_sess=XYZ; Path=/",
                # Missing CSP and security headers
            },
            "<html><body>No links</body></html>",
        ),
    }

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        code, headers, body = responses[url]
        return httpx.Response(code, headers=headers, text=body)

    transport = httpx.MockTransport(handler)

    registry = CheckRegistry()
    registry.register(SecurityHeadersCheck)
    registry.register(CookieSecurityCheck)

    engine = ScannerEngine(registry=registry)
    config = ScanConfig(
        target_url="https://example.com/",
        crawl_enabled=True,
        max_depth=1,
        max_pages=2,
    )
    scope = TargetScope(allowed_hosts={"example.com"})

    result = await engine.run_scan(
        config=config,
        scope=scope,
        transport=transport,
        dns_resolver=mock_dns_resolver,
    )

    assert result.status == ScanStatus.COMPLETED
    assert len(result.scanned_pages) == 2

    # Findings from /insecure-page must identify insecure cookie and missing headers
    insecure_findings = [f for f in result.findings if f.url == "https://example.com/insecure-page"]
    assert len(insecure_findings) > 0
    assert any("Cookie" in f.title for f in insecure_findings)
    assert any("Content-Security-Policy" in f.title for f in insecure_findings)

    # Total requests must be exactly 2 (crawler fetched each page once, checks reused data)
    assert result.total_requests == 2


@pytest.mark.asyncio
async def test_duplicate_findings_deduplicated_across_and_within_pages(mock_dns_resolver):
    """Verify duplicate findings on same URL are deduped, but same on distinct URLs remain."""
    responses = {
        "https://example.com/": (
            200,
            {"Content-Type": "text/html"},
            '<html><body><a href="/sub">Sub</a></body></html>',
        ),
        "https://example.com/sub": (
            200,
            {"Content-Type": "text/html"},
            "<html><body>Sub page</body></html>",
        ),
    }

    def handler(req: httpx.Request) -> httpx.Response:
        headers, body = responses[str(req.url)][1], responses[str(req.url)][2]
        return httpx.Response(200, headers=headers, text=body)

    transport = httpx.MockTransport(handler)

    registry = CheckRegistry()
    registry.register(DuplicateFindingCheck)

    engine = ScannerEngine(registry=registry)
    config = ScanConfig(target_url="https://example.com/", crawl_enabled=True, max_depth=1)
    scope = TargetScope(allowed_hosts={"example.com"})

    result = await engine.run_scan(
        config=config,
        scope=scope,
        transport=transport,
        dns_resolver=mock_dns_resolver,
    )

    # Within each page, duplicates must be collapsed to 1.
    # Across both pages, findings must NOT be collapsed together because URLs differ.
    assert len(result.findings) == 2
    assert result.findings[0].url == "https://example.com/"
    assert result.findings[1].url == "https://example.com/sub"


@pytest.mark.asyncio
async def test_check_failure_on_one_page_does_not_abort_other_pages(mock_dns_resolver):
    """Verify check exception on one page records partial status without aborting other pages."""
    responses = {
        "https://example.com/": (
            200,
            {"Content-Type": "text/html"},
            '<html><body><a href="/faulty">Faulty</a><a href="/good">Good</a></body></html>',
        ),
        "https://example.com/faulty": (
            200,
            {"Content-Type": "text/html"},
            "<html><body>Faulty page</body></html>",
        ),
        "https://example.com/good": (
            200,
            {"Content-Type": "text/html"},
            "<html><body>Good page</body></html>",
        ),
    }

    def handler(req: httpx.Request) -> httpx.Response:
        headers, body = responses[str(req.url)][1], responses[str(req.url)][2]
        return httpx.Response(200, headers=headers, text=body)

    transport = httpx.MockTransport(handler)

    registry = CheckRegistry()
    registry.register(FlakyCheckOnSpecificPage)

    engine = ScannerEngine(registry=registry)
    config = ScanConfig(target_url="https://example.com/", crawl_enabled=True, max_depth=1)
    scope = TargetScope(allowed_hosts={"example.com"})

    result = await engine.run_scan(
        config=config,
        scope=scope,
        transport=transport,
        dns_resolver=mock_dns_resolver,
    )

    # Status must be PARTIAL because one check threw on /faulty
    assert result.status == ScanStatus.PARTIAL
    assert any("flaky_check@https://example.com/faulty" in k for k in result.check_errors)

    # But checks ran and emitted findings on https://example.com/ and https://example.com/good!
    successful_urls = {f.url for f in result.findings}
    assert "https://example.com/" in successful_urls
    assert "https://example.com/good" in successful_urls
    assert len(result.scanned_pages) == 3


@pytest.mark.asyncio
async def test_crawl_failure_on_one_page_does_not_abort_other_pages(mock_dns_resolver):
    """Verify that an HTTP 500 or network error on one page records failed_pages and continues."""

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url == "https://example.com/":
            return httpx.Response(
                200,
                headers={"Content-Type": "text/html"},
                text=(
                    '<html><body><a href="/broken">Broken</a>'
                    '<a href="/valid">Valid</a></body></html>'
                ),
            )

        if url == "https://example.com/broken":
            return httpx.Response(500, text="Internal Server Error")
        if url == "https://example.com/valid":
            return httpx.Response(200, headers={"Content-Type": "text/html"}, text="Valid page")
        return httpx.Response(404, text="Not Found")

    transport = httpx.MockTransport(handler)

    registry = CheckRegistry()
    registry.register(DummyPageFindingCheck)

    engine = ScannerEngine(registry=registry)
    config = ScanConfig(target_url="https://example.com/", crawl_enabled=True, max_depth=1)
    scope = TargetScope(allowed_hosts={"example.com"})

    result = await engine.run_scan(
        config=config,
        scope=scope,
        transport=transport,
        dns_resolver=mock_dns_resolver,
    )

    # /broken failed crawl with HTTP 500
    assert result.status == ScanStatus.PARTIAL
    assert any("broken" in fp["url"] for fp in result.failed_pages)

    # Scanned pages must contain root and valid page
    assert "https://example.com/" in result.scanned_pages
    assert "https://example.com/valid" in result.scanned_pages
    assert "https://example.com/broken" not in result.scanned_pages


@pytest.mark.asyncio
async def test_multi_page_scan_enforces_page_and_depth_limits(mock_dns_resolver):
    """Verify max_pages and max_depth strictly bound crawl discovery."""

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/":
            next_idx = 1
        else:
            next_idx = int(path.strip("/p")) + 1
        return httpx.Response(
            200,
            headers={"Content-Type": "text/html"},
            text=f'<a href="/p{next_idx}">P{next_idx}</a>',
        )

    transport = httpx.MockTransport(handler)

    registry = CheckRegistry()
    registry.register(DummyPageFindingCheck)

    engine = ScannerEngine(registry=registry)
    # Bound to max_pages=3
    config = ScanConfig(
        target_url="https://example.com/",
        crawl_enabled=True,
        max_depth=5,
        max_pages=3,
    )
    scope = TargetScope(allowed_hosts={"example.com"})

    result = await engine.run_scan(
        config=config,
        scope=scope,
        transport=transport,
        dns_resolver=mock_dns_resolver,
    )

    assert len(result.scanned_pages) == 3
    assert result.total_requests == 3


@pytest.mark.asyncio
async def test_multi_page_scan_enforces_request_limit(mock_dns_resolver):
    """Verify request quota stops discovery and marks scan PARTIAL."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Content-Type": "text/html"},
            text='<a href="/a">A</a><a href="/b">B</a><a href="/c">C</a>',
        )

    transport = httpx.MockTransport(handler)

    registry = CheckRegistry()
    registry.register(DummyPageFindingCheck)

    engine = ScannerEngine(registry=registry)
    config = ScanConfig(
        target_url="https://example.com/",
        crawl_enabled=True,
        max_requests=2,  # Hard request limit
        max_pages=10,
    )
    scope = TargetScope(allowed_hosts={"example.com"})

    result = await engine.run_scan(
        config=config,
        scope=scope,
        transport=transport,
        dns_resolver=mock_dns_resolver,
    )

    assert result.total_requests <= 2
    assert result.status == ScanStatus.PARTIAL


@pytest.mark.asyncio
async def test_multi_page_scan_retains_initial_target_when_seed_fails(mock_dns_resolver):
    """Verify scan result represents target when seed page fails immediately."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="Server Error")

    transport = httpx.MockTransport(handler)

    registry = CheckRegistry()
    registry.register(DummyPageFindingCheck)

    engine = ScannerEngine(registry=registry)
    config = ScanConfig(target_url="https://example.com/", crawl_enabled=True)
    scope = TargetScope(allowed_hosts={"example.com"})

    result = await engine.run_scan(
        config=config,
        scope=scope,
        transport=transport,
        dns_resolver=mock_dns_resolver,
    )

    assert result.status == ScanStatus.FAILED
    assert result.target_url == "https://example.com/"
    assert len(result.scanned_pages) == 0
    assert len(result.failed_pages) == 1
    assert result.failed_pages[0]["url"] == "https://example.com/"


@pytest.mark.asyncio
async def test_multi_page_scan_cancellation_cleans_up(mock_dns_resolver):
    """Verify task cancellation sets CANCELLED status and re-raises CancelledError."""
    gate = asyncio.Event()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Content-Type": "text/html"},
            text='<a href="/a">A</a>',
        )

    transport = httpx.MockTransport(handler)

    class BlockingCheck(BaseCheck):
        @property
        def metadata(self) -> CheckMetadata:
            return CheckMetadata(
                check_id="blocking_check",
                name="Blocking Check",
                description="Blocks until gate is set.",
                severity=Severity.INFO,
            )

        async def run(self, context: ScanContext) -> list[Finding]:
            await gate.wait()
            return []

    registry = CheckRegistry()
    registry.register(BlockingCheck)

    engine = ScannerEngine(registry=registry)
    config = ScanConfig(target_url="https://example.com/", crawl_enabled=True)
    scope = TargetScope(allowed_hosts={"example.com"})

    scan_task = asyncio.create_task(
        engine.run_scan(
            config=config,
            scope=scope,
            transport=transport,
            dns_resolver=mock_dns_resolver,
        )
    )
    await asyncio.sleep(0.05)
    scan_task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await scan_task


@pytest.mark.asyncio
async def test_api_multi_page_scan_endpoint_integration(mock_dns_resolver):
    """Verify POST /api/v1/scans with multi-page crawling enabled via API client."""
    responses = {
        "https://example.com/": (
            200,
            {
                "Content-Type": "text/html; charset=utf-8",
                "Content-Security-Policy": "default-src 'self'",
            },
            '<html><body><a href="/about">About</a></body></html>',
        ),
        "https://example.com/about": (
            200,
            {
                "Content-Type": "text/html; charset=utf-8",
                # Missing CSP
            },
            "<html><body>About Us</body></html>",
        ),
    }

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        code, headers, body = responses[url]
        return httpx.Response(code, headers=headers, text=body)

    mock_transport = httpx.MockTransport(handler)

    from app.api.v1.endpoints.scans import (
        get_async_dns_resolver,
        get_dns_resolver,
        get_scan_transport,
    )

    app.dependency_overrides[get_scan_transport] = lambda: mock_transport
    app.dependency_overrides[get_dns_resolver] = lambda: mock_dns_resolver
    app.dependency_overrides[get_async_dns_resolver] = lambda: None

    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://testserver") as client:
            payload = {
                "target_url": "https://example.com",
                "crawl_enabled": True,
                "max_pages": 5,
                "max_depth": 2,
            }
            res = await client.post("/api/v1/scans", json=payload)
            assert res.status_code == 200
            data = res.json()

            assert data["status"] == "completed"
            assert data["target_url"] == "https://example.com/"
            assert len(data["scanned_pages"]) == 2
            assert "https://example.com/" in data["scanned_pages"]
            assert "https://example.com/about" in data["scanned_pages"]
            assert data["total_requests"] == 2

            # Check that findings for /about were captured
            about_findings = [
                f for f in data["findings"] if f["url"] == "https://example.com/about"
            ]
            assert len(about_findings) > 0
    finally:
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_api_scan_omitted_crawl_enabled_defaults_to_single_page(mock_dns_resolver):
    """Verify that an API request omitting crawl_enabled performs single-page scan."""

    responses = {
        "https://example.com/": (
            200,
            {
                "Content-Type": "text/html; charset=utf-8",
                "Content-Security-Policy": "default-src 'self'",
            },
            '<html><body><a href="/subpage">Subpage</a></body></html>',
        ),
        "https://example.com/subpage": (
            200,
            {"Content-Type": "text/html; charset=utf-8"},
            "<html><body>Subpage</body></html>",
        ),
    }

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        code, headers, body = responses[url]
        return httpx.Response(code, headers=headers, text=body)

    mock_transport = httpx.MockTransport(handler)

    from app.api.v1.endpoints.scans import (
        get_async_dns_resolver,
        get_dns_resolver,
        get_scan_transport,
    )

    app.dependency_overrides[get_scan_transport] = lambda: mock_transport
    app.dependency_overrides[get_dns_resolver] = lambda: mock_dns_resolver
    app.dependency_overrides[get_async_dns_resolver] = lambda: None

    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://testserver") as client:
            # Request payload omits crawl_enabled
            payload = {"target_url": "https://example.com"}
            res = await client.post("/api/v1/scans", json=payload)
            assert res.status_code == 200
            data = res.json()

            # Must remain strictly single-page: /subpage is NOT crawled
            assert data["status"] == "completed"
            assert data["target_url"] == "https://example.com/"
            assert data["scanned_pages"] == ["https://example.com/"]
            assert data["total_requests"] == 1
    finally:
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_api_scan_explicit_crawl_disabled(mock_dns_resolver):
    """Verify that an API request with crawl_enabled=False performs single-page scan."""
    responses = {
        "https://example.com/": (
            200,
            {
                "Content-Type": "text/html; charset=utf-8",
                "Content-Security-Policy": "default-src 'self'",
            },
            '<html><body><a href="/other">Other</a></body></html>',
        ),
    }

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        code, headers, body = responses[url]
        return httpx.Response(code, headers=headers, text=body)

    mock_transport = httpx.MockTransport(handler)

    from app.api.v1.endpoints.scans import (
        get_async_dns_resolver,
        get_dns_resolver,
        get_scan_transport,
    )

    app.dependency_overrides[get_scan_transport] = lambda: mock_transport
    app.dependency_overrides[get_dns_resolver] = lambda: mock_dns_resolver
    app.dependency_overrides[get_async_dns_resolver] = lambda: None

    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://testserver") as client:
            payload = {
                "target_url": "https://example.com",
                "crawl_enabled": False,
            }
            res = await client.post("/api/v1/scans", json=payload)
            assert res.status_code == 200
            data = res.json()

            assert data["status"] == "completed"
            assert data["target_url"] == "https://example.com/"
            assert data["scanned_pages"] == ["https://example.com/"]
            assert data["total_requests"] == 1
            # Verify all standard contract fields are present
            assert "findings" in data
            assert "executed_checks" in data
            assert "check_errors" in data
            assert "duration_seconds" in data
            assert "start_time" in data
            assert "end_time" in data
            assert "failed_pages" in data
    finally:
        app.dependency_overrides.clear()

"""Integration and unit tests for controlled active check framework."""

import asyncio

import httpx
import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app
from app.scanner.checks.http_methods import (
    PROBE_HEADER_NAME,
    PROBE_HEADER_VALUE,
    HttpTraceMethodCheck,
)
from app.scanner.checks.http_options import HttpOptionsMethodCheck
from app.scanner.engine import ScannerEngine
from app.scanner.models import CheckType, ScanConfig, ScanStatus, Severity
from app.scanner.registry import (
    default_active_registry,
    default_registry,
)
from app.scanner.scope import TargetScope


@pytest.fixture
def mock_dns_resolver():
    """Mock DNS resolver returning a valid public IP."""
    return lambda host: ["93.184.216.34"]


@pytest.mark.asyncio
async def test_active_check_classification():
    """Verify that checks are properly classified as passive or active."""
    trace_check = HttpTraceMethodCheck()
    assert trace_check.metadata.check_type == CheckType.ACTIVE
    assert trace_check.metadata.check_id == "http_trace_method"
    assert trace_check.metadata.severity == Severity.LOW

    options_check = HttpOptionsMethodCheck()
    assert options_check.metadata.check_type == CheckType.ACTIVE
    assert options_check.metadata.check_id == "http_options_method"
    assert options_check.metadata.severity == Severity.INFO

    # All standard default checks must be classified as PASSIVE
    for check in default_registry.list_checks():
        assert check.metadata.check_type == CheckType.PASSIVE


@pytest.mark.asyncio
async def test_active_checks_disabled_by_default(mock_dns_resolver):
    """Verify that active checks do not execute when active_checks_enabled is False (default)."""
    executed_methods: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        executed_methods.append(request.method)
        return httpx.Response(
            200,
            headers={"Content-Type": "text/html", "Content-Security-Policy": "default-src 'self'"},
            text="<html><body>Hello</body></html>",
        )

    transport = httpx.MockTransport(handler)

    engine = ScannerEngine(
        registry=default_registry,
        active_registry=default_active_registry,
    )
    # active_checks_enabled defaults to False
    config = ScanConfig(target_url="https://example.com/")
    scope = TargetScope(allowed_hosts={"example.com"})

    result = await engine.run_scan(
        config=config,
        scope=scope,
        transport=transport,
        dns_resolver=mock_dns_resolver,
    )

    assert result.status == ScanStatus.COMPLETED
    assert "http_trace_method" not in result.executed_checks
    # Only GET / HEAD requests occurred, never TRACE
    assert "TRACE" not in executed_methods


@pytest.mark.asyncio
async def test_active_checks_explicit_opt_in_executes(mock_dns_resolver):
    """Verify that active checks execute when active_checks_enabled is explicitly True."""
    executed_methods: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        executed_methods.append(request.method)
        if request.method == "TRACE":
            return httpx.Response(
                200,
                headers={"Content-Type": "message/http"},
                text="TRACE / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            )
        return httpx.Response(
            200,
            headers={"Content-Type": "text/html", "Content-Security-Policy": "default-src 'self'"},
            text="<html><body>Hello</body></html>",
        )

    transport = httpx.MockTransport(handler)

    engine = ScannerEngine(
        registry=default_registry,
        active_registry=default_active_registry,
    )
    config = ScanConfig(
        target_url="https://example.com/",
        active_checks_enabled=True,
    )
    scope = TargetScope(allowed_hosts={"example.com"})

    result = await engine.run_scan(
        config=config,
        scope=scope,
        transport=transport,
        dns_resolver=mock_dns_resolver,
    )

    assert result.status == ScanStatus.COMPLETED
    assert "http_trace_method" in result.executed_checks
    assert "TRACE" in executed_methods

    # Must produce finding for TRACE reflection
    trace_findings = [f for f in result.findings if f.check_id == "http_trace_method"]
    assert len(trace_findings) == 1
    assert trace_findings[0].title == "HTTP TRACE Method Enabled"
    assert trace_findings[0].url == "https://example.com/"
    assert trace_findings[0].severity == Severity.LOW


@pytest.mark.asyncio
async def test_active_check_clean_when_trace_disabled(mock_dns_resolver):
    """Verify that active check emits no findings when TRACE is rejected (e.g. 405)."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "TRACE":
            return httpx.Response(405, text="Method Not Allowed")
        return httpx.Response(
            200,
            headers={"Content-Type": "text/html", "Content-Security-Policy": "default-src 'self'"},
            text="<html><body>Hello</body></html>",
        )

    transport = httpx.MockTransport(handler)

    engine = ScannerEngine(
        registry=default_registry,
        active_registry=default_active_registry,
    )
    config = ScanConfig(
        target_url="https://example.com/",
        active_checks_enabled=True,
    )
    scope = TargetScope(allowed_hosts={"example.com"})

    result = await engine.run_scan(
        config=config,
        scope=scope,
        transport=transport,
        dns_resolver=mock_dns_resolver,
    )

    assert result.status == ScanStatus.COMPLETED
    assert "http_trace_method" in result.executed_checks
    trace_findings = [f for f in result.findings if f.check_id == "http_trace_method"]
    assert len(trace_findings) == 0


@pytest.mark.asyncio
async def test_active_check_rejected_without_opt_in(mock_dns_resolver):
    """Verify requesting an active check ID with active_checks_enabled=False errors."""
    transport = httpx.MockTransport(lambda req: httpx.Response(200, text="OK"))

    engine = ScannerEngine(
        registry=default_registry,
        active_registry=default_active_registry,
    )
    config = ScanConfig(
        target_url="https://example.com/",
        check_ids=["http_trace_method", "security_headers"],
        active_checks_enabled=False,
    )
    scope = TargetScope(allowed_hosts={"example.com"})

    result = await engine.run_scan(
        config=config,
        scope=scope,
        transport=transport,
        dns_resolver=mock_dns_resolver,
    )

    # Passive check ran, but active check was safely disabled
    assert "security_headers" in result.executed_checks
    assert "http_trace_method" not in result.executed_checks
    assert "http_trace_method" in result.check_errors
    assert "active_checks_enabled is False" in result.check_errors["http_trace_method"]
    assert result.status == ScanStatus.PARTIAL


@pytest.mark.asyncio
async def test_api_active_check_requires_authorization():
    """Verify API rejects requests for active checks when active_checks_enabled is False."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        payload = {
            "target_url": "https://example.com",
            "check_ids": ["http_trace_method"],
            "active_checks_enabled": False,
        }
        res = await client.post("/api/v1/scans", json=payload)
        assert res.status_code == 400
        data = res.json()
        assert (
            "Active checks ['http_trace_method'] requested but active_checks_enabled is False"
            in data["detail"]
        )


@pytest.mark.asyncio
async def test_active_check_respects_shared_request_budget(mock_dns_resolver):
    """Verify active checks respect the overall scan request budget."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="OK")

    transport = httpx.MockTransport(handler)

    engine = ScannerEngine(
        registry=default_registry,
        active_registry=default_active_registry,
    )
    # Permitting only 1 request total across scan session
    config = ScanConfig(
        target_url="https://example.com/",
        check_ids=["security_headers", "http_trace_method"],
        active_checks_enabled=True,
        max_requests=1,
    )
    scope = TargetScope(allowed_hosts={"example.com"})

    result = await engine.run_scan(
        config=config,
        scope=scope,
        transport=transport,
        dns_resolver=mock_dns_resolver,
    )

    # One check used the 1 request slot; the other encountered limit error
    assert result.total_requests == 1
    assert result.status == ScanStatus.PARTIAL
    assert "http_trace_method" in result.check_errors


@pytest.mark.asyncio
async def test_active_check_multi_page_attribution(mock_dns_resolver):
    """Verify active checks run sequentially and attribute findings to tested subpage URLs."""
    responses = {
        "https://example.com/": (
            200,
            {"Content-Type": "text/html"},
            '<html><body><a href="/vulnerable">Vulnerable</a></body></html>',
        ),
        "https://example.com/vulnerable": (
            200,
            {"Content-Type": "text/html"},
            "<html><body>Subpage</body></html>",
        ),
    }

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if request.method == "TRACE" and "vulnerable" in url:
            return httpx.Response(
                200,
                headers={"Content-Type": "message/http"},
                text="TRACE /vulnerable HTTP/1.1\r\n\r\n",
            )
        if request.method == "TRACE":
            return httpx.Response(405, text="Method Not Allowed")
        code, headers, body = responses[url]
        return httpx.Response(code, headers=headers, text=body)

    transport = httpx.MockTransport(handler)

    engine = ScannerEngine(
        registry=default_registry,
        active_registry=default_active_registry,
    )
    config = ScanConfig(
        target_url="https://example.com/",
        crawl_enabled=True,
        active_checks_enabled=True,
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

    # Active finding must be attributed specifically to the vulnerable subpage URL
    trace_findings = [f for f in result.findings if f.check_id == "http_trace_method"]
    assert len(trace_findings) == 1
    assert trace_findings[0].url == "https://example.com/vulnerable"


@pytest.mark.asyncio
async def test_checks_endpoint_include_active_query_param():
    """Verify GET /api/v1/checks?include_active=true exposes active checks with metadata."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        # Default query (passive only)
        res_default = await client.get("/api/v1/checks")
        assert res_default.status_code == 200
        data_default = res_default.json()
        assert len(data_default) == 4
        assert all(c["check_type"] == "passive" for c in data_default)

        # include_active=true
        res_active = await client.get("/api/v1/checks?include_active=true")
        assert res_active.status_code == 200
        data_active = res_active.json()
        assert len(data_active) == 6
        active_ids = [c["check_id"] for c in data_active if c["check_type"] == "active"]
        assert active_ids == ["http_options_method", "http_trace_method"]


@pytest.mark.asyncio
async def test_active_check_ignores_ambiguous_html_response(mock_dns_resolver):
    """Verify that 200 OK HTML containing 'trace' without probe echo does not produce a finding."""

    def handler(request: httpx.Request) -> httpx.Response:
        # Ambiguous response: 200 OK returning HTML mentioning 'trace'
        return httpx.Response(
            200,
            headers={"Content-Type": "text/html; charset=utf-8"},
            text=(
                "<!DOCTYPE html><html><head><title>Trace Logistics</title></head>"
                "<body><p>Trace your package delivery status here.</p></body></html>"
            ),
        )

    transport = httpx.MockTransport(handler)
    engine = ScannerEngine(
        registry=default_registry,
        active_registry=default_active_registry,
    )
    config = ScanConfig(
        target_url="https://example.com/",
        check_ids=["http_trace_method"],
        active_checks_enabled=True,
    )
    scope = TargetScope(allowed_hosts={"example.com"})

    result = await engine.run_scan(
        config=config,
        scope=scope,
        transport=transport,
        dns_resolver=mock_dns_resolver,
    )

    assert result.status == ScanStatus.COMPLETED
    assert "http_trace_method" in result.executed_checks
    trace_findings = [f for f in result.findings if f.check_id == "http_trace_method"]
    assert len(trace_findings) == 0


@pytest.mark.asyncio
async def test_active_check_ignores_plain_text_trace_disabled_message(mock_dns_resolver):
    """Verify that 200 OK plain text claiming TRACE is disabled does not produce a finding."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Content-Type": "text/plain"},
            text="TRACE is disabled on this server. Please use standard endpoints.",
        )

    transport = httpx.MockTransport(handler)
    engine = ScannerEngine(
        registry=default_registry,
        active_registry=default_active_registry,
    )
    config = ScanConfig(
        target_url="https://example.com/",
        check_ids=["http_trace_method"],
        active_checks_enabled=True,
    )
    scope = TargetScope(allowed_hosts={"example.com"})

    result = await engine.run_scan(
        config=config,
        scope=scope,
        transport=transport,
        dns_resolver=mock_dns_resolver,
    )

    assert result.status == ScanStatus.COMPLETED
    assert "http_trace_method" in result.executed_checks
    trace_findings = [f for f in result.findings if f.check_id == "http_trace_method"]
    assert len(trace_findings) == 0


@pytest.mark.asyncio
async def test_active_check_detects_reflected_probe_header(mock_dns_resolver):
    """Verify that echoing the diagnostic probe header produces a deterministic finding."""

    def handler(request: httpx.Request) -> httpx.Response:
        echoed_probe = request.headers.get(PROBE_HEADER_NAME, "")
        assert echoed_probe == PROBE_HEADER_VALUE
        return httpx.Response(
            200,
            headers={"Content-Type": "text/plain"},
            text=f"TRACE / HTTP/1.1\r\n{PROBE_HEADER_NAME}: {echoed_probe}\r\n\r\n",
        )

    transport = httpx.MockTransport(handler)
    engine = ScannerEngine(
        registry=default_registry,
        active_registry=default_active_registry,
    )
    config = ScanConfig(
        target_url="https://example.com/",
        check_ids=["http_trace_method"],
        active_checks_enabled=True,
    )
    scope = TargetScope(allowed_hosts={"example.com"})

    result = await engine.run_scan(
        config=config,
        scope=scope,
        transport=transport,
        dns_resolver=mock_dns_resolver,
    )

    assert result.status == ScanStatus.COMPLETED
    trace_findings = [f for f in result.findings if f.check_id == "http_trace_method"]
    assert len(trace_findings) == 1
    finding = trace_findings[0]
    assert finding.title == "HTTP TRACE Method Enabled"
    assert PROBE_HEADER_NAME in finding.evidence
    assert finding.extra_data["reflected_probe_header"] is True


@pytest.mark.asyncio
async def test_unknown_check_id_in_engine_records_error_and_preserves_valid_checks(
    mock_dns_resolver,
):
    """Verify unknown check IDs record error and do not disrupt valid active checks."""
    transport = httpx.MockTransport(
        lambda req: httpx.Response(
            200,
            headers={"Content-Type": "message/http"},
            text="TRACE / HTTP/1.1\r\n\r\n",
        )
    )
    engine = ScannerEngine(
        registry=default_registry,
        active_registry=default_active_registry,
    )
    config = ScanConfig(
        target_url="https://example.com/",
        check_ids=["invalid_custom_check", "http_trace_method"],
        active_checks_enabled=True,
    )
    scope = TargetScope(allowed_hosts={"example.com"})

    result = await engine.run_scan(
        config=config,
        scope=scope,
        transport=transport,
        dns_resolver=mock_dns_resolver,
    )

    assert result.status == ScanStatus.PARTIAL
    assert "invalid_custom_check" in result.check_errors
    assert "is not registered" in result.check_errors["invalid_custom_check"]
    assert "http_trace_method" in result.executed_checks


@pytest.mark.asyncio
async def test_active_check_cancellation_propagates(mock_dns_resolver):
    """Verify asyncio cancellation during active check execution propagates cleanly."""
    pause_gate = asyncio.Event()

    async def blocking_handler(request: httpx.Request) -> httpx.Response:
        await pause_gate.wait()
        return httpx.Response(200, text="OK")

    transport = httpx.MockTransport(blocking_handler)
    engine = ScannerEngine(
        registry=default_registry,
        active_registry=default_active_registry,
    )
    config = ScanConfig(
        target_url="https://example.com/",
        check_ids=["http_trace_method"],
        active_checks_enabled=True,
    )
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
async def test_multi_page_budget_exhaustion_with_active_checks(mock_dns_resolver):
    """Verify that multi-page scan respects budget exhaustion across crawling and active checks."""
    responses = {
        "https://example.com/": (
            200,
            {"Content-Type": "text/html"},
            '<html><body><a href="/p1">P1</a></body></html>',
        ),
        "https://example.com/p1": (
            200,
            {"Content-Type": "text/html"},
            "<html><body>Page 1</body></html>",
        ),
    }

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        code, headers, body = responses[url]
        return httpx.Response(code, headers=headers, text=body)

    transport = httpx.MockTransport(handler)
    engine = ScannerEngine(
        registry=default_registry,
        active_registry=default_active_registry,
    )
    # Budget of 2 requests: crawler consumes 2 requests (seed + /p1)
    # Active check on discovered pages will hit budget limit
    config = ScanConfig(
        target_url="https://example.com/",
        crawl_enabled=True,
        active_checks_enabled=True,
        max_depth=1,
        max_pages=2,
        max_requests=2,
    )
    scope = TargetScope(allowed_hosts={"example.com"})

    result = await engine.run_scan(
        config=config,
        scope=scope,
        transport=transport,
        dns_resolver=mock_dns_resolver,
    )

    assert result.status == ScanStatus.PARTIAL
    assert result.total_requests == 2
    # Active check encountered limit error
    assert any("Scan request limit of 2 exceeded" in err for err in result.check_errors.values())


@pytest.mark.asyncio
async def test_options_check_with_valid_allow_header(mock_dns_resolver):
    """Verify OPTIONS check emits an INFO finding with parsed methods from Allow header."""
    options_requests = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal options_requests
        if request.method == "OPTIONS":
            options_requests += 1
            return httpx.Response(
                200,
                headers={"Allow": "GET, HEAD, POST, OPTIONS"},
            )
        return httpx.Response(200, text="OK")

    transport = httpx.MockTransport(handler)
    engine = ScannerEngine(
        registry=default_registry,
        active_registry=default_active_registry,
    )
    config = ScanConfig(
        target_url="https://example.com/",
        check_ids=["http_options_method"],
        active_checks_enabled=True,
    )
    scope = TargetScope(allowed_hosts={"example.com"})

    result = await engine.run_scan(
        config=config,
        scope=scope,
        transport=transport,
        dns_resolver=mock_dns_resolver,
    )

    assert result.status == ScanStatus.COMPLETED
    assert "http_options_method" in result.executed_checks
    assert options_requests == 1

    findings = [f for f in result.findings if f.check_id == "http_options_method"]
    assert len(findings) == 1
    finding = findings[0]
    assert finding.title == "HTTP Methods Advertised via OPTIONS"
    assert finding.severity == Severity.INFO
    assert "GET, HEAD, OPTIONS, POST" in finding.evidence
    assert finding.extra_data["advertised_methods"] == ["GET", "HEAD", "OPTIONS", "POST"]
    assert finding.extra_data["status_code"] == 200


@pytest.mark.asyncio
async def test_options_check_with_missing_allow_header(mock_dns_resolver):
    """Verify OPTIONS response without Allow header produces no findings."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "OPTIONS":
            return httpx.Response(200, text="No Allow header here")
        return httpx.Response(200, text="OK")

    transport = httpx.MockTransport(handler)
    engine = ScannerEngine(
        registry=default_registry,
        active_registry=default_active_registry,
    )
    config = ScanConfig(
        target_url="https://example.com/",
        check_ids=["http_options_method"],
        active_checks_enabled=True,
    )
    scope = TargetScope(allowed_hosts={"example.com"})

    result = await engine.run_scan(
        config=config,
        scope=scope,
        transport=transport,
        dns_resolver=mock_dns_resolver,
    )

    assert result.status == ScanStatus.COMPLETED
    assert "http_options_method" in result.executed_checks
    findings = [f for f in result.findings if f.check_id == "http_options_method"]
    assert len(findings) == 0


@pytest.mark.asyncio
async def test_options_check_with_empty_malformed_and_duplicated_methods(mock_dns_resolver):
    """Verify Allow header parsing handles malformed tokens, casing, and deduplication."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "OPTIONS":
            return httpx.Response(
                200,
                headers={"Allow": "GET, post, , GET, invalid***token, OPTIONS, HEAD, ,"},
            )
        return httpx.Response(200, text="OK")

    transport = httpx.MockTransport(handler)
    engine = ScannerEngine(
        registry=default_registry,
        active_registry=default_active_registry,
    )
    config = ScanConfig(
        target_url="https://example.com/",
        check_ids=["http_options_method"],
        active_checks_enabled=True,
    )
    scope = TargetScope(allowed_hosts={"example.com"})

    result = await engine.run_scan(
        config=config,
        scope=scope,
        transport=transport,
        dns_resolver=mock_dns_resolver,
    )

    assert result.status == ScanStatus.COMPLETED
    findings = [f for f in result.findings if f.check_id == "http_options_method"]
    assert len(findings) == 1
    assert findings[0].extra_data["advertised_methods"] == ["GET", "HEAD", "OPTIONS", "POST"]


@pytest.mark.asyncio
async def test_options_check_non_2xx_responses_yield_no_findings(mock_dns_resolver):
    """Verify 405 Method Not Allowed or 501 Not Implemented yield no findings."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "OPTIONS":
            return httpx.Response(405, headers={"Allow": "GET, POST"}, text="Not Allowed")
        return httpx.Response(200, text="OK")

    transport = httpx.MockTransport(handler)
    engine = ScannerEngine(
        registry=default_registry,
        active_registry=default_active_registry,
    )
    config = ScanConfig(
        target_url="https://example.com/",
        check_ids=["http_options_method"],
        active_checks_enabled=True,
    )
    scope = TargetScope(allowed_hosts={"example.com"})

    result = await engine.run_scan(
        config=config,
        scope=scope,
        transport=transport,
        dns_resolver=mock_dns_resolver,
    )

    assert result.status == ScanStatus.COMPLETED
    findings = [f for f in result.findings if f.check_id == "http_options_method"]
    assert len(findings) == 0


@pytest.mark.asyncio
async def test_options_check_no_false_vulnerability_from_advertised_trace_put_delete(
    mock_dns_resolver,
):
    """Verify advertising PUT, DELETE, or TRACE produces only an INFO finding, not vulnerability."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "OPTIONS":
            return httpx.Response(
                200,
                headers={"Allow": "GET, POST, PUT, DELETE, TRACE"},
            )
        return httpx.Response(200, text="OK")

    transport = httpx.MockTransport(handler)
    engine = ScannerEngine(
        registry=default_registry,
        active_registry=default_active_registry,
    )
    config = ScanConfig(
        target_url="https://example.com/",
        check_ids=["http_options_method"],
        active_checks_enabled=True,
    )
    scope = TargetScope(allowed_hosts={"example.com"})

    result = await engine.run_scan(
        config=config,
        scope=scope,
        transport=transport,
        dns_resolver=mock_dns_resolver,
    )

    assert result.status == ScanStatus.COMPLETED
    findings = [f for f in result.findings if f.check_id == "http_options_method"]
    assert len(findings) == 1
    # Finding must remain strictly INFO, never upgraded to vulnerability
    assert findings[0].severity == Severity.INFO
    assert findings[0].title == "HTTP Methods Advertised via OPTIONS"
    assert "DELETE, GET, POST, PUT, TRACE" in findings[0].evidence


@pytest.mark.asyncio
async def test_options_check_timeout_handling(mock_dns_resolver):
    """Verify request timeout during OPTIONS check records error and does not crash scan."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "OPTIONS":
            raise httpx.ReadTimeout("Connection timed out", request=request)
        return httpx.Response(200, text="OK")

    transport = httpx.MockTransport(handler)
    engine = ScannerEngine(
        registry=default_registry,
        active_registry=default_active_registry,
    )
    config = ScanConfig(
        target_url="https://example.com/",
        check_ids=["http_options_method"],
        active_checks_enabled=True,
    )
    scope = TargetScope(allowed_hosts={"example.com"})

    result = await engine.run_scan(
        config=config,
        scope=scope,
        transport=transport,
        dns_resolver=mock_dns_resolver,
    )

    assert result.status == ScanStatus.FAILED
    assert "http_options_method" in result.check_errors
    assert "timed out" in result.check_errors["http_options_method"]


@pytest.mark.asyncio
async def test_options_check_disabled_by_default(mock_dns_resolver):
    """Verify OPTIONS check does not execute when active_checks_enabled is False."""
    options_invoked = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal options_invoked
        if request.method == "OPTIONS":
            options_invoked = True
        return httpx.Response(200, text="OK")

    transport = httpx.MockTransport(handler)
    engine = ScannerEngine(
        registry=default_registry,
        active_registry=default_active_registry,
    )
    config = ScanConfig(
        target_url="https://example.com/",
        active_checks_enabled=False,
    )
    scope = TargetScope(allowed_hosts={"example.com"})

    result = await engine.run_scan(
        config=config,
        scope=scope,
        transport=transport,
        dns_resolver=mock_dns_resolver,
    )

    assert result.status == ScanStatus.COMPLETED
    assert not options_invoked
    assert "http_options_method" not in result.executed_checks


@pytest.mark.asyncio
async def test_options_check_explicit_opt_in(mock_dns_resolver):
    """Verify OPTIONS check executes when active_checks_enabled is True."""
    options_invoked = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal options_invoked
        if request.method == "OPTIONS":
            options_invoked = True
            return httpx.Response(200, headers={"Allow": "GET, OPTIONS"})
        return httpx.Response(200, text="OK")

    transport = httpx.MockTransport(handler)
    engine = ScannerEngine(
        registry=default_registry,
        active_registry=default_active_registry,
    )
    config = ScanConfig(
        target_url="https://example.com/",
        check_ids=["http_options_method"],
        active_checks_enabled=True,
    )
    scope = TargetScope(allowed_hosts={"example.com"})

    result = await engine.run_scan(
        config=config,
        scope=scope,
        transport=transport,
        dns_resolver=mock_dns_resolver,
    )

    assert result.status == ScanStatus.COMPLETED
    assert options_invoked
    assert "http_options_method" in result.executed_checks


@pytest.mark.asyncio
async def test_options_check_shared_request_budget_enforcement(mock_dns_resolver):
    """Verify OPTIONS check respects overall scan request budget."""
    transport = httpx.MockTransport(
        lambda req: httpx.Response(200, headers={"Allow": "GET, OPTIONS"}, text="OK")
    )
    engine = ScannerEngine(
        registry=default_registry,
        active_registry=default_active_registry,
    )
    # Budget of 1 request: passive check uses 1; OPTIONS check hits limit
    config = ScanConfig(
        target_url="https://example.com/",
        check_ids=["security_headers", "http_options_method"],
        active_checks_enabled=True,
        max_requests=1,
    )
    scope = TargetScope(allowed_hosts={"example.com"})

    result = await engine.run_scan(
        config=config,
        scope=scope,
        transport=transport,
        dns_resolver=mock_dns_resolver,
    )

    assert result.total_requests == 1
    assert result.status == ScanStatus.PARTIAL
    assert "http_options_method" in result.check_errors
    assert "Scan request limit of 1 exceeded" in result.check_errors["http_options_method"]


@pytest.mark.asyncio
async def test_options_check_scope_and_redirect_protection(mock_dns_resolver):
    """Verify that an off-scope redirect on OPTIONS is blocked by client scope policy."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "OPTIONS":
            # Off-scope redirect attempt
            return httpx.Response(
                302,
                headers={"Location": "https://evil-offscope.com/options"},
            )
        return httpx.Response(200, text="OK")

    transport = httpx.MockTransport(handler)
    engine = ScannerEngine(
        registry=default_registry,
        active_registry=default_active_registry,
    )
    config = ScanConfig(
        target_url="https://example.com/",
        check_ids=["http_options_method"],
        active_checks_enabled=True,
    )
    scope = TargetScope(allowed_hosts={"example.com"})

    result = await engine.run_scan(
        config=config,
        scope=scope,
        transport=transport,
        dns_resolver=mock_dns_resolver,
    )

    # Check should fail safely because redirect went off-scope
    assert "http_options_method" in result.check_errors
    assert "violates target scope" in result.check_errors["http_options_method"]


@pytest.mark.asyncio
async def test_options_check_single_request_guarantee(mock_dns_resolver):
    """Verify that HttpOptionsMethodCheck dispatches at most one OPTIONS request."""
    dispatched_methods: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        dispatched_methods.append(request.method)
        if request.method == "OPTIONS":
            return httpx.Response(200, headers={"Allow": "GET, POST, OPTIONS"})
        return httpx.Response(200, text="OK")

    transport = httpx.MockTransport(handler)
    engine = ScannerEngine(
        registry=default_registry,
        active_registry=default_active_registry,
    )
    config = ScanConfig(
        target_url="https://example.com/",
        check_ids=["http_options_method"],
        active_checks_enabled=True,
    )
    scope = TargetScope(allowed_hosts={"example.com"})

    result = await engine.run_scan(
        config=config,
        scope=scope,
        transport=transport,
        dns_resolver=mock_dns_resolver,
    )

    assert result.status == ScanStatus.COMPLETED
    assert dispatched_methods.count("OPTIONS") == 1
    assert result.total_requests == 1


@pytest.mark.asyncio
async def test_options_and_trace_both_run_when_active_enabled(mock_dns_resolver):
    """Verify both active checks execute sequentially when active checks are enabled."""
    dispatched: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        dispatched.append(request.method)
        if request.method == "OPTIONS":
            return httpx.Response(200, headers={"Allow": "GET, OPTIONS, TRACE"})
        if request.method == "TRACE":
            return httpx.Response(405, text="Method Not Allowed")
        return httpx.Response(200, text="OK")

    transport = httpx.MockTransport(handler)
    engine = ScannerEngine(
        registry=default_registry,
        active_registry=default_active_registry,
    )
    config = ScanConfig(
        target_url="https://example.com/",
        check_ids=["http_options_method", "http_trace_method"],
        active_checks_enabled=True,
    )
    scope = TargetScope(allowed_hosts={"example.com"})

    result = await engine.run_scan(
        config=config,
        scope=scope,
        transport=transport,
        dns_resolver=mock_dns_resolver,
    )

    assert result.status == ScanStatus.COMPLETED
    assert "http_options_method" in result.executed_checks
    assert "http_trace_method" in result.executed_checks
    assert "OPTIONS" in dispatched
    assert "TRACE" in dispatched
    # OPTIONS finding present (INFO); TRACE rejected with 405, so 0 findings for TRACE
    opt_findings = [f for f in result.findings if f.check_id == "http_options_method"]
    trace_findings = [f for f in result.findings if f.check_id == "http_trace_method"]
    assert len(opt_findings) == 1
    assert len(trace_findings) == 0

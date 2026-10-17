"""Unit tests for HttpsConfigurationCheck and multi-check baseline sharing."""

import asyncio

import httpx
import pytest

from app.scanner.check import ScanContext
from app.scanner.checks.headers import SecurityHeadersCheck
from app.scanner.checks.https import HttpsConfigurationCheck
from app.scanner.client import ScannerHttpClient, ScannerResponse, ScannerTimeoutError
from app.scanner.models import Severity
from app.scanner.scope import ScopePolicy, TargetScope


def make_context_with_response(
    target_url: str,
    response: ScannerResponse,
) -> ScanContext:
    """Create ScanContext with a pre-populated ScannerResponse."""
    scope = TargetScope(allowed_hosts={"example.com"})
    policy = ScopePolicy(scope, dns_resolver=lambda _: ["93.184.216.34"])
    client = ScannerHttpClient(scope_policy=policy)
    return ScanContext(
        target_url=target_url,
        scope=scope,
        client=client,
        baseline_response=response,
    )


@pytest.mark.asyncio
async def test_https_direct_secure():
    """Verify that a direct HTTPS endpoint produces no findings."""
    resp = ScannerResponse(
        status_code=200,
        headers=httpx.Headers({"Content-Type": "text/html"}),
        url="https://example.com/",
        content=b"OK",
        history=[],
    )
    context = make_context_with_response("https://example.com/", resp)
    check = HttpsConfigurationCheck()

    findings = await check.run(context)
    assert len(findings) == 0


@pytest.mark.asyncio
async def test_https_http_upgraded_to_https():
    """Verify that HTTP upgrading to HTTPS is recognized as an upgrade, not a vulnerability."""
    resp = ScannerResponse(
        status_code=200,
        headers=httpx.Headers({"Content-Type": "text/html"}),
        url="https://example.com/",
        content=b"OK",
        history=["http://example.com/"],
    )
    context = make_context_with_response("http://example.com/", resp)
    check = HttpsConfigurationCheck()

    findings = await check.run(context)
    assert len(findings) == 0


@pytest.mark.asyncio
async def test_https_http_remains_on_http():
    """Verify that an HTTP endpoint remaining on cleartext HTTP produces a Medium finding."""
    resp = ScannerResponse(
        status_code=200,
        headers=httpx.Headers({"Content-Type": "text/html"}),
        url="http://example.com/",
        content=b"OK",
        history=[],
    )
    context = make_context_with_response("http://example.com/", resp)
    check = HttpsConfigurationCheck()

    findings = await check.run(context)
    assert len(findings) == 1
    f = findings[0]
    assert f.check_id == "https_configuration"
    assert f.title == "Cleartext HTTP Service Without HTTPS Upgrade"
    assert f.severity == Severity.MEDIUM
    assert "cleartext HTTP" in f.evidence


@pytest.mark.asyncio
async def test_https_downgrade_redirect_chain():
    """Verify that an HTTPS target redirecting to cleartext HTTP produces a High finding."""
    resp = ScannerResponse(
        status_code=200,
        headers=httpx.Headers({"Content-Type": "text/html"}),
        url="http://example.com/insecure-login",
        content=b"Insecure Page",
        history=["https://example.com/login"],
    )
    context = make_context_with_response("https://example.com/login", resp)
    check = HttpsConfigurationCheck()

    findings = await check.run(context)
    assert len(findings) == 1
    f = findings[0]
    assert f.check_id == "https_configuration"
    assert f.title == "Insecure HTTPS to HTTP Downgrade Redirection"
    assert f.severity == Severity.HIGH
    assert "Redirect chain:" in f.evidence
    assert "https://example.com/login -> http://example.com/insecure-login" in f.evidence


@pytest.mark.asyncio
async def test_https_failure_to_obtain_baseline_bubbles_up():
    """Verify that a network failure during baseline retrieval bubbles up without false findings."""

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("Timeout")

    transport = httpx.MockTransport(handler)
    scope = TargetScope(allowed_hosts={"example.com"})
    policy = ScopePolicy(scope, dns_resolver=lambda _: ["93.184.216.34"])

    async with ScannerHttpClient(scope_policy=policy, transport=transport) as client:
        context = ScanContext(target_url="https://example.com/", scope=scope, client=client)
        check = HttpsConfigurationCheck()

        with pytest.raises(ScannerTimeoutError):
            await check.run(context)


@pytest.mark.asyncio
async def test_both_checks_share_single_baseline_request():
    """Verify that SecurityHeadersCheck and HttpsConfigurationCheck share 1 baseline request."""
    request_count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal request_count
        request_count += 1
        return httpx.Response(
            200,
            headers={
                "Content-Type": "text/html",
                "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
                "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "strict-origin-when-cross-origin",
                "Permissions-Policy": "camera=()",
            },
            text="<html>Secure app</html>",
        )

    transport = httpx.MockTransport(handler)
    scope = TargetScope(allowed_hosts={"example.com"})
    policy = ScopePolicy(scope, dns_resolver=lambda _: ["93.184.216.34"])

    async with ScannerHttpClient(scope_policy=policy, transport=transport) as client:
        context = ScanContext(target_url="https://example.com/", scope=scope, client=client)

        sec_check = SecurityHeadersCheck()
        https_check = HttpsConfigurationCheck()

        # Run both checks concurrently on the same context
        findings_sec, findings_https = await asyncio.gather(
            sec_check.run(context),
            https_check.run(context),
        )

        # Security check evaluates headers
        assert len(findings_sec) == 0

        # HTTPS check evaluates scheme
        assert len(findings_https) == 0

        # Exactly 1 request was issued across both checks!
        assert request_count == 1
        assert client.request_count == 1
        assert context.has_baseline_response is True

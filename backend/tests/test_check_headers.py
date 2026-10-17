"""Unit tests for SecurityHeadersCheck."""

import httpx
import pytest

from app.scanner.check import ScanContext
from app.scanner.checks.headers import SecurityHeadersCheck
from app.scanner.client import ScannerHttpClient
from app.scanner.models import Severity
from app.scanner.scope import ScopePolicy, TargetScope


def make_context(
    url: str,
    headers: dict[str, str],
    status_code: int = 200,
) -> ScanContext:
    """Helper to build a ScanContext with mocked HTTP transport."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code, headers=headers, text="OK")

    transport = httpx.MockTransport(handler)
    scope = TargetScope(allowed_hosts={"example.com"})
    policy = ScopePolicy(scope, dns_resolver=lambda _: ["93.184.216.34"])
    client = ScannerHttpClient(scope_policy=policy, transport=transport)
    return ScanContext(target_url=url, scope=scope, client=client)


@pytest.mark.asyncio
async def test_security_headers_all_present_secure():
    """Verify that a fully hardened response produces zero findings."""
    headers = {
        "Content-Type": "text/html; charset=utf-8",
        "Content-Security-Policy": (
            "default-src 'self'; script-src 'self' https://trusted.cdn; "
            "object-src 'none'; frame-ancestors 'none'"
        ),
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    }
    context = make_context("https://example.com/", headers)
    check = SecurityHeadersCheck()

    findings = await check.run(context)
    assert len(findings) == 0


@pytest.mark.asyncio
async def test_security_headers_missing_all():
    """Verify findings when an HTTPS HTML endpoint provides no security headers."""
    headers = {"Content-Type": "text/html"}
    context = make_context("https://example.com/", headers)
    check = SecurityHeadersCheck()

    findings = await check.run(context)
    # Expected: CSP, HSTS, XCTO, Clickjacking, Referrer-Policy, Permissions-Policy
    titles = {f.title for f in findings}
    assert "Missing Content-Security-Policy" in titles
    assert "Missing Strict-Transport-Security Header" in titles
    assert "Missing or Invalid X-Content-Type-Options Header" in titles
    assert "Missing Clickjacking Protections" in titles
    assert "Missing Referrer-Policy Header" in titles
    assert "Missing Permissions-Policy Header" in titles

    # Verify no finding has CRITICAL or HIGH severity (all LOW or INFO)
    for f in findings:
        assert f.severity in (Severity.LOW, Severity.INFO)
        assert f.check_id == "security_headers"


@pytest.mark.asyncio
async def test_security_headers_hsts_not_flagged_on_http():
    """Verify that missing HSTS is not flagged on an HTTP response."""
    headers = {
        "Content-Type": "text/html",
        "Content-Security-Policy": "default-src 'self'; object-src 'none'; frame-ancestors 'none'",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "geolocation=()",
    }
    context = make_context("http://example.com/", headers)
    check = SecurityHeadersCheck()

    findings = await check.run(context)
    titles = [f.title for f in findings]
    assert "Missing Strict-Transport-Security Header" not in titles


@pytest.mark.asyncio
async def test_security_headers_hsts_valid_no_finding():
    """Verify that a valid HSTS header with max-age >= 120 days emits no finding."""
    headers = {
        "Content-Type": "application/json",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'none'",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "camera=()",
    }
    context = make_context("https://example.com/api", headers)
    check = SecurityHeadersCheck()

    findings = await check.run(context)
    hsts_findings = [f for f in findings if "Strict-Transport-Security" in f.title]
    assert len(hsts_findings) == 0


@pytest.mark.asyncio
async def test_security_headers_hsts_short_max_age():
    """Verify that short HSTS max-age emits an INFO severity finding."""
    headers = {
        "Strict-Transport-Security": "max-age=86400",  # 1 day
    }
    context = make_context("https://example.com/", headers)
    check = SecurityHeadersCheck()

    findings = await check.run(context)
    short_hsts = [f for f in findings if f.title == "Short Strict-Transport-Security Max-Age"]
    assert len(short_hsts) == 1
    assert short_hsts[0].severity == Severity.INFO
    assert "86400" in short_hsts[0].evidence


@pytest.mark.asyncio
async def test_security_headers_hsts_missing_or_malformed_max_age():
    """Verify that malformed HSTS headers emit LOW severity findings."""
    # 1. Missing max-age directive
    ctx_missing = make_context(
        "https://example.com/", {"Strict-Transport-Security": "includeSubDomains"}
    )
    check = SecurityHeadersCheck()
    findings_missing = await check.run(ctx_missing)
    f_missing = [
        f for f in findings_missing if f.title == "Malformed Strict-Transport-Security Header"
    ]
    assert len(f_missing) == 1

    # 2. Non-numeric max-age directive
    ctx_bad_int = make_context(
        "https://example.com/", {"Strict-Transport-Security": "max-age=one_year"}
    )
    findings_bad = await check.run(ctx_bad_int)
    f_bad = [f for f in findings_bad if f.title == "Malformed Strict-Transport-Security Header"]
    assert len(f_bad) == 1


@pytest.mark.asyncio
async def test_security_headers_csp_risky_directives():
    """Verify detection of 'unsafe-inline' and 'unsafe-eval' in script-src."""
    headers = {
        "Content-Security-Policy": (
            "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
            "object-src 'none'; frame-ancestors 'none'"
        ),
        "Content-Type": "text/html",
    }
    context = make_context("https://example.com/", headers)
    check = SecurityHeadersCheck()

    findings = await check.run(context)
    risky = [f for f in findings if f.title == "Insecure Content-Security-Policy Directives"]
    assert len(risky) == 1
    assert risky[0].severity == Severity.LOW
    assert "'unsafe-inline'" in risky[0].evidence
    assert "'unsafe-eval'" in risky[0].evidence


@pytest.mark.asyncio
async def test_security_headers_csp_object_src_wildcard():
    """Verify detection of overly permissive object-src wildcard."""
    headers = {
        "Content-Security-Policy": "default-src 'self'; object-src *; frame-ancestors 'none'",
        "Content-Type": "text/html",
    }
    context = make_context("https://example.com/", headers)
    check = SecurityHeadersCheck()

    findings = await check.run(context)
    obj_wildcard = [f for f in findings if f.title == "Overly Permissive CSP object-src Directive"]
    assert len(obj_wildcard) == 1
    assert obj_wildcard[0].severity == Severity.LOW


@pytest.mark.asyncio
async def test_security_headers_clickjacking_mitigated_by_csp_frame_ancestors():
    """Verify that CSP frame-ancestors satisfies clickjacking protection without X-Frame-Options."""
    headers = {
        "Content-Type": "text/html",
        "Content-Security-Policy": "default-src 'self'; object-src 'none'; frame-ancestors 'self'",
    }
    context = make_context("https://example.com/", headers)
    check = SecurityHeadersCheck()

    findings = await check.run(context)
    clickjacking_findings = [
        f for f in findings if "Clickjacking" in f.title or "X-Frame-Options" in f.title
    ]
    assert len(clickjacking_findings) == 0


@pytest.mark.asyncio
async def test_security_headers_clickjacking_mitigated_by_xfo():
    """Verify that X-Frame-Options DENY or SAMEORIGIN satisfies clickjacking protection."""
    headers = {
        "Content-Type": "text/html",
        "X-Frame-Options": "SAMEORIGIN",
        "Content-Security-Policy": "default-src 'self'; object-src 'none'",
    }
    context = make_context("https://example.com/", headers)
    check = SecurityHeadersCheck()

    findings = await check.run(context)
    clickjacking_findings = [
        f for f in findings if "Clickjacking" in f.title or "X-Frame-Options" in f.title
    ]
    assert len(clickjacking_findings) == 0


@pytest.mark.asyncio
async def test_security_headers_clickjacking_obsolete_xfo():
    """Verify that obsolete X-Frame-Options ALLOW-FROM is flagged."""
    headers = {
        "Content-Type": "text/html",
        "X-Frame-Options": "ALLOW-FROM https://trusted.example.com",
    }
    context = make_context("https://example.com/", headers)
    check = SecurityHeadersCheck()

    findings = await check.run(context)
    obsolete = [f for f in findings if f.title == "Invalid or Obsolete X-Frame-Options Header"]
    assert len(obsolete) == 1
    assert "ALLOW-FROM" in obsolete[0].evidence


@pytest.mark.asyncio
async def test_security_headers_clickjacking_ignored_on_json():
    """Verify that non-HTML responses (e.g. application/json) are not flagged for clickjacking."""
    headers = {
        "Content-Type": "application/json",
        "Content-Security-Policy": "default-src 'none'",
    }
    context = make_context("https://example.com/api", headers)
    check = SecurityHeadersCheck()

    findings = await check.run(context)
    clickjacking_findings = [
        f for f in findings if "Clickjacking" in f.title or "X-Frame-Options" in f.title
    ]
    assert len(clickjacking_findings) == 0


@pytest.mark.asyncio
async def test_security_headers_xcto_case_and_invalid():
    """Verify case-insensitivity of nosniff and detection of invalid values."""
    # Case-insensitive valid nosniff
    ctx_case = make_context("https://example.com/", {"X-Content-Type-Options": "NoSniff"})
    findings_case = await SecurityHeadersCheck().run(ctx_case)
    assert not any(
        f.title == "Missing or Invalid X-Content-Type-Options Header" for f in findings_case
    )

    # Invalid value
    ctx_invalid = make_context("https://example.com/", {"X-Content-Type-Options": "sniff"})
    findings_invalid = await SecurityHeadersCheck().run(ctx_invalid)
    assert any(
        f.title == "Missing or Invalid X-Content-Type-Options Header" for f in findings_invalid
    )


@pytest.mark.asyncio
async def test_security_headers_referrer_policy_insecure():
    """Verify that unsafe-url or no-referrer-when-downgrade produces a warning."""
    headers = {"Referrer-Policy": "unsafe-url"}
    context = make_context("https://example.com/", headers)
    findings = await SecurityHeadersCheck().run(context)

    weak_ref = [f for f in findings if f.title == "Weak Referrer-Policy Configuration"]
    assert len(weak_ref) == 1
    assert weak_ref[0].severity == Severity.LOW
    assert "unsafe-url" in weak_ref[0].evidence


@pytest.mark.asyncio
async def test_security_headers_empty_and_whitespace_values():
    """Verify that empty and whitespace-only header values are handled safely without crashing."""
    headers = {
        "Content-Type": "text/html",
        "Content-Security-Policy": "   ",
        "Strict-Transport-Security": "",
        "X-Content-Type-Options": "   ",
        "X-Frame-Options": "",
        "Referrer-Policy": "   ",
        "Permissions-Policy": "",
    }
    context = make_context("https://example.com/", headers)
    findings = await SecurityHeadersCheck().run(context)

    titles = {f.title for f in findings}
    assert "Missing Content-Security-Policy" in titles
    assert "Missing Strict-Transport-Security Header" in titles
    assert "Missing or Invalid X-Content-Type-Options Header" in titles
    assert "Missing Clickjacking Protections" in titles
    assert "Missing Referrer-Policy Header" in titles
    assert "Missing Permissions-Policy Header" in titles

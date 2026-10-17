"""Unit tests for CorsSecurityCheck and scanner engine registration."""

import json

import httpx
import pytest

from app.scanner.check import ScanContext
from app.scanner.checks.cors import CorsSecurityCheck
from app.scanner.client import ScannerHttpClient, ScannerTimeoutError
from app.scanner.engine import ScannerEngine
from app.scanner.models import ScanConfig, ScanStatus, Severity
from app.scanner.registry import default_registry
from app.scanner.scope import ScopePolicy, TargetScope


def make_context(
    url: str,
    headers: dict[str, str] | list[tuple[str, str]] | None = None,
    status_code: int = 200,
) -> ScanContext:
    """Helper creating ScanContext with mock HTTP transport returning specified headers."""
    header_list: list[tuple[str, str]] = []
    if headers:
        if isinstance(headers, dict):
            for k, v in headers.items():
                header_list.append((k, v))
        else:
            header_list.extend(headers)

    response_headers = httpx.Headers(header_list)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code, headers=response_headers, text="OK")

    transport = httpx.MockTransport(handler)
    scope = TargetScope(allowed_hosts={"example.com"})
    policy = ScopePolicy(scope, dns_resolver=lambda _: ["93.184.216.34"])
    client = ScannerHttpClient(scope_policy=policy, transport=transport)
    return ScanContext(target_url=url, scope=scope, client=client)


@pytest.mark.asyncio
async def test_cors_no_headers():
    """1. Response with no CORS headers produces zero findings."""
    context = make_context("https://example.com/", {})
    findings = await CorsSecurityCheck().run(context)
    assert len(findings) == 0


@pytest.mark.asyncio
async def test_cors_wildcard_allowed_origin():
    """2. Wildcard origin without credentials produces Low severity finding."""
    headers = {"Access-Control-Allow-Origin": "*"}
    context = make_context("https://example.com/", headers)
    findings = await CorsSecurityCheck().run(context)

    assert len(findings) == 1
    f = findings[0]
    assert f.title == "Permissive CORS Wildcard Origin Allowed"
    assert f.severity == Severity.LOW
    assert "uncredentialed" in f.evidence
    assert f.extra_data.get("allowed_origin") == "*"
    assert f.extra_data.get("allow_credentials") is False


@pytest.mark.asyncio
async def test_cors_wildcard_with_credentials_enabled():
    """3. Wildcard origin combined with credentials reports conflicting browser rejection."""
    headers = {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": "true",
    }
    context = make_context("https://example.com/", headers)
    findings = await CorsSecurityCheck().run(context)

    assert len(findings) == 1
    f = findings[0]
    assert f.title == "Conflicting CORS Wildcard Origin With Credentials Allowed"
    assert f.severity == Severity.LOW
    assert "Fetch standard" in f.evidence
    assert "does not grant" in f.evidence
    assert f.extra_data.get("allow_credentials") is True


@pytest.mark.asyncio
async def test_cors_explicit_trusted_origin():
    """4. Explicit valid HTTPS origin with Vary: Origin and credentials produces zero findings."""
    headers = {
        "Access-Control-Allow-Origin": "https://app.example.com",
        "Access-Control-Allow-Credentials": "true",
        "Vary": "Origin",
    }
    context = make_context("https://example.com/", headers)
    findings = await CorsSecurityCheck().run(context)
    assert len(findings) == 0


@pytest.mark.asyncio
async def test_cors_null_allowed_origin():
    """5. 'null' allowed origin reports sandbox iframe and redirect risk."""
    # 5a. Without credentials
    headers_no_cred = {"Access-Control-Allow-Origin": "null"}
    context = make_context("https://example.com/", headers_no_cred)
    findings = await CorsSecurityCheck().run(context)

    assert len(findings) == 1
    f = findings[0]
    assert f.title == "Insecure CORS Null Origin Allowed"
    assert f.severity == Severity.MEDIUM
    assert "sandboxed iframe" in f.evidence
    assert f.extra_data.get("allow_credentials") is False

    # 5b. With credentials
    headers_cred = {
        "Access-Control-Allow-Origin": "null",
        "Access-Control-Allow-Credentials": "true",
    }
    context_cred = make_context("https://example.com/", headers_cred)
    findings_cred = await CorsSecurityCheck().run(context_cred)

    assert len(findings_cred) == 1
    f_cred = findings_cred[0]
    assert f_cred.title == "Insecure CORS Null Origin Allowed"
    assert f_cred.severity == Severity.MEDIUM
    assert "credentials" in f_cred.evidence.lower()
    assert f_cred.extra_data.get("allow_credentials") is True


@pytest.mark.asyncio
async def test_cors_malformed_allowed_origin():
    """6. Malformed origin syntax is detected and reported as Low severity finding."""
    malformed_origins = [
        "https://*.example.com",  # Wildcard subdomain (invalid in CORS)
        "example.com",  # Missing scheme
        "https://app.example.com/api",  # Path not allowed in origin
        "https://app.example.com/",  # Trailing slash not allowed in origin
        "https://a.com https://b.com",  # Space-separated origins
        "https://[invalid",  # Unparseable URL
    ]

    for origin in malformed_origins:
        headers = {"Access-Control-Allow-Origin": origin}
        context = make_context("https://example.com/", headers)
        findings = await CorsSecurityCheck().run(context)

        malformed_findings = [
            f for f in findings if "Malformed CORS Access-Control-Allow-Origin" in f.title
        ]
        assert len(malformed_findings) == 1, f"Expected malformed finding for '{origin}'"
        assert malformed_findings[0].severity == Severity.LOW
        assert "malformed" in malformed_findings[0].evidence


@pytest.mark.asyncio
async def test_cors_duplicate_or_conflicting_headers():
    """7. Duplicate or comma-separated ACAO headers produce a single structured finding."""
    # 7a. Duplicate separate headers
    header_list = [
        ("Access-Control-Allow-Origin", "https://a.example.com"),
        ("Access-Control-Allow-Origin", "https://b.example.com"),
    ]
    context = make_context("https://example.com/", header_list)
    findings = await CorsSecurityCheck().run(context)

    assert len(findings) == 1
    assert findings[0].title == "Duplicate CORS Access-Control-Allow-Origin Headers"
    assert findings[0].severity == Severity.LOW

    # 7b. Single comma-separated header
    headers_comma = {
        "Access-Control-Allow-Origin": "https://a.example.com, https://b.example.com",
    }
    context_comma = make_context("https://example.com/", headers_comma)
    findings_comma = await CorsSecurityCheck().run(context_comma)

    assert len(findings_comma) == 1
    assert findings_comma[0].title == "Multiple Origins in CORS Access-Control-Allow-Origin Header"
    assert findings_comma[0].severity == Severity.LOW


@pytest.mark.asyncio
async def test_cors_case_insensitive_handling():
    """8. Header names and directives are handled case-insensitively."""
    headers = {
        "access-control-allow-origin": "*",
        "ACCESS-CONTROL-ALLOW-CREDENTIALS": "TRUE",
    }
    context = make_context("https://example.com/", headers)
    findings = await CorsSecurityCheck().run(context)

    assert len(findings) == 1
    assert findings[0].title == "Conflicting CORS Wildcard Origin With Credentials Allowed"


@pytest.mark.asyncio
async def test_cors_explicit_origin_vary_handling():
    """9. Explicit allowed origin checks presence of Vary: Origin."""
    # 9a. With Vary: Origin present
    headers_with_vary = {
        "Access-Control-Allow-Origin": "https://app.example.com",
        "Vary": "Accept-Encoding, Origin",
    }
    context_with_vary = make_context("https://example.com/", headers_with_vary)
    findings_with_vary = await CorsSecurityCheck().run(context_with_vary)
    vary_findings = [f for f in findings_with_vary if "Vary: Origin" in f.title]
    assert len(vary_findings) == 0

    # 9b. Missing Vary: Origin
    headers_without_vary = {
        "Access-Control-Allow-Origin": "https://app.example.com",
        "Vary": "Accept-Encoding",
    }
    context_without_vary = make_context("https://example.com/", headers_without_vary)
    findings_without_vary = await CorsSecurityCheck().run(context_without_vary)
    vary_findings = [f for f in findings_without_vary if "Vary: Origin" in f.title]
    assert len(vary_findings) == 1
    assert vary_findings[0].severity == Severity.LOW
    assert "caches" in vary_findings[0].evidence

    # 9c. No Vary header at all
    headers_no_vary = {"Access-Control-Allow-Origin": "https://app.example.com"}
    context_no_vary = make_context("https://example.com/", headers_no_vary)
    findings_no_vary = await CorsSecurityCheck().run(context_no_vary)
    vary_findings = [f for f in findings_no_vary if "Vary: Origin" in f.title]
    assert len(vary_findings) == 1


@pytest.mark.asyncio
async def test_cors_baseline_failure_does_not_create_false_findings():
    """10. Baseline network failure bubbles up without generating false CORS findings."""

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("Timeout connecting to server")

    transport = httpx.MockTransport(handler)
    scope = TargetScope(allowed_hosts={"example.com"})
    policy = ScopePolicy(scope, dns_resolver=lambda _: ["93.184.216.34"])

    async with ScannerHttpClient(scope_policy=policy, transport=transport) as client:
        context = ScanContext(target_url="https://example.com/", scope=scope, client=client)
        check = CorsSecurityCheck()

        with pytest.raises(ScannerTimeoutError):
            await check.run(context)


@pytest.mark.asyncio
async def test_cors_engine_registration_and_execution_once():
    """11. CorsSecurityCheck is registered in default_registry and executes once in engine."""
    assert "cors_security" in default_registry
    registered_check = default_registry.get("cors_security")
    assert isinstance(registered_check, CorsSecurityCheck)
    assert registered_check.check_id == "cors_security"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Access-Control-Allow-Origin": "*"},
            text="OK",
        )

    transport = httpx.MockTransport(handler)
    scope = TargetScope(allowed_hosts={"example.com"})
    config = ScanConfig(target_url="https://example.com/")

    engine = ScannerEngine()
    result = await engine.run_scan(config, scope=scope, transport=transport)

    assert result.status == ScanStatus.COMPLETED
    assert "cors_security" in result.executed_checks
    assert result.executed_checks.count("cors_security") == 1

    cors_findings = [f for f in result.findings if f.check_id == "cors_security"]
    assert len(cors_findings) == 1
    assert cors_findings[0].title == "Permissive CORS Wildcard Origin Allowed"


@pytest.mark.asyncio
async def test_cors_baseline_sharing_single_request():
    """12. CorsSecurityCheck shares baseline without issuing extra network requests."""
    request_count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal request_count
        request_count += 1
        return httpx.Response(
            200,
            headers={"Access-Control-Allow-Origin": "*"},
            text="OK",
        )

    transport = httpx.MockTransport(handler)
    scope = TargetScope(allowed_hosts={"example.com"})
    policy = ScopePolicy(scope, dns_resolver=lambda _: ["93.184.216.34"])

    async with ScannerHttpClient(scope_policy=policy, transport=transport) as client:
        context = ScanContext(target_url="https://example.com/", scope=scope, client=client)
        check = CorsSecurityCheck()

        findings1 = await check.run(context)
        assert len(findings1) == 1
        assert request_count == 1
        assert client.request_count == 1

        # Second call reuses cached baseline response (0 additional requests)
        findings2 = await check.run(context)
        assert len(findings2) == 1
        assert request_count == 1
        assert client.request_count == 1


@pytest.mark.asyncio
async def test_cors_secret_markers_never_leaked():
    """13. Secret markers in cookies or auth headers are never leaked in findings or repr."""
    secret_token = "SECRET_CORS_BEARER_TOKEN_XYZ987"
    raw_headers = {
        "Access-Control-Allow-Origin": "*",
        "Set-Cookie": f"session_id={secret_token}; Path=/; Secure; HttpOnly",
        "Authorization": f"Bearer {secret_token}",
    }
    context = make_context("https://example.com/", raw_headers)
    findings = await CorsSecurityCheck().run(context)

    assert len(findings) > 0
    for finding in findings:
        serialized = finding.model_dump_json()
        finding_repr = repr(finding)
        finding_str = str(finding)
        extra_str = json.dumps(finding.extra_data)

        assert secret_token not in finding.title
        assert secret_token not in finding.evidence
        assert secret_token not in finding.recommendation
        assert secret_token not in extra_str
        assert secret_token not in serialized
        assert secret_token not in finding_repr
        assert secret_token not in finding_str


@pytest.mark.asyncio
async def test_cors_no_duplicate_findings_for_single_issue():
    """14. Conflicting wildcard+credentials does not produce duplicate wildcard findings."""
    headers = {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": "true",
    }
    context = make_context("https://example.com/", headers)
    findings = await CorsSecurityCheck().run(context)

    # Exactly 1 finding: Conflicting CORS Wildcard Origin With Credentials Allowed
    assert len(findings) == 1
    assert findings[0].title == "Conflicting CORS Wildcard Origin With Credentials Allowed"


@pytest.mark.asyncio
async def test_cors_insecure_http_origin_on_https_endpoint():
    """15. Cleartext HTTP allowed origin on HTTPS endpoint is flagged as Low severity."""
    headers = {
        "Access-Control-Allow-Origin": "http://api.example.com",
        "Vary": "Origin",
    }
    context = make_context("https://example.com/", headers)
    findings = await CorsSecurityCheck().run(context)

    http_findings = [
        f for f in findings if "CORS Configured With Insecure HTTP Allowed Origin" in f.title
    ]
    assert len(http_findings) == 1
    assert http_findings[0].severity == Severity.LOW
    assert "unencrypted HTTP" in http_findings[0].evidence

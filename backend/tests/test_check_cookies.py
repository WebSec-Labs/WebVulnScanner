"""Unit tests for CookieSecurityCheck and secret value protection."""

import json

import httpx
import pytest

from app.scanner.check import ScanContext
from app.scanner.checks.cookies import CookieSecurityCheck
from app.scanner.client import ScannerHttpClient, ScannerTimeoutError
from app.scanner.models import Severity
from app.scanner.scope import ScopePolicy, TargetScope


def make_context(
    url: str,
    raw_cookies: list[str] | None = None,
    status_code: int = 200,
) -> ScanContext:
    """Helper creating ScanContext with mock HTTP transport returning Set-Cookie headers."""
    header_list: list[tuple[str, str]] = []
    if raw_cookies:
        for c in raw_cookies:
            header_list.append(("set-cookie", c))

    headers = httpx.Headers(header_list)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code, headers=headers, text="OK")

    transport = httpx.MockTransport(handler)
    scope = TargetScope(allowed_hosts={"example.com"})
    policy = ScopePolicy(scope, dns_resolver=lambda _: ["93.184.216.34"])
    client = ScannerHttpClient(scope_policy=policy, transport=transport)
    return ScanContext(target_url=url, scope=scope, client=client)


@pytest.mark.asyncio
async def test_cookie_properly_configured():
    """1. Properly configured cookie with Secure, HttpOnly, and SameSite produces 0 findings."""
    raw = ["session_id=SECRET123; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=3600"]
    context = make_context("https://example.com/", raw)
    check = CookieSecurityCheck()

    findings = await check.run(context)
    assert len(findings) == 0


@pytest.mark.asyncio
async def test_cookie_multiple_headers_and_expires_comma():
    """2 & 3. Multiple Set-Cookie headers with commas in Expires are parsed cleanly."""
    raw = [
        "cookie_a=VAL1; Path=/; Secure; HttpOnly; SameSite=Lax",
        (
            "cookie_b=VAL2; Expires=Wed, 21 Oct 2026 07:28:00 GMT; "
            "Path=/; Secure; HttpOnly; SameSite=Strict"
        ),
    ]
    context = make_context("https://example.com/", raw)
    check = CookieSecurityCheck()

    findings = await check.run(context)
    assert len(findings) == 0


@pytest.mark.asyncio
async def test_cookie_missing_secure_on_https():
    """4. Cookie missing Secure flag on HTTPS produces a finding."""
    raw = ["pref=dark; Path=/; HttpOnly; SameSite=Lax"]
    context = make_context("https://example.com/", raw)
    findings = await CookieSecurityCheck().run(context)

    secure_findings = [f for f in findings if "Missing Secure Attribute" in f.title]
    assert len(secure_findings) == 1
    assert secure_findings[0].severity == Severity.LOW
    assert "Secure" in secure_findings[0].evidence


@pytest.mark.asyncio
async def test_cookie_missing_httponly_session_cookie():
    """5. Missing HttpOnly on plausibly session-related cookie emits Medium severity."""
    raw = ["auth_token=JWT_PAYLOAD; Path=/; Secure; SameSite=Strict"]
    context = make_context("https://example.com/", raw)
    findings = await CookieSecurityCheck().run(context)

    http_findings = [f for f in findings if "Missing HttpOnly Attribute" in f.title]
    assert len(http_findings) == 1
    assert http_findings[0].severity == Severity.MEDIUM
    assert "session or auth" in http_findings[0].evidence


@pytest.mark.asyncio
async def test_cookie_missing_httponly_ordinary_cookie():
    """6. Missing HttpOnly on an ordinary cookie emits Low severity."""
    raw = ["theme=light; Path=/; Secure; SameSite=Lax"]
    context = make_context("https://example.com/", raw)
    findings = await CookieSecurityCheck().run(context)

    http_findings = [f for f in findings if "Missing HttpOnly Attribute" in f.title]
    assert len(http_findings) == 1
    assert http_findings[0].severity == Severity.LOW


@pytest.mark.asyncio
async def test_cookie_missing_samesite():
    """7. Cookie missing SameSite attribute produces a Low severity finding."""
    raw = ["tracker=TR123; Path=/; Secure; HttpOnly"]
    context = make_context("https://example.com/", raw)
    findings = await CookieSecurityCheck().run(context)

    samesite_findings = [f for f in findings if "Missing SameSite Attribute" in f.title]
    assert len(samesite_findings) == 1
    assert samesite_findings[0].severity == Severity.LOW


@pytest.mark.asyncio
async def test_cookie_samesite_none_without_secure():
    """8. SameSite=None without Secure flag produces a Medium severity finding."""
    raw = ["cross_site_id=VAL; Path=/; HttpOnly; SameSite=None"]
    context = make_context("https://example.com/", raw)
    findings = await CookieSecurityCheck().run(context)

    none_findings = [f for f in findings if "SameSite=None Without Secure" in f.title]
    assert len(none_findings) == 1
    assert none_findings[0].severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_cookie_secure_prefix_valid():
    """9. Correct __Secure- prefix cookie produces no prefix finding."""
    raw = ["__Secure-Token=SECRET; Path=/; Secure; HttpOnly; SameSite=Strict"]
    context = make_context("https://example.com/", raw)
    findings = await CookieSecurityCheck().run(context)

    prefix_findings = [f for f in findings if "__Secure-" in f.title]
    assert len(prefix_findings) == 0


@pytest.mark.asyncio
async def test_cookie_secure_prefix_violation():
    """10. __Secure- prefix missing Secure attribute produces a Medium finding."""
    raw = ["__Secure-Token=SECRET; Path=/; HttpOnly; SameSite=Strict"]
    context = make_context("https://example.com/", raw)
    findings = await CookieSecurityCheck().run(context)

    prefix_findings = [f for f in findings if "__Secure-" in f.title]
    assert len(prefix_findings) == 1
    assert prefix_findings[0].severity == Severity.MEDIUM
    assert "lacks required 'Secure'" in prefix_findings[0].evidence


@pytest.mark.asyncio
async def test_cookie_host_prefix_valid():
    """11. Correct __Host- prefix cookie produces no prefix finding."""
    raw = ["__Host-Id=SECRET; Path=/; Secure; HttpOnly; SameSite=Strict"]
    context = make_context("https://example.com/", raw)
    findings = await CookieSecurityCheck().run(context)

    prefix_findings = [f for f in findings if "__Host-" in f.title]
    assert len(prefix_findings) == 0


@pytest.mark.asyncio
async def test_cookie_host_prefix_violations():
    """12. __Host- prefix violations (domain present, wrong path, missing secure)."""
    raw = ["__Host-Auth=SECRET; Domain=example.com; Path=/api; HttpOnly; SameSite=Strict"]
    context = make_context("https://example.com/", raw)
    findings = await CookieSecurityCheck().run(context)

    prefix_findings = [f for f in findings if "__Host-" in f.title]
    assert len(prefix_findings) == 1
    assert prefix_findings[0].severity == Severity.MEDIUM
    evidence = prefix_findings[0].evidence
    assert "missing 'Secure' attribute" in evidence
    assert "domain attribute is present" in evidence
    assert "path is '/api'" in evidence


@pytest.mark.asyncio
async def test_cookie_prefix_case_sensitivity():
    """13. Lowercase lookalikes (__host-, __secure-) do not activate prefix enforcement."""
    raw = ["__host-custom=VAL; Domain=example.com; Path=/app; SameSite=Lax"]
    context = make_context("https://example.com/", raw)
    findings = await CookieSecurityCheck().run(context)

    # Should NOT trigger '__Host- Prefix Requirements' finding
    prefix_findings = [f for f in findings if "__Host-" in f.title]
    assert len(prefix_findings) == 0


@pytest.mark.asyncio
async def test_cookie_multiple_equals_in_value():
    """14. Values containing multiple equals signs parse without error and drop value."""
    raw = ["b64token=dXNlcj1hZG1pbjtwYXNzPXNlY3JldA==; Path=/; Secure; HttpOnly; SameSite=Strict"]
    context = make_context("https://example.com/", raw)
    findings = await CookieSecurityCheck().run(context)

    assert len(findings) == 0


@pytest.mark.asyncio
async def test_cookie_malformed_headers():
    """15. Malformed headers (empty parts, missing name, syntax errors) do not crash check."""
    raw = [
        "   ",
        "=unnamed; Path=/",
        "; Secure; HttpOnly",
        "Secure; HttpOnly",
        "valid=val; Max-Age=invalid; Secure; HttpOnly; SameSite=Lax",
    ]
    context = make_context("https://example.com/", raw)
    findings = await CookieSecurityCheck().run(context)

    # Only 'valid' cookie was parsed
    cookie_names = [f.extra_data.get("cookie_name") for f in findings]
    for c in cookie_names:
        assert c == "valid"


@pytest.mark.asyncio
async def test_cookie_empty_or_absent_headers():
    """16. Absent or empty Set-Cookie headers produce zero findings."""
    context = make_context("https://example.com/", None)
    findings = await CookieSecurityCheck().run(context)
    assert len(findings) == 0


@pytest.mark.asyncio
async def test_cookie_secret_markers_never_retained_or_exposed():
    """17. Secret markers in cookie values never appear anywhere in findings or extra_data."""
    secret_marker_1 = "SUPER_SECRET_TOKEN_ALPHA_9999"
    secret_marker_2 = "CONFIDENTIAL_PASSWORD_HASH_ZZZZ"
    secret_marker_3 = "TOP_SECRET_SESSION_KEY_0000"

    raw = [
        f"session_id={secret_marker_1}; Path=/",
        f"user_auth={secret_marker_2}; Domain=example.com",
        f"__Secure-Admin={secret_marker_3}; Path=/admin",
    ]
    context = make_context("https://example.com/", raw)
    findings = await CookieSecurityCheck().run(context)

    assert len(findings) > 0

    all_secrets = [secret_marker_1, secret_marker_2, secret_marker_3]

    for finding in findings:
        serialized_json = finding.model_dump_json()
        finding_repr = repr(finding)
        finding_str = str(finding)
        extra_str = json.dumps(finding.extra_data)

        for secret in all_secrets:
            # Secret marker must NEVER appear in any finding field or representation
            assert secret not in finding.title
            assert secret not in finding.evidence
            assert secret not in finding.recommendation
            assert secret not in extra_str
            assert secret not in serialized_json
            assert secret not in finding_repr
            assert secret not in finding_str


@pytest.mark.asyncio
async def test_cookie_baseline_sharing_single_request():
    """18. CookieSecurityCheck shares baseline without issuing extra network requests."""
    request_count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal request_count
        request_count += 1
        return httpx.Response(
            200,
            headers={"set-cookie": "pref=dark; Path=/; Secure; HttpOnly; SameSite=Lax"},
            text="OK",
        )

    transport = httpx.MockTransport(handler)
    scope = TargetScope(allowed_hosts={"example.com"})
    policy = ScopePolicy(scope, dns_resolver=lambda _: ["93.184.216.34"])

    async with ScannerHttpClient(scope_policy=policy, transport=transport) as client:
        context = ScanContext(target_url="https://example.com/", scope=scope, client=client)
        check = CookieSecurityCheck()

        # Run check
        findings = await check.run(context)
        assert len(findings) == 0
        assert request_count == 1
        assert client.request_count == 1

        # Running again reuses cached baseline response (0 additional requests)
        findings2 = await check.run(context)
        assert len(findings2) == 0
        assert request_count == 1
        assert client.request_count == 1


@pytest.mark.asyncio
async def test_cookie_baseline_failure_does_not_create_false_findings():
    """19. Baseline network failure bubbles up without generating false cookie findings."""

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("Timeout connecting to server")

    transport = httpx.MockTransport(handler)
    scope = TargetScope(allowed_hosts={"example.com"})
    policy = ScopePolicy(scope, dns_resolver=lambda _: ["93.184.216.34"])

    async with ScannerHttpClient(scope_policy=policy, transport=transport) as client:
        context = ScanContext(target_url="https://example.com/", scope=scope, client=client)
        check = CookieSecurityCheck()

        with pytest.raises(ScannerTimeoutError):
            await check.run(context)


@pytest.mark.asyncio
async def test_cookie_cleartext_http_handling():
    """20. Cookies served over HTTP indicate cleartext transport limitation."""
    raw = ["pref=dark; Path=/; HttpOnly; SameSite=Lax"]
    context = make_context("http://example.com/", raw)
    findings = await CookieSecurityCheck().run(context)

    http_findings = [f for f in findings if "Insecure HTTP Connection" in f.title]
    assert len(http_findings) == 1
    assert http_findings[0].severity == Severity.LOW
    assert "unencrypted HTTP" in http_findings[0].evidence


@pytest.mark.asyncio
async def test_cookie_session_heuristic_short_keyword_false_positives():
    """21. Ordinary words ending in 'id' (grid, solid, liquid, hybrid) are not marked session."""
    false_positive_names = ["grid", "solid", "liquid", "hybrid", "GRID", "Hybrid"]
    for name in false_positive_names:
        raw = [f"{name}=VAL123; Path=/; Secure; SameSite=Lax"]
        context = make_context("https://example.com/", raw)
        findings = await CookieSecurityCheck().run(context)

        # Missing HttpOnly should be LOW severity, not MEDIUM
        http_findings = [f for f in findings if "Missing HttpOnly Attribute" in f.title]
        assert len(http_findings) == 1, f"Expected 1 HttpOnly finding for {name}"
        assert http_findings[0].severity == Severity.LOW, (
            f"Expected LOW severity for {name}, got {http_findings[0].severity}"
        )
        assert "session or auth" not in http_findings[0].evidence


@pytest.mark.asyncio
async def test_cookie_session_heuristic_legitimate_session_names():
    """22. Legitimate session cookie names receive elevated MEDIUM severity for missing HttpOnly."""
    session_names = [
        "id",
        "sid",
        "user_id",
        "session_id",
        "account-id",
        "client.id",
        "USER_ID",
        "auth_token",
        "PHPSESSID",
        "JSESSIONID",
        "connect.sid",
    ]
    for name in session_names:
        raw = [f"{name}=VAL123; Path=/; Secure; SameSite=Lax"]
        context = make_context("https://example.com/", raw)
        findings = await CookieSecurityCheck().run(context)

        http_findings = [f for f in findings if "Missing HttpOnly Attribute" in f.title]
        assert len(http_findings) == 1, f"Expected 1 HttpOnly finding for {name}"
        assert http_findings[0].severity == Severity.MEDIUM, (
            f"Expected MEDIUM severity for {name}, got {http_findings[0].severity}"
        )
        assert "session or auth" in http_findings[0].evidence


@pytest.mark.asyncio
async def test_cookie_secure_prefix_served_over_http():
    """23. Attributed __Secure- cookie served over cleartext HTTP reports transport limitation."""
    raw = ["__Secure-Token=SECRET; Path=/; Secure; HttpOnly; SameSite=Strict"]
    context = make_context("http://example.com/", raw)
    findings = await CookieSecurityCheck().run(context)

    # Must report Secure Prefix Ineffective Over Cleartext HTTP
    prefix_findings = [f for f in findings if "Secure Prefix Ineffective" in f.title]
    assert len(prefix_findings) == 1
    f = prefix_findings[0]
    assert f.severity == Severity.MEDIUM
    assert "RFC 6265bis" in f.evidence
    assert "secure origin" in f.evidence
    assert "unencrypted HTTP" in f.evidence
    assert "reject this cookie" in f.evidence
    # Ensure no claim that browser accepted or stored it
    assert "stored" not in f.evidence.lower()
    assert "accepted" not in f.evidence.lower()

    # Ensure no duplicated finding for the same underlying issue
    assert len([x for x in findings if "Insecure HTTP Connection" in x.title]) == 0
    assert len([x for x in findings if "Missing Secure" in x.title]) == 0


@pytest.mark.asyncio
async def test_cookie_host_prefix_served_over_http():
    """24. Attributed __Host- cookie served over cleartext HTTP reports transport limitation."""
    raw = ["__Host-Token=SECRET; Path=/; Secure; HttpOnly; SameSite=Strict"]
    context = make_context("http://example.com/", raw)
    findings = await CookieSecurityCheck().run(context)

    # Must report Host Prefix Ineffective Over Cleartext HTTP
    prefix_findings = [f for f in findings if "Host Prefix Ineffective" in f.title]
    assert len(prefix_findings) == 1
    f = prefix_findings[0]
    assert f.severity == Severity.MEDIUM
    assert "RFC 6265bis" in f.evidence
    assert "secure origin" in f.evidence
    assert "unencrypted HTTP" in f.evidence
    assert "reject this cookie" in f.evidence
    # Ensure no claim that browser accepted or stored it
    assert "stored" not in f.evidence.lower()
    assert "accepted" not in f.evidence.lower()

    # Ensure no duplicate finding
    assert len([x for x in findings if "Insecure HTTP Connection" in x.title]) == 0
    assert len([x for x in findings if "Missing Secure" in x.title]) == 0


@pytest.mark.asyncio
async def test_cookie_ordinary_http_cookie_regression():
    """25. Ordinary cookies on HTTP report Insecure HTTP Connection without prefix findings."""
    raw = [
        "ordinary_cookie=VALUE; Path=/; HttpOnly; SameSite=Lax",
        "another_with_secure=VALUE2; Path=/; Secure; HttpOnly; SameSite=Lax",
    ]
    context = make_context("http://example.com/", raw)
    findings = await CookieSecurityCheck().run(context)

    # ordinary_cookie without Secure gets 'Insecure HTTP Connection' (LOW)
    http_findings = [f for f in findings if "Insecure HTTP Connection" in f.title]
    assert len(http_findings) == 1
    assert http_findings[0].severity == Severity.LOW
    assert http_findings[0].extra_data.get("cookie_name") == "ordinary_cookie"

    # another_with_secure has Secure, so no Insecure HTTP Connection finding
    # and neither should generate any prefix findings
    prefix_findings = [f for f in findings if "Prefix" in f.title]
    assert len(prefix_findings) == 0

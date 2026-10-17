"""Unit tests for shared check utilities and value-free cookie parsing."""

from dataclasses import asdict

import httpx

from app.scanner.checks.utils import (
    ParsedCookie,
    get_first_header,
    get_header_list,
    parse_csp_directives,
    parse_directives,
    parse_set_cookie,
    parse_set_cookie_headers,
    split_comma_header,
)

# ============================================================================
# Cookie Parsing Tests
# ============================================================================


def test_parse_cookie_ordinary():
    """Verify parsing an ordinary cookie with standard flags."""
    raw = "session_id=s3cr3t123; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=3600"
    cookie = parse_set_cookie(raw)

    assert isinstance(cookie, ParsedCookie)
    assert cookie.name == "session_id"
    assert cookie.secure is True
    assert cookie.httponly is True
    assert cookie.samesite == "Lax"
    assert cookie.path == "/"
    assert cookie.domain is None
    assert cookie.max_age == 3600
    assert cookie.has_expires is False
    assert cookie.is_host_prefix is False
    assert cookie.is_secure_prefix is False


def test_parse_cookie_multiple_equals_in_value():
    """Verify that values containing '=' are parsed without truncation and value is dropped."""
    raw = "token=eyJhbGciOiJIUzI1NiJ9==; Path=/api; Secure"
    cookie = parse_set_cookie(raw)

    assert cookie is not None
    assert cookie.name == "token"
    assert cookie.secure is True
    assert cookie.httponly is False
    assert cookie.path == "/api"
    # Ensure value is NOT present anywhere on the parsed object
    assert "eyJ" not in repr(cookie)
    assert not hasattr(cookie, "value")


def test_parse_cookie_unusual_attribute_ordering():
    """Verify parsing when flags appear before or interspersed with path/domain."""
    raw = "auth_tok=val99; HttpOnly; Domain=example.com; Secure; Path=/auth; SameSite=Strict"
    cookie = parse_set_cookie(raw)

    assert cookie is not None
    assert cookie.name == "auth_tok"
    assert cookie.secure is True
    assert cookie.httponly is True
    assert cookie.domain == "example.com"
    assert cookie.path == "/auth"
    assert cookie.samesite == "Strict"


def test_parse_cookie_case_insensitive_flags():
    """Verify that flag attributes are matched case-insensitively."""
    raw = "pref=dark; sEcUrE; hTtPoNlY; sAmEsItE=sTrIcT; mAx-AgE=7200"
    cookie = parse_set_cookie(raw)

    assert cookie is not None
    assert cookie.name == "pref"
    assert cookie.secure is True
    assert cookie.httponly is True
    assert cookie.samesite == "Strict"
    assert cookie.max_age == 7200


def test_parse_cookie_samesite_variants():
    """Verify SameSite handling: Strict, Lax, None, unknown, and omitted."""
    c_none = parse_set_cookie("c1=v; SameSite=None; Secure")
    assert c_none is not None
    assert c_none.samesite == "None"

    c_lax = parse_set_cookie("c2=v; samesite=lax")
    assert c_lax is not None
    assert c_lax.samesite == "Lax"

    c_strict = parse_set_cookie("c3=v; SAMESITE=STRICT")
    assert c_strict is not None
    assert c_strict.samesite == "Strict"

    c_custom = parse_set_cookie("c4=v; SameSite=CustomValue")
    assert c_custom is not None
    assert c_custom.samesite == "CustomValue"

    c_empty_samesite = parse_set_cookie("c5=v; SameSite=")
    assert c_empty_samesite is not None
    assert c_empty_samesite.samesite is None

    c_absent = parse_set_cookie("c6=v; Secure")
    assert c_absent is not None
    assert c_absent.samesite is None


def test_parse_cookie_prefix_case_sensitivity():
    """Verify that __Host- and __Secure- prefixes are strictly case-sensitive per spec."""
    host_valid = parse_set_cookie("__Host-Session=xyz; Path=/; Secure")
    assert host_valid is not None
    assert host_valid.name == "__Host-Session"
    assert host_valid.is_host_prefix is True
    assert host_valid.is_secure_prefix is False

    host_invalid_case = parse_set_cookie("__host-session=xyz; Path=/; Secure")
    assert host_invalid_case is not None
    assert host_invalid_case.name == "__host-session"
    assert host_invalid_case.is_host_prefix is False

    sec_valid = parse_set_cookie("__Secure-Token=xyz; Secure")
    assert sec_valid is not None
    assert sec_valid.name == "__Secure-Token"
    assert sec_valid.is_secure_prefix is True

    sec_invalid_case = parse_set_cookie("__secure-token=xyz; Secure")
    assert sec_invalid_case is not None
    assert sec_invalid_case.name == "__secure-token"
    assert sec_invalid_case.is_secure_prefix is False


def test_parse_cookie_malformed_and_edge_cases():
    """Verify safe conservative handling of malformed and empty inputs without raising."""
    assert parse_set_cookie(None) is None
    assert parse_set_cookie("") is None
    assert parse_set_cookie("   ") is None
    assert parse_set_cookie(";;;") is None

    # Missing name (starts with '=')
    assert parse_set_cookie("=supersecret; Secure") is None

    # Header starting directly with attributes (missing cookie pair)
    assert parse_set_cookie("; Secure; HttpOnly") is None
    assert parse_set_cookie("Secure; HttpOnly") is None

    # Malformed Max-Age non-integer
    cookie_bad_max = parse_set_cookie("foo=bar; Max-Age=notanumber; Secure")
    assert cookie_bad_max is not None
    assert cookie_bad_max.name == "foo"
    assert cookie_bad_max.max_age is None
    assert cookie_bad_max.secure is True

    # Unknown custom attribute stored in extra_attributes
    cookie_extra = parse_set_cookie("foo=bar; CustomFlag; Version=1")
    assert cookie_extra is not None
    assert "customflag" in cookie_extra.extra_attributes
    assert cookie_extra.extra_attributes["version"] == "1"


def test_parse_cookie_value_never_retained_or_exposed():
    """Prove that sensitive secrets in cookie values are never retained in any representation."""
    secret_value = "SUPER_SECRET_BEARER_TOKEN_987654321_XXX"
    raw = f"session={secret_value}; Path=/; Secure; HttpOnly; SameSite=Strict"

    cookie = parse_set_cookie(raw)
    assert cookie is not None

    # 1. Parsed object has no value attribute
    assert not hasattr(cookie, "value")

    # 2. String and Repr representations never contain the secret
    assert secret_value not in repr(cookie)
    assert secret_value not in str(cookie)

    # 3. asdict serialization never contains the secret
    cookie_dict = asdict(cookie)
    assert secret_value not in str(cookie_dict)
    assert "value" not in cookie_dict

    # 4. extra_attributes never contains the secret
    assert secret_value not in str(cookie.extra_attributes)


def test_parse_multiple_cookies_with_expires_comma():
    """Verify parsing multiple Set-Cookie headers when Expires contains a comma."""
    headers = httpx.Headers(
        [
            ("set-cookie", "pref=light; Path=/"),
            (
                "set-cookie",
                "session=abc12345; Expires=Wed, 21 Oct 2025 07:28:00 GMT; Path=/; Secure; HttpOnly",
            ),
            ("set-cookie", "tracker=tr_999; SameSite=Lax"),
        ]
    )

    cookies = parse_set_cookie_headers(headers)
    assert len(cookies) == 3

    assert cookies[0].name == "pref"
    assert cookies[0].path == "/"
    assert cookies[0].secure is False

    assert cookies[1].name == "session"
    assert cookies[1].has_expires is True
    assert cookies[1].secure is True
    assert cookies[1].httponly is True
    assert "abc12345" not in repr(cookies[1])

    assert cookies[2].name == "tracker"
    assert cookies[2].samesite == "Lax"


# ============================================================================
# Shared Header Helpers Tests
# ============================================================================


def test_split_comma_header_standard():
    """Verify splitting standard comma-separated header lists."""
    assert split_comma_header("GET, POST, OPTIONS") == ["GET", "POST", "OPTIONS"]
    assert split_comma_header("DENY, SAMEORIGIN") == ["DENY", "SAMEORIGIN"]


def test_split_comma_header_respects_quotes():
    """Verify that commas inside double or single quotes are not split."""
    val = 'camera=(), microphone=("https://a.example.com, https://b.example.com"), geolocation=*'
    tokens = split_comma_header(val)

    assert len(tokens) == 3
    assert tokens[0] == "camera=()"
    assert tokens[1] == 'microphone=("https://a.example.com, https://b.example.com")'
    assert tokens[2] == "geolocation=*"


def test_split_comma_header_edge_cases():
    """Verify conservative behavior for empty, repeated commas, and unclosed quotes."""
    assert split_comma_header(None) == []
    assert split_comma_header("") == []
    assert split_comma_header("   ") == []
    assert split_comma_header("a,,,b,  ,c") == ["a", "b", "c"]

    # Unclosed quote does not crash
    assert split_comma_header('a, "unclosed quote, b') == ["a", '"unclosed quote, b']


def test_parse_directives_hsts():
    """Verify parsing Strict-Transport-Security directives."""
    raw = "max-age=31536000; includeSubDomains; preload"
    directives = parse_directives(raw)

    assert directives == {
        "max-age": "31536000",
        "includesubdomains": None,
        "preload": None,
    }


def test_parse_directives_edge_cases():
    """Verify directives parsing with irregular whitespace and delimiters."""
    assert parse_directives(None) == {}
    assert parse_directives("") == {}
    assert parse_directives(";; ; ;") == {}
    assert parse_directives("k1=v1=extra; k2; =noval") == {"k1": "v1=extra", "k2": None}


def test_parse_csp_directives():
    """Verify parsing Content-Security-Policy directives."""
    csp = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.example.com; "
        "object-src 'none'; "
        "frame-ancestors 'none'"
    )
    directives = parse_csp_directives(csp)

    assert len(directives) == 4
    assert directives["default-src"] == ["'self'"]
    assert directives["script-src"] == [
        "'self'",
        "'unsafe-inline'",
        "https://cdn.example.com",
    ]
    assert directives["object-src"] == ["'none'"]
    assert directives["frame-ancestors"] == ["'none'"]


def test_parse_csp_directives_first_occurrence_precedence():
    """Verify that subsequent occurrences of the same directive are ignored per CSP spec."""
    csp = "script-src 'self'; script-src 'unsafe-eval' *; default-src 'none'"
    directives = parse_csp_directives(csp)

    assert directives["script-src"] == ["'self'"]
    assert directives["default-src"] == ["'none'"]


def test_parse_csp_directives_empty_and_trailing():
    """Verify handling of empty strings and trailing semicolons."""
    assert parse_csp_directives(None) == {}
    assert parse_csp_directives("") == {}
    assert parse_csp_directives(" ; ;; ") == {}

    directives = parse_csp_directives("default-src 'self'; ; ;")
    assert directives == {"default-src": ["'self'"]}


def test_get_first_header_case_insensitive():
    """Verify case-insensitive retrieval of single header value."""
    headers = httpx.Headers({"Content-Security-Policy": "default-src 'self'"})

    assert get_first_header(headers, "content-security-policy") == "default-src 'self'"
    assert get_first_header(headers, "CONTENT-SECURITY-POLICY") == "default-src 'self'"
    assert get_first_header(headers, "Non-Existent-Header") is None


def test_get_header_list_split_and_raw():
    """Verify retrieving header lists with and without comma splitting."""
    headers = httpx.Headers(
        [
            ("access-control-allow-methods", "GET, POST"),
            ("access-control-allow-methods", "OPTIONS, HEAD"),
        ]
    )

    split_list = get_header_list(headers, "access-control-allow-methods", split_commas=True)
    assert split_list == ["GET", "POST", "OPTIONS", "HEAD"]

    raw_list = get_header_list(headers, "access-control-allow-methods", split_commas=False)
    assert raw_list == ["GET, POST", "OPTIONS, HEAD"]

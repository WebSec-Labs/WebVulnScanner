"""Shared utilities for passive security checks.

Includes safe cookie parsing without value retention and robust HTTP header
parsing helpers for directive-style and comma-separated headers.
"""

from dataclasses import dataclass, field

import httpx


@dataclass(frozen=True, slots=True)
class ParsedCookie:
    """Safe, typed representation of a parsed Set-Cookie header.

    SECURITY INVARIANT:
    This data structure NEVER stores, retains, or exposes the cookie's value.
    The value is discarded immediately during parsing to prevent secrets from
    appearing in memory, logs, reports, or findings.
    """

    name: str
    secure: bool = False
    httponly: bool = False
    samesite: str | None = None
    domain: str | None = None
    path: str | None = None
    max_age: int | None = None
    has_expires: bool = False
    extra_attributes: dict[str, str | None] = field(default_factory=dict)

    @property
    def is_host_prefix(self) -> bool:
        """Return True if cookie name starts with exact '__Host-' prefix."""
        return self.name.startswith("__Host-")

    @property
    def is_secure_prefix(self) -> bool:
        """Return True if cookie name starts with exact '__Secure-' prefix."""
        return self.name.startswith("__Secure-")


_KNOWN_COOKIE_ATTRIBUTES = {
    "secure",
    "httponly",
    "samesite",
    "domain",
    "path",
    "max-age",
    "expires",
}


def parse_set_cookie(header_value: str | None) -> ParsedCookie | None:
    """Safely parse a single Set-Cookie header without retaining its value.

    Guarantees:
    - Never retains the cookie value in the returned ParsedCookie object.
    - Treats attribute names case-insensitively while preserving cookie name case.
    - Preserves case sensitivity for standards-defined prefixes (__Host-, __Secure-).
    - Safely handles malformed and incomplete inputs without raising exceptions.
    - Does not split cookie values containing '='.
    """
    if not header_value or not isinstance(header_value, str):
        return None

    stripped = header_value.strip()
    if not stripped:
        return None

    try:
        parts = [p.strip() for p in stripped.split(";") if p.strip()]
        if not parts:
            return None

        # First part is the cookie-pair (name=value)
        cookie_pair = parts[0]
        name, sep, _discarded_value = cookie_pair.partition("=")
        # Deliberately remove local reference to value immediately
        del _discarded_value

        cookie_name = name.strip()
        if not cookie_name:
            return None

        # If there was no '=' separator, check if parts[0] is actually an attribute
        if not sep and cookie_name.lower() in _KNOWN_COOKIE_ATTRIBUTES:
            return None

        secure = False
        httponly = False
        samesite: str | None = None
        domain: str | None = None
        path: str | None = None
        max_age: int | None = None
        has_expires = False
        extra_attributes: dict[str, str | None] = {}

        for attr_part in parts[1:]:
            attr_name, attr_sep, attr_val = attr_part.partition("=")
            attr_key = attr_name.strip().lower()
            if not attr_key:
                continue

            attr_val_clean = attr_val.strip() if attr_sep else None

            if attr_key == "secure":
                secure = True
            elif attr_key == "httponly":
                httponly = True
            elif attr_key == "samesite":
                if attr_val_clean:
                    v_lower = attr_val_clean.lower()
                    if v_lower == "strict":
                        samesite = "Strict"
                    elif v_lower == "lax":
                        samesite = "Lax"
                    elif v_lower == "none":
                        samesite = "None"
                    else:
                        samesite = attr_val_clean
                else:
                    samesite = None
            elif attr_key == "domain":
                domain = attr_val_clean
            elif attr_key == "path":
                path = attr_val_clean
            elif attr_key == "max-age":
                if attr_val_clean is not None:
                    try:
                        max_age = int(attr_val_clean)
                    except (ValueError, TypeError):
                        max_age = None
            elif attr_key == "expires":
                has_expires = True
            else:
                extra_attributes[attr_key] = attr_val_clean

        return ParsedCookie(
            name=cookie_name,
            secure=secure,
            httponly=httponly,
            samesite=samesite,
            domain=domain,
            path=path,
            max_age=max_age,
            has_expires=has_expires,
            extra_attributes=extra_attributes,
        )
    except Exception:
        # Never format or log header_value to avoid leaking secrets
        return None


def parse_set_cookie_headers(headers: httpx.Headers) -> list[ParsedCookie]:
    """Extract and parse all Set-Cookie headers from an httpx.Headers collection.

    Uses get_list('set-cookie', split_commas=False) so commas in Expires dates
    do not erroneously split headers into corrupt fragments.
    """
    raw_cookies = headers.get_list("set-cookie", split_commas=False)
    results: list[ParsedCookie] = []
    for raw in raw_cookies:
        cookie = parse_set_cookie(raw)
        if cookie is not None:
            results.append(cookie)
    return results


def split_comma_header(value: str | None) -> list[str]:
    """Split comma-separated header value into trimmed items, ignoring commas inside quotes.

    Handles absent, empty, and malformed inputs conservatively without raising exceptions.
    """
    if not value or not isinstance(value, str):
        return []

    stripped = value.strip()
    if not stripped:
        return []

    items: list[str] = []
    current: list[str] = []
    in_quote: str | None = None

    for char in stripped:
        if in_quote:
            current.append(char)
            if char == in_quote:
                in_quote = None
        elif char in ('"', "'"):
            in_quote = char
            current.append(char)
        elif char == ",":
            token = "".join(current).strip()
            if token:
                items.append(token)
            current = []
        else:
            current.append(char)

    token = "".join(current).strip()
    if token:
        items.append(token)
    return items


def parse_directives(value: str | None, delimiter: str = ";") -> dict[str, str | None]:
    """Parse delimiter-separated directives into a dictionary of lowercase directive names.

    Example:
        'max-age=31536000; includeSubDomains' -> {'max-age': '31536000', 'includesubdomains': None}
    """
    if not value or not isinstance(value, str):
        return {}

    stripped = value.strip()
    if not stripped:
        return {}

    directives: dict[str, str | None] = {}
    for part in stripped.split(delimiter):
        part = part.strip()
        if not part:
            continue
        key, sep, val = part.partition("=")
        clean_key = key.strip().lower()
        if not clean_key:
            continue
        directives[clean_key] = val.strip() if sep else None

    return directives


def parse_csp_directives(value: str | None) -> dict[str, list[str]]:
    """Parse Content-Security-Policy directives into directive-name -> source-list.

    Directives are separated by semicolons. Inside each directive, the first
    whitespace-separated token is the directive name (lowercased), followed
    by source expressions or parameters.

    Per CSP specification, if a directive occurs multiple times in the same policy,
    the first occurrence takes precedence and subsequent ones are ignored.
    """
    if not value or not isinstance(value, str):
        return {}

    stripped = value.strip()
    if not stripped:
        return {}

    result: dict[str, list[str]] = {}
    for part in stripped.split(";"):
        tokens = part.strip().split()
        if not tokens:
            continue
        directive_name = tokens[0].lower()
        directive_values = tokens[1:]
        if directive_name not in result:
            result[directive_name] = directive_values

    return result


def get_first_header(headers: httpx.Headers, name: str) -> str | None:
    """Retrieve the first non-empty header value case-insensitively, or None."""
    val = headers.get(name)
    if val is not None:
        stripped = val.strip()
        if stripped:
            return stripped
    return None


def get_header_list(
    headers: httpx.Headers,
    name: str,
    split_commas: bool = True,
) -> list[str]:
    """Retrieve all non-empty values for a header, optionally splitting comma-separated items."""
    raw_list = headers.get_list(name, split_commas=False)
    if not split_commas:
        return [item.strip() for item in raw_list if item and item.strip()]

    result: list[str] = []
    for item in raw_list:
        result.extend(split_comma_header(item))
    return result

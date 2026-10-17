"""Cookie security check module.

Evaluates Set-Cookie response headers for defensive security attributes
(Secure, HttpOnly, SameSite) and standard prefix compliance (__Host-, __Secure-)
without retaining or exposing cookie values.
"""

import re

from app.scanner.check import BaseCheck, CheckMetadata, ScanContext
from app.scanner.checks.utils import ParsedCookie, parse_set_cookie_headers
from app.scanner.models import Finding, Severity

# Short keywords that must match full delimited tokens to avoid false positives
# on ordinary words ending in or starting with 'id' or 'sid' (e.g. 'grid', 'solid').
_SHORT_EXACT_KEYWORDS = {"id", "sid"}

_SESSION_COOKIE_KEYWORDS = (
    "session",
    "sess",
    "auth",
    "token",
    "jwt",
    "login",
    "access",
    "phpsessid",
    "jsessionid",
    "aspsessionid",
    "connect.sid",
    "csrftoken",
    "xsrf",
)


def _is_plausibly_session_cookie(name: str) -> bool:
    """Return True if cookie name contains common authentication or session keywords.

    Note: This is an advisory heuristic. The scanner does not claim a cookie is
    a confirmed credential solely based on its name.
    """
    lower = name.lower()
    clean_parts = re.split(r"[-_.]", lower)

    # 1. Exact token match for short keywords (e.g., 'id', 'sid')
    for kw in _SHORT_EXACT_KEYWORDS:
        if kw in clean_parts:
            return True

    # 2. Token or prefix/suffix match for longer descriptive keywords
    for kw in _SESSION_COOKIE_KEYWORDS:
        if kw in clean_parts:
            return True
        if len(kw) > 3 and (lower.startswith(kw) or lower.endswith(kw)):
            return True

    return False


def _safe_cookie_name(name: str, max_len: int = 80) -> str:
    """Sanitize and bound cookie name for display in findings."""
    cleaned = re.sub(r"[\x00-\x1f\x7f-\x9f]", "", name.strip())
    if len(cleaned) > max_len:
        return cleaned[:max_len] + "..."
    return cleaned


class CookieSecurityCheck(BaseCheck):
    """Inspects Set-Cookie headers for secure attribute configuration and prefix compliance."""

    @property
    def metadata(self) -> CheckMetadata:
        return CheckMetadata(
            check_id="cookie_security",
            name="Cookie Security Check",
            description=(
                "Inspects Set-Cookie response headers for missing security flags "
                "(Secure, HttpOnly, SameSite) and standards-defined prefix compliance "
                "without exposing cookie values."
            ),
            severity=Severity.LOW,
        )

    async def run(self, context: ScanContext) -> list[Finding]:
        """Execute cookie security check using the shared baseline response."""
        response = await context.get_baseline_response()
        findings: list[Finding] = []

        # Parse all individual Set-Cookie headers safely without value retention
        cookies = parse_set_cookie_headers(response.headers)
        if not cookies:
            return findings

        is_https = response.url.startswith("https://")

        for cookie in cookies:
            cookie_findings = self._evaluate_cookie(cookie, is_https, response.url)
            findings.extend(cookie_findings)

        return findings

    def _evaluate_cookie(
        self,
        cookie: ParsedCookie,
        is_https: bool,
        response_url: str,
    ) -> list[Finding]:
        """Evaluate a single parsed cookie against security standards."""
        findings: list[Finding] = []
        name = _safe_cookie_name(cookie.name)
        plausibly_session = _is_plausibly_session_cookie(cookie.name)

        safe_attributes = {
            "secure": cookie.secure,
            "httponly": cookie.httponly,
            "samesite": cookie.samesite,
            "domain": cookie.domain,
            "path": cookie.path,
        }

        # 1. Secure Attribute (for standard cookies; prefix cookies report under prefix rules)
        is_prefix_cookie = cookie.is_secure_prefix or cookie.is_host_prefix
        if not is_prefix_cookie:
            if is_https:
                if not cookie.secure:
                    severity = Severity.MEDIUM if plausibly_session else Severity.LOW
                    role_note = (
                        " The cookie name suggests possible session or auth usage, "
                        "though its exact role cannot be confirmed from response alone."
                        if plausibly_session
                        else ""
                    )
                    findings.append(
                        self.create_finding(
                            url=response_url,
                            title=f"Cookie '{name}' Missing Secure Attribute",
                            severity=severity,
                            evidence=(
                                f"Cookie '{name}' was served over HTTPS without "
                                f"'Secure'.{role_note}"
                            ),
                            recommendation=(
                                "Add the 'Secure' attribute so browsers send the cookie "
                                "strictly over encrypted HTTPS connections."
                            ),
                            extra_data={"cookie_name": name, "attributes": safe_attributes},
                        )
                    )
            else:
                if not cookie.secure and not (cookie.is_secure_prefix or cookie.is_host_prefix):
                    findings.append(
                        self.create_finding(
                            url=response_url,
                            title=f"Cookie '{name}' Served Over Insecure HTTP Connection",
                            severity=Severity.LOW,
                            evidence=(
                                f"Cookie '{name}' was set over an unencrypted HTTP response. "
                                "Without HTTPS, the cookie cannot be protected with 'Secure'."
                            ),
                            recommendation=(
                                "Migrate the service to HTTPS and configure the 'Secure' attribute."
                            ),
                            extra_data={"cookie_name": name, "attributes": safe_attributes},
                        )
                    )

        # 2. HttpOnly Attribute
        if not cookie.httponly:
            severity = Severity.MEDIUM if plausibly_session else Severity.LOW
            role_note = (
                " The cookie name suggests possible session or auth usage, "
                "though its exact role cannot be confirmed from response alone."
                if plausibly_session
                else ""
            )
            findings.append(
                self.create_finding(
                    url=response_url,
                    title=f"Cookie '{name}' Missing HttpOnly Attribute",
                    severity=severity,
                    evidence=(
                        f"Cookie '{name}' lacks 'HttpOnly', making it accessible "
                        f"to client scripts via Document.cookie.{role_note}"
                    ),
                    recommendation=(
                        "Add the 'HttpOnly' flag to mitigate XSS-based credential theft "
                        "if client script access is not required."
                    ),
                    extra_data={"cookie_name": name, "attributes": safe_attributes},
                )
            )

        # 3. SameSite Attribute
        if cookie.samesite is None:
            findings.append(
                self.create_finding(
                    url=response_url,
                    title=f"Cookie '{name}' Missing SameSite Attribute",
                    severity=Severity.LOW,
                    evidence=(
                        f"Cookie '{name}' does not specify a 'SameSite' attribute. "
                        "Explicit SameSite configuration is recommended."
                    ),
                    recommendation=(
                        "Set 'SameSite=Lax' or 'SameSite=Strict' to mitigate CSRF "
                        "and unintended cross-origin transmission."
                    ),
                    extra_data={"cookie_name": name, "attributes": safe_attributes},
                )
            )
        elif cookie.samesite.lower() == "none":
            if not cookie.secure:
                findings.append(
                    self.create_finding(
                        url=response_url,
                        title=f"Cookie '{name}' Insecure SameSite=None Without Secure Attribute",
                        severity=Severity.MEDIUM,
                        evidence=(
                            f"Cookie '{name}' specifies 'SameSite=None' without 'Secure'. "
                            "Browsers reject SameSite=None cookies unless Secure is set."
                        ),
                        recommendation=(
                            "Add the 'Secure' flag whenever 'SameSite=None' is used, "
                            "and ensure transport is HTTPS."
                        ),
                        extra_data={"cookie_name": name, "attributes": safe_attributes},
                    )
                )
            elif plausibly_session:
                findings.append(
                    self.create_finding(
                        url=response_url,
                        title=f"Cookie '{name}' Configured With Permissive SameSite=None",
                        severity=Severity.LOW,
                        evidence=(
                            f"Cookie '{name}' uses 'SameSite=None', allowing cross-origin "
                            "requests to include it. The name suggests sensitive state."
                        ),
                        recommendation=(
                            "Review whether 'SameSite=None' is necessary. Prefer 'SameSite=Lax' "
                            "or 'SameSite=Strict' for sensitive cookies."
                        ),
                        extra_data={"cookie_name": name, "attributes": safe_attributes},
                    )
                )

        # 4. Cookie Prefix Rules (RFC 6265bis)
        if cookie.is_secure_prefix:
            if not is_https:
                findings.append(
                    self.create_finding(
                        url=response_url,
                        title=f"Cookie '{name}' Secure Prefix Ineffective Over Cleartext HTTP",
                        severity=Severity.MEDIUM,
                        evidence=(
                            f"Cookie '{name}' uses the '__Secure-' prefix but was transmitted "
                            "over an unencrypted HTTP response. RFC 6265bis requires secure-prefix "
                            "cookies to originate strictly from a secure origin (HTTPS). "
                            "Conforming browsers will reject this cookie, leaving intended "
                            "protections unapplied."
                        ),
                        recommendation=(
                            "Serve the application over HTTPS and transmit secure-prefix cookies "
                            "strictly over encrypted connections."
                        ),
                        extra_data={"cookie_name": name, "attributes": safe_attributes},
                    )
                )
            elif not cookie.secure:
                findings.append(
                    self.create_finding(
                        url=response_url,
                        title=f"Cookie '{name}' Violates __Secure- Prefix Requirements",
                        severity=Severity.MEDIUM,
                        evidence=(
                            f"Cookie '{name}' uses '__Secure-' prefix but lacks required 'Secure'. "
                            "Conforming browsers will reject this cookie."
                        ),
                        recommendation=(
                            "Add the 'Secure' attribute or remove the '__Secure-' prefix."
                        ),
                        extra_data={"cookie_name": name, "attributes": safe_attributes},
                    )
                )

        if cookie.is_host_prefix:
            if not is_https:
                violations = ["transmitted over unencrypted HTTP (requires secure origin HTTPS)"]
                if not cookie.secure:
                    violations.append("missing 'Secure' attribute")
                if cookie.path != "/":
                    violations.append(f"path is '{cookie.path or '<omitted>'}' (must be '/')")
                if cookie.domain is not None:
                    violations.append(
                        f"domain attribute is present ('{cookie.domain}') but must be omitted"
                    )

                findings.append(
                    self.create_finding(
                        url=response_url,
                        title=f"Cookie '{name}' Host Prefix Ineffective Over Cleartext HTTP",
                        severity=Severity.MEDIUM,
                        evidence=(
                            f"Cookie '{name}' uses the '__Host-' prefix but was transmitted "
                            "over an unencrypted HTTP response. RFC 6265bis requires '__Host-' "
                            "cookies to originate strictly from a secure origin (HTTPS). "
                            "Conforming browsers will reject this cookie."
                            + (
                                f" Additional attribute violations: {', '.join(violations[1:])}."
                                if len(violations) > 1
                                else ""
                            )
                        ),
                        recommendation=(
                            "Serve the application over HTTPS and configure the cookie with "
                            "'Secure', 'Path=/', and omit the 'Domain' attribute."
                        ),
                        extra_data={
                            "cookie_name": name,
                            "violations": violations,
                            "attributes": safe_attributes,
                        },
                    )
                )
            else:
                violations = []
                if not cookie.secure:
                    violations.append("missing 'Secure' attribute")
                if cookie.path != "/":
                    violations.append(f"path is '{cookie.path or '<omitted>'}' (must be '/')")
                if cookie.domain is not None:
                    violations.append(
                        f"domain attribute is present ('{cookie.domain}') but must be omitted"
                    )

                if violations:
                    findings.append(
                        self.create_finding(
                            url=response_url,
                            title=f"Cookie '{name}' Violates __Host- Prefix Requirements",
                            severity=Severity.MEDIUM,
                            evidence=(
                                f"Cookie '{name}' uses '__Host-' prefix but violates "
                                f"standard rules: {', '.join(violations)}. "
                                "Conforming browsers reject this cookie."
                            ),
                            recommendation=(
                                "Configure the cookie with 'Secure', 'Path=/', and omit 'Domain'."
                            ),
                            extra_data={
                                "cookie_name": name,
                                "violations": violations,
                                "attributes": safe_attributes,
                            },
                        )
                    )

        return findings

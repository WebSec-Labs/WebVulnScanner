"""Security headers passive check module.

Evaluates presence and configuration of essential HTTP response security headers:
- Content-Security-Policy (CSP)
- Strict-Transport-Security (HSTS)
- X-Content-Type-Options
- Clickjacking protections (CSP frame-ancestors and X-Frame-Options)
- Referrer-Policy
- Permissions-Policy
"""

from app.scanner.check import BaseCheck, CheckMetadata, ScanContext
from app.scanner.checks.utils import (
    get_first_header,
    parse_csp_directives,
    parse_directives,
    split_comma_header,
)
from app.scanner.models import Finding, Severity


class SecurityHeadersCheck(BaseCheck):
    """Evaluates security headers against defensive best practices."""

    @property
    def metadata(self) -> CheckMetadata:
        return CheckMetadata(
            check_id="security_headers",
            name="Security Headers Check",
            description=(
                "Inspects HTTP response headers for missing or insecurely configured "
                "defensive protections including CSP, HSTS, X-Content-Type-Options, "
                "X-Frame-Options, Referrer-Policy, and Permissions-Policy."
            ),
            severity=Severity.LOW,
        )

    async def run(self, context: ScanContext) -> list[Finding]:
        """Execute security headers check using the shared baseline response."""
        response = await context.get_baseline_response()
        findings: list[Finding] = []

        headers = response.headers
        content_type = (get_first_header(headers, "content-type") or "").lower()
        is_html = "text/html" in content_type or "application/xhtml+xml" in content_type

        # 1. Content-Security-Policy (CSP)
        csp_val = get_first_header(headers, "content-security-policy")
        if not csp_val:
            findings.append(
                self.create_finding(
                    url=response.url,
                    title="Missing Content-Security-Policy",
                    severity=Severity.LOW,
                    evidence="The Content-Security-Policy response header is absent.",
                    recommendation=(
                        "Implement a Content-Security-Policy (CSP) header defining authorized "
                        "sources for scripts, styles, frames, and subresources."
                    ),
                )
            )
        else:
            csp_directives = parse_csp_directives(csp_val)

            # Inspect script-src (or default-src fallback) for unsafe keywords
            script_sources = csp_directives.get("script-src", csp_directives.get("default-src", []))
            risky_script_tokens: list[str] = []
            for token in script_sources:
                t_lower = token.strip().lower()
                if t_lower in ("'unsafe-inline'", "'unsafe-eval'"):
                    risky_script_tokens.append(token)

            if risky_script_tokens:
                directive_name = "script-src" if "script-src" in csp_directives else "default-src"
                findings.append(
                    self.create_finding(
                        url=response.url,
                        title="Insecure Content-Security-Policy Directives",
                        severity=Severity.LOW,
                        evidence=(
                            f"CSP directive '{directive_name}' contains risky keywords: "
                            f"{', '.join(risky_script_tokens)}"
                        ),
                        recommendation=(
                            "Remove 'unsafe-inline' and 'unsafe-eval' from CSP script-src "
                            "directives. Use cryptographic nonces, hashes, or refactor code."
                        ),
                    )
                )

            # Inspect object-src
            object_sources = csp_directives.get("object-src")
            if object_sources is not None and any(t == "*" for t in object_sources):
                findings.append(
                    self.create_finding(
                        url=response.url,
                        title="Overly Permissive CSP object-src Directive",
                        severity=Severity.LOW,
                        evidence="CSP directive 'object-src' allows wildcard ('*') plugins.",
                        recommendation=(
                            "Set 'object-src 'none'' in CSP to disable legacy plugin execution."
                        ),
                    )
                )
            elif object_sources is None and "default-src" not in csp_directives:
                findings.append(
                    self.create_finding(
                        url=response.url,
                        title="Missing CSP object-src Directive",
                        severity=Severity.LOW,
                        evidence=(
                            "CSP does not define 'object-src' or 'default-src' to restrict "
                            "plugin execution."
                        ),
                        recommendation=(
                            "Explicitly set 'object-src 'none'' in your Content-Security-Policy."
                        ),
                    )
                )

        # 2. Strict-Transport-Security (HSTS)
        # Evaluated ONLY when the final response was served over HTTPS
        if response.url.startswith("https://"):
            hsts_val = get_first_header(headers, "strict-transport-security")
            if not hsts_val:
                findings.append(
                    self.create_finding(
                        url=response.url,
                        title="Missing Strict-Transport-Security Header",
                        severity=Severity.LOW,
                        evidence="HTTPS response is missing the Strict-Transport-Security header.",
                        recommendation=(
                            "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' "
                            "to enforce encrypted HTTPS connections."
                        ),
                    )
                )
            else:
                hsts_dirs = parse_directives(hsts_val)
                if "max-age" not in hsts_dirs or hsts_dirs["max-age"] is None:
                    findings.append(
                        self.create_finding(
                            url=response.url,
                            title="Malformed Strict-Transport-Security Header",
                            severity=Severity.LOW,
                            evidence=(
                                f"HSTS header '{hsts_val}' is missing the 'max-age' directive."
                            ),
                            recommendation=(
                                "Configure a valid 'max-age' in seconds (e.g. max-age=31536000)."
                            ),
                        )
                    )
                else:
                    try:
                        max_age_int = int(hsts_dirs["max-age"])
                        # Less than 120 days is considered short for production
                        if max_age_int < 10_368_000:
                            findings.append(
                                self.create_finding(
                                    url=response.url,
                                    title="Short Strict-Transport-Security Max-Age",
                                    severity=Severity.INFO,
                                    evidence=(
                                        f"HSTS max-age is {max_age_int}s (< 120 days). "
                                        "A longer duration is recommended for production."
                                    ),
                                    recommendation=(
                                        "Increase HSTS max-age to at least 31536000 seconds (1 yr) "
                                        "once HTTPS deployment is validated."
                                    ),
                                )
                            )
                    except ValueError:
                        findings.append(
                            self.create_finding(
                                url=response.url,
                                title="Malformed Strict-Transport-Security Header",
                                severity=Severity.LOW,
                                evidence=(
                                    f"HSTS max-age '{hsts_dirs['max-age']}' is not a valid integer."
                                ),
                                recommendation=(
                                    "Ensure HSTS 'max-age' directive contains only numeric digits."
                                ),
                            )
                        )

        # 3. X-Content-Type-Options
        xcto_val = get_first_header(headers, "x-content-type-options")
        if not xcto_val or xcto_val.lower() != "nosniff":
            findings.append(
                self.create_finding(
                    url=response.url,
                    title="Missing or Invalid X-Content-Type-Options Header",
                    severity=Severity.LOW,
                    evidence=(
                        f"Observed X-Content-Type-Options: {repr(xcto_val)}. Expected 'nosniff'."
                        if xcto_val
                        else "The X-Content-Type-Options response header is absent."
                    ),
                    recommendation="Set 'X-Content-Type-Options: nosniff' on all HTTP responses.",
                )
            )

        # 4. Clickjacking Protections (HTML responses only)
        if is_html:
            has_csp_frame_ancestors = False
            if csp_val:
                csp_dirs = parse_csp_directives(csp_val)
                if "frame-ancestors" in csp_dirs and csp_dirs["frame-ancestors"]:
                    has_csp_frame_ancestors = True

            xfo_val = get_first_header(headers, "x-frame-options")

            if not has_csp_frame_ancestors:
                if not xfo_val:
                    findings.append(
                        self.create_finding(
                            url=response.url,
                            title="Missing Clickjacking Protections",
                            severity=Severity.LOW,
                            evidence=(
                                f"HTML response ('{content_type}') lacks both CSP "
                                "'frame-ancestors' and 'X-Frame-Options' headers."
                            ),
                            recommendation=(
                                "Protect against clickjacking by setting 'frame-ancestors 'none'' "
                                "(or 'frame-ancestors 'self'') in CSP, or setting "
                                "'X-Frame-Options: DENY'."
                            ),
                        )
                    )
                else:
                    clean_xfo = xfo_val.strip().upper()
                    if clean_xfo not in ("DENY", "SAMEORIGIN"):
                        findings.append(
                            self.create_finding(
                                url=response.url,
                                title="Invalid or Obsolete X-Frame-Options Header",
                                severity=Severity.LOW,
                                evidence=(
                                    f"Observed X-Frame-Options header '{xfo_val}', which is "
                                    "obsolete or unsupported by modern browsers. Modern browsers "
                                    "require 'DENY', 'SAMEORIGIN', or CSP 'frame-ancestors'."
                                ),
                                recommendation=(
                                    "Replace obsolete X-Frame-Options with 'X-Frame-Options: DENY' "
                                    "or use CSP 'frame-ancestors'."
                                ),
                            )
                        )

        # 5. Referrer-Policy
        ref_val = get_first_header(headers, "referrer-policy")
        if not ref_val:
            findings.append(
                self.create_finding(
                    url=response.url,
                    title="Missing Referrer-Policy Header",
                    severity=Severity.INFO,
                    evidence="The Referrer-Policy response header is absent.",
                    recommendation=(
                        "Configure 'Referrer-Policy: strict-origin-when-cross-origin' to protect "
                        "path and query parameters across origins."
                    ),
                )
            )
        else:
            insecure_policies = {"unsafe-url", "no-referrer-when-downgrade"}
            tokens = [t.lower() for t in split_comma_header(ref_val)]
            safe_tokens = {
                "strict-origin-when-cross-origin",
                "no-referrer",
                "same-origin",
                "strict-origin",
            }
            if any(t in insecure_policies for t in tokens) and not any(
                t in safe_tokens for t in tokens
            ):
                findings.append(
                    self.create_finding(
                        url=response.url,
                        title="Weak Referrer-Policy Configuration",
                        severity=Severity.LOW,
                        evidence=(
                            f"Observed weak Referrer-Policy '{ref_val}' which may leak "
                            "sensitive URLs to third parties."
                        ),
                        recommendation=(
                            "Change Referrer-Policy to 'strict-origin-when-cross-origin' "
                            "or 'no-referrer'."
                        ),
                    )
                )

        # 6. Permissions-Policy
        perm_val = get_first_header(headers, "permissions-policy")
        if not perm_val:
            findings.append(
                self.create_finding(
                    url=response.url,
                    title="Missing Permissions-Policy Header",
                    severity=Severity.INFO,
                    evidence="The Permissions-Policy response header is absent.",
                    recommendation=(
                        "Set Permissions-Policy to explicitly control browser features like "
                        "geolocation, camera, microphone, and payment APIs."
                    ),
                )
            )

        return findings

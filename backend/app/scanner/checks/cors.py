"""CORS misconfiguration passive security check module.

Evaluates Access-Control-* response headers for security weaknesses:
- Wildcard origin (*) with or without credentials
- Insecure null origin allowance
- Malformed, duplicate, or multiple allowed origin values
- Insecure cleartext HTTP origin on HTTPS endpoints
- Cache consistency issues (missing Vary: Origin on explicit origins)
without issuing extra network requests or active exploitation.
"""

import re
from urllib.parse import urlsplit

from app.scanner.check import BaseCheck, CheckMetadata, ScanContext
from app.scanner.checks.utils import get_first_header, get_header_list
from app.scanner.models import Finding, Severity


def _safe_origin(val: str, max_len: int = 100) -> str:
    """Sanitize origin string for safe inclusion in findings without secret leakage."""
    cleaned = re.sub(r"[\x00-\x1f\x7f-\x9f]", "", val.strip())
    if len(cleaned) > max_len:
        return cleaned[:max_len] + "..."
    return cleaned


def _is_valid_origin(origin: str) -> bool:
    """Validate whether an origin string conforms to RFC 6454 / Fetch origin syntax."""
    if not origin or " " in origin or "\t" in origin:
        return False

    try:
        parsed = urlsplit(origin)
    except Exception:
        return False

    # Origin must have valid http/https scheme and non-empty netloc
    if parsed.scheme.lower() not in ("http", "https"):
        return False
    if not parsed.netloc or not parsed.hostname:
        return False

    # Hostname must not contain wildcards (e.g. *.example.com is invalid in CORS)
    if "*" in parsed.hostname:
        return False

    # Origin must not contain path, query, fragment, or user credentials
    if parsed.path != "" or parsed.query != "" or parsed.fragment != "":
        return False
    if parsed.username is not None or parsed.password is not None:
        return False

    return True


class CorsSecurityCheck(BaseCheck):
    """Evaluates CORS response headers for defensive security and configuration weaknesses."""

    @property
    def metadata(self) -> CheckMetadata:
        return CheckMetadata(
            check_id="cors_security",
            name="CORS Security Check",
            description=(
                "Inspects Cross-Origin Resource Sharing (CORS) response headers for "
                "insecure wildcard origins, null origin allowance, credential conflicts, "
                "and cache consistency issues."
            ),
            severity=Severity.LOW,
        )

    async def run(self, context: ScanContext) -> list[Finding]:
        """Execute CORS security check using the shared baseline response."""
        response = await context.get_baseline_response()
        findings: list[Finding] = []

        headers = response.headers
        response_url = response.url
        is_https = response_url.startswith("https://")

        # 1. Retrieve all Access-Control-Allow-Origin headers case-insensitively
        raw_acao_list = headers.get_list("access-control-allow-origin", split_commas=False)
        if not raw_acao_list:
            # No CORS origin header present; CORS is not active on this response
            return findings

        # 2. Retrieve credentials flag
        raw_acac = get_first_header(headers, "access-control-allow-credentials")
        allow_credentials = (raw_acac or "").strip().lower() == "true"

        # 3. Check for duplicate ACAO header entries
        if len(raw_acao_list) > 1:
            safe_origins = [_safe_origin(v) for v in raw_acao_list]
            findings.append(
                self.create_finding(
                    url=response_url,
                    title="Duplicate CORS Access-Control-Allow-Origin Headers",
                    severity=Severity.LOW,
                    evidence=(
                        f"The response contains {len(raw_acao_list)} duplicate "
                        f"'Access-Control-Allow-Origin' headers: {', '.join(safe_origins)}. "
                        "Conforming browsers reject CORS responses with multiple ACAO headers."
                    ),
                    recommendation=(
                        "Configure the server to return exactly one 'Access-Control-Allow-Origin' "
                        "header with a single allowed origin or '*'."
                    ),
                    extra_data={"origins": safe_origins},
                )
            )
            return findings

        raw_acao = raw_acao_list[0].strip()

        # 4. Check for comma-separated multiple origins in a single header
        if "," in raw_acao:
            safe_origin = _safe_origin(raw_acao)
            findings.append(
                self.create_finding(
                    url=response_url,
                    title="Multiple Origins in CORS Access-Control-Allow-Origin Header",
                    severity=Severity.LOW,
                    evidence=(
                        f"The 'Access-Control-Allow-Origin' header contains comma-separated values "
                        f"('{safe_origin}'). The CORS specification allows only a single origin "
                        "or '*', not a comma-separated list. Conforming browsers reject this."
                    ),
                    recommendation=(
                        "Return a single allowed origin dynamically based on an allowlist of "
                        "trusted origins, rather than a comma-separated list."
                    ),
                    extra_data={"raw_origin": safe_origin},
                )
            )
            return findings

        safe_origin = _safe_origin(raw_acao)

        # 5. Wildcard Origin (*)
        if raw_acao == "*":
            if allow_credentials:
                findings.append(
                    self.create_finding(
                        url=response_url,
                        title="Conflicting CORS Wildcard Origin With Credentials Allowed",
                        severity=Severity.LOW,
                        evidence=(
                            "The response specifies 'Access-Control-Allow-Origin: *' alongside "
                            "'Access-Control-Allow-Credentials: true'. Under the Fetch standard, "
                            "browsers block credentialed cross-origin requests when the allowed "
                            "origin is '*'. This combination does not grant credentialed access, "
                            "but represents an invalid or conflicting CORS configuration."
                        ),
                        recommendation=(
                            "If credentials are required, replace '*' with an explicit, trusted "
                            "origin in 'Access-Control-Allow-Origin'. If credentials are not "
                            "needed, remove 'Access-Control-Allow-Credentials: true'."
                        ),
                        extra_data={"allowed_origin": "*", "allow_credentials": True},
                    )
                )
            else:
                findings.append(
                    self.create_finding(
                        url=response_url,
                        title="Permissive CORS Wildcard Origin Allowed",
                        severity=Severity.LOW,
                        evidence=(
                            "The response specifies 'Access-Control-Allow-Origin: *', allowing any "
                            "third-party origin to read response content via uncredentialed "
                            "requests. This is standard for public resources, but may expose data "
                            "if the endpoint serves sensitive or internal content."
                        ),
                        recommendation=(
                            "If this endpoint serves sensitive or non-public data, restrict "
                            "'Access-Control-Allow-Origin' to trusted origins. For public APIs, "
                            "this configuration may be intended."
                        ),
                        extra_data={"allowed_origin": "*", "allow_credentials": False},
                    )
                )
            return findings

        # 6. Null Origin (null)
        if raw_acao.lower() == "null":
            cred_note = (
                " Combined with 'Access-Control-Allow-Credentials: true', this attempts "
                "to allow credentialed requests from the 'null' origin."
                if allow_credentials
                else ""
            )
            findings.append(
                self.create_finding(
                    url=response_url,
                    title="Insecure CORS Null Origin Allowed",
                    severity=Severity.MEDIUM,
                    evidence=(
                        "The response specifies 'Access-Control-Allow-Origin: null'. Browsers "
                        "assign the 'null' origin to sandboxed iframes, local file:// resources, "
                        "and cross-origin redirects. Trusting 'null' allows any website to read "
                        f"response data by framing it in a sandboxed iframe.{cred_note}"
                    ),
                    recommendation=(
                        "Avoid specifying 'null' in 'Access-Control-Allow-Origin'. Explicitly "
                        "validate and specify trusted origin domains instead."
                    ),
                    extra_data={
                        "allowed_origin": "null",
                        "allow_credentials": allow_credentials,
                    },
                )
            )
            return findings

        # 7. Validate origin syntax
        if not _is_valid_origin(raw_acao):
            findings.append(
                self.create_finding(
                    url=response_url,
                    title="Malformed CORS Access-Control-Allow-Origin Header",
                    severity=Severity.LOW,
                    evidence=(
                        f"The 'Access-Control-Allow-Origin' header value '{safe_origin}' is "
                        "malformed or invalid according to the CORS specification. Conforming "
                        "browsers reject CORS requests with malformed origin headers."
                    ),
                    recommendation=(
                        "Configure 'Access-Control-Allow-Origin' with a single valid origin "
                        "conforming to '<scheme>://<host>[:<port>]' (e.g., "
                        "'https://app.example.com'), '*', or omit the header."
                    ),
                    extra_data={"allowed_origin": safe_origin},
                )
            )
            return findings

        # 8. Valid explicit origin checks
        parsed_origin = urlsplit(raw_acao)

        # 8a. Cleartext HTTP allowed origin on HTTPS endpoint
        if (
            is_https
            and parsed_origin.scheme.lower() == "http"
            and parsed_origin.hostname not in ("localhost", "127.0.0.1", "::1")
        ):
            findings.append(
                self.create_finding(
                    url=response_url,
                    title="CORS Configured With Insecure HTTP Allowed Origin",
                    severity=Severity.LOW,
                    evidence=(
                        f"The target is served over HTTPS but specifies an unencrypted HTTP "
                        f"origin '{safe_origin}' in 'Access-Control-Allow-Origin'. An active "
                        "network attacker intercepting traffic on the unencrypted origin could "
                        "read cross-origin data."
                    ),
                    recommendation=(
                        "Update the allowed origin to use secure HTTPS transport for all "
                        "remote origins."
                    ),
                    extra_data={
                        "allowed_origin": safe_origin,
                        "allow_credentials": allow_credentials,
                    },
                )
            )

        # 8b. Vary: Origin check for explicit allowed origins
        vary_headers = get_header_list(headers, "vary", split_commas=True)
        has_vary_origin = any(v.lower() in ("origin", "*") for v in vary_headers)
        if not has_vary_origin:
            findings.append(
                self.create_finding(
                    url=response_url,
                    title="Missing Vary: Origin Header for Explicit CORS Origin",
                    severity=Severity.LOW,
                    evidence=(
                        f"The response specifies an explicit 'Access-Control-Allow-Origin' "
                        f"('{safe_origin}') without a 'Vary: Origin' header. Intermediate caches "
                        "and reverse proxies may serve this response to requests from other "
                        "origins, causing CORS failures or cache consistency issues."
                    ),
                    recommendation=(
                        "Add 'Origin' to the 'Vary' response header (e.g., 'Vary: Origin') so "
                        "caches properly partition responses by requesting origin."
                    ),
                    extra_data={
                        "allowed_origin": safe_origin,
                        "vary_headers": vary_headers,
                    },
                )
            )

        return findings

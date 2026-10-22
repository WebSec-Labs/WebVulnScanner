"""HTTP methods active security check module.

Evaluates server handling of diagnostic and potentially risky HTTP methods
without mutating server state, injecting exploit payloads, or extracting data.
"""

from urllib.parse import urlsplit

from app.scanner.check import BaseCheck, CheckMetadata
from app.scanner.client import ScannerResponse
from app.scanner.models import CheckType, Finding, Severity

PROBE_HEADER_NAME = "X-Scan-Trace-Probe"
PROBE_HEADER_VALUE = "webvulnscanner-trace-probe"


class HttpTraceMethodCheck(BaseCheck):
    """Actively probes whether the target server has the HTTP TRACE method enabled.

    HTTP TRACE is defined in RFC 7231 / RFC 9110 as a diagnostic loop-back mechanism.
    When enabled, a web server echoes received request lines and headers back to the
    client. Modern browsers restrict client-side scripts from reading TRACE responses
    (mitigating direct Cross-Site Tracing / XST attacks in browsers). However, enabled
    TRACE violates defense-in-depth principles and may disclose sensitive headers or
    internal proxy details to non-browser attackers.
    """

    @property
    def metadata(self) -> CheckMetadata:
        return CheckMetadata(
            check_id="http_trace_method",
            name="HTTP TRACE Method Check",
            description=(
                "Actively probes whether the HTTP TRACE method is enabled on the target server. "
                "While modern browsers mitigate direct client-side Cross-Site Tracing (XST), "
                "enabling TRACE violates defense-in-depth and can expose headers or proxy metadata."
            ),
            severity=Severity.LOW,
            check_type=CheckType.ACTIVE,
        )

    async def run(self, context) -> list[Finding]:
        """Dispatch a single harmless TRACE probe with a benign diagnostic header."""
        # Active check: explicitly issues a single TRACE request via shared client
        response: ScannerResponse = await context.client.request(
            "TRACE",
            context.target_url,
            headers={PROBE_HEADER_NAME: PROBE_HEADER_VALUE},
        )

        findings: list[Finding] = []

        if response.status_code != 200:
            return findings

        content_type = response.headers.get("content-type", "").lower()
        body_text = response.text
        parsed_target = urlsplit(context.target_url)
        target_path = parsed_target.path or "/"

        # Determine if the response exhibits genuine reflection of the TRACE request:
        # 1. The benign diagnostic probe header was reflected in the body.
        has_probe_echo = PROBE_HEADER_VALUE in body_text

        # 2. Strict RFC 7231 / RFC 9110 message/http encapsulation with the request line.
        has_rfc_encapsulation = (
            "message/http" in content_type and f"TRACE {target_path}" in body_text
        )

        # 3. Raw request line echo starting the body with HTTP protocol version.
        stripped_body = body_text.strip()
        has_request_line_echo = stripped_body.startswith(f"TRACE {target_path}") and (
            "HTTP/1." in stripped_body or "HTTP/2" in stripped_body
        )

        # Reject HTML pages (e.g. 200 OK default index or custom error pages)
        # unless our specific probe header was explicitly echoed in the body.
        is_html = (
            "<html" in body_text.lower()
            or "<!doctype" in body_text.lower()
            or "text/html" in content_type
        )
        if is_html and not has_probe_echo:
            return findings

        # Guard against ambiguous plain text (e.g., "TRACE is not supported")
        is_genuine_reflection = has_probe_echo or has_rfc_encapsulation or has_request_line_echo

        if is_genuine_reflection:
            evidence_parts: list[str] = [
                f"Server at '{response.url}' responded to HTTP TRACE with status 200."
            ]
            if has_probe_echo:
                evidence_parts.append(
                    f"Diagnostic probe header '{PROBE_HEADER_NAME}' was echoed in the body."
                )
            elif has_rfc_encapsulation:
                evidence_parts.append(
                    f"Response used '{content_type}' and reflected "
                    f"request line 'TRACE {target_path}'."
                )
            elif has_request_line_echo:
                evidence_parts.append(
                    f"Response body reflected the HTTP request line 'TRACE {target_path}'."
                )

            findings.append(
                self.create_finding(
                    url=response.url,
                    title="HTTP TRACE Method Enabled",
                    severity=Severity.LOW,
                    evidence=" ".join(evidence_parts),
                    recommendation=(
                        "Disable the HTTP TRACE method in web server configuration (e.g. "
                        "'TraceEnable Off' in Apache httpd, or reject TRACE in Nginx/IIS). "
                        "Modern browsers block TRACE in fetch/XHR, but disabling TRACE "
                        "enforces defense-in-depth."
                    ),
                    extra_data={
                        "status_code": response.status_code,
                        "content_type": content_type,
                        "reflected_probe_header": has_probe_echo,
                        "rfc_message_http": has_rfc_encapsulation,
                    },
                )
            )

        return findings

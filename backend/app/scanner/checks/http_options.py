"""HTTP OPTIONS method discovery active security check module.

Inspects HTTP methods advertised by the target server via the Allow header
without sending state-changing requests, mutating data, or injecting payloads.
"""

import re

from app.scanner.check import BaseCheck, CheckMetadata
from app.scanner.checks.utils import get_header_list
from app.scanner.client import ScannerResponse
from app.scanner.models import CheckType, Finding, Severity

# RFC 9110 compliant method token syntax (1 to 30 ASCII alphanumeric/hyphen/underscore chars)
METHOD_TOKEN_REGEX = re.compile(r"^[A-Za-z0-9_\-]{1,30}$")


class HttpOptionsMethodCheck(BaseCheck):
    """Actively inspects methods advertised by the target server via HTTP OPTIONS.

    Issues a single non-destructive HTTP OPTIONS probe to the target URL and
    parses the standard Allow response header. This check provides informational
    visibility into advertised capabilities without attempting to verify access,
    exploitability, or authentication bypass.
    """

    @property
    def metadata(self) -> CheckMetadata:
        return CheckMetadata(
            check_id="http_options_method",
            name="HTTP OPTIONS Method Check",
            description=(
                "Actively queries the HTTP OPTIONS method to inspect methods advertised by "
                "the target server via the Allow header. Provides informational visibility "
                "without verifying access or testing exploitability."
            ),
            severity=Severity.INFO,
            check_type=CheckType.ACTIVE,
        )

    async def run(self, context) -> list[Finding]:
        """Dispatch a single harmless OPTIONS probe to context.target_url."""
        # Active check: explicitly issues a single OPTIONS request via shared client
        response: ScannerResponse = await context.client.request("OPTIONS", context.target_url)

        findings: list[Finding] = []

        # Only process successful OPTIONS responses (200 OK or 204 No Content)
        if response.status_code not in (200, 204):
            return findings

        # Extract and parse all comma-separated tokens from Allow header(s)
        raw_tokens = get_header_list(response.headers, "allow", split_commas=True)
        if not raw_tokens:
            return findings

        valid_methods: set[str] = set()
        for raw_token in raw_tokens:
            token = raw_token.strip().upper()
            if METHOD_TOKEN_REGEX.match(token):
                valid_methods.add(token)

        if not valid_methods:
            return findings

        sorted_methods = sorted(valid_methods)
        methods_str = ", ".join(sorted_methods)

        evidence = (
            f"Server at '{response.url}' responded to HTTP OPTIONS with status "
            f"{response.status_code} and advertised the following methods in the "
            f"Allow header: {methods_str}."
        )

        findings.append(
            self.create_finding(
                url=response.url,
                title="HTTP Methods Advertised via OPTIONS",
                severity=Severity.INFO,
                evidence=evidence,
                recommendation=(
                    "Review the advertised HTTP methods to ensure only required capabilities "
                    "are exposed for this resource. Disable unnecessary methods (such as PUT, "
                    "DELETE, or WebDAV extensions) if not actively required by the application."
                ),
                extra_data={
                    "status_code": response.status_code,
                    "advertised_methods": sorted_methods,
                },
            )
        )

        return findings

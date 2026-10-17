"""HTTPS deployment and transport security check module.

Evaluates scheme usage, upgrade redirects, and downgrade detection without
speculating on certificate or cipher details not exposed by the HTTP engine.
"""

from urllib.parse import urlsplit

from app.scanner.check import BaseCheck, CheckMetadata, ScanContext
from app.scanner.models import Finding, Severity


class HttpsConfigurationCheck(BaseCheck):
    """Inspects HTTPS deployment, redirection behavior, and transport security posture."""

    @property
    def metadata(self) -> CheckMetadata:
        return CheckMetadata(
            check_id="https_configuration",
            name="HTTPS Configuration Check",
            description=(
                "Evaluates target scheme, final response scheme, and redirect history "
                "to ensure transport encryption and prevent downgrade attacks."
            ),
            severity=Severity.MEDIUM,
        )

    async def run(self, context: ScanContext) -> list[Finding]:
        """Execute HTTPS configuration check using the shared baseline response."""
        response = await context.get_baseline_response()
        findings: list[Finding] = []

        target_scheme = urlsplit(context.target_url).scheme.lower()
        final_scheme = urlsplit(response.url).scheme.lower()
        history = response.history

        # 1. Insecure HTTPS-to-HTTP Downgrade Redirection (High Severity)
        # Check if requested initially over HTTPS or any intermediate hop was HTTPS,
        # but final destination is plain HTTP.
        started_https = target_scheme == "https"
        any_hop_https = any(urlsplit(hop).scheme.lower() == "https" for hop in history)

        if (started_https or any_hop_https) and final_scheme == "http":
            chain_repr = " -> ".join([*history, response.url])
            findings.append(
                self.create_finding(
                    url=response.url,
                    title="Insecure HTTPS to HTTP Downgrade Redirection",
                    severity=Severity.HIGH,
                    evidence=(
                        f"Target began or traversed HTTPS but was redirected to an insecure "
                        f"cleartext HTTP destination. Redirect chain: {chain_repr}"
                    ),
                    recommendation=(
                        "Ensure all redirect chains maintain HTTPS transport encryption. "
                        "Never redirect an HTTPS request to an HTTP endpoint."
                    ),
                    extra_data={"redirect_chain": [*history, response.url]},
                )
            )
            return findings

        # 2. Cleartext HTTP Service Without HTTPS Upgrade (Medium Severity)
        # If target was requested over HTTP and final response remains on HTTP
        if target_scheme == "http" and final_scheme == "http":
            findings.append(
                self.create_finding(
                    url=response.url,
                    title="Cleartext HTTP Service Without HTTPS Upgrade",
                    severity=Severity.MEDIUM,
                    evidence=(
                        f"The service was requested over cleartext HTTP ('{context.target_url}') "
                        f"and served the final response over HTTP ('{response.url}') without "
                        "redirecting to HTTPS."
                    ),
                    recommendation=(
                        "Configure the web server to automatically redirect all cleartext HTTP "
                        "requests (port 80) to HTTPS (port 443) using an HTTP 301 redirect."
                    ),
                )
            )
            return findings

        # 3. HTTP Target Upgrading to HTTPS:
        # Observed upgrade (e.g. http:// -> https://). Per specification, this is not an issue.

        # 4. Direct HTTPS:
        # Directly served over HTTPS. No transport vulnerability.

        return findings

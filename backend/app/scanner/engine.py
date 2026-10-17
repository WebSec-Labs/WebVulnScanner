"""Scanner engine orchestrator for executing checks safely against validated targets."""

import asyncio
from datetime import UTC, datetime
from typing import Any

import httpx

from app.scanner.check import BaseCheck, ScanContext
from app.scanner.client import ScannerHttpClient
from app.scanner.models import ScanConfig, ScanResult, ScanStatus
from app.scanner.registry import CheckRegistry, default_registry
from app.scanner.scope import ScopeError, ScopePolicy, TargetScope


class ScannerEngine:
    """Orchestrates registered checks within security boundaries and execution limits."""

    def __init__(self, registry: CheckRegistry | None = None):
        self.registry = registry or default_registry

    async def run_scan(
        self,
        config: ScanConfig,
        scope: TargetScope,
        transport: httpx.AsyncBaseTransport | None = None,
        extra_context: dict[str, Any] | None = None,
    ) -> ScanResult:
        """Execute checks against target URL within configured constraints.

        - Enforces scope policy upfront asynchronously.
        - Resolves checks only from the explicit registry.
        - Bounded by concurrency, timeout, and request caps.
        - Records individual check exceptions without disguising failures as successes.

        Cancellation Contract:
        If the task running run_scan is cancelled, running check tasks are cancelled,
        client resources are cleaned up asynchronously via client context management (__aexit__),
        result.status is set to ScanStatus.CANCELLED, and asyncio.CancelledError is re-raised
        to conform to standard asyncio cancellation semantics.
        """
        start_time = datetime.now(UTC)
        scope_policy = ScopePolicy(scope)

        # Pre-validate target URL asynchronously
        try:
            normalized_target = await scope_policy.validate_url_async(config.target_url)
        except ScopeError as exc:
            end_time = datetime.now(UTC)
            return ScanResult(
                target_url=config.target_url,
                status=ScanStatus.FAILED,
                check_errors={"target_validation": str(exc)},
                start_time=start_time,
                end_time=end_time,
                duration_seconds=(end_time - start_time).total_seconds(),
            )

        # Resolve checks deterministically
        checks_to_run: list[BaseCheck] = []
        check_errors: dict[str, str] = {}

        if config.check_ids is not None:
            for cid in config.check_ids:
                if cid in self.registry:
                    checks_to_run.append(self.registry.get(cid))
                else:
                    check_errors[cid] = f"Check '{cid}' is not registered"
        else:
            checks_to_run = self.registry.list_checks()

        result = ScanResult(
            target_url=normalized_target,
            status=ScanStatus.RUNNING,
            check_errors=check_errors,
            start_time=start_time,
        )

        # Set up safe HTTP client bounded by session limits
        client = ScannerHttpClient(
            scope_policy=scope_policy,
            timeout=config.timeout_seconds,
            connect_timeout=config.connect_timeout_seconds,
            max_redirects=config.max_redirects,
            max_response_bytes=config.max_response_bytes,
            max_requests=config.max_requests,
            transport=transport,
        )

        semaphore = asyncio.Semaphore(config.max_concurrency)
        context = ScanContext(
            target_url=normalized_target,
            scope=scope,
            client=client,
            extra=extra_context or {},
        )

        async def _execute_check(check: BaseCheck) -> None:
            async with semaphore:
                try:
                    findings = await check.run(context)
                    result.findings.extend(findings)
                    result.executed_checks.append(check.check_id)
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    result.check_errors[check.check_id] = f"Check execution error: {exc}"

        try:
            async with client:
                if checks_to_run:
                    tasks = [_execute_check(check) for check in checks_to_run]
                    await asyncio.gather(*tasks)

            end_time = datetime.now(UTC)
            result.end_time = end_time
            result.duration_seconds = (end_time - start_time).total_seconds()
            result.total_requests = client.request_count

            if result.check_errors and not result.executed_checks and checks_to_run:
                result.status = ScanStatus.FAILED
            elif result.check_errors:
                result.status = ScanStatus.PARTIAL
            else:
                result.status = ScanStatus.COMPLETED

        except asyncio.CancelledError:
            end_time = datetime.now(UTC)
            result.end_time = end_time
            result.duration_seconds = (end_time - start_time).total_seconds()
            result.status = ScanStatus.CANCELLED
            result.total_requests = client.request_count
            raise

        return result

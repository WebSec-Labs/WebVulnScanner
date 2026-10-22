"""Scanner engine orchestrator for executing checks safely against validated targets."""

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import httpx

from app.scanner.check import BaseCheck, ScanContext
from app.scanner.client import ScannerHttpClient
from app.scanner.crawler.models import CrawlConfig, CrawlLimitReason
from app.scanner.crawler.normalizer import get_effective_origin
from app.scanner.crawler.service import BoundedCrawler, SameOriginScopePolicy
from app.scanner.models import CheckType, ScanConfig, ScanResult, ScanStatus
from app.scanner.registry import CheckRegistry, default_active_registry, default_registry
from app.scanner.scope import ScopeError, ScopePolicy, TargetScope


class ScannerEngine:
    """Orchestrates registered checks within security boundaries and execution limits."""

    def __init__(
        self,
        registry: CheckRegistry | None = None,
        active_registry: CheckRegistry | None = None,
    ):
        self.registry = default_registry if registry is None else registry
        self.active_registry = (
            default_active_registry if active_registry is None else active_registry
        )

    async def run_scan(
        self,
        config: ScanConfig,
        scope: TargetScope,
        transport: httpx.AsyncBaseTransport | None = None,
        extra_context: dict[str, Any] | None = None,
        dns_resolver: Callable[[str], list[str]] | None = None,
        async_dns_resolver: Callable[[str], Any] | None = None,
    ) -> ScanResult:
        """Execute checks against target URL within configured constraints.

        - Enforces scope policy upfront asynchronously.
        - When config.crawl_enabled is True, discovers same-origin pages and runs checks per page.
        - When config.crawl_enabled is False, preserves single-page scanning behavior.
        - Passive checks analyze responses without extra network requests.
        - Active checks run sequentially only when config.active_checks_enabled is True.
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
        dns_resolver = dns_resolver or (
            extra_context.get("dns_resolver") if extra_context else None
        )
        async_dns_resolver = async_dns_resolver or (
            extra_context.get("async_dns_resolver") if extra_context else None
        )

        scope_policy = ScopePolicy(
            scope=scope,
            dns_resolver=dns_resolver,
            async_dns_resolver=async_dns_resolver,
        )

        # Pre-validate target URL asynchronously
        try:
            normalized_target = await scope_policy.validate_url_async(config.target_url)
        except ScopeError as exc:
            end_time = datetime.now(UTC)
            return ScanResult(
                target_url=config.target_url,
                status=ScanStatus.FAILED,
                check_errors={"target_validation": str(exc)},
                failed_pages=[{"url": config.target_url, "error": str(exc)}],
                start_time=start_time,
                end_time=end_time,
                duration_seconds=(end_time - start_time).total_seconds(),
            )

        # Resolve checks deterministically
        checks_to_run: list[BaseCheck] = []
        check_errors: dict[str, str] = {}

        # Build available checks dictionary combining primary and active registries
        available_checks: dict[str, BaseCheck] = dict(self.registry._checks)
        if self.active_registry:
            for cid, chk in self.active_registry._checks.items():
                if cid not in available_checks:
                    available_checks[cid] = chk

        if config.check_ids is not None:
            for cid in config.check_ids:
                if cid in available_checks:
                    check = available_checks[cid]
                    is_active = (
                        getattr(check.metadata, "check_type", CheckType.PASSIVE) == CheckType.ACTIVE
                    )
                    if is_active and not config.active_checks_enabled:
                        check_errors[cid] = (
                            f"Active check '{cid}' is disabled because "
                            "active_checks_enabled is False. Explicit authorization is required."
                        )
                    else:
                        checks_to_run.append(check)
                else:
                    check_errors[cid] = f"Check '{cid}' is not registered"
        else:
            # When check_ids is omitted:
            # 1. Passive checks always run
            for chk in self.registry.list_checks():
                chk_type = getattr(chk.metadata, "check_type", CheckType.PASSIVE)
                if chk_type == CheckType.PASSIVE:
                    checks_to_run.append(chk)
                elif chk_type == CheckType.ACTIVE and config.active_checks_enabled:
                    checks_to_run.append(chk)

            # 2. Active checks run only if active_checks_enabled is explicitly True
            if config.active_checks_enabled and self.active_registry:
                for chk in self.active_registry.list_checks():
                    if chk not in checks_to_run:
                        checks_to_run.append(chk)

        # Classify resolved checks into passive (concurrent) and active (sequential)
        passive_checks = [
            c
            for c in checks_to_run
            if getattr(c.metadata, "check_type", CheckType.PASSIVE) == CheckType.PASSIVE
        ]
        active_checks = [
            c
            for c in checks_to_run
            if getattr(c.metadata, "check_type", CheckType.PASSIVE) == CheckType.ACTIVE
        ]

        result = ScanResult(
            target_url=normalized_target,
            status=ScanStatus.RUNNING,
            check_errors=check_errors,
            start_time=start_time,
        )

        target_origin = get_effective_origin(normalized_target)
        same_origin_policy = SameOriginScopePolicy(
            target_origin=target_origin,
            scope=scope,
            dns_resolver=dns_resolver,
            async_dns_resolver=async_dns_resolver,
        )

        # Set up safe HTTP client bounded by session limits
        client = ScannerHttpClient(
            scope_policy=same_origin_policy,
            timeout=config.timeout_seconds,
            connect_timeout=config.connect_timeout_seconds,
            max_redirects=config.max_redirects,
            max_response_bytes=config.max_response_bytes,
            max_requests=config.max_requests,
            transport=transport,
        )

        semaphore = asyncio.Semaphore(config.max_concurrency)

        try:
            async with client:
                if config.crawl_enabled:
                    # Multi-page crawl execution
                    crawl_config = CrawlConfig(
                        target_url=normalized_target,
                        max_depth=config.max_depth,
                        max_pages=config.max_pages,
                        max_requests=config.max_requests,
                        timeout_seconds=config.timeout_seconds,
                        max_response_bytes=config.max_response_bytes,
                        max_concurrency=min(config.max_concurrency, 2),
                    )
                    crawler = BoundedCrawler(
                        config=crawl_config,
                        scope=scope,
                        client=client,
                        dns_resolver=dns_resolver,
                        async_dns_resolver=async_dns_resolver,
                    )
                    crawl_result = await crawler.crawl()

                    # Record crawl page failures
                    for p in crawl_result.pages:
                        if p.error:
                            result.failed_pages.append({"url": p.url, "error": p.error})
                        elif p.status_code is not None and p.status_code >= 400:
                            result.failed_pages.append(
                                {"url": p.url, "error": f"HTTP {p.status_code}"}
                            )

                    # Check for seed-level failure
                    if (
                        crawl_result.pages
                        and crawl_result.pages[0].url == normalized_target
                        and crawl_result.pages[0].error
                    ):
                        result.check_errors["crawler"] = crawl_result.pages[0].error
                        eligible_pages = []
                    else:
                        eligible_pages = [
                            p
                            for p in crawl_result.pages
                            if p.error is None
                            and p.status_code is not None
                            and 200 <= p.status_code < 400
                        ]

                    seen_finding_keys: set[tuple[str, str, str, str]] = set()
                    executed_check_set: set[str] = set()

                    for page in eligible_pages:
                        cached_resp = crawl_result.responses.get(page.url)
                        page_context = ScanContext(
                            target_url=page.url,
                            scope=scope,
                            client=client,
                            extra=extra_context or {},
                            baseline_response=cached_resp,
                        )

                        async def _execute_check_on_page(
                            check: BaseCheck, ctx: ScanContext = page_context, p_url: str = page.url
                        ) -> None:
                            try:
                                findings = await check.run(ctx)
                                for f in findings:
                                    key = (f.check_id, f.url, f.title, f.evidence)
                                    if key not in seen_finding_keys:
                                        seen_finding_keys.add(key)
                                        result.findings.append(f)
                                executed_check_set.add(check.check_id)
                            except asyncio.CancelledError:
                                raise
                            except Exception as exc:
                                result.check_errors[f"{check.check_id}@{p_url}"] = (
                                    f"Check execution error: {exc}"
                                )

                        async def _execute_passive_with_sem(check: BaseCheck) -> None:
                            async with semaphore:
                                await _execute_check_on_page(check)

                        # 1. Execute passive checks concurrently with semaphore
                        if passive_checks:
                            tasks = [_execute_passive_with_sem(c) for c in passive_checks]
                            await asyncio.gather(*tasks)

                        # 2. Execute active checks sequentially to prevent target flooding
                        for active_check in active_checks:
                            await _execute_check_on_page(active_check)

                        result.scanned_pages.append(page.url)

                    result.executed_checks = sorted(executed_check_set)

                    if result.check_errors and not result.executed_checks and checks_to_run:
                        result.status = ScanStatus.FAILED
                    elif not eligible_pages and not checks_to_run:
                        result.status = ScanStatus.COMPLETED
                    elif not eligible_pages:
                        result.status = ScanStatus.FAILED
                    elif (
                        result.check_errors
                        or result.failed_pages
                        or crawl_result.limit_reached
                        in {CrawlLimitReason.REQUEST_LIMIT, CrawlLimitReason.RUNTIME_LIMIT}
                    ):
                        result.status = ScanStatus.PARTIAL
                    else:
                        result.status = ScanStatus.COMPLETED

                else:
                    # Single-page scan execution (Phase 4 compatibility)
                    context = ScanContext(
                        target_url=normalized_target,
                        scope=scope,
                        client=client,
                        extra=extra_context or {},
                    )

                    seen_finding_keys_single: set[tuple[str, str, str, str]] = set()

                    async def _execute_single_check(check: BaseCheck) -> None:
                        try:
                            findings = await check.run(context)
                            for f in findings:
                                key = (f.check_id, f.url, f.title, f.evidence)
                                if key not in seen_finding_keys_single:
                                    seen_finding_keys_single.add(key)
                                    result.findings.append(f)
                            result.executed_checks.append(check.check_id)
                        except asyncio.CancelledError:
                            raise
                        except Exception as exc:
                            result.check_errors[check.check_id] = f"Check execution error: {exc}"

                    async def _execute_single_passive(check: BaseCheck) -> None:
                        async with semaphore:
                            await _execute_single_check(check)

                    # 1. Execute passive checks concurrently with semaphore
                    if passive_checks:
                        tasks = [_execute_single_passive(check) for check in passive_checks]
                        await asyncio.gather(*tasks)

                    # 2. Execute active checks sequentially
                    for active_check in active_checks:
                        await _execute_single_check(active_check)

                    result.executed_checks = sorted(list(set(result.executed_checks)))

                    if result.executed_checks or not checks_to_run:
                        result.scanned_pages.append(normalized_target)

                    if result.check_errors and not result.executed_checks and checks_to_run:
                        result.status = ScanStatus.FAILED
                    elif result.check_errors:
                        result.status = ScanStatus.PARTIAL
                    else:
                        result.status = ScanStatus.COMPLETED

            end_time = datetime.now(UTC)
            result.end_time = end_time
            result.duration_seconds = (end_time - start_time).total_seconds()
            result.total_requests = client.request_count

        except asyncio.CancelledError:
            end_time = datetime.now(UTC)
            result.end_time = end_time
            result.duration_seconds = (end_time - start_time).total_seconds()
            result.status = ScanStatus.CANCELLED
            result.total_requests = client.request_count
            raise

        return result

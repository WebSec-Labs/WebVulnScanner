"""Bounded, same-origin web crawler service with strict SSRF and scope guardrails."""

import asyncio
import logging
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import httpx

from app.scanner.client import (
    MaxRedirectsExceededError,
    RequestLimitExceededError,
    ResponseSizeExceededError,
    ScannerClientError,
    ScannerHttpClient,
    ScannerNetworkError,
    ScannerTimeoutError,
)
from app.scanner.crawler.extractor import extract_links
from app.scanner.crawler.models import (
    CrawlConfig,
    CrawledPage,
    CrawlLimitReason,
    CrawlResult,
)
from app.scanner.crawler.normalizer import (
    EffectiveOrigin,
    get_effective_origin,
    is_same_origin,
    normalize_crawler_url,
    resolve_and_normalize_url,
)
from app.scanner.scope import (
    RedirectScopeViolationError,
    ScopeError,
    ScopePolicy,
    TargetNotAuthorizedError,
    TargetScope,
)

logger = logging.getLogger(__name__)


class SameOriginScopePolicy(ScopePolicy):
    """Scope policy enforcing strict same-origin on URLs and redirect hops."""

    def __init__(
        self,
        target_origin: EffectiveOrigin,
        scope: TargetScope,
        dns_resolver: Callable[[str], list[str]] | None = None,
        async_dns_resolver: Callable[[str], Any] | None = None,
    ) -> None:
        super().__init__(
            scope=scope,
            dns_resolver=dns_resolver,
            async_dns_resolver=async_dns_resolver,
        )
        self.target_origin = target_origin

    async def validate_url_async(self, raw_url: str) -> str:
        """Validate URL against SSRF policy and exact same-origin boundary."""
        normalized = await super().validate_url_async(raw_url)
        origin = get_effective_origin(normalized)
        if origin != self.target_origin:
            raise TargetNotAuthorizedError(
                f"URL '{normalized}' does not match authorized origin "
                f"({self.target_origin.scheme}://{self.target_origin.hostname}:"
                f"{self.target_origin.effective_port})"
            )
        return normalized

    async def validate_redirect_async(self, current_url: str, location_header: str) -> str:
        """Validate redirect hop against SSRF policy and exact same-origin boundary."""
        resolved_next = await super().validate_redirect_async(current_url, location_header)
        next_origin = get_effective_origin(resolved_next)
        if next_origin != self.target_origin:
            raise RedirectScopeViolationError(
                f"Redirect destination '{resolved_next}' escapes authorized origin "
                f"({self.target_origin.scheme}://{self.target_origin.hostname}:"
                f"{self.target_origin.effective_port})"
            )
        return resolved_next


class BoundedCrawler:
    """Deterministic, bounded breadth-first web crawler restricted to same-origin pages."""

    def __init__(
        self,
        config: CrawlConfig,
        scope: TargetScope | None = None,
        client: ScannerHttpClient | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        dns_resolver: Callable[[str], list[str]] | None = None,
        async_dns_resolver: Callable[[str], Any] | None = None,
    ) -> None:
        self.config = config
        self._custom_scope = scope
        self._custom_client = client
        self.transport = transport
        self.dns_resolver = dns_resolver
        self.async_dns_resolver = async_dns_resolver

    async def crawl(self) -> CrawlResult:
        """Execute bounded same-origin crawl according to configured limits."""
        start_time = datetime.now(UTC)

        # 1. Normalize seed URL and determine authoritative origin
        try:
            normalized_seed = normalize_crawler_url(
                self.config.target_url,
                max_length=self.config.max_url_length,
            )
            origin = get_effective_origin(normalized_seed)
        except ScopeError as exc:
            end_time = datetime.now(UTC)
            return CrawlResult(
                target_url=self.config.target_url,
                start_time=start_time,
                end_time=end_time,
                duration_seconds=(end_time - start_time).total_seconds(),
                pages=[
                    CrawledPage(
                        url=self.config.target_url,
                        depth=0,
                        error=f"Invalid target URL: {exc}",
                    )
                ],
                limit_reached=CrawlLimitReason.QUEUE_EXHAUSTED,
            )

        # 2. Build strictly pinned same-origin target scope and scope policy
        target_scope = self._custom_scope or TargetScope(
            allowed_hosts={origin.hostname},
            allowed_schemes={origin.scheme},
            allowed_ports={origin.effective_port},
            allow_subdomains=False,
            allow_local_lab_targets=False,
        )

        scope_policy = SameOriginScopePolicy(
            target_origin=origin,
            scope=target_scope,
            dns_resolver=self.dns_resolver,
            async_dns_resolver=self.async_dns_resolver,
        )

        # Pre-validate seed URL with scope policy
        try:
            await scope_policy.validate_url_async(normalized_seed)
        except ScopeError as exc:
            end_time = datetime.now(UTC)
            return CrawlResult(
                target_url=normalized_seed,
                start_time=start_time,
                end_time=end_time,
                duration_seconds=(end_time - start_time).total_seconds(),
                pages=[
                    CrawledPage(
                        url=normalized_seed,
                        depth=0,
                        error=f"Target rejected by scope policy: {exc}",
                    )
                ],
                limit_reached=CrawlLimitReason.QUEUE_EXHAUSTED,
            )

        # 3. Setup safe HTTP client
        owns_client = self._custom_client is None
        client = self._custom_client or ScannerHttpClient(
            scope_policy=scope_policy,
            timeout=self.config.timeout_seconds,
            max_redirects=5,
            max_response_bytes=self.config.max_response_bytes,
            max_requests=self.config.effective_max_requests,
            transport=self.transport,
        )

        # 4. State tracking for breadth-first crawl
        result = CrawlResult(target_url=normalized_seed, start_time=start_time)
        scheduled_urls: set[str] = {normalized_seed}
        visited_urls: set[str] = set()
        current_level: list[tuple[str, int]] = [(normalized_seed, 0)]
        semaphore = asyncio.Semaphore(self.config.max_concurrency)
        limit_reached = CrawlLimitReason.QUEUE_EXHAUSTED
        more_links_at_max_depth = False

        # Helper to fetch a single page with semaphore bounding
        async def _fetch_single_page(
            target_url: str,
            depth: int,
        ) -> tuple[CrawledPage, list[str], Any]:
            async with semaphore:
                req_start = datetime.now(UTC)
                try:
                    # Enforce request budget check before dispatching
                    if client.request_count >= self.config.effective_max_requests:
                        raise RequestLimitExceededError(
                            f"Request limit of {self.config.effective_max_requests} reached"
                        )

                    response = await client.get(target_url)
                    req_duration = (datetime.now(UTC) - req_start).total_seconds()

                    # Re-verify same origin on final response URL
                    if not is_same_origin(normalized_seed, response.url):
                        raise RedirectScopeViolationError(
                            f"Final URL '{response.url}' does not match seed origin"
                        )

                    final_url = normalize_crawler_url(
                        response.url,
                        max_length=self.config.max_url_length,
                    )
                    content_type = response.headers.get("content-type")
                    is_html = bool(
                        content_type
                        and (
                            "text/html" in content_type.lower()
                            or "application/xhtml+xml" in content_type.lower()
                        )
                    )

                    discovered: list[str] = []
                    if is_html and response.status_code == 200:
                        raw_links = extract_links(
                            response.text,
                            max_link_length=self.config.max_url_length,
                        )
                        for raw in raw_links:
                            try:
                                resolved = resolve_and_normalize_url(
                                    raw,
                                    base_url=final_url,
                                    max_length=self.config.max_url_length,
                                    same_origin_only=True,
                                )
                                await scope_policy.validate_url_async(resolved)
                                discovered.append(resolved)
                            except (ScopeError, ValueError):
                                # Discard cross-origin, SSRF, or malformed links safely
                                continue

                    page = CrawledPage(
                        url=final_url,
                        depth=depth,
                        status_code=response.status_code,
                        content_type=content_type,
                        links_count=len(discovered),
                        response_time_seconds=req_duration,
                    )
                    return page, discovered, response

                except ScannerTimeoutError as exc:
                    req_dur = (datetime.now(UTC) - req_start).total_seconds()
                    return (
                        CrawledPage(
                            url=target_url,
                            depth=depth,
                            error=f"Timeout: {exc}",
                            response_time_seconds=req_dur,
                        ),
                        [],
                        None,
                    )
                except ScannerNetworkError as exc:
                    req_dur = (datetime.now(UTC) - req_start).total_seconds()
                    return (
                        CrawledPage(
                            url=target_url,
                            depth=depth,
                            error=f"Network error: {exc}",
                            response_time_seconds=req_dur,
                        ),
                        [],
                        None,
                    )
                except RedirectScopeViolationError as exc:
                    req_dur = (datetime.now(UTC) - req_start).total_seconds()
                    return (
                        CrawledPage(
                            url=target_url,
                            depth=depth,
                            error=f"Redirect scope violation: {exc}",
                            response_time_seconds=req_dur,
                        ),
                        [],
                        None,
                    )
                except MaxRedirectsExceededError as exc:
                    req_dur = (datetime.now(UTC) - req_start).total_seconds()
                    return (
                        CrawledPage(
                            url=target_url,
                            depth=depth,
                            error=f"Too many redirects: {exc}",
                            response_time_seconds=req_dur,
                        ),
                        [],
                        None,
                    )
                except ResponseSizeExceededError as exc:
                    req_dur = (datetime.now(UTC) - req_start).total_seconds()
                    return (
                        CrawledPage(
                            url=target_url,
                            depth=depth,
                            error=f"Response size exceeded limit: {exc}",
                            response_time_seconds=req_dur,
                        ),
                        [],
                        None,
                    )
                except RequestLimitExceededError as exc:
                    req_dur = (datetime.now(UTC) - req_start).total_seconds()
                    return (
                        CrawledPage(
                            url=target_url,
                            depth=depth,
                            error=f"Request limit reached: {exc}",
                            response_time_seconds=req_dur,
                        ),
                        [],
                        None,
                    )
                except ScopeError as exc:
                    req_dur = (datetime.now(UTC) - req_start).total_seconds()
                    return (
                        CrawledPage(
                            url=target_url,
                            depth=depth,
                            error=f"Scope policy violation: {exc}",
                            response_time_seconds=req_dur,
                        ),
                        [],
                        None,
                    )
                except ScannerClientError as exc:
                    req_dur = (datetime.now(UTC) - req_start).total_seconds()
                    return (
                        CrawledPage(
                            url=target_url,
                            depth=depth,
                            error=f"Client error: {exc}",
                            response_time_seconds=req_dur,
                        ),
                        [],
                        None,
                    )
                except Exception as exc:
                    req_dur = (datetime.now(UTC) - req_start).total_seconds()
                    return (
                        CrawledPage(
                            url=target_url,
                            depth=depth,
                            error=f"Unexpected error: {type(exc).__name__}",
                            response_time_seconds=req_dur,
                        ),
                        [],
                        None,
                    )

        # 5. Execute bounded breadth-first crawl within runtime timeout
        try:
            async with asyncio.timeout(self.config.max_runtime_seconds):
                for depth in range(self.config.max_depth + 1):
                    if not current_level:
                        break

                    # Check page limit before starting level
                    if len(result.pages) >= self.config.max_pages:
                        limit_reached = CrawlLimitReason.PAGE_LIMIT
                        break

                    # Take only up to remaining page budget
                    remaining_slots = self.config.max_pages - len(result.pages)
                    urls_to_fetch = current_level[:remaining_slots]
                    if len(current_level) > remaining_slots:
                        limit_reached = CrawlLimitReason.PAGE_LIMIT

                    # Fetch pages concurrently with bounded semaphore
                    fetch_tasks = [
                        _fetch_single_page(item_url, item_depth)
                        for item_url, item_depth in urls_to_fetch
                    ]
                    level_results = await asyncio.gather(*fetch_tasks)

                    next_level: list[tuple[str, int]] = []
                    request_limit_hit = False

                    # Process in deterministic discovery order
                    for page, discovered_links, resp in level_results:
                        if page.url in visited_urls:
                            continue

                        visited_urls.add(page.url)
                        scheduled_urls.add(page.url)
                        result.pages.append(page)
                        if resp is not None:
                            result.responses[page.url] = resp

                        if page.error and "Request limit reached" in page.error:
                            request_limit_hit = True

                        # Enqueue discovered links for next depth level if within depth bounds
                        if depth < self.config.max_depth:
                            for link in discovered_links:
                                if link not in scheduled_urls:
                                    scheduled_urls.add(link)
                                    next_level.append((link, depth + 1))
                        else:
                            # At max depth, note if further links existed
                            if discovered_links:
                                more_links_at_max_depth = True

                    if request_limit_hit:
                        limit_reached = CrawlLimitReason.REQUEST_LIMIT
                        break

                    if len(result.pages) >= self.config.max_pages:
                        limit_reached = CrawlLimitReason.PAGE_LIMIT
                        break

                    current_level = next_level

                # If queue exhausted but deeper links were available at max depth
                if (
                    limit_reached == CrawlLimitReason.QUEUE_EXHAUSTED
                    and more_links_at_max_depth
                    and len(result.pages) < self.config.max_pages
                ):
                    limit_reached = CrawlLimitReason.DEPTH_LIMIT

        except TimeoutError:
            limit_reached = CrawlLimitReason.RUNTIME_LIMIT
        except asyncio.CancelledError:
            result.limit_reached = CrawlLimitReason.CANCELLED
            result.end_time = datetime.now(UTC)
            result.duration_seconds = (result.end_time - start_time).total_seconds()
            result.total_requests = client.request_count
            if owns_client:
                await client.close()
            raise
        finally:
            if owns_client:
                await client.close()

        end_time = datetime.now(UTC)
        result.end_time = end_time
        result.duration_seconds = (end_time - start_time).total_seconds()
        result.total_requests = client.request_count
        result.limit_reached = limit_reached

        return result


async def crawl(
    target_url: str,
    max_depth: int = 3,
    max_pages: int = 20,
    max_runtime_seconds: float = 30.0,
    max_concurrency: int = 2,
    transport: httpx.AsyncBaseTransport | None = None,
    dns_resolver: Callable[[str], list[str]] | None = None,
    async_dns_resolver: Callable[[str], Any] | None = None,
    **kwargs: Any,
) -> CrawlResult:
    """Convenience function to execute a bounded same-origin crawl."""
    config = CrawlConfig(
        target_url=target_url,
        max_depth=max_depth,
        max_pages=max_pages,
        max_runtime_seconds=max_runtime_seconds,
        max_concurrency=max_concurrency,
        **kwargs,
    )
    crawler = BoundedCrawler(
        config=config,
        transport=transport,
        dns_resolver=dns_resolver,
        async_dns_resolver=async_dns_resolver,
    )
    return await crawler.crawl()

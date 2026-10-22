"""Unit and integration tests for bounded same-origin crawler service."""

import asyncio
from unittest.mock import patch

import httpx
import pytest

from app.scanner.crawler.models import (
    CrawlConfig,
    CrawlLimitReason,
)
from app.scanner.crawler.service import BoundedCrawler, crawl


@pytest.fixture
def mock_dns_resolver():
    """Mock DNS resolver returning a valid public IP."""
    return lambda host: ["93.184.216.34"]


@pytest.mark.asyncio
async def test_bounded_crawler_class_instantiation(mock_dns_resolver):
    """Verify BoundedCrawler class directly instantiated with CrawlConfig."""
    config = CrawlConfig(target_url="https://example.com/", max_depth=1, max_pages=2)
    transport = httpx.MockTransport(
        lambda req: httpx.Response(
            200,
            headers={"Content-Type": "text/html"},
            text="<a href='/a'>A</a>",
        )
    )
    crawler = BoundedCrawler(
        config=config,
        transport=transport,
        dns_resolver=mock_dns_resolver,
    )
    result = await crawler.crawl()
    assert result.successful_count == 2
    assert result.limit_reached == CrawlLimitReason.PAGE_LIMIT


@pytest.mark.asyncio
async def test_crawl_basic_breadth_first(mock_dns_resolver):
    """Verify breadth-first crawl order and link discovery across depth levels."""
    responses = {
        "https://example.com/": (
            200,
            "text/html",
            '<html><body><a href="/about">About</a><a href="/contact">Contact</a></body></html>',
        ),
        "https://example.com/about": (
            200,
            "text/html",
            '<html><body><a href="/team">Team</a></body></html>',
        ),
        "https://example.com/contact": (
            200,
            "text/html",
            '<html><body><a href="/map">Map</a></body></html>',
        ),
        "https://example.com/team": (
            200,
            "text/html",
            "<html><body>Team Page</body></html>",
        ),
        "https://example.com/map": (
            200,
            "text/html",
            "<html><body>Map Page</body></html>",
        ),
    }

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url in responses:
            status, ct, text = responses[url]
            return httpx.Response(status, headers={"Content-Type": ct}, text=text)
        return httpx.Response(404, text="Not Found")

    transport = httpx.MockTransport(handler)
    result = await crawl(
        target_url="https://example.com/",
        max_depth=3,
        max_pages=10,
        transport=transport,
        dns_resolver=mock_dns_resolver,
    )

    assert result.target_url == "https://example.com/"
    assert result.successful_count == 5
    assert result.failed_count == 0
    assert result.limit_reached == CrawlLimitReason.QUEUE_EXHAUSTED

    page_urls = [p.url for p in result.pages]
    # Depth 0
    assert page_urls[0] == "https://example.com/"
    assert result.pages[0].depth == 0
    # Depth 1 (breadth-first)
    assert set(page_urls[1:3]) == {"https://example.com/about", "https://example.com/contact"}
    assert {result.pages[1].depth, result.pages[2].depth} == {1}
    # Depth 2 (breadth-first)
    assert set(page_urls[3:5]) == {"https://example.com/team", "https://example.com/map"}
    assert {result.pages[3].depth, result.pages[4].depth} == {2}


@pytest.mark.asyncio
async def test_crawl_cycle_and_duplicate_prevention(mock_dns_resolver):
    """Verify that cyclical links and duplicate references do not cause repeated fetches."""
    fetch_counts: dict[str, int] = {}

    responses = {
        "https://example.com/": (
            200,
            "text/html",
            '<a href="/a">A</a><a href="/b">B</a><a href="/">Home</a>',
        ),
        "https://example.com/a": (
            200,
            "text/html",
            '<a href="/b">B</a><a href="/">Home</a>',
        ),
        "https://example.com/b": (
            200,
            "text/html",
            '<a href="/a">A</a><a href="/">Home</a>',
        ),
    }

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        fetch_counts[url] = fetch_counts.get(url, 0) + 1
        status, ct, text = responses[url]
        return httpx.Response(status, headers={"Content-Type": ct}, text=text)

    transport = httpx.MockTransport(handler)
    result = await crawl(
        target_url="https://example.com/",
        max_depth=3,
        max_pages=10,
        transport=transport,
        dns_resolver=mock_dns_resolver,
    )

    assert len(result.pages) == 3
    assert set(fetch_counts.keys()) == {
        "https://example.com/",
        "https://example.com/a",
        "https://example.com/b",
    }
    # Each page must be fetched exactly once
    assert all(count == 1 for count in fetch_counts.values())


@pytest.mark.asyncio
async def test_crawl_depth_limit_enforced(mock_dns_resolver):
    """Verify that crawler halts link traversal strictly at max_depth."""
    responses = {
        "https://example.com/0": (200, "text/html", '<a href="/1">1</a>'),
        "https://example.com/1": (200, "text/html", '<a href="/2">2</a>'),
        "https://example.com/2": (200, "text/html", '<a href="/3">3</a>'),
        "https://example.com/3": (200, "text/html", '<a href="/4">4</a>'),
    }

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        status, ct, text = responses[url]
        return httpx.Response(status, headers={"Content-Type": ct}, text=text)

    transport = httpx.MockTransport(handler)
    result = await crawl(
        target_url="https://example.com/0",
        max_depth=2,
        max_pages=10,
        transport=transport,
        dns_resolver=mock_dns_resolver,
    )

    crawled_urls = [p.url for p in result.pages]
    assert crawled_urls == [
        "https://example.com/0",
        "https://example.com/1",
        "https://example.com/2",
    ]
    assert "https://example.com/3" not in crawled_urls
    assert result.limit_reached == CrawlLimitReason.DEPTH_LIMIT


@pytest.mark.asyncio
async def test_crawl_page_limit_enforced(mock_dns_resolver):
    """Verify that crawl stops immediately when max_pages budget is reached."""
    responses = {
        "https://example.com/": (
            200,
            "text/html",
            "".join(f'<a href="/p{i}">P{i}</a>' for i in range(10)),
        ),
    }
    for i in range(10):
        responses[f"https://example.com/p{i}"] = (200, "text/html", f"Page {i}")

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        status, ct, text = responses[url]
        return httpx.Response(status, headers={"Content-Type": ct}, text=text)

    transport = httpx.MockTransport(handler)
    result = await crawl(
        target_url="https://example.com/",
        max_depth=2,
        max_pages=4,
        transport=transport,
        dns_resolver=mock_dns_resolver,
    )

    assert len(result.pages) == 4
    assert result.limit_reached == CrawlLimitReason.PAGE_LIMIT


@pytest.mark.asyncio
async def test_crawl_request_budget_enforced(mock_dns_resolver):
    """Verify that request limits prevent exceeding the effective request budget."""
    responses = {
        "https://example.com/": (
            200,
            "text/html",
            "".join(f'<a href="/p{i}">P{i}</a>' for i in range(10)),
        ),
    }
    for i in range(10):
        responses[f"https://example.com/p{i}"] = (200, "text/html", f"Page {i}")

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        status, ct, text = responses[url]
        return httpx.Response(status, headers={"Content-Type": ct}, text=text)

    transport = httpx.MockTransport(handler)
    result = await crawl(
        target_url="https://example.com/",
        max_depth=2,
        max_pages=10,
        max_requests=3,
        request_overhead=0,
        transport=transport,
        dns_resolver=mock_dns_resolver,
    )

    assert result.total_requests == 3
    assert result.limit_reached == CrawlLimitReason.REQUEST_LIMIT


@pytest.mark.asyncio
async def test_crawl_concurrency_bounded_to_at_most_two(mock_dns_resolver):
    """Verify that maximum active concurrent requests never exceeds 2."""
    active_requests = 0
    max_observed_concurrency = 0

    responses = {
        "https://example.com/": (
            200,
            "text/html",
            "".join(f'<a href="/delay{i}">D{i}</a>' for i in range(6)),
        ),
    }
    for i in range(6):
        responses[f"https://example.com/delay{i}"] = (200, "text/html", f"Delay {i}")

    async def async_handler(request: httpx.Request) -> httpx.Response:
        nonlocal active_requests, max_observed_concurrency
        active_requests += 1
        if active_requests > max_observed_concurrency:
            max_observed_concurrency = active_requests

        await asyncio.sleep(0.02)
        active_requests -= 1

        url = str(request.url)
        status, ct, text = responses[url]
        return httpx.Response(status, headers={"Content-Type": ct}, text=text)

    transport = httpx.MockTransport(async_handler)
    result = await crawl(
        target_url="https://example.com/",
        max_depth=2,
        max_pages=6,
        max_concurrency=2,
        transport=transport,
        dns_resolver=mock_dns_resolver,
    )

    assert max_observed_concurrency <= 2
    assert len(result.pages) == 6


@pytest.mark.asyncio
async def test_crawl_cross_origin_links_discarded(mock_dns_resolver):
    """Verify that links to other hosts, subdomains, schemes, and ports are discarded."""
    external_requested = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal external_requested
        url = str(request.url)
        if "example.com:443" not in url and "https://example.com/" not in url:
            external_requested = True
            return httpx.Response(200, text="External")

        html = """
        <a href="https://other.com/ext">Other Domain</a>
        <a href="https://sub.example.com/sub">Subdomain</a>
        <a href="http://example.com/scheme">Different Scheme</a>
        <a href="https://example.com:8443/port">Different Port</a>
        <a href="/same-origin">Same Origin</a>
        """
        if url == "https://example.com/":
            return httpx.Response(200, headers={"Content-Type": "text/html"}, text=html)
        return httpx.Response(200, headers={"Content-Type": "text/html"}, text="Same origin OK")

    transport = httpx.MockTransport(handler)
    result = await crawl(
        target_url="https://example.com/",
        max_depth=2,
        transport=transport,
        dns_resolver=mock_dns_resolver,
    )

    crawled_urls = [p.url for p in result.pages]
    assert crawled_urls == ["https://example.com/", "https://example.com/same-origin"]
    assert external_requested is False


@pytest.mark.asyncio
async def test_crawl_ssrf_links_discarded(mock_dns_resolver):
    """Verify links resolving to loopback, private IP, and metadata addresses are rejected."""
    ssrf_requested = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal ssrf_requested
        url = str(request.url)
        if any(bad in url for bad in ("127.0.0.1", "169.254", "localhost")):
            ssrf_requested = True
            return httpx.Response(200, text="SSRF Hit")

        html = """
        <a href="http://127.0.0.1:8000/admin">Loopback</a>
        <a href="http://169.254.169.254/latest/meta-data/">Cloud Metadata</a>
        <a href="http://localhost:8080/test">Localhost</a>
        <a href="/safe-link">Safe Link</a>
        """
        if url == "https://example.com/":
            return httpx.Response(200, headers={"Content-Type": "text/html"}, text=html)
        return httpx.Response(200, headers={"Content-Type": "text/html"}, text="Safe OK")

    transport = httpx.MockTransport(handler)
    result = await crawl(
        target_url="https://example.com/",
        max_depth=2,
        transport=transport,
        dns_resolver=mock_dns_resolver,
    )

    crawled_urls = [p.url for p in result.pages]
    assert crawled_urls == ["https://example.com/", "https://example.com/safe-link"]
    assert ssrf_requested is False


@pytest.mark.asyncio
async def test_crawl_same_origin_redirect_followed(mock_dns_resolver):
    """Verify that same-origin redirects are followed and the final URL is recorded."""

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url == "https://example.com/old-page":
            return httpx.Response(301, headers={"Location": "/new-page"})
        if url == "https://example.com/new-page":
            return httpx.Response(
                200,
                headers={"Content-Type": "text/html"},
                text='<a href="/target">Target</a>',
            )
        if url == "https://example.com/target":
            return httpx.Response(200, headers={"Content-Type": "text/html"}, text="Target OK")
        return httpx.Response(404, text="Not Found")

    transport = httpx.MockTransport(handler)
    result = await crawl(
        target_url="https://example.com/old-page",
        max_depth=2,
        transport=transport,
        dns_resolver=mock_dns_resolver,
    )

    crawled_urls = [p.url for p in result.pages]
    assert "https://example.com/new-page" in crawled_urls
    assert "https://example.com/target" in crawled_urls


@pytest.mark.asyncio
async def test_crawl_cross_origin_redirect_blocked(mock_dns_resolver):
    """Verify that redirects escaping to another origin are intercepted and blocked."""
    evil_requested = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal evil_requested
        url = str(request.url)
        if "evil.com" in url:
            evil_requested = True
            return httpx.Response(200, text="Evil Exploit")
        if url == "https://example.com/":
            return httpx.Response(
                200,
                headers={"Content-Type": "text/html"},
                text='<a href="/trap">Trap Link</a><a href="/good">Good Link</a>',
            )
        if url == "https://example.com/trap":
            return httpx.Response(302, headers={"Location": "https://evil.com/payload"})
        if url == "https://example.com/good":
            return httpx.Response(200, headers={"Content-Type": "text/html"}, text="Good Page")
        return httpx.Response(404, text="Not Found")

    transport = httpx.MockTransport(handler)
    result = await crawl(
        target_url="https://example.com/",
        max_depth=2,
        transport=transport,
        dns_resolver=mock_dns_resolver,
    )

    assert evil_requested is False
    assert result.successful_count == 2
    assert result.failed_count == 1
    trap_page = next(p for p in result.pages if "/trap" in p.url)
    assert trap_page.error is not None
    assert "Redirect" in trap_page.error or "scope" in trap_page.error.lower()


@pytest.mark.asyncio
async def test_crawl_ssrf_redirect_blocked(mock_dns_resolver):
    """Verify that redirects targeting cloud metadata or private IPs are blocked."""
    metadata_requested = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal metadata_requested
        url = str(request.url)
        if "169.254" in url:
            metadata_requested = True
            return httpx.Response(200, text="AWS Metadata")
        if url == "https://example.com/":
            return httpx.Response(
                200,
                headers={"Content-Type": "text/html"},
                text='<a href="/meta-trap">Meta Trap</a>',
            )
        if url == "https://example.com/meta-trap":
            return httpx.Response(
                302,
                headers={"Location": "http://169.254.169.254/latest/meta-data/"},
            )
        return httpx.Response(404, text="Not Found")

    transport = httpx.MockTransport(handler)
    result = await crawl(
        target_url="https://example.com/",
        max_depth=2,
        transport=transport,
        dns_resolver=mock_dns_resolver,
    )

    assert metadata_requested is False
    assert result.failed_count == 1
    meta_page = next(p for p in result.pages if "/meta-trap" in p.url)
    assert meta_page.error is not None


@pytest.mark.asyncio
async def test_crawl_non_html_responses_not_parsed(mock_dns_resolver):
    """Verify that non-HTML responses (JSON, images) are recorded but not parsed for links."""

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url == "https://example.com/":
            return httpx.Response(
                200,
                headers={"Content-Type": "text/html"},
                text='<a href="/api/data.json">Data</a><a href="/page2">Page2</a>',
            )
        if url == "https://example.com/api/data.json":
            # JSON response containing HTML-like text
            return httpx.Response(
                200,
                headers={"Content-Type": "application/json"},
                text='{"html_snippet": "<a href=\\"/ignored-inside-json\\">Click</a>"}',
            )
        if url == "https://example.com/page2":
            return httpx.Response(200, headers={"Content-Type": "text/html"}, text="Page 2")
        return httpx.Response(404, text="Not Found")

    transport = httpx.MockTransport(handler)
    result = await crawl(
        target_url="https://example.com/",
        max_depth=3,
        transport=transport,
        dns_resolver=mock_dns_resolver,
    )

    json_page = next(p for p in result.pages if p.url == "https://example.com/api/data.json")
    assert json_page.status_code == 200
    assert json_page.content_type == "application/json"
    assert json_page.links_count == 0
    assert not any("/ignored-inside-json" in p.url for p in result.pages)


@pytest.mark.asyncio
async def test_crawl_http_errors_isolated_without_crashing(mock_dns_resolver):
    """Verify that HTTP 404, 500, and connection errors do not abort the crawl."""

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url == "https://example.com/":
            return httpx.Response(
                200,
                headers={"Content-Type": "text/html"},
                text=(
                    '<a href="/notfound">404</a><a href="/servererror">500</a><a href="/ok">OK</a>'
                ),
            )
        if url == "https://example.com/notfound":
            return httpx.Response(404, text="Not Found")
        if url == "https://example.com/servererror":
            return httpx.Response(500, text="Internal Error")
        if url == "https://example.com/ok":
            return httpx.Response(200, headers={"Content-Type": "text/html"}, text="OK Page")
        return httpx.Response(404, text="Not Found")

    transport = httpx.MockTransport(handler)
    result = await crawl(
        target_url="https://example.com/",
        max_depth=2,
        transport=transport,
        dns_resolver=mock_dns_resolver,
    )

    assert result.successful_count == 2  # / and /ok
    assert result.failed_count == 2  # /notfound and /servererror
    assert len(result.pages) == 4


@pytest.mark.asyncio
async def test_crawl_timeout_error_isolated(mock_dns_resolver):
    """Verify timeouts on individual pages are caught and recorded without aborting the crawl."""

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url == "https://example.com/":
            return httpx.Response(
                200,
                headers={"Content-Type": "text/html"},
                text='<a href="/hang">Hang</a><a href="/fast">Fast</a>',
            )
        if url == "https://example.com/hang":
            raise httpx.ReadTimeout("Socket read timed out")
        if url == "https://example.com/fast":
            return httpx.Response(200, headers={"Content-Type": "text/html"}, text="Fast OK")
        return httpx.Response(404, text="Not Found")

    transport = httpx.MockTransport(handler)
    result = await crawl(
        target_url="https://example.com/",
        max_depth=2,
        transport=transport,
        dns_resolver=mock_dns_resolver,
    )

    assert result.successful_count == 2
    assert result.failed_count == 1
    hang_page = next(p for p in result.pages if "/hang" in p.url)
    assert hang_page.error is not None
    assert "Timeout" in hang_page.error


@pytest.mark.asyncio
async def test_crawl_runtime_limit_exceeded(mock_dns_resolver):
    """Verify that exceeding total crawl runtime stops further scheduling."""

    async def async_handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url == "https://example.com/":
            return httpx.Response(
                200,
                headers={"Content-Type": "text/html"},
                text='<a href="/slow1">S1</a><a href="/slow2">S2</a>',
            )
        await asyncio.sleep(0.3)
        return httpx.Response(200, headers={"Content-Type": "text/html"}, text="Slow OK")

    transport = httpx.MockTransport(async_handler)
    result = await crawl(
        target_url="https://example.com/",
        max_depth=3,
        max_runtime_seconds=0.1,  # Short runtime cap
        transport=transport,
        dns_resolver=mock_dns_resolver,
    )

    assert result.limit_reached == CrawlLimitReason.RUNTIME_LIMIT


@pytest.mark.asyncio
async def test_crawl_cancellation_cleans_up(mock_dns_resolver):
    """Verify task cancellation sets cancelled status and cleans up resources."""

    async def infinite_hang(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(100.0)
        return httpx.Response(200, text="Never")

    transport = httpx.MockTransport(infinite_hang)
    crawl_task = asyncio.create_task(
        crawl(
            target_url="https://example.com/",
            max_depth=2,
            transport=transport,
            dns_resolver=mock_dns_resolver,
        )
    )

    await asyncio.sleep(0.05)
    crawl_task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await crawl_task


@pytest.mark.asyncio
async def test_crawl_invalid_seed_url_fails_gracefully():
    """Verify malformed seed URLs return failed result safely without uncaught exception."""
    result = await crawl(
        target_url="javascript:alert(1)",
        max_depth=1,
    )
    assert result.successful_count == 0
    assert result.failed_count == 1
    assert result.pages[0].error is not None


@pytest.mark.asyncio
async def test_crawl_zero_live_network_or_dns_operations():
    """Prove that mock crawl executes with zero live network sockets or DNS queries."""
    with (
        patch("socket.getaddrinfo") as mock_addr,
        patch("socket.create_connection") as mock_conn,
        patch("httpcore.AsyncNetworkBackend.connect_tcp") as mock_tcp,
    ):
        result = await crawl(
            target_url="https://example.com/",
            max_depth=1,
            transport=httpx.MockTransport(
                lambda req: httpx.Response(200, headers={"Content-Type": "text/html"}, text="OK")
            ),
            dns_resolver=lambda host: ["93.184.216.34"],
        )
        assert len(result.pages) == 1
        mock_addr.assert_not_called()
        mock_conn.assert_not_called()
        mock_tcp.assert_not_called()

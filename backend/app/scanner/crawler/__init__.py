"""Crawler modules for bounded, same-origin web crawling."""

from app.scanner.crawler.extractor import (
    DEFAULT_MAX_HTML_CHARS,
    DEFAULT_MAX_LINK_LENGTH,
    DEFAULT_MAX_LINKS,
    DEFAULT_SUPPORTED_LINK_RELS,
    HTMLAnchorExtractor,
    extract_links,
)
from app.scanner.crawler.models import (
    CrawlConfig,
    CrawledPage,
    CrawlLimitReason,
    CrawlResult,
)
from app.scanner.crawler.normalizer import (
    DEFAULT_ALLOWED_PORTS,
    MAX_URL_LENGTH,
    CrawlerUrlError,
    EffectiveOrigin,
    get_effective_origin,
    get_effective_port,
    is_same_origin,
    normalize_crawler_url,
    remove_dot_segments,
    resolve_and_normalize_url,
)
from app.scanner.crawler.service import (
    BoundedCrawler,
    SameOriginScopePolicy,
    crawl,
)

__all__ = [
    "DEFAULT_ALLOWED_PORTS",
    "DEFAULT_MAX_HTML_CHARS",
    "DEFAULT_MAX_LINKS",
    "DEFAULT_MAX_LINK_LENGTH",
    "DEFAULT_SUPPORTED_LINK_RELS",
    "BoundedCrawler",
    "CrawlConfig",
    "CrawlLimitReason",
    "CrawlResult",
    "CrawledPage",
    "CrawlerUrlError",
    "EffectiveOrigin",
    "HTMLAnchorExtractor",
    "MAX_URL_LENGTH",
    "SameOriginScopePolicy",
    "crawl",
    "extract_links",
    "get_effective_origin",
    "get_effective_port",
    "is_same_origin",
    "normalize_crawler_url",
    "remove_dot_segments",
    "resolve_and_normalize_url",
]

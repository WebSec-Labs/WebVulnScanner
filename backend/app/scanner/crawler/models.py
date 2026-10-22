"""Data models for crawler configuration, crawled pages, and crawl results."""

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, computed_field, field_validator

from app.scanner.crawler.normalizer import MAX_URL_LENGTH


class CrawlLimitReason(StrEnum):
    """Reason why a crawl execution terminated."""

    PAGE_LIMIT = "page_limit_reached"
    DEPTH_LIMIT = "depth_limit_reached"
    RUNTIME_LIMIT = "runtime_limit_reached"
    REQUEST_LIMIT = "request_limit_reached"
    CANCELLED = "cancelled"
    QUEUE_EXHAUSTED = "queue_exhausted"


class CrawlConfig(BaseModel):
    """Validated configuration for bounded same-origin crawling."""

    target_url: str = Field(
        ...,
        min_length=1,
        max_length=MAX_URL_LENGTH,
        description="Starting seed URL for the crawl",
    )
    max_depth: int = Field(
        default=3,
        ge=1,
        le=5,
        description="Maximum crawl depth (0 is starting page)",
    )
    max_pages: int = Field(
        default=20,
        ge=1,
        le=100,
        description="Maximum unique pages to fetch",
    )
    max_runtime_seconds: float = Field(
        default=30.0,
        ge=0.1,
        le=120.0,
        description="Maximum total crawl runtime in seconds",
    )
    max_concurrency: int = Field(
        default=2,
        ge=1,
        le=2,
        description="Maximum concurrent requests (hard cap of 2 for this phase)",
    )
    max_url_length: int = Field(
        default=MAX_URL_LENGTH,
        ge=64,
        le=MAX_URL_LENGTH,
        description="Maximum allowed URL length in characters",
    )
    max_requests: int | None = Field(
        default=None,
        ge=1,
        description="Optional hard request budget limit",
    )
    request_overhead: int = Field(
        default=10,
        ge=0,
        le=50,
        description="Allowed request overhead for redirects and retries",
    )
    timeout_seconds: float = Field(
        default=10.0,
        ge=1.0,
        le=30.0,
        description="Per-request timeout in seconds",
    )
    max_response_bytes: int = Field(
        default=1_000_000,
        ge=1024,
        le=10_000_000,
        description="Maximum response size allowed per page in bytes",
    )

    @field_validator("target_url")
    @classmethod
    def validate_target_url(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError("Target URL cannot be empty or whitespace only")
        return stripped

    @property
    def effective_max_requests(self) -> int:
        """Total request budget, bounded by max_pages + request_overhead."""
        budget = self.max_pages + self.request_overhead
        if self.max_requests is not None:
            return min(self.max_requests, budget)
        return budget


class CrawledPage(BaseModel):
    """Metadata representing an individual page processed during the crawl."""

    url: str = Field(..., description="Normalized URL of the fetched page")
    depth: int = Field(..., ge=0, description="Crawl depth at which the page was processed")
    status_code: int | None = Field(
        default=None,
        description="HTTP status code if a response was received",
    )
    content_type: str | None = Field(
        default=None,
        description="Content-Type response header value if available",
    )
    links_count: int = Field(
        default=0,
        ge=0,
        description="Count of valid same-origin links discovered on this page",
    )
    error: str | None = Field(
        default=None,
        description="Non-sensitive error description if request or parsing failed",
    )
    response_time_seconds: float | None = Field(
        default=None,
        ge=0.0,
        description="Response duration in seconds if measured",
    )


class CrawlResult(BaseModel):
    """Aggregated outcome of a bounded crawl run."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    target_url: str = Field(..., description="Normalized starting seed URL")
    start_time: datetime | None = Field(default=None, description="UTC start timestamp")
    end_time: datetime | None = Field(default=None, description="UTC completion timestamp")
    duration_seconds: float = Field(
        default=0.0,
        ge=0.0,
        description="Total crawl execution duration in seconds",
    )
    total_requests: int = Field(
        default=0,
        ge=0,
        description="Total HTTP requests dispatched by the scanner client",
    )
    pages: list[CrawledPage] = Field(
        default_factory=list,
        description="List of all crawled page records in discovery order",
    )
    limit_reached: CrawlLimitReason | None = Field(
        default=None,
        description="Termination limit indicator",
    )
    extra_metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Optional non-sensitive diagnostic metadata",
    )
    responses: dict[str, Any] = Field(
        default_factory=dict,
        exclude=True,
        description="Internal mapping of URL to ScannerResponse for reuse by scanner engine",
    )

    @computed_field
    @property
    def successful_count(self) -> int:
        """Count of pages successfully fetched with 2xx/3xx HTTP status and no error."""
        return sum(
            1
            for p in self.pages
            if p.error is None and p.status_code is not None and 200 <= p.status_code < 400
        )

    @computed_field
    @property
    def failed_count(self) -> int:
        """Count of pages that failed with network errors, timeouts, or 4xx/5xx status."""
        return sum(
            1
            for p in self.pages
            if p.error is not None or (p.status_code is not None and p.status_code >= 400)
        )

    @property
    def successful_pages(self) -> list[CrawledPage]:
        """List of successfully fetched pages."""
        return [
            p
            for p in self.pages
            if p.error is None and p.status_code is not None and 200 <= p.status_code < 400
        ]

    @property
    def failed_pages(self) -> list[CrawledPage]:
        """List of failed page attempts."""
        return [
            p
            for p in self.pages
            if p.error is not None or (p.status_code is not None and p.status_code >= 400)
        ]

"""Data models for scanner findings, configurations, and results."""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class Severity(StrEnum):
    """Vulnerability finding severity levels."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def _missing_(cls, value: object):
        if isinstance(value, str):
            lower_val = value.lower()
            for member in cls:
                if member.value == lower_val:
                    return member
        return None


class CheckType(StrEnum):
    """Execution classification of a scanner check."""

    PASSIVE = "passive"
    ACTIVE = "active"

    @classmethod
    def _missing_(cls, value: object):
        if isinstance(value, str):
            lower_val = value.lower()
            for member in cls:
                if member.value == lower_val:
                    return member
        return None


class Finding(BaseModel):
    """Validated vulnerability finding model produced by scanner checks."""

    check_id: str = Field(..., min_length=1, max_length=100, description="Unique check identifier")
    title: str = Field(..., min_length=1, max_length=200, description="Finding summary title")
    severity: Severity = Field(..., description="Vulnerability severity level")
    url: str = Field(..., min_length=1, description="Target URL where finding was observed")
    evidence: str = Field(..., description="Observed evidence or diagnostic details")
    recommendation: str = Field(..., description="Remediation guidance for fixing the issue")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="UTC timestamp of when the finding was recorded",
    )
    extra_data: dict[str, Any] = Field(
        default_factory=dict,
        description="Optional structured metadata for machine-readable context",
    )

    @field_validator("check_id", "title", "url", mode="before")
    @classmethod
    def strip_and_validate_strings(cls, v: Any) -> Any:
        if isinstance(v, str):
            stripped = v.strip()
            if not stripped:
                raise ValueError("Field cannot be empty or whitespace only")
            return stripped
        return v


class ScanStatus(StrEnum):
    """Status lifecycle of a scan execution."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanResult(BaseModel):
    """Aggregated scan execution outcome and findings report."""

    target_url: str
    status: ScanStatus = ScanStatus.PENDING
    findings: list[Finding] = Field(default_factory=list)
    executed_checks: list[str] = Field(default_factory=list)
    check_errors: dict[str, str] = Field(default_factory=dict)
    total_requests: int = 0
    start_time: datetime | None = None
    end_time: datetime | None = None
    duration_seconds: float = 0.0
    scanned_pages: list[str] = Field(
        default_factory=list,
        description="List of page URLs successfully scanned",
    )
    failed_pages: list[dict[str, str]] = Field(
        default_factory=list,
        description="List of pages that failed crawl or scan with error details",
    )


class ScanConfig(BaseModel):
    """Execution configuration for a scan run."""

    target_url: str
    check_ids: list[str] | None = Field(
        default=None,
        description="Optional subset of check IDs to execute. Runs all if None.",
    )
    max_requests: int = Field(default=50, ge=1, le=500)
    timeout_seconds: float = Field(default=10.0, ge=1.0, le=60.0)
    connect_timeout_seconds: float = Field(default=5.0, ge=0.5, le=30.0)
    max_redirects: int = Field(default=5, ge=0, le=10)
    max_response_bytes: int = Field(default=1_000_000, ge=1024, le=10_000_000)
    max_concurrency: int = Field(default=5, ge=1, le=20)
    crawl_enabled: bool = Field(
        default=False,
        description="Whether to discover and scan same-origin pages using the crawler.",
    )
    max_depth: int = Field(
        default=2,
        ge=0,
        le=5,
        description="Maximum crawl depth for multi-page discovery (0 scans only target URL).",
    )
    max_pages: int = Field(
        default=10,
        ge=1,
        le=50,
        description="Maximum same-origin pages to crawl and scan.",
    )
    active_checks_enabled: bool = Field(
        default=False,
        description=(
            "Explicit authorization opt-in to execute active security checks. "
            "Disabled by default. Users must have explicit authorization to test targets."
        ),
    )

"""Schemas for scanner API requests and responses."""

from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.scanner.models import Finding, ScanStatus, Severity


class ScanCreateRequest(BaseModel):
    """Payload to initiate a new vulnerability scan."""

    model_config = ConfigDict(extra="forbid")

    target_url: str = Field(
        ...,
        min_length=1,
        max_length=2048,
        description="Target URL to assess (e.g. 'https://example.com')",
        examples=["https://example.com"],
    )
    check_ids: list[Annotated[str, Field(min_length=1, max_length=100)]] | None = Field(
        default=None,
        max_length=50,
        description=(
            "Optional subset of check IDs to execute. "
            "If None or omitted, runs all registered default checks."
        ),
    )
    max_requests: int = Field(
        default=50,
        ge=1,
        le=100,
        description="Maximum HTTP requests permitted for this scan session.",
    )
    timeout_seconds: float = Field(
        default=10.0,
        ge=1.0,
        le=30.0,
        description="Maximum request timeout in seconds.",
    )
    max_concurrency: int = Field(
        default=5,
        ge=1,
        le=10,
        description="Maximum concurrent check tasks for this scan.",
    )

    @field_validator("target_url")
    @classmethod
    def validate_target_url(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError("Target URL cannot be empty or whitespace only")
        return stripped


class CheckMetadataResponse(BaseModel):
    """Metadata describing a registered scanner check."""

    check_id: str = Field(..., description="Unique check identifier")
    name: str = Field(..., description="Human-readable check display name")
    description: str = Field(..., description="Description of security issues evaluated")
    severity: Severity = Field(..., description="Default vulnerability severity level")


class ScanResponse(BaseModel):
    """Aggregated scan execution outcome and findings report."""

    target_url: str = Field(..., description="Normalized target URL")
    status: ScanStatus = Field(..., description="Terminal lifecycle status of the scan")
    findings: list[Finding] = Field(
        default_factory=list,
        description="List of detected vulnerability findings",
    )
    executed_checks: list[str] = Field(
        default_factory=list,
        description="IDs of checks that completed execution",
    )
    check_errors: dict[str, str] = Field(
        default_factory=dict,
        description="Errors recorded by individual checks",
    )
    total_requests: int = Field(
        default=0,
        description="Total HTTP requests dispatched by the scanner client",
    )
    start_time: datetime | None = Field(
        default=None,
        description="UTC timestamp of scan initiation",
    )
    end_time: datetime | None = Field(
        default=None,
        description="UTC timestamp of scan completion",
    )
    duration_seconds: float = Field(
        default=0.0,
        description="Total execution duration in seconds",
    )

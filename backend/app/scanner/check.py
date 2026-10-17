"""Scanner check interface, metadata, and execution context."""

import asyncio
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, Field

from app.scanner.models import Finding, Severity

if TYPE_CHECKING:
    from app.scanner.client import ScannerHttpClient, ScannerResponse
    from app.scanner.scope import TargetScope


class CheckMetadata(BaseModel):
    """Metadata describing a scanner check module."""

    check_id: str = Field(..., min_length=1, max_length=100)
    name: str = Field(..., min_length=1, max_length=200)
    description: str = Field(..., min_length=1)
    severity: Severity = Field(default=Severity.INFO)


class ScanContext:
    """Runtime context provided to checks during scan execution."""

    def __init__(
        self,
        target_url: str,
        scope: "TargetScope",
        client: "ScannerHttpClient",
        extra: dict[str, Any] | None = None,
        baseline_response: "ScannerResponse | None" = None,
    ):
        self.target_url = target_url
        self.scope = scope
        self.client = client
        self.extra = extra or {}
        self._baseline_response = baseline_response
        self._baseline_error: Exception | None = None
        self._baseline_lock = asyncio.Lock()

    @property
    def has_baseline_response(self) -> bool:
        """Return True if a baseline response is already cached."""
        return self._baseline_response is not None

    @property
    def cached_baseline_response(self) -> "ScannerResponse | None":
        """Return the cached baseline response if available, or None."""
        return self._baseline_response

    async def get_baseline_response(self) -> "ScannerResponse":
        """Retrieve the shared baseline response safely across concurrent checks.

        - If a baseline response was already retrieved, returns it immediately.
        - If a prior baseline request failed, re-raises that error without retrying.
        - Concurrent callers share the single in-flight baseline request via an asyncio.Lock.
        - Does not bypass ScannerHttpClient, its scope policy, DNS pinning, or request budget.
        - Cancellation is propagated cleanly without caching CancelledError or leaking tasks.
        """
        if self._baseline_response is not None:
            return self._baseline_response
        if self._baseline_error is not None:
            raise self._baseline_error

        async with self._baseline_lock:
            if self._baseline_response is not None:
                return self._baseline_response
            if self._baseline_error is not None:
                raise self._baseline_error

            try:
                response = await self.client.get(self.target_url)
                self._baseline_response = response
                return response
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self._baseline_error = exc
                raise


class BaseCheck(ABC):
    """Abstract base class that all scanner checks must implement."""

    @property
    @abstractmethod
    def metadata(self) -> CheckMetadata:
        """Return metadata defining check identifier, name, and severity."""
        ...

    @property
    def check_id(self) -> str:
        """Convenience property for accessing the check ID."""
        return self.metadata.check_id

    @abstractmethod
    async def run(self, context: ScanContext) -> list[Finding]:
        """Execute the check against the target and return any discovered findings."""
        ...

    def create_finding(
        self,
        url: str,
        evidence: str,
        recommendation: str,
        title: str | None = None,
        severity: Severity | None = None,
        extra_data: dict[str, Any] | None = None,
    ) -> Finding:
        """Helper to create a validated Finding using the check's metadata."""
        return Finding(
            check_id=self.metadata.check_id,
            title=title or self.metadata.name,
            severity=severity or self.metadata.severity,
            url=url,
            evidence=evidence,
            recommendation=recommendation,
            extra_data=extra_data or {},
        )

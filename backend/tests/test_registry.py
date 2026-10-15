"""Unit tests for CheckRegistry and BaseCheck interface."""

import pytest

from app.scanner.check import BaseCheck, CheckMetadata, ScanContext
from app.scanner.models import Finding, Severity
from app.scanner.registry import (
    CheckNotFoundError,
    CheckRegistry,
    DuplicateCheckIdError,
    InvalidCheckError,
)


class DummyHeaderCheck(BaseCheck):
    """Sample check for testing registry and interface."""

    @property
    def metadata(self) -> CheckMetadata:
        return CheckMetadata(
            check_id="sec_headers",
            name="Security Headers Check",
            description="Inspects presence of standard security headers.",
            severity=Severity.LOW,
        )

    async def run(self, context: ScanContext) -> list[Finding]:
        return [
            self.create_finding(
                url=context.target_url,
                evidence="Missing HSTS header",
                recommendation="Add Strict-Transport-Security.",
            )
        ]


class AnotherCheck(BaseCheck):
    """Another check for testing deterministic ordering."""

    @property
    def metadata(self) -> CheckMetadata:
        return CheckMetadata(
            check_id="cors_misconfig",
            name="CORS Policy Check",
            description="Checks for overly permissive CORS headers.",
            severity=Severity.MEDIUM,
        )

    async def run(self, context: ScanContext) -> list[Finding]:
        return []


def test_registry_register_and_get():
    """Verify check registration by instance and retrieval."""
    registry = CheckRegistry()
    check = DummyHeaderCheck()
    registry.register(check)

    assert "sec_headers" in registry
    assert len(registry) == 1
    retrieved = registry.get("sec_headers")
    assert retrieved.check_id == "sec_headers"


def test_registry_register_class():
    """Verify check registration by class type."""
    registry = CheckRegistry()
    registry.register(DummyHeaderCheck)

    assert "sec_headers" in registry
    assert registry.get("sec_headers").check_id == "sec_headers"


def test_registry_duplicate_rejection():
    """Verify duplicate check IDs are rejected with DuplicateCheckIdError."""
    registry = CheckRegistry()
    registry.register(DummyHeaderCheck)

    with pytest.raises(DuplicateCheckIdError):
        registry.register(DummyHeaderCheck)


def test_registry_invalid_check_id():
    """Verify check IDs with invalid syntax are rejected."""

    class BadIdCheck(BaseCheck):
        @property
        def metadata(self) -> CheckMetadata:
            return CheckMetadata(
                check_id="INVALID_UPPERCASE",
                name="Bad Check",
                description="Invalid ID check",
            )

        async def run(self, context: ScanContext) -> list[Finding]:
            return []

    registry = CheckRegistry()
    with pytest.raises(InvalidCheckError):
        registry.register(BadIdCheck)


def test_registry_invalid_implementation():
    """Verify objects not inheriting from BaseCheck are rejected."""
    registry = CheckRegistry()

    class NotACheck:
        pass

    with pytest.raises(InvalidCheckError):
        registry.register(NotACheck)  # type: ignore

    with pytest.raises(InvalidCheckError):
        registry.register("some_string")  # type: ignore


def test_registry_deterministic_ordering():
    """Verify that list_checks returns checks sorted alphabetically by check_id."""
    registry = CheckRegistry()
    # Register in non-alphabetical order
    registry.register(DummyHeaderCheck)  # id: "sec_headers"
    registry.register(AnotherCheck)  # id: "cors_misconfig"

    check_ids = registry.list_check_ids()
    assert check_ids == ["cors_misconfig", "sec_headers"]

    checks = registry.list_checks()
    assert [c.check_id for c in checks] == ["cors_misconfig", "sec_headers"]


def test_registry_not_found():
    """Verify lookup of nonexistent check raises CheckNotFoundError."""
    registry = CheckRegistry()
    with pytest.raises(CheckNotFoundError):
        registry.get("nonexistent")


def test_registry_unregister_and_clear():
    """Verify unregister and clear operations."""
    registry = CheckRegistry()
    registry.register(DummyHeaderCheck)
    registry.register(AnotherCheck)

    assert len(registry) == 2
    registry.unregister("sec_headers")
    assert len(registry) == 1
    assert "sec_headers" not in registry

    registry.clear()
    assert len(registry) == 0

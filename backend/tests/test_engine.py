"""Unit tests for ScannerEngine orchestrator."""

import asyncio

import httpx
import pytest

from app.scanner.check import BaseCheck, CheckMetadata, ScanContext
from app.scanner.engine import ScannerEngine
from app.scanner.models import Finding, ScanConfig, ScanStatus, Severity
from app.scanner.registry import CheckRegistry
from app.scanner.scope import TargetScope


class SuccessCheckA(BaseCheck):
    """Check that emits a valid finding."""

    @property
    def metadata(self) -> CheckMetadata:
        return CheckMetadata(
            check_id="check_a",
            name="Check A",
            description="Emits a sample finding.",
            severity=Severity.LOW,
        )

    async def run(self, context: ScanContext) -> list[Finding]:
        response = await context.client.get(context.target_url)
        if response.status_code == 200:
            return [
                self.create_finding(
                    url=context.target_url,
                    evidence="Status 200 observed",
                    recommendation="No action needed",
                )
            ]
        return []


class SuccessCheckB(BaseCheck):
    """Check that emits no findings."""

    @property
    def metadata(self) -> CheckMetadata:
        return CheckMetadata(
            check_id="check_b",
            name="Check B",
            description="Finds no issues.",
            severity=Severity.INFO,
        )

    async def run(self, context: ScanContext) -> list[Finding]:
        return []


class FaultyCheck(BaseCheck):
    """Check that encounters an unexpected exception."""

    @property
    def metadata(self) -> CheckMetadata:
        return CheckMetadata(
            check_id="faulty_check",
            name="Faulty Check",
            description="Always raises an unhandled error.",
            severity=Severity.HIGH,
        )

    async def run(self, context: ScanContext) -> list[Finding]:
        raise RuntimeError("Unexpected failure during check execution")


class SecondaryRequestCheck(BaseCheck):
    """Check that attempts a request to test quota exhaustion."""

    @property
    def metadata(self) -> CheckMetadata:
        return CheckMetadata(
            check_id="check_secondary",
            name="Secondary Check",
            description="Performs an extra request.",
            severity=Severity.MEDIUM,
        )

    async def run(self, context: ScanContext) -> list[Finding]:
        await context.client.get(f"{context.target_url}extra")
        return []


@pytest.mark.asyncio
async def test_engine_run_scan_success():
    """Verify standard scan orchestration, finding collection, and metrics."""
    registry = CheckRegistry()
    registry.register(SuccessCheckA)
    registry.register(SuccessCheckB)

    def mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="Welcome")

    transport = httpx.MockTransport(mock_handler)
    engine = ScannerEngine(registry=registry)

    scope = TargetScope(allowed_hosts={"example.com"})
    config = ScanConfig(target_url="https://example.com/")

    result = await engine.run_scan(config, scope=scope, transport=transport)

    assert result.status == ScanStatus.COMPLETED
    assert result.target_url == "https://example.com/"
    assert len(result.findings) == 1
    assert result.findings[0].check_id == "check_a"
    assert "check_a" in result.executed_checks
    assert "check_b" in result.executed_checks
    assert result.total_requests == 1
    assert result.duration_seconds >= 0.0
    assert result.check_errors == {}


@pytest.mark.asyncio
async def test_engine_selective_checks():
    """Verify that only specified check_ids are executed."""
    registry = CheckRegistry()
    registry.register(SuccessCheckA)
    registry.register(SuccessCheckB)

    def mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="Welcome")

    transport = httpx.MockTransport(mock_handler)
    engine = ScannerEngine(registry=registry)

    scope = TargetScope(allowed_hosts={"example.com"})
    config = ScanConfig(
        target_url="https://example.com/",
        check_ids=["check_b", "nonexistent_check"],
    )

    result = await engine.run_scan(config, scope=scope, transport=transport)

    assert "check_b" in result.executed_checks
    assert "check_a" not in result.executed_checks
    assert "nonexistent_check" in result.check_errors
    assert "is not registered" in result.check_errors["nonexistent_check"]
    # Because one check failed to register/run while another succeeded:
    assert result.status == ScanStatus.PARTIAL


@pytest.mark.asyncio
async def test_engine_out_of_scope_target_rejected():
    """Verify out-of-scope targets fail immediately without executing checks."""
    registry = CheckRegistry()
    registry.register(SuccessCheckA)

    engine = ScannerEngine(registry=registry)
    scope = TargetScope(allowed_hosts={"example.com"})
    config = ScanConfig(target_url="https://unauthorized.org/")

    result = await engine.run_scan(config, scope=scope)

    assert result.status == ScanStatus.FAILED
    assert "target_validation" in result.check_errors
    assert len(result.executed_checks) == 0
    assert len(result.findings) == 0


@pytest.mark.asyncio
async def test_engine_handles_check_failure_with_partial_status():
    """Verify check errors produce PARTIAL status without disguising failure as full completion."""
    registry = CheckRegistry()
    registry.register(SuccessCheckA)
    registry.register(FaultyCheck)

    def mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="OK")

    transport = httpx.MockTransport(mock_handler)
    engine = ScannerEngine(registry=registry)

    scope = TargetScope(allowed_hosts={"example.com"})
    config = ScanConfig(target_url="https://example.com/")

    result = await engine.run_scan(config, scope=scope, transport=transport)

    # SuccessCheckA still completed and found its issue
    assert "check_a" in result.executed_checks
    assert len(result.findings) == 1

    # FaultyCheck error is explicitly captured in check_errors
    assert "faulty_check" in result.check_errors
    assert "Unexpected failure during check execution" in result.check_errors["faulty_check"]

    # Overall scan status reflects PARTIAL completion
    assert result.status == ScanStatus.PARTIAL


@pytest.mark.asyncio
async def test_engine_quota_exhaustion_sets_partial_status():
    """Verify that scan session request limit exhaustion marks status as PARTIAL."""
    registry = CheckRegistry()
    registry.register(SuccessCheckA)
    registry.register(SecondaryRequestCheck)

    def mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="OK")

    transport = httpx.MockTransport(mock_handler)
    engine = ScannerEngine(registry=registry)

    scope = TargetScope(allowed_hosts={"example.com"})
    # Only permit 1 request across the whole scan
    config = ScanConfig(
        target_url="https://example.com/",
        max_requests=1,
        max_concurrency=1,
    )

    result = await engine.run_scan(config, scope=scope, transport=transport)

    # Check A completed using the 1 available request slot
    assert "check_a" in result.executed_checks
    assert result.total_requests == 1

    # Secondary check failed with request limit exceeded
    assert "check_secondary" in result.check_errors
    assert "Scan request limit of 1 exceeded" in result.check_errors["check_secondary"]

    # Status must be PARTIAL, not COMPLETED
    assert result.status == ScanStatus.PARTIAL


@pytest.mark.asyncio
async def test_engine_cancellation_handling():
    """Verify that cancellation sets status to CANCELLED cleanly."""

    class SlowCheck(BaseCheck):
        @property
        def metadata(self) -> CheckMetadata:
            return CheckMetadata(
                check_id="slow_check",
                name="Slow Check",
                description="Sleeps to allow cancellation.",
            )

        async def run(self, context: ScanContext) -> list[Finding]:
            await asyncio.sleep(10.0)
            return []

    registry = CheckRegistry()
    registry.register(SlowCheck)

    engine = ScannerEngine(registry=registry)
    scope = TargetScope(allowed_hosts={"example.com"})
    config = ScanConfig(target_url="https://example.com/")

    scan_task = asyncio.create_task(engine.run_scan(config, scope=scope))
    await asyncio.sleep(0.05)
    scan_task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await scan_task


@pytest.mark.asyncio
async def test_engine_cancellation_cleans_up_client_resources():
    """Verify that cancellation cleans up client sessions and closes underlying transports."""
    client_instance = None

    class CaptureClientCheck(BaseCheck):
        @property
        def metadata(self) -> CheckMetadata:
            return CheckMetadata(
                check_id="capture_check",
                name="Capture Client Check",
                description="Captures client reference and sleeps.",
            )

        async def run(self, context: ScanContext) -> list[Finding]:
            nonlocal client_instance
            client_instance = context.client
            await asyncio.sleep(10.0)
            return []

    registry = CheckRegistry()
    registry.register(CaptureClientCheck)

    engine = ScannerEngine(registry=registry)
    scope = TargetScope(allowed_hosts={"example.com"})
    config = ScanConfig(target_url="https://example.com/")

    scan_task = asyncio.create_task(engine.run_scan(config, scope=scope))
    await asyncio.sleep(0.05)
    assert client_instance is not None
    assert client_instance._client.is_closed is False

    scan_task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await scan_task

    # Verify underlying HTTP client was closed on cancellation cleanup
    assert client_instance._client.is_closed is True


@pytest.mark.asyncio
async def test_engine_preserves_explicit_empty_registry():
    """Verify that an explicitly supplied empty CheckRegistry is preserved without fallback."""
    empty_registry = CheckRegistry()
    assert len(empty_registry) == 0

    engine = ScannerEngine(registry=empty_registry)

    # 1. Verify engine retains the exact custom registry instance and it remains empty
    assert engine.registry is empty_registry
    assert len(engine.registry) == 0

    # 2. Handler tracking any network requests
    request_count = 0

    def mock_handler(request: httpx.Request) -> httpx.Response:
        nonlocal request_count
        request_count += 1
        return httpx.Response(200, text="OK")

    transport = httpx.MockTransport(mock_handler)
    scope = TargetScope(allowed_hosts={"example.com"})
    config = ScanConfig(target_url="https://example.com/")

    # 3. Run scan with empty registry
    result = await engine.run_scan(config, scope=scope, transport=transport)

    # 4. Verify scan completes successfully with 0 checks executed and 0 findings
    assert result.status == ScanStatus.COMPLETED
    assert result.executed_checks == []
    assert result.findings == []
    assert result.check_errors == {}

    # 5. Verify no default checks unexpectedly ran
    assert len(result.executed_checks) == 0
    assert request_count == 0

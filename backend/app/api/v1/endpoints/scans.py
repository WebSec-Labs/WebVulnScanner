"""Endpoint for orchestrating safe vulnerability scans.

Concurrency Note:
    Scan concurrency is limited to 10 concurrent executions per worker process
    using an asyncio.Semaphore tied to the application lifecycle on app.state.
    Multiple worker processes scale aggregate capacity proportionally.
    Distributed rate limiting and background queues are deferred to future phases.
"""

import asyncio
import logging
from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.scanner.client import ScannerTimeoutError
from app.scanner.engine import ScannerEngine
from app.scanner.models import ScanConfig
from app.scanner.registry import default_registry
from app.scanner.scope import (
    InvalidTargetUrlError,
    ScopeError,
    ScopePolicy,
    SSRFProhibitedError,
    TargetNotAuthorizedError,
    TargetScope,
    normalize_url,
)
from app.schemas.scan import ScanCreateRequest, ScanResponse

logger = logging.getLogger(__name__)

router = APIRouter()


async def get_scan_semaphore(request: Request) -> asyncio.Semaphore:
    """Return the scan concurrency semaphore bound to the application lifecycle.

    Enforces the intended limit of 10 concurrent scans per worker process.
    If invoked outside a managed lifespan (e.g. lightweight test harnesses),
    falls back to a cleanly loop-bound semaphore on app.state, avoiding
    accumulation or retention of closed event loops.
    """
    current_loop = asyncio.get_running_loop()
    sem = getattr(request.app.state, "scan_semaphore", None)
    if sem is None or getattr(sem, "_loop", None) is not current_loop:
        sem = asyncio.Semaphore(10)
        request.app.state.scan_semaphore = sem
    return sem


def get_scan_transport() -> httpx.AsyncBaseTransport | None:
    """Dependency provider for HTTP transport. Returns None for standard safe network backend."""
    return None


def get_dns_resolver() -> Callable[[str], list[str]] | None:
    """Dependency provider for synchronous DNS resolution."""
    return None


def get_async_dns_resolver() -> Callable[[str], Any] | None:
    """Dependency provider for asynchronous DNS resolution."""
    return None


@router.post(
    "",
    response_model=ScanResponse,
    status_code=status.HTTP_200_OK,
    summary="Execute security scan against target URL",
    description=(
        "Initiates and completes a defensive passive security scan against an authorized target. "
        "Enforces strict SSRF prevention, DNS pinning, and target-scope boundaries."
    ),
    responses={
        400: {"description": "Malformed URL, unsupported scheme, or unknown check ID"},
        422: {"description": "Target address is prohibited (private, loopback, or metadata)"},
        500: {"description": "Internal scanner execution error"},
        504: {"description": "Scan execution timed out against target host"},
    },
)
async def create_scan(
    payload: ScanCreateRequest,
    semaphore: asyncio.Semaphore = Depends(get_scan_semaphore),
    transport: httpx.AsyncBaseTransport | None = Depends(get_scan_transport),
    dns_resolver: Callable[[str], list[str]] | None = Depends(get_dns_resolver),
    async_dns_resolver: Callable[[str], Any] | None = Depends(get_async_dns_resolver),
) -> ScanResponse:
    """Validate target, enforce SSRF guardrails, and execute passive scanner checks."""
    # 1. URL Normalization and Syntax Validation
    try:
        normalized_url = normalize_url(payload.target_url)
    except InvalidTargetUrlError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid target URL: {exc}",
        ) from exc

    parsed = urlsplit(normalized_url)
    if not parsed.hostname:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Target URL must contain a valid hostname",
        )

    clean_hostname = parsed.hostname.rstrip(".").lower()

    # 2. Scope Construction — strictly bounded to submitted target host
    target_scope = TargetScope(
        allowed_hosts={clean_hostname},
        allow_subdomains=False,
        allow_local_lab_targets=False,
    )

    policy = ScopePolicy(
        scope=target_scope,
        dns_resolver=dns_resolver,
        async_dns_resolver=async_dns_resolver,
    )

    # 3. Asynchronous Scope & SSRF Policy Validation
    try:
        validated_url = await policy.validate_url_async(normalized_url)
    except SSRFProhibitedError as exc:
        logger.warning("SSRF blocked for host '%s': %s", clean_hostname, exc)
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Target destination is prohibited by SSRF security policy",
        ) from exc
    except TargetNotAuthorizedError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"Target is outside authorized scope: {exc}",
        ) from exc
    except InvalidTargetUrlError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Target URL validation or DNS resolution failed: {exc}",
        ) from exc
    except ScopeError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"Target scope policy violation: {exc}",
        ) from exc

    # 4. Validate requested check IDs against registered default checks
    if payload.check_ids is not None:
        registered_ids = default_registry.list_check_ids()
        unknown_ids = [cid for cid in payload.check_ids if cid not in default_registry]
        if unknown_ids:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unknown check IDs: {unknown_ids}. Available checks: {registered_ids}",
            )

    # 5. Build bounded scan configuration
    config = ScanConfig(
        target_url=validated_url,
        check_ids=payload.check_ids,
        max_requests=payload.max_requests,
        timeout_seconds=payload.timeout_seconds,
        max_concurrency=payload.max_concurrency,
    )

    # 6. Execute scan through ScannerEngine with concurrency bounding
    engine = ScannerEngine(registry=default_registry)

    try:
        async with semaphore:
            result = await engine.run_scan(
                config=config,
                scope=target_scope,
                transport=transport,
            )
    except (TimeoutError, ScannerTimeoutError) as exc:
        logger.warning("Scan execution timed out for host '%s': %s", clean_hostname, exc)
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail="Scan execution timed out against target host",
        ) from exc
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        logger.exception("Unexpected error during scan execution: %s", type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An internal error occurred during scan execution",
        ) from exc

    return ScanResponse(
        target_url=result.target_url,
        status=result.status,
        findings=result.findings,
        executed_checks=result.executed_checks,
        check_errors=result.check_errors,
        total_requests=result.total_requests,
        start_time=result.start_time,
        end_time=result.end_time,
        duration_seconds=result.duration_seconds,
    )

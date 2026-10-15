"""Tests for API health endpoints."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_root_endpoint(async_client: AsyncClient):
    """Verify that root endpoint returns successful status and metadata."""
    response = await async_client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert "version" in data
    assert "docs" in data
    assert data["health"] == "/health"


@pytest.mark.asyncio
async def test_health_endpoint(async_client: AsyncClient):
    """Verify that /health endpoint reports ok status."""
    response = await async_client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["app"] == "WebVulnScanner"
    assert data["environment"] == "development"


@pytest.mark.asyncio
async def test_api_v1_health_endpoint(async_client: AsyncClient):
    """Verify that /api/v1/health endpoint reports ok status."""
    response = await async_client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["app"] == "WebVulnScanner"

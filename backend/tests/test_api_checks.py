"""Unit and integration tests for GET /api/v1/checks endpoint."""

import pytest
from httpx import AsyncClient

from app.scanner.registry import default_registry


@pytest.mark.asyncio
async def test_get_checks_success(async_client: AsyncClient):
    """Verify that /api/v1/checks returns all registered checks with expected metadata."""
    response = await async_client.get("/api/v1/checks")
    assert response.status_code == 200
    data = response.json()

    assert isinstance(data, list)
    assert len(data) == len(default_registry)

    # Verify deterministic sorting matches registry's alphabetical check_ids
    expected_ids = default_registry.list_check_ids()
    returned_ids = [c["check_id"] for c in data]
    assert returned_ids == expected_ids
    assert returned_ids == [
        "cookie_security",
        "cors_security",
        "https_configuration",
        "security_headers",
    ]


@pytest.mark.asyncio
async def test_get_checks_metadata_fields(async_client: AsyncClient):
    """Verify that each check in /api/v1/checks contains genuine, non-fabricated metadata."""
    response = await async_client.get("/api/v1/checks")
    assert response.status_code == 200
    data = response.json()

    for item in data:
        assert "check_id" in item
        assert "name" in item
        assert "description" in item
        assert "severity" in item
        assert item["check_id"] in default_registry

        # Verify values align with the underlying check's CheckMetadata
        underlying = default_registry.get(item["check_id"])
        meta = underlying.metadata
        assert item["check_id"] == meta.check_id
        assert item["name"] == meta.name
        assert item["description"] == meta.description
        assert item["severity"] == meta.severity.value

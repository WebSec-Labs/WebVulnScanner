"""Endpoint for discovering registered scanner checks."""

from fastapi import APIRouter

from app.scanner.registry import default_active_registry, default_registry
from app.schemas.scan import CheckMetadataResponse

router = APIRouter()


@router.get(
    "",
    response_model=list[CheckMetadataResponse],
    summary="List registered scanner checks",
    description=(
        "Retrieve metadata for all checks registered in the default registry "
        "sorted deterministically by check ID."
    ),
)
async def list_checks(include_active: bool = False) -> list[CheckMetadataResponse]:
    """Return all registered checks with their genuine metadata."""
    checks = default_registry.list_checks()
    if include_active:
        checks = sorted(checks + default_active_registry.list_checks(), key=lambda c: c.check_id)
    return [
        CheckMetadataResponse(
            check_id=c.metadata.check_id,
            name=c.metadata.name,
            description=c.metadata.description,
            severity=c.metadata.severity,
            check_type=c.metadata.check_type,
        )
        for c in checks
    ]

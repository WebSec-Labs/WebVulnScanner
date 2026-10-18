"""API v1 router aggregating all endpoint subrouters."""

from fastapi import APIRouter

from app.api.v1.endpoints import checks, scans

api_router = APIRouter()
api_router.include_router(scans.router, prefix="/scans", tags=["Scans"])
api_router.include_router(checks.router, prefix="/checks", tags=["Checks"])

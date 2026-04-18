"""v1 API router aggregator."""

from fastapi import APIRouter, Depends

from app.api.v1 import (
    assets,
    audit_logs,
    auth,
    findings,
    ratings,
    reports,
    scan_schedules,
    scans,
    tenants,
    users,
)
from app.core.dependencies import get_current_user
from app.schemas.user import UserRead

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(auth.router)
api_router.include_router(tenants.router)
api_router.include_router(assets.router)
api_router.include_router(scans.router)
api_router.include_router(scan_schedules.router)
api_router.include_router(findings.router)
api_router.include_router(ratings.router)
api_router.include_router(reports.router)
api_router.include_router(users.router)
api_router.include_router(audit_logs.router)


@api_router.get("/me", response_model=UserRead, tags=["meta"])
async def read_current_user(user=Depends(get_current_user)) -> UserRead:
    """Echo back the authenticated user — used by frontend to bootstrap session."""
    return UserRead.model_validate(user)

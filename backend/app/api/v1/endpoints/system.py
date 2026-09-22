from fastapi import APIRouter, Depends

from app.auth.dependencies import require_roles
from app.auth.models import LocalUser, UserRole
from app.db.database import check_database_health
from app.schemas.history import DatabaseStatusResponse
from app.schemas.system import SystemStatusResponse
from app.services.system_service import SystemService, get_system_service

router = APIRouter()


@router.get("/status", response_model=SystemStatusResponse)
async def get_system_status(
    system_service: SystemService = Depends(get_system_service),
) -> SystemStatusResponse:
    return system_service.get_status()


@router.get("/database", response_model=DatabaseStatusResponse)
async def get_database_status(
    _user: LocalUser = Depends(require_roles(UserRole.VIEWER, UserRole.ANALYST, UserRole.OPERATOR, UserRole.ADMIN)),
) -> DatabaseStatusResponse:
    info = check_database_health()
    return DatabaseStatusResponse(**info)

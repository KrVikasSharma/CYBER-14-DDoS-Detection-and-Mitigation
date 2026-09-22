from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.auth.dependencies import require_roles
from app.auth.models import LocalUser, UserRole
from app.db.database import get_db
from app.db.repository import get_mitigation_history
from app.schemas.history import PaginatedMitigationResponse

router = APIRouter()


@router.get(
    "/history",
    response_model=PaginatedMitigationResponse,
    status_code=status.HTTP_200_OK,
    summary="Get paginated simulation mitigation history",
)
async def list_mitigation_history(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    action: str | None = Query(default=None),
    status_filter: str | None = Query(default=None, alias="status"),
    attack_type: str | None = Query(default=None),
    start_date: datetime | None = Query(default=None),
    end_date: datetime | None = Query(default=None),
    db: Session = Depends(get_db),
    _user: LocalUser = Depends(require_roles(UserRole.VIEWER, UserRole.ANALYST, UserRole.OPERATOR, UserRole.ADMIN)),
) -> PaginatedMitigationResponse:
    try:
        data = get_mitigation_history(
            db=db,
            page=page,
            page_size=page_size,
            action=action,
            status=status_filter,
            attack_type=attack_type,
            start_date=start_date,
            end_date=end_date,
        )
        return PaginatedMitigationResponse(**data)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Database persistence error: {exc}",
        ) from exc

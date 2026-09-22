from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.auth.dependencies import require_roles
from app.auth.models import LocalUser, UserRole
from app.db.database import get_db
from app.db.repository import get_audit_logs
from app.schemas.history import PaginatedAuditLogsResponse

router = APIRouter()


@router.get(
    "/logs",
    response_model=PaginatedAuditLogsResponse,
    status_code=status.HTTP_200_OK,
    summary="Get paginated system and security audit logs",
)
async def list_audit_logs(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    event_type: str | None = Query(default=None),
    actor: str | None = Query(default=None),
    start_date: datetime | None = Query(default=None),
    end_date: datetime | None = Query(default=None),
    db: Session = Depends(get_db),
    _user: LocalUser = Depends(require_roles(UserRole.ANALYST, UserRole.OPERATOR, UserRole.ADMIN)),
) -> PaginatedAuditLogsResponse:
    try:
        data = get_audit_logs(
            db=db,
            page=page,
            page_size=page_size,
            event_type=event_type,
            actor=actor,
            start_date=start_date,
            end_date=end_date,
        )
        return PaginatedAuditLogsResponse(**data)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Database persistence error: {exc}",
        ) from exc

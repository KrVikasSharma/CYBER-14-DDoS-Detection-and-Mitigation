from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.auth.dependencies import require_roles
from app.auth.models import LocalUser, UserRole
from app.db.database import get_db
from app.db.repository import get_incident_by_id, get_incidents
from app.schemas.history import IncidentDetailResponse, PaginatedIncidentsResponse

router = APIRouter()


@router.get(
    "",
    response_model=PaginatedIncidentsResponse,
    status_code=status.HTTP_200_OK,
    summary="List attack incidents with search, filtering and server-side pagination",
)
async def list_incidents(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    search: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    status_filter: str | None = Query(default=None, alias="status"),
    attack_type: str | None = Query(default=None),
    source_ip: str | None = Query(default=None),
    start_date: datetime | None = Query(default=None),
    end_date: datetime | None = Query(default=None),
    db: Session = Depends(get_db),
    _user: LocalUser = Depends(require_roles(UserRole.VIEWER, UserRole.ANALYST, UserRole.OPERATOR, UserRole.ADMIN)),
) -> PaginatedIncidentsResponse:
    try:
        data = get_incidents(
            db=db,
            page=page,
            page_size=page_size,
            search=search,
            severity=severity,
            status=status_filter,
            attack_type=attack_type,
            source_ip=source_ip,
            start_date=start_date,
            end_date=end_date,
        )
        return PaginatedIncidentsResponse(**data)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Database persistence error: {exc}",
        ) from exc


@router.get(
    "/{incident_id}",
    response_model=IncidentDetailResponse,
    status_code=status.HTTP_200_OK,
    summary="Get incident detail by incident ID (e.g. INC-20260922-0001)",
)
async def get_incident(
    incident_id: str,
    db: Session = Depends(get_db),
    _user: LocalUser = Depends(require_roles(UserRole.VIEWER, UserRole.ANALYST, UserRole.OPERATOR, UserRole.ADMIN)),
) -> IncidentDetailResponse:
    try:
        data = get_incident_by_id(db=db, incident_id=incident_id)
        if not data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Incident '{incident_id}' was not found.",
            )
        return IncidentDetailResponse(**data)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Database persistence error: {exc}",
        ) from exc

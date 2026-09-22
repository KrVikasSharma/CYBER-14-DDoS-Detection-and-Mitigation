from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.auth.dependencies import require_roles
from app.auth.models import LocalUser, UserRole
from app.db.database import get_db
from app.db.repository import get_detections_history
from app.schemas.history import PaginatedDetectionsResponse

router = APIRouter()


@router.get(
    "/history",
    response_model=PaginatedDetectionsResponse,
    status_code=status.HTTP_200_OK,
    summary="Get paginated detection history",
)
async def list_detections_history(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    o2_label: int | None = Query(default=None),
    o3_label: str | None = Query(default=None),
    min_confidence: float | None = Query(default=None, ge=0.0, le=1.0),
    start_date: datetime | None = Query(default=None),
    end_date: datetime | None = Query(default=None),
    db: Session = Depends(get_db),
    _user: LocalUser = Depends(require_roles(UserRole.VIEWER, UserRole.ANALYST, UserRole.OPERATOR, UserRole.ADMIN)),
) -> PaginatedDetectionsResponse:
    try:
        data = get_detections_history(
            db=db,
            page=page,
            page_size=page_size,
            o2_label=o2_label,
            o3_label=o3_label,
            min_confidence=min_confidence,
            start_date=start_date,
            end_date=end_date,
        )
        return PaginatedDetectionsResponse(**data)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Database persistence error: {exc}",
        ) from exc

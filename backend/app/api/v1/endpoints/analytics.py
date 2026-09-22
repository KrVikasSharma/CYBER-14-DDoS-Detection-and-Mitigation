import logging
from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from app.auth.dependencies import get_current_user
from app.auth.models import LocalUser
from app.db.database import get_db
from app.db.repository import get_live_analytics_summary
from app.schemas.history import LiveAnalyticsResponse

logger = logging.getLogger(__name__)

router = APIRouter()


def get_active_connection_count() -> int:
    """Safely obtain active connection count without failing if ML models are uninitialized."""
    try:
        from app.services.streaming_service import get_streaming_service
        svc = get_streaming_service()
        return svc.connection_count()
    except Exception:
        return 0


@router.get(
    "/live",
    response_model=LiveAnalyticsResponse,
    status_code=status.HTTP_200_OK,
    summary="Get aggregated live and historical telemetry for continuous charts",
)
async def get_live_analytics(
    db: Session = Depends(get_db),
    _user: LocalUser = Depends(get_current_user),
) -> LiveAnalyticsResponse:
    """
    Returns live metrics summary including active connections,
    total requests, attack class distribution, and mitigation counts.
    """
    active_conn = get_active_connection_count()
    try:
        data = get_live_analytics_summary(db, active_connections=active_conn)
        return LiveAnalyticsResponse(**data)
    except Exception as exc:
        logger.warning(f"Unable to read live analytics from database: {exc}")
        # Safe fallback with active connection count
        return LiveAnalyticsResponse(
            total_requests=0,
            current_rate=0.0,
            active_connections=active_conn,
            unique_sources=0,
            detected_attacks=0,
            blocked=0,
            rate_limited=0,
            allow=0,
            attack_distribution={},
            mitigation_distribution={},
        )

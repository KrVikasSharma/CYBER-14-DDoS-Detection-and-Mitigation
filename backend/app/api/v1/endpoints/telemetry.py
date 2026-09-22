from fastapi import APIRouter, Depends

from app.auth.dependencies import require_roles
from app.auth.models import LocalUser, UserRole
from app.auth.config import get_auth_settings
from app.schemas.evidence import TelemetryResponse
from app.services.telemetry_service import telemetry_store
from app.core.config import get_settings

router = APIRouter()


@router.get("/telemetry", response_model=TelemetryResponse)
async def telemetry(
    _user: LocalUser = Depends(require_roles(UserRole.VIEWER, UserRole.ANALYST, UserRole.OPERATOR, UserRole.ADMIN)),
) -> TelemetryResponse:
    settings = get_settings()
    auth = get_auth_settings()
    snapshot = telemetry_store.snapshot()
    values = snapshot.pop("latencies")
    percentile = lambda fraction: float(values[min(len(values) - 1, round((len(values) - 1) * fraction))]) if values else None
    return TelemetryResponse(
        state="FIXTURE_ONLY" if settings.o2_fixture_only or settings.o3_fixture_only else "READY",
        **snapshot,
        average_latency_ms=sum(values) / len(values) if values else None,
        p50_latency_ms=percentile(0.50),
        p95_latency_ms=percentile(0.95),
        p99_latency_ms=percentile(0.99),
        websocket_connection_count=None,
        model_readiness="ready_fixture_only" if settings.o2_fixture_only or settings.o3_fixture_only else "ready",
        fixture_only=settings.o2_fixture_only or settings.o3_fixture_only,
        authentication_mode="local_demo" if auth.auth_enabled else "local_development",
    )

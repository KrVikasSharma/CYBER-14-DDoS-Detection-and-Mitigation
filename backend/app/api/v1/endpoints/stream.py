from fastapi import APIRouter, Depends, HTTPException, status

from app.auth.dependencies import require_roles
from app.auth.models import LocalUser, UserRole
from app.schemas.streaming import StreamSimulationRequest, StreamSimulationResponse
from app.services.streaming_service import (
    SimulatorDisabledError,
    StreamingMessageError,
    StreamingService,
    get_streaming_service,
)

router = APIRouter()


@router.post(
    "/simulate",
    response_model=StreamSimulationResponse,
    status_code=status.HTTP_200_OK,
    summary="Run controlled application-level streaming observations",
)
async def simulate_stream(
    request: StreamSimulationRequest,
    streaming_service: StreamingService = Depends(get_streaming_service),
    _user: LocalUser = Depends(require_roles(UserRole.OPERATOR, UserRole.ADMIN)),
) -> StreamSimulationResponse:
    try:
        return await streaming_service.simulate(request)
    except SimulatorDisabledError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except StreamingMessageError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

import json
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status

from app.auth.dependencies import require_roles
from app.auth.models import LocalUser, UserRole
from app.schemas.detection import DetectionAnalyzeRequest, DetectionAnalyzeResponse
from app.services.detection_service import (
    DetectionService,
    DetectionServiceError,
    IncompatibleModelError,
    ModelUnavailableError,
    PredictionFailureError,
    get_detection_service,
)

router = APIRouter()


@router.post(
    "/analyze",
    response_model=DetectionAnalyzeResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyze traffic and produce a simulation-only mitigation decision",
)
async def analyze_detection(
    request: DetectionAnalyzeRequest,
    detection_service: DetectionService = Depends(get_detection_service),
    _user: LocalUser = Depends(require_roles(UserRole.ANALYST, UserRole.OPERATOR, UserRole.ADMIN)),
) -> DetectionAnalyzeResponse:
    try:
        return detection_service.analyze(request)
    except ModelUnavailableError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc
    except IncompatibleModelError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc
    except PredictionFailureError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    except DetectionServiceError as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)) from exc


@router.get(
    "/demo-scenarios",
    summary="Get verified demo scenario feature payloads for presentation",
)
async def get_demo_scenarios(
    _user: LocalUser = Depends(require_roles(UserRole.ANALYST, UserRole.OPERATOR, UserRole.ADMIN)),
) -> dict[str, Any]:
    demo_path = Path("data/demo/demo_scenarios.json")
    if demo_path.exists():
        with open(demo_path, encoding="utf-8") as f:
            return json.load(f)
    return {}

from fastapi import APIRouter

from app.api.v1.endpoints import (
    analytics,
    audit,
    auth,
    detection,
    detections_history,
    evaluation,
    evidence,
    incidents,
    mitigation_history,
    stream,
    system,
    telemetry,
)

api_router = APIRouter()
api_router.include_router(auth.router, prefix="/auth", tags=["auth"])
api_router.include_router(evaluation.router, prefix="/evaluation", tags=["evaluation"])
api_router.include_router(evidence.router, prefix="/evidence", tags=["evidence"])
api_router.include_router(telemetry.router, prefix="/system", tags=["telemetry"])
api_router.include_router(system.router, prefix="/system", tags=["system"])
api_router.include_router(detection.router, prefix="/detection", tags=["detection"])
api_router.include_router(detections_history.router, prefix="/detections", tags=["detections"])
api_router.include_router(incidents.router, prefix="/incidents", tags=["incidents"])
api_router.include_router(mitigation_history.router, prefix="/mitigation", tags=["mitigation"])
api_router.include_router(audit.router, prefix="/audit", tags=["audit"])
api_router.include_router(stream.router, prefix="/stream", tags=["streaming"])
api_router.include_router(analytics.router, prefix="/analytics", tags=["analytics"])


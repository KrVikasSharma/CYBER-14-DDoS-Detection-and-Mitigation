from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.detection import DetectionAnalyzeRequest


class StreamErrorResponse(BaseModel):
    type: Literal["error"] = "error"
    request_id: UUID
    error_code: str
    message: str


class StreamDetectionResponse(BaseModel):
    type: Literal["detection_result"] = "detection_result"
    response: dict[str, Any]
    fixture_only: bool
    connection_id: str | None = None


class StreamSimulationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scenario: str = Field(..., min_length=1, max_length=64, description="Scenario to simulate")
    observations: int = Field(default=1, ge=1, le=100)
    interval_ms: int = Field(default=0, ge=0, le=1000)


class StreamSimulationResponse(BaseModel):
    type: Literal["simulation_result"] = "simulation_result"
    source: Literal["controlled_simulator"] = "controlled_simulator"
    scenario: str
    observation_count: int
    results: list[StreamDetectionResponse]

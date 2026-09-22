from datetime import datetime
import math
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


class FlowMetadata(BaseModel):
    model_config = ConfigDict(extra="ignore")

    source_ip: str | None = Field(default=None, description="Source IP address (observability metadata)")
    source_port: int | None = Field(default=None, description="Source port (observability metadata)")
    destination_ip: str | None = Field(default=None, description="Destination IP address (observability metadata)")
    destination_port: int | None = Field(default=None, description="Destination port (observability metadata)")
    protocol: str | None = Field(default=None, description="Transport protocol name (observability metadata)")
    timestamp: str | None = Field(default=None, description="Flow timestamp (observability metadata)")


class DetectionAnalyzeRequest(BaseModel):
    """Traffic features must match the configured O2/O3 artifact contracts exactly."""

    model_config = ConfigDict(extra="ignore")

    source_identifier: str = Field(min_length=1, max_length=255)
    traffic_rate: float | None = Field(default=None, ge=0.0, description="Observed traffic rate.")
    features: dict[str, float] = Field(
        min_length=1,
        max_length=128,
        description="Numeric feature values keyed by the configured model feature names.",
    )
    metadata: FlowMetadata | None = Field(default=None, description="Optional non-ML observability metadata.")
    source_ip: str | None = Field(default=None, description="Optional observability metadata.")
    source_port: int | None = Field(default=None, description="Optional observability metadata.")
    destination_ip: str | None = Field(default=None, description="Optional observability metadata.")
    destination_port: int | None = Field(default=None, description="Optional observability metadata.")
    protocol: str | None = Field(default=None, description="Optional observability metadata.")
    timestamp: str | None = Field(default=None, description="Optional observability metadata.")

    @field_validator("source_identifier")
    @classmethod
    def validate_source_identifier(cls, value: str) -> str:
        if value.strip() != value or any(ord(char) < 32 for char in value):
            raise ValueError("source_identifier must be printable with no surrounding whitespace")
        return value

    @field_validator("features")
    @classmethod
    def validate_features(cls, value: dict[str, float]) -> dict[str, float]:
        for name, feature_value in value.items():
            if not name or name.strip() != name or any(ord(char) < 32 for char in name):
                raise ValueError("feature names must be printable and have no surrounding whitespace")
            if not isinstance(feature_value, (int, float)) or isinstance(feature_value, bool):
                raise ValueError(f"feature {name!r} must be numeric")
            if not math.isfinite(feature_value):
                raise ValueError(f"feature {name!r} must be finite")
        return value

    @field_validator("traffic_rate")
    @classmethod
    def validate_traffic_rate(cls, value: float | None) -> float | None:
        if value is not None and not math.isfinite(value):
            raise ValueError("traffic_rate must be finite")
        return value


class BinaryDetectionResponse(BaseModel):
    model_config = ConfigDict(protected_namespaces=())

    detected: bool
    label: int
    confidence: float
    threshold: float = 0.50
    model_version: str


class ClassificationResponse(BaseModel):
    model_config = ConfigDict(protected_namespaces=())

    available: bool
    attack_type: str | None = None
    confidence: float | None = None
    probabilities: dict[str, float] | None = None
    threshold: float = 0.80
    decision_method: str = "argmax_posterior_probability"
    model_version: str | None = None


class MitigationResponse(BaseModel):
    decision: str
    reason: str
    decision_id: str
    policy_version: str
    state: str
    duration_seconds: int | None = None
    expires_at: datetime | None = None
    executor_type: str
    simulation_only: bool = True
    audit_event_id: str
    parameters: dict[str, Any] = Field(default_factory=dict)


class LatencyResponse(BaseModel):
    feature_preparation_ms: float
    o2_inference_ms: float
    o3_inference_ms: float
    mitigation_decision_ms: float
    total_analysis_ms: float
    measurement_scope: str = "local_operational_telemetry_not_cyber14_kpi"


class DetectionAnalyzeResponse(BaseModel):
    request_id: UUID
    timestamp: datetime
    source_identifier: str
    traffic_rate: float | None = None
    metadata: FlowMetadata = Field(default_factory=FlowMetadata)
    o2: BinaryDetectionResponse
    o3: ClassificationResponse
    mitigation: MitigationResponse
    latency: LatencyResponse
    artifact_scope: dict[str, Any]

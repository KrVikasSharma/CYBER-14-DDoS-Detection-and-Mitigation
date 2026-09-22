from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class DecisionAction(StrEnum):
    ALLOW = "ALLOW"
    RATE_LIMIT = "RATE_LIMIT"
    BLOCK = "BLOCK"


class MitigationState(StrEnum):
    ACTIVE = "ACTIVE"
    RECOVERED = "RECOVERED"
    REVOKED = "REVOKED"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class DetectionResult(BaseModel):
    """Validated O2/O3 result consumed by policy, not a model-training input."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    attack_type: str = Field(alias="detected_class", min_length=1, max_length=128)
    confidence: float = Field(ge=0.0, le=1.0)
    traffic_rate: float | None = Field(default=None, ge=0.0)
    source_identifier: str | None = Field(default=None, min_length=1, max_length=255)
    observed_at: datetime = Field(default_factory=utc_now)

    @field_validator("attack_type", "source_identifier")
    @classmethod
    def reject_control_characters(cls, value: str | None) -> str | None:
        if value is None:
            return value
        if value.strip() != value or any(ord(char) < 32 for char in value):
            raise ValueError("identifiers must be printable and have no surrounding whitespace")
        return value

    @field_validator("observed_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("observed_at must include timezone information")
        return value.astimezone(timezone.utc)


class MitigationDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision_id: str = Field(min_length=1)
    decision: DecisionAction
    reason: str = Field(min_length=1)
    attack_type: str
    confidence: float
    source_identifier: str | None = None
    created_at: datetime
    expires_at: datetime | None = None
    policy_version: str
    state: MitigationState = MitigationState.ACTIVE
    recovery_action: DecisionAction = DecisionAction.ALLOW
    parameters: dict[str, Any] = Field(default_factory=dict)


class ExecutionResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    executor_type: str
    action: DecisionAction
    success: bool
    executed_at: datetime
    error: str | None = None


class RecoveryRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision_id: str
    source_identifier: str | None = None
    previous_state: MitigationState
    new_state: MitigationState
    recovered_at: datetime
    reason: str


class AuditEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str
    event_type: str
    timestamp: datetime
    decision_id: str
    action: DecisionAction
    reason: str
    attack_type: str
    confidence: float
    source_identifier: str | None = None
    policy_version: str
    state_transition: str
    executor_type: str
    success: bool
    error: str | None = None
    expires_at: datetime | None = None

    def to_record(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

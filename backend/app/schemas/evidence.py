from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class StatusRecord(BaseModel):
    id: str
    name: str
    status: str
    description: str | None = None
    measured_value: float | int | str | None = None
    reference_value: float | int | str | None = None
    threshold: float | int | str | None = None
    unit: str | None = None
    trials: int | None = None
    condition: str | None = None
    evidence_available: bool = False
    official_result: bool = False
    fixture_only: bool = False
    reason: str | None = None
    run_id: str | None = None


class StatusCounts(BaseModel):
    total: int
    passed: int
    failed: int
    not_executed: int
    blocked: int


class EvidenceRun(BaseModel):
    run_id: str
    run_type: str
    created_at: str | None = None
    framework_version: str | None = None
    configuration_hash: str | None = None
    fixture_only: bool = False
    official_result: bool = False
    status: str
    artifact_names: list[str] = Field(default_factory=list)
    record_counts: dict[str, int] = Field(default_factory=dict)


class EvidenceSummary(BaseModel):
    state: str
    available_runs: int
    latest_run_id: str | None = None
    fixture_only: bool
    official_result_eligible: bool
    evidence_complete: bool
    generated_at: str | None = None
    counts: dict[str, int]


class AuditRecord(BaseModel):
    event_id: str
    event_type: str
    timestamp: str
    decision_id: str
    action: str
    reason: str
    attack_type: str
    confidence: float
    source_identifier: str | None = None
    policy_version: str
    state_transition: str
    executor_type: str
    success: bool
    error: str | None = None
    expires_at: str | None = None


class TelemetryResponse(BaseModel):
    model_config = ConfigDict(protected_namespaces=())

    state: str
    request_count: int
    detection_count: int
    mitigation_decision_counts: dict[str, int]
    error_count: int
    average_latency_ms: float | None = None
    p50_latency_ms: float | None = None
    p95_latency_ms: float | None = None
    p99_latency_ms: float | None = None
    websocket_connection_count: int | None = None
    simulator_events: int
    uptime_seconds: float | None = None
    model_readiness: str
    fixture_only: bool
    authentication_mode: str
    durable_store: bool = False
    limitation: str = "Process-local bounded telemetry; not a durable production metrics backend."

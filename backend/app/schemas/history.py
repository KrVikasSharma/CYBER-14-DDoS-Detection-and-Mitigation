from typing import Any
from pydantic import BaseModel, Field


class DatabaseStatusResponse(BaseModel):
    status: str = Field(..., description="'connected' or 'disconnected'")
    database_name: str
    host: str
    port: int
    latency_ms: float | None = None
    last_successful_connection: str | None = None
    tables: dict[str, int] = Field(default_factory=dict)
    error: str | None = None


class DetectionHistoryItem(BaseModel):
    id: int
    traffic_event_id: int | None = None
    source_ip: str | None = None
    source_port: int | None = None
    destination_ip: str | None = None
    destination_port: int | None = None
    protocol: str | None = None
    traffic_rate: float | None = None
    o2_label: int
    o2_confidence: float
    o2_threshold: float
    o3_label: str | None = None
    o3_confidence: float | None = None
    o3_threshold: float | None = None
    latency_ms: float | None = None
    created_at: str | None = None
    created_at_ist: str | None = None


class PaginatedDetectionsResponse(BaseModel):
    items: list[DetectionHistoryItem]
    total: int
    page: int
    page_size: int
    total_pages: int


class IncidentItem(BaseModel):
    id: int
    incident_id: str
    source_ip: str
    destination_ip: str
    attack_type: str
    severity: str
    status: str
    o2_confidence: float | None = None
    o3_confidence: float | None = None
    mitigation_action: str | None = None
    first_seen: str | None = None
    first_seen_ist: str | None = None
    last_seen: str | None = None
    last_seen_ist: str | None = None
    occurrence_count: int
    created_at: str | None = None
    created_at_ist: str | None = None
    updated_at: str | None = None


class PaginatedIncidentsResponse(BaseModel):
    items: list[IncidentItem]
    total: int
    page: int
    page_size: int
    total_pages: int


class IncidentDetailResponse(IncidentItem):
    mitigations: list[dict[str, Any]] = Field(default_factory=list)
    detections: list[dict[str, Any]] = Field(default_factory=list)
    audit_trail: list[dict[str, Any]] = Field(default_factory=list)


class MitigationHistoryItem(BaseModel):
    id: int
    detection_id: int | None = None
    incident_id: str | None = None
    source_ip: str | None = None
    attack_type: str | None = None
    action: str
    reason: str
    duration_seconds: int | None = None
    requests_per_second: float | None = None
    status: str
    started_at: str | None = None
    started_at_ist: str | None = None
    expires_at: str | None = None
    expires_at_ist: str | None = None
    revoked_at: str | None = None
    created_at: str | None = None
    created_at_ist: str | None = None


class PaginatedMitigationResponse(BaseModel):
    items: list[MitigationHistoryItem]
    total: int
    page: int
    page_size: int
    total_pages: int


class AuditLogItem(BaseModel):
    id: int
    event_type: str
    actor: str
    action: str
    resource_type: str | None = None
    resource_id: str | None = None
    details: str | None = None
    client_ip: str | None = None
    status: str | None = None
    reason: str | None = None
    created_at: str | None = None
    created_at_ist: str | None = None



class PaginatedAuditLogsResponse(BaseModel):
    items: list[AuditLogItem]
    total: int
    page: int
    page_size: int
    total_pages: int


class LiveAnalyticsLatency(BaseModel):
    avg_ms: float = 0.0
    latest_ms: float = 0.0


class LiveAnalyticsResponse(BaseModel):
    total_requests: int = 0
    current_rate: float = 0.0
    active_connections: int = 0
    unique_sources: int = 0
    detected_attacks: int = 0
    blocked: int = 0
    rate_limited: int = 0
    allow: int = 0
    latency: LiveAnalyticsLatency = Field(default_factory=LiveAnalyticsLatency)
    attack_distribution: dict[str, int] = Field(default_factory=dict)
    mitigation_distribution: dict[str, int] = Field(default_factory=dict)


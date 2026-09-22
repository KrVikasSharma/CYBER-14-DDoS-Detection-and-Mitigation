from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    BigInteger,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from app.core.time import now_utc, utc_now

PK_BIGINT = BigInteger().with_variant(Integer, "sqlite")
FK_BIGINT = BigInteger().with_variant(Integer, "sqlite")


class Base(DeclarativeBase):
    pass



class TrafficEvent(Base):
    __tablename__ = "traffic_events"

    id: Mapped[int] = mapped_column(PK_BIGINT, primary_key=True, autoincrement=True)
    source_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    source_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    destination_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    destination_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(16), nullable=True)
    timestamp: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    traffic_rate: Mapped[float | None] = mapped_column(Float, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, server_default=func.now())

    detections: Mapped[list["Detection"]] = relationship(
        "Detection", back_populates="traffic_event", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("ix_traffic_events_timestamp", "timestamp"),
        Index("ix_traffic_events_source_ip", "source_ip"),
    )


class Detection(Base):
    __tablename__ = "detections"

    id: Mapped[int] = mapped_column(PK_BIGINT, primary_key=True, autoincrement=True)
    traffic_event_id: Mapped[int | None] = mapped_column(
        FK_BIGINT, ForeignKey("traffic_events.id", ondelete="SET NULL"), nullable=True
    )
    o2_label: Mapped[int] = mapped_column(Integer, nullable=False)
    o2_confidence: Mapped[float] = mapped_column(Float, nullable=False)
    o2_threshold: Mapped[float] = mapped_column(Float, nullable=False)
    o3_label: Mapped[str | None] = mapped_column(String(64), nullable=True)
    o3_confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    o3_threshold: Mapped[float | None] = mapped_column(Float, nullable=True)
    latency_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, server_default=func.now()
    )

    traffic_event: Mapped[TrafficEvent | None] = relationship("TrafficEvent", back_populates="detections")
    mitigation_actions: Mapped[list["MitigationAction"]] = relationship(
        "MitigationAction", back_populates="detection", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("ix_detections_created_at", "created_at"),
        Index("ix_detections_o2_label", "o2_label"),
        Index("ix_detections_o3_label", "o3_label"),
    )


class AttackIncident(Base):
    __tablename__ = "attack_incidents"

    id: Mapped[int] = mapped_column(PK_BIGINT, primary_key=True, autoincrement=True)
    incident_id: Mapped[str] = mapped_column(String(32), unique=True, nullable=False)
    source_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    destination_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    attack_type: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="HIGH")
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="DETECTED")
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    occurrence_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, server_default=func.now(), onupdate=utc_now
    )

    mitigation_actions: Mapped[list["MitigationAction"]] = relationship(
        "MitigationAction", back_populates="incident"
    )

    __table_args__ = (
        Index("ix_attack_incidents_incident_id", "incident_id"),
        Index("ix_attack_incidents_source_ip", "source_ip"),
        Index("ix_attack_incidents_attack_type", "attack_type"),
        Index("ix_attack_incidents_status", "status"),
    )


class MitigationAction(Base):
    __tablename__ = "mitigation_actions"

    id: Mapped[int] = mapped_column(PK_BIGINT, primary_key=True, autoincrement=True)
    detection_id: Mapped[int | None] = mapped_column(
        FK_BIGINT, ForeignKey("detections.id", ondelete="SET NULL"), nullable=True
    )
    incident_id: Mapped[int | None] = mapped_column(
        FK_BIGINT, ForeignKey("attack_incidents.id", ondelete="SET NULL"), nullable=True
    )
    action: Mapped[str] = mapped_column(String(32), nullable=False)
    reason: Mapped[str] = mapped_column(String(255), nullable=False)
    duration_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    requests_per_second: Mapped[float | None] = mapped_column(Float, nullable=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="ACTIVE")
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, server_default=func.now())

    detection: Mapped[Detection | None] = relationship("Detection", back_populates="mitigation_actions")
    incident: Mapped[AttackIncident | None] = relationship("AttackIncident", back_populates="mitigation_actions")

    __table_args__ = (
        Index("ix_mitigation_actions_status", "status"),
        Index("ix_mitigation_actions_started_at", "started_at"),
    )


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(PK_BIGINT, primary_key=True, autoincrement=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    actor: Mapped[str] = mapped_column(String(64), nullable=False, default="system")
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    resource_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    resource_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    details: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, server_default=func.now()
    )

    __table_args__ = (
        Index("ix_audit_logs_created_at", "created_at"),
    )

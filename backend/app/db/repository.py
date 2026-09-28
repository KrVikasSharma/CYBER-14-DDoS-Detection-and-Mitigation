from datetime import datetime, timedelta, timezone
import json
import logging
import math
from typing import Any

from sqlalchemy import desc, func, or_, select
from sqlalchemy.orm import Session, joinedload

from app.core.time import format_iso_utc, format_ist, now_utc, parse_iso_to_utc, utc_now
from app.db.models import AttackIncident, AuditLog, Detection, MitigationAction, TrafficEvent

logger = logging.getLogger(__name__)


def generate_incident_id(db: Session, now: datetime | None = None) -> str:
    """Generate unique sequential incident ID formatted as INC-YYYYMMDD-XXXX."""
    current_time = now or utc_now()
    date_prefix = f"INC-{current_time.strftime('%Y%m%d')}-"
    
    # Query latest incident with today's prefix
    stmt = (
        select(AttackIncident.incident_id)
        .where(AttackIncident.incident_id.like(f"{date_prefix}%"))
        .order_by(desc(AttackIncident.incident_id))
        .limit(1)
    )
    last_id = db.scalar(stmt)
    if last_id:
        try:
            seq_num = int(last_id.split("-")[-1]) + 1
        except Exception:
            seq_num = 1
    else:
        seq_num = 1
    return f"{date_prefix}{seq_num:04d}"


def persist_detection_event(
    db: Session,
    response_payload: Any,
    actor: str = "system",
) -> dict[str, Any]:
    """
    Persist traffic observation, detection inference, incident tracking,
    mitigation action, and audit trail in an atomic database transaction.
    """
    now = now_utc()

    # Extract metadata safely whether response_payload is dict or Pydantic model
    if hasattr(response_payload, "model_dump"):
        data = response_payload.model_dump(mode="json")
    elif isinstance(response_payload, dict):
        data = response_payload
    else:
        raise ValueError("Invalid detection response payload")

    meta = data.get("metadata") or {}
    src_ip = meta.get("source_ip") or "192.168.1.50"
    dst_ip = meta.get("destination_ip") or "10.0.0.1"
    src_port = meta.get("source_port")
    dst_port = meta.get("destination_port")
    protocol = meta.get("protocol") or "TCP"
    traffic_rate = data.get("traffic_rate")

    # Flow observation event timestamp vs DB creation timestamp
    flow_raw_ts = meta.get("timestamp") or data.get("timestamp")
    flow_ts = parse_iso_to_utc(flow_raw_ts) or now

    # 1. Traffic Event
    event = TrafficEvent(
        source_ip=src_ip,
        source_port=src_port,
        destination_ip=dst_ip,
        destination_port=dst_port,
        protocol=protocol,
        timestamp=flow_ts,
        traffic_rate=traffic_rate,
        created_at=now,
    )
    db.add(event)
    db.flush()

    # 2. Detection
    o2_data = data.get("o2") or {}
    o3_data = data.get("o3") or {}
    latency_data = data.get("latency") or {}

    o2_label = int(o2_data.get("label", 0))
    o2_confidence = float(o2_data.get("confidence", 1.0))
    o2_threshold = float(o2_data.get("threshold", 0.5))

    o3_label = str(o3_data.get("attack_type")) if o3_data.get("attack_type") and o2_label == 1 else None
    o3_confidence = float(o3_data.get("confidence")) if o3_data.get("confidence") is not None and o2_label == 1 else None
    o3_threshold = float(o3_data.get("threshold", 0.8)) if o2_label == 1 else None
    latency_ms = float(latency_data.get("total_analysis_ms", 0.0))

    # Detection analysis completion timestamp
    processed_at = parse_iso_to_utc(data.get("timestamp")) or now

    detection = Detection(
        traffic_event_id=event.id,
        o2_label=o2_label,
        o2_confidence=o2_confidence,
        o2_threshold=o2_threshold,
        o3_label=o3_label,
        o3_confidence=o3_confidence,
        o3_threshold=o3_threshold,
        latency_ms=latency_ms,
        created_at=processed_at,
    )
    db.add(detection)
    db.flush()

    incident: AttackIncident | None = None
    incident_action_type = "NONE"

    # 3. Incident Management (for Attacks: O2 label == 1)
    if o2_label == 1 and o3_label:
        # Check active incident window (within 1 hour and in DETECTED or CONTAINED status)
        active_window_start = now - timedelta(hours=1)
        existing_stmt = (
            select(AttackIncident)
            .where(
                AttackIncident.source_ip == src_ip,
                AttackIncident.attack_type == o3_label,
                AttackIncident.status.in_(["DETECTED", "CONTAINED"]),
                AttackIncident.last_seen >= active_window_start,
            )
            .order_by(desc(AttackIncident.last_seen))
            .limit(1)
        )
        existing_incident = db.scalar(existing_stmt)

        if existing_incident:
            existing_incident.last_seen = flow_ts
            existing_incident.occurrence_count += 1
            existing_incident.updated_at = now
            incident = existing_incident
            incident_action_type = "INCIDENT_UPDATED"
        else:
            inc_id_str = generate_incident_id(db, now)
            severity = "CRITICAL" if (o3_confidence or 1.0) >= 0.95 else ("HIGH" if (o3_confidence or 1.0) >= 0.80 else "MEDIUM")
            incident = AttackIncident(
                incident_id=inc_id_str,
                source_ip=src_ip,
                destination_ip=dst_ip,
                attack_type=o3_label,
                severity=severity,
                status="DETECTED",
                first_seen=flow_ts,
                last_seen=flow_ts,
                occurrence_count=1,
                created_at=now,
                updated_at=now,
            )
            db.add(incident)
            db.flush()
            incident_action_type = "INCIDENT_CREATED"

    # 4. Mitigation Action
    mit_data = data.get("mitigation") or {}
    mit_action_str = str(mit_data.get("decision", "ALLOW")).upper()
    reason = str(mit_data.get("reason", "Simulation observation verified"))
    duration_sec = mit_data.get("duration_seconds")
    rps = traffic_rate if traffic_rate is not None else (mit_data.get("parameters") or {}).get("rate_limit_rps")

    started_at = parse_iso_to_utc(mit_data.get("created_at")) or now
    expires_at = parse_iso_to_utc(mit_data.get("expires_at"))
    if not expires_at and duration_sec:
        expires_at = started_at + timedelta(seconds=int(duration_sec))

    action_status = "ACTIVE" if mit_action_str in {"BLOCK", "RATE_LIMIT"} else "EXECUTED"
    mitigation = MitigationAction(
        detection_id=detection.id,
        incident_id=incident.id if incident else None,
        action=mit_action_str,
        reason=reason[:250],
        duration_seconds=int(duration_sec) if duration_sec else None,
        requests_per_second=float(rps) if rps is not None else None,
        status=action_status,
        started_at=started_at,
        expires_at=expires_at,
        created_at=now,
    )
    db.add(mitigation)
    db.flush()

    # 5. Audit Logs
    audit_events: list[AuditLog] = []

    # Detection audit log
    audit_events.append(
        AuditLog(
            event_type="DETECTION",
            actor=actor,
            action="CLASSIFY_FLOW",
            resource_type="detection",
            resource_id=str(detection.id),
            details=json.dumps({
                "source_ip": src_ip,
                "o2_label": "ATTACK" if o2_label == 1 else "BENIGN",
                "o3_label": o3_label,
                "mitigation": mit_action_str,
            }),
            created_at=now,
        )
    )

    # Incident audit log if created or updated
    if incident and incident_action_type != "NONE":
        audit_events.append(
            AuditLog(
                event_type=incident_action_type,
                actor=actor,
                action="AGGREGATE_ATTACK" if incident_action_type == "INCIDENT_UPDATED" else "OPEN_INCIDENT",
                resource_type="attack_incident",
                resource_id=incident.incident_id,
                details=json.dumps({
                    "incident_id": incident.incident_id,
                    "attack_type": incident.attack_type,
                    "occurrences": incident.occurrence_count,
                    "source_ip": src_ip,
                }),
                created_at=now,
            )
        )

    # Mitigation audit log
    if mit_action_str in {"BLOCK", "RATE_LIMIT"}:
        audit_events.append(
            AuditLog(
                event_type="MITIGATION_APPLIED",
                actor=actor,
                action=f"APPLY_{mit_action_str}",
                resource_type="mitigation_action",
                resource_id=str(mitigation.id),
                details=json.dumps({
                    "action": mit_action_str,
                    "target_ip": src_ip,
                    "duration_seconds": duration_sec,
                    "reason": reason,
                }),
                created_at=now,
            )
        )

    db.add_all(audit_events)
    db.commit()

    return {
        "traffic_event_id": event.id,
        "detection_id": detection.id,
        "incident_id": incident.incident_id if incident else None,
        "mitigation_id": mitigation.id,
    }


def log_audit_event(
    db: Session,
    event_type: str,
    actor: str,
    action: str,
    resource_type: str | None = None,
    resource_id: str | None = None,
    details: dict[str, Any] | str | None = None,
) -> AuditLog:
    """Log an explicit system or security audit event."""
    details_str = json.dumps(details) if isinstance(details, dict) else (str(details) if details else None)
    log_entry = AuditLog(
        event_type=event_type,
        actor=actor,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=details_str,
        created_at=now_utc(),
    )
    db.add(log_entry)
    db.commit()
    db.refresh(log_entry)
    return log_entry


def get_detections_history(
    db: Session,
    page: int = 1,
    page_size: int = 25,
    o2_label: int | None = None,
    o3_label: str | None = None,
    min_confidence: float | None = None,
    start_date: datetime | None = None,
    end_date: datetime | None = None,
) -> dict[str, Any]:
    """Retrieve paginated detection history with relational traffic metadata."""
    page_size = min(max(1, page_size), 100)
    page = max(1, page)

    stmt = select(Detection).options(joinedload(Detection.traffic_event))

    if o2_label is not None:
        stmt = stmt.where(Detection.o2_label == o2_label)
    if o3_label:
        stmt = stmt.where(Detection.o3_label == o3_label)
    if min_confidence is not None:
        stmt = stmt.where(
            or_(
                Detection.o2_confidence >= min_confidence,
                Detection.o3_confidence >= min_confidence,
            )
        )
    if start_date:
        stmt = stmt.where(Detection.created_at >= start_date)
    if end_date:
        stmt = stmt.where(Detection.created_at <= end_date)

    count_stmt = select(func.count()).select_from(stmt.subquery())
    total = db.scalar(count_stmt) or 0

    stmt = stmt.order_by(desc(Detection.created_at)).offset((page - 1) * page_size).limit(page_size)
    items = db.scalars(stmt).all()

    results = []
    for d in items:
        event = d.traffic_event
        results.append({
            "id": d.id,
            "traffic_event_id": d.traffic_event_id,
            "source_ip": event.source_ip if event else None,
            "source_port": event.source_port if event else None,
            "destination_ip": event.destination_ip if event else None,
            "destination_port": event.destination_port if event else None,
            "protocol": event.protocol if event else None,
            "traffic_rate": event.traffic_rate if event else None,
            "o2_label": d.o2_label,
            "o2_confidence": d.o2_confidence,
            "o2_threshold": d.o2_threshold,
            "o3_label": d.o3_label,
            "o3_confidence": d.o3_confidence,
            "o3_threshold": d.o3_threshold,
            "latency_ms": d.latency_ms,
            "created_at": format_iso_utc(d.created_at),
            "created_at_ist": format_ist(d.created_at),
        })

    total_pages = math.ceil(total / page_size) if total > 0 else 1
    return {
        "items": results,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
    }


def get_incidents(
    db: Session,
    page: int = 1,
    page_size: int = 25,
    search: str | None = None,
    severity: str | None = None,
    status: str | None = None,
    attack_type: str | None = None,
    source_ip: str | None = None,
    start_date: datetime | None = None,
    end_date: datetime | None = None,
) -> dict[str, Any]:
    """Retrieve paginated attack incidents with search and multi-attribute filters."""
    page_size = min(max(1, page_size), 100)
    page = max(1, page)

    stmt = select(AttackIncident).options(
        joinedload(AttackIncident.mitigation_actions).joinedload(MitigationAction.detection)
    )

    if search:
        search_pattern = f"%{search}%"
        stmt = stmt.where(
            or_(
                AttackIncident.incident_id.ilike(search_pattern),
                AttackIncident.source_ip.ilike(search_pattern),
                AttackIncident.attack_type.ilike(search_pattern),
            )
        )
    if severity:
        stmt = stmt.where(AttackIncident.severity == severity.upper())
    if status:
        stmt = stmt.where(AttackIncident.status == status.upper())
    if attack_type:
        stmt = stmt.where(AttackIncident.attack_type == attack_type.upper())
    if source_ip:
        stmt = stmt.where(AttackIncident.source_ip == source_ip)
    if start_date:
        stmt = stmt.where(AttackIncident.first_seen >= start_date)
    if end_date:
        stmt = stmt.where(AttackIncident.last_seen <= end_date)

    count_stmt = select(func.count()).select_from(stmt.subquery())
    total = db.scalar(count_stmt) or 0


    stmt = stmt.order_by(desc(AttackIncident.last_seen)).offset((page - 1) * page_size).limit(page_size)
    items = db.scalars(stmt).unique().all()

    results = []
    for inc in items:
        latest_mit = inc.mitigation_actions[-1] if inc.mitigation_actions else None
        latest_det = latest_mit.detection if latest_mit else None
        results.append({
            "id": inc.id,
            "incident_id": inc.incident_id,
            "source_ip": inc.source_ip,
            "destination_ip": inc.destination_ip,
            "attack_type": inc.attack_type,
            "severity": inc.severity,
            "status": inc.status,
            "o2_confidence": latest_det.o2_confidence if latest_det else None,
            "o3_confidence": latest_det.o3_confidence if latest_det else None,
            "mitigation_action": latest_mit.action if latest_mit else "NONE",
            "first_seen": format_iso_utc(inc.first_seen),
            "first_seen_ist": format_ist(inc.first_seen),
            "last_seen": format_iso_utc(inc.last_seen),
            "last_seen_ist": format_ist(inc.last_seen),
            "occurrence_count": inc.occurrence_count,
            "created_at": format_iso_utc(inc.created_at),
            "created_at_ist": format_ist(inc.created_at),
            "updated_at": format_iso_utc(inc.updated_at),
        })

    total_pages = math.ceil(total / page_size) if total > 0 else 1
    return {
        "items": results,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
    }



def get_incident_by_id(db: Session, incident_id: str) -> dict[str, Any] | None:
    """Retrieve full incident details including detections, mitigations, and audit trail."""
    stmt = (
        select(AttackIncident)
        .options(joinedload(AttackIncident.mitigation_actions))
        .where(AttackIncident.incident_id == incident_id)
    )
    inc = db.scalar(stmt)
    if not inc:
        return None

    # Fetch related detections for this source IP and attack type
    det_stmt = (
        select(Detection)
        .join(TrafficEvent, Detection.traffic_event_id == TrafficEvent.id)
        .where(
            TrafficEvent.source_ip == inc.source_ip,
            Detection.o3_label == inc.attack_type,
            Detection.created_at >= inc.first_seen - timedelta(minutes=5),
            Detection.created_at <= inc.last_seen + timedelta(minutes=5),
        )
        .order_by(desc(Detection.created_at))
        .limit(20)
    )
    detections = db.scalars(det_stmt).all()

    # Fetch audit trail
    audit_stmt = (
        select(AuditLog)
        .where(AuditLog.resource_id == inc.incident_id)
        .order_by(desc(AuditLog.created_at))
        .limit(20)
    )
    audits = db.scalars(audit_stmt).all()

    return {
        "id": inc.id,
        "incident_id": inc.incident_id,
        "source_ip": inc.source_ip,
        "destination_ip": inc.destination_ip,
        "attack_type": inc.attack_type,
        "severity": inc.severity,
        "status": inc.status,
        "first_seen": format_iso_utc(inc.first_seen),
        "first_seen_ist": format_ist(inc.first_seen),
        "last_seen": format_iso_utc(inc.last_seen),
        "last_seen_ist": format_ist(inc.last_seen),
        "occurrence_count": inc.occurrence_count,
        "created_at": format_iso_utc(inc.created_at),
        "created_at_ist": format_ist(inc.created_at),
        "updated_at": format_iso_utc(inc.updated_at),
        "mitigations": [
            {
                "id": m.id,
                "action": m.action,
                "reason": m.reason,
                "duration_seconds": m.duration_seconds,
                "requests_per_second": m.requests_per_second,
                "status": m.status,
                "started_at": format_iso_utc(m.started_at),
                "started_at_ist": format_ist(m.started_at),
                "expires_at": format_iso_utc(m.expires_at),
                "expires_at_ist": format_ist(m.expires_at),
            }
            for m in inc.mitigation_actions
        ],
        "detections": [
            {
                "id": d.id,
                "o2_label": d.o2_label,
                "o2_confidence": d.o2_confidence,
                "o3_label": d.o3_label,
                "o3_confidence": d.o3_confidence,
                "created_at": format_iso_utc(d.created_at),
                "created_at_ist": format_ist(d.created_at),
            }
            for d in detections
        ],
        "audit_trail": [
            {
                "id": a.id,
                "event_type": a.event_type,
                "actor": a.actor,
                "action": a.action,
                "details": a.details,
                "created_at": format_iso_utc(a.created_at),
                "created_at_ist": format_ist(a.created_at),
            }
            for a in audits
        ],
    }


def get_mitigation_history(
    db: Session,
    page: int = 1,
    page_size: int = 25,
    action: str | None = None,
    status: str | None = None,
    attack_type: str | None = None,
    start_date: datetime | None = None,
    end_date: datetime | None = None,
) -> dict[str, Any]:
    """Retrieve paginated mitigation actions."""
    page_size = min(max(1, page_size), 100)
    page = max(1, page)

    stmt = select(MitigationAction).options(
        joinedload(MitigationAction.incident),
        joinedload(MitigationAction.detection),
    )

    if action:
        stmt = stmt.where(MitigationAction.action == action.upper())
    if status:
        stmt = stmt.where(MitigationAction.status == status.upper())
    if attack_type:
        stmt = stmt.join(AttackIncident, MitigationAction.incident_id == AttackIncident.id).where(
            AttackIncident.attack_type == attack_type.upper()
        )
    if start_date:
        stmt = stmt.where(MitigationAction.started_at >= start_date)
    if end_date:
        stmt = stmt.where(MitigationAction.started_at <= end_date)

    count_stmt = select(func.count()).select_from(stmt.subquery())
    total = db.scalar(count_stmt) or 0

    stmt = stmt.order_by(desc(MitigationAction.started_at)).offset((page - 1) * page_size).limit(page_size)
    items = db.scalars(stmt).all()

    results = []
    for m in items:
        results.append({
            "id": m.id,
            "detection_id": m.detection_id,
            "incident_id": m.incident.incident_id if m.incident else None,
            "source_ip": m.incident.source_ip if m.incident else None,
            "attack_type": m.incident.attack_type if m.incident else (m.detection.o3_label if m.detection else None),
            "action": m.action,
            "reason": m.reason,
            "duration_seconds": m.duration_seconds,
            "requests_per_second": m.requests_per_second,
            "status": m.status,
            "started_at": format_iso_utc(m.started_at),
            "started_at_ist": format_ist(m.started_at),
            "expires_at": format_iso_utc(m.expires_at),
            "expires_at_ist": format_ist(m.expires_at),
            "revoked_at": format_iso_utc(m.revoked_at),
            "created_at": format_iso_utc(m.created_at),
            "created_at_ist": format_ist(m.created_at),
        })

    total_pages = math.ceil(total / page_size) if total > 0 else 1
    return {
        "items": results,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
    }


def get_audit_logs(
    db: Session,
    page: int = 1,
    page_size: int = 25,
    event_type: str | None = None,
    actor: str | None = None,
    start_date: datetime | None = None,
    end_date: datetime | None = None,
) -> dict[str, Any]:
    """Retrieve paginated audit logs."""
    page_size = min(max(1, page_size), 100)
    page = max(1, page)

    stmt = select(AuditLog)

    if event_type:
        stmt = stmt.where(
            or_(
                AuditLog.event_type == event_type.upper(),
                AuditLog.action == event_type.upper(),
            )
        )
    if actor:
        stmt = stmt.where(AuditLog.actor == actor)
    if start_date:
        stmt = stmt.where(AuditLog.created_at >= start_date)
    if end_date:
        stmt = stmt.where(AuditLog.created_at <= end_date)

    count_stmt = select(func.count()).select_from(stmt.subquery())
    total = db.scalar(count_stmt) or 0

    stmt = stmt.order_by(desc(AuditLog.created_at)).offset((page - 1) * page_size).limit(page_size)
    items = db.scalars(stmt).all()

    results = []
    for a in items:
        details_obj: dict[str, Any] = {}
        if a.details:
            try:
                parsed = json.loads(a.details)
                if isinstance(parsed, dict):
                    details_obj = parsed
            except Exception:
                details_obj = {}

        client_ip = details_obj.get("client_ip") or details_obj.get("target_ip")
        status_val = details_obj.get("status")
        if not status_val:
            if details_obj.get("success") is True:
                status_val = "SUCCESS"
            elif details_obj.get("success") is False:
                status_val = "FAILURE"
            elif a.action in {"LOGIN", "LOGOUT"}:
                status_val = "SUCCESS"
            elif a.action == "LOGIN_REJECTED_CONCURRENT":
                status_val = "REJECTED"
            elif a.action in {"APPLY_BLOCK", "APPLY_RATE_LIMIT"}:
                status_val = "EXECUTED"

        reason_val = details_obj.get("reason")

        results.append({
            "id": a.id,
            "event_type": a.event_type,
            "actor": a.actor,
            "action": a.action,
            "resource_type": a.resource_type,
            "resource_id": a.resource_id,
            "details": a.details,
            "client_ip": client_ip,
            "status": status_val,
            "reason": reason_val,
            "created_at": format_iso_utc(a.created_at),
            "created_at_ist": format_ist(a.created_at),
        })

    total_pages = math.ceil(total / page_size) if total > 0 else 1
    return {
        "items": results,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
    }



def get_live_analytics_summary(db: Session, active_connections: int = 0) -> dict[str, Any]:
    """Calculate live analytics aggregates across historical and current database records."""
    total_requests = db.scalar(select(func.count(TrafficEvent.id))) or 0
    unique_sources = db.scalar(select(func.count(func.distinct(TrafficEvent.source_ip)))) or 0

    detected_attacks = db.scalar(select(func.count(Detection.id)).where(Detection.o2_label == 1)) or 0

    blocked = db.scalar(select(func.count(MitigationAction.id)).where(MitigationAction.action == "BLOCK")) or 0
    rate_limited = db.scalar(select(func.count(MitigationAction.id)).where(MitigationAction.action == "RATE_LIMIT")) or 0
    allow = db.scalar(select(func.count(MitigationAction.id)).where(MitigationAction.action == "ALLOW")) or 0

    recent_traffic = db.execute(
        select(TrafficEvent.traffic_rate)
        .order_by(desc(TrafficEvent.id))
        .limit(1)
    ).scalar_one_or_none()
    current_rate = float(recent_traffic) if recent_traffic is not None else 0.0

    recent_latencies = db.execute(
        select(Detection.latency_ms)
        .where(Detection.latency_ms.is_not(None))
        .order_by(desc(Detection.id))
        .limit(50)
    ).scalars().all()

    avg_latency = round(float(sum(recent_latencies) / len(recent_latencies)), 2) if recent_latencies else 0.0
    latest_latency = round(float(recent_latencies[0]), 2) if recent_latencies else 0.0

    attack_counts = db.execute(
        select(Detection.o3_label, func.count(Detection.id))
        .where(Detection.o3_label.is_not(None))
        .group_by(Detection.o3_label)
    ).all()
    attack_distribution = {label: count for label, count in attack_counts if label}

    mit_counts = db.execute(
        select(MitigationAction.action, func.count(MitigationAction.id))
        .group_by(MitigationAction.action)
    ).all()
    mitigation_distribution = {action: count for action, count in mit_counts if action}

    return {
        "total_requests": total_requests,
        "current_rate": current_rate,
        "active_connections": active_connections,
        "unique_sources": unique_sources,
        "detected_attacks": detected_attacks,
        "blocked": blocked,
        "rate_limited": rate_limited,
        "allow": allow,
        "latency": {
            "avg_ms": avg_latency,
            "latest_ms": latest_latency,
        },
        "attack_distribution": attack_distribution,
        "mitigation_distribution": mitigation_distribution,
    }


-- ======================================================================
-- CYBER-14: MySQL Workbench IST Query & Presentation Guide
-- Timezone: Asia/Kolkata (IST: UTC+05:30)
-- Canonical Storage: UTC (+00:00)
-- ======================================================================

USE cyber14_ddos;

-- ----------------------------------------------------------------------
-- OPTION 1: PRE-CONFIGURED READ-ONLY IST PRESENTATION VIEWS (RECOMMENDED)
-- These views display both canonical UTC and converted IST side-by-side.
-- ----------------------------------------------------------------------

-- 1. Audit Logs in IST
SELECT 
    id,
    event_type,
    actor,
    action,
    resource_type,
    resource_id,
    details,
    created_at_utc,
    created_at_ist
FROM v_audit_logs_ist
ORDER BY id DESC
LIMIT 25;

-- 2. Detections & ML Latency in IST
SELECT 
    id,
    traffic_event_id,
    o2_label,
    o2_confidence,
    o3_label,
    o3_confidence,
    latency_ms,
    created_at_utc,
    created_at_ist
FROM v_detections_ist
ORDER BY id DESC
LIMIT 25;

-- 3. Attack Incidents in IST
SELECT 
    id,
    incident_id,
    source_ip,
    destination_ip,
    attack_type,
    severity,
    status,
    occurrence_count,
    first_seen_ist,
    last_seen_ist,
    created_at_ist,
    updated_at_ist
FROM v_attack_incidents_ist
ORDER BY id DESC
LIMIT 25;

-- 4. Mitigation Actions in IST
SELECT 
    id,
    detection_id,
    incident_id,
    action,
    reason,
    duration_seconds,
    requests_per_second,
    status,
    started_at_ist,
    expires_at_ist,
    created_at_ist
FROM v_mitigation_actions_ist
ORDER BY id DESC
LIMIT 25;

-- 5. Traffic Events in IST
SELECT 
    id,
    source_ip,
    source_port,
    destination_ip,
    destination_port,
    protocol,
    traffic_rate,
    timestamp_ist,
    created_at_ist
FROM v_traffic_events_ist
ORDER BY id DESC
LIMIT 25;


-- ----------------------------------------------------------------------
-- OPTION 2: DIRECT AD-HOC QUERIES USING CONVERT_TZ
-- Use these directly on the core tables.
-- ----------------------------------------------------------------------

-- Audit Logs:
SELECT 
    id,
    event_type,
    action,
    actor,
    created_at AS utc_stored,
    CONVERT_TZ(created_at, '+00:00', '+05:30') AS created_at_ist
FROM audit_logs
ORDER BY id DESC
LIMIT 20;

-- Detections:
SELECT 
    id,
    traffic_event_id,
    o2_label,
    o3_label,
    latency_ms,
    created_at AS utc_stored,
    CONVERT_TZ(created_at, '+00:00', '+05:30') AS created_at_ist
FROM detections
ORDER BY id DESC
LIMIT 20;

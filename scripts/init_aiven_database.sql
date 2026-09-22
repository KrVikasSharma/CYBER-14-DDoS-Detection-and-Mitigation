-- ======================================================================
-- CYBER-14: Aiven MySQL Database Initialization Script
-- ======================================================================
--
-- Target:    Aiven MySQL 8.4 (cloud)
-- Database:  defaultdb (Aiven default)
-- Charset:   utf8mb4 / utf8mb4_unicode_ci
-- Timezone:  All timestamps stored as canonical UTC (+00:00)
-- IST Views: Read-only presentation views using CONVERT_TZ(+00:00, +05:30)
--
-- This script is safe to run on a NEW/EMPTY Aiven database.
-- It does NOT contain any local data, credentials, or INSERT statements.
--
-- Usage:
--   mysql -h <AIVEN_HOST> -P <AIVEN_PORT> -u <AIVEN_USER> -p \
--         --ssl-mode=REQUIRED defaultdb < scripts/init_aiven_database.sql
--
-- ======================================================================

-- Enforce UTC session timezone for this connection
SET time_zone = '+00:00';

-- ======================================================================
-- TABLE 1: traffic_events
-- ======================================================================
CREATE TABLE IF NOT EXISTS `traffic_events` (
    `id`               BIGINT       NOT NULL AUTO_INCREMENT,
    `source_ip`        VARCHAR(45)  NOT NULL,
    `source_port`      INTEGER      NULL,
    `destination_ip`   VARCHAR(45)  NOT NULL,
    `destination_port` INTEGER      NULL,
    `protocol`         VARCHAR(16)  NULL,
    `timestamp`        DATETIME     NULL,
    `traffic_rate`     FLOAT        NULL,
    `created_at`       DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    INDEX `ix_traffic_events_timestamp` (`timestamp`),
    INDEX `ix_traffic_events_source_ip` (`source_ip`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ======================================================================
-- TABLE 2: detections
-- ======================================================================
CREATE TABLE IF NOT EXISTS `detections` (
    `id`                BIGINT       NOT NULL AUTO_INCREMENT,
    `traffic_event_id`  BIGINT       NULL,
    `o2_label`          INTEGER      NOT NULL,
    `o2_confidence`     FLOAT        NOT NULL,
    `o2_threshold`      FLOAT        NOT NULL,
    `o3_label`          VARCHAR(64)  NULL,
    `o3_confidence`     FLOAT        NULL,
    `o3_threshold`      FLOAT        NULL,
    `latency_ms`        FLOAT        NULL,
    `created_at`        DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    INDEX `ix_detections_created_at` (`created_at`),
    INDEX `ix_detections_o2_label` (`o2_label`),
    INDEX `ix_detections_o3_label` (`o3_label`),
    CONSTRAINT `fk_detections_traffic_event_id`
        FOREIGN KEY (`traffic_event_id`) REFERENCES `traffic_events` (`id`)
        ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ======================================================================
-- TABLE 3: attack_incidents
-- ======================================================================
CREATE TABLE IF NOT EXISTS `attack_incidents` (
    `id`               BIGINT       NOT NULL AUTO_INCREMENT,
    `incident_id`      VARCHAR(32)  NOT NULL,
    `source_ip`        VARCHAR(45)  NOT NULL,
    `destination_ip`   VARCHAR(45)  NOT NULL,
    `attack_type`      VARCHAR(64)  NOT NULL,
    `severity`         VARCHAR(16)  NOT NULL DEFAULT 'HIGH',
    `status`           VARCHAR(20)  NOT NULL DEFAULT 'DETECTED',
    `first_seen`       DATETIME     NULL,
    `last_seen`        DATETIME     NULL,
    `occurrence_count` INTEGER      NOT NULL DEFAULT 1,
    `created_at`       DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at`       DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    UNIQUE INDEX `uq_attack_incidents_incident_id` (`incident_id`),
    INDEX `ix_attack_incidents_incident_id` (`incident_id`),
    INDEX `ix_attack_incidents_source_ip` (`source_ip`),
    INDEX `ix_attack_incidents_attack_type` (`attack_type`),
    INDEX `ix_attack_incidents_status` (`status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ======================================================================
-- TABLE 4: mitigation_actions
-- ======================================================================
CREATE TABLE IF NOT EXISTS `mitigation_actions` (
    `id`                  BIGINT       NOT NULL AUTO_INCREMENT,
    `detection_id`        BIGINT       NULL,
    `incident_id`         BIGINT       NULL,
    `action`              VARCHAR(32)  NOT NULL,
    `reason`              VARCHAR(255) NOT NULL,
    `duration_seconds`    INTEGER      NULL,
    `requests_per_second` FLOAT        NULL,
    `status`              VARCHAR(20)  NOT NULL DEFAULT 'ACTIVE',
    `started_at`          DATETIME     NULL,
    `expires_at`          DATETIME     NULL,
    `revoked_at`          DATETIME     NULL,
    `created_at`          DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    INDEX `ix_mitigation_actions_status` (`status`),
    INDEX `ix_mitigation_actions_started_at` (`started_at`),
    CONSTRAINT `fk_mitigation_actions_detection_id`
        FOREIGN KEY (`detection_id`) REFERENCES `detections` (`id`)
        ON DELETE SET NULL,
    CONSTRAINT `fk_mitigation_actions_incident_id`
        FOREIGN KEY (`incident_id`) REFERENCES `attack_incidents` (`id`)
        ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ======================================================================
-- TABLE 5: audit_logs
-- ======================================================================
CREATE TABLE IF NOT EXISTS `audit_logs` (
    `id`            BIGINT       NOT NULL AUTO_INCREMENT,
    `event_type`    VARCHAR(64)  NOT NULL,
    `actor`         VARCHAR(64)  NOT NULL DEFAULT 'system',
    `action`        VARCHAR(64)  NOT NULL,
    `resource_type` VARCHAR(64)  NULL,
    `resource_id`   VARCHAR(64)  NULL,
    `details`       TEXT         NULL,
    `created_at`    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    INDEX `ix_audit_logs_created_at` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- ======================================================================
-- IST PRESENTATION VIEWS (Read-Only)
-- Canonical UTC storage is never modified.
-- These views add CONVERT_TZ(col, '+00:00', '+05:30') columns for
-- human-readable India Standard Time display.
-- ======================================================================

-- VIEW 1: v_traffic_events_ist
CREATE OR REPLACE VIEW `v_traffic_events_ist` AS
SELECT
    `id`,
    `source_ip`,
    `source_port`,
    `destination_ip`,
    `destination_port`,
    `protocol`,
    `timestamp`  AS `timestamp_utc`,
    CONVERT_TZ(`timestamp`, '+00:00', '+05:30') AS `timestamp_ist`,
    `traffic_rate`,
    `created_at` AS `created_at_utc`,
    CONVERT_TZ(`created_at`, '+00:00', '+05:30') AS `created_at_ist`
FROM `traffic_events`;

-- VIEW 2: v_detections_ist
CREATE OR REPLACE VIEW `v_detections_ist` AS
SELECT
    `id`,
    `traffic_event_id`,
    `o2_label`,
    `o2_confidence`,
    `o2_threshold`,
    `o3_label`,
    `o3_confidence`,
    `o3_threshold`,
    `latency_ms`,
    `created_at` AS `created_at_utc`,
    CONVERT_TZ(`created_at`, '+00:00', '+05:30') AS `created_at_ist`
FROM `detections`;

-- VIEW 3: v_attack_incidents_ist
CREATE OR REPLACE VIEW `v_attack_incidents_ist` AS
SELECT
    `id`,
    `incident_id`,
    `source_ip`,
    `destination_ip`,
    `attack_type`,
    `severity`,
    `status`,
    `first_seen`       AS `first_seen_utc`,
    CONVERT_TZ(`first_seen`, '+00:00', '+05:30')  AS `first_seen_ist`,
    `last_seen`        AS `last_seen_utc`,
    CONVERT_TZ(`last_seen`, '+00:00', '+05:30')   AS `last_seen_ist`,
    `occurrence_count`,
    `created_at`       AS `created_at_utc`,
    CONVERT_TZ(`created_at`, '+00:00', '+05:30')  AS `created_at_ist`,
    `updated_at`       AS `updated_at_utc`,
    CONVERT_TZ(`updated_at`, '+00:00', '+05:30')  AS `updated_at_ist`
FROM `attack_incidents`;

-- VIEW 4: v_mitigation_actions_ist
CREATE OR REPLACE VIEW `v_mitigation_actions_ist` AS
SELECT
    `id`,
    `detection_id`,
    `incident_id`,
    `action`,
    `reason`,
    `duration_seconds`,
    `requests_per_second`,
    `status`,
    `started_at`   AS `started_at_utc`,
    CONVERT_TZ(`started_at`, '+00:00', '+05:30')  AS `started_at_ist`,
    `expires_at`   AS `expires_at_utc`,
    CONVERT_TZ(`expires_at`, '+00:00', '+05:30')  AS `expires_at_ist`,
    `revoked_at`   AS `revoked_at_utc`,
    CONVERT_TZ(`revoked_at`, '+00:00', '+05:30')  AS `revoked_at_ist`,
    `created_at`   AS `created_at_utc`,
    CONVERT_TZ(`created_at`, '+00:00', '+05:30')  AS `created_at_ist`
FROM `mitigation_actions`;

-- VIEW 5: v_audit_logs_ist
CREATE OR REPLACE VIEW `v_audit_logs_ist` AS
SELECT
    `id`,
    `event_type`,
    `actor`,
    `action`,
    `resource_type`,
    `resource_id`,
    `details`,
    `created_at` AS `created_at_utc`,
    CONVERT_TZ(`created_at`, '+00:00', '+05:30') AS `created_at_ist`
FROM `audit_logs`;


-- ======================================================================
-- VERIFICATION QUERIES (run after initialization to confirm schema)
-- ======================================================================

-- Check all 5 tables exist
-- SELECT TABLE_NAME FROM information_schema.TABLES
-- WHERE TABLE_SCHEMA = DATABASE() AND TABLE_TYPE = 'BASE TABLE'
-- ORDER BY TABLE_NAME;

-- Check all 5 views exist
-- SELECT TABLE_NAME FROM information_schema.VIEWS
-- WHERE TABLE_SCHEMA = DATABASE()
-- ORDER BY TABLE_NAME;

-- Check foreign keys
-- SELECT CONSTRAINT_NAME, TABLE_NAME, COLUMN_NAME,
--        REFERENCED_TABLE_NAME, REFERENCED_COLUMN_NAME
-- FROM information_schema.KEY_COLUMN_USAGE
-- WHERE TABLE_SCHEMA = DATABASE() AND REFERENCED_TABLE_NAME IS NOT NULL;

-- Confirm tables are empty (no local data copied)
-- SELECT 'traffic_events' AS tbl, COUNT(*) AS rows FROM traffic_events
-- UNION ALL SELECT 'detections', COUNT(*) FROM detections
-- UNION ALL SELECT 'attack_incidents', COUNT(*) FROM attack_incidents
-- UNION ALL SELECT 'mitigation_actions', COUNT(*) FROM mitigation_actions
-- UNION ALL SELECT 'audit_logs', COUNT(*) FROM audit_logs;

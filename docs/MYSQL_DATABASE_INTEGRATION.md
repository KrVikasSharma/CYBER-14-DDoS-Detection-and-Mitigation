# CYBER-14: MySQL Enterprise Database Integration & Persistence Architecture

## 1. Architectural Role of MySQL in CYBER-14

In the CYBER-14 DDoS Detection and Mitigation system, **MySQL 8.0** serves as the persistent audit and operational relational database layer. While the core real-time inference pipeline processes network flows in-memory at microsecond-level latencies via the frozen 78-feature machine learning models (O2 Binary Detection and O3 Multi-Class Attack Classification), MySQL provides:

- **Historical Flow Persistence:** Immutable audit records for every evaluated flow observation and traffic metadata vector.
- **Incident Lifecycle Management:** Aggregation of repetitive attack vectors into structured security incidents (`INC-YYYYMMDD-XXXX`) to prevent alert fatigue.
- **Mitigation Decision Auditability:** Persistent recording of simulated mitigation decisions (`ALLOW`, `RATE_LIMIT`, `BLOCK`) with forensic justifications.
- **Compliance & Security Auditing:** Tamper-evident logging of administrative authentication events, authorization checks, and system state transitions.
- **Zero-Impact Decoupling:** Complete non-blocking separation between machine learning inference and persistence. Database latency or connectivity failures never interrupt or halt real-time packet classification.

```
+-----------------------------------------------------------------------------+
|                          CYBER-14 ML INFERENCE PIPELINE                     |
|                                                                             |
|  [Network Flow] ---> [Frozen 78-Feature Contract] ---> [O2 Binary Detector] |
|                                                                 |           |
|                                                +----------------+           |
|                                                |                            |
|                                          (If Attack)                        |
|                                                v                            |
|                                     [O3 Multi-Class Attack]                 |
|                                                |                            |
|                                                v                            |
|                                    [Mitigation Engine]                      |
|                                                |                            |
+------------------------------------------------+----------------------------+
                                                 |
                       (Non-blocking Persistence Hook)
                                                 v
+-----------------------------------------------------------------------------+
|                     MYSQL 8.0 RELATIONAL PERSISTENCE LAYER                  |
|                                                                             |
|  +----------------+     +------------+     +-----------------------------+  |
|  | traffic_events |<--- | detections |<--- |     mitigation_actions      |  |
|  +----------------+     +------------+     +-----------------------------+  |
|                                                          |                  |
|                                                          v                  |
|       +------------+                       +-----------------------------+  |
|       | audit_logs |                       |      attack_incidents       |  |
|       +------------+                       +-----------------------------+  |
+-----------------------------------------------------------------------------+
```

---

## 2. Database Configuration and Environment Variables

The database connection is managed via SQLAlchemy 2.0 with the PyMySQL driver. Configuration parameters are encapsulated within the application settings (`backend/app/core/config.py`) and loaded via environment variables:

| Environment Variable | Default Value | Description |
| :--- | :--- | :--- |
| `DATABASE_URL` | `mysql+pymysql://root:root@127.0.0.1:3306/cyber14_ddos` | Connection string specifying driver, credentials, host, port, and schema name. |
| `DB_POOL_SIZE` | `10` | Number of persistent connections maintained in the connection pool. |
| `DB_MAX_OVERFLOW` | `20` | Maximum number of concurrent burst connections beyond `DB_POOL_SIZE`. |
| `DB_POOL_RECYCLE` | `3600` | Connection recycling timeout in seconds (1 hour) to avoid stale socket disconnects. |
| `DEMO_MODE` | `true` | Retains simulation boundaries and verifies synthetic CIC-DDoS2019 data flows. |

Credentials and sensitive strings are excluded from version control via `.gitignore`. The template file `backend/.env.example` provides presentation-ready default references.

---

## 3. Complete Schema Explanation and ER Relationships

The persistence architecture consists of 5 normalized relational tables designed in 3rd Normal Form (3NF):

```
                        +----------------------+
                        |    traffic_events    |
                        +----------------------+
                        | PK id (BIGINT)       |
                        |    source_ip         |
                        |    destination_ip    |
                        |    protocol          |
                        |    traffic_rate      |
                        +----------------------+
                                   |
                                   | 1:N
                                   v
+-----------------------+ 1:N   +----------------------+
|   attack_incidents    |<------|      detections      |
+-----------------------+       +----------------------+
| PK id (BIGINT)        |       | PK id (BIGINT)       |
| UK incident_id        |       | FK traffic_event_id  |
|    attack_type        |       |    o2_label          |
|    severity           |       |    o2_confidence     |
|    status             |       |    o3_label          |
|    occurrence_count   |       |    o3_confidence     |
+-----------------------+       +----------------------+
            |                              |
            | 1:N                          | 1:N
            +--------------+---------------+
                           |
                           v
              +--------------------------+
              |    mitigation_actions    |
              +--------------------------+
              | PK id (BIGINT)           |
              | FK detection_id          |
              | FK incident_id           |
              |    action                |
              |    reason                |
              |    duration_seconds      |
              |    status                |
              +--------------------------+

              +--------------------------+
              |        audit_logs        |
              +--------------------------+
              | PK id (BIGINT)           |
              |    event_type            |
              |    actor                 |
              |    action                |
              |    resource_type         |
              |    resource_id           |
              |    details               |
              +--------------------------+
```

### Table Definitions

1. **`traffic_events`**:
   - Stores raw observational flow telemetry (source IP, destination IP, source port, destination port, protocol, traffic rate, timestamp).
   - Serves as the immutable root entity for all recorded network flows.

2. **`detections`**:
   - Stores inference outputs from both O2 (Binary Classifier: 0=Benign, 1=Attack) and O3 (Multi-Class Classifier).
   - Contains model confidence levels, classification thresholds, and end-to-end inference latency in milliseconds.
   - Foreign key: `traffic_event_id` -> `traffic_events(id)` (ON DELETE SET NULL).

3. **`attack_incidents`**:
   - Aggregates ongoing or repeated malicious flows matching identical `(source_ip, attack_type)`.
   - Maintains unique human-readable tracking ID `incident_id` formatted as `INC-YYYYMMDD-XXXX`.
   - Tracks severity (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), status (`DETECTED`, `MITIGATING`, `RESOLVED`), `first_seen`, `last_seen`, and `occurrence_count`.

4. **`mitigation_actions`**:
   - Records decisions made by the Mitigation Engine: `ALLOW`, `RATE_LIMIT`, or `BLOCK`.
   - Stores enforcement duration, rate limits applied, expiration timestamps, and policy reason string.
   - Foreign keys: `detection_id` -> `detections(id)`, `incident_id` -> `attack_incidents(id)`.

5. **`audit_logs`**:
   - Comprehensive audit trail recording authentication attempts (`LOGIN_SUCCESS`, `LOGIN_FAILURE`, `LOGOUT`), incident state changes (`INCIDENT_CREATED`, `INCIDENT_UPDATED`), and configuration modifications.
   - Enforces tamper-evident system traceability.

---

## 4. Index Design and Query Optimization

To ensure sub-millisecond query execution even under sustained high-throughput streaming, indexes are explicitly created across all foreign keys, timestamps, and filter fields:

- **`traffic_events`**:
  - `ix_traffic_events_timestamp`: B-Tree index on `timestamp` for range queries.
  - `ix_traffic_events_source_ip`: Fast filtering by origin IP.
- **`detections`**:
  - `ix_detections_created_at`: Chronological timeline queries.
  - `ix_detections_o2_label`: Fast separation of benign vs. attack telemetry.
  - `ix_detections_o3_label`: Fast filtering by specific attack categories (e.g., `SYN`, `NETBIOS`, `DRDOS_DNS`).
- **`attack_incidents`**:
  - `ix_attack_incidents_incident_id`: Direct indexed lookups on `INC-YYYYMMDD-XXXX`.
  - `ix_attack_incidents_source_ip`: Incident correlation by attacker IP.
  - `ix_attack_incidents_attack_type`: Categorical incident metrics.
  - `ix_attack_incidents_status`: Fast operational queue filtering (`DETECTED`, `MITIGATING`).
- **`mitigation_actions`**:
  - `ix_mitigation_actions_status`: Active vs. expired mitigation filtering.
  - `ix_mitigation_actions_started_at`: Time-series mitigation rate graphs.
- **`audit_logs`**:
  - `ix_audit_logs_created_at`: Chronological audit filtering and compliance export.

---

## 5. Incident Generation and Aggregation Logic

To avoid creating millions of individual incident tickets for high-volume packet streams, the persistence layer utilizes an intelligent aggregation heuristic in `backend/app/db/repository.py`:

```python
# Incident aggregation window: 15 minutes
incident = db.execute(
    select(AttackIncident).where(
        AttackIncident.source_ip == source_ip,
        AttackIncident.attack_type == attack_type,
        AttackIncident.status.in_(["DETECTED", "MITIGATING"]),
        AttackIncident.last_seen >= now - timedelta(minutes=15),
    )
).scalar_one_or_none()
```

- **Matching Active Incident:** When a packet matches an active incident from the same source IP and attack class within 15 minutes, `occurrence_count` is incremented, `last_seen` is updated to current UTC time, and severity escalates if thresholds are exceeded.
- **New Incident Creation:** If no active incident exists within the window, a new sequential identifier is generated: `INC-{YYYYMMDD}-{XXXX}` (e.g. `INC-20260922-0001`).
- **Audit Logging:** Every incident creation or escalation automatically emits an audit log event (`INCIDENT_CREATED` or `INCIDENT_UPDATED`).

---

## 6. Real-Time Streaming Integration Architecture

The WebSocket streaming pipeline (`backend/app/api/websocket.py` and `backend/app/services/streaming_service.py`) seamlessly persists each classified observation into MySQL without interrupting active streaming clients:

1. Streaming client receives observation from demo simulator or external source.
2. `DetectionService.analyze()` performs feature validation against the 78-feature contract and executes model inference.
3. Once the inference response is constructed, a safe persistence worker encapsulates the transaction in a dedicated database session.
4. If MySQL is unreachable, the transaction fails silently with a structured logger warning; the WebSocket frame is immediately dispatched to frontend dashboards with zero dropped frames.

---

## 7. Resilience, Connection Pooling, and Failure Handling

CYBER-14 implements defense-in-depth failure resilience:

- **Connection Pooling with Health Pre-Ping:** `pool_pre_ping=True` ensures stale or severed MySQL connections are automatically recycled before executing transactions.
- **Graceful Degradation:** If the MySQL database server is stopped (`net stop MySQL80` or crash):
  - Machine learning inference continues running at 100% availability.
  - Real-time WebSocket streaming continues delivering live analytics.
  - The API returns HTTP 503 on historical query endpoints with explicit diagnostic messages.
  - The frontend displays a database disconnected warning in the System Settings card without crashing.
- **Credential Masking:** System health endpoints (`/api/v1/system/database`) sanitize the connection URL and strictly suppress passwords, usernames, and secret parameters.

---

## 8. RBAC and Audit Logging

All persistent database operations and API endpoints adhere to the CYBER-14 Role-Based Access Control (RBAC) model:

| Role | Incident History | Detection History | Mitigation History | System Database Status | Audit Logs Access |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Viewer** | View | View | View | View | Denied (403 Forbidden) |
| **Analyst** | View / Search | View / Search | View / Search | View | View / Search |
| **Operator** | View / Update | View / Export | View / Manage | View | View / Export |
| **Admin** | Full Access | Full Access | Full Access | Full Access | Full Access |

---

## 9. API Documentation for Database Endpoints

All historical endpoints support server-side pagination with parameters `page` (default 1) and `page_size` (default 25, maximum 100).

### 1. `GET /api/v1/system/database`
- **Description:** Returns live database connectivity status, latency, and table row counts.
- **RBAC:** Requires authenticated user (Viewer, Analyst, Operator, Admin).
- **Sample Response:**
  ```json
  {
    "status": "connected",
    "database_name": "cyber14_ddos",
    "host": "127.0.0.1",
    "port": 3306,
    "latency_ms": 0.62,
    "last_successful_connection": "2026-09-22T03:01:18.086938+00:00",
    "tables": {
      "traffic_events": 356,
      "detections": 356,
      "attack_incidents": 14,
      "mitigation_actions": 356,
      "audit_logs": 441
    },
    "error": null
  }
  ```

### 2. `GET /api/v1/detections/history`
- **Description:** Retrieves paginated historical flow detections.
- **Query Filters:** `page`, `page_size`, `o2_label` (0 or 1), `o3_label` (e.g., `SYN`, `NETBIOS`), `source_ip`, `start_date`, `end_date`.

### 3. `GET /api/v1/incidents`
- **Description:** Lists aggregated attack incidents.
- **Query Filters:** `page`, `page_size`, `status`, `attack_type`, `severity`, `source_ip`.

### 4. `GET /api/v1/incidents/{incident_id}`
- **Description:** Comprehensive drilldown for an incident including linked mitigation actions, detections, and correlated audit events.

### 5. `GET /api/v1/mitigation/history`
- **Description:** Retrieves historical mitigation enforcement actions.
- **Query Filters:** `page`, `page_size`, `action` (`ALLOW`, `RATE_LIMIT`, `BLOCK`), `status`, `start_date`, `end_date`.

### 6. `GET /api/v1/audit/logs`
- **Description:** Accesses security audit logs.
- **RBAC:** Restricted to Analyst, Operator, and Admin roles (Viewers receive 403 Forbidden).

---

## 10. Dashboard Integration Walkthrough

The React dashboard integrates persistent database features across multiple pages:

1. **Incident History Page (`/incidents`):**
   - Direct top-level navigation item.
   - Filter bar by Attack Type, Status, and Severity.
   - Incident Table with `INC-YYYYMMDD-XXXX` links, occurrence badges, and timestamp tracking.
   - Interactive Detail Modal displaying associated mitigations, detections, and audit events.
2. **Threat Detection (`/detection`):**
   - "Detection History (MySQL Database)" section displaying recent classified flows with server-side pagination.
3. **Mitigation Center (`/mitigation`):**
   - "Mitigation History (MySQL Database)" section showing historical enforcement records.
4. **Evidence & Audit (`/evidence`):**
   - "Database Audit Logs (MySQL)" section showing administrative and security event logs.
5. **System Settings (`/settings`):**
   - "MySQL Database Status" card showing live status, round-trip latency, and record counters across all 5 tables.

---

## 11. MySQL Workbench Inspection Guide with Exact Queries

To inspect the database in MySQL Workbench:
1. Open MySQL Workbench and connect to `127.0.0.1:3306` with username `root` and password `root`.
2. Select schema `cyber14_ddos`.
3. Execute the standard inspection queries below:

```sql
-- 1. Check all table record counts
SELECT 'traffic_events' AS tbl, COUNT(*) AS count FROM traffic_events
UNION ALL
SELECT 'detections' AS tbl, COUNT(*) AS count FROM detections
UNION ALL
SELECT 'attack_incidents' AS tbl, COUNT(*) AS count FROM attack_incidents
UNION ALL
SELECT 'mitigation_actions' AS tbl, COUNT(*) AS count FROM mitigation_actions
UNION ALL
SELECT 'audit_logs' AS tbl, COUNT(*) AS count FROM audit_logs;

-- 2. View recent attack incidents with occurrence counts
SELECT incident_id, source_ip, attack_type, severity, occurrence_count, status, first_seen, last_seen
FROM attack_incidents
ORDER BY updated_at DESC
LIMIT 10;

-- 3. Correlate detections with mitigation decisions
SELECT 
    d.id AS detection_id,
    t.source_ip,
    d.o2_label,
    d.o3_label,
    m.action AS mitigation_action,
    m.reason,
    d.latency_ms,
    d.created_at
FROM detections d
JOIN traffic_events t ON d.traffic_event_id = t.id
JOIN mitigation_actions m ON m.detection_id = d.id
ORDER BY d.created_at DESC
LIMIT 10;

-- 4. Inspect audit logs for login events and incident creation
SELECT id, event_type, actor, action, resource_type, resource_id, created_at
FROM audit_logs
ORDER BY created_at DESC
LIMIT 15;
```

---

## 12. Database Initialization and Verification Procedures

To initialize or verify the database schema:

```powershell
# Run the automated database initializer
$env:PYTHONPATH="backend"
.\.venv\Scripts\python.exe scripts/init_database.py
```

The script:
1. Connects to MySQL using credentials from application settings.
2. Creates the database `cyber14_ddos` if not present (`CREATE DATABASE IF NOT EXISTS`).
3. Creates all 5 tables and their 16 indexes safely without dropping or truncating existing data.
4. Queries schema metadata to confirm table presence.

---

## 13. Security Considerations and Credential Protection

- **No Frontend Exposure:** Database host, port, credentials, and connection strings are strictly confined to the backend server. The frontend communicates solely through authenticated REST endpoints.
- **Sanitized Metadata:** The `/api/v1/system/database` endpoint uses URL parsing to extract hostname and port while stripping passwords and authentication tokens.
- **SQL Injection Prevention:** All SQL queries are executed using SQLAlchemy parameterized statements and ORM expressions; zero raw unescaped string formatting is used.

---

## 14. ML Contract Preservation Confirmation

The MySQL persistence layer does NOT alter, modify, or loosen the frozen ML contract:
- The 78-feature CIC-DDoS2019 contract is preserved exactly as defined.
- O2 Binary and O3 Multi-Class model artifacts are evaluated using unaltered feature vectors.
- Mitigation actions remain strictly simulated (no live iptables, nftables, or raw packet operations).
- The `DEMO MODE | REAL CIC-DDoS2019 SAMPLE | NOT OFFICIAL ACCEPTANCE` disclaimer banner remains active.

---

## 15. Verification Results and Test Evidence

All automated test suites verify the complete integration:
- **Unit & Database Tests:** 8 dedicated database unit tests in `tests/unit/test_database.py` passed (100%).
- **Full Backend Suite:** 128 tests in `pytest` passed with 0 errors.
- **Frontend Vitest Suite:** 7 frontend tests in `vitest` passed with 0 errors.
- **Frontend Production Build:** Vite build succeeded in 397ms without bundling errors.
- **Presentation Verification:** `scripts/verify_demo_presentation.py` passed all checks.
- **Multi-Class WebSocket Streaming:** 26 observations streamed across all 10 attack classes, verifying real-time persistence in MySQL.

---

## 16. Presentation Script Section: Demonstrating MySQL Live

When demonstrating CYBER-14 to evaluators:

1. **Open the Dashboard:** Navigate to `http://127.0.0.1:5173` and log in as `admin`.
2. **Show Database Status:** Go to **Settings** and show the **MySQL Database Status** card displaying `Connected`, latency `< 1ms`, and current row counts across the 5 tables.
3. **Show Real-Time Ingestion:** Navigate to **Real-time Stream** and start the multi-class stream.
4. **Show Incident History:** Click on the new **Incident History** page in navigation. Point out:
   - Unique IDs: `INC-YYYYMMDD-XXXX`
   - Occurrence counts aggregating repeated attack waves without duplicate incident clutter.
   - Click **View Details** on any incident to show the linked mitigation actions, detections, and audit events in the modal.
5. **Show MySQL Workbench:** Switch to MySQL Workbench and execute:
   ```sql
   SELECT incident_id, attack_type, occurrence_count, status FROM attack_incidents ORDER BY id DESC LIMIT 5;
   ```
   Show that the records in MySQL Workbench match the frontend in real time.
6. **Emphasize Architectural Decoupling:** Highlight that the database persistence hook is non-blocking; if MySQL experiences network lag, real-time packet classification continues uninterrupted.

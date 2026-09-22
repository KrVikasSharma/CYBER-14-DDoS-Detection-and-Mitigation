# Aiven MySQL Setup — CYBER-14

> Cloud MySQL for the CYBER-14 DDoS Detection and Mitigation project.

## Aiven Instance Details

| Property    | Value                                |
|-------------|--------------------------------------|
| Engine      | MySQL 8.4                            |
| Database    | `defaultdb`                          |
| SSL         | **Required** (`--ssl-mode=REQUIRED`) |
| Charset     | `utf8mb4` / `utf8mb4_unicode_ci`     |
| Timezone    | Canonical storage: **UTC** (`+00:00`)|

## Environment Variables

Set these in your backend deployment (Render) or local `.env`:

```env
AIVEN_MYSQL_HOST=<your-aiven-host>.aivencloud.com
AIVEN_MYSQL_PORT=<port>
AIVEN_MYSQL_USER=avnadmin
AIVEN_MYSQL_PASSWORD=<password>       # NEVER commit this
AIVEN_MYSQL_DATABASE=defaultdb
AIVEN_MYSQL_SSL=REQUIRED
```

> [!CAUTION]
> Never commit the Aiven password or connection string to Git.
> Use environment variables or a secrets manager.

## Running the Initialization Script

Connect to Aiven and run the schema script:

```bash
mysql -h $AIVEN_MYSQL_HOST \
      -P $AIVEN_MYSQL_PORT \
      -u $AIVEN_MYSQL_USER \
      -p \
      --ssl-mode=REQUIRED \
      $AIVEN_MYSQL_DATABASE < scripts/init_aiven_database.sql
```

This creates:
- **5 tables**: `traffic_events`, `detections`, `attack_incidents`, `mitigation_actions`, `audit_logs`
- **5 IST views**: `v_traffic_events_ist`, `v_detections_ist`, `v_attack_incidents_ist`, `v_mitigation_actions_ist`, `v_audit_logs_ist`
- **Zero data rows** — the script contains no INSERT statements

## Verification Queries

After running the init script, verify:

### 1. Confirm tables exist

```sql
SELECT TABLE_NAME FROM information_schema.TABLES
WHERE TABLE_SCHEMA = DATABASE() AND TABLE_TYPE = 'BASE TABLE'
ORDER BY TABLE_NAME;
```

Expected: 5 rows (`attack_incidents`, `audit_logs`, `detections`, `mitigation_actions`, `traffic_events`).

### 2. Confirm views exist

```sql
SELECT TABLE_NAME FROM information_schema.VIEWS
WHERE TABLE_SCHEMA = DATABASE()
ORDER BY TABLE_NAME;
```

Expected: 5 rows (`v_attack_incidents_ist`, `v_audit_logs_ist`, `v_detections_ist`, `v_mitigation_actions_ist`, `v_traffic_events_ist`).

### 3. Confirm foreign keys

```sql
SELECT CONSTRAINT_NAME, TABLE_NAME, COLUMN_NAME,
       REFERENCED_TABLE_NAME, REFERENCED_COLUMN_NAME
FROM information_schema.KEY_COLUMN_USAGE
WHERE TABLE_SCHEMA = DATABASE() AND REFERENCED_TABLE_NAME IS NOT NULL;
```

Expected: 3 foreign keys:
- `detections.traffic_event_id` → `traffic_events.id`
- `mitigation_actions.detection_id` → `detections.id`
- `mitigation_actions.incident_id` → `attack_incidents.id`

### 4. Confirm all tables are empty

```sql
SELECT 'traffic_events' AS tbl, COUNT(*) AS rows FROM traffic_events
UNION ALL SELECT 'detections', COUNT(*) FROM detections
UNION ALL SELECT 'attack_incidents', COUNT(*) FROM attack_incidents
UNION ALL SELECT 'mitigation_actions', COUNT(*) FROM mitigation_actions
UNION ALL SELECT 'audit_logs', COUNT(*) FROM audit_logs;
```

Expected: all row counts = 0.

## UTC / IST Timezone Behavior

| Layer       | Timezone | Details |
|-------------|----------|---------|
| Storage     | UTC      | All `DATETIME` columns store canonical UTC values |
| Session     | UTC      | `SET time_zone = '+00:00'` enforced per connection |
| IST Views   | IST      | `CONVERT_TZ(col, '+00:00', '+05:30')` for display |
| Backend API | Both     | Returns `created_at` (UTC) + `created_at_ist` (IST) |
| Frontend    | IST      | Displays IST using `utils/time.js` |

## Architecture

```
GitHub → Vercel (React/Vite frontend)
              ↓
         Render (FastAPI + WebSocket backend)
              ↓
         Aiven (MySQL 8.4, SSL required)
```

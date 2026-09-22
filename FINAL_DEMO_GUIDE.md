# CYBER-14: Live Presentation & Demonstration Guide
## Step-by-Step Evaluator Walkthrough

**Project Identifier:** CYBER-14 — DDoS Detection & Mitigation  
**Operating Mode:** DEMO MODE (Real CIC-DDoS2019 Sample, 9,990 rows)  
**Backend Port:** `http://localhost:8000`  
**Frontend Port:** `http://localhost:5173` (Vite dev server) or preview  
**Presentation Audience:** Academic Capstone Evaluators & Technical Reviewers  

---

## 1. Executive Demonstration Overview

This guide provides the exact sequence of operational steps, commands, and talking points required to conduct a live presentation of project **CYBER-14**. 

During this presentation, you will demonstrate:
1. System startup with strict environment variables and demo mode enforcement.
2. Secure administrator authentication and Role-Based Access Control (RBAC).
3. System health telemetry and verification of the frozen 78-feature manifest.
4. **Three Core Demonstration Cases**:
   - **Case 1 (Benign Traffic):** Legitimate baseline traffic $\to$ O2 detects Legitimate $\to$ Mitigation issues **`ALLOW`**.
   - **Case 2 (Flash Crowd):** High-volume legitimate traffic ($2,500 \text{ req/s}$) $\to$ O2 detects Legitimate $\to$ Mitigation issues **`RATE_LIMIT`** (graceful containment, no malicious block).
   - **Case 3 (DDoS Attack):** High-intensity attack (e.g., NetBIOS reflection) $\to$ O2 detects Attack $\to$ O3 classifies NetBIOS $\to$ Mitigation issues bounded **`BLOCK`** ($300\text{s}$ expiry).
5. Real-time telemetry streaming over WebSockets.
6. The 9 dedicated views of the operational React SOC dashboard.
7. How to truthfully explain **DEMO MODE** vs. official acceptance testing.

---

## 2. Startup Commands

Open two separate Windows PowerShell terminals in the project root: `D:\capstone\DDoS Detection and Mitigation`.

### Terminal 1: Backend Service (Demo Mode)

Run the following commands to activate the Python virtual environment and launch FastAPI with demonstration settings:

```powershell
# Set environment variables for presentation demo mode
$env:PYTHONPATH = "backend"
$env:DEMO_MODE = "true"
$env:AUTH_ENABLED = "true"
$env:AUTH_SECRET_KEY = "presentation-secret-key-32-chars-long!"
$env:AUTH_BOOTSTRAP_PASSWORD = "DemoAdminPassword123!"
$env:STREAM_SIMULATOR_ENABLED = "true"

# Activate virtual environment and start Uvicorn ASGI server
.\.venv\Scripts\Activate.ps1
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

*Expected Terminal 1 Output:*
```
INFO:     Started server process
INFO:     Waiting for application startup.
INFO:     [CYBER-14] Demo Mode active with 78-feature real CIC-DDoS2019 models.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
```

### Terminal 2: Frontend Dashboard (Vite SPA)

In the second PowerShell terminal, navigate to `dashboard/frontend` and start the Vite development server:

```powershell
cd dashboard\frontend
npm.cmd run dev
```

*Expected Terminal 2 Output:*
```
  VITE v6.x.x  ready in 250 ms

  ➜  Local:   http://localhost:5173/
  ➜  Network: use --host to expose
  ➜  press h + enter to show help
```

Open your browser to `http://localhost:5173`.

---

## 3. System Health & Sanity Check

Before logging into the dashboard, verify backend responsiveness directly via PowerShell or browser:

```powershell
# Verify public health endpoint
curl.exe -s http://localhost:8000/health
```
*Expected JSON:*
```json
{"status":"ok","service":"CYBER-14 DDoS Detection and Mitigation"}
```

```powershell
# Verify public system status
curl.exe -s http://localhost:8000/api/v1/system/status
```
*Expected JSON:*
```json
{
  "service": "CYBER-14 DDoS Detection and Mitigation",
  "environment": "development",
  "status": "ok",
  "api_version": "/api/v1",
  "ml_status": "ready_demo_sample",
  "mitigation_status": "simulation_only_ready",
  "streaming_status": "ready",
  "authentication_enabled": true,
  "authentication_mode": "local_demo",
  "configured_roles": ["viewer", "analyst", "operator", "admin"],
  "simulator_enabled": true
}
```

---

## 4. Authentication & RBAC Walkthrough

1. Open `http://localhost:5173` in your web browser.
2. The browser automatically presents the secure **CYBER-14 Login Modal**.
3. Point out to evaluators:
   - Protected API routes reject unauthenticated access with `401 Unauthorized`.
   - The system implements bcrypt-hashed password verification and HMAC-SHA256 signed JSON Web Tokens (JWT).
4. Enter the presentation administrator credentials:
   - **Username:** `admin`
   - **Password:** `DemoAdminPassword123!`
5. Click **Sign In**.
6. The dashboard unlocks and displays the top banner:
   ```
   [ DEMO MODE | REAL CIC-DDoS2019 SAMPLE | NOT OFFICIAL ACCEPTANCE ]
   ```
7. Note: The token is stored securely in browser memory (`localStorage` / session state) and transmitted in the `Authorization: Bearer <token>` header for all subsequent API and WebSocket calls.

---

## 5. The Three Core Demonstration Scenarios

Navigate to the **Binary Threat Detection (O2)** view using the navigation bar. Notice the three preset scenario buttons: **[ Load Benign ]**, **[ Load Flash Crowd ]**, and **[ Load Attack (NetBIOS) ]**.

You can execute these directly in the UI with a single click, or demonstrate the backend API using the `curl` commands below.

### Demonstration Case 1: Legitimate Benign Traffic
- **Scenario Description:** Normal, low-rate user traffic entering the network ($10 \text{ req/s}$).
- **Action:** Click **[ Load Benign ]** or execute:

```powershell
$token = (Invoke-RestMethod -Uri "http://localhost:8000/api/v1/auth/login" -Method Post -ContentType "application/json" -Body '{"username":"admin","password":"DemoAdminPassword123!"}').access_token
$headers = @{ Authorization = "Bearer $token" }
$scenarios = Invoke-RestMethod -Uri "http://localhost:8000/api/v1/detection/demo-scenarios" -Headers $headers

# Case 1: Benign
$body1 = @{ source_identifier = "192.168.1.50"; traffic_rate = 10.0; features = $scenarios.benign.features } | ConvertTo-Json -Depth 5
Invoke-RestMethod -Uri "http://localhost:8000/api/v1/detection/analyze" -Method Post -ContentType "application/json" -Headers $headers -Body $body1
```

- **Observed System Reaction:**
  - **O2 Binary Result:** `0 (BENIGN)` (Confidence: `1.0000`).
  - **O3 Multi-Class:** Not triggered or `BENIGN` (Attack classification unnecessary).
  - **Mitigation Decision:** **`ALLOW`**.
  - **Policy Reason:** *"Trusted legitimate classification is below the flash-crowd containment threshold."*
- **Talking Point for Evaluators:** *"Notice that legitimate baseline traffic is immediately allowed with zero friction. The O2 detector evaluates the 78 features in ~16 ms without false-alarming."*

---

### Demonstration Case 2: High-Volume Flash Crowd (Non-Malicious Spike)
- **Scenario Description:** Legitimate promotional event or news surge causing traffic to spike to $2,500 \text{ req/s}$ from valid clients.
- **Action:** Click **[ Load Flash Crowd ]** or execute:

```powershell
# Case 2: Flash Crowd
$body2 = @{ source_identifier = "192.168.1.60"; traffic_rate = 2500.0; features = $scenarios.flash_crowd.features } | ConvertTo-Json -Depth 5
Invoke-RestMethod -Uri "http://localhost:8000/api/v1/detection/analyze" -Method Post -ContentType "application/json" -Headers $headers -Body $body2
```

- **Observed System Reaction:**
  - **O2 Binary Result:** `0 (BENIGN)` (Confidence: `1.0000`).
  - **O3 Multi-Class:** `BENIGN`.
  - **Mitigation Decision:** **`RATE_LIMIT`**.
  - **Policy Reason:** *"Trusted classification with sustained traffic above the configured flash-crowd threshold; contain volume without treating it as malicious."*
  - **Expiry:** Temporary containment bounded to $60\text{s}$.
- **Talking Point for Evaluators:** *"This is the core resolution of the Flash-Crowd Dilemma. A standard volumetric threshold firewall would have blocked this source IP entirely. CYBER-14's O2 model recognizes the features are benign, so the mitigation engine applies graceful rate-limiting containment without permanently blocking legitimate users."*

---

### Demonstration Case 3: High-Confidence DDoS Attack (NetBIOS Reflection)
- **Scenario Description:** Reflection/amplification attack saturating the network ($2,000 \text{ req/s}$).
- **Action:** Click **[ Load Attack (NetBIOS) ]** or execute:

```powershell
# Case 3: NetBIOS Attack
$body3 = @{ source_identifier = "198.51.100.15"; traffic_rate = 2000.0; features = $scenarios.attack_fixture.features } | ConvertTo-Json -Depth 5
Invoke-RestMethod -Uri "http://localhost:8000/api/v1/detection/analyze" -Method Post -ContentType "application/json" -Headers $headers -Body $body3
```

- **Observed System Reaction:**
  - **O2 Binary Result:** `1 (ATTACK)` (Confidence: `1.0000`).
  - **O3 Multi-Class:** `NETBIOS` (Confidence: `0.8222`).
  - **Mitigation Decision:** **`BLOCK`**.
  - **Policy Reason:** *"Known attack classification meets the confirmed-attack confidence threshold."*
  - **Expiry:** Bounded block scheduled for $300\text{s}$ ($5 \text{ minutes}$).
- **Talking Point for Evaluators:** *"Here, O2 immediately flags the malicious flow, and O3 classifies the specific reflection vector as NetBIOS with 82.2% confidence. Because confidence exceeds the 0.80 policy threshold, the mitigation engine issues a bounded 300-second BLOCK executed safely in memory."*

---

## 6. Walkthrough of Dashboard Views

Guide the evaluators through each navigation view on the frontend:

### View 1: Overview (Dashboard)
- **What to show:** Threat velocity charts, active mitigation counts (e.g., 1 blocked, 1 rate-limited), and real-time alert logs.
- **Key visual:** The split indicator between benign traffic, contained rate-limits, and isolated attack vectors.

### View 2: Binary Detection (O2)
- **What to show:** Live probability distribution gauge for $P(\text{Attack})$. 
- **Interactive Action:** Toggle between the three scenario buttons to show the gauge move dynamically between 0.0% and 100.0%.

### View 3: Multi-Class Classification (O3)
- **What to show:** Breakdown of the 17 CIC-DDoS2019 attack categories.
- **Talking Point:** Explain that O3 distinguishes reflection vectors (DNS, NTP, SNMP, SSDP, MSSQL, NetBIOS) from exploit floods (SYN, TFTP, UDP-Lag).

### View 4: Mitigation Control Center
- **What to show:** The active containment table.
- **Interactive Action:** Point out the active `BLOCK` on `198.51.100.15` and `RATE_LIMIT` on `192.168.1.60`. Click **[ Revoke Rule ]** to demonstrate administrator override capability and clean audit logging.
- **Key Safety Point:** Reiterate that this executor operates in memory with zero kernel disruption.

### View 5: Real-Time Traffic Stream
- **What to show:** The live telemetry stream over `WS /ws/traffic`.
- **Action:** Click **[ Start Simulation Stream ]**. The dashboard will stream live observations sampled from the real dataset. Watch the chart update at 1 observation per second with latency indicators.

### View 6: Evidence & Audit Registry
- **What to show:** The interactive manifest tabs.
- **Tabs to Click:**
  - *Feature Manifest:* Displays the frozen 78-feature list and SHA-256 fingerprint (`997e6b28...`).
  - *Demo Evaluation:* Shows test accuracy (99.90%), confusion matrix, and latency percentiles.
  - *Raw Schema Inventory:* Shows the local path to the 18 raw files (28.92 GB, 70.4M rows).
- **Talking Point:** *"Every piece of evidence shown on this screen is backed by an immutable JSON file in the `evidence/` directory."*

### View 7: System Status & KPIs
- **What to show:** Health indicators, memory usage, and the KPI compliance table.
- **Talking Point:** Emphasize that KPIs are marked `NOT_EXECUTED (Official)` alongside the verified `DEMO SAMPLE` reference numbers.

### View 8: Training & Artifacts
- **What to show:** Random Forest hyperparameters (50 trees depth 8 for O2; 60 trees depth 12 for O3), model file sizes (300 KB for O2, 9.55 MB for O3), and joblib checksums.

### View 9: Settings & Environment
- **What to show:** Active environment variables, JWT token expiration timer, and developer mode debugging details.

---

## 7. How to Explain DEMO MODE Truthfully to Evaluators

When presenting to evaluators, use the following script to articulate the relationship between demonstration results and official acceptance:

> **Evaluator Question:** *"Are these numbers (99.90% accuracy) based on the full 30 GB dataset?"*  
>
> **Your Exact Truthful Response:**  
> *"No. That is an important academic distinction in our project.  
> 
> The real CIC-DDoS2019 dataset is 28.92 GB across 18 CSV files, containing 70,427,637 rows. We have verified the raw dataset locally, audited all 88 columns, and frozen the 78-feature numeric contract with SHA-256 integrity.  
> 
> However, training on all 70 million rows requires distributed cluster computing with out-of-core streaming. For this capstone demonstration, we engineered a reproducible, stratified sample of 9,990 rows across all 18 files, using train-only median imputation to avoid leakage.  
> 
> The 99.90% accuracy for O2 and 70.77% accuracy for O3 were measured on the 1,998 held-out test rows of this real dataset sample.  
> 
> In accordance with academic integrity, our official Acceptance Criteria (AC-1 through AC-4) and KPIs (KPI-1 through KPI-6) remain strictly recorded as `NOT_EXECUTED`, and adversarial tests (NT-1 through NT-5) are recorded as `BLOCKED`. We do not claim full 70M-row benchmark completion, but rather a fully verified, working architecture demonstrated on real CIC-DDoS2019 data."*

---

## 8. Summary Checklist for Presenters

Before entering the presentation room, confirm:
- [ ] Backend running in Terminal 1 with `$env:DEMO_MODE="true"`.
- [ ] Frontend running in Terminal 2 on `http://localhost:5173`.
- [ ] Administrator login credentials memorized (`admin` / `DemoAdminPassword123!`).
- [ ] Browser window sized to full screen with console drawer open or ready.
- [ ] Verified that `DemoBanner` is clearly visible on every screen.
- [ ] Prepared to explain flash-crowd containment vs. attack blocking.
- [ ] Prepared to cite the 78-feature contract fingerprint (`997e6b28...`).

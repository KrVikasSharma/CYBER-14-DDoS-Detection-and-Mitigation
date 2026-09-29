# CYBER-14: FINAL PRESENTATION SLIDE DECK OUTLINE
## 15-Slide Presentation Structure for Capstone Review & Defense

**Project Title:** CYBER-14 — Real-Time DDoS Detection and Mitigation  
**Format:** 15-Slide Academic & Technical Defense Deck  
**Target Duration:** 15–20 Minutes (followed by Q&A)

---

### Slide 1: Title & Overview
- **Header:** CYBER-14: Real-Time DDoS Detection and Mitigation System
- **Subtitle:** Hierarchical ML Detection, Deterministic Flash-Crowd Disambiguation & Safe Policy Mitigation
- **Key Information:**
  - Capstone Final Evaluation (2025–2026)
  - Dataset: Canadian Institute for Cybersecurity (CIC-DDoS2019)
  - Architecture: Tier-1 Binary (O2) + Tier-2 Multi-Class (O3) + Deterministic Policy Engine

---

### Slide 2: Problem Statement & Industry Motivation
- **Header:** The Escalating DDoS Crisis
- **Key Bullet Points:**
  - **Volume & Vector Diversity:** Multi-vector amplification floods (DNS, NTP, SNMP, SSDP, MSSQL) easily overwhelm static threshold firewalls.
  - **The Flash-Crowd Dilemma:** Legitimate surges (breaking news, flash sales) mirror volumetric floods; conventional systems blacklist entire IP blocks, dropping real customers.
  - **Overfitting & Latency Bottlenecks:** Existing ML models overfit to transient IP addresses and introduce excessive inference latency ($> 100\text{ ms}$).

---

### Slide 3: Project Objectives (O2 – O5)
- **Header:** Core Capstone Engineering Objectives
- **Key Bullet Points:**
  - **O2 (Binary Threat Detection):** Rapid binary classification ($\ge 95\%$ accuracy, sub-$30\text{ ms}$ latency).
  - **O3 (Multi-Class Threat Classification):** Granular threat attribution across 17 CIC-DDoS2019 classes.
  - **O4 (Mitigation Decision Engine):** Distinguish flash crowds from attacks; issue bounded `ALLOW`, `RATE_LIMIT`, `BLOCK` actions.
  - **O5 (Operational SOC Platform):** FastAPI backend, authenticated WebSocket telemetry (`/ws/traffic`), React SOC dashboard, MySQL audit persistence.

---

### Slide 4: Key Design Principles & Architecture
- **Header:** System Architecture & Data Flow
- **Visual Diagram:** Ingress Flow $\rightarrow$ 78-Feature Contract $\rightarrow$ O2 Binary $\rightarrow$ O3 Multi-Class $\rightarrow$ Mitigation Engine $\rightarrow$ WebSocket & MySQL $\rightarrow$ React SOC UI.
- **Key Pillars:**
  - Fast-path binary triage ($< 10\text{ ms}$) for 85%+ benign traffic.
  - Granular multi-class attribution invoked only on confirmed attacks.
  - Non-destructive rate-limiting containment for ambiguous traffic.

---

### Slide 5: Dataset Provenance & 78-Feature Contract
- **Header:** Authentic CIC-DDoS2019 Ingestion
- **Key Bullet Points:**
  - **Source:** 18 raw CSV benchmark files covering 16 attack families and benign traffic.
  - **Frozen Representative Sample:** 9,990 rows stratified with deterministic seed `42` (80% Train: 7,992 rows, 20% Test: 1,998 rows).
  - **Zero Data Leakage:** Train-only median imputation applied immutably to the held-out test partition.
  - **78-Feature Contract:** IPs, ports, and timestamps strictly excluded to prevent environment memorization.

---

### Slide 6: Tier-1 (O2) Binary Threat Detection Results
- **Header:** O2 Binary Threat Discrimination
- **Model Details:** 50-tree Random Forest, max depth 8, 293 KB footprint.
- **Measured Metrics (1,998 Test Samples):**
  - **Accuracy:** **99.90%** ($1,996 / 1,998$)
  - **Recall:** **100.00%** ($1,854 / 1,854$ attacks detected)
  - **False Negative Rate:** **0.00%** ($0$ missed attacks)
  - **False Positive Rate:** **1.39%** ($2 / 144$ benign flows)
  - **Inference Latency (P50/P95):** **$5.19\text{ ms}$ / $8.21\text{ ms}$** ($\le 30\text{ ms}$ target $\rightarrow$ **PASS**)

---

### Slide 7: Tier-2 (O3) Multi-Class Threat Attribution
- **Header:** O3 Granular Threat Attribution across 17 Classes
- **Model Details:** 60-tree Random Forest, max depth 12, 9.11 MB footprint.
- **Measured Metrics:**
  - **Top-1 Overall Accuracy:** **70.77%** ($1,414 / 1,998$)
  - **Macro Weighted F1:** **0.6909**
  - **High-Volume Reflection Vectors:** TFTP ($99.1\%$), Syn ($98.2\%$), NTP ($98.2\%$), DNS ($94.7\%$), SNMP ($94.6\%$), SSDP ($93.7\%$).
  - **Rare Vectors:** Handled via safe rate-limiting fallback.

---

### Slide 8: Flash-Crowd Disambiguation & Safe Mitigation
- **Header:** Protecting Legitimate Surges
- **Key Logic:**
  - Rate $\ge 1,000\text{ req/s}$ + Low ML Confidence ($< 0.50$) $\rightarrow$ `RATE_LIMIT` ($60\text{s}$ window, $100\text{ req/s}$ burst).
  - Rate $\ge 1,000\text{ req/s}$ + High ML Confidence ($\ge 0.80$) $\rightarrow$ `BLOCK` ($300\text{s}$ source isolation).
- **Benchmark Evidence:**
  - 432 legitimate surge flows tested up to $5,000\text{ req/s}$.
  - **0 Destructive Blocks (0.0% destructive FPR)**.
  - KPI-2 marked `NOT_EXECUTED` pending formal client threshold calibration.

---

### Slide 9: Real-Time Streaming & React SOC Dashboard
- **Header:** Operational Command & Control
- **Key Features:**
  - Full-duplex WebSocket stream (`/ws/traffic`) with client heartbeat & auto-reconnect.
  - 9 specialized SOC views: Overview, O2 Gauges, O3 Radar, Incident History, Mitigation Sliders, Live Stream, Evidence Hub, KPIs, Training Artifacts.
  - Interactive source flow metadata inspection with 78-feature contract annotations.

---

### Slide 10: Persistence, RBAC & Degraded-Mode Resilience
- **Header:** Security, Auditing & Fault Tolerance
- **Key Bullet Points:**
  - **MySQL Database:** ACID persistence with automatic fallback to in-memory ring buffer during DB disconnects (DM-06).
  - **Authentication & RBAC:** JWT Bearer tokens with bcrypt password hashing and 4 least-privilege roles.
  - **Degraded-Mode Testing (DM-01 .. DM-08):** 8/8 fault injection scenarios passed (missing model, policy exception, malformed schema, extreme flood, etc.).

---

### Slide 11: Hardware Resource Profile & Capacity Scaling
- **Header:** Resource Ceilings & Throughput Benchmarks
- **Key Metrics:**
  - **Host Profile:** 12 AMD64 Cores, 15.65 GB RAM.
  - **Process RSS:** **224.62 MB** (well within $2,048.0\text{ MB}$ AC-4 limit).
  - **Single-Flow Latency:** $5.19\text{ ms P50}$ / $8.21\text{ ms P95}$.
  - **Batch Throughput Scaling:**
    - Batch 1: 50.41 flows/sec ($19.84\text{ ms/flow}$)
    - Batch 100: 4,820.14 flows/sec ($0.21\text{ ms/flow}$)
    - Batch 1,998: **59,717.26 flows/sec** ($0.017\text{ ms/flow}$)

---

### Slide 12: Official Acceptance Compliance Matrix
- **Header:** Full Acceptance Framework Audit (15 Criteria)
- **Summary Table:**
  - **KPIs (1–6):** 5 PASS, 1 NOT_EXECUTED (KPI-2)
  - **Acceptance Criteria (1–4):** 3 PASS, 1 NOT_EXECUTED (AC-3)
  - **Negative Security Tests (1–5):** 5 PASS
  - **Degraded Mode (DM-01–08):** 8 PASS
  - **Overall Score:** **13 PASS / 0 FAIL / 2 NOT_EXECUTED / 0 BLOCKED**

---

### Slide 13: Cryptographic Integrity & Zero-Leak Audit
- **Header:** Traceability & Reproducibility
- **Key Bullet Points:**
  - **Artifact Catalog:** 68 files indexed in `evidence_manifest.json`.
  - **SHA-256 Checksums:** 100% verified in `SHA256SUMS.txt` (0 mismatches).
  - **Secret Scan Audit:** 714 files scanned, **0 exposed credentials, passwords, or live tokens**.
  - **One-Command Verification:** `python scripts/run_acceptance.py --all`

---

### Slide 14: Known Limitations & Scope Boundaries
- **Header:** Transparent Academic Disclaimers
- **Key Points:**
  - **Representative Sample Scope:** Evaluated on frozen 1,998-row test partition rather than 50 GB uncompressed PCAP.
  - **Software Simulation:** Mitigation executed in policy simulation without physical hardware SDN switch drops.
  - **Pending Formal Items:** KPI-2 (threshold calibration) and AC-3 (human examiner sign-off) preserved as `NOT_EXECUTED`.
  - **Multi-Class Attribution:** Research-grade trade-offs for rare application-layer classes.

---

### Slide 15: Conclusion & Future Roadmap
- **Header:** Summary & Next Steps
- **Conclusions:**
  - CYBER-14 successfully demonstrates high-speed, accurate, and safe DDoS detection and mitigation.
  - Two-tier ML hierarchy achieves **99.90% accuracy**, **$8.21\text{ ms P95}$ latency**, and **0% flash-crowd false drops**.
  - 100% of executed acceptance criteria passed with complete forensic integrity.
- **Future Roadmap:**
  - Kernel-level eBPF/XDP driver for hardware line-rate filtering.
  - Distributed 10Gbps physical network testbed evaluation.

---

**Presentation Outline Status:** **READY FOR SLIDE GENERATION & DEFENSE**

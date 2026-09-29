# CYBER-14: FINAL VIVA & DEFENSE PREPARATION GUIDE
## Comprehensive Technical Walkthrough, Architecture Rationales, Viva Q&A, and Defense Strategy

**Project Identifier:** CYBER-14 — Real-Time DDoS Detection & Mitigation  
**Target:** Final Capstone Viva Voce, Technical Presentation & Examiner Defense  
**Authoritative Evidence Repository:** [`evidence/evidence_manifest.json`](file:///d:/capstone/DDoS%20Detection%20and%20Mitigation/evidence/evidence_manifest.json) | [`evidence/independent_review_package.json`](file:///d:/capstone/DDoS%20Detection%20and%20Mitigation/evidence/independent_review_package.json)

---

## 1. Quick Oral Explanations (Pitch Scripts)

### 1.1 The 2-Minute Executive Summary
> "Good morning, respected examiners. Our project is **CYBER-14: Real-Time DDoS Detection and Mitigation System**. 
> 
> Modern networks face two critical DDoS challenges: first, multi-vector attacks easily bypass traditional static firewalls; second, existing ML-based detectors frequently overfit to IP addresses and misclassify legitimate traffic surges—such as flash sales—as DDoS attacks, blacklisting genuine users.
> 
> To solve this, CYBER-14 introduces a **hierarchical two-stage detection and mitigation pipeline** trained on the authentic **CIC-DDoS2019** dataset under a strict **78-feature tabular contract**. Network identifiers like Source/Destination IPs and timestamps are completely excluded from ML inputs to prevent topology memorization. 
> 
> **Tier 1 (O2)** provides ultra-fast binary detection at **99.90% accuracy** with an isolated latency of **$8.21\text{ ms P95}$** and **$0.0\%$ false negatives**. Only flagged attacks flow to **Tier 2 (O3)**, which attributes the attack across **17 granular classes** at **70.77% accuracy**. 
> 
> Our deterministic mitigation engine evaluates traffic rate alongside ML confidence to prevent false drops: legitimate flash crowds receive non-destructive `RATE_LIMIT` ($0$ drops across $432$ test surges), while confirmed attacks receive time-bounded `BLOCK` actions. The entire system is delivered through an asynchronous FastAPI backend, authenticated WebSocket live streaming, a React SOC dashboard, and dual-tier MySQL audit persistence. In formal evaluation, our system achieves **13 PASS, 0 FAIL, and 2 explicitly NOT_EXECUTED** items, preserving strict academic honesty."

---

### 1.2 The 5-Minute Technical Deep-Dive
> "To elaborate on our engineering architecture and empirical evidence:
> 
> **1. Data Contract & Ingestion:** We extracted a representative 9,990-row frozen partition across all 18 raw CSV files of CIC-DDoS2019 with deterministic seed 42. Imputation statistics were computed strictly on the 80% training set (7,992 rows) and applied to the 20% held-out test set (1,998 rows), guaranteeing zero data leakage.
> 
> **2. Hierarchical Model Design:** Rather than running an expensive multi-class classifier on every packet, we structured the pipeline into two tiers:
> - **O2 Binary Detector:** A 50-tree Random Forest (depth 8, 293 KB footprint) evaluated on 1,998 test rows. It achieves $99.90\%$ accuracy, $100.0\%$ attack recall, and $1.39\%$ FPR ($2 / 144$ benign flows flagged).
> - **O3 Multi-Class Classifier:** A 60-tree Random Forest (depth 12, 9.11 MB footprint) classifying 17 classes (16 attack families + BENIGN). High-volume reflection attacks (TFTP, Syn, NTP, DNS) achieve $> 93\%$ precision, yielding an overall top-1 accuracy of $70.77\%$.
> 
> **3. Flash-Crowd Disambiguation:** When traffic surges above $1,000\text{ req/s}$, traditional systems trigger blanket drops. CYBER-14 checks O2 confidence: if confidence is low ($< 0.50$), it issues a non-destructive $60\text{s}$ `RATE_LIMIT` window allowing up to $100\text{ req/s}$, preventing service starvation. Tested across 432 legitimate surge flows, the destructive drop rate was exactly $0.0\%$.
> 
> **4. Operational Infrastructure:** The backend is built on FastAPI and WebSockets (`/ws/traffic`), broadcasting live flow telemetry to a React 19 SOC dashboard with 9 specialized views. All mitigation events and audit logs persist asynchronously to MySQL with canonical UTC timestamps and in-memory fallback.
> 
> **5. Acceptance & Reproducibility:** We evaluated 15 formal criteria: 13 passed, 0 failed. We explicitly preserved `KPI-2` and `AC-3` as `NOT_EXECUTED` because customer threshold calibration and external human audit remain pending. Every artifact is cryptographically indexed across 68 SHA-256 hashes with 0 secret leaks."

---

## 2. Core Architectural Rationales (Why & How)

### Why a Two-Tier (O2 + O3) Hierarchy?
- **Fast-Path Efficiency:** Over 85% of traffic in normal network conditions is benign. Running a lightweight 50-tree binary detector (O2) requires only $\sim 5\text{ ms}$, saving CPU cycles.
- **Resource Conservation:** The heavier 60-tree 17-class model (O3) is only invoked when O2 flags an attack with $\ge 50\%$ probability.

### Why 78 Features and Excluding IPs / Ports / Timestamps?
- **Zero Network Memorization:** If Source/Destination IPs or ports were fed to tree models, the trees would split on specific IP subnets in the training lab, resulting in 100% training accuracy but 0% real-world generalization.
- **Statistical Invariance:** 78 statistical flow features (packet length variance, inter-arrival times, flag counts, flow bytes/s) capture protocol behavior regardless of which IP launches the attack.

### Why Random Forest over Deep Learning (LSTM/CNN)?
- **Sub-10ms Inference Latency:** Random Forest inference on structured tabular flow data runs in $5.19\text{ ms P50}$ on standard commodity CPUs without requiring power-hungry GPUs.
- **Explainability & Compactness:** Decision trees provide explicit feature importance and can be bounded by `max_depth` (8 and 12) to fit under 10 MB RAM footprint.

### Why WebSockets for Telemetry?
- **Low Latency & Bounded Overhead:** Polling HTTP endpoints every 500ms creates connection handshake overhead. WebSockets maintain a persistent full-duplex TCP socket with client heartbeat and automatic exponential reconnect backoff.

### Why MySQL with In-Memory Ring Buffer Fallback?
- **Forensic Tamper-Evidence:** MySQL provides ACID-compliant persistence for security audits, forensic timelines, and regulatory compliance.
- **Degraded-Mode Resilience (DM-06):** If the database goes offline, the system seamlessly redirects logs to an in-memory ring buffer, ensuring line-rate traffic detection never stalls.

---

## 3. Top 20 Technical Viva Questions & Answers

#### Q1: What dataset was used, and how did you prevent data leakage?
**Answer:** We used the authentic CIC-DDoS2019 dataset across 18 raw CSV files. We created a 9,990-row frozen representative partition using deterministic seed 42. Imputation medians were computed strictly on the 80% training set (7,992 rows) and applied to the 20% test set (1,998 rows).

#### Q2: What are the exact evaluation metrics of the O2 binary detector?
**Answer:** On the 1,998 held-out test rows: Accuracy = 99.90% (1,996/1,998), Recall = 100.0% (1,854/1,854 attacks), Precision = 99.89%, F1 = 0.9995, FPR = 1.39% (2/144 benign), FNR = 0.0%.

#### Q3: Why does O3 achieve 70.77% accuracy rather than 99%?
**Answer:** O3 performs 17-class granular classification. While reflection vectors (TFTP, Syn, NTP, DNS) achieve $> 93\%$, rare classes like `WebDDoS` and `LDAP` have limited sample support in the demo partition. In our hierarchical design, Tier 1 reliably catches the attack, and Tier 2 provides best-effort vector attribution.

#### Q4: How does CYBER-14 distinguish a flash crowd from a DDoS attack?
**Answer:** The mitigation engine checks both traffic volume and ML confidence. If traffic exceeds $1,000\text{ req/s}$ but O2 confidence is low ($< 0.50$), it classifies the flow as a flash crowd and applies non-destructive `RATE_LIMIT` rather than `BLOCK`.

#### Q5: What were the results of the flash-crowd benchmark?
**Answer:** Across 432 legitimate surge flows (up to $5,000\text{ req/s}$), the system produced **0 destructive blocks (0.0% destructive FPR)** and safely rate-limited high surges.

#### Q6: What is the official KPI-3 latency measurement?
**Answer:** Isolated in-memory model inference latency is **$5.19\text{ ms P50}$** and **$8.21\text{ ms P95}$**, well within the official $\le 30.0\text{ ms}$ threshold.

#### Q7: Why do end-to-end HTTP and WebSocket latencies measure ~140–160 ms?
**Answer:** End-to-end latency includes network socket round-trips, JSON serialization/deserialization, and React UI render cycles. Official KPI-3 strictly governs the real-time ML decision engine fast path.

#### Q8: What mitigation decisions are supported?
**Answer:** `ALLOW` (clean traffic), `RATE_LIMIT` (bounded burst window of 60s, 100 req/s), and `BLOCK` (source isolation for 300s).

#### Q9: Are packets actually dropped on the physical network?
**Answer:** No. Mitigation is executed in safe software simulation (`SimulatedMitigationExecutor`) to prevent accidental host network disruption in an academic testing environment.

#### Q10: How much memory does the entire process consume?
**Answer:** Measured process RSS under load is **224.62 MB**, which is only 11.0% of the $2,048.0\text{ MB}$ AC-4 resource envelope ceiling.

#### Q11: What is the maximum batch inference throughput?
**Answer:** At batch size 1,998, vectorized inference achieves **59,717 flows/sec** ($0.017\text{ ms}$ per sample).

#### Q12: How is role-based access control (RBAC) enforced?
**Answer:** Via JWT Bearer tokens signed with HMAC-SHA256 and bcrypt password hashing. Roles include `viewer`, `analyst`, `operator`, and `admin`.

#### Q13: What happens if an attacker tampers with a JWT token?
**Answer:** The backend cryptographic verification immediately fails and returns an HTTP 401 Unauthorized response (verified in NT-4).

#### Q14: How does the system handle a database outage?
**Answer:** As verified in DM-06, if MySQL becomes unreachable, the telemetry logger redirects audit records to an in-memory ring buffer without halting detection.

#### Q15: What happens if an incoming request is missing features?
**Answer:** As verified in DM-03 and AC-2, Pydantic schema validation rejects the malformed vector with HTTP 422 Unprocessable Entity, preventing pipeline crashes.

#### Q16: How do you handle timestamps across distributed servers?
**Answer:** All timestamps are generated and stored in canonical UTC (`ISO-8601`). The frontend converts timestamps to Indian Standard Time (IST, UTC+05:30) with explicit timezone markers.

#### Q17: What are the 8 degraded-mode scenarios tested?
**Answer:** Missing model (DM-01), policy crash (DM-02), feature truncation (DM-03), extreme surge (DM-04), scaler corruption (DM-05), DB drop (DM-06), O2/O3 conflict (DM-07), borderline flash crowd (DM-08). All 8 passed.

#### Q18: What is the cryptographic checksum status of the repository?
**Answer:** All 68 tracked artifacts match their SHA-256 hashes in `SHA256SUMS.txt`, and secret scanning confirmed 0 exposed credentials across 714 files.

#### Q19: Why are KPI-2 and AC-3 marked as NOT_EXECUTED?
**Answer:** `KPI-2` is awaiting formal customer threshold calibration for flash-crowd containment; `AC-3` requires external human auditor evaluation. Marking them NOT_EXECUTED reflects academic honesty.

#### Q20: What is the overall acceptance score?
**Answer:** 15 total criteria evaluated: **13 PASS, 0 FAIL, 2 NOT_EXECUTED, 0 BLOCKED**.

---

## 4. Top 10 Project Defense & Examiner Challenge Questions

#### D1: "Why didn't you evaluate on all 70 million rows of CIC-DDoS2019?"
**Defense:** "Evaluating 70 million rows would require over 50 GB of memory and distributed Spark cluster infrastructure, exceeding standard single-workstation limits. Instead, we created a stratified, deterministic 9,990-row frozen partition (seed 42) that preserves the authentic class distributions across all 18 raw files, enabling exact reproducibility without data distortion."

#### D2: "Why is O3 classification accuracy only 70.77%? Isn't that low?"
**Defense:** "70.77% represents top-1 classification across 17 fine-grained classes. In high-volume reflection attacks (TFTP, Syn, NTP), accuracy is over 93%. Furthermore, in our hierarchical architecture, O2 already intercepted 100% of attacks at Tier 1. O3's role is tactical attribution, and any low-confidence attribution safely falls back to rate-limiting containment."

#### D3: "If your mitigation is simulated, how do we know it works in a real network?"
**Defense:** "Our `MitigationEngine` produces fully structured, deterministic decision objects (`ALLOW`, `RATE_LIMIT`, `BLOCK`) with duration and rate limits. The simulation layer implements the exact same policy interface required by eBPF/XDP or OpenFlow controllers, proving mathematical correctness without risking host network outages during testing."

#### D4: "Could an attacker evade detection by slowing down packet rates?"
**Defense:** "Low-rate attacks like Slowloris alter flow duration and packet length variance features rather than volume. Our 78-feature contract includes flow inter-arrival times, header lengths, and TCP flag ratios, allowing O2 to identify anomalous protocol behavior even at low rates."

#### D5: "Why did you use Random Forest instead of XGBoost or Deep Neural Networks?"
**Defense:** "Random Forest offers sub-$10\text{ ms}$ inference on CPU, zero GPU dependency, resistance to overfitting with bounded depth, and lower memory footprint (293 KB vs tens of megabytes for neural networks), making it optimal for edge and line-rate gateway deployment."

#### D6: "Why did you keep KPI-2 and AC-3 as NOT_EXECUTED instead of marking them PASS?"
**Defense:** "Academic integrity is a core requirement of this project. KPI-2 has empirical evidence (0 drops on 432 flows), but the client threshold contract was not formally frozen. AC-3 by definition requires an independent human auditor. Claiming PASS without external sign-off would be dishonest."

#### D7: "How do you know your models didn't memorize IP addresses?"
**Defense:** "Our preprocessor enforces a frozen 78-feature manifest. `Source IP`, `Destination IP`, `Source Port`, `Destination Port`, and `Timestamp` are stripped before vectors reach the ML models (verified in NT-4)."

#### D8: "How do you prevent WebSocket broadcast storms during an active DDoS attack?"
**Defense:** "The WebSocket gateway batches telemetry events into fixed-interval frames ($100\text{ ms}$ windows) and applies client-side queue throttling, preventing browser UI crashes under heavy flow rates."

#### D9: "What is the single biggest bottleneck in your system?"
**Defense:** "The end-to-end HTTP JSON serialization and database write path ($\sim 140\text{ ms}$). However, the core ML inference engine runs in under $10\text{ ms}$, meaning line-rate inline filtering can occur asynchronously before database persistence."

#### D10: "What would be your next step if you had 3 more months?"
**Defense:** "We would implement a kernel-level eBPF/XDP driver to test physical hardware line-rate packet dropping, perform distributed multi-node testing on a 10Gbps physical testbed, and collect additional training samples for rare application-layer attack classes."

---

**Viva Preparation Status:** **COMPLETE & DEFENSE-READY**

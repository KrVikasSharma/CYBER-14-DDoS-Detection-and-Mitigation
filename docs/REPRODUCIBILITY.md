# CYBER-14: Independent Evaluation and Reproducibility Guide

**Project**: CYBER-14: Machine Learning-Driven DDoS Detection and Automated Mitigation  
**Specification**: 78-Feature Frozen Vector Contract / Multi-Tier Hierarchical Inference  
**Dataset Reference**: CIC-DDoS2019 Authentic Benchmark (`data/demo/processed/test.csv`)  
**Security Classification**: Non-Sensitive / Zero Committed Credentials  

---

## 1. Overview & Evaluation Philosophy

This document provides complete, deterministic, and self-contained instructions for an independent evaluator to audit, test, and reproduce all acceptance criteria, KPIs, negative security tests, and resource profiles in the CYBER-14 repository.

### Key Guarantees:
- **No 50GB Download Required**: All evaluations run directly on the authentic, frozen 1,998-row 78-feature CIC-DDoS2019 test partition (`data/demo/processed/test.csv`) and structured scenario fixtures.
- **Deterministic & Verifiable**: All model weights, metadata, fixtures, and scenarios are cryptographically checksummed in [`evidence/SHA256SUMS.txt`](file:///d:/capstone/DDoS%20Detection%20and%20Mitigation/evidence/SHA256SUMS.txt).
- **Zero Secrets / Isolated Execution**: The system executes locally without requiring live external services, cloud databases, or exposed production secrets.

---

## 2. Environment Prerequisites

- **Operating System**: Windows 10/11, Linux (Ubuntu 20.04+), or macOS (AMD64 / ARM64).
- **Python**: Python 3.11 or 3.12 (standard distribution).
- **Node.js**: Node.js 18+ and npm.
- **Git**: Git 2.30+.

### Setup Instructions:

```bash
# 1. Clone repository
git clone https://github.com/KrVikasSharma/CYBER-14-DDoS-Detection-and-Mitigation.git
cd "CYBER-14-DDoS-Detection-and-Mitigation"

# 2. Setup Python environment and install dependencies
python -m venv .venv
# On Windows:
.venv\Scripts\activate
# On Linux/macOS:
source .venv/bin/activate

pip install -r requirements.txt
pip install -e .

# 3. Setup Frontend dependencies
cd dashboard/frontend
npm install
cd ../..
```

---

## 3. Authoritative Checksum Verification

Verify that all source contracts, models, test partitions, and scenarios match the official manifest:

```bash
# Verify integrity of all tracked artifacts
python -c "from ml.evaluation.evidence_manifest import verify_sha256sums; from pathlib import Path; print(verify_sha256sums(Path('evidence/SHA256SUMS.txt')))"
```

Expected output: `status: PASS`, `mismatched: []`, `missing: []`.

---

## 4. Complete Test and Acceptance Commands

### A. Full Acceptance Campaign (ACs, KPIs, NTs)
Runs all 15 official acceptance criteria, key performance indicators, and negative security tests:
```bash
python scripts/run_acceptance.py --all
```
*Expected Result*: **13 PASS | 0 FAIL | 2 NOT_EXECUTED (KPI-2, AC-3) | 0 BLOCKED**.

---

### B. Individual Targeted Acceptance Suites

| Target Evaluation | CLI Command | Expected Status | Primary Metrics |
| :--- | :--- | :---: | :--- |
| **KPI Suite (KPI-1 - KPI-6)** | `python scripts/run_acceptance.py --kpis` | **PASS (5/5 PASS, 1 NOT_EXEC)** | Accuracy $\ge 99.9\%$, Latency P95 $< 30\text{ ms}$, Unsafe $= 0$ |
| **Flash-Crowd Benchmark** | `python scripts/run_acceptance.py --flash-crowd` | **NOT_EXECUTED / AUDITED** | $0$ destructive drops on $432$ surge samples |
| **O2 vs O3 Comparison** | `python scripts/run_acceptance.py --o2-o3` | **PASS** | O2 binary ($99.90\%$) vs O3 multiclass ($70.77\%$) |
| **Condition-Wise Repeated Trials** | `python scripts/run_acceptance.py --repeated-trials` | **PASS (5/5 Conditions)** | RT-01..RT-05: Benign, Surge, Attack, Borderline, Boundary |
| **Failure & Degraded-Mode** | `python scripts/run_acceptance.py --degraded-mode` | **PASS (8/8 Scenarios)** | DM-01..DM-08: Fail-closed & graceful degradation |
| **Resource Profiling & Capacity** | `python scripts/run_acceptance.py --resource-profile` | **PASS** | $59,717\text{ flows/s}$ peak throughput, $P95 = 25.12\text{ ms}$ |
| **Negative Security Tests** | `python scripts/run_acceptance.py --negative-tests` | **PASS (5/5 Tests)** | NT-1..NT-5: Token tamper, revocation, attack diversity |

---

### C. Backend Unit Test Suite
Runs all 134 isolated backend unit tests:
```bash
python -m pytest tests/unit
```
*Expected Result*: **134 passed**.

---

### D. Frontend Test Suite & Production Build
In directory `dashboard/frontend`:
```bash
# Run Vitest unit & component test suite
npm test -- --run

# Run Vite production asset bundle build
npm run build
```
*Expected Result*: **3 test files passed, 15 tests passed (15/15)** and **Vite build complete with 0 errors**.

---

## 5. Provenance of Artifacts & Evidence Hierarchy

```
evidence/
├── evidence_manifest.json          # Complete machine-readable catalog of all runs & artifacts
├── SHA256SUMS.txt                  # Cryptographic checksums for exact bitwise verification
├── acceptance/runs/                # Full acceptance campaign runs
├── degraded_mode/runs/             # DM-01 to DM-08 failure mode execution logs
├── flash_crowd/runs/               # KPI-2 / NT-1 surge traffic rate evaluations
├── kpis/runs/                      # KPI-1 to KPI-6 statistical measurement runs
├── negative_tests/runs/            # NT-1 to NT-5 security invariant audits
├── o2_o3/runs/                     # Comparative evaluation matrices
├── repeated_trials/runs/           # RT-01 to RT-05 repeated condition records
└── resource_profiling/runs/        # Multi-layer latency and throughput profiles
```

---

## 6. Secret & Security Handling Policy

- **No Hardcoded Credentials**: No passwords, database tokens, or JWT signing keys are stored in the repository.
- **Safe Defaults**: If `AUTH_SECRET_KEY` is not provided in environment variables, the system operates with test isolation defaults and rejects production authentication escalation.
- **Audit Verification**: Run `python ml/evaluation/evidence_manifest.py` to verify that 0 sensitive tokens are present in any scanned file.

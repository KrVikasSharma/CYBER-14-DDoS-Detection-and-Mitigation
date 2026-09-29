# CYBER-14 STEP 7 — EVIDENCE MANIFEST AND REPRODUCIBILITY REPORT

**Project**: CYBER-14: Autonomous DDoS Detection and Mitigation Pipeline  
**Phase**: Step 7 — Evidence Manifest, Provenance, and Reproducibility Assurance  
**Generated Manifest**: `evidence/evidence_manifest.json`  
**Checksums File**: `evidence/SHA256SUMS.txt`  
**Reproducibility Guide**: `docs/REPRODUCIBILITY.md`  
**Execution Timestamp**: 2026-09-29T04:49:15Z  
**Platform**: Windows 11 (AMD64), Intel64 Family 6 Model 141 (12 Logical Cores), 15.65 GB RAM  
**Git Commit**: `303e19d705ab093670ce5ea4161abff9e2c175cb`  
**Final Step-7 Status**: **PASS**

---

## 1. Executive Summary

CYBER-14 Step 7 establishes an unbroken, cryptographically verified chain of evidence for the entire DDoS Detection and Mitigation project. An external auditor or reviewer can trace every KPI, acceptance condition, failure scenario, and latency profile directly back to its source implementation, frozen dataset partition, and exact execution run without downloading or processing the full 70M-row raw CIC-DDoS2019 dataset.

### Summary of Audit & Verification:
- **Total Artifacts Cataloged & Hashed**: **66 core artifacts** across specifications, frozen datasets, trained ML models, scenario manifests, build outputs, and execution runs.
- **SHA-256 Hash Verification**: **100% Match (66/66 verified, 0 mismatched, 0 missing)**.
- **Secret / Sensitive Data Audit**: **PASS (625 files scanned, 0 sensitive credentials or private keys exposed)**.
- **Acceptance Suite Execution**: **13 PASS | 0 FAIL | 2 NOT_EXECUTED (KPI-2, AC-3) | 0 BLOCKED**.
- **Pytest Unit Suite**: **134/134 PASS (100%)**.
- **Frontend Vitest Suite**: **15/15 PASS (100%)**.
- **Frontend Production Build**: **Vite production build successful (0 errors)**.

---

## 2. Artifact Categories & Provenance

### Category 1: Specifications and Contracts
| Relative Path | Artifact Type | Purpose / Scope | Source Controlled | Verified SHA-256 (Prefix) |
| :--- | :--- | :--- | :---: | :--- |
| `docs/architecture.md` | specification | System Architecture & Threat Model | Yes | `9dbdc24e...` |
| `docs/MYSQL_DATABASE_INTEGRATION.md` | specification | MySQL / Aiven Integration Contract | Yes | `01934988...` |
| `docs/AIVEN_MYSQL_SETUP.md` | specification | Cloud DB Setup Guide | Yes | `6f38ef33...` |
| `docs/TIMEZONE_AND_TIMESTAMP_POLICY.md` | specification | Timezone & Timestamp Policy | Yes | `c5409199...` |
| `pyproject.toml` | configuration | Dependencies and test harness config | Yes | `b3d4f8fb...` |
| `backend/app/config.py` | configuration | Runtime configuration defaults | Yes | `e2a44f5a...` |

### Category 2: Frozen Datasets & Scenario Manifests
| Relative Path | Rows | Features | Related Requirements | Verified SHA-256 (Prefix) |
| :--- | :---: | :---: | :--- | :--- |
| `data/demo/processed/test.csv` | 1,998 | 78 | O2, O3, KPI-1, KPI-5, KPI-6, AC-1, NT-3 | `46e5ca93...` |
| `data/demo/processed/train.csv` | 7,992 | 78 | Training provenance | `3c89c8fa...` |
| `data/demo/flash_crowd/flash_crowd_fixture.csv` | 432 | 78 | KPI-2, NT-1 | `c50f952f...` |
| `data/demo/flash_crowd/flash_crowd_scenarios.json` | — | — | KPI-2, NT-1 rate conditions | `9e30a57a...` |
| `data/demo/degraded_mode/degraded_mode_scenarios.json` | — | — | AC-2, DM-01..DM-08 failure matrix | `6df5c689...` |
| `data/demo/repeated_trials/repeated_trials_manifest.json` | — | — | O5, RT-01..RT-05 condition trials | `45f657a8...` |

### Category 3: Machine Learning Model Artifacts
| Relative Path | Target Scope | Architecture / Hyperparameters | Size | Verified SHA-256 |
| :--- | :--- | :--- | :---: | :--- |
| `data/demo/models/o2/model.joblib` | Binary (`BENIGN` vs `ATTACK`) | `RandomForestClassifier` (50 trees, max depth 8) | 293 KB | `47ab64235dc87bc5381727fc71236f7497ff68b47f6a38fb634160a58146f61d` |
| `data/demo/models/o2/metadata.json` | O2 Provenance | Feature names, schema, metrics | 7.9 KB | `2f94bf34bdfbc4a3ec473ecb8b0e7740f95fcb8b0e11fe9c9c3e921d743a1a9e` |
| `data/demo/models/o3/model.joblib` | Attack-Family (17 Classes) | `RandomForestClassifier` (60 trees, max depth 12) | 9,326 KB | `e357d41a9300c79cd497f5f94c6096ea39590fea0f77b96f35eb49558e8d6b90` |
| `data/demo/models/o3/metadata.json` | O3 Provenance | 17-class mapping, hyperparameters | 7.8 KB | `82f91bcbf716766ea9d9f1c7d2ee015a953fe56314f58f0c5b36417faeebef17` |

### Category 4: Evidence Runs by Evaluation Suite
| Suite Name | Latest Execution Run ID | Reproduction CLI Command | Observed Status | Artifacts Tracked |
| :--- | :--- | :--- | :---: | :---: |
| **Acceptance Suite** | `acceptance-20260929T044038Z-dd0eeae3` | `python scripts/run_acceptance.py --all` | **PASS** | 5 |
| **KPI Suite** | `kpis-20260929T044012Z-95288f61` | `python scripts/run_acceptance.py --kpis` | **PASS** | 2 |
| **Flash-Crowd Benchmark** | `flash_crowd-20260929T044040Z-fdefab7a` | `python scripts/run_acceptance.py --flash-crowd` | **AUDITED** | 4 |
| **O2 vs O3 Comparison** | `o2_o3-20260929T031058Z-cad58c6f` | `python scripts/run_acceptance.py --o2-o3` | **PASS** | 4 |
| **Repeated Trials** | `repeated_trials-20260929T035416Z-f04c9baf` | `python scripts/run_acceptance.py --repeated-trials` | **PASS** | 4 |
| **Degraded Mode** | `degraded_mode-20260929T042601Z-8582c255` | `python scripts/run_acceptance.py --degraded-mode` | **PASS** | 4 |
| **Resource Profiling** | `resource_profile-20260929T043226Z-8a350961` | `python scripts/run_acceptance.py --resource-profile` | **PASS** | 7 |
| **Negative Tests** | `negative-20260929T044052Z-8d3fcd48` | `python scripts/run_acceptance.py --negative-tests` | **PASS** | 3 |

---

## 3. Secret and Sensitive Data Audit

An automated scanner examined **625 text files** across the repository for potential credential exposures (RSA private keys, AWS access keys, high-entropy API tokens, unredacted cloud database passwords):

- **Files Scanned**: 625
- **Exposed Private Keys**: 0
- **Exposed AWS Credentials**: 0
- **Exposed Database Passwords**: 0
- **Exposed Auth Secret Keys**: 0
- **Audit Verdict**: **PASS (Zero sensitive data leaks detected)**

---

## 4. Full Verification & Regression Evidence

| Evaluation Step | Command | Execution Time | Results / Verdict |
| :--- | :--- | :---: | :---: |
| **Full Acceptance Suite** | `python scripts/run_acceptance.py --all` | ~18s | **13 PASS, 0 FAIL, 2 NOT_EXEC** |
| **Degraded Mode Suite** | `python scripts/run_acceptance.py --degraded-mode` | ~4s | **8/8 PASS** |
| **Resource Profiling** | `python scripts/run_acceptance.py --resource-profile` | ~42s | **PASS** ($59,717\text{ flows/s}$, $P95 = 25.12\text{ ms}$) |
| **Backend Unit Tests** | `python -m pytest tests/unit` | ~32s | **134/134 PASS** |
| **Frontend Unit Tests** | `npm.cmd test -- --run` | ~5s | **15/15 PASS** |
| **Frontend Production Build** | `npm.cmd run build` | ~1.3s | **PASS (0 build errors)** |

---

## 5. Working Tree & Git Integrity

- **Branch**: `main` (synchronized with `origin/main`).
- **Unstaged Working Files**: All modifications and created manifests remain strictly unstaged and uncommitted per instruction.
- **Push Actions**: 0 pushes executed.

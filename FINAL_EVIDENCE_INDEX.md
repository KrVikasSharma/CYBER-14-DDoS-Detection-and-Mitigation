# CYBER-14: Master Evidence & Artifact Index
## Comprehensive Catalog of Research Evidence, Schemas, Manifests, and Verification Records

**Project Identifier:** CYBER-14 — DDoS Detection & Mitigation  
**Evaluation Standard:** Auditable Machine Learning & Cybersecurity Evidence  
**Generated / Consolidated:** September 2026  
**Repository Working Copy:** `D:\capstone\DDoS Detection and Mitigation`  
**Dataset Reference:** Canadian Institute for Cybersecurity CIC-DDoS2019 (28.92 GB, 18 Files)  

---

## 1. Evidence Governance & Integrity Policy

Every claim made in the project documentation, reports, and presentation is supported by immutable, versioned evidence artifacts stored within the repository. 

To maintain academic and forensic integrity:
- **No Synthetic Substitutions:** Real CIC-DDoS2019 data was inspected and sampled. Synthetic test fixtures are strictly labeled as `fixture_only` and quarantined from evaluation metrics.
- **Contract Freezing:** Feature names, ordering, and types are frozen under SHA-256 digests. Any vector missing or altering features is rejected.
- **Impartial Status Attribution:** Acceptance tests and negative tests that were not run or blocked are recorded as `NOT_EXECUTED` or `BLOCKED` rather than modified into passing grades.

---

## 2. Feature Manifests & Schema Evidence

| File Path | Format | Size | Date / Hash | Description & Verification Status |
| :--- | :--- | :--- | :--- | :--- |
| [`evidence/cic_ddos2019_feature_manifest.json`](file:///D:/capstone/DDoS%20Detection%20and%20Mitigation/evidence/cic_ddos2019_feature_manifest.json) | JSON | 31.7 KB | Fingerprint: `997e6b28c6bcc5bf76a57789cf3f0cc8e41f7792e95742b3f8a800852c6ede3a` | **FROZEN CONTRACT:** Authoritative list of 78 numeric network features, exact types, ordering, and 10 excluded columns. Status: **VERIFIED & ENFORCED**. |
| [`evidence/cic_ddos2019_feature_manifest.md`](file:///D:/capstone/DDoS%20Detection%20and%20Mitigation/evidence/cic_ddos2019_feature_manifest.md) | Markdown | 17.4 KB | 2026-09-21 | Human-readable explanation of feature sanitization, whitespace trimming, and column exclusion rationale. Status: **ACTIVE**. |
| [`evidence/cic_ddos2019_raw_schema_inventory.json`](file:///D:/capstone/DDoS%20Detection%20and%20Mitigation/evidence/cic_ddos2019_raw_schema_inventory.json) | JSON | 25.6 KB | 2026-09-21 | Complete schema inspection record across all 18 raw CSV files (28.92 GB, 70,427,637 rows), documenting 88 raw headers. Status: **VERIFIED ON DISK**. |
| [`evidence/cic_ddos2019_raw_schema_report.md`](file:///D:/capstone/DDoS%20Detection%20and%20Mitigation/evidence/cic_ddos2019_raw_schema_report.md) | Markdown | 13.4 KB | 2026-09-21 | Comprehensive narrative report detailing file paths, row counts, byte sizes, and header whitespace anomalies. Status: **ACTIVE**. |
| [`evidence/cic_ddos2019_label_inventory.json`](file:///D:/capstone/DDoS%20Detection%20and%20Mitigation/evidence/cic_ddos2019_label_inventory.json) | JSON | 2.3 KB | 2026-09-21 | Inventory of all 17 distinct raw label strings found in the raw dataset and their normalized mappings. Status: **VERIFIED**. |

---

## 3. Demonstration Sample & Evaluation Evidence

| File Path | Format | Size | Date / Hash | Description & Verification Status |
| :--- | :--- | :--- | :--- | :--- |
| [`evidence/cic_ddos2019_demo_sample_manifest.json`](file:///D:/capstone/DDoS%20Detection%20and%20Mitigation/evidence/cic_ddos2019_demo_sample_manifest.json) | JSON | 5.6 KB | 2026-09-21 | Metadata manifest for the 9,990-row demonstration sample extracted deterministically (555 rows per file) across 18 CSVs. Status: **VERIFIED**. |
| [`evidence/cic_ddos2019_demo_sample_manifest.md`](file:///D:/capstone/DDoS%20Detection%20and%20Mitigation/evidence/cic_ddos2019_demo_sample_manifest.md) | Markdown | 3.1 KB | 2026-09-21 | Narrative summary of sample extraction parameters, class distributions, and train/test partition details. Status: **ACTIVE**. |
| [`evidence/cic_ddos2019_demo_evaluation.json`](file:///D:/capstone/DDoS%20Detection%20and%20Mitigation/evidence/cic_ddos2019_demo_evaluation.json) | JSON | 17.5 KB | 2026-09-21T17:48:51Z | Comprehensive evaluation metrics on 1,998 test rows: O2 accuracy (99.90%), O3 accuracy (70.77%), confusion matrices, latency ($p50=16.18\text{ms}$). Status: **VERIFIED DEMO RESULT**. |
| [`evidence/cic_ddos2019_demo_evaluation.md`](file:///D:/capstone/DDoS%20Detection%20and%20Mitigation/evidence/cic_ddos2019_demo_evaluation.md) | Markdown | 3.6 KB | 2026-09-21 | Formatted presentation report detailing O2/O3 scores, per-class breakdown, latency benchmarks, and disclaimers. Status: **ACTIVE**. |
| [`evidence/demo_presentation_verification.json`](file:///D:/capstone/DDoS%20Detection%20and%20Mitigation/evidence/demo_presentation_verification.json) | JSON | 3.2 KB | 2026-09-21T18:07:31Z | Machine-readable validation log of the 6 core presentation tasks (startup, auth, 3 cases, websocket, UI views, evidence). Status: **PASS**. |
| [`evidence/demo_presentation_verification.md`](file:///D:/capstone/DDoS%20Detection%20and%20Mitigation/evidence/demo_presentation_verification.md) | Markdown | 4.4 KB | 2026-09-21 | Detailed verification report demonstrating end-to-end presentation readiness with explicit pass/fail checks. Status: **ACTIVE**. |

---

## 4. Official Acceptance & Negative Test Evidence

| File Path | Format | Size | Run ID | Description & Verification Status |
| :--- | :--- | :--- | :--- | :--- |
| [`evidence/acceptance/runs/acceptance-20260921T050124Z-ee6af611/result.json`](file:///D:/capstone/DDoS%20Detection%20and%20Mitigation/evidence/acceptance/runs/acceptance-20260921T050124Z-ee6af611/result.json) | JSON | 2.8 KB | `acceptance-20260921T050124Z-ee6af611` | Official Acceptance Criteria (AC-1..4) and KPI (KPI-1..6) evaluation run. Formal Status: **NOT_EXECUTED** (Fixture-only mechanics; real 70M-row acceptance unexecuted). |
| [`evidence/acceptance/runs/acceptance-20260921T050124Z-ee6af611/metrics.json`](file:///D:/capstone/DDoS%20Detection%20and%20Mitigation/evidence/acceptance/runs/acceptance-20260921T050124Z-ee6af611/metrics.json) | JSON | 2.1 KB | `acceptance-20260921T050124Z-ee6af611` | Metric output record from acceptance harness execution. Status: **RECORDED**. |
| [`evidence/acceptance/runs/acceptance-20260921T050124Z-ee6af611/environment.json`](file:///D:/capstone/DDoS%20Detection%20and%20Mitigation/evidence/acceptance/runs/acceptance-20260921T050124Z-ee6af611/environment.json) | JSON | 283 B | `acceptance-20260921T050124Z-ee6af611` | Execution environment metadata (Python 3.12, Windows OS, host architecture). Status: **RECORDED**. |
| [`evidence/acceptance/acceptance_config.json`](file:///D:/capstone/DDoS%20Detection%20and%20Mitigation/evidence/acceptance/acceptance_config.json) | JSON | 835 B | Config Hash: `8bb92565...` | Official configuration threshold file for acceptance runners. Status: **ACTIVE**. |
| [`evidence/negative_tests/runs/negative-20260921T050145Z-1ad2719c/result.json`](file:///D:/capstone/DDoS%20Detection%20and%20Mitigation/evidence/negative_tests/runs/negative-20260921T050145Z-1ad2719c/result.json) | JSON | 2.9 KB | `negative-20260921T050145Z-1ad2719c` | Official Negative Tests (NT-1..5) evaluation run. Formal Status: **BLOCKED** (Requires authorized physical attack testbed). |

---

## 5. Machine Learning Model Artifacts & Provenance

| Artifact Location | Type | File Size | Parameters / Features | Operational Role |
| :--- | :--- | :--- | :--- | :--- |
| [`data/demo/models/o2/model.joblib`](file:///D:/capstone/DDoS%20Detection%20and%20Mitigation/data/demo/models/o2/model.joblib) | Joblib / Scikit-Learn | 300,089 B | 50 trees, max depth 8, random state 42 | **O2 Binary Detector:** Evaluates 78 features $\to$ 0 (BENIGN) or 1 (ATTACK). Test accuracy: 99.90%. |
| [`data/demo/models/o2/feature_metadata.json`](file:///D:/capstone/DDoS%20Detection%20and%20Mitigation/data/demo/models/o2/feature_metadata.json) | JSON | 2.3 KB | 78 numeric features | Exact feature ordering and names expected by O2 serialized estimator. |
| [`data/demo/models/o2/training_metadata.json`](file:///D:/capstone/DDoS%20Detection%20and%20Mitigation/data/demo/models/o2/training_metadata.json) | JSON | 407 B | Train rows: 7,992; Test rows: 1,998 | Record of train/test partition size and training duration. |
| [`data/demo/models/o2/o2_reference_record.json`](file:///D:/capstone/DDoS%20Detection%20and%20Mitigation/data/demo/models/o2/o2_reference_record.json) | JSON | 2.9 KB | Precision: 0.9989, Recall: 1.000 | Immutable record of O2 reference metrics. |
| [`data/demo/models/o3/model.joblib`](file:///D:/capstone/DDoS%20Detection%20and%20Mitigation/data/demo/models/o3/model.joblib) | Joblib / Scikit-Learn | 9,549,841 B | 60 trees, max depth 12, 17 classes | **O3 Multi-Class Classifier:** Resolves attack family across 17 classes. Test accuracy: 70.77%. |
| [`data/demo/models/o3/class_metadata.json`](file:///D:/capstone/DDoS%20Detection%20and%20Mitigation/data/demo/models/o3/class_metadata.json) | JSON | 773 B | 17 class labels | Numerical target to string class label mapping dictionary. |
| [`data/demo/models/o3/feature_metadata.json`](file:///D:/capstone/DDoS%20Detection%20and%20Mitigation/data/demo/models/o3/feature_metadata.json) | JSON | 2.3 KB | 78 numeric features | Exact feature ordering and names expected by O3 serialized estimator. |
| [`data/demo/models/o3/o3_reference_record.json`](file:///D:/capstone/DDoS%20Detection%20and%20Mitigation/data/demo/models/o3/o3_reference_record.json) | JSON | 3.8 KB | Macro F1: 0.6399, Weighted F1: 0.6909 | Immutable record of O3 reference metrics across 17 classes. |

---

## 6. Demonstration Data Artifacts

| File Path | Format | Size | Description & Usage |
| :--- | :--- | :--- | :--- |
| [`data/demo/cic_ddos2019_sample.csv`](file:///D:/capstone/DDoS%20Detection%20and%20Mitigation/data/demo/cic_ddos2019_sample.csv) | CSV | 4.49 MB | Deterministic 9,990-row sample extracted from the 18 raw files (555 rows per file). Contains 641 benign and 9,349 attack rows across 17 classes. |
| [`data/demo/demo_scenarios.json`](file:///D:/capstone/DDoS%20Detection%20and%20Mitigation/data/demo/demo_scenarios.json) | JSON | 8.0 KB | Complete 78-feature real vector definitions for the three presentation cases: `benign`, `flash_crowd`, and `attack_fixture` (NetBIOS). Replayed by `/ws/traffic`. |

---

## 7. Schema and Record Templates

| File Path | Format | Size | Description |
| :--- | :--- | :--- | :--- |
| [`evidence/dataset_manifest_template.json`](file:///D:/capstone/DDoS%20Detection%20and%20Mitigation/evidence/dataset_manifest_template.json) | JSON | 379 B | Baseline template for recording raw dataset origin, hash, and row counts. |
| [`evidence/mitigation_record_template.json`](file:///D:/capstone/DDoS%20Detection%20and%20Mitigation/evidence/mitigation_record_template.json) | JSON | 877 B | Standard schema for recording mitigation policy inputs, decisions, expiries, and audit logs. |
| [`evidence/o2_reference_record_template.json`](file:///D:/capstone/DDoS%20Detection%20and%20Mitigation/evidence/o2_reference_record_template.json) | JSON | 697 B | Standard schema for recording O2 binary model evaluation outputs. |
| [`evidence/o3_reference_record_template.json`](file:///D:/capstone/DDoS%20Detection%20and%20Mitigation/evidence/o3_reference_record_template.json) | JSON | 626 B | Standard schema for recording O3 multi-class model evaluation outputs. |

---

## 8. Verification & Audit Trail Summary

Every evidence record cataloged above has been validated against the active codebase:
1. **API Accessibility:** The FastAPI backend exposes direct read access to these artifacts via `/api/v1/evidence/demo-manifest`, `/api/v1/evidence/demo-evaluation`, and `/api/v1/evidence/feature-manifest`.
2. **Dashboard Integration:** The React dashboard renders these files in the **Evidence & Audit Registry** view.
3. **Automated Consistency:** Tested and passed by [`scripts/verify_demo_presentation.py`](file:///D:/capstone/DDoS%20Detection%20and%20Mitigation/scripts/verify_demo_presentation.py) and Pytest regression suites.

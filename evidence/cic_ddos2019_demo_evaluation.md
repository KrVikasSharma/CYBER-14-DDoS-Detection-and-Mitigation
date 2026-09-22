# DEMO SAMPLE EVALUATION & MITIGATION REPORT

> [!IMPORTANT]
> **DEMO SAMPLE RESULT — REAL CIC-DDoS2019 SAMPLE — NOT OFFICIAL ACCEPTANCE**
> This report documents model training, evaluation, latency, and mitigation performance on the controlled 10,000-row real CIC-DDoS2019 demonstration sample. It does NOT constitute official acceptance KPI evaluation.

- **Generated At (UTC):** 2026-09-21T17:48:51.674517+00:00
- **Training Rows:** 7,992
- **Testing Rows:** 1,998
- **Frozen Model Features:** Exactly 78
- **Feature Manifest Fingerprint:** `997e6b28c6bcc5bf76a57789cf3f0cc8e41f7792e95742b3f8a800852c6ede3a`

## 1. O2 Binary Reference Detector Metrics

- **Accuracy:** `99.90%`
- **Precision:** `99.89%`
- **Recall:** `100.00%`
- **F1 Score:** `0.9995`

### O2 Confusion Matrix (Test Split)

| | Predicted Legitimate (0) | Predicted Attack (1) | Total |
| :--- | -: | -: | -: |
| **Actual Legitimate (0)** | 142 (TN) | 2 (FP) | 144 |
| **Actual Attack (1)** | 0 (FN) | 1854 (TP) | 1854 |
| **Total** | 142 | 1856 | 1998 |

## 2. O3 Multiclass Attack Classifier Metrics

- **Accuracy:** `70.77%`
- **Macro Precision:** `65.82%`
- **Macro Recall:** `66.87%`
- **Macro F1 Score:** `0.6399`
- **Weighted F1 Score:** `0.6909`
- **Distinct Classes Handled:** `17`

### O3 Per-Class Performance Summary

| Class | Support | Precision | Recall | F1 Score |
| :--- | -: | -: | -: | -: |
| `BENIGN` | 144 | 100.0% | 99.3% | 0.9965 |
| `DRDOS_DNS` | 90 | 88.5% | 51.1% | 0.6479 |
| `DRDOS_LDAP` | 101 | 37.9% | 63.4% | 0.4741 |
| `DRDOS_MSSQL` | 96 | 28.6% | 8.3% | 0.1290 |
| `DRDOS_NETBIOS` | 85 | 66.3% | 71.8% | 0.6893 |
| `DRDOS_NTP` | 84 | 94.3% | 97.6% | 0.9591 |
| `DRDOS_SNMP` | 106 | 92.0% | 75.5% | 0.8290 |
| `DRDOS_SSDP` | 103 | 51.7% | 90.3% | 0.6572 |
| `DRDOS_UDP` | 102 | 57.8% | 91.2% | 0.7072 |
| `LDAP` | 40 | 0.0% | 0.0% | 0.0000 |
| `MSSQL` | 165 | 79.0% | 75.2% | 0.7702 |
| `NETBIOS` | 215 | 78.6% | 73.5% | 0.7596 |
| `PORTMAP` | 97 | 57.6% | 74.2% | 0.6486 |
| `SYN` | 246 | 96.7% | 71.5% | 0.8224 |
| `TFTP` | 114 | 60.9% | 95.6% | 0.7440 |
| `UDP` | 108 | 73.5% | 79.6% | 0.7644 |
| `UDP-LAG` | 102 | 55.9% | 18.6% | 0.2794 |

## 3. Latency Measurements (100 Trials)

| Metric | O2 Detector Latency | O3 Classifier Latency | Unit |
| :--- | -: | -: | :--- |
| **Median (p50)** | 16.18 | 16.10 | ms |
| **95th Percentile (p95)** | 16.74 | 17.05 | ms |
| **99th Percentile (p99)** | 17.51 | 18.86 | ms |
| **Min / Max** | 15.60 / 49.79 | 15.44 / 20.00 | ms |

## 4. End-to-End Mitigation Demonstration

| Scenario | Source IP | Detection / Classification | Mitigation Action | Verified |
| :--- | :--- | :--- | :--- | :-: |
| Legitimate Benign Traffic | `192.168.1.50` | LEGITIMATE (0) -> BENIGN | **`ALLOW`** | PASS |
| High-Rate Legitimate Flash-Crowd Traffic | `192.168.1.60` | LEGITIMATE (0) -> BENIGN | **`RATE_LIMIT`** | PASS |
| Confirmed High-Confidence Attack Flow (Confidence >= 0.80) | `198.51.100.99` | ATTACK (1) -> DRDOS_DNS | **`BLOCK`** | PASS |
| Detected Attack: SYN | `198.51.100.11` | ATTACK (1) -> TFTP | **`RATE_LIMIT`** | PASS |
| Detected Attack: DRDOS_DNS | `198.51.100.12` | ATTACK (1) -> DRDOS_SSDP | **`RATE_LIMIT`** | PASS |
| Detected Attack: TFTP | `198.51.100.13` | ATTACK (1) -> TFTP | **`RATE_LIMIT`** | PASS |
| Detected Attack: MSSQL | `198.51.100.14` | ATTACK (1) -> MSSQL | **`RATE_LIMIT`** | PASS |
| Detected Attack: NETBIOS | `198.51.100.15` | ATTACK (1) -> NETBIOS | **`BLOCK`** | PASS |
| Detected Attack: UDP | `198.51.100.16` | ATTACK (1) -> DRDOS_UDP | **`RATE_LIMIT`** | PASS |

# CIC-DDoS2019 Frozen Feature Manifest (Version 1.0.0)

**Dataset Identifier:** `cic-ddos2019`  
**Source Reference:** [`evidence/cic_ddos2019_raw_schema_inventory.json`](file:///d:/capstone/DDoS%20Detection%20and%20Mitigation/evidence/cic_ddos2019_raw_schema_inventory.json)  
**Total Source Raw Columns:** 88 columns  
**Total Included Features (O2 / O3):** 78 features  
**Total Excluded Columns:** 10 columns  
**Feature Vector SHA-256 Fingerprint:** `997e6b28c6bcc5bf76a57789cf3f0cc8e41f7792e95742b3f8a800852c6ede3a`  
**Created At (UTC):** 2026-09-21T17:25:14.738736+00:00  

---

## 1. RAW-COLUMN NORMALIZATION RULE

- **Method:** `str.strip()` applied to each header token.
- **Provenance Preservation:** The raw 88-column header from the CIC-DDoS2019 CSV files contains leading whitespace on 80 of the 88 columns (e.g. `' Source IP'`, `' Protocol'`, `' Label'`).
- **Standardization:**
  - `' Source IP'` -> `'Source IP'`
  - `' Protocol'` -> `'Protocol'`
  - `' Label'` -> `'Label'`
- **Spelling Integrity:** The original dataset spelling `'SimillarHTTP'` (retaining the double 'l' typo) is explicitly preserved and not silently renamed.

---

## 2. EXPLICIT EXCLUDED COLUMNS (10 COLUMNS)

Every excluded column is categorized with an explicit rationale grounded in leakage prevention and protocol robustness:

| # | Raw Column Name | Normalized Name | Source Index | Type | Exclusion Category | Rationale |
| :-: | :--- | :--- | :-: | :-: | :--- | :--- |
| 1 | `Unnamed: 0` | `Unnamed: 0` | 0 | `int64` | **INDEX_LEAKAGE** | Arbitrary integer row index generated during CSV export. Has zero causal relationship to network traffic; if included, decision trees partition row offsets. |
| 2 | `Flow ID` | `Flow ID` | 1 | `str` | **IDENTITY_LEAKAGE** | Textual flow tuple identifier string combining IPs, ports, and timestamp. Memorizes specific connection instances rather than traffic dynamics. |
| 3 | ` Source IP` | `Source IP` | 2 | `str` | **IDENTITY_LEAKAGE** | Host source IP address. Testbed IP addresses memorize specific simulated attackers/clients rather than generalizable attack traffic patterns. |
| 4 | ` Source Port` | `Source Port` | 3 | `int64` | **EPHEMERAL_PORT_LEAKAGE** | Client or reflected source port. Highly dynamic/ephemeral or testbed-artifact specific; causes brittle port memorization. |
| 5 | ` Destination IP` | `Destination IP` | 4 | `str` | **IDENTITY_LEAKAGE** | Victim host IP address. Memorizing static victim subnet addresses prevents generalization to any other protected network. |
| 6 | ` Destination Port` | `Destination Port` | 5 | `int64` | **SERVICE_PORT_BIAS** | Destination service port. In CIC-DDoS2019, attack scripts targeted specific ports (e.g. 53, 123). Including destination port encourages models to predict attack types based purely on port numbers rather than flow volume and packet rate dynamics, causing severe false positives against legitimate services on the same port. |
| 7 | ` Timestamp` | `Timestamp` | 7 | `str` | **TEMPORAL_LEAKAGE** | Capture wall-clock timestamp string. Attack campaigns occurred during discrete time windows on Jan 12 and Mar 11, 2019. Trees learn to partition capture dates/times directly. |
| 8 | `SimillarHTTP` | `SimillarHTTP` | 85 | `str` | **PAYLOAD_METADATA_SPARSITY** | Non-numeric string metadata field containing HTTP request snippets or '0'. Highly sparse, absent for UDP/ICMP/non-HTTP flows, and introduces text memorization. Excluded to ensure a uniform numeric flow feature space. Original spelling 'SimillarHTTP' is strictly preserved without modification. |
| 9 | ` Inbound` | `Inbound` | 86 | `int64` | **TOPOLOGY_LEAKAGE** | Artificial binary direction flag assigned during testbed packet generation indicating flow toward victim subnet. In production perimeter monitoring, all ingress traffic is inbound, making this testbed-specific flag ungeneralizable. |
| 10 | ` Label` | `Label` | 87 | `str` | **TARGET_LEAKAGE** | Supervised learning ground-truth target column. Preprocessed into label_original, label_normalized, and label_binary; strictly excluded from model feature inputs. |

---

## 3. O2 & O3 FEATURE CONTRACTS

### Shared Feature Vector Decision
Both **O2** (binary attack-vs-benign reference detector) and **O3** (attack-type multi-class reference classifier) use the **identical 78-feature vector**.
- **Parity:** In real-time detection, feature extraction occurs once per flow. Shared features enable immediate O3 classification following an O2 positive trigger without re-indexing.
- **Integrity:** Both models share the identical zero-identity-leakage boundary (no IPs, ports, or timestamps).

### Ordered Feature List (78 Numeric Features)
Every feature is strictly ordered according to its natural sequence in the raw CSV schema (after exclusions):

| # | Normalized Feature Name | Raw Header in CSV | Source Index | Type | Category | Network Characteristic / Rationale |
| :-: | :--- | :--- | :-: | :-: | :--- | :--- |
| 1 | `Protocol` | ` Protocol` | 6 | `int64` | `protocol` | Transport layer protocol number (e.g., 6 for TCP, 17 for UDP). |
| 2 | `Flow Duration` | ` Flow Duration` | 8 | `int64` | `temporal_duration` | Total duration of the bidirectional flow in microseconds. |
| 3 | `Total Fwd Packets` | ` Total Fwd Packets` | 9 | `int64` | `volumetric_packet_count` | Total number of packets transmitted in the forward direction. |
| 4 | `Total Backward Packets` | ` Total Backward Packets` | 10 | `int64` | `volumetric_packet_count` | Total number of packets transmitted in the backward direction. |
| 5 | `Total Length of Fwd Packets` | `Total Length of Fwd Packets` | 11 | `float64` | `volumetric_byte_length` | Total bytes transmitted in forward packet payloads. |
| 6 | `Total Length of Bwd Packets` | ` Total Length of Bwd Packets` | 12 | `float64` | `volumetric_byte_length` | Total bytes transmitted in backward packet payloads. |
| 7 | `Fwd Packet Length Max` | ` Fwd Packet Length Max` | 13 | `float64` | `packet_size_distribution` | Maximum packet size in forward direction. |
| 8 | `Fwd Packet Length Min` | ` Fwd Packet Length Min` | 14 | `float64` | `packet_size_distribution` | Minimum packet size in forward direction. |
| 9 | `Fwd Packet Length Mean` | ` Fwd Packet Length Mean` | 15 | `float64` | `packet_size_distribution` | Mean packet size in forward direction. |
| 10 | `Fwd Packet Length Std` | ` Fwd Packet Length Std` | 16 | `float64` | `packet_size_distribution` | Standard deviation of forward packet sizes. |
| 11 | `Bwd Packet Length Max` | `Bwd Packet Length Max` | 17 | `float64` | `packet_size_distribution` | Maximum packet size in backward direction. |
| 12 | `Bwd Packet Length Min` | ` Bwd Packet Length Min` | 18 | `float64` | `packet_size_distribution` | Minimum packet size in backward direction. |
| 13 | `Bwd Packet Length Mean` | ` Bwd Packet Length Mean` | 19 | `float64` | `packet_size_distribution` | Mean packet size in backward direction. |
| 14 | `Bwd Packet Length Std` | ` Bwd Packet Length Std` | 20 | `float64` | `packet_size_distribution` | Standard deviation of backward packet sizes. |
| 15 | `Flow Bytes/s` | `Flow Bytes/s` | 21 | `float64` | `rate_throughput` | Flow transmission rate in bytes per second. |
| 16 | `Flow Packets/s` | ` Flow Packets/s` | 22 | `float64` | `rate_throughput` | Flow transmission rate in packets per second. |
| 17 | `Flow IAT Mean` | ` Flow IAT Mean` | 23 | `float64` | `temporal_iat` | Mean inter-arrival time between packets in the flow. |
| 18 | `Flow IAT Std` | ` Flow IAT Std` | 24 | `float64` | `temporal_iat` | Standard deviation of inter-arrival times in the flow. |
| 19 | `Flow IAT Max` | ` Flow IAT Max` | 25 | `float64` | `temporal_iat` | Maximum inter-arrival time in the flow. |
| 20 | `Flow IAT Min` | ` Flow IAT Min` | 26 | `float64` | `temporal_iat` | Minimum inter-arrival time in the flow. |
| 21 | `Fwd IAT Total` | `Fwd IAT Total` | 27 | `float64` | `temporal_iat` | Total inter-arrival time of forward packets. |
| 22 | `Fwd IAT Mean` | ` Fwd IAT Mean` | 28 | `float64` | `temporal_iat` | Mean inter-arrival time between forward packets. |
| 23 | `Fwd IAT Std` | ` Fwd IAT Std` | 29 | `float64` | `temporal_iat` | Standard deviation of forward packet inter-arrival times. |
| 24 | `Fwd IAT Max` | ` Fwd IAT Max` | 30 | `float64` | `temporal_iat` | Maximum forward inter-arrival time. |
| 25 | `Fwd IAT Min` | ` Fwd IAT Min` | 31 | `float64` | `temporal_iat` | Minimum forward inter-arrival time. |
| 26 | `Bwd IAT Total` | `Bwd IAT Total` | 32 | `float64` | `temporal_iat` | Total inter-arrival time of backward packets. |
| 27 | `Bwd IAT Mean` | ` Bwd IAT Mean` | 33 | `float64` | `temporal_iat` | Mean inter-arrival time between backward packets. |
| 28 | `Bwd IAT Std` | ` Bwd IAT Std` | 34 | `float64` | `temporal_iat` | Standard deviation of backward packet inter-arrival times. |
| 29 | `Bwd IAT Max` | ` Bwd IAT Max` | 35 | `float64` | `temporal_iat` | Maximum backward inter-arrival time. |
| 30 | `Bwd IAT Min` | ` Bwd IAT Min` | 36 | `float64` | `temporal_iat` | Minimum backward inter-arrival time. |
| 31 | `Fwd PSH Flags` | `Fwd PSH Flags` | 37 | `int64` | `tcp_flags` | Number of forward packets with Push (PSH) flag set. |
| 32 | `Bwd PSH Flags` | ` Bwd PSH Flags` | 38 | `int64` | `tcp_flags` | Number of backward packets with Push (PSH) flag set. |
| 33 | `Fwd URG Flags` | ` Fwd URG Flags` | 39 | `int64` | `tcp_flags` | Number of forward packets with Urgent (URG) flag set. |
| 34 | `Bwd URG Flags` | ` Bwd URG Flags` | 40 | `int64` | `tcp_flags` | Number of backward packets with Urgent (URG) flag set. |
| 35 | `Fwd Header Length` | ` Fwd Header Length` | 41 | `int64` | `header_length` | Total bytes used for headers in the forward direction. |
| 36 | `Bwd Header Length` | ` Bwd Header Length` | 42 | `int64` | `header_length` | Total bytes used for headers in the backward direction. |
| 37 | `Fwd Packets/s` | `Fwd Packets/s` | 43 | `float64` | `rate_throughput` | Forward packet transmission rate per second. |
| 38 | `Bwd Packets/s` | ` Bwd Packets/s` | 44 | `float64` | `rate_throughput` | Backward packet transmission rate per second. |
| 39 | `Min Packet Length` | ` Min Packet Length` | 45 | `float64` | `packet_size_distribution` | Minimum packet length observed across the entire flow. |
| 40 | `Max Packet Length` | ` Max Packet Length` | 46 | `float64` | `packet_size_distribution` | Maximum packet length observed across the entire flow. |
| 41 | `Packet Length Mean` | ` Packet Length Mean` | 47 | `float64` | `packet_size_distribution` | Mean packet length observed across the entire flow. |
| 42 | `Packet Length Std` | ` Packet Length Std` | 48 | `float64` | `packet_size_distribution` | Standard deviation of packet length across the flow. |
| 43 | `Packet Length Variance` | ` Packet Length Variance` | 49 | `float64` | `packet_size_distribution` | Variance of packet length across the flow. |
| 44 | `FIN Flag Count` | `FIN Flag Count` | 50 | `int64` | `tcp_flags` | Count of packets with TCP FIN flag set. |
| 45 | `SYN Flag Count` | ` SYN Flag Count` | 51 | `int64` | `tcp_flags` | Count of packets with TCP SYN flag set. |
| 46 | `RST Flag Count` | ` RST Flag Count` | 52 | `int64` | `tcp_flags` | Count of packets with TCP RST flag set. |
| 47 | `PSH Flag Count` | ` PSH Flag Count` | 53 | `int64` | `tcp_flags` | Count of packets with TCP PSH flag set. |
| 48 | `ACK Flag Count` | ` ACK Flag Count` | 54 | `int64` | `tcp_flags` | Count of packets with TCP ACK flag set. |
| 49 | `URG Flag Count` | ` URG Flag Count` | 55 | `int64` | `tcp_flags` | Count of packets with TCP URG flag set. |
| 50 | `CWE Flag Count` | ` CWE Flag Count` | 56 | `int64` | `tcp_flags` | Count of packets with TCP CWE flag set. |
| 51 | `ECE Flag Count` | ` ECE Flag Count` | 57 | `int64` | `tcp_flags` | Count of packets with TCP ECE flag set. |
| 52 | `Down/Up Ratio` | ` Down/Up Ratio` | 58 | `float64` | `flow_ratio` | Ratio of incoming to outgoing packets. |
| 53 | `Average Packet Size` | ` Average Packet Size` | 59 | `float64` | `packet_size_distribution` | Average packet size in the flow. |
| 54 | `Avg Fwd Segment Size` | ` Avg Fwd Segment Size` | 60 | `float64` | `packet_size_distribution` | Average forward segment size. |
| 55 | `Avg Bwd Segment Size` | ` Avg Bwd Segment Size` | 61 | `float64` | `packet_size_distribution` | Average backward segment size. |
| 56 | `Fwd Header Length.1` | ` Fwd Header Length.1` | 62 | `int64` | `header_length` | Duplicate forward header length metric preserved from CICFlowMeter. |
| 57 | `Fwd Avg Bytes/Bulk` | `Fwd Avg Bytes/Bulk` | 63 | `int64` | `bulk_transfer` | Average bytes per bulk transmission in forward direction. |
| 58 | `Fwd Avg Packets/Bulk` | ` Fwd Avg Packets/Bulk` | 64 | `int64` | `bulk_transfer` | Average packets per bulk transmission in forward direction. |
| 59 | `Fwd Avg Bulk Rate` | ` Fwd Avg Bulk Rate` | 65 | `int64` | `bulk_transfer` | Average bulk transfer rate in forward direction. |
| 60 | `Bwd Avg Bytes/Bulk` | ` Bwd Avg Bytes/Bulk` | 66 | `int64` | `bulk_transfer` | Average bytes per bulk transmission in backward direction. |
| 61 | `Bwd Avg Packets/Bulk` | ` Bwd Avg Packets/Bulk` | 67 | `int64` | `bulk_transfer` | Average packets per bulk transmission in backward direction. |
| 62 | `Bwd Avg Bulk Rate` | `Bwd Avg Bulk Rate` | 68 | `int64` | `bulk_transfer` | Average bulk transfer rate in backward direction. |
| 63 | `Subflow Fwd Packets` | `Subflow Fwd Packets` | 69 | `int64` | `subflow_metrics` | Average forward packets in subflow. |
| 64 | `Subflow Fwd Bytes` | ` Subflow Fwd Bytes` | 70 | `int64` | `subflow_metrics` | Average forward bytes in subflow. |
| 65 | `Subflow Bwd Packets` | ` Subflow Bwd Packets` | 71 | `int64` | `subflow_metrics` | Average backward packets in subflow. |
| 66 | `Subflow Bwd Bytes` | ` Subflow Bwd Bytes` | 72 | `int64` | `subflow_metrics` | Average backward bytes in subflow. |
| 67 | `Init_Win_bytes_forward` | `Init_Win_bytes_forward` | 73 | `int64` | `window_and_segment` | Initial window size in forward direction. |
| 68 | `Init_Win_bytes_backward` | ` Init_Win_bytes_backward` | 74 | `int64` | `window_and_segment` | Initial window size in backward direction. |
| 69 | `act_data_pkt_fwd` | ` act_data_pkt_fwd` | 75 | `int64` | `window_and_segment` | Count of packets with at least 1 byte of TCP data payload in forward direction. |
| 70 | `min_seg_size_forward` | ` min_seg_size_forward` | 76 | `int64` | `window_and_segment` | Minimum segment size observed in forward direction. |
| 71 | `Active Mean` | `Active Mean` | 77 | `float64` | `active_idle_dynamics` | Mean time a flow was active before becoming idle. |
| 72 | `Active Std` | ` Active Std` | 78 | `float64` | `active_idle_dynamics` | Standard deviation of active time before becoming idle. |
| 73 | `Active Max` | ` Active Max` | 79 | `float64` | `active_idle_dynamics` | Maximum time a flow was active before becoming idle. |
| 74 | `Active Min` | ` Active Min` | 80 | `float64` | `active_idle_dynamics` | Minimum time a flow was active before becoming idle. |
| 75 | `Idle Mean` | `Idle Mean` | 81 | `float64` | `active_idle_dynamics` | Mean time a flow was idle before becoming active. |
| 76 | `Idle Std` | ` Idle Std` | 82 | `float64` | `active_idle_dynamics` | Standard deviation of idle time before becoming active. |
| 77 | `Idle Max` | ` Idle Max` | 83 | `float64` | `active_idle_dynamics` | Maximum time a flow was idle before becoming active. |
| 78 | `Idle Min` | ` Idle Min` | 84 | `float64` | `active_idle_dynamics` | Minimum time a flow was idle before becoming active. |

---

## 4. LEAKAGE CONTROLS & COMPLIANCE

| Leakage Category | Status | Control Mechanism |
| :--- | :---: | :--- |
| **Target Leakage** | **PREVENTED** | Ground-truth `Label` column excluded from all model inputs; label columns (`label_original`, `label_normalized`, `label_binary`) are isolated to supervised training targets only. |
| **Host Identity Leakage** | **PREVENTED** | `Source IP` and `Destination IP` are permanently excluded to prevent overfitting to testbed subnets. |
| **Flow Instance Leakage** | **PREVENTED** | `Flow ID` tuple string is permanently excluded. |
| **Port / Service Bias** | **PREVENTED** | `Source Port` (ephemeral) and `Destination Port` (target service) are excluded. Models must classify attacks by packet dynamics and flow volume, not port numbers. |
| **Temporal Leakage** | **PREVENTED** | `Timestamp` string excluded to avoid date/time partitioning. |
| **Payload Metadata Sparsity** | **PREVENTED** | `SimillarHTTP` string excluded to maintain uniform numeric space across non-HTTP flows. |
| **Topological Bias** | **PREVENTED** | `Inbound` binary direction flag excluded to eliminate testbed-specific topology artifacts. |
| **Post-Decision Leakage** | **PREVENTED** | Pipeline rejects columns matching prefixes: `mitigation_`, `decision_`, `acceptance_`, `kpi_`, `latency_`, `result_`. |

---

## 5. VALIDATION STATUS

> [!IMPORTANT]
> This frozen feature manifest is an auditable engineering contract derived from the verified 88-column CIC-DDoS2019 schema. In compliance with project guidelines, **official acceptance results (KPI-1..6, AC-1..4, NT-1..5) remain NOT EXECUTED** until model training and evaluation are conducted on the local dataset.

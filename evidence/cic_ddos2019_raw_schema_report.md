# CIC-DDoS2019 Raw Schema Inventory & Verification Report

**Dataset Identifier:** `cic-ddos2019`  
**Kaggle Source:** [`rodrigorosasilva/cic-ddos2019-30gb-full-dataset-csv-files`](https://www.kaggle.com/datasets/rodrigorosasilva/cic-ddos2019-30gb-full-dataset-csv-files)  
**Official Reference:** [Canadian Institute for Cybersecurity (CIC) / University of New Brunswick (UNB)](https://www.unb.ca/cic/datasets/ddos-2019.html)  
**Local Dataset Path:** `C:\Users\Vikas\.cache\kagglehub\datasets\rodrigorosasilva\cic-ddos2019-30gb-full-dataset-csv-files\versions\1`  
**Verification Date (UTC):** 2026-09-21 17:21:22 UTC  
**Verification Mode:** Full-File Header & Hash Verification + Bounded (1,000-row/file) Sample Inspection  

---

## 1. FULL-FILE VERIFIED FACTS

### File Inventory & Streaming SHA-256 Hashes
All **18 CSV files** were recursively enumerated and verified. Hashes were calculated via streaming chunked reads (4 MB buffers) without loading whole files into memory. Total raw dataset volume is **28.92 GB** (31,055,543,940 bytes).

| # | Group | File Name | Size (MB) | Full-File SHA-256 Digest | Columns |
| :-: | :-: | :--- | -: | :--- | :-: |
| 1 | `01-12` | `DrDoS_DNS.csv` | 2,034.48 | `eee1a2cf10be29129f00930e250236c237b97d2941e8cea766006db82047df83` | 88 |
| 2 | `01-12` | `DrDoS_LDAP.csv` | 874.81 | `fbc836bfb01d9eb5f5a2b4aae3428d7c17f449ede5466273249a9ce6095338b0` | 88 |
| 3 | `01-12` | `DrDoS_MSSQL.csv` | 1,801.66 | `534ebd8bb98a571b6e0a65a65091cb22b09156fa4db82e5752a92df02ea5402b` | 88 |
| 4 | `01-12` | `DrDoS_NetBIOS.csv` | 1,618.84 | `b0dbf6d712a021380cade45f753531a5860d0bfd4d338b4013ea5566d968329e` | 88 |
| 5 | `01-12` | `DrDoS_NTP.csv` | 615.13 | `b4ae33b2a22975f2c4c8b0e2bfc501fee38dae274dca37d4b01010de059c9c2c` | 88 |
| 6 | `01-12` | `DrDoS_SNMP.csv` | 2,071.93 | `a74a411a37fbb1a4d4acd20bb8a7e93714992e34d9fb08b3b2c5e1795c867eb7` | 88 |
| 7 | `01-12` | `DrDoS_SSDP.csv` | 1,194.65 | `0bc1a2bb6dbef3851b7a2177ef74bd801dcf592b69ef5bbe5044821e695423c1` | 88 |
| 8 | `01-12` | `DrDoS_UDP.csv` | 1,436.27 | `85c54bf54f987586e1d8da14b76d1167baa4636755cae24e648067e5242d679a` | 88 |
| 9 | `01-12` | `Syn.csv` | 607.79 | `05a272a7005be14262d3929ad16877db42fc74a03032a3a5b58d0230ab08896a` | 88 |
| 10 | `01-12` | `TFTP.csv` | 8,871.09 | `b56314cca3f68c9027e9fa684c7c565df6fc5c510c87f12b1c00390364e44d7c` | 88 |
| 11 | `01-12` | `UDPLag.csv` | 150.65 | `f67708a8462509932759ffed7eb92dca0f423267609d1be38a461708d4ea5b7e` | 88 |
| 12 | `03-11` | `LDAP.csv` | 831.03 | `d1cfc7cb9252b73d9789f7307d7583be9c3a8e90ee9c096eefe8b0d3d8be23c3` | 88 |
| 13 | `03-11` | `MSSQL.csv` | 2,275.68 | `d13cf30e7b987f7e916c54643f2e03dd4c31fc4b2051be175d5ee83d392d8f88` | 88 |
| 14 | `03-11` | `NetBIOS.csv` | 1,352.76 | `ddd2e8cd76c125e1d93094af519845e2ed1eaf44edcd3f783b3a9dee638a5e1e` | 88 |
| 15 | `03-11` | `Portmap.csv` | 74.97 | `d0148da21f3c645b32b21b59386721eddd497a16e3de4e2950391e575fca2e28` | 88 |
| 16 | `03-11` | `Syn.csv` | 1,790.4 | `603648e7c56e9232b6d647470dc01b6451502c594a4ebf235b45103edb5e545a` | 88 |
| 17 | `03-11` | `UDP.csv` | 1,709.74 | `27e262e851f12a5fc29cd433fec53a63e9e8fc3cfdc1a1d78f77995bd175a59b` | 88 |
| 18 | `03-11` | `UDPLag.csv` | 304.98 | `c8a471f56721118dc0c5ae86ae348cd261f81cf7313c08f5bbdf913005ce7ced` | 88 |

### Schema Consistency & Column Count
- **Total Columns:** Exactly **88 columns** in every file.
- **Header Uniformity:** **100% Identical.** All 18 files across both `01-12` and `03-11` share the exact same column names in the exact same sequence.
- **Day-Based Subdirectory Comparison:**
  - `01-12` (Day 1 capture): 11 files, 21,277.31 MB.
  - `03-11` (Day 2 capture): 7 files, 8,339.56 MB.
  - Schema Difference: **None** (identical column list and ordering).

### Key Columns Verification
The specific mandatory and structural columns were located and confirmed:

| Required Field | Raw Header String | Column Index | Present? | Whitespace Note |
| :--- | :--- | :-: | :-: | :--- |
| `Unnamed: 0` | `'Unnamed: 0'` | 0 | Yes | No leading space |
| `Source IP` | `' Source IP'` | 2 | Yes | Leading space present |
| `Source Port` | `' Source Port'` | 3 | Yes | Leading space present |
| `Destination IP` | `' Destination IP'` | 4 | Yes | Leading space present |
| `Destination Port` | `' Destination Port'` | 5 | Yes | Leading space present |
| `Protocol` | `' Protocol'` | 6 | Yes | Leading space present |
| `Timestamp` | `' Timestamp'` | 7 | Yes | Leading space present |
| `SimillarHTTP` | `'SimillarHTTP'` | 85 | Yes | No leading space; typo in original dataset retained |
| `Inbound` | `' Inbound'` | 86 | Yes | Leading space present |
| `Label` | `' Label'` | 87 | Yes | Leading space present |

### Complete Canonical Column Listing (88 Columns)
All 88 columns as they appear in the raw CSV header:

| Index | Raw Column Name | Stripped Column Name | Sample Dtype |
| :-: | :--- | :--- | :--- |
| 0 | `Unnamed: 0` | `Unnamed: 0` | `int64` |
| 1 | `Flow ID` | `Flow ID` | `str` |
| 2 | ` Source IP` | `Source IP` | `str` |
| 3 | ` Source Port` | `Source Port` | `int64` |
| 4 | ` Destination IP` | `Destination IP` | `str` |
| 5 | ` Destination Port` | `Destination Port` | `int64` |
| 6 | ` Protocol` | `Protocol` | `int64` |
| 7 | ` Timestamp` | `Timestamp` | `str` |
| 8 | ` Flow Duration` | `Flow Duration` | `int64` |
| 9 | ` Total Fwd Packets` | `Total Fwd Packets` | `int64` |
| 10 | ` Total Backward Packets` | `Total Backward Packets` | `int64` |
| 11 | `Total Length of Fwd Packets` | `Total Length of Fwd Packets` | `float64` |
| 12 | ` Total Length of Bwd Packets` | `Total Length of Bwd Packets` | `float64` |
| 13 | ` Fwd Packet Length Max` | `Fwd Packet Length Max` | `float64` |
| 14 | ` Fwd Packet Length Min` | `Fwd Packet Length Min` | `float64` |
| 15 | ` Fwd Packet Length Mean` | `Fwd Packet Length Mean` | `float64` |
| 16 | ` Fwd Packet Length Std` | `Fwd Packet Length Std` | `float64` |
| 17 | `Bwd Packet Length Max` | `Bwd Packet Length Max` | `float64` |
| 18 | ` Bwd Packet Length Min` | `Bwd Packet Length Min` | `float64` |
| 19 | ` Bwd Packet Length Mean` | `Bwd Packet Length Mean` | `float64` |
| 20 | ` Bwd Packet Length Std` | `Bwd Packet Length Std` | `float64` |
| 21 | `Flow Bytes/s` | `Flow Bytes/s` | `float64` |
| 22 | ` Flow Packets/s` | `Flow Packets/s` | `float64` |
| 23 | ` Flow IAT Mean` | `Flow IAT Mean` | `float64` |
| 24 | ` Flow IAT Std` | `Flow IAT Std` | `float64` |
| 25 | ` Flow IAT Max` | `Flow IAT Max` | `float64` |
| 26 | ` Flow IAT Min` | `Flow IAT Min` | `float64` |
| 27 | `Fwd IAT Total` | `Fwd IAT Total` | `float64` |
| 28 | ` Fwd IAT Mean` | `Fwd IAT Mean` | `float64` |
| 29 | ` Fwd IAT Std` | `Fwd IAT Std` | `float64` |
| 30 | ` Fwd IAT Max` | `Fwd IAT Max` | `float64` |
| 31 | ` Fwd IAT Min` | `Fwd IAT Min` | `float64` |
| 32 | `Bwd IAT Total` | `Bwd IAT Total` | `float64` |
| 33 | ` Bwd IAT Mean` | `Bwd IAT Mean` | `float64` |
| 34 | ` Bwd IAT Std` | `Bwd IAT Std` | `float64` |
| 35 | ` Bwd IAT Max` | `Bwd IAT Max` | `float64` |
| 36 | ` Bwd IAT Min` | `Bwd IAT Min` | `float64` |
| 37 | `Fwd PSH Flags` | `Fwd PSH Flags` | `int64` |
| 38 | ` Bwd PSH Flags` | `Bwd PSH Flags` | `int64` |
| 39 | ` Fwd URG Flags` | `Fwd URG Flags` | `int64` |
| 40 | ` Bwd URG Flags` | `Bwd URG Flags` | `int64` |
| 41 | ` Fwd Header Length` | `Fwd Header Length` | `int64` |
| 42 | ` Bwd Header Length` | `Bwd Header Length` | `int64` |
| 43 | `Fwd Packets/s` | `Fwd Packets/s` | `float64` |
| 44 | ` Bwd Packets/s` | `Bwd Packets/s` | `float64` |
| 45 | ` Min Packet Length` | `Min Packet Length` | `float64` |
| 46 | ` Max Packet Length` | `Max Packet Length` | `float64` |
| 47 | ` Packet Length Mean` | `Packet Length Mean` | `float64` |
| 48 | ` Packet Length Std` | `Packet Length Std` | `float64` |
| 49 | ` Packet Length Variance` | `Packet Length Variance` | `float64` |
| 50 | `FIN Flag Count` | `FIN Flag Count` | `int64` |
| 51 | ` SYN Flag Count` | `SYN Flag Count` | `int64` |
| 52 | ` RST Flag Count` | `RST Flag Count` | `int64` |
| 53 | ` PSH Flag Count` | `PSH Flag Count` | `int64` |
| 54 | ` ACK Flag Count` | `ACK Flag Count` | `int64` |
| 55 | ` URG Flag Count` | `URG Flag Count` | `int64` |
| 56 | ` CWE Flag Count` | `CWE Flag Count` | `int64` |
| 57 | ` ECE Flag Count` | `ECE Flag Count` | `int64` |
| 58 | ` Down/Up Ratio` | `Down/Up Ratio` | `float64` |
| 59 | ` Average Packet Size` | `Average Packet Size` | `float64` |
| 60 | ` Avg Fwd Segment Size` | `Avg Fwd Segment Size` | `float64` |
| 61 | ` Avg Bwd Segment Size` | `Avg Bwd Segment Size` | `float64` |
| 62 | ` Fwd Header Length.1` | `Fwd Header Length.1` | `int64` |
| 63 | `Fwd Avg Bytes/Bulk` | `Fwd Avg Bytes/Bulk` | `int64` |
| 64 | ` Fwd Avg Packets/Bulk` | `Fwd Avg Packets/Bulk` | `int64` |
| 65 | ` Fwd Avg Bulk Rate` | `Fwd Avg Bulk Rate` | `int64` |
| 66 | ` Bwd Avg Bytes/Bulk` | `Bwd Avg Bytes/Bulk` | `int64` |
| 67 | ` Bwd Avg Packets/Bulk` | `Bwd Avg Packets/Bulk` | `int64` |
| 68 | `Bwd Avg Bulk Rate` | `Bwd Avg Bulk Rate` | `int64` |
| 69 | `Subflow Fwd Packets` | `Subflow Fwd Packets` | `int64` |
| 70 | ` Subflow Fwd Bytes` | `Subflow Fwd Bytes` | `int64` |
| 71 | ` Subflow Bwd Packets` | `Subflow Bwd Packets` | `int64` |
| 72 | ` Subflow Bwd Bytes` | `Subflow Bwd Bytes` | `int64` |
| 73 | `Init_Win_bytes_forward` | `Init_Win_bytes_forward` | `int64` |
| 74 | ` Init_Win_bytes_backward` | `Init_Win_bytes_backward` | `int64` |
| 75 | ` act_data_pkt_fwd` | `act_data_pkt_fwd` | `int64` |
| 76 | ` min_seg_size_forward` | `min_seg_size_forward` | `int64` |
| 77 | `Active Mean` | `Active Mean` | `float64` |
| 78 | ` Active Std` | `Active Std` | `float64` |
| 79 | ` Active Max` | `Active Max` | `float64` |
| 80 | ` Active Min` | `Active Min` | `float64` |
| 81 | `Idle Mean` | `Idle Mean` | `float64` |
| 82 | ` Idle Std` | `Idle Std` | `float64` |
| 83 | ` Idle Max` | `Idle Max` | `float64` |
| 84 | ` Idle Min` | `Idle Min` | `float64` |
| 85 | `SimillarHTTP` | `SimillarHTTP` | `str` |
| 86 | ` Inbound` | `Inbound` | `int64` |
| 87 | ` Label` | `Label` | `str` |

---

## 2. BOUNDED SAMPLE OBSERVATIONS

> [!NOTE]
> The following observations are derived from a bounded sample of **1,000 rows per file** (18,000 rows total). They reflect empirical observations from the initial data segments and do not claim full-dataset coverage.

### Detected Data Types
- **Identifier / Metadata Columns (Object / String):**
  - `Flow ID` (index 1)
  - ` Source IP` (index 2)
  - ` Destination IP` (index 4)
  - ` Timestamp` (index 7)
  - `SimillarHTTP` (index 85)
  - ` Label` (index 87)
- **Integer Columns (34 columns):**
  - `Unnamed: 0`, ` Source Port`, ` Destination Port`, ` Protocol`, ` Flow Duration`, packet flags, bulk rates, subflow packet counts, etc.
- **Floating-Point Columns (48 columns):**
  - Rates, IAT statistics, packet length means/stds/variances, active/idle window statistics, down/up ratios.

### Example Observed Labels (from 1,000 rows/file sample)
Across the 18 sampled files, the following **17 distinct label strings** were observed:
`BENIGN`, `DrDoS_DNS`, `DrDoS_LDAP`, `DrDoS_MSSQL`, `DrDoS_NTP`, `DrDoS_NetBIOS`, `DrDoS_SNMP`, `DrDoS_SSDP`, `DrDoS_UDP`, `LDAP`, `MSSQL`, `NetBIOS`, `Portmap`, `Syn`, `TFTP`, `UDP`, `UDP-lag`

#### Breakdown by File (Sampled 1,000 rows):
- `01-12/DrDoS_DNS.csv`: `BENIGN`, `DrDoS_DNS`
- `01-12/DrDoS_LDAP.csv`: `DrDoS_LDAP`
- `01-12/DrDoS_MSSQL.csv`: `DrDoS_MSSQL`
- `01-12/DrDoS_NetBIOS.csv`: `BENIGN`, `DrDoS_NetBIOS`
- `01-12/DrDoS_NTP.csv`: `BENIGN`, `DrDoS_NTP`
- `01-12/DrDoS_SNMP.csv`: `DrDoS_SNMP`
- `01-12/DrDoS_SSDP.csv`: `BENIGN`, `DrDoS_SSDP`
- `01-12/DrDoS_UDP.csv`: `DrDoS_UDP`
- `01-12/Syn.csv`: `BENIGN`, `Syn`
- `01-12/TFTP.csv`: `TFTP`
- `01-12/UDPLag.csv`: `UDP-lag`
- `03-11/LDAP.csv`: `NetBIOS`
- `03-11/MSSQL.csv`: `BENIGN`, `LDAP`
- `03-11/NetBIOS.csv`: `NetBIOS`
- `03-11/Portmap.csv`: `BENIGN`, `Portmap`
- `03-11/Syn.csv`: `Syn`
- `03-11/UDP.csv`: `MSSQL`
- `03-11/UDPLag.csv`: `UDP`

---

## 3. NOT VERIFIED YET (DEFERRED)

The following items are deliberately deferred to ensure memory safety, prevent synthetic result fabrication, and maintain academic rigor:
1. **Complete Label Inventory:** A full scan across the 28.92 GB dataset to catalogue every single attack sub-label and count will be performed during bounded dataset ingestion/filtering.
2. **Exact Total Row Counts:** Full row counting across ~30 GB of CSVs was skipped to avoid excessive I/O before the ingestion pipeline is executed.
3. **Infinite / Missing Values in Deeper Rows:** Numerical validation outside the 1,000-row sample will be conducted by `ml/preprocessing/validation.py` during dataset preparation.
4. **Official KPI / Acceptance Execution:** Official KPI-1 through KPI-6, AC-1 through AC-4, and NT-1 through NT-5 remain **`NOT_EXECUTED`** or **`BLOCKED`**.

---

## 4. CONCLUSION & READINESS FOR DATA-5

- **18 / 18 CSV files** confirmed and SHA-256 authenticated.
- **88-column canonical schema** confirmed identical across all files.
- **Raw whitespace quirks** (`' Label'`, `' Source IP'`, `' Protocol'`) documented.
- **Schema verified ready** for the creation of the frozen feature manifest and local ingestion pipeline.

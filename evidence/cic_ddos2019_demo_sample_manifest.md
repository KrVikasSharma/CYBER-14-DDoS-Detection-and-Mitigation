# SMALL REAL CIC-DDoS2019 DEMONSTRATION SAMPLE

> [!NOTE]
> **NOT OFFICIAL ACCEPTANCE DATA**
> This is a controlled demonstration sample of approximately 10,000 rows extracted deterministically from the real CIC-DDoS2019 CSV files for project presentation, local model demonstration, and pipeline verification.

- **Creation Date (UTC):** 2026-09-21T17:45:46.189711+00:00
- **Source Dataset:** rodrigorosasilva/cic-ddos2019-30gb-full-dataset-csv-files (KaggleHub version 1)
- **Random Seed:** 42
- **Total Rows:** 9,990
- **Columns:** 88
- **Feature Manifest Fingerprint:** `997e6b28c6bcc5bf76a57789cf3f0cc8e41f7792e95742b3f8a800852c6ede3a`
- **Sample Output Path:** `data\demo\cic_ddos2019_sample.csv`

## Label Distribution in Sample

| Label | Category | Count | Percentage |
| :--- | :--- | -: | -: |
| `Syn` | DDoS Attack | 1,106 | 11.07% |
| `NetBIOS` | DDoS Attack | 1,065 | 10.66% |
| `MSSQL` | DDoS Attack | 788 | 7.89% |
| `BENIGN` | Legitimate | 641 | 6.42% |
| `DrDoS_UDP` | DDoS Attack | 555 | 5.56% |
| `UDP` | DDoS Attack | 553 | 5.54% |
| `UDP-lag` | DDoS Attack | 553 | 5.54% |
| `DrDoS_LDAP` | DDoS Attack | 552 | 5.53% |
| `TFTP` | DDoS Attack | 551 | 5.52% |
| `DrDoS_SNMP` | DDoS Attack | 514 | 5.15% |
| `DrDoS_SSDP` | DDoS Attack | 505 | 5.06% |
| `DrDoS_DNS` | DDoS Attack | 485 | 4.85% |
| `DrDoS_NTP` | DDoS Attack | 485 | 4.85% |
| `DrDoS_MSSQL` | DDoS Attack | 485 | 4.85% |
| `Portmap` | DDoS Attack | 485 | 4.85% |
| `DrDoS_NetBIOS` | DDoS Attack | 485 | 4.85% |
| `LDAP` | DDoS Attack | 182 | 1.82% |

## Source Files and Sampling Breakdown

| Source File | SHA-256 (first 12 chars) | Sampled Rows | Labels Included |
| :--- | :--- | -: | :--- |
| `01-12\DrDoS_DNS.csv` | `eee1a2cf10be...` | 555 | DrDoS_DNS (485), BENIGN (70) |
| `01-12\DrDoS_LDAP.csv` | `fbc836bfb01d...` | 555 | DrDoS_LDAP (552), BENIGN (3) |
| `01-12\DrDoS_MSSQL.csv` | `534ebd8bb98a...` | 555 | DrDoS_MSSQL (485), BENIGN (70) |
| `01-12\DrDoS_NetBIOS.csv` | `b0dbf6d712a0...` | 555 | DrDoS_NetBIOS (485), BENIGN (70) |
| `01-12\DrDoS_NTP.csv` | `b4ae33b2a229...` | 555 | DrDoS_NTP (485), BENIGN (70) |
| `01-12\DrDoS_SNMP.csv` | `a74a411a37fb...` | 555 | DrDoS_SNMP (514), BENIGN (41) |
| `01-12\DrDoS_SSDP.csv` | `0bc1a2bb6dbe...` | 555 | DrDoS_SSDP (505), BENIGN (50) |
| `01-12\DrDoS_UDP.csv` | `85c54bf54f98...` | 555 | DrDoS_UDP (555) |
| `01-12\Syn.csv` | `05a272a7005b...` | 555 | Syn (551), BENIGN (4) |
| `01-12\TFTP.csv` | `b56314cca3f6...` | 555 | TFTP (551), BENIGN (4) |
| `01-12\UDPLag.csv` | `f67708a84625...` | 555 | UDP-lag (553), BENIGN (2) |
| `03-11\LDAP.csv` | `d1cfc7cb9252...` | 555 | NetBIOS (513), BENIGN (42) |
| `03-11\MSSQL.csv` | `d13cf30e7b98...` | 555 | MSSQL (303), LDAP (182), BENIGN (70) |
| `03-11\NetBIOS.csv` | `ddd2e8cd76c1...` | 555 | NetBIOS (552), BENIGN (3) |
| `03-11\Portmap.csv` | `d0148da21f3c...` | 555 | Portmap (485), BENIGN (70) |
| `03-11\Syn.csv` | `603648e7c56e...` | 555 | Syn (555) |
| `03-11\UDP.csv` | `27e262e851f1...` | 555 | MSSQL (485), BENIGN (70) |
| `03-11\UDPLag.csv` | `c8a471f56721...` | 555 | UDP (553), BENIGN (2) |

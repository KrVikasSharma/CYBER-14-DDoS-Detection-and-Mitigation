import json
import logging
import sys
from datetime import timezone, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pandas as pd

from ml.data.manifest import load_feature_manifest

logger = logging.getLogger("cyber14.create_demo_sample")

RAW_DATASET_DIR = Path(
    r"C:\Users\Vikas\.cache\kagglehub\datasets\rodrigorosasilva\cic-ddos2019-30gb-full-dataset-csv-files\versions\1"
)
OUTPUT_FILE = Path("data/demo/cic_ddos2019_sample.csv")
MANIFEST_JSON = Path("evidence/cic_ddos2019_demo_sample_manifest.json")
MANIFEST_MD = Path("evidence/cic_ddos2019_demo_sample_manifest.md")
RAW_INVENTORY_JSON = Path("evidence/cic_ddos2019_raw_schema_inventory.json")
RANDOM_SEED = 42
TARGET_TOTAL_ROWS = 10000


RAW_FILE_SHA256 = {
    "01-12\\DrDoS_DNS.csv": "eee1a2cf10be29129f00930e250236c237b97d2941e8cea766006db82047df83",
    "01-12\\DrDoS_LDAP.csv": "fbc836bfb01d9eb5f5a2b4aae3428d7c17f449ede5466273249a9ce6095338b0",
    "01-12\\DrDoS_MSSQL.csv": "534ebd8bb98a571b6e0a65a65091cb22b09156fa4db82e5752a92df02ea5402b",
    "01-12\\DrDoS_NetBIOS.csv": "b0dbf6d712a021380cade45f753531a5860d0bfd4d338b4013ea5566d968329e",
    "01-12\\DrDoS_NTP.csv": "b4ae33b2a22975f2c4c8b0e2bfc501fee38dae274dca37d4b01010de059c9c2c",
    "01-12\\DrDoS_SNMP.csv": "a74a411a37fbb1a4d4acd20bb8a7e93714992e34d9fb08b3b2c5e1795c867eb7",
    "01-12\\DrDoS_SSDP.csv": "0bc1a2bb6dbef3851b7a2177ef74bd801dcf592b69ef5bbe5044821e695423c1",
    "01-12\\DrDoS_UDP.csv": "85c54bf54f987586e1d8da14b76d1167baa4636755cae24e648067e5242d679a",
    "01-12\\Syn.csv": "05a272a7005be14262d3929ad16877db42fc74a03032a3a5b58d0230ab08896a",
    "01-12\\TFTP.csv": "b56314cca3f68c9027e9fa684c7c565df6fc5c510c87f12b1c00390364e44d7c",
    "01-12\\UDPLag.csv": "f67708a8462509932759ffed7eb92dca0f423267609d1be38a461708d4ea5b7e",
    "03-11\\LDAP.csv": "d1cfc7cb9252b73d9789f7307d7583be9c3a8e90ee9c096eefe8b0d3d8be23c3",
    "03-11\\MSSQL.csv": "d13cf30e7b987f7e916c54643f2e03dd4c31fc4b2051be175d5ee83d392d8f88",
    "03-11\\NetBIOS.csv": "ddd2e8cd76c125e1d93094af519845e2ed1eaf44edcd3f783b3a9dee638a5e1e",
    "03-11\\Portmap.csv": "d0148da21f3c645b32b21b59386721eddd497a16e3de4e2950391e575fca2e28",
    "03-11\\Syn.csv": "603648e7c56e9232b6d647470dc01b6451502c594a4ebf235b45103edb5e545a",
    "03-11\\UDP.csv": "27e262e851f12a5fc29cd433fec53a63e9e8fc3cfdc1a1d78f77995bd175a59b",
    "03-11\\UDPLag.csv": "c8a471f56721118dc0c5ae86ae348cd261f81cf7313c08f5bbdf913005ce7ced",
}


def create_demo_sample(
    raw_dir: Path = RAW_DATASET_DIR,
    output_path: Path = OUTPUT_FILE,
    target_total: int = TARGET_TOTAL_ROWS,
    seed: int = RANDOM_SEED,
) -> pd.DataFrame:
    file_hashes = RAW_FILE_SHA256

    csv_files = sorted(raw_dir.rglob("*.csv"))
    if not csv_files:
        raise FileNotFoundError(f"No CSV files found in {raw_dir}")

    feature_manifest = load_feature_manifest()
    manifest_fingerprint = feature_manifest.get("feature_list_sha256")

    rows_per_file_target = target_total // len(csv_files)
    logger.info(
        "Sampling ~%d rows per file across %d files (seed=%d)",
        rows_per_file_target,
        len(csv_files),
        seed,
    )

    sampled_frames = []
    file_stats = []

    for i, file_path in enumerate(csv_files, 1):
        rel_path = str(file_path.relative_to(raw_dir))
        file_sha = file_hashes.get(rel_path, "UNKNOWN")

        # Read only the first chunk (25,000 rows) to keep memory tiny
        chunk = pd.read_csv(file_path, nrows=25000, low_memory=False)
        chunk.columns = [col.strip() for col in chunk.columns]

        if "Label" not in chunk.columns:
            raise ValueError(f"Label column missing in {rel_path}")

        # Separate benign and attack in this chunk
        benign_chunk = chunk[chunk["Label"].astype(str).str.strip().str.upper() == "BENIGN"]
        attack_chunk = chunk[chunk["Label"].astype(str).str.strip().str.upper() != "BENIGN"]

        # Target roughly 60-80 benign rows per file if available, and remaining as attack
        benign_target = min(len(benign_chunk), 70)
        attack_target = min(len(attack_chunk), rows_per_file_target - benign_target)

        file_sample_parts = []
        if benign_target > 0:
            s_benign = benign_chunk.sample(n=benign_target, random_state=seed + i)
            file_sample_parts.append(s_benign)
        if attack_target > 0:
            s_attack = attack_chunk.sample(n=attack_target, random_state=seed + i)
            file_sample_parts.append(s_attack)

        if not file_sample_parts:
            # Fallback to general sample if neither branch matched
            file_sample = chunk.sample(n=min(len(chunk), rows_per_file_target), random_state=seed + i)
        else:
            file_sample = pd.concat(file_sample_parts, ignore_index=True)

        sampled_frames.append(file_sample)
        counts = file_sample["Label"].astype(str).str.strip().value_counts().to_dict()
        file_stats.append(
            {
                "file": rel_path,
                "sha256": file_sha,
                "sampled_rows": len(file_sample),
                "labels": counts,
            }
        )
        logger.info(
            "[%d/%d] %s: sampled %d rows (labels: %s)",
            i,
            len(csv_files),
            rel_path,
            len(file_sample),
            counts,
        )

    full_sample = pd.concat(sampled_frames, ignore_index=True)
    # Final shuffle to mix file order deterministically
    full_sample = full_sample.sample(frac=1.0, random_state=seed).reset_index(drop=True)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    full_sample.to_csv(output_path, index=False)
    logger.info("Saved %d sample rows to %s", len(full_sample), output_path)

    # Compile evidence manifest
    label_dist = full_sample["Label"].astype(str).str.strip().value_counts().to_dict()
    evidence_manifest = {
        "title": "SMALL REAL CIC-DDoS2019 DEMONSTRATION SAMPLE — NOT OFFICIAL ACCEPTANCE DATA",
        "description": "Controlled demonstration sample from real CIC-DDoS2019 CSVs for presentation and local testing.",
        "official_acceptance_data": False,
        "source_dataset": "rodrigorosasilva/cic-ddos2019-30gb-full-dataset-csv-files (KaggleHub version 1)",
        "source_directory": str(raw_dir),
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "random_seed": seed,
        "sampling_method": "deterministic stratified streaming sample per file",
        "feature_manifest_fingerprint": manifest_fingerprint,
        "total_sampled_rows": len(full_sample),
        "total_columns": len(full_sample.columns),
        "label_distribution": label_dist,
        "benign_count": label_dist.get("BENIGN", 0),
        "attack_count": sum(c for l, c in label_dist.items() if l != "BENIGN"),
        "source_files": file_stats,
    }

    MANIFEST_JSON.parent.mkdir(parents=True, exist_ok=True)
    MANIFEST_JSON.write_text(json.dumps(evidence_manifest, indent=2), encoding="utf-8")

    # Generate Markdown evidence report
    md_lines = [
        "# SMALL REAL CIC-DDoS2019 DEMONSTRATION SAMPLE",
        "",
        "> [!NOTE]",
        "> **NOT OFFICIAL ACCEPTANCE DATA**",
        "> This is a controlled demonstration sample of approximately 10,000 rows extracted deterministically from the real CIC-DDoS2019 CSV files for project presentation, local model demonstration, and pipeline verification.",
        "",
        f"- **Creation Date (UTC):** {evidence_manifest['created_at_utc']}",
        f"- **Source Dataset:** {evidence_manifest['source_dataset']}",
        f"- **Random Seed:** {seed}",
        f"- **Total Rows:** {len(full_sample):,}",
        f"- **Columns:** {len(full_sample.columns)}",
        f"- **Feature Manifest Fingerprint:** `{manifest_fingerprint}`",
        f"- **Sample Output Path:** `{output_path}`",
        "",
        "## Label Distribution in Sample",
        "",
        "| Label | Category | Count | Percentage |",
        "| :--- | :--- | -: | -: |",
    ]
    total_n = len(full_sample)
    for label, count in label_dist.items():
        cat = "Legitimate" if label == "BENIGN" else "DDoS Attack"
        pct = (count / total_n) * 100.0
        md_lines.append(f"| `{label}` | {cat} | {count:,} | {pct:.2f}% |")

    md_lines.extend(
        [
            "",
            "## Source Files and Sampling Breakdown",
            "",
            "| Source File | SHA-256 (first 12 chars) | Sampled Rows | Labels Included |",
            "| :--- | :--- | -: | :--- |",
        ]
    )
    for fs in file_stats:
        labels_str = ", ".join(f"{k} ({v})" for k, v in fs["labels"].items())
        sha_short = fs["sha256"][:12] if fs["sha256"] != "UNKNOWN" else "UNKNOWN"
        md_lines.append(f"| `{fs['file']}` | `{sha_short}...` | {fs['sampled_rows']} | {labels_str} |")

    md_lines.append("")
    MANIFEST_MD.write_text("\n".join(md_lines), encoding="utf-8")
    logger.info("Wrote evidence manifest to %s and %s", MANIFEST_JSON, MANIFEST_MD)

    return full_sample


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    create_demo_sample()

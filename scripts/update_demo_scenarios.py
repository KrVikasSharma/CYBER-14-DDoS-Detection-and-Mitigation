import json
from pathlib import Path

# Load current scenarios
current_path = Path("data/demo/demo_scenarios.json")
current = json.loads(current_path.read_text(encoding="utf-8"))

# Load candidate scenarios
candidates = json.loads(Path("scripts/candidate_scenarios.json").read_text(encoding="utf-8"))

# Keep benign, flash_crowd, attack_fixture
new_scenarios = {
    "benign": current["benign"],
    "flash_crowd": current["flash_crowd"],
    "attack_fixture": current["attack_fixture"],
}

# Map candidates to clean attack keys
key_mapping = {
    "netbios": "netbios",
    "syn": "syn",
    "udp": "udp",
    "drdos_dns": "dns",
    "drdos_ldap": "ldap",
    "mssql": "mssql",
    "drdos_ntp": "ntp",
    "tftp": "tftp",
    "portmap": "portmap",
    "drdos_snmp": "snmp",
}

for cand_key, clean_key in key_mapping.items():
    if cand_key in candidates:
        cand_data = candidates[cand_key]
        new_scenarios[clean_key] = {
            "display_name": cand_data["display_name"],
            "source_label": cand_data["source_label"],
            "traffic_rate": cand_data["traffic_rate"],
            "metadata": cand_data["metadata"],
            "features": cand_data["features"],
            "expected_category": cand_data["evaluation_reference"]["o3_prediction"],
        }

current_path.write_text(json.dumps(new_scenarios, indent=2), encoding="utf-8")
print(f"Updated {current_path} with {len(new_scenarios)} scenarios:")
for k, v in new_scenarios.items():
    exp = v.get("expected_category", v.get("metadata", {}).get("protocol", "N/A"))
    print(f"  - {k:15s}: display='{v.get('display_name', k)}', expected='{exp}'")

import json
import joblib
import numpy as np
import pandas as pd
from pathlib import Path

# Load test dataset
df_test = pd.read_csv("data/demo/processed/test.csv")
manifest = json.loads(Path("evidence/cic_ddos2019_feature_manifest.json").read_text(encoding="utf-8"))
feature_cols = manifest["included_features_o2"]

X = df_test[feature_cols].copy()

# Load models
o2_model = joblib.load("data/demo/models/o2/model.joblib")
o3_model = joblib.load("data/demo/models/o3/model.joblib")
o3_classes = list(o3_model.classes_)

# Vectorized predictions
o2_probs = o2_model.predict_proba(X)[:, 1]
o3_probs = o3_model.predict_proba(X)
o3_pred_indices = np.argmax(o3_probs, axis=1)
o3_pred_classes = [o3_classes[i] for i in o3_pred_indices]
o3_confidences = np.max(o3_probs, axis=1)

df_test["o2_prob"] = o2_probs
df_test["o2_pred"] = o2_probs >= 0.50
df_test["o3_pred"] = o3_pred_classes
df_test["o3_conf"] = o3_confidences

# Families to select
families = [
    ("NETBIOS", "NetBIOS"),
    ("SYN", "SYN"),
    ("UDP", "UDP Flood"),
    ("DRDOS_DNS", "DNS Amplification"),
    ("DRDOS_LDAP", "LDAP Amplification"),
    ("MSSQL", "MSSQL Attack"),
    ("DRDOS_NTP", "NTP Amplification"),
    ("TFTP", "TFTP Flood"),
    ("PORTMAP", "Portmap Attack"),
    ("DRDOS_SNMP", "SNMP Amplification"),
]

print("=== CANDIDATE ATTACK VECTORS ===")
selected_scenarios = {}

for cls_key, display_name in families:
    # Filter where true label matches cls_key and O2 detected attack
    subset = df_test[(df_test["label_normalized"] == cls_key) & (df_test["o2_pred"] == True)]
    # Look for where O3 also predicts cls_key
    matching = subset[subset["o3_pred"] == cls_key]
    if len(matching) > 0:
        best_row = matching.sort_values("o3_conf", ascending=False).iloc[0]
    else:
        best_row = subset.sort_values("o3_conf", ascending=False).iloc[0]

    row_idx = int(best_row.name)
    features_dict = {col: float(best_row[col]) for col in feature_cols}
    
    # Metadata specific to attack family
    proto = "TCP" if cls_key in {"SYN", "MSSQL"} else "UDP"
    port_map = {
        "NETBIOS": 137,
        "SYN": 80,
        "UDP": 53,
        "DRDOS_DNS": 53,
        "DRDOS_LDAP": 389,
        "MSSQL": 1433,
        "DRDOS_NTP": 123,
        "TFTP": 69,
        "PORTMAP": 111,
        "DRDOS_SNMP": 161,
    }
    dst_port = port_map.get(cls_key, 80)
    
    scenario_dict = {
        "display_name": display_name,
        "source_label": str(best_row["label_original"]),
        "traffic_rate": 2000,
        "features": features_dict,
        "metadata": {
            "source_ip": f"192.168.1.{100 + len(selected_scenarios)}",
            "source_port": 50000 + len(selected_scenarios),
            "destination_ip": "10.0.0.1",
            "destination_port": dst_port,
            "protocol": proto,
            "timestamp": "2026-09-22T00:00:00Z"
        },
        "evaluation_reference": {
            "source_row_index": row_idx,
            "o2_detection": bool(best_row["o2_pred"]),
            "o2_confidence": float(best_row["o2_prob"]),
            "o3_prediction": str(best_row["o3_pred"]),
            "o3_confidence": float(best_row["o3_conf"]),
            "mitigation_decision": "BLOCK" if best_row["o3_conf"] >= 0.80 else "RATE_LIMIT"
        }
    }
    selected_scenarios[cls_key.lower()] = scenario_dict

    print(f"[{cls_key}] Row: {row_idx:4d} | Orig: {best_row['label_original']:15s} | O2: {best_row['o2_prob']*100:.1f}% | O3 Pred: {best_row['o3_pred']:12s} ({best_row['o3_conf']*100:.1f}%) | Action: {'BLOCK' if best_row['o3_conf'] >= 0.80 else 'RATE_LIMIT'}")

print(f"\nSuccessfully selected {len(selected_scenarios)} distinct attack scenarios!")
Path("scripts/candidate_scenarios.json").write_text(json.dumps(selected_scenarios, indent=2), encoding="utf-8")

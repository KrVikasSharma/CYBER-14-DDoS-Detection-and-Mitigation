import asyncio
import json
import time
from pathlib import Path
import httpx
import websockets

BACKEND_URL = "http://127.0.0.1:8000"
WS_URL = "ws://127.0.0.1:8000/ws/traffic"

async def test_multiclass_live_stream():
    print("==================================================")
    print("CYBER-14: LIVE MULTI-CLASS O3 STREAM VERIFICATION")
    print("==================================================")

    # 1. Login
    async with httpx.AsyncClient(base_url=BACKEND_URL) as client:
        resp = await client.post("/api/v1/auth/login", json={"username": "admin", "password": "DemoAdminPassword123!"})
        assert resp.status_code == 200, f"Login failed: {resp.text}"
        token = resp.json()["access_token"]
        print("[OK] Authenticated admin session.")

    scenarios = json.loads(Path("data/demo/demo_scenarios.json").read_text(encoding="utf-8"))
    ws_url = f"{WS_URL}?access_token={token}"

    sequence = [
        "benign",
        "syn",
        "flash_crowd",
        "netbios",
        "benign",
        "udp",
        "dns",
        "mssql",
        "ldap",
        "ntp",
        "tftp",
        "portmap",
        "snmp",
    ]

    # Run 26 observations (2 full cycles of the 13-scenario sequence)
    total_observations = 26
    print(f"\nStreaming {total_observations} real CIC-DDoS2019 observations over live WebSocket...")

    observations_recorded = []
    o3_classes_observed = set()
    mitigation_actions_observed = set()

    async with websockets.connect(ws_url) as ws:
        for idx in range(total_observations):
            key = sequence[idx % len(sequence)]
            sc = scenarios[key]
            meta = sc.get("metadata", {})
            payload = {
                "source_identifier": f"multiclass:{key}:{idx:03d}",
                "traffic_rate": sc["traffic_rate"],
                "features": sc["features"],
                "metadata": {
                    "source_ip": meta.get("source_ip", f"192.168.1.{100 + idx}"),
                    "source_port": meta.get("source_port", 50000) + (idx % 100),
                    "destination_ip": meta.get("destination_ip", "10.0.0.1"),
                    "destination_port": meta.get("destination_port", 80),
                    "protocol": meta.get("protocol", "TCP"),
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                }
            }
            await ws.send(json.dumps(payload))
            raw_msg = await asyncio.wait_for(ws.recv(), timeout=5.0)
            data = json.loads(raw_msg)
            assert data.get("type") == "detection_result", f"Unexpected response: {data}"

            resp = data["response"]
            o2_det = resp["o2"]["detected"]
            o2_conf = resp["o2"]["confidence"]
            o3_type = resp["o3"]["attack_type"]
            o3_conf = resp["o3"]["confidence"]
            mit_action = resp["mitigation"]["decision"]
            flow_meta = resp.get("metadata", {})
            src_ep = f"{flow_meta.get('source_ip')}:{flow_meta.get('source_port')}"
            dst_ep = f"{flow_meta.get('destination_ip')}:{flow_meta.get('destination_port')}"

            if o3_type:
                o3_classes_observed.add(o3_type)
            mitigation_actions_observed.add(mit_action)

            observations_recorded.append({
                "step": idx + 1,
                "scenario": key,
                "source_endpoint": src_ep,
                "destination_endpoint": dst_ep,
                "o2_detected": o2_det,
                "o2_confidence": o2_conf,
                "o3_attack_type": o3_type,
                "o3_confidence": o3_conf,
                "mitigation_decision": mit_action,
                "latency_ms": resp["latency"]["total_analysis_ms"]
            })

            conf_str = f"{o3_conf * 100:.1f}%" if o3_conf is not None else "N/A"
            print(f"[{idx + 1:02d}/26] Scenario: {key:12s} | O2: {'ATTACK' if o2_det else 'BENIGN':6s} ({o2_conf*100:.1f}%) | O3: {str(o3_type):12s} ({conf_str:6s}) | Action: {mit_action:10s} | {src_ep} -> {dst_ep}")

            # Pace at ~150ms for the test script (frontend paces at 1.8s)
            await asyncio.sleep(0.15)

    print("\n==================================================")
    print("LIVE MULTI-CLASS STREAM RESULTS SUMMARY:")
    print("==================================================")
    print(f"Total Observations Streamed: {len(observations_recorded)}")
    print(f"Distinct O3 Attack Classes Observed ({len(o3_classes_observed)}): {sorted(o3_classes_observed)}")
    print(f"Mitigation Actions Observed: {sorted(mitigation_actions_observed)}")

    # Assertions for academic integrity & functionality
    assert len(observations_recorded) == 26, "Did not complete 26 observations"
    assert len(o3_classes_observed) >= 5, f"Expected at least 5 distinct attack classes, got {len(o3_classes_observed)}"
    assert "ALLOW" in mitigation_actions_observed, "Missing ALLOW action"
    assert "RATE_LIMIT" in mitigation_actions_observed, "Missing RATE_LIMIT action"
    assert "BLOCK" in mitigation_actions_observed, "Missing BLOCK action"

    # Verify flow metadata is preserved across all observations
    for obs in observations_recorded:
        assert obs["source_endpoint"] != "None:None", f"Missing source endpoint in observation {obs['step']}"
        assert obs["destination_endpoint"] != "None:None", f"Missing destination endpoint in observation {obs['step']}"

    print("\n[SUCCESS] ALL MULTI-CLASS O3 VERIFICATION CHECKS PASSED 100%!")
    Path("evidence/multiclass_live_stream_results.json").write_text(json.dumps(observations_recorded, indent=2), encoding="utf-8")
    print("[OK] Results saved to evidence/multiclass_live_stream_results.json")

if __name__ == "__main__":
    asyncio.run(test_multiclass_live_stream())

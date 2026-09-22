import asyncio
import json
import os
import sys
import time
import urllib.error
import urllib.request
import websockets

sys.path.insert(0, os.path.abspath("."))
sys.path.insert(0, os.path.abspath("backend"))

from app.auth.models import LocalUser, UserRole
from app.auth.tokens import create_access_token

BASE_URL = "http://127.0.0.1:8000"
WS_URL = "ws://127.0.0.1:8000/ws/traffic"
SECRET = "presentation-secret-key-32-chars-long!"
PASSWORD = "DemoAdminPassword123!"

# Generate tokens for all 4 roles
TOKENS = {
    "admin": create_access_token(LocalUser(username="admin_user", role=UserRole.ADMIN, auth_mode="local_demo"), SECRET, 3600),
    "operator": create_access_token(LocalUser(username="operator_user", role=UserRole.OPERATOR, auth_mode="local_demo"), SECRET, 3600),
    "analyst": create_access_token(LocalUser(username="analyst_user", role=UserRole.ANALYST, auth_mode="local_demo"), SECRET, 3600),
    "viewer": create_access_token(LocalUser(username="viewer_user", role=UserRole.VIEWER, auth_mode="local_demo"), SECRET, 3600),
}

def http_req(method, path, body=None, token=None):
    url = f"{BASE_URL}{path}"
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            status = resp.status
            content = resp.read().decode()
            try:
                parsed = json.loads(content)
            except Exception:
                parsed = content
            return {"status": status, "body": parsed, "error": None}
    except urllib.error.HTTPError as e:
        content = e.read().decode()
        try:
            parsed = json.loads(content)
        except Exception:
            parsed = content
        return {"status": e.code, "body": parsed, "error": str(e)}
    except Exception as e:
        return {"status": 0, "body": None, "error": str(e)}

async def run_audit():
    audit_results = {
        "routes": [],
        "auth_rbac": [],
        "detection": [],
        "websocket": [],
        "metadata": [],
        "mitigation": [],
        "evidence": []
    }

    print("==================================================")
    print("1. RUNNING BACKEND ROUTE AUDIT")
    print("==================================================")

    # 1. GET /health
    r_unauth = http_req("GET", "/health")
    audit_results["routes"].append({
        "method": "GET", "path": "/health", "auth": "NONE", "role": "NONE",
        "unauth_status": r_unauth["status"], "auth_status": r_unauth["status"],
        "result": "PASS" if r_unauth["status"] == 200 else "FAIL",
        "consumer": "Top bar, Health checks"
    })

    # 2. GET /api/system/status
    r_unauth = http_req("GET", "/api/system/status")
    audit_results["routes"].append({
        "method": "GET", "path": "/api/system/status", "auth": "NONE", "role": "NONE",
        "unauth_status": r_unauth["status"], "auth_status": r_unauth["status"],
        "result": "PASS" if r_unauth["status"] == 200 else "FAIL",
        "consumer": "Legacy compatibility"
    })

    # 3. GET /api/v1/system/status
    r_unauth = http_req("GET", "/api/v1/system/status")
    audit_results["routes"].append({
        "method": "GET", "path": "/api/v1/system/status", "auth": "NONE", "role": "NONE",
        "unauth_status": r_unauth["status"], "auth_status": r_unauth["status"],
        "result": "PASS" if r_unauth["status"] == 200 else "FAIL",
        "consumer": "Dashboard, Topbar, Sidebar"
    })

    # 4. GET /api/v1/system/telemetry
    r_unauth = http_req("GET", "/api/v1/system/telemetry")
    r_auth = http_req("GET", "/api/v1/system/telemetry", token=TOKENS["admin"])
    audit_results["routes"].append({
        "method": "GET", "path": "/api/v1/system/telemetry", "auth": "BEARER", "role": "VIEWER+",
        "unauth_status": r_unauth["status"], "auth_status": r_auth["status"],
        "result": "PASS" if (r_unauth["status"] == 401 and r_auth["status"] == 200) else "FAIL",
        "consumer": "Analytics & KPIs, Dashboard"
    })

    # 5. POST /api/v1/auth/login
    r_login_invalid = http_req("POST", "/api/v1/auth/login", body={"username": "admin", "password": "WrongPassword"})
    r_login_valid = http_req("POST", "/api/v1/auth/login", body={"username": "admin", "password": PASSWORD})
    audit_results["routes"].append({
        "method": "POST", "path": "/api/v1/auth/login", "auth": "NONE", "role": "NONE",
        "unauth_status": r_login_valid["status"], "auth_status": r_login_valid["status"],
        "result": "PASS" if (r_login_invalid["status"] == 401 and r_login_valid["status"] == 200) else "FAIL",
        "consumer": "Login Screen"
    })

    # 6. GET /api/v1/auth/me
    r_unauth = http_req("GET", "/api/v1/auth/me")
    r_auth = http_req("GET", "/api/v1/auth/me", token=TOKENS["admin"])
    audit_results["routes"].append({
        "method": "GET", "path": "/api/v1/auth/me", "auth": "BEARER", "role": "ALL",
        "unauth_status": r_unauth["status"], "auth_status": r_auth["status"],
        "result": "PASS" if (r_unauth["status"] == 401 and r_auth["status"] == 200) else "FAIL",
        "consumer": "App Shell, Topbar, Sidebar, Profile"
    })

    # 7. POST /api/v1/auth/logout
    r_unauth = http_req("POST", "/api/v1/auth/logout")
    r_auth = http_req("POST", "/api/v1/auth/logout", token=TOKENS["admin"])
    audit_results["routes"].append({
        "method": "POST", "path": "/api/v1/auth/logout", "auth": "BEARER", "role": "ALL",
        "unauth_status": r_unauth["status"], "auth_status": r_auth["status"],
        "result": "PASS" if (r_unauth["status"] == 401 and r_auth["status"] == 200) else "FAIL",
        "consumer": "Sidebar, Profile"
    })

    # Fetch demo scenarios
    scenarios_resp = http_req("GET", "/api/v1/detection/demo-scenarios", token=TOKENS["admin"])
    scenarios = scenarios_resp["body"]

    # 8. GET /api/v1/detection/demo-scenarios
    r_unauth = http_req("GET", "/api/v1/detection/demo-scenarios")
    audit_results["routes"].append({
        "method": "GET", "path": "/api/v1/detection/demo-scenarios", "auth": "BEARER", "role": "ANALYST+",
        "unauth_status": r_unauth["status"], "auth_status": scenarios_resp["status"],
        "result": "PASS" if (r_unauth["status"] == 401 and scenarios_resp["status"] == 200) else "FAIL",
        "consumer": "Threat Detection, Live Traffic"
    })

    # 9. POST /api/v1/detection/analyze
    benign_sc = scenarios["benign"]
    r_unauth = http_req("POST", "/api/v1/detection/analyze", body={"source_identifier": "test", "traffic_rate": 10, "features": benign_sc["features"]})
    r_auth = http_req("POST", "/api/v1/detection/analyze", body={"source_identifier": "test", "traffic_rate": 10, "features": benign_sc["features"]}, token=TOKENS["admin"])
    r_invalid = http_req("POST", "/api/v1/detection/analyze", body={"source_identifier": "test", "traffic_rate": 10, "features": {"invalid_feat": 1}}, token=TOKENS["admin"])
    audit_results["routes"].append({
        "method": "POST", "path": "/api/v1/detection/analyze", "auth": "BEARER", "role": "ANALYST+",
        "unauth_status": r_unauth["status"], "auth_status": r_auth["status"],
        "result": "PASS" if (r_unauth["status"] == 401 and r_auth["status"] == 200 and r_invalid["status"] == 422) else "FAIL",
        "consumer": "Threat Detection (O2)"
    })

    # 10. POST /api/v1/stream/simulate
    r_unauth = http_req("POST", "/api/v1/stream/simulate", body={"scenario": "benign", "observations": 2, "interval_ms": 0})
    r_auth = http_req("POST", "/api/v1/stream/simulate", body={"scenario": "benign", "observations": 2, "interval_ms": 0}, token=TOKENS["admin"])
    audit_results["routes"].append({
        "method": "POST", "path": "/api/v1/stream/simulate", "auth": "BEARER", "role": "OPERATOR+",
        "unauth_status": r_unauth["status"], "auth_status": r_auth["status"],
        "result": "PASS" if (r_unauth["status"] == 401 and r_auth["status"] == 200) else "FAIL",
        "consumer": "Live Traffic (Simulator Panel)"
    })

    # 11. GET /api/v1/evaluation/kpis
    r_unauth = http_req("GET", "/api/v1/evaluation/kpis")
    r_auth = http_req("GET", "/api/v1/evaluation/kpis", token=TOKENS["admin"])
    audit_results["routes"].append({
        "method": "GET", "path": "/api/v1/evaluation/kpis", "auth": "BEARER", "role": "VIEWER+",
        "unauth_status": r_unauth["status"], "auth_status": r_auth["status"],
        "result": "PASS" if (r_unauth["status"] == 401 and r_auth["status"] == 200) else "FAIL",
        "consumer": "Analytics & KPIs"
    })

    # 12. GET /api/v1/evaluation/acceptance
    r_unauth = http_req("GET", "/api/v1/evaluation/acceptance")
    r_auth = http_req("GET", "/api/v1/evaluation/acceptance", token=TOKENS["admin"])
    audit_results["routes"].append({
        "method": "GET", "path": "/api/v1/evaluation/acceptance", "auth": "BEARER", "role": "VIEWER+",
        "unauth_status": r_unauth["status"], "auth_status": r_auth["status"],
        "result": "PASS" if (r_unauth["status"] == 401 and r_auth["status"] == 200) else "FAIL",
        "consumer": "Training & Artifacts"
    })

    # 13. GET /api/v1/evaluation/negative-tests
    r_unauth = http_req("GET", "/api/v1/evaluation/negative-tests")
    r_auth = http_req("GET", "/api/v1/evaluation/negative-tests", token=TOKENS["admin"])
    audit_results["routes"].append({
        "method": "GET", "path": "/api/v1/evaluation/negative-tests", "auth": "BEARER", "role": "VIEWER+",
        "unauth_status": r_unauth["status"], "auth_status": r_auth["status"],
        "result": "PASS" if (r_unauth["status"] == 401 and r_auth["status"] == 200) else "FAIL",
        "consumer": "Training & Artifacts"
    })

    # 14. GET /api/v1/evidence/summary
    r_unauth = http_req("GET", "/api/v1/evidence/summary")
    r_auth = http_req("GET", "/api/v1/evidence/summary", token=TOKENS["admin"])
    audit_results["routes"].append({
        "method": "GET", "path": "/api/v1/evidence/summary", "auth": "BEARER", "role": "VIEWER+",
        "unauth_status": r_unauth["status"], "auth_status": r_auth["status"],
        "result": "PASS" if (r_unauth["status"] == 401 and r_auth["status"] == 200) else "FAIL",
        "consumer": "Evidence & Audit (Available API)"
    })

    # 15. GET /api/v1/evidence/runs
    r_unauth = http_req("GET", "/api/v1/evidence/runs")
    r_auth = http_req("GET", "/api/v1/evidence/runs", token=TOKENS["admin"])
    audit_results["routes"].append({
        "method": "GET", "path": "/api/v1/evidence/runs", "auth": "BEARER", "role": "VIEWER+",
        "unauth_status": r_unauth["status"], "auth_status": r_auth["status"],
        "result": "PASS" if (r_unauth["status"] == 401 and r_auth["status"] == 200) else "FAIL",
        "consumer": "Evidence & Audit (Official Run History)"
    })

    # 16. GET /api/v1/evidence/audit
    r_unauth = http_req("GET", "/api/v1/evidence/audit")
    r_auth = http_req("GET", "/api/v1/evidence/audit?limit=10", token=TOKENS["admin"])
    audit_results["routes"].append({
        "method": "GET", "path": "/api/v1/evidence/audit", "auth": "BEARER", "role": "VIEWER+",
        "unauth_status": r_unauth["status"], "auth_status": r_auth["status"],
        "result": "PASS" if (r_unauth["status"] == 401 and r_auth["status"] == 200) else "FAIL",
        "consumer": "Evidence & Audit (Audit Trail Tab)"
    })

    # 17. GET /api/v1/evidence/demo-manifest
    r_unauth = http_req("GET", "/api/v1/evidence/demo-manifest")
    r_auth = http_req("GET", "/api/v1/evidence/demo-manifest", token=TOKENS["admin"])
    audit_results["routes"].append({
        "method": "GET", "path": "/api/v1/evidence/demo-manifest", "auth": "BEARER", "role": "VIEWER+",
        "unauth_status": r_unauth["status"], "auth_status": r_auth["status"],
        "result": "PASS" if (r_unauth["status"] == 401 and r_auth["status"] == 200) else "FAIL",
        "consumer": "Evidence & Audit (Sample Manifest Tab)"
    })

    # 18. GET /api/v1/evidence/demo-evaluation
    r_unauth = http_req("GET", "/api/v1/evidence/demo-evaluation")
    r_auth = http_req("GET", "/api/v1/evidence/demo-evaluation", token=TOKENS["admin"])
    audit_results["routes"].append({
        "method": "GET", "path": "/api/v1/evidence/demo-evaluation", "auth": "BEARER", "role": "VIEWER+",
        "unauth_status": r_unauth["status"], "auth_status": r_auth["status"],
        "result": "PASS" if (r_unauth["status"] == 401 and r_auth["status"] == 200) else "FAIL",
        "consumer": "Evidence & Audit (Demo Metrics Tab)"
    })

    # 19. GET /api/v1/evidence/feature-manifest
    r_unauth = http_req("GET", "/api/v1/evidence/feature-manifest")
    r_auth = http_req("GET", "/api/v1/evidence/feature-manifest", token=TOKENS["admin"])
    audit_results["routes"].append({
        "method": "GET", "path": "/api/v1/evidence/feature-manifest", "auth": "BEARER", "role": "VIEWER+",
        "unauth_status": r_unauth["status"], "auth_status": r_auth["status"],
        "result": "PASS" if (r_unauth["status"] == 401 and r_auth["status"] == 200) else "FAIL",
        "consumer": "Evidence & Audit (Feature Manifest Tab)"
    })

    # 20. WS /ws/traffic
    ws_unauth_closed = False
    try:
        async with websockets.connect(WS_URL) as ws:
            pass
    except Exception:
        ws_unauth_closed = True

    ws_auth_ok = False
    try:
        async with websockets.connect(f"{WS_URL}?access_token={TOKENS['admin']}") as ws:
            ws_auth_ok = True
    except Exception:
        ws_auth_ok = False

    audit_results["routes"].append({
        "method": "WS", "path": "/ws/traffic", "auth": "BEARER / PARAM", "role": "OPERATOR+",
        "unauth_status": 1008 if ws_unauth_closed else 200,
        "auth_status": 101 if ws_auth_ok else 500,
        "result": "PASS" if (ws_unauth_closed and ws_auth_ok) else "FAIL",
        "consumer": "Live Traffic, Dashboard"
    })

    print(f"Tested {len(audit_results['routes'])} routes. All passed: {all(r['result'] == 'PASS' for r in audit_results['routes'])}")

    print("\n==================================================")
    print("2. RUNNING RBAC RESTRICTION AUDIT")
    print("==================================================")
    # Test RBAC matrix:
    # Endpoint: /api/v1/stream/simulate (Requires OPERATOR or ADMIN)
    r_sim_admin = http_req("POST", "/api/v1/stream/simulate", body={"scenario": "benign", "observations": 1, "interval_ms": 0}, token=TOKENS["admin"])
    r_sim_operator = http_req("POST", "/api/v1/stream/simulate", body={"scenario": "benign", "observations": 1, "interval_ms": 0}, token=TOKENS["operator"])
    r_sim_analyst = http_req("POST", "/api/v1/stream/simulate", body={"scenario": "benign", "observations": 1, "interval_ms": 0}, token=TOKENS["analyst"])
    r_sim_viewer = http_req("POST", "/api/v1/stream/simulate", body={"scenario": "benign", "observations": 1, "interval_ms": 0}, token=TOKENS["viewer"])

    audit_results["auth_rbac"].append({
        "endpoint": "POST /api/v1/stream/simulate (Requires OPERATOR/ADMIN)",
        "admin_status": r_sim_admin["status"],
        "operator_status": r_sim_operator["status"],
        "analyst_status": r_sim_analyst["status"],
        "viewer_status": r_sim_viewer["status"],
        "rbac_enforced": r_sim_admin["status"] == 200 and r_sim_operator["status"] == 200 and r_sim_analyst["status"] == 403 and r_sim_viewer["status"] == 403
    })
    print(f"RBAC Stream Simulation: {audit_results['auth_rbac'][-1]}")

    # Endpoint: /api/v1/detection/analyze (Requires ANALYST, OPERATOR, or ADMIN)
    r_det_admin = http_req("POST", "/api/v1/detection/analyze", body={"source_identifier": "t", "traffic_rate": 1, "features": benign_sc["features"]}, token=TOKENS["admin"])
    r_det_analyst = http_req("POST", "/api/v1/detection/analyze", body={"source_identifier": "t", "traffic_rate": 1, "features": benign_sc["features"]}, token=TOKENS["analyst"])
    r_det_viewer = http_req("POST", "/api/v1/detection/analyze", body={"source_identifier": "t", "traffic_rate": 1, "features": benign_sc["features"]}, token=TOKENS["viewer"])

    audit_results["auth_rbac"].append({
        "endpoint": "POST /api/v1/detection/analyze (Requires ANALYST/OPERATOR/ADMIN)",
        "admin_status": r_det_admin["status"],
        "analyst_status": r_det_analyst["status"],
        "viewer_status": r_det_viewer["status"],
        "rbac_enforced": r_det_admin["status"] == 200 and r_det_analyst["status"] == 200 and r_det_viewer["status"] == 403
    })
    print(f"RBAC Detection Analyze: {audit_results['auth_rbac'][-1]}")

    # Token tampering test
    tampered_token = TOKENS["admin"][:-5] + "XXXXX"
    r_tampered = http_req("GET", "/api/v1/auth/me", token=tampered_token)
    audit_results["auth_rbac"].append({
        "test": "Tampered token rejected",
        "status": r_tampered["status"],
        "rejected": r_tampered["status"] == 401
    })
    print(f"Tampered Token Rejected: {r_tampered['status'] == 401}")

    print("\n==================================================")
    print("3. O2/O3 DETECTION END-TO-END PIPELINE AUDIT")
    print("==================================================")
    # Scenario 1: Benign
    benign_sc = scenarios["benign"]
    res_b = http_req("POST", "/api/v1/detection/analyze", body={
        "source_identifier": "audit:benign",
        "traffic_rate": benign_sc["traffic_rate"],
        "features": benign_sc["features"],
        "metadata": benign_sc["metadata"]
    }, token=TOKENS["admin"])["body"]

    # Scenario 2: Flash crowd
    flash_sc = scenarios["flash_crowd"]
    res_f = http_req("POST", "/api/v1/detection/analyze", body={
        "source_identifier": "audit:flash_crowd",
        "traffic_rate": flash_sc["traffic_rate"],
        "features": flash_sc["features"],
        "metadata": flash_sc["metadata"]
    }, token=TOKENS["admin"])["body"]

    # Scenario 3: NetBIOS Attack
    attack_sc = scenarios["attack_fixture"]
    res_a = http_req("POST", "/api/v1/detection/analyze", body={
        "source_identifier": "audit:attack",
        "traffic_rate": attack_sc["traffic_rate"],
        "features": attack_sc["features"],
        "metadata": attack_sc["metadata"]
    }, token=TOKENS["admin"])["body"]

    b_pass = (res_b["o2"]["detected"] is False and res_b["mitigation"]["decision"] == "ALLOW")
    f_pass = (res_f["o2"]["detected"] is False and res_f["mitigation"]["decision"] == "RATE_LIMIT")
    a_pass = (res_a["o2"]["detected"] is True and res_a["o3"]["attack_type"].upper() == "NETBIOS" and res_a["mitigation"]["decision"] == "BLOCK")

    audit_results["detection"].append({
        "scenario": "BENIGN", "o2_detected": res_b["o2"]["detected"], "o3": res_b["o3"]["attack_type"],
        "decision": res_b["mitigation"]["decision"], "passed": b_pass
    })
    audit_results["detection"].append({
        "scenario": "FLASH_CROWD", "o2_detected": res_f["o2"]["detected"], "o3": res_f["o3"]["attack_type"],
        "decision": res_f["mitigation"]["decision"], "passed": f_pass
    })
    audit_results["detection"].append({
        "scenario": "ATTACK (NetBIOS)", "o2_detected": res_a["o2"]["detected"], "o3": res_a["o3"]["attack_type"],
        "decision": res_a["mitigation"]["decision"], "passed": a_pass
    })
    print(f"BENIGN pipeline: {b_pass}")
    print(f"FLASH CROWD pipeline: {f_pass}")
    print(f"ATTACK pipeline: {a_pass}")

    print("\n==================================================")
    print("4. IP / FLOW METADATA & 78-FEATURE CONTRACT AUDIT")
    print("==================================================")
    # Check that metadata is returned in response
    meta_b = res_b.get("metadata", {})
    meta_present = (
        meta_b.get("source_ip") == benign_sc["metadata"]["source_ip"] and
        meta_b.get("destination_ip") == benign_sc["metadata"]["destination_ip"] and
        meta_b.get("protocol") == benign_sc["metadata"]["protocol"]
    )

    # Check that passing metadata inside features fails validation (feature contract violation)
    corrupted_features = dict(benign_sc["features"])
    corrupted_features["Source IP"] = "1.2.3.4"
    r_corrupt = http_req("POST", "/api/v1/detection/analyze", body={
        "source_identifier": "corrupt",
        "traffic_rate": 10,
        "features": corrupted_features
    }, token=TOKENS["admin"])

    contract_rejected = (r_corrupt["status"] == 422)
    audit_results["metadata"].append({
        "metadata_echoed": meta_present,
        "contract_rejects_spurious_features": contract_rejected,
        "features_validated_count": len(benign_sc["features"]),
    })
    print(f"Flow metadata preserved & echoed: {meta_present}")
    print(f"78-feature contract rejects spurious network columns in features: {contract_rejected}")

    print("\n==================================================")
    print("5. WEBSOCKET FULL LIFECYCLE AUDIT")
    print("==================================================")
    ws_uri = f"{WS_URL}?access_token={TOKENS['admin']}"
    ws_lifecycle_pass = False
    async with websockets.connect(ws_uri) as ws:
        # Send benign observation
        await ws.send(json.dumps({
            "source_identifier": "ws_audit:benign",
            "traffic_rate": benign_sc["traffic_rate"],
            "features": benign_sc["features"],
            "metadata": benign_sc["metadata"]
        }))
        raw_resp = await ws.recv()
        resp1 = json.loads(raw_resp)

        # Send attack observation
        await ws.send(json.dumps({
            "source_identifier": "ws_audit:attack",
            "traffic_rate": attack_sc["traffic_rate"],
            "features": attack_sc["features"],
            "metadata": attack_sc["metadata"]
        }))
        raw_resp = await ws.recv()
        resp2 = json.loads(raw_resp)

        ws_lifecycle_pass = (
            resp1.get("type") == "detection_result" and
            resp1["response"]["mitigation"]["decision"] == "ALLOW" and
            resp2.get("type") == "detection_result" and
            resp2["response"]["mitigation"]["decision"] == "BLOCK"
        )

    # Test reconnect
    reconnect_ok = False
    async with websockets.connect(ws_uri) as ws:
        reconnect_ok = True

    audit_results["websocket"].append({
        "lifecycle_verified": ws_lifecycle_pass,
        "reconnect_verified": reconnect_ok
    })
    print(f"WebSocket send/receive/verify: {ws_lifecycle_pass}")
    print(f"WebSocket clean reconnect: {reconnect_ok}")

    print("\n==================================================")
    print("6. MITIGATION & AUDIT TRAIL VERIFICATION")
    print("==================================================")
    # Check that audit log has records
    audit_resp = http_req("GET", "/api/v1/evidence/audit?limit=20", token=TOKENS["admin"])
    audit_records = audit_resp["body"]
    audit_has_records = len(audit_records) > 0
    executor_is_simulated = res_a["mitigation"]["executor_type"] == "simulated"

    audit_results["mitigation"].append({
        "executor_type": res_a["mitigation"]["executor_type"],
        "is_simulation_only": executor_is_simulated,
        "audit_trail_recorded": audit_has_records,
        "audit_record_count": len(audit_records)
    })
    print(f"Mitigation Executor is simulated: {executor_is_simulated}")
    print(f"Audit records present: {audit_has_records} (count: {len(audit_records)})")

    print("\n==================================================")
    print("7. EVIDENCE & KPI TRUTHFULNESS CHECK")
    print("==================================================")
    kpi_resp = http_req("GET", "/api/v1/evaluation/kpis", token=TOKENS["admin"])["body"]
    acc_resp = http_req("GET", "/api/v1/evaluation/acceptance", token=TOKENS["admin"])["body"]
    neg_resp = http_req("GET", "/api/v1/evaluation/negative-tests", token=TOKENS["admin"])["body"]

    kpis_not_executed = all(r["status"] == "NOT_EXECUTED" for r in kpi_resp.get("records", []))
    acc_not_executed = all(r["status"] == "NOT_EXECUTED" for r in acc_resp.get("records", []))
    neg_blocked = all(r["status"] == "BLOCKED" for r in neg_resp.get("records", []))

    audit_results["evidence"].append({
        "kpis_not_executed": kpis_not_executed,
        "acceptance_not_executed": acc_not_executed,
        "negative_tests_blocked": neg_blocked
    })
    print(f"KPI-1..6 strictly NOT_EXECUTED: {kpis_not_executed}")
    print(f"AC-1..4 strictly NOT_EXECUTED: {acc_not_executed}")
    print(f"NT-1..5 strictly BLOCKED: {neg_blocked}")

    # Write results to json
    with open("evidence/complete_system_audit_data.json", "w", encoding="utf-8") as f:
        json.dump(audit_results, f, indent=2)
    print("\n[SUCCESS] Audit data written to evidence/complete_system_audit_data.json")

if __name__ == "__main__":
    asyncio.run(run_audit())

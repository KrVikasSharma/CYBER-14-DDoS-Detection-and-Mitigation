import asyncio
import json
import time
from pathlib import Path
import httpx
import websockets

BACKEND_URL = "http://127.0.0.1:8000"
WS_URL = "ws://127.0.0.1:8000/ws/traffic"

async def test_stream_lifecycle():
    print("==================================================")
    print("CYBER-14: WEBSOCKET STREAM LIFECYCLE AUDIT")
    print("==================================================")

    # 1. Login to get valid token
    async with httpx.AsyncClient(base_url=BACKEND_URL) as client:
        login_resp = await client.post("/api/v1/auth/login", json={"username": "admin", "password": "DemoAdminPassword123!"})
        assert login_resp.status_code == 200, f"Login failed: {login_resp.text}"
        token = login_resp.json()["access_token"]
        print("[OK] Obtained JWT access token for admin")

    ws_authenticated_url = f"{WS_URL}?access_token={token}"
    scenarios = json.loads(Path("data/demo/demo_scenarios.json").read_text(encoding="utf-8"))

    # TEST 1: Heartbeat Ping / Pong
    print("\n[TEST 1] Testing Heartbeat Ping/Pong Keepalive...")
    async with websockets.connect(ws_authenticated_url) as ws:
        await ws.send(json.dumps({"type": "ping"}))
        raw_pong = await asyncio.wait_for(ws.recv(), timeout=3.0)
        pong = json.loads(raw_pong)
        assert pong["type"] == "pong", f"Expected pong, got {pong}"
        assert "timestamp" in pong
        assert "connection_id" in pong
        print(f"  [OK] Received pong response: {pong}")

    # TEST 2: Manual Observation Triggers (Send Benign, Send Flash Crowd, Send Attack)
    print("\n[TEST 2] Testing Manual Observation Triggers...")
    async with websockets.connect(ws_authenticated_url) as ws:
        # Case A: Benign
        b_sc = scenarios["benign"]
        await ws.send(json.dumps({
            "source_identifier": "manual:benign:001",
            "traffic_rate": b_sc["traffic_rate"],
            "features": b_sc["features"],
            "metadata": {"source_ip": "192.168.1.100", "source_port": 54321, "destination_ip": "10.0.0.1", "destination_port": 80, "protocol": "TCP"}
        }))
        res_b = json.loads(await asyncio.wait_for(ws.recv(), timeout=3.0))
        assert res_b["type"] == "detection_result"
        assert res_b["response"]["mitigation"]["decision"] == "ALLOW"
        print(f"  [OK] Send Benign -> ALLOW (O2 conf: {res_b['response']['o2']['confidence'] * 100:.1f}%, threshold: {res_b['response']['o2']['threshold'] * 100:.1f}%)")

        # Case B: Flash Crowd
        fc_sc = scenarios["flash_crowd"]
        await ws.send(json.dumps({
            "source_identifier": "manual:flash_crowd:002",
            "traffic_rate": fc_sc["traffic_rate"],
            "features": fc_sc["features"],
            "metadata": {"source_ip": "192.168.1.101", "source_port": 54322, "destination_ip": "10.0.0.1", "destination_port": 80, "protocol": "TCP"}
        }))
        res_fc = json.loads(await asyncio.wait_for(ws.recv(), timeout=3.0))
        assert res_fc["type"] == "detection_result"
        assert res_fc["response"]["mitigation"]["decision"] == "RATE_LIMIT"
        assert res_fc["response"]["mitigation"]["duration_seconds"] == 60
        print(f"  [OK] Send Flash Crowd -> RATE_LIMIT (Duration: 60s, threshold: 1,000 req/s)")

        # Case C: Attack
        att_sc = scenarios["attack_fixture"]
        await ws.send(json.dumps({
            "source_identifier": "manual:attack:003",
            "traffic_rate": att_sc["traffic_rate"],
            "features": att_sc["features"],
            "metadata": {"source_ip": "192.168.1.102", "source_port": 54323, "destination_ip": "10.0.0.1", "destination_port": 137, "protocol": "UDP"}
        }))
        res_att = json.loads(await asyncio.wait_for(ws.recv(), timeout=3.0))
        assert res_att["type"] == "detection_result"
        assert res_att["response"]["mitigation"]["decision"] == "BLOCK"
        assert res_att["response"]["mitigation"]["duration_seconds"] == 300
        print(f"  [OK] Send Attack -> BLOCK (O3: {res_att['response']['o3']['attack_type']}, Duration: 300s)")

    # TEST 3: Simulated Auto-Stream (Observations every ~1.8s + Ping Keepalive)
    print("\n[TEST 3] Testing Simulated Auto-Stream with Periodic Keepalive...")
    async with websockets.connect(ws_authenticated_url) as ws:
        for step in range(5):
            seq_key = ["benign", "benign", "flash_crowd", "attack_fixture"][step % 4]
            sc = scenarios[seq_key]
            await ws.send(json.dumps({
                "source_identifier": f"autostream:{seq_key}:{step:03d}",
                "traffic_rate": sc["traffic_rate"],
                "features": sc["features"],
                "metadata": {"source_ip": f"192.168.1.{10 + step}", "source_port": 50000 + step, "destination_ip": "10.0.0.1", "destination_port": 80, "protocol": "TCP"}
            }))
            res = json.loads(await asyncio.wait_for(ws.recv(), timeout=3.0))
            assert res["type"] == "detection_result"
            print(f"  [OK] Step {step + 1}/5: {seq_key} -> {res['response']['mitigation']['decision']} (latency: {res['response']['latency']['total_analysis_ms']:.1f}ms)")
            # Wait ~1.8s between auto-stream steps
            await asyncio.sleep(1.8)

        # Send heartbeat ping
        await ws.send(json.dumps({"type": "ping"}))
        pong = json.loads(await asyncio.wait_for(ws.recv(), timeout=3.0))
        assert pong["type"] == "pong"
        print("  [OK] Heartbeat ping during active streaming verified.")

    # TEST 4: Connect -> Disconnect -> Connect -> Disconnect Cleanly (No Duplicates)
    print("\n[TEST 4] Testing Rapid Connect / Disconnect Lifecycle...")
    for cycle in range(3):
        async with websockets.connect(ws_authenticated_url) as ws:
            await ws.send(json.dumps({"type": "ping"}))
            pong = json.loads(await asyncio.wait_for(ws.recv(), timeout=3.0))
            assert pong["type"] == "pong"
        # cleanly disconnected
        print(f"  [OK] Cycle {cycle + 1}: connected, pinged, cleanly closed.")

    print("\n==================================================")
    print("ALL STREAM LIFECYCLE TESTS PASSED SUCCESSFULLY!")
    print("==================================================")

if __name__ == "__main__":
    asyncio.run(test_stream_lifecycle())

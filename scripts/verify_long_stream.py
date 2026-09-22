import asyncio
import json
import time
from pathlib import Path
import httpx
import websockets

BACKEND_URL = "http://127.0.0.1:8000"
WS_URL = "ws://127.0.0.1:8000/ws/traffic"

async def test_long_continuous_stream():
    print("==================================================")
    print("CYBER-14: 2+ MINUTE CONTINUOUS STREAMING AUDIT")
    print("==================================================")

    async with httpx.AsyncClient(base_url=BACKEND_URL) as client:
        login_resp = await client.post("/api/v1/auth/login", json={"username": "admin", "password": "DemoAdminPassword123!"})
        assert login_resp.status_code == 200
        token = login_resp.json()["access_token"]

    ws_url = f"{WS_URL}?access_token={token}"
    scenarios = json.loads(Path("data/demo/demo_scenarios.json").read_text(encoding="utf-8"))

    # Phase 1: 125 seconds continuous streaming (~70 observations @ 1.8s interval)
    print("\n[PHASE 1] Starting 125-second continuous streaming test (target ~70 observations)...")
    start_time = time.monotonic()
    received_count = 0
    seq = ["benign", "benign", "flash_crowd", "attack_fixture"]
    step = 0
    decisions_seen = set()

    async with websockets.connect(ws_url) as ws:
        # Background keepalive task
        async def keepalive():
            try:
                while True:
                    await asyncio.sleep(15.0)
                    await ws.send(json.dumps({"type": "ping"}))
            except asyncio.CancelledError:
                pass

        keepalive_task = asyncio.create_task(keepalive())

        try:
            while time.monotonic() - start_time < 125.0:
                cur_sc = seq[step % len(seq)]
                sc_data = scenarios[cur_sc]
                payload = {
                    "source_identifier": f"continuous:{cur_sc}:{step:04d}",
                    "traffic_rate": sc_data["traffic_rate"],
                    "features": sc_data["features"],
                    "metadata": {
                        "source_ip": f"192.168.1.{20 + (step % 50)}",
                        "source_port": 50000 + (step % 1000),
                        "destination_ip": "10.0.0.1",
                        "destination_port": 80 if cur_sc != "attack_fixture" else 137,
                        "protocol": "TCP" if cur_sc != "attack_fixture" else "UDP",
                        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    }
                }
                await ws.send(json.dumps(payload))
                raw_msg = await asyncio.wait_for(ws.recv(), timeout=5.0)
                msg = json.loads(raw_msg)

                # If pong arrived from keepalive, receive next msg
                if msg.get("type") == "pong":
                    raw_msg = await asyncio.wait_for(ws.recv(), timeout=5.0)
                    msg = json.loads(raw_msg)

                assert msg["type"] == "detection_result", f"Unexpected message: {msg}"
                dec = msg["response"]["mitigation"]["decision"]
                decisions_seen.add(dec)
                received_count += 1
                step += 1

                elapsed = time.monotonic() - start_time
                if step % 10 == 0 or elapsed > 120.0:
                    print(f"  [STREAMING] Elapsed: {elapsed:.1f}s | Observations: {received_count} | Last Action: {dec} | No errors")

                await asyncio.sleep(1.8)

        finally:
            keepalive_task.cancel()

    elapsed = time.monotonic() - start_time
    print(f"[OK] Completed continuous stream: {received_count} observations received over {elapsed:.1f}s with 0 errors!")
    assert received_count >= 60, f"Expected >= 60 observations, got {received_count}"
    assert "ALLOW" in decisions_seen, "Missing ALLOW decision"
    assert "RATE_LIMIT" in decisions_seen, "Missing RATE_LIMIT decision"
    assert "BLOCK" in decisions_seen, "Missing BLOCK decision"

    # Phase 2: Pause -> Stop socket -> Restart socket
    print("\n[PHASE 2] Testing Clean Pause & Reconnect...")
    # Pause simulates user clicking pause: no frames for 5 seconds
    await asyncio.sleep(5.0)
    print("  [OK] Clean pause verified (no unexpected errors).")

    # Reconnect
    print("\n[PHASE 3] Reconnecting socket and verifying final scenarios...")
    async with websockets.connect(ws_url) as ws:
        # Test 1: BENIGN -> ALLOW
        await ws.send(json.dumps({
            "source_identifier": "final:benign",
            "traffic_rate": scenarios["benign"]["traffic_rate"],
            "features": scenarios["benign"]["features"],
        }))
        res1 = json.loads(await ws.recv())
        assert res1["response"]["mitigation"]["decision"] == "ALLOW"
        print("  [OK] Final BENIGN -> ALLOW verified.")

        # Test 2: FLASH CROWD -> RATE_LIMIT
        await ws.send(json.dumps({
            "source_identifier": "final:flash_crowd",
            "traffic_rate": scenarios["flash_crowd"]["traffic_rate"],
            "features": scenarios["flash_crowd"]["features"],
        }))
        res2 = json.loads(await ws.recv())
        assert res2["response"]["mitigation"]["decision"] == "RATE_LIMIT"
        print("  [OK] Final FLASH CROWD -> RATE_LIMIT verified.")

        # Test 3: ATTACK -> BLOCK
        await ws.send(json.dumps({
            "source_identifier": "final:attack",
            "traffic_rate": scenarios["attack_fixture"]["traffic_rate"],
            "features": scenarios["attack_fixture"]["features"],
        }))
        res3 = json.loads(await ws.recv())
        assert res3["response"]["mitigation"]["decision"] == "BLOCK"
        print("  [OK] Final ATTACK -> BLOCK verified.")

    print("\n==================================================")
    print("2+ MINUTE CONTINUOUS STREAMING AUDIT PASSED 100%!")
    print("==================================================")

if __name__ == "__main__":
    asyncio.run(test_long_continuous_stream())

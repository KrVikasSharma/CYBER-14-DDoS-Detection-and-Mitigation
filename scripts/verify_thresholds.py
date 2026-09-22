import httpx
import json
from pathlib import Path

def main():
    client = httpx.Client(base_url="http://127.0.0.1:8000", timeout=10.0)
    login_res = client.post("/api/v1/auth/login", json={"username": "admin", "password": "DemoAdminPassword123!"})
    assert login_res.status_code == 200, f"Login failed: {login_res.text}"
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    scenarios = json.loads(Path("data/demo/demo_scenarios.json").read_text(encoding="utf-8"))
    test_cases = [
        ("BENIGN", "demo:presentation:benign", scenarios["benign"]),
        ("FLASH CROWD", "demo:presentation:flash_crowd", scenarios["flash_crowd"]),
        ("NETBIOS ATTACK", "demo:presentation:attack_netbios", scenarios["attack_fixture"]),
    ]

    for name, src_id, item in test_cases:
        payload = {
            "source_identifier": src_id,
            "traffic_rate": item["traffic_rate"],
            "features": item["features"],
        }
        res = client.post("/api/v1/detection/analyze", headers=headers, json=payload)
        assert res.status_code == 200, f"Analyze failed for {name}: {res.text}"
        data = res.json()
        print(f"==================================================")
        print(f"SCENARIO: {name}")
        print(f"==================================================")
        print(f"O2 detected: {data['o2']['detected']}")
        print(f"O2 confidence: {data['o2']['confidence'] * 100:.1f}%")
        print(f"O2 threshold: {data['o2']['threshold'] * 100:.1f}%")
        print(f"O3 attack_type: {data['o3']['attack_type']}")
        if data['o3']['confidence'] is not None:
            print(f"O3 confidence: {data['o3']['confidence'] * 100:.1f}%")
        else:
            print("O3 confidence: None (BENIGN)")
        print(f"O3 threshold: {data['o3']['threshold'] * 100:.1f}%")
        print(f"O3 decision_method: {data['o3']['decision_method']}")
        print(f"Mitigation decision: {data['mitigation']['decision']}")
        print(f"Mitigation duration_seconds: {data['mitigation']['duration_seconds']}")
        print(f"Mitigation parameters: {json.dumps(data['mitigation']['parameters'], indent=2)}")
        print()

        # Assertions
        assert data["o2"]["threshold"] == 0.50, f"Expected 0.50 threshold, got {data['o2']['threshold']}"
        assert data["o3"]["threshold"] == 0.80, f"Expected 0.80 threshold, got {data['o3']['threshold']}"

        if name == "BENIGN":
            assert data["o2"]["detected"] is False
            assert data["mitigation"]["decision"] == "ALLOW"
            assert data["mitigation"]["duration_seconds"] is None
            assert data["mitigation"]["parameters"]["flash_crowd_rate_threshold"] == 1000.0
            assert data["mitigation"]["parameters"]["legitimate_confidence_threshold"] == 0.80
        elif name == "FLASH CROWD":
            assert data["o2"]["detected"] is False
            assert data["mitigation"]["decision"] == "RATE_LIMIT"
            assert data["mitigation"]["duration_seconds"] == 60
            assert data["mitigation"]["parameters"]["flash_crowd_rate_threshold"] == 1000.0
            assert data["mitigation"]["parameters"]["rate_limit_duration_seconds"] == 60
            assert data["mitigation"]["parameters"]["requests_per_second"] == 100.0
        elif name == "NETBIOS ATTACK":
            assert data["o2"]["detected"] is True
            assert data["o3"]["attack_type"].upper() == "NETBIOS"
            assert data["mitigation"]["decision"] == "BLOCK"
            assert data["mitigation"]["duration_seconds"] == 300
            assert data["mitigation"]["parameters"]["confirmed_confidence_threshold"] == 0.80
            assert data["mitigation"]["parameters"]["block_duration_seconds"] == 300

    print("ALL 3 SCENARIOS VERIFIED SUCCESSFULLY WITH CONFIGURED THRESHOLDS AND DURATIONS!")

if __name__ == "__main__":
    main()

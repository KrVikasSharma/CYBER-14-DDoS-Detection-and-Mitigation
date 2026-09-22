import json
import time
from pathlib import Path

import pandas as pd
import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from app.core.config import Settings
from app.main import create_app
from app.services.detection_service import DetectionService
from app.services.streaming_service import StreamingService, get_streaming_service
from ml.o2.config import O2ModelConfig
from ml.o2.train import train_o2_reference_detector
from ml.o3.config import O3ModelConfig
from ml.o3.train import train_o3_reference_classifier


FIXTURE_PATH = Path("data/fixtures/o3_tiny_processed_fixture.csv")


def observation(source="192.0.2.10", features=None, traffic_rate=10):
    return {
        "source_identifier": source,
        "traffic_rate": traffic_rate,
        "features": features or {"Flow Duration": 10, "Total Fwd Packets": 1, "Protocol": 6},
    }


@pytest.fixture
def streaming_context(workspace_tmp_path):
    dataset = pd.read_csv(FIXTURE_PATH)
    o2 = train_o2_reference_detector(
        dataset,
        O2ModelConfig(artifact_dir=workspace_tmp_path / "o2", random_seed=7, n_estimators=10),
        dataset_reference="stream-fixture",
    )
    o3 = train_o3_reference_classifier(
        dataset,
        O3ModelConfig(artifact_dir=workspace_tmp_path / "o3", random_seed=7, n_estimators=10),
        dataset_reference="stream-fixture",
        fixture_only=True,
    )
    settings = Settings(
        o2_model_path=o2.model_path,
        o3_model_path=o3.model_path,
        o2_fixture_only=True,
        o3_fixture_only=True,
        stream_simulator_enabled=True,
        websocket_max_message_bytes=512,
        websocket_max_messages_per_second=10,
        websocket_idle_timeout_seconds=2,
    )
    detection = DetectionService(settings)
    streaming = StreamingService(settings, detection)
    application = create_app()
    application.dependency_overrides[get_streaming_service] = lambda: streaming
    return application, streaming


def test_websocket_connection_valid_observation_and_disconnect(streaming_context):
    application, streaming = streaming_context
    with TestClient(application) as client:
        with client.websocket_connect("/ws/traffic") as websocket:
            websocket.send_json(observation())
            result = websocket.receive_json()
            assert result["type"] == "detection_result"
            assert result["response"]["o2"]["detected"] is False
            assert result["response"]["mitigation"]["decision"] == "ALLOW"
            assert result["response"]["mitigation"]["audit_event_id"]
            assert result["fixture_only"] is True
            assert result["connection_id"]
        for _ in range(20):
            if streaming.connection_count() == 0:
                break
            time.sleep(0.01)
        assert streaming.connection_count() == 0


def test_websocket_attack_propagates_o2_o3_mitigation_and_audit(streaming_context):
    application, _ = streaming_context
    with TestClient(application) as client:
        with client.websocket_connect("/ws/traffic") as websocket:
            websocket.send_json(
                observation(
                    source="192.0.2.20",
                    traffic_rate=2000,
                    features={"Flow Duration": 50, "Total Fwd Packets": 20, "Protocol": 17},
                )
            )
            result = websocket.receive_json()
            response = result["response"]
            assert response["o2"]["detected"] is True
            assert response["o3"]["available"] is True
            assert response["o3"]["probabilities"]
            assert response["mitigation"]["simulation_only"] is True
            assert response["latency"]["total_analysis_ms"] >= 0


def test_websocket_malformed_json_and_invalid_observation_are_structured_errors(streaming_context):
    application, _ = streaming_context
    with TestClient(application) as client:
        with client.websocket_connect("/ws/traffic") as websocket:
            websocket.send_text("not-json")
            malformed = websocket.receive_json()
            assert malformed["type"] == "error"
            assert malformed["error_code"] == "invalid_json"
            websocket.send_json({"source_identifier": "192.0.2.1", "features": {"Flow Duration": 10}})
            missing = websocket.receive_json()
            assert missing["error_code"] == "invalid_observation"
            websocket.send_json(
                observation(features={"Flow Duration": "not-a-number", "Total Fwd Packets": 1, "Protocol": 6})
            )
            invalid = websocket.receive_json()
            assert invalid["error_code"] == "invalid_observation"


def test_websocket_oversized_message_is_rejected_and_rate_limited(streaming_context):
    application, streaming = streaming_context
    streaming._settings.websocket_max_messages_per_second = 1
    with TestClient(application) as client:
        with client.websocket_connect("/ws/traffic") as websocket:
            websocket.send_text(json.dumps({"padding": "x" * 1000}))
            oversized = websocket.receive_json()
            assert oversized["error_code"] == "message_too_large"
        with client.websocket_connect("/ws/traffic") as websocket:
            websocket.send_json(observation())
            websocket.receive_json()
            websocket.send_json(observation(source="192.0.2.11"))
            limited = websocket.receive_json()
            assert limited["error_code"] == "rate_limit_exceeded"


def test_multiple_sequential_observations_are_processed(streaming_context):
    application, _ = streaming_context
    with TestClient(application) as client:
        with client.websocket_connect("/ws/traffic") as websocket:
            for index in range(3):
                websocket.send_json(observation(source=f"192.0.2.{index + 1}"))
                result = websocket.receive_json()
                assert result["type"] == "detection_result"


@pytest.mark.parametrize("scenario", ["benign", "flash_crowd", "attack_fixture"])
def test_controlled_simulator_scenarios_use_same_detection_pipeline(streaming_context, scenario):
    application, _ = streaming_context
    with TestClient(application) as client:
        response = client.post(
            "/api/v1/stream/simulate",
            json={"scenario": scenario, "observations": 2, "interval_ms": 0},
        )
    assert response.status_code == 200
    body = response.json()
    assert body["source"] == "controlled_simulator"
    assert body["scenario"] == scenario
    assert body["observation_count"] == 2
    assert all(item["type"] == "detection_result" for item in body["results"])
    assert all(item["fixture_only"] is True for item in body["results"])
    assert all("controlled_simulator" in item["response"]["source_identifier"] for item in body["results"])
    if scenario == "attack_fixture":
        assert body["results"][0]["response"]["o2"]["detected"] is True


def test_simulator_disabled_returns_forbidden(streaming_context):
    application, streaming = streaming_context
    streaming._settings.stream_simulator_enabled = False
    with TestClient(application) as client:
        response = client.post("/api/v1/stream/simulate", json={"scenario": "benign"})
    assert response.status_code == 403


def test_simulator_generates_application_observations_only(streaming_context):
    application, _ = streaming_context
    with TestClient(application) as client:
        response = client.post("/api/v1/stream/simulate", json={"scenario": "attack_fixture"})
    result = response.json()["results"][0]["response"]
    assert result["source_identifier"].startswith("controlled_simulator:")
    assert "socket" not in result
    assert "packet" not in result


def test_websocket_rejects_invalid_or_missing_access_token_when_auth_is_enabled(monkeypatch):
    monkeypatch.setenv("AUTH_ENABLED", "true")
    monkeypatch.setenv("AUTH_SECRET_KEY", "x" * 40)
    monkeypatch.setenv("AUTH_BOOTSTRAP_PASSWORD", "password")
    monkeypatch.setenv("AUTH_BOOTSTRAP_ROLE", "admin")
    from app.auth.config import get_auth_settings
    get_auth_settings.cache_clear()
    application = create_app()
    application.dependency_overrides[get_streaming_service] = lambda: object()
    client = TestClient(application)
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/ws/traffic", params={"access_token": "bad-token"}):
            pass
    get_auth_settings.cache_clear()


def test_websocket_accepts_valid_token_for_operator_role(monkeypatch, workspace_tmp_path):
    monkeypatch.setenv("AUTH_ENABLED", "true")
    monkeypatch.setenv("AUTH_SECRET_KEY", "y" * 40)
    monkeypatch.setenv("AUTH_BOOTSTRAP_PASSWORD", "password")
    monkeypatch.setenv("AUTH_BOOTSTRAP_ROLE", "operator")
    from app.auth.config import get_auth_settings
    from app.auth.service import AuthService
    from app.services.detection_service import DetectionService
    get_auth_settings.cache_clear()
    dataset = pd.read_csv(FIXTURE_PATH)
    o2 = train_o2_reference_detector(
        dataset,
        O2ModelConfig(artifact_dir=workspace_tmp_path / "o2", random_seed=7, n_estimators=10),
        dataset_reference="stream-auth-fixture",
    )
    o3 = train_o3_reference_classifier(
        dataset,
        O3ModelConfig(artifact_dir=workspace_tmp_path / "o3", random_seed=7, n_estimators=10),
        dataset_reference="stream-auth-fixture",
        fixture_only=True,
    )
    settings = Settings(
        o2_model_path=o2.model_path,
        o3_model_path=o3.model_path,
        o2_fixture_only=True,
        o3_fixture_only=True,
        stream_simulator_enabled=True,
        websocket_max_message_bytes=512,
        websocket_max_messages_per_second=10,
        websocket_idle_timeout_seconds=2,
    )
    application = create_app()
    application.dependency_overrides[get_streaming_service] = lambda: StreamingService(settings, DetectionService(settings))
    token = AuthService(get_auth_settings()).login("admin", "password").access_token
    with TestClient(application) as client:
        with client.websocket_connect("/ws/traffic", params={"access_token": token}) as websocket:
            websocket.send_json(observation())
            result = websocket.receive_json()
            assert result["type"] == "detection_result"
    get_auth_settings.cache_clear()


def test_websocket_heartbeat_ping_returns_pong(streaming_context):
    application, _ = streaming_context
    with TestClient(application) as client:
        with client.websocket_connect("/ws/traffic") as websocket:
            websocket.send_json({"type": "ping"})
            result = websocket.receive_json()
            assert result["type"] == "pong"
            assert "connection_id" in result
            assert "timestamp" in result


def test_websocket_idle_timeout_terminates_abandoned_connection(streaming_context):
    application, streaming = streaming_context
    streaming._settings.websocket_idle_timeout_seconds = 1
    with TestClient(application) as client:
        with client.websocket_connect("/ws/traffic") as websocket:
            # Abandon connection for >1 second
            time.sleep(1.2)
            result = websocket.receive_json()
            assert result["type"] == "error"
            assert result["error_code"] == "idle_timeout"
            assert "idle too long" in result["message"]
            with pytest.raises(WebSocketDisconnect):
                websocket.receive_json()


def test_websocket_heartbeat_prevents_idle_timeout(streaming_context):
    application, streaming = streaming_context
    streaming._settings.websocket_idle_timeout_seconds = 2
    with TestClient(application) as client:
        with client.websocket_connect("/ws/traffic") as websocket:
            # Send ping at 0.8s to keep connection alive
            time.sleep(0.8)
            websocket.send_json({"type": "ping"})
            pong = websocket.receive_json()
            assert pong["type"] == "pong"

            # Send another ping at 0.8s (total 1.6s > original 1s)
            time.sleep(0.8)
            websocket.send_json({"type": "ping"})
            pong2 = websocket.receive_json()
            assert pong2["type"] == "pong"

            # Now send observation; connection is still healthy!
            websocket.send_json(observation())
            result = websocket.receive_json()
            assert result["type"] == "detection_result"

from pathlib import Path

import pandas as pd
import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.main import create_app
from app.services.detection_service import (
    DetectionService,
    IncompatibleModelError,
    ModelUnavailableError,
    get_detection_service,
)
from ml.mitigation.engine import MitigationEngine
from ml.o2.config import O2ModelConfig
from ml.o2.train import train_o2_reference_detector
from ml.o3.config import O3ModelConfig
from ml.o3.train import train_o3_reference_classifier


FIXTURE_PATH = Path("data/fixtures/o3_tiny_processed_fixture.csv")


@pytest.fixture
def configured_service(workspace_tmp_path):
    dataset = pd.read_csv(FIXTURE_PATH)
    o2_result = train_o2_reference_detector(
        dataset,
        O2ModelConfig(
            artifact_dir=workspace_tmp_path / "o2",
            random_seed=7,
            n_estimators=10,
            max_depth=4,
        ),
        dataset_reference="api-o3-fixture",
    )
    o3_result = train_o3_reference_classifier(
        dataset,
        O3ModelConfig(
            artifact_dir=workspace_tmp_path / "o3",
            random_seed=7,
            n_estimators=10,
            max_depth=3,
        ),
        dataset_reference="api-o3-fixture",
        fixture_only=True,
    )
    settings = Settings(
        o2_model_path=o2_result.model_path,
        o3_model_path=o3_result.model_path,
        o2_fixture_only=True,
        o3_fixture_only=True,
    )
    return DetectionService(settings), settings


def payload(source="192.0.2.10", features=None, traffic_rate=10.0):
    return {
        "source_identifier": source,
        "traffic_rate": traffic_rate,
        "features": features or {"Flow Duration": 10, "Total Fwd Packets": 1, "Protocol": 6},
    }


def test_valid_benign_request_returns_detection_mitigation_audit_and_latency(configured_service):
    service, _ = configured_service
    response = service.analyze(payload())
    assert response.o2.detected is False
    assert response.o2.label == 0
    assert response.o3.available is False
    assert response.mitigation.decision == "ALLOW"
    assert response.mitigation.simulation_only is True
    assert response.mitigation.audit_event_id
    assert response.latency.total_analysis_ms >= 0
    assert response.latency.o2_inference_ms >= 0
    assert response.artifact_scope["o2_fixture_only"] is True
    assert response.artifact_scope["o3_fixture_only"] is True


def test_attack_request_runs_o3_and_mitigation(configured_service):
    service, _ = configured_service
    response = service.analyze(
        payload(
            source="192.0.2.20",
            features={"Flow Duration": 50, "Total Fwd Packets": 20, "Protocol": 17},
            traffic_rate=2000,
        )
    )
    assert response.o2.detected is True
    assert response.o3.available is True
    assert response.o3.attack_type in {"DRDOS_DNS", "SYN", "TFTP", "BENIGN"}
    assert response.o3.probabilities
    assert response.mitigation.decision in {"BLOCK", "RATE_LIMIT"}
    assert response.mitigation.policy_version == "mitigation-policy-0.1.0"
    assert response.latency.o3_inference_ms >= 0


def test_fastapi_endpoint_returns_schema_and_request_correlation(configured_service):
    service, settings = configured_service
    application = create_app()
    application.dependency_overrides[get_detection_service] = lambda: service
    client = TestClient(application)
    response = client.post("/api/v1/detection/analyze", json=payload())
    assert response.status_code == 200
    body = response.json()
    assert body["request_id"]
    assert body["source_identifier"] == "192.0.2.10"
    assert body["o2"]["detected"] is False
    assert body["mitigation"]["simulation_only"] is True
    assert body["latency"]["measurement_scope"].endswith("not_cyber14_kpi")
    assert client.get("/health").status_code == 200
    assert client.get("/api/system/status").status_code == 200
    assert client.get("/api/v1/system/status").status_code == 200
    assert settings.o2_fixture_only is True


def test_missing_feature_fails_with_validation_error(configured_service):
    service, _ = configured_service
    application = create_app()
    application.dependency_overrides[get_detection_service] = lambda: service
    response = TestClient(application).post(
        "/api/v1/detection/analyze",
        json=payload(features={"Flow Duration": 10, "Total Fwd Packets": 1}),
    )
    assert response.status_code == 422
    assert response.json()["error"] == "http_error"


def test_invalid_numeric_and_source_payloads_fail_with_validation_error(configured_service):
    service, _ = configured_service
    application = create_app()
    application.dependency_overrides[get_detection_service] = lambda: service
    client = TestClient(application)
    invalid_numeric = payload()
    invalid_numeric["features"]["Protocol"] = "six"
    assert client.post("/api/v1/detection/analyze", json=invalid_numeric).status_code == 422
    assert client.post("/api/v1/detection/analyze", json=payload(source=" bad ")).status_code == 422
    assert client.post("/api/v1/detection/analyze", json={"source_identifier": "x"}).status_code == 422


def test_model_unavailable_and_incompatible_model_fail_clearly(tmp_path):
    missing = Settings(
        o2_model_path=tmp_path / "missing-o2.joblib",
        o3_model_path=tmp_path / "missing-o3.joblib",
    )
    with pytest.raises(ModelUnavailableError, match="O2 model artifact"):
        DetectionService(missing)

    incompatible = tmp_path / "incompatible"
    incompatible.mkdir()
    pd.DataFrame({"x": [0, 1], "label_binary": [0, 1]}).to_csv(tmp_path / "input.csv", index=False)
    # A missing model is still reported as unavailable rather than selecting an arbitrary path.
    with pytest.raises(ModelUnavailableError):
        DetectionService(
            Settings(
                o2_model_path=incompatible / "model.joblib",
                o3_model_path=tmp_path / "missing-o3.joblib",
            )
        )


def test_detection_service_reuses_mitigation_engine_audit(configured_service):
    service, _ = configured_service
    assert isinstance(service._mitigation, MitigationEngine)
    service.analyze(payload())
    assert len(service._mitigation.audit.events()) == 1

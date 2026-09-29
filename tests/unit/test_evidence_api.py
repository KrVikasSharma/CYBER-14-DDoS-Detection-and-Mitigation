from fastapi.testclient import TestClient
import json

from app.main import create_app
from app.services.evidence_service import EvidenceService


def complete_official_context(run_dir):
    (run_dir / "evidence.json").write_text("{}", encoding="utf-8")
    result = {
        "run_type": "acceptance",
        "official_cyber14_kpi_result": True,
        "fixture_only": False,
        "configuration_hash": "config-hash",
        "configuration_reference": "acceptance_config.json",
        "input_references": ["dataset.csv"],
        "output_references": ["result.json"],
        "dataset_reference": "CIC-DDoS2019-v1",
    }
    manifest = {
        "run_type": "acceptance",
        "configuration_hash": "config-hash",
        "configuration_reference": "acceptance_config.json",
        "input_references": ["dataset.csv"],
        "output_references": ["result.json"],
        "fixture_only": False,
    }
    return result, manifest


def status_record(tmp_path, record, result_updates=None):
    run_dir = tmp_path / "run"
    run_dir.mkdir(parents=True)
    result, manifest = complete_official_context(run_dir)
    result.update(result_updates or {})
    service = EvidenceService(tmp_path)
    return service._status_record("KPI-1", record, result, manifest, "run", run_dir)


def test_evidence_and_evaluation_endpoints_preserve_fixture_statuses():
    client = TestClient(create_app())
    summary = client.get("/api/v1/evidence/summary")
    assert summary.status_code == 200
    assert summary.json()["state"] in {"FIXTURE_ONLY", "NOT_AVAILABLE", "PARTIAL"}

    kpis = client.get("/api/v1/evaluation/kpis")
    assert kpis.status_code == 200
    records = kpis.json()["records"]
    assert len(records) == 6
    assert all(record["status"] in {"PASS", "FAIL", "NOT_EXECUTED", "BLOCKED", "FIXTURE_ONLY", "EXECUTED_NON_OFFICIAL", "OFFICIAL_INCOMPLETE"} for record in records)
    assert all(record["official_result"] is False for record in records)

    acceptance = client.get("/api/v1/evaluation/acceptance")
    negative = client.get("/api/v1/evaluation/negative-tests")
    assert len(acceptance.json()["records"]) == 4
    assert len(negative.json()["records"]) == 5


def test_evidence_runs_are_safe_and_audit_limit_is_bounded():
    client = TestClient(create_app())
    runs = client.get("/api/v1/evidence/runs")
    assert runs.status_code == 200
    assert all("D:" not in str(run) and "password" not in str(run).lower() for run in runs.json())
    audit = client.get("/api/v1/evidence/audit?limit=1")
    assert audit.status_code == 200
    assert len(audit.json()) <= 1


def test_telemetry_endpoint_returns_process_local_safe_shape():
    client = TestClient(create_app())
    response = client.get("/api/v1/system/telemetry")
    assert response.status_code == 200
    body = response.json()
    assert body["durable_store"] is False
    assert "AUTH_SECRET_KEY" not in str(body)
    assert body["state"] in {"READY", "FIXTURE_ONLY"}


def test_complete_official_pass_remains_pass(tmp_path):
    record = {
        "status": "PASS",
        "official_result": True,
        "evidence": ["evidence.json"],
        "threshold": 0.9,
        "trials": 30,
        "oracle": {"expected": "safe"},
    }
    status = status_record(tmp_path, record)
    assert status.status == "PASS"
    assert status.official_result is True
    assert status.evidence_available is True


def test_incomplete_passes_are_not_authoritative(tmp_path):
    base = {
        "status": "PASS",
        "official_result": True,
        "evidence": ["evidence.json"],
        "threshold": 0.9,
        "trials": 30,
        "oracle": {"expected": "safe"},
    }
    for field in ("threshold", "trials", "oracle", "evidence"):
        record = dict(base)
        record.pop(field)
        status = status_record(tmp_path / field, record)
        assert status.status == "OFFICIAL_INCOMPLETE"
        assert status.official_result is False


def test_fixture_and_non_official_passes_are_distinguished(tmp_path):
    fixture = status_record(
        tmp_path / "fixture",
        {"status": "PASS", "official_result": True, "evidence": ["evidence.json"]},
        {"fixture_only": True},
    )
    non_official = status_record(
        tmp_path / "non-official",
        {"status": "PASS", "official_result": False, "evidence": ["evidence.json"]},
    )
    assert fixture.status == "FIXTURE_ONLY"
    assert non_official.status == "EXECUTED_NON_OFFICIAL"


def test_not_executed_and_blocked_never_become_pass(tmp_path):
    for raw_status in ("NOT_EXECUTED", "BLOCKED"):
        status = status_record(
            tmp_path / raw_status,
            {"status": raw_status, "official_result": True, "evidence": ["evidence.json"]},
        )
        assert status.status == raw_status
        assert status.status != "PASS"


def test_missing_evidence_reference_is_incomplete(tmp_path):
    status = status_record(
        tmp_path,
        {
            "status": "PASS",
            "official_result": True,
            "evidence": ["missing.json"],
            "threshold": 0.9,
            "trials": 30,
            "oracle": {"expected": "safe"},
        },
    )
    assert status.status == "OFFICIAL_INCOMPLETE"
    assert status.evidence_available is False


def test_summary_does_not_call_fixture_statuses_complete(tmp_path):
    run_dir = tmp_path / "evidence" / "acceptance" / "runs" / "run-1"
    run_dir.mkdir(parents=True)
    (run_dir / "result.json").write_text(
        json.dumps({
            "run_id": "run-1",
            "run_type": "acceptance",
            "fixture_only": True,
            "official_cyber14_kpi_result": False,
            "kpis": {f"KPI-{index}": {"status": "NOT_EXECUTED", "fixture_only": True} for index in range(1, 7)},
            "acceptance_conditions": {f"AC-{index}": {"status": "NOT_EXECUTED", "fixture_only": True} for index in range(1, 5)},
        }),
        encoding="utf-8",
    )
    (run_dir / "evidence_manifest.json").write_text(
        json.dumps({"run_id": "run-1", "run_type": "acceptance", "status": "NOT_EXECUTED", "fixture_only": True}),
        encoding="utf-8",
    )
    service = EvidenceService(tmp_path)
    summary = service.summary()
    assert summary.state == "FIXTURE_ONLY"
    assert summary.evidence_complete is False


def test_acceptance_dashboard_endpoint_structure():
    client = TestClient(create_app())
    response = client.get("/api/v1/evidence/acceptance-dashboard")
    assert response.status_code == 200
    data = response.json()
    assert "acceptance_summary" in data
    assert "kpi_status" in data
    assert "acceptance_criteria" in data
    assert "negative_tests" in data
    assert "degraded_mode" in data
    assert "resource_evidence" in data
    assert "evidence_integrity" in data
    assert "limitations" in data

    # Verify summary counts
    summary = data["acceptance_summary"]
    assert summary["total_tests"] == 15
    assert summary["passed"] == 13
    assert summary["failed"] == 0
    assert summary["not_executed"] == 2

    # Verify KPI-2 and AC-3 are NOT_EXECUTED
    kpis = {k["id"]: k for k in data["kpi_status"]}
    assert kpis["KPI-2"]["status"] == "NOT_EXECUTED"
    acs = {a["id"]: a for a in data["acceptance_criteria"]}
    assert acs["AC-3"]["status"] == "NOT_EXECUTED"

    # Verify integrity and secrets
    integrity = data["evidence_integrity"]
    assert integrity["sha256_verification_status"] == "PASS"
    assert integrity["secrets_detected"] == 0
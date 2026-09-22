from pathlib import Path
from copy import deepcopy

import pytest

from ml.evaluation.acceptance import load_config, run_acceptance
from ml.evaluation.comparison import compare_threshold
from ml.evaluation.confusion import multiclass_confusion
from ml.evaluation.evidence import configuration_hash
from ml.evaluation.latency import InsufficientTrialsError, measure_latency
from ml.evaluation.metrics import attack_path_metrics, binary_metrics, percentage_points
from ml.evaluation.negative_tests import run_negative_tests
from ml.evaluation.trials import OracleResult, execute_trials


def test_binary_metrics_and_percentage_points_are_calculated():
    result = binary_metrics([0, 0, 1, 1], [0, 1, 1, 0])
    assert result["accuracy"] == 0.5
    assert result["false_positive_rate"] == 0.5
    assert result["confusion_matrix"] == {
        "true_negative": 1,
        "false_positive": 1,
        "false_negative": 1,
        "true_positive": 1,
    }
    assert percentage_points(0.85, 0.80) == pytest.approx(5.0)


def test_attack_path_and_multiclass_confusion_are_calculated():
    assert attack_path_metrics([0, 1, 1], [0, 1, 0])["detection_rate"] == 0.5
    result = multiclass_confusion(["BENIGN", "SYN"], ["BENIGN", "BENIGN"])
    assert result["matrix"] == [[1, 0], [1, 0]]


def test_latency_reports_percentiles_and_enforces_official_trial_minimum():
    result = measure_latency(lambda: None, 30, official=True)
    assert result["trial_count"] == 30
    assert result["failures"] == 0
    assert result["p95_ms"] >= result["p50_ms"]
    with pytest.raises(InsufficientTrialsError):
        measure_latency(lambda: None, 5, official=True)


def test_latency_records_one_failed_trial_without_using_it_as_a_sample():
    outcomes = iter([False, True, True])

    def operation():
        if not next(outcomes):
            raise RuntimeError("first trial failed")

    result = measure_latency(operation, 3, minimum_successful_trials=2)
    assert result["trial_count"] == 3
    assert result["successful_trials"] == 2
    assert result["failed_trials"] == 1
    assert result["failure_reasons"] == ["RuntimeError: first trial failed"]
    assert len(result["successful_latency_samples"]) == 2
    assert result["status"] == "PASS"


def test_latency_with_multiple_failures_is_not_valid_below_minimum():
    outcomes = iter([False, False, True, True])

    def operation():
        if not next(outcomes):
            raise ValueError("trial failed")

    result = measure_latency(operation, 4, minimum_successful_trials=3)
    assert result["successful_trials"] == 2
    assert result["failed_trials"] == 2
    assert result["status"] == "NOT_EXECUTED"
    assert result["p50_ms"] is None
    assert len(result["failure_reasons"]) == 2


def test_latency_all_trials_failed_has_no_percentiles():
    result = measure_latency(lambda: (_ for _ in ()).throw(RuntimeError("unavailable")), 3)
    assert result["successful_trials"] == 0
    assert result["failed_trials"] == 3
    assert result["status"] == "NOT_EXECUTED"
    assert result["p95_ms"] is None


def test_latency_enforces_minimum_successful_trials():
    result = measure_latency(lambda: None, 2, minimum_successful_trials=3)
    assert result["status"] == "NOT_EXECUTED"
    assert result["successful_trials"] == 2
    assert result["successful_latency_samples"]


def test_latency_is_valid_with_enough_successes_despite_failures():
    outcomes = iter([True, False, True, True])

    def operation():
        if not next(outcomes):
            raise RuntimeError("intermittent failure")

    result = measure_latency(
        operation,
        4,
        official=True,
        minimum_official_trials=4,
        minimum_successful_trials=3,
    )
    assert result["status"] == "PASS"
    assert result["successful_trials"] == 3
    assert result["failed_trials"] == 1
    assert result["p99_ms"] is not None


def test_comparison_requires_supplied_threshold_and_never_invents_status():
    assert compare_threshold(0.9, 0.8, direction="at_least")["status"] == "PASS"
    assert compare_threshold(0.7, 0.8, direction="at_least")["status"] == "FAIL"
    unavailable = compare_threshold(None, None, direction="at_least")
    assert unavailable["status"] == "NOT_EXECUTED"


def test_configuration_hash_is_order_independent():
    assert configuration_hash({"b": 2, "a": 1}) == configuration_hash({"a": 1, "b": 2})


def test_trial_oracle_is_explicit_and_failures_are_not_passes():
    oracle = OracleResult("SYN", True, "BLOCK")
    results = execute_trials(
        [("trial-1", {"value": 1}, oracle), ("trial-2", {"value": 2}, oracle)],
        lambda record: {"attack_type": "SYN", "detected": True, "decision": "BLOCK"},
    )
    assert all(result.status == "PASS" for result in results)
    failed = execute_trials([("trial-fail", {}, oracle)], lambda _: (_ for _ in ()).throw(ValueError("no")))
    assert failed[0].status == "FAIL"
    assert "ValueError: no" in failed[0].error


def test_trial_oracle_mismatch_is_fail_and_preserves_observed_result():
    oracle = OracleResult("SYN", True, "BLOCK")
    observed = {"attack_type": "UDP", "detected": True, "decision": "RATE_LIMIT"}
    results = execute_trials([("trial-mismatch", {}, oracle)], lambda _: observed)
    assert results[0].status == "FAIL"
    assert results[0].observed_record == observed
    assert "expected 'SYN', observed 'UDP'" in results[0].error
    assert "expected 'BLOCK', observed 'RATE_LIMIT'" in results[0].error


def test_trial_oracle_rejects_missing_or_malformed_oracles():
    missing = execute_trials([("trial-missing", {}, None)], lambda _: {"detected": True})
    malformed = execute_trials([("trial-malformed", {}, OracleResult())], lambda _: {"detected": True})
    assert missing[0].status == "FAIL"
    assert "missing or malformed" in missing[0].error
    assert malformed[0].status == "FAIL"
    assert "does not define" in malformed[0].error


def test_trial_oracle_comparison_does_not_mutate_observed_data():
    observed = {"o2": {"detected": True}, "mitigation": {"decision": "BLOCK"}}
    original = deepcopy(observed)
    oracle = OracleResult(expected_binary_attack=True, expected_mitigation="BLOCK")
    result = execute_trials([("trial-immutable", {}, oracle)], lambda _: observed)[0]
    assert result.status == "PASS"
    assert observed == original


def test_fixture_acceptance_is_not_executed_and_writes_evidence(workspace_tmp_path):
    config_path = Path("evidence/acceptance/acceptance_config.json")
    result = run_acceptance(
        load_config(config_path),
        fixture_only=True,
        output_root=workspace_tmp_path / "acceptance",
    )
    assert result["fixture_only"] is True
    assert result["official_cyber14_kpi_result"] is False
    assert all(item["status"] == "NOT_EXECUTED" for item in result["kpis"].values())
    run_dir = workspace_tmp_path / "acceptance" / result["run_id"]
    assert (run_dir / "result.json").exists()
    assert (run_dir / "metrics.json").exists()
    assert (run_dir / "environment.json").exists()
    assert (run_dir / "evidence_manifest.json").exists()


def test_negative_tests_are_blocked_without_official_environment(workspace_tmp_path):
    config = load_config(Path("evidence/acceptance/acceptance_config.json"))
    result = run_negative_tests(
        config,
        fixture_only=True,
        output_root=workspace_tmp_path / "negative",
    )
    assert result["status"] == "BLOCKED"
    assert set(result["tests"]) == {"NT-1", "NT-2", "NT-3", "NT-4", "NT-5"}
    assert all(item["status"] == "BLOCKED" for item in result["tests"].values())

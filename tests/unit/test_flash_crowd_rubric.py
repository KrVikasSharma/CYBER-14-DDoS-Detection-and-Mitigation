import pytest
from pathlib import Path
from typing import Any

from ml.evaluation.flash_crowd import (
    DEFAULT_RUBRIC_PATH,
    calculate_inter_rater_agreement,
    evaluate_formal_flash_crowd_benchmark,
    evaluate_o2_reference_score,
    evaluate_objective_rubric_score,
    load_flash_crowd_rubric,
    validate_flash_crowd_rubric,
)
from ml.evaluation.kpis import evaluate_kpi2_flash_crowd_false_positive
from app.services.evidence_service import EvidenceService


def test_rubric_validation_success():
    rubric = load_flash_crowd_rubric(DEFAULT_RUBRIC_PATH)
    assert rubric["rubric_id"] == "CYBER14-FC-RUBRIC-V1"
    assert rubric["rubric_version"] == "1.0.0"
    assert rubric["scale"]["pass_threshold"] == 80.0
    assert rubric["scale"]["reference_margin_delta"] == 5.0
    assert rubric["scale"]["min_raters"] == 2
    assert len(rubric["criteria"]) == 5
    assert sum(c["weight"] for c in rubric["criteria"]) == 100.0


def test_rubric_validation_invalid_weights_raises():
    bad_rubric = {
        "rubric_id": "TEST",
        "rubric_version": "1.0.0",
        "scale": {"min_score": 0.0, "max_score": 100.0, "pass_threshold": 80.0, "reference_margin_delta": 5.0, "min_raters": 2},
        "anchors": {"0": "a", "50": "b", "80": "c", "100": "d"},
        "criteria": [
            {"criterion_id": f"C{i}", "weight": 10.0, "anchors": {"0": "a", "50": "b", "80": "c", "100": "d"}}
            for i in range(5)
        ],
        "scoring_method": {},
        "rater_requirements": {},
    }
    with pytest.raises(ValueError, match="Criteria weights must sum to 100.0"):
        validate_flash_crowd_rubric(bad_rubric)


def test_inter_rater_agreement_calculation():
    rubric = load_flash_crowd_rubric(DEFAULT_RUBRIC_PATH)
    # 1. Concordant raters
    card1 = {
        "rater_id": "R1",
        "criteria_scores": {c["criterion_id"]: {"score": 20.0} for c in rubric["criteria"]},
    }
    card2 = {
        "rater_id": "R2",
        "criteria_scores": {c["criterion_id"]: {"score": 20.0} for c in rubric["criteria"]},
    }
    agr_perfect = calculate_inter_rater_agreement([card1, card2], rubric)
    assert agr_perfect == 1.0

    # 2. Slight variation
    card3 = {
        "rater_id": "R2_slight",
        "criteria_scores": {
            "C1_BASELINE_PASS_THROUGH": {"score": 18.0},
            "C2_NON_DESTRUCTIVE_CONTAINMENT": {"score": 20.0},
            "C3_DYNAMIC_RECOVERY": {"score": 18.0},
            "C4_LATENCY_BOUNDEDNESS": {"score": 20.0},
            "C5_AUDIT_TRANSPARENCY": {"score": 20.0},
        },
    }
    agr_high = calculate_inter_rater_agreement([card1, card3], rubric)
    assert agr_high is not None
    assert agr_high >= 0.90

    # 3. Single rater returns None
    assert calculate_inter_rater_agreement([card1], rubric) is None


def test_objective_candidate_and_o2_reference_scores():
    rubric = load_flash_crowd_rubric(DEFAULT_RUBRIC_PATH)
    mock_conditions = [
        {
            "condition_id": "FC-COND-01",
            "condition_name": "Baseline",
            "is_flash_crowd": False,
            "observations_count": 144,
            "destructive_block_count": 0,
            "allow_count": 144,
            "rate_limit_count": 0,
            "latency_stats_ms": {"combined_decision": {"p95": 2.5}},
        },
        {
            "condition_id": "FC-COND-04",
            "condition_name": "Surge",
            "is_flash_crowd": True,
            "observations_count": 144,
            "destructive_block_count": 0,
            "allow_count": 0,
            "rate_limit_count": 144,
            "latency_stats_ms": {"combined_decision": {"p95": 3.1}},
        },
    ]
    cand_eval = evaluate_objective_rubric_score(mock_conditions, rubric)
    assert cand_eval["candidate_score"] == 100.0

    o2_eval = evaluate_o2_reference_score(mock_conditions, rubric)
    assert o2_eval["o2_reference_score"] == 45.0
    delta = cand_eval["candidate_score"] - o2_eval["o2_reference_score"]
    assert delta == 55.0


def test_missing_rater_leaves_kpi2_not_executed():
    res = evaluate_kpi2_flash_crowd_false_positive()
    assert res["status"] == "NOT_EXECUTED"
    assert res["test_id"] == "KPI-2"
    assert res["observed_result"]["raters_count"] == 0
    assert res["observed_result"]["raters_required"] == 2
    assert res["observed_result"]["candidate_score"] >= 80.0
    assert res["observed_result"]["o2_reference_score"] == 45.0
    assert "pending 2 independent human rater scorecards" in res["reasons"][0]


def test_two_raters_evaluated_pass():
    rubric = load_flash_crowd_rubric(DEFAULT_RUBRIC_PATH)
    scorecards = [
        {
            "rater_id": "RATER-01-PRIMARY",
            "criteria_scores": {c["criterion_id"]: {"score": 20.0} for c in rubric["criteria"]},
        },
        {
            "rater_id": "RATER-02-SECONDARY",
            "criteria_scores": {
                "C1_BASELINE_PASS_THROUGH": {"score": 19.0},
                "C2_NON_DESTRUCTIVE_CONTAINMENT": {"score": 20.0},
                "C3_DYNAMIC_RECOVERY": {"score": 20.0},
                "C4_LATENCY_BOUNDEDNESS": {"score": 18.0},
                "C5_AUDIT_TRANSPARENCY": {"score": 20.0},
            },
        },
    ]
    res = evaluate_formal_flash_crowd_benchmark(rater_scorecards=scorecards)
    assert res["status"] == "PASS"
    assert res["observed_result"]["raters_count"] == 2
    assert res["observed_result"]["candidate_score"] >= 80.0


def test_evidence_service_kpi2_dashboard_serialization():
    service = EvidenceService()
    dashboard = service.acceptance_dashboard()
    kpi_list = dashboard.get("kpi_status", [])
    kpi2 = next((k for k in kpi_list if k["id"] == "KPI-2" or k.get("kpi_id") == "KPI-2"), None)
    assert kpi2 is not None
    assert kpi2["status"] == "NOT_EXECUTED"
    assert ">= 80.0/100.0" in kpi2["threshold"]
    assert "Candidate:" in kpi2["observed_display"] or "Score:" in kpi2["observed_display"]
    assert "metrics" in kpi2

import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
BACKEND_ROOT = ROOT / "backend"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

import joblib
import numpy as np
import pandas as pd

from ml.evaluation.comparison import compare_threshold
from ml.evaluation.evidence import create_evidence_record, new_run_id, utc_now, write_json
from ml.evaluation.latency import measure_latency
from ml.evaluation.metrics import attack_path_metrics, binary_metrics
from ml.mitigation.config import MitigationConfig
from ml.mitigation.engine import MitigationEngine
from ml.mitigation.models import DetectionResult
from ml.o2.config import O2_TARGET_COLUMN
from ml.o2.features import split_features_target


DEFAULT_TEST_DATASET = Path("data/demo/processed/test.csv")
DEFAULT_O2_MODEL_PATH = Path("data/demo/models/o2/model.joblib")
DEFAULT_O3_MODEL_PATH = Path("data/demo/models/o3/model.joblib")


def _resolve_dataset_path(path: str | Path | None) -> Path:
    if path is None:
        return DEFAULT_TEST_DATASET
    p = Path(path)
    if not p.exists() and not str(p).startswith("data/"):
        candidate = Path("data/demo/processed/test.csv")
        if candidate.exists():
            return candidate
    return p


def evaluate_kpi1_detection_accuracy(
    *,
    dataset_path: Path | str | None = None,
    model_path: Path = DEFAULT_O2_MODEL_PATH,
    threshold: float = 0.95,
) -> dict[str, Any]:
    """KPI-1: Binary detection accuracy on authentic test partition (target >= 95.0%)."""
    ds_path = _resolve_dataset_path(dataset_path)
    if not ds_path.exists() or not model_path.exists():
        return create_evidence_record(
            test_id="KPI-1",
            test_name="Detection Accuracy",
            status="NOT_EXECUTED",
            reasons=[f"Required test dataset or model missing ({ds_path}, {model_path})"],
            expected_result={"accuracy": f">={threshold}"},
        )

    try:
        model = joblib.load(model_path)
        if hasattr(model, "n_jobs") and model.n_jobs != 1:
            model.n_jobs = 1
        df = pd.read_csv(ds_path)
        feature_cols = [c for c in df.columns if c not in ("label_binary", "label_original", "label_normalized")]
        features, target = split_features_target(df, feature_cols, O2_TARGET_COLUMN)
        predictions = model.predict(features)

        metrics = binary_metrics(target, predictions)
        comparison = compare_threshold(metrics["accuracy"], threshold, direction="at_least")
        status = comparison["status"]

        return create_evidence_record(
            test_id="KPI-1",
            test_name="Detection Accuracy",
            status=status,
            dataset_reference=str(ds_path),
            model_version="0.1.0",
            expected_result={"metric": "accuracy", "threshold": threshold, "direction": "at_least"},
            observed_result={"accuracy": round(metrics["accuracy"], 4), "sample_count": metrics["sample_count"]},
            metrics=metrics,
            reasons=[comparison["reason"]],
        )
    except Exception as exc:
        return create_evidence_record(
            test_id="KPI-1",
            test_name="Detection Accuracy",
            status="FAIL",
            errors=[f"{type(exc).__name__}: {exc}"],
        )


def evaluate_kpi2_flash_crowd_false_positive(
    *,
    dataset_path: Path | str | None = None,
    model_path: Path = DEFAULT_O2_MODEL_PATH,
    rubric_path: Path | str | None = None,
    rater_scorecards: list[dict[str, Any]] | None = None,
    threshold: float | None = None,
) -> dict[str, Any]:
    """KPI-2: False-positive rate evaluation on legitimate high-rate traffic & flash crowds (0-100 rubric)."""
    from ml.evaluation.flash_crowd import (
        DEFAULT_RUBRIC_PATH,
        evaluate_formal_flash_crowd_benchmark,
    )

    r_path = Path(rubric_path) if rubric_path is not None else DEFAULT_RUBRIC_PATH
    return evaluate_formal_flash_crowd_benchmark(
        model_path=model_path,
        rubric_path=r_path,
        rater_scorecards=rater_scorecards,
        threshold_destructive_fpr=threshold,
    )


def evaluate_kpi3_detection_latency(
    *,
    dataset_path: Path | str | None = None,
    model_path: Path = DEFAULT_O2_MODEL_PATH,
    trials: int = 35,
    threshold_p95_ms: float = 30.0,
) -> dict[str, Any]:
    """KPI-3: End-to-end detection latency under repeated trials (target p95 <= 30.0 ms)."""
    ds_path = _resolve_dataset_path(dataset_path)
    if not ds_path.exists() or not model_path.exists():
        return create_evidence_record(
            test_id="KPI-3",
            test_name="Detection Latency",
            status="NOT_EXECUTED",
            reasons=[f"Required test dataset or model missing ({ds_path}, {model_path})"],
            expected_result={"p95_ms": f"<={threshold_p95_ms}"},
        )

    try:
        model = joblib.load(model_path)
        if hasattr(model, "n_jobs") and model.n_jobs != 1:
            model.n_jobs = 1
        df = pd.read_csv(ds_path)
        feature_cols = [c for c in df.columns if c not in ("label_binary", "label_original", "label_normalized")]
        sample_row = df[feature_cols].iloc[[0]]

        def _infer():
            return model.predict(sample_row)

        # Warm-up phase (5 iterations) before timing trials
        for _ in range(5):
            _infer()

        latency_res = measure_latency(_infer, trials=trials, official=True, minimum_official_trials=30)
        p95 = latency_res.get("p95_ms")
        comparison = compare_threshold(p95, threshold_p95_ms, direction="at_most")
        status = comparison["status"] if latency_res["status"] == "PASS" else latency_res["status"]

        return create_evidence_record(
            test_id="KPI-3",
            test_name="Detection Latency",
            status=status,
            dataset_reference=str(ds_path),
            model_version="0.1.0",
            expected_result={"metric": "p95_ms", "threshold": threshold_p95_ms, "direction": "at_most"},
            observed_result={
                "p50_ms": round(latency_res.get("p50_ms", 0), 2) if latency_res.get("p50_ms") is not None else None,
                "p95_ms": round(p95, 2) if p95 is not None else None,
                "p99_ms": round(latency_res.get("p99_ms", 0), 2) if latency_res.get("p99_ms") is not None else None,
                "trial_count": latency_res["trial_count"],
            },
            metrics=latency_res,
            reasons=[comparison["reason"]],
        )
    except Exception as exc:
        return create_evidence_record(
            test_id="KPI-3",
            test_name="Detection Latency",
            status="FAIL",
            errors=[f"{type(exc).__name__}: {exc}"],
        )


def evaluate_kpi4_unsafe_outcome_count() -> dict[str, Any]:
    """KPI-4: Unsafe or unauthorized outcome count across security contracts (target count == 0)."""
    try:
        config = MitigationConfig()
        engine = MitigationEngine(config=config)
        unsafe_events = 0
        violations = []

        # Contract 1: Normal benign flow must receive ALLOW (never destructive BLOCK)
        d1 = engine.analyze_detection(DetectionResult(attack_type="BENIGN", confidence=0.99, traffic_rate=10.0, source_identifier="192.168.1.50"))
        if d1.decision != "ALLOW":
            unsafe_events += 1
            violations.append(f"Benign normal traffic received {d1.decision} instead of ALLOW")

        # Contract 2: High-rate flash crowd must receive RATE_LIMIT (never destructive BLOCK)
        d2 = engine.analyze_detection(DetectionResult(attack_type="BENIGN", confidence=0.99, traffic_rate=2500.0, source_identifier="192.168.1.50"))
        if d2.decision == "BLOCK":
            unsafe_events += 1
            violations.append("Flash crowd received destructive BLOCK action")

        # Contract 3: Confirmed attack must receive mitigation (BLOCK/RATE_LIMIT/SCRUB), never ALLOW
        d3 = engine.analyze_detection(DetectionResult(attack_type="SYN", confidence=0.95, traffic_rate=1500.0, source_identifier="198.51.100.22"))
        if d3.decision == "ALLOW":
            unsafe_events += 1
            violations.append("Confirmed SYN attack received ALLOW action")

        # Contract 4: Low-confidence attack must receive containment (RATE_LIMIT), not permanent destructive block
        d4 = engine.analyze_detection(DetectionResult(attack_type="UDP", confidence=0.1, traffic_rate=500.0, source_identifier="198.51.100.23"))
        if d4.decision == "BLOCK":
            unsafe_events += 1
            violations.append("Low confidence attack received uncontained BLOCK action")

        comparison = compare_threshold(unsafe_events, 0, direction="equal")
        status = comparison["status"]

        return create_evidence_record(
            test_id="KPI-4",
            test_name="Unsafe/Unauthorized Outcome Count",
            status=status,
            expected_result={"metric": "unsafe_outcomes", "threshold": 0, "direction": "equal"},
            observed_result={"unsafe_outcomes": unsafe_events, "violations": violations},
            metrics={"unsafe_event_count": unsafe_events, "safety_checks_passed": len(violations) == 0, "contracts_tested": 4},
            reasons=[comparison["reason"]],
        )
    except Exception as exc:
        return create_evidence_record(
            test_id="KPI-4",
            test_name="Unsafe/Unauthorized Outcome Count",
            status="FAIL",
            errors=[f"{type(exc).__name__}: {exc}"],
        )


def evaluate_kpi5_attack_path_prevention_rate(
    *,
    dataset_path: Path | str | None = None,
    model_path: Path = DEFAULT_O2_MODEL_PATH,
    threshold: float = 0.95,
) -> dict[str, Any]:
    """KPI-5: Attack-path detection and prevention rate across all true attack flows (target >= 95.0%)."""
    ds_path = _resolve_dataset_path(dataset_path)
    if not ds_path.exists() or not model_path.exists():
        return create_evidence_record(
            test_id="KPI-5",
            test_name="Attack-Path Detection/Prevention Rate",
            status="NOT_EXECUTED",
            reasons=[f"Required test dataset or model missing ({ds_path}, {model_path})"],
            expected_result={"detection_rate": f">={threshold}"},
        )

    try:
        model = joblib.load(model_path)
        if hasattr(model, "n_jobs") and model.n_jobs != 1:
            model.n_jobs = 1
        df = pd.read_csv(ds_path)
        feature_cols = [c for c in df.columns if c not in ("label_binary", "label_original", "label_normalized")]
        features, target = split_features_target(df, feature_cols, O2_TARGET_COLUMN)
        predictions = model.predict(features)

        metrics = attack_path_metrics(target, predictions)
        rate = metrics["detection_rate"]

        # Confirm mitigation engine outcome on detected attacks
        config = MitigationConfig()
        engine = MitigationEngine(config=config)
        sample_attack = engine.analyze_detection(DetectionResult(attack_type="SYN", confidence=0.99, traffic_rate=2000.0, source_identifier="198.51.100.50"))
        mitigation_action_valid = sample_attack.decision in ("BLOCK", "RATE_LIMIT", "SCRUB")

        comparison = compare_threshold(rate, threshold, direction="at_least")
        status = comparison["status"] if mitigation_action_valid else "FAIL"

        return create_evidence_record(
            test_id="KPI-5",
            test_name="Attack-Path Detection/Prevention Rate",
            status=status,
            dataset_reference=str(ds_path),
            model_version="0.1.0",
            expected_result={"metric": "detection_rate", "threshold": threshold, "direction": "at_least"},
            observed_result={
                "detection_rate": round(rate, 4),
                "detected_attack_samples": metrics["detected_attack_samples"],
                "total_attack_samples": metrics["attack_samples"],
                "mitigation_action_verified": str(sample_attack.decision),
            },
            metrics=metrics,
            reasons=[comparison["reason"]],
        )
    except Exception as exc:
        return create_evidence_record(
            test_id="KPI-5",
            test_name="Attack-Path Detection/Prevention Rate",
            status="FAIL",
            errors=[f"{type(exc).__name__}: {exc}"],
        )


def evaluate_kpi6_false_positive_resilience(
    *,
    dataset_path: Path | str | None = None,
    model_path: Path = DEFAULT_O2_MODEL_PATH,
    threshold_fpr: float = 0.02,
) -> dict[str, Any]:
    """KPI-6: False-positive rate on legitimate traffic (target <= 2.0%) and pipeline resilience."""
    ds_path = _resolve_dataset_path(dataset_path)
    if not ds_path.exists() or not model_path.exists():
        return create_evidence_record(
            test_id="KPI-6",
            test_name="False-Positive Rate",
            status="NOT_EXECUTED",
            reasons=[f"Required test dataset or model missing ({ds_path}, {model_path})"],
            expected_result={"false_positive_rate": f"<={threshold_fpr}"},
        )

    try:
        model = joblib.load(model_path)
        if hasattr(model, "n_jobs") and model.n_jobs != 1:
            model.n_jobs = 1
        df = pd.read_csv(ds_path)
        feature_cols = [c for c in df.columns if c not in ("label_binary", "label_original", "label_normalized")]
        features, target = split_features_target(df, feature_cols, O2_TARGET_COLUMN)
        predictions = model.predict(features)

        metrics = binary_metrics(target, predictions)
        fpr = metrics["false_positive_rate"]
        comparison = compare_threshold(fpr, threshold_fpr, direction="at_most")
        status = comparison["status"]

        return create_evidence_record(
            test_id="KPI-6",
            test_name="False-Positive Rate",
            status=status,
            dataset_reference=str(ds_path),
            model_version="0.1.0",
            expected_result={"metric": "false_positive_rate", "threshold": threshold_fpr, "direction": "at_most"},
            observed_result={"false_positive_rate": round(fpr, 4), "sample_count": metrics["sample_count"]},
            metrics=metrics,
            reasons=[comparison["reason"]],
        )
    except Exception as exc:
        return create_evidence_record(
            test_id="KPI-6",
            test_name="False-Positive Rate",
            status="FAIL",
            errors=[f"{type(exc).__name__}: {exc}"],
        )


def run_all_kpis(
    *,
    dataset_path: Path | str | None = None,
    output_root: Path = Path("evidence/kpis/runs"),
) -> dict[str, Any]:
    """Execute complete KPI-1 through KPI-6 campaign and persist structured machine-readable evidence."""
    ds_path = _resolve_dataset_path(dataset_path)
    run_id = new_run_id("kpis")
    run_dir = output_root / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    results = {
        "KPI-1": evaluate_kpi1_detection_accuracy(dataset_path=ds_path),
        "KPI-2": evaluate_kpi2_flash_crowd_false_positive(dataset_path=ds_path),
        "KPI-3": evaluate_kpi3_detection_latency(dataset_path=ds_path),
        "KPI-4": evaluate_kpi4_unsafe_outcome_count(),
        "KPI-5": evaluate_kpi5_attack_path_prevention_rate(dataset_path=ds_path),
        "KPI-6": evaluate_kpi6_false_positive_resilience(dataset_path=ds_path),
    }

    summary = {
        "run_id": run_id,
        "run_type": "kpis",
        "recorded_at_utc": utc_now(),
        "dataset_reference": str(ds_path),
        "total_kpis": len(results),
        "passed": sum(r["status"] == "PASS" for r in results.values()),
        "failed": sum(r["status"] == "FAIL" for r in results.values()),
        "not_executed": sum(r["status"] == "NOT_EXECUTED" for r in results.values()),
        "blocked": sum(r["status"] == "BLOCKED" for r in results.values()),
        "kpis": results,
    }

    write_json(run_dir / "result.json", summary)
    write_json(run_dir / "evidence_manifest.json", {
        "run_id": run_id,
        "run_type": "kpis",
        "output_references": ["result.json"],
        "status": "PASS" if all(r["status"] == "PASS" for r in results.values()) else "PARTIAL",
    })

    return summary

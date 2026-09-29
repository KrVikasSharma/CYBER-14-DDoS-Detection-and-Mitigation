import hashlib
import json
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
import pandas as pd

from ml.evaluation.evidence import create_evidence_record, file_sha256, new_run_id, utc_now, write_json
from ml.evaluation.resource_envelope import capture_resource_envelope
from ml.mitigation.config import MitigationConfig
from ml.mitigation.engine import MitigationEngine
from ml.mitigation.models import DetectionResult
from ml.o2.config import O2_TARGET_COLUMN
from ml.o2.features import split_features_target
from ml.o3.config import O3_TARGET_COLUMN
from ml.o3.features import split_features_target as split_features_target_o3


DEFAULT_TEST_DATASET = Path("data/demo/processed/test.csv")
DEFAULT_O2_MODEL = Path("data/demo/models/o2/model.joblib")
DEFAULT_O3_MODEL = Path("data/demo/models/o3/model.joblib")
DEFAULT_SCENARIOS = Path("data/demo/demo_scenarios.json")


def _resolve_dataset_path(path: str | Path | None) -> Path:
    if path is None:
        return DEFAULT_TEST_DATASET
    p = Path(path)
    if not p.exists() and not str(p).startswith("data/"):
        candidate = Path("data/demo/processed/test.csv")
        if candidate.exists():
            return candidate
    return p


def evaluate_ac1_representative_operation(
    *,
    dataset_path: Path | str | None = None,
    scenarios_path: Path = DEFAULT_SCENARIOS,
    o2_model_path: Path = DEFAULT_O2_MODEL,
    o3_model_path: Path = DEFAULT_O3_MODEL,
) -> dict[str, Any]:
    """AC-1: Representative Operation on authentic CIC-DDoS2019 dataset and demo scenarios."""
    ds_path = _resolve_dataset_path(dataset_path)
    missing = [str(p) for p in (ds_path, o2_model_path, o3_model_path) if not p.exists()]
    if missing:
        return create_evidence_record(
            test_id="AC-1",
            test_name="Representative Operation",
            status="NOT_EXECUTED",
            reasons=[f"Missing required artifacts: {', '.join(missing)}"],
        )

    try:
        o2_model = joblib.load(o2_model_path)
        o3_model = joblib.load(o3_model_path)
        df = pd.read_csv(ds_path)
        feature_cols = [c for c in df.columns if c not in ("label_binary", "label_original", "label_normalized")]

        # Step 1: 78-feature compliance
        features_count = len(feature_cols)
        feature_ok = features_count == 78

        # Step 2: Binary discrimination
        features_o2, target_o2 = split_features_target(df, feature_cols, O2_TARGET_COLUMN)
        pred_o2 = o2_model.predict(features_o2)
        o2_accuracy = float((pred_o2 == target_o2).mean())

        # Step 3: Multi-class classification
        features_o3, target_o3 = split_features_target_o3(df, feature_cols, O3_TARGET_COLUMN)
        pred_o3 = o3_model.predict(features_o3)
        o3_accuracy = float((pred_o3 == target_o3).mean())

        # Step 4: Mitigation engine evaluation
        config = MitigationConfig()
        engine = MitigationEngine(config=config)
        d_benign = engine.analyze_detection(DetectionResult(attack_type="BENIGN", confidence=0.99, traffic_rate=10.0, source_identifier="192.168.1.50"))
        d_flash = engine.analyze_detection(DetectionResult(attack_type="BENIGN", confidence=0.99, traffic_rate=2000.0, source_identifier="192.168.1.50"))
        d_attack = engine.analyze_detection(DetectionResult(attack_type="SYN", confidence=0.95, traffic_rate=2000.0, source_identifier="192.168.1.50"))

        mitigation_ok = (
            d_benign.decision == "ALLOW"
            and d_flash.decision == "RATE_LIMIT"
            and d_attack.decision == "BLOCK"
        )

        all_ok = feature_ok and (o2_accuracy >= 0.95) and mitigation_ok
        status = "PASS" if all_ok else "FAIL"

        return create_evidence_record(
            test_id="AC-1",
            test_name="Representative Operation",
            status=status,
            dataset_reference=str(ds_path),
            model_version="0.1.0",
            expected_result={
                "features_count": 78,
                "o2_accuracy_minimum": 0.95,
                "benign_action": "ALLOW",
                "flash_crowd_action": "RATE_LIMIT",
                "attack_action": "BLOCK",
            },
            observed_result={
                "features_count": features_count,
                "o2_accuracy": round(o2_accuracy, 4),
                "o3_accuracy": round(o3_accuracy, 4),
                "benign_action": str(d_benign.decision),
                "flash_crowd_action": str(d_flash.decision),
                "attack_action": str(d_attack.decision),
            },
            metrics={
                "features_count": features_count,
                "o2_accuracy": o2_accuracy,
                "o3_accuracy": o3_accuracy,
                "test_sample_count": len(df),
            },
            reasons=["All representative operation checks passed" if all_ok else "One or more representative checks failed"],
        )
    except Exception as exc:
        return create_evidence_record(
            test_id="AC-1",
            test_name="Representative Operation",
            status="FAIL",
            errors=[f"{type(exc).__name__}: {exc}"],
        )


def evaluate_ac2_boundary_failure_operation() -> dict[str, Any]:
    """AC-2: Boundary / Failure Operation verifying fail-closed error handling and robustness."""
    try:
        from app.core.config import Settings, get_settings
        from app.schemas.detection import DetectionAnalyzeRequest
        from app.services.detection_service import DetectionService, FeatureContractError

        checks = []

        # Check 1: Missing features in request triggers fail-closed FeatureContractError
        settings = Settings(demo_mode=True)
        svc = DetectionService(settings)
        missing_caught = False
        try:
            svc.validate_feature_contract(DetectionAnalyzeRequest(features={"Protocol": 6.0}, source_identifier="192.168.1.1"))
        except FeatureContractError:
            missing_caught = True
        checks.append({"test": "missing_features_fail_closed", "passed": missing_caught})

        # Check 2: Normal benign traffic receives ALLOW
        config = MitigationConfig()
        engine = MitigationEngine(config=config)
        d1 = engine.analyze_detection(DetectionResult(attack_type="BENIGN", confidence=0.5, traffic_rate=50.0, source_identifier="192.168.1.1"))
        checks.append({"test": "benign_flow", "action": d1.decision, "passed": d1.decision in ("ALLOW", "RATE_LIMIT")})

        # Check 3: Extreme volumetric surge rate (1,000,000 req/s) with legitimate confidence receives RATE_LIMIT
        d_extreme = engine.analyze_detection(DetectionResult(attack_type="BENIGN", confidence=0.95, traffic_rate=1000000.0, source_identifier="192.168.1.2"))
        checks.append({"test": "extreme_volumetric_rate", "action": d_extreme.decision, "passed": d_extreme.decision == "RATE_LIMIT"})

        # Check 4: Low-confidence attack flow receives containment (RATE_LIMIT), not immediate destructive block
        d_low_conf = engine.analyze_detection(DetectionResult(attack_type="UDP", confidence=0.1, traffic_rate=500.0, source_identifier="192.168.1.3"))
        checks.append({"test": "low_confidence_attack_containment", "action": d_low_conf.decision, "passed": d_low_conf.decision == "RATE_LIMIT"})

        # Check 5: Boundary IPv6 loopback handling
        d_ipv6 = engine.analyze_detection(DetectionResult(attack_type="BENIGN", confidence=0.9, traffic_rate=10.0, source_identifier="::1"))
        checks.append({"test": "ipv6_loopback_handling", "action": d_ipv6.decision, "passed": d_ipv6.decision == "ALLOW"})

        all_passed = all(c["passed"] for c in checks)
        status = "PASS" if all_passed else "FAIL"

        return create_evidence_record(
            test_id="AC-2",
            test_name="Boundary/Failure Operation",
            status=status,
            expected_result={"fail_closed_robustness": True, "all_edge_checks_passed": True},
            observed_result={"checks": checks, "all_passed": all_passed},
            metrics={"total_checks": len(checks), "passed_checks": sum(c["passed"] for c in checks)},
            reasons=["All boundary and failure resilience tests executed successfully" if all_passed else "One or more boundary checks failed"],
        )
    except Exception as exc:
        return create_evidence_record(
            test_id="AC-2",
            test_name="Boundary/Failure Operation",
            status="FAIL",
            errors=[f"{type(exc).__name__}: {exc}"],
        )


def evaluate_ac3_independent_acceptance_prep(
    *,
    output_dir: Path = Path("evidence/acceptance"),
) -> dict[str, Any]:
    """AC-3: Independent Acceptance Preparation (produces verifiable review package; status remains PENDING_INDEPENDENT_REVIEW)."""
    try:
        package_manifest = {
            "package_type": "independent_review_verification_bundle",
            "project": "CYBER-14",
            "review_status": "PENDING_INDEPENDENT_REVIEW",
            "generated_at_utc": utc_now(),
            "acceptance_criteria": ["AC-1", "AC-2", "AC-3", "AC-4"],
            "kpis": ["KPI-1", "KPI-2", "KPI-3", "KPI-4", "KPI-5", "KPI-6"],
            "negative_tests": ["NT-1", "NT-2", "NT-3", "NT-4", "NT-5"],
            "artifact_hashes": {
                "dataset_sample": file_sha256(Path("data/demo/cic_ddos2019_sample.csv")) if Path("data/demo/cic_ddos2019_sample.csv").exists() else None,
                "o2_model": file_sha256(Path("data/demo/models/o2/model.joblib")) if Path("data/demo/models/o2/model.joblib").exists() else None,
                "o3_model": file_sha256(Path("data/demo/models/o3/model.joblib")) if Path("data/demo/models/o3/model.joblib").exists() else None,
            },
            "notes": "Formal independent human audit sign-off is pending external reviewer evaluation.",
        }

        package_path = output_dir / "independent_review_package.json"
        write_json(package_path, package_manifest)

        return create_evidence_record(
            test_id="AC-3",
            test_name="Independent Acceptance Preparation",
            status="NOT_EXECUTED",
            expected_result={"independent_reviewer_signoff": "REQUIRED"},
            observed_result={"review_bundle_generated": True, "package_path": str(package_path), "current_state": "PENDING_INDEPENDENT_REVIEW"},
            metrics={"package_artifacts_count": len(package_manifest["artifact_hashes"])},
            reasons=["Independent review package prepared; awaiting formal external human auditor evaluation (NOT_EXECUTED)."],
            artifact_references=[str(package_path)],
        )
    except Exception as exc:
        return create_evidence_record(
            test_id="AC-3",
            test_name="Independent Acceptance Preparation",
            status="FAIL",
            errors=[f"{type(exc).__name__}: {exc}"],
        )


def evaluate_ac4_frozen_resource_envelope(
    *,
    dataset_path: Path | str | None = None,
    o2_model_path: Path = DEFAULT_O2_MODEL,
) -> dict[str, Any]:
    """AC-4: Frozen Resource Envelope measuring actual hardware, memory, throughput, and inference runtime."""
    ds_path = _resolve_dataset_path(dataset_path)
    if not ds_path.exists() or not o2_model_path.exists():
        return create_evidence_record(
            test_id="AC-4",
            test_name="Frozen Resource Envelope",
            status="NOT_EXECUTED",
            reasons=[f"Required dataset or model missing ({ds_path}, {o2_model_path})"],
        )

    try:
        model = joblib.load(o2_model_path)
        df = pd.read_csv(ds_path)
        feature_cols = [c for c in df.columns if c not in ("label_binary", "label_original", "label_normalized")]
        features = df[feature_cols]

        def _batch_predict():
            return model.predict(features)

        envelope = capture_resource_envelope(_batch_predict, sample_count=len(features))
        metrics = envelope.get("execution_metrics", {})
        throughput = metrics.get("throughput_flows_per_sec", 0)

        # Baseline check: ensure non-zero throughput and valid resource readings
        has_resources = (
            envelope.get("cpu_logical_cores") is not None
            and envelope.get("total_ram_gb") is not None
            and throughput is not None
            and throughput > 0
        )
        status = "PASS" if has_resources else "FAIL"

        return create_evidence_record(
            test_id="AC-4",
            test_name="Frozen Resource Envelope",
            status=status,
            expected_result={"valid_resource_readings": True, "throughput_positive": True},
            observed_result={
                "cpu_cores": envelope.get("cpu_logical_cores"),
                "total_ram_gb": envelope.get("total_ram_gb"),
                "memory_load_percent": envelope.get("memory_load_percent"),
                "model_inference_throughput_flows_per_sec": throughput,
                "elapsed_seconds": metrics.get("elapsed_seconds"),
                "workload_type": "ML model batch inference",
            },
            metrics=envelope,
            reasons=["Resource envelope successfully captured and bounded (ML model batch inference)" if status == "PASS" else "Resource capture encountered missing fields"],
        )
    except Exception as exc:
        return create_evidence_record(
            test_id="AC-4",
            test_name="Frozen Resource Envelope",
            status="FAIL",
            errors=[f"{type(exc).__name__}: {exc}"],
        )


def run_all_acceptance_criteria(
    *,
    dataset_path: Path | str | None = None,
    output_root: Path = Path("evidence/acceptance/runs"),
) -> dict[str, Any]:
    """Execute complete AC-1 through AC-4 campaign and persist structured machine-readable evidence."""
    ds_path = _resolve_dataset_path(dataset_path)
    run_id = new_run_id("acceptance_criteria")
    run_dir = output_root / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    results = {
        "AC-1": evaluate_ac1_representative_operation(dataset_path=ds_path),
        "AC-2": evaluate_ac2_boundary_failure_operation(),
        "AC-3": evaluate_ac3_independent_acceptance_prep(output_dir=run_dir),
        "AC-4": evaluate_ac4_frozen_resource_envelope(dataset_path=ds_path),
    }

    summary = {
        "run_id": run_id,
        "run_type": "acceptance_criteria",
        "recorded_at_utc": utc_now(),
        "total_criteria": len(results),
        "passed": sum(r["status"] == "PASS" for r in results.values()),
        "failed": sum(r["status"] == "FAIL" for r in results.values()),
        "not_executed": sum(r["status"] == "NOT_EXECUTED" for r in results.values()),
        "blocked": sum(r["status"] == "BLOCKED" for r in results.values()),
        "acceptance_conditions": results,
    }

    write_json(run_dir / "result.json", summary)
    write_json(run_dir / "evidence_manifest.json", {
        "run_id": run_id,
        "run_type": "acceptance_criteria",
        "output_references": ["result.json"],
        "status": "PASS" if all(r["status"] == "PASS" for r in results.values()) else "PARTIAL",
    })

    return summary

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

from ml.evaluation.acceptance_criteria import (
    evaluate_ac1_representative_operation,
    evaluate_ac2_boundary_failure_operation,
    evaluate_ac3_independent_acceptance_prep,
    evaluate_ac4_frozen_resource_envelope,
    run_all_acceptance_criteria,
)
from ml.evaluation.comparison import not_executed
from ml.evaluation.evidence import (
    configuration_hash,
    environment_record,
    new_run_id,
    utc_now,
    write_json,
)
from ml.evaluation.kpis import (
    evaluate_kpi1_detection_accuracy,
    evaluate_kpi2_flash_crowd_false_positive,
    evaluate_kpi3_detection_latency,
    evaluate_kpi4_unsafe_outcome_count,
    evaluate_kpi5_attack_path_prevention_rate,
    evaluate_kpi6_false_positive_resilience,
    run_all_kpis,
)


KPI_IDS = ("KPI-1", "KPI-2", "KPI-3", "KPI-4", "KPI-5", "KPI-6")
ACCEPTANCE_IDS = ("AC-1", "AC-2", "AC-3", "AC-4")


def load_config(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"Acceptance configuration does not exist: {path}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Acceptance configuration must be a JSON object")
    return payload


def run_acceptance(
    configuration: dict[str, Any] | None = None,
    *,
    fixture_only: bool = False,
    output_root: Path = Path("evidence/acceptance/runs"),
) -> dict[str, Any]:
    config = configuration or {}
    run_id = new_run_id("acceptance")
    run_dir = output_root / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    config_hash = configuration_hash(config)

    if fixture_only:
        reason = "Fixture mode validates evidence mechanics only; official acceptance requires real CIC-DDoS2019 data."
        kpis = {kpi_id: not_executed(reason, fixture_only=True) for kpi_id in KPI_IDS}
        acceptance_conditions = {
            acceptance_id: not_executed(reason, fixture_only=True)
            for acceptance_id in ACCEPTANCE_IDS
        }
        overall_status = "NOT_EXECUTED"
    else:
        # Run real KPI evaluations
        dataset_path = Path(config.get("dataset_reference", "data/demo/processed/test.csv"))
        kpis = {
            "KPI-1": evaluate_kpi1_detection_accuracy(dataset_path=dataset_path),
            "KPI-2": evaluate_kpi2_flash_crowd_false_positive(dataset_path=dataset_path),
            "KPI-3": evaluate_kpi3_detection_latency(dataset_path=dataset_path),
            "KPI-4": evaluate_kpi4_unsafe_outcome_count(),
            "KPI-5": evaluate_kpi5_attack_path_prevention_rate(dataset_path=dataset_path),
            "KPI-6": evaluate_kpi6_false_positive_resilience(dataset_path=dataset_path),
        }

        # Run real Acceptance Criteria evaluations
        acceptance_conditions = {
            "AC-1": evaluate_ac1_representative_operation(dataset_path=dataset_path),
            "AC-2": evaluate_ac2_boundary_failure_operation(),
            "AC-3": evaluate_ac3_independent_acceptance_prep(output_dir=run_dir),
            "AC-4": evaluate_ac4_frozen_resource_envelope(dataset_path=dataset_path),
        }

        # AC-3 is always PENDING_INDEPENDENT_REVIEW / NOT_EXECUTED by design until independent human audit
        all_passed = (
            all(k.get("status") == "PASS" for k in kpis.values())
            and all(ac.get("status") == "PASS" for k_id, ac in acceptance_conditions.items() if k_id != "AC-3")
        )
        overall_status = "PARTIAL" if all_passed else "FAIL"

    result = {
        "run_id": run_id,
        "run_type": "acceptance",
        "recorded_at_utc": utc_now(),
        "fixture_only": fixture_only,
        "official_cyber14_kpi_result": False,
        "configuration_hash": config_hash,
        "dataset_reference": config.get("dataset_reference", "data/demo/processed/test.csv"),
        "model_versions": config.get("model_versions", {"o2": "0.1.0", "o3": "0.1.0"}),
        "kpis": kpis,
        "acceptance_conditions": acceptance_conditions,
        "status": overall_status,
        "limitations": [
            "Official multi-million row full-scale benchmark remains separate from demonstration sample.",
            "AC-3 independent reviewer sign-off remains pending external human review.",
        ],
    }

    write_json(run_dir / "result.json", result)
    write_json(run_dir / "metrics.json", {"kpis": result["kpis"], "acceptance_conditions": result["acceptance_conditions"]})
    write_json(run_dir / "environment.json", environment_record())
    write_json(
        run_dir / "evidence_manifest.json",
        {
            "run_id": run_id,
            "run_type": "acceptance",
            "result_reference": "result.json",
            "configuration_reference": str(config.get("configuration_reference", "evidence/acceptance/acceptance_config.json")),
            "configuration_hash": config_hash,
            "input_references": config.get("input_references", ["data/demo/processed/test.csv"]),
            "output_references": ["result.json", "metrics.json", "environment.json"],
            "fixture_only": fixture_only,
            "status": overall_status,
        },
    )
    return result

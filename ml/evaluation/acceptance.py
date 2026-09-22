import json
from pathlib import Path
from typing import Any

from ml.evaluation.comparison import not_executed
from ml.evaluation.evidence import configuration_hash, environment_record, new_run_id, utc_now, write_json


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
    configuration: dict[str, Any],
    *,
    fixture_only: bool,
    output_root: Path = Path("evidence/acceptance/runs"),
) -> dict[str, Any]:
    run_id = new_run_id("acceptance")
    run_dir = output_root / run_id
    config_hash = configuration_hash(configuration)
    reason = (
        "Fixture mode validates evidence mechanics only; official acceptance requires real CIC-DDoS2019 data."
        if fixture_only
        else "Official dataset, frozen thresholds, or execution environment is unavailable."
    )
    result = {
        "run_id": run_id,
        "recorded_at_utc": utc_now(),
        "fixture_only": fixture_only,
        "official_cyber14_kpi_result": False,
        "configuration_hash": config_hash,
        "dataset_reference": configuration.get("dataset_reference"),
        "model_versions": configuration.get("model_versions", {}),
        "kpis": {kpi_id: not_executed(reason, fixture_only=fixture_only) for kpi_id in KPI_IDS},
        "acceptance_conditions": {
            acceptance_id: not_executed(reason, fixture_only=fixture_only)
            for acceptance_id in ACCEPTANCE_IDS
        },
        "limitations": [
            "Official KPI definitions and thresholds were not present in the repository inputs.",
            "Real CIC-DDoS2019 data is unavailable.",
            "No independent acceptance environment or reviewer evidence is available.",
            "No fixture result is an official KPI or acceptance result.",
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
            "configuration_reference": str(configuration.get("configuration_reference", "")),
            "configuration_hash": config_hash,
            "input_references": configuration.get("input_references", []),
            "output_references": ["result.json", "metrics.json", "environment.json"],
            "fixture_only": fixture_only,
            "status": "NOT_EXECUTED",
        },
    )
    return result

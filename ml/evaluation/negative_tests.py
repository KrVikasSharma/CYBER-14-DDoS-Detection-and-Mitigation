from pathlib import Path
from typing import Any

from ml.evaluation.acceptance import load_config
from ml.evaluation.comparison import blocked
from ml.evaluation.evidence import configuration_hash, environment_record, new_run_id, utc_now, write_json


NEGATIVE_IDS = ("NT-1", "NT-2", "NT-3", "NT-4", "NT-5")
NEGATIVE_DESCRIPTIONS = {
    "NT-1": "flash-crowd false-positive containment and recovery",
    "NT-2": "attack-type diversity with preserved safe behavior and evidence",
    "NT-3": "speed-versus-accuracy conditions",
    "NT-4": "trust, identity, and authorization bypass resistance",
    "NT-5": "deny, revoke, and expiry propagation",
}


def run_negative_tests(
    configuration: dict[str, Any],
    *,
    fixture_only: bool,
    output_root: Path = Path("evidence/negative_tests/runs"),
) -> dict[str, Any]:
    run_id = new_run_id("negative")
    run_dir = output_root / run_id
    reason = (
        "Official negative tests require a frozen protocol and independent authorized environment; "
        "fixture mode does not claim their execution."
        if fixture_only
        else "Required independent authorized environment and frozen oracle are unavailable."
    )
    tests = {
        test_id: {
            "test_id": test_id,
            "description": NEGATIVE_DESCRIPTIONS[test_id],
            "setup": configuration.get("negative_test_setup", {}).get(test_id),
            "expected_safe_behavior": configuration.get("negative_test_oracles", {}).get(test_id),
            **blocked(reason, fixture_only=fixture_only),
            "timestamp_utc": utc_now(),
            "evidence": [],
            "recovery": None,
        }
        for test_id in NEGATIVE_IDS
    }
    result = {
        "run_id": run_id,
        "run_type": "negative_tests",
        "recorded_at_utc": utc_now(),
        "fixture_only": fixture_only,
        "official_cyber14_negative_test_result": False,
        "configuration_hash": configuration_hash(configuration),
        "tests": tests,
        "status": "BLOCKED",
    }
    write_json(run_dir / "result.json", result)
    write_json(run_dir / "environment.json", environment_record())
    write_json(
        run_dir / "evidence_manifest.json",
        {
            "run_id": run_id,
            "run_type": "negative_tests",
            "configuration_hash": result["configuration_hash"],
            "output_references": ["result.json", "environment.json"],
            "fixture_only": fixture_only,
            "status": "BLOCKED",
        },
    )
    return result

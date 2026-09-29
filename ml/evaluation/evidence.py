import hashlib
import json
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def configuration_hash(configuration: dict[str, Any]) -> str:
    encoded = json.dumps(configuration, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def get_git_commit() -> str:
    try:
        import subprocess
        return subprocess.check_output(["git", "rev-parse", "HEAD"], text=True, stderr=subprocess.DEVNULL).strip()
    except Exception:
        return "UNKNOWN_COMMIT"


def environment_record() -> dict[str, Any]:
    return {
        "git_commit": get_git_commit(),
        "python_version": sys.version,
        "platform": platform.platform(),
        "processor": platform.processor(),
        "machine": platform.machine(),
        "recorded_at_utc": utc_now(),
    }


def new_run_id(prefix: str) -> str:
    return f"{prefix}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{uuid4().hex[:8]}"


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def create_evidence_record(
    *,
    project: str = "CYBER-14",
    test_id: str,
    test_name: str,
    status: str,
    dataset_reference: str | None = None,
    sample_fixture_id: str | None = None,
    model_version: str | None = None,
    configuration: dict[str, Any] | None = None,
    expected_result: Any = None,
    observed_result: Any = None,
    metrics: dict[str, Any] | None = None,
    errors: list[str] | None = None,
    artifact_references: list[str] | None = None,
    reasons: list[str] | None = None,
) -> dict[str, Any]:
    """Generate canonical machine-readable evidence record matching CYBER-14 audit contracts."""
    return {
        "project": project,
        "test_id": test_id,
        "test_name": test_name,
        "status": status,
        "timestamp": utc_now(),
        "git_commit": get_git_commit(),
        "dataset_source_identifier": dataset_reference,
        "sample_fixture_identifier": sample_fixture_id,
        "model_version_identifier": model_version,
        "configuration": configuration or {},
        "expected_result": expected_result,
        "observed_result": observed_result,
        "metrics": metrics or {},
        "errors": errors or [],
        "reasons": reasons or [],
        "environment_information": environment_record(),
        "artifact_references": artifact_references or [],
    }

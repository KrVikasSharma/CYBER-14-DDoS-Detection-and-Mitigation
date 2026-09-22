import json
from pathlib import Path
from typing import Any

import joblib


class O2ArtifactError(FileNotFoundError):
    """Raised when an O2 artifact is missing or invalid."""


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise O2ArtifactError(f"Required O2 metadata file is missing: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def save_model(path: Path, model: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, path)


def load_model(path: Path) -> object:
    if not path.exists():
        raise O2ArtifactError(f"O2 model artifact is missing: {path}")
    return joblib.load(path)


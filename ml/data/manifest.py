import json
from pathlib import Path
from typing import Any

DEFAULT_MANIFEST_PATH = Path("evidence/cic_ddos2019_feature_manifest.json")


class FeatureManifestError(ValueError):
    """Raised when a feature manifest cannot be loaded or fails schema validation."""


def normalize_column_name(column: str) -> str:
    """Deterministic whitespace stripping preserving canonical naming."""
    return column.strip()


def normalize_column_names(columns: list[str]) -> list[str]:
    """Normalize a sequence of column headers."""
    return [normalize_column_name(col) for col in columns]


def load_feature_manifest(manifest_path: Path | None = None) -> dict[str, Any]:
    """Load and validate the frozen CIC-DDoS2019 feature manifest."""
    path = manifest_path or DEFAULT_MANIFEST_PATH
    if not path.exists():
        raise FeatureManifestError(f"Feature manifest file does not exist: {path}")

    try:
        content = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise FeatureManifestError(f"Failed to read feature manifest JSON at {path}: {exc}") from exc

    validate_manifest_structure(content)
    return content


def validate_manifest_structure(manifest: dict[str, Any]) -> None:
    """Validate the internal schema and invariants of the frozen manifest."""
    required_keys = {
        "manifest_version",
        "dataset_identifier",
        "source_schema_column_count",
        "included_features_o2",
        "included_features_o3",
        "excluded_columns",
        "feature_metadata",
        "feature_list_sha256",
    }
    missing = required_keys - set(manifest.keys())
    if missing:
        raise FeatureManifestError(f"Manifest missing required root keys: {sorted(missing)}")

    o2_features = manifest["included_features_o2"]
    o3_features = manifest["included_features_o3"]
    if not isinstance(o2_features, list) or len(o2_features) != 78:
        raise FeatureManifestError(
            f"Expected exactly 78 O2 features in manifest, found {len(o2_features) if isinstance(o2_features, list) else type(o2_features)}"
        )
    if not isinstance(o3_features, list) or len(o3_features) != 78:
        raise FeatureManifestError(
            f"Expected exactly 78 O3 features in manifest, found {len(o3_features) if isinstance(o3_features, list) else type(o3_features)}"
        )
    if o2_features != o3_features:
        raise FeatureManifestError("O2 and O3 feature vectors must be identical in this manifest.")

    excluded = manifest["excluded_columns"]
    if not isinstance(excluded, list) or len(excluded) != 10:
        raise FeatureManifestError(
            f"Expected exactly 10 excluded columns, found {len(excluded) if isinstance(excluded, list) else type(excluded)}"
        )


def get_frozen_features(model_target: str = "o2", manifest_path: Path | None = None) -> list[str]:
    """Return the ordered list of frozen feature names for O2 or O3."""
    manifest = load_feature_manifest(manifest_path)
    key = "included_features_o2" if model_target.lower() == "o2" else "included_features_o3"
    return list(manifest[key])

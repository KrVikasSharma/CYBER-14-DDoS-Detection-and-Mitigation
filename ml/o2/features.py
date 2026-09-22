from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pandas as pd

from ml.data.manifest import DEFAULT_MANIFEST_PATH, load_feature_manifest
from ml.o2.config import (
    O2_FORBIDDEN_COLUMNS,
    O2_FORBIDDEN_PREFIXES,
    O2_LABEL_COLUMNS,
    O2_TARGET_COLUMN,
)


class O2FeatureContractError(ValueError):
    """Raised when a processed dataset violates the O2 feature contract."""


@dataclass(frozen=True)
class O2FeatureContract:
    target_column: str
    feature_columns: list[str]
    forbidden_columns_present: list[str]
    manifest_fingerprint: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "target_column": self.target_column,
            "feature_columns": self.feature_columns,
            "forbidden_columns_present": self.forbidden_columns_present,
            "feature_ordering": "processed_csv_column_order_after_exclusions",
            "manifest_fingerprint": self.manifest_fingerprint,
        }


def select_o2_feature_columns(
    dataset: pd.DataFrame,
    manifest: dict[str, Any] | Path | None = None,
) -> list[str]:
    forbidden = set(O2_LABEL_COLUMNS) | set(O2_FORBIDDEN_COLUMNS)

    # Check for forbidden post-decision / leakage columns in dataset
    leakage_columns: list[str] = []
    for column in dataset.columns:
        lowered = column.lower().strip()
        if any(lowered.startswith(prefix) for prefix in O2_FORBIDDEN_PREFIXES):
            leakage_columns.append(column)

    if leakage_columns:
        raise O2FeatureContractError(
            "Processed dataset contains post-decision or evaluation columns that are not "
            f"allowed as O2 features: {leakage_columns}"
        )

    if manifest is not None:
        manifest_data = (
            load_feature_manifest(Path(manifest))
            if isinstance(manifest, (str, Path))
            else manifest
        )
        expected_features: list[str] = list(manifest_data["included_features_o2"])

        # 1. Fail closed on missing required features
        missing = [col for col in expected_features if col not in dataset.columns]
        if missing:
            raise O2FeatureContractError(f"Dataset is missing required manifest features: {missing}")

        # 2. Fail closed if forbidden column is in expected features
        forbidden_in_manifest = [col for col in expected_features if col in forbidden or col.strip() in forbidden]
        if forbidden_in_manifest:
            raise O2FeatureContractError(
                f"Forbidden columns detected in manifest feature contract: {forbidden_in_manifest}"
            )

        # 3. Fail closed on unexpected features / schema mismatch
        dataset_feature_candidates = [
            col
            for col in dataset.columns
            if col not in forbidden and col.strip() not in forbidden and not any(col.lower().strip().startswith(p) for p in O2_FORBIDDEN_PREFIXES)
        ]
        unexpected = [col for col in dataset_feature_candidates if col not in set(expected_features)]
        if unexpected:
            raise O2FeatureContractError(
                f"Dataset contains unexpected feature columns not defined in manifest: {unexpected}"
            )

        # 4. Fail closed on feature ordering mismatch
        dataset_ordered_features = [col for col in dataset.columns if col in set(expected_features)]
        if dataset_ordered_features != expected_features:
            raise O2FeatureContractError(
                "Dataset feature ordering does not match the frozen manifest specification."
            )

        return expected_features

    # Fallback to dynamic numeric selection for legacy fixture datasets without manifest
    feature_columns: list[str] = []
    for column in dataset.columns:
        if column in forbidden or column.strip() in forbidden:
            continue
        if pd.api.types.is_numeric_dtype(dataset[column]):
            feature_columns.append(column)

    if not feature_columns:
        raise O2FeatureContractError("No numeric O2 feature columns are available.")
    return feature_columns


def validate_o2_dataset(
    dataset: pd.DataFrame,
    manifest: dict[str, Any] | Path | None = None,
) -> O2FeatureContract:
    if dataset.empty:
        raise O2FeatureContractError("O2 dataset is empty.")
    if O2_TARGET_COLUMN not in dataset.columns:
        raise O2FeatureContractError(f"Missing required O2 target column: {O2_TARGET_COLUMN}")
    if dataset[O2_TARGET_COLUMN].isna().any():
        raise O2FeatureContractError("O2 target column contains missing values.")

    target_values = set(dataset[O2_TARGET_COLUMN].astype(int).unique())
    if not target_values.issubset({0, 1}):
        raise O2FeatureContractError(
            f"O2 target column must contain only 0/1 values; found {sorted(target_values)}."
        )
    if len(target_values) < 2:
        raise O2FeatureContractError(
            "O2 training/evaluation requires both legitimate (0) and attack (1) samples."
        )

    forbidden_present = [
        column
        for column in dataset.columns
        if column in set(O2_LABEL_COLUMNS) | set(O2_FORBIDDEN_COLUMNS)
        or column.strip() in set(O2_LABEL_COLUMNS) | set(O2_FORBIDDEN_COLUMNS)
    ]

    manifest_fingerprint = None
    if manifest is not None:
        manifest_data = (
            load_feature_manifest(Path(manifest))
            if isinstance(manifest, (str, Path))
            else manifest
        )
        manifest_fingerprint = manifest_data.get("feature_list_sha256")

    feature_columns = select_o2_feature_columns(dataset, manifest=manifest)
    return O2FeatureContract(
        target_column=O2_TARGET_COLUMN,
        feature_columns=feature_columns,
        forbidden_columns_present=forbidden_present,
        manifest_fingerprint=manifest_fingerprint,
    )


def validate_o2_dataset_against_manifest(
    dataset: pd.DataFrame,
    manifest_path: Path | None = None,
) -> O2FeatureContract:
    """Convenience validator that strictly enforces the default frozen manifest."""
    path = manifest_path or DEFAULT_MANIFEST_PATH
    return validate_o2_dataset(dataset, manifest=path)


def split_features_target(
    dataset: pd.DataFrame,
    feature_columns: list[str],
    target_column: str = O2_TARGET_COLUMN,
) -> tuple[pd.DataFrame, pd.Series]:
    missing_features = [column for column in feature_columns if column not in dataset.columns]
    if missing_features:
        raise O2FeatureContractError(f"Dataset is missing O2 feature columns: {missing_features}")
    if target_column not in dataset.columns:
        raise O2FeatureContractError(f"Dataset is missing O2 target column: {target_column}")
    return dataset[feature_columns], dataset[target_column].astype(int)

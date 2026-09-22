from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pandas as pd

from ml.data.manifest import DEFAULT_MANIFEST_PATH, load_feature_manifest
from ml.o3.config import (
    O3_FORBIDDEN_COLUMNS,
    O3_FORBIDDEN_PREFIXES,
    O3_LABEL_COLUMNS,
    O3_TARGET_COLUMN,
    known_o3_labels,
)


class O3FeatureContractError(ValueError):
    """Raised when a processed dataset violates the O3 feature or label contract."""


@dataclass(frozen=True)
class O3FeatureContract:
    target_column: str
    feature_columns: list[str]
    available_classes: list[str]
    original_labels_by_class: dict[str, list[str]]
    forbidden_columns_present: list[str]
    manifest_fingerprint: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "target_column": self.target_column,
            "feature_columns": self.feature_columns,
            "available_classes": self.available_classes,
            "original_labels_by_class": self.original_labels_by_class,
            "forbidden_columns_present": self.forbidden_columns_present,
            "feature_ordering": "processed_csv_column_order_after_exclusions",
            "manifest_fingerprint": self.manifest_fingerprint,
        }


def select_o3_feature_columns(
    dataset: pd.DataFrame,
    manifest: dict[str, Any] | Path | None = None,
) -> list[str]:
    forbidden = set(O3_LABEL_COLUMNS) | set(O3_FORBIDDEN_COLUMNS)

    leakage_columns: list[str] = []
    for column in dataset.columns:
        lowered = column.lower().strip()
        if any(lowered.startswith(prefix) for prefix in O3_FORBIDDEN_PREFIXES):
            leakage_columns.append(column)

    if leakage_columns:
        raise O3FeatureContractError(
            "Processed dataset contains post-decision or evaluation columns that are not "
            f"allowed as O3 features: {leakage_columns}"
        )

    if manifest is not None:
        manifest_data = (
            load_feature_manifest(Path(manifest))
            if isinstance(manifest, (str, Path))
            else manifest
        )
        expected_features: list[str] = list(manifest_data["included_features_o3"])

        # 1. Fail closed on missing required features
        missing = [col for col in expected_features if col not in dataset.columns]
        if missing:
            raise O3FeatureContractError(f"Dataset is missing required manifest features: {missing}")

        # 2. Fail closed if forbidden column is in expected features
        forbidden_in_manifest = [col for col in expected_features if col in forbidden or col.strip() in forbidden]
        if forbidden_in_manifest:
            raise O3FeatureContractError(
                f"Forbidden columns detected in manifest feature contract: {forbidden_in_manifest}"
            )

        # 3. Fail closed on unexpected features / schema mismatch
        dataset_feature_candidates = [
            col
            for col in dataset.columns
            if col not in forbidden and col.strip() not in forbidden and not any(col.lower().strip().startswith(p) for p in O3_FORBIDDEN_PREFIXES)
        ]
        unexpected = [col for col in dataset_feature_candidates if col not in set(expected_features)]
        if unexpected:
            raise O3FeatureContractError(
                f"Dataset contains unexpected feature columns not defined in manifest: {unexpected}"
            )

        # 4. Fail closed on feature ordering mismatch
        dataset_ordered_features = [col for col in dataset.columns if col in set(expected_features)]
        if dataset_ordered_features != expected_features:
            raise O3FeatureContractError(
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
        raise O3FeatureContractError("No numeric O3 feature columns are available.")
    return feature_columns


def validate_o3_dataset(
    dataset: pd.DataFrame,
    manifest: dict[str, Any] | Path | None = None,
) -> O3FeatureContract:
    if dataset.empty:
        raise O3FeatureContractError("O3 dataset is empty.")
    if O3_TARGET_COLUMN not in dataset.columns:
        raise O3FeatureContractError(f"Missing required O3 target column: {O3_TARGET_COLUMN}")
    if "label_binary" not in dataset.columns:
        raise O3FeatureContractError("Processed O3 dataset must retain label_binary for traceability.")
    if dataset[O3_TARGET_COLUMN].isna().any():
        raise O3FeatureContractError("O3 target column contains missing values.")
    if (dataset[O3_TARGET_COLUMN].astype(str).str.strip() == "").any():
        raise O3FeatureContractError("O3 target column contains empty labels.")

    labels = dataset[O3_TARGET_COLUMN].astype(str).str.strip()
    known = set(known_o3_labels())
    unique_labels = sorted(labels.unique())
    unknown = [label for label in unique_labels if label.upper() not in known]
    if unknown:
        raise O3FeatureContractError(
            f"O3 dataset contains labels outside the documented preprocessing mapping: {unknown}"
        )
    unnormalized = [label for label in unique_labels if label != label.upper()]
    if unnormalized:
        raise O3FeatureContractError(
            f"O3 target column must contain normalized labels; found: {unnormalized}"
        )
    if len(unique_labels) < 2:
        raise O3FeatureContractError("O3 requires at least two classes in the supplied dataset.")

    original_labels_by_class: dict[str, list[str]] = {}
    if "label_original" in dataset.columns:
        for label in unique_labels:
            originals = dataset.loc[
                dataset[O3_TARGET_COLUMN] == label,
                "label_original",
            ].astype(str)
            original_labels_by_class[label] = sorted(set(originals))
    else:
        original_labels_by_class = {label: [] for label in unique_labels}

    forbidden_present = [
        column
        for column in dataset.columns
        if column in set(O3_LABEL_COLUMNS) | set(O3_FORBIDDEN_COLUMNS)
        or column.strip() in set(O3_LABEL_COLUMNS) | set(O3_FORBIDDEN_COLUMNS)
    ]

    manifest_fingerprint = None
    if manifest is not None:
        manifest_data = (
            load_feature_manifest(Path(manifest))
            if isinstance(manifest, (str, Path))
            else manifest
        )
        manifest_fingerprint = manifest_data.get("feature_list_sha256")

    feature_columns = select_o3_feature_columns(dataset, manifest=manifest)
    return O3FeatureContract(
        target_column=O3_TARGET_COLUMN,
        feature_columns=feature_columns,
        available_classes=unique_labels,
        original_labels_by_class=original_labels_by_class,
        forbidden_columns_present=forbidden_present,
        manifest_fingerprint=manifest_fingerprint,
    )


def validate_o3_dataset_against_manifest(
    dataset: pd.DataFrame,
    manifest_path: Path | None = None,
) -> O3FeatureContract:
    """Convenience validator that strictly enforces the default frozen manifest."""
    path = manifest_path or DEFAULT_MANIFEST_PATH
    return validate_o3_dataset(dataset, manifest=path)


def split_features_target(
    dataset: pd.DataFrame,
    feature_columns: list[str],
    target_column: str = O3_TARGET_COLUMN,
) -> tuple[pd.DataFrame, pd.Series]:
    missing_features = [column for column in feature_columns if column not in dataset.columns]
    if missing_features:
        raise O3FeatureContractError(f"Dataset is missing O3 feature columns: {missing_features}")
    if target_column not in dataset.columns:
        raise O3FeatureContractError(f"Dataset is missing O3 target column: {target_column}")
    return dataset[feature_columns], dataset[target_column].astype(str)


def validate_inference_features(dataset: pd.DataFrame, feature_columns: list[str]) -> None:
    if dataset.empty:
        raise O3FeatureContractError("Prediction dataset is empty.")
    missing = [column for column in feature_columns if column not in dataset.columns]
    if missing:
        raise O3FeatureContractError(f"Prediction dataset is missing O3 features: {missing}")

    allowed = set(feature_columns) | set(O3_LABEL_COLUMNS)
    unexpected_numeric = [
        column
        for column in dataset.columns
        if column not in allowed and pd.api.types.is_numeric_dtype(dataset[column])
    ]
    if unexpected_numeric:
        raise O3FeatureContractError(
            f"Prediction dataset contains unexpected numeric features: {unexpected_numeric}"
        )
    non_numeric = [
        column for column in feature_columns if not pd.api.types.is_numeric_dtype(dataset[column])
    ]
    if non_numeric:
        raise O3FeatureContractError(f"O3 features must be numeric: {non_numeric}")
    missing_values = [column for column in feature_columns if dataset[column].isna().any()]
    if missing_values:
        raise O3FeatureContractError(f"O3 features contain missing values: {missing_values}")

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
import sklearn

from ml.o3.artifacts import save_model, write_json
from ml.o3.config import O3ModelConfig, build_artifact_paths, known_o3_labels
from ml.o3.features import split_features_target, validate_o3_dataset
from ml.o3.model import build_o3_model
from ml.preprocessing.preprocessor import deterministic_train_test_split


@dataclass(frozen=True)
class O3TrainingResult:
    artifact_dir: Path
    model_path: Path
    feature_metadata_path: Path
    training_metadata_path: Path
    class_metadata_path: Path
    reference_record_path: Path
    feature_columns: list[str]
    classes: list[str]


def read_processed_dataset(path: Path) -> pd.DataFrame:
    if not path.exists():
        raise FileNotFoundError(f"Processed O3 dataset does not exist: {path}")
    if path.suffix.lower() != ".csv":
        raise ValueError(f"Processed O3 dataset must be a CSV file: {path}")
    return pd.read_csv(path)


def train_o3_reference_classifier(
    dataset: pd.DataFrame,
    config: O3ModelConfig,
    dataset_reference: str | None = None,
    fixture_only: bool = False,
) -> O3TrainingResult:
    contract = validate_o3_dataset(dataset)
    train_frame, holdout_frame = deterministic_train_test_split(
        dataset,
        test_size=config.test_size,
        random_seed=config.random_seed,
    )
    if train_frame.empty:
        raise ValueError("O3 training split is empty.")

    missing_from_train = sorted(set(contract.available_classes) - set(train_frame[contract.target_column]))
    if missing_from_train:
        raise ValueError(
            "O3 training split is missing classes. Provide more data or adjust split settings: "
            f"{missing_from_train}"
        )

    features, target = split_features_target(
        train_frame,
        contract.feature_columns,
        contract.target_column,
    )
    model = build_o3_model(config)
    model.fit(features, target)

    paths = build_artifact_paths(config.artifact_dir)
    paths.artifact_dir.mkdir(parents=True, exist_ok=True)
    save_model(paths.model_path, model)

    class_counts = dataset[contract.target_column].astype(str).value_counts().sort_index().to_dict()
    feature_metadata = {
        "model_identifier": config.model_identifier,
        "model_version": config.model_version,
        "target_column": contract.target_column,
        "feature_columns": contract.feature_columns,
        "feature_count": len(contract.feature_columns),
        "feature_ordering": "processed_csv_column_order_after_exclusions",
        "forbidden_columns_present_but_excluded": contract.forbidden_columns_present,
        "leakage_prevention": {
            "excluded_label_columns": ["label_binary", "label_original", "label_normalized"],
            "excluded_identifier_columns": [
                "Flow ID",
                "Source IP",
                "Src IP",
                "Destination IP",
                "Dst IP",
                "Source Port",
                "Src Port",
                "Destination Port",
                "Dst Port",
                "Timestamp",
            ],
            "forbidden_prefixes": [
                "mitigation_",
                "decision_",
                "acceptance_",
                "kpi_",
                "latency_",
                "result_",
            ],
        },
    }
    write_json(paths.feature_metadata_path, feature_metadata)

    class_metadata = {
        "target_column": contract.target_column,
        "available_classes": contract.available_classes,
        "class_count": len(contract.available_classes),
        "class_distribution": {label: int(count) for label, count in class_counts.items()},
        "original_labels_by_class": contract.original_labels_by_class,
        "known_label_contract": list(known_o3_labels()),
    }
    write_json(paths.class_metadata_path, class_metadata)

    training_metadata = {
        "model_identifier": config.model_identifier,
        "model_version": config.model_version,
        "model_type": "sklearn.ensemble.GradientBoostingClassifier",
        "trained_at_utc": datetime.now(timezone.utc).isoformat(),
        "dataset_reference": dataset_reference,
        "fixture_only": fixture_only,
        "target_column": contract.target_column,
        "random_seed": config.random_seed,
        "training_configuration": config.to_metadata(),
        "split_configuration": {
            "method": "deterministic_train_test_split",
            "test_size": config.test_size,
            "random_seed": config.random_seed,
            "train_count": int(len(train_frame)),
            "holdout_count": int(len(holdout_frame)),
        },
        "sample_summary": {
            "sample_count": int(len(dataset)),
            "number_of_classes": len(contract.available_classes),
            "class_distribution": {label: int(count) for label, count in class_counts.items()},
        },
        "software_versions": {
            "numpy": np.__version__,
            "pandas": pd.__version__,
            "scikit_learn": sklearn.__version__,
        },
        "artifact_files": {
            "model": str(paths.model_path),
            "feature_metadata": str(paths.feature_metadata_path),
            "class_metadata": str(paths.class_metadata_path),
            "training_metadata": str(paths.training_metadata_path),
        },
    }
    write_json(paths.training_metadata_path, training_metadata)

    reference_record = {
        "model_identifier": config.model_identifier,
        "model_version": config.model_version,
        "dataset_provenance_reference": dataset_reference,
        "fixture_only": fixture_only,
        "feature_contract": feature_metadata,
        "class_mapping": class_metadata,
        "training_configuration": training_metadata,
        "evaluation_configuration": {
            "status": "not_run_by_training_cli",
            "note": "Run scripts/evaluate_o3.py with evaluation data to produce measured metrics.",
        },
        "measured_metrics": None,
        "latency_measurements": None,
        "software_versions": training_metadata["software_versions"],
        "limitations": [
            "Reference classifier only.",
            "Not a CYBER-14 KPI or acceptance result.",
            "Real CIC-DDoS2019 performance requires the real dataset.",
        ],
    }
    write_json(paths.reference_record_path, reference_record)

    return O3TrainingResult(
        artifact_dir=paths.artifact_dir,
        model_path=paths.model_path,
        feature_metadata_path=paths.feature_metadata_path,
        training_metadata_path=paths.training_metadata_path,
        class_metadata_path=paths.class_metadata_path,
        reference_record_path=paths.reference_record_path,
        feature_columns=contract.feature_columns,
        classes=contract.available_classes,
    )


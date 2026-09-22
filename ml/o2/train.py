from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import sklearn

from ml.o2.artifacts import save_model, write_json
from ml.o2.config import O2ModelConfig, build_artifact_paths
from ml.o2.features import split_features_target, validate_o2_dataset
from ml.o2.model import build_o2_model
from ml.preprocessing.preprocessor import deterministic_train_test_split


@dataclass(frozen=True)
class O2TrainingResult:
    artifact_dir: Path
    model_path: Path
    feature_metadata_path: Path
    training_metadata_path: Path
    reference_record_path: Path
    feature_columns: list[str]


def read_processed_dataset(path: Path) -> pd.DataFrame:
    if not path.exists():
        raise FileNotFoundError(f"Processed O2 dataset does not exist: {path}")
    if path.suffix.lower() != ".csv":
        raise ValueError(f"Processed O2 dataset must be a CSV file: {path}")
    return pd.read_csv(path)


def train_o2_reference_detector(
    dataset: pd.DataFrame,
    config: O2ModelConfig,
    dataset_reference: str | None = None,
) -> O2TrainingResult:
    contract = validate_o2_dataset(dataset)
    train_frame, holdout_frame = deterministic_train_test_split(
        dataset,
        test_size=config.test_size,
        random_seed=config.random_seed,
    )
    if train_frame.empty:
        raise ValueError("O2 training split is empty.")

    features, target = split_features_target(
        train_frame,
        contract.feature_columns,
        contract.target_column,
    )
    model = build_o2_model(config)
    model.fit(features, target)

    paths = build_artifact_paths(config.artifact_dir)
    paths.artifact_dir.mkdir(parents=True, exist_ok=True)
    save_model(paths.model_path, model)

    label_counts = dataset[contract.target_column].astype(int).value_counts().to_dict()
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
                "Timestamp",
            ],
            "forbidden_prefixes": ["mitigation_", "decision_", "acceptance_", "kpi_", "latency_"],
        },
    }
    write_json(paths.feature_metadata_path, feature_metadata)

    training_metadata = {
        "model_identifier": config.model_identifier,
        "model_version": config.model_version,
        "model_type": "sklearn.ensemble.RandomForestClassifier",
        "trained_at_utc": datetime.now(timezone.utc).isoformat(),
        "dataset_reference": dataset_reference,
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
            "attack_count": int(label_counts.get(1, 0)),
            "legitimate_count": int(label_counts.get(0, 0)),
        },
        "software_versions": {
            "numpy": np.__version__,
            "pandas": pd.__version__,
            "scikit_learn": sklearn.__version__,
        },
        "artifact_files": {
            "model": str(paths.model_path),
            "feature_metadata": str(paths.feature_metadata_path),
            "training_metadata": str(paths.training_metadata_path),
        },
    }
    write_json(paths.training_metadata_path, training_metadata)

    reference_record = {
        "model_identifier": config.model_identifier,
        "model_version": config.model_version,
        "feature_contract": feature_metadata,
        "dataset_provenance_identifier": dataset_reference,
        "training_configuration": training_metadata,
        "evaluation_configuration": {
            "status": "not_run_by_training_cli",
            "note": "Run scripts/evaluate_o2.py with a real evaluation CSV to produce measured metrics.",
        },
        "measured_metrics": None,
        "latency_measurements": None,
        "resource_measurements": None,
        "official_cyber14_kpi_result": False,
    }
    write_json(paths.reference_record_path, reference_record)

    return O2TrainingResult(
        artifact_dir=paths.artifact_dir,
        model_path=paths.model_path,
        feature_metadata_path=paths.feature_metadata_path,
        training_metadata_path=paths.training_metadata_path,
        reference_record_path=paths.reference_record_path,
        feature_columns=contract.feature_columns,
    )


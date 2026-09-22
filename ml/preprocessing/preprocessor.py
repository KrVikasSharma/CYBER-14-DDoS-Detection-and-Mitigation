import hashlib
import json
from dataclasses import dataclass, field

import numpy as np
import pandas as pd

from ml.data.config import DatasetPipelineConfig
from ml.preprocessing.labels import build_label_mapping, normalize_label


@dataclass
class ProcessedDataset:
    full: pd.DataFrame
    train: pd.DataFrame
    test: pd.DataFrame
    feature_columns: list[str]
    preprocessing_metadata: dict[str, object] = field(default_factory=dict)


class CICDDoS2019Preprocessor:
    def __init__(self, config: DatasetPipelineConfig) -> None:
        self.config = config
        self.label_mapping = build_label_mapping(config.normal_labels, config.ddos_labels)

    def preprocess(self, dataset: pd.DataFrame) -> ProcessedDataset:
        working = dataset.copy()

        if self.config.drop_duplicate_rows:
            working = working.drop_duplicates().reset_index(drop=True)

        working["label_original"] = working[self.config.label_column].astype(str)
        working["label_normalized"] = working[self.config.label_column].map(normalize_label)
        working["label_binary"] = working["label_normalized"].map(self.label_mapping)

        feature_columns = self.select_numeric_features(working)
        split_source = pd.concat(
            [working[feature_columns], working[["label_original", "label_normalized", "label_binary"]]],
            axis=1,
        )
        split_source["label_binary"] = split_source["label_binary"].astype(int)
        train_source, test_source = deterministic_train_test_split(
            split_source,
            test_size=self.config.test_size,
            random_seed=self.config.random_seed,
        )
        imputation_parameters = self.fit_imputation_parameters(train_source[feature_columns])
        train = self.transform_with_imputation(train_source, feature_columns, imputation_parameters)
        test = self.transform_with_imputation(test_source, feature_columns, imputation_parameters)
        processed = self.transform_with_imputation(split_source, feature_columns, imputation_parameters)
        preprocessing_metadata = self.build_preprocessing_metadata(
            feature_columns,
            imputation_parameters,
            len(train),
            len(test),
        )
        return ProcessedDataset(
            full=processed.reset_index(drop=True),
            train=train.reset_index(drop=True),
            test=test.reset_index(drop=True),
            feature_columns=feature_columns,
            preprocessing_metadata=preprocessing_metadata,
        )

    def select_numeric_features(self, dataset: pd.DataFrame) -> list[str]:
        from ml.data.manifest import get_frozen_features
        frozen_features = get_frozen_features("o2")
        missing_frozen = [col for col in frozen_features if col not in dataset.columns]
        if not missing_frozen:
            # Real CIC-DDoS2019 dataset or full sample: enforce exact 78 features in exact manifest order
            return list(frozen_features)

        excluded = set(self.config.excluded_columns) | {
            self.config.label_column,
            "label_original",
            "label_normalized",
            "label_binary",
        }
        return [
            column
            for column in dataset.columns
            if column not in excluded and pd.api.types.is_numeric_dtype(dataset[column])
        ]

    def fit_imputation_parameters(self, features: pd.DataFrame) -> dict[str, float]:
        if self.config.missing_numeric_strategy != "median":
            raise ValueError(
                f"Unsupported missing numeric strategy: {self.config.missing_numeric_strategy}"
            )

        cleaned = features.replace([np.inf, -np.inf], np.nan)
        medians = cleaned.median(numeric_only=True)
        missing_medians = [column for column in features.columns if pd.isna(medians.get(column))]
        if missing_medians:
            raise ValueError(
                "Cannot calculate training-only median for numeric feature(s) with no valid "
                f"training values: {missing_medians}"
            )
        return {column: float(medians[column]) for column in features.columns}

    def transform_with_imputation(
        self,
        dataset: pd.DataFrame,
        feature_columns: list[str],
        imputation_parameters: dict[str, float],
    ) -> pd.DataFrame:
        transformed = dataset.copy()
        features = transformed[feature_columns].replace([np.inf, -np.inf], np.nan)
        transformed.loc[:, feature_columns] = features.fillna(imputation_parameters)
        return transformed

    def build_preprocessing_metadata(
        self,
        feature_columns: list[str],
        imputation_parameters: dict[str, float],
        training_rows: int,
        test_rows: int,
    ) -> dict[str, object]:
        metadata = {
            "preprocessing_version": "train-only-imputation-1",
            "split_strategy": "deterministic_train_test_split",
            "random_seed": self.config.random_seed,
            "test_size": self.config.test_size,
            "feature_columns": feature_columns,
            "imputation_strategy": self.config.missing_numeric_strategy,
            "imputation_parameters": imputation_parameters,
            "imputation_parameters_fit": "FIT_ON_TRAIN_ONLY",
            "training_rows": training_rows,
            "test_rows": test_rows,
        }
        metadata["configuration_fingerprint"] = hashlib.sha256(
            json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        return metadata


def deterministic_train_test_split(
    dataset: pd.DataFrame,
    test_size: float,
    random_seed: int,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    if not 0 < test_size < 1:
        raise ValueError("test_size must be between 0 and 1.")
    if dataset.empty:
        return dataset.copy(), dataset.copy()
    if len(dataset) == 1:
        return dataset.copy(), dataset.iloc[0:0].copy()

    shuffled = dataset.sample(frac=1.0, random_state=random_seed)
    test_count = max(1, min(len(dataset) - 1, round(len(dataset) * test_size)))
    test = shuffled.iloc[:test_count]
    train = shuffled.iloc[test_count:]
    return train, test

import time
from dataclasses import dataclass
from typing import Any

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_recall_fscore_support,
    precision_score,
    recall_score,
)

from ml.o3.config import O3_TARGET_COLUMN, known_o3_labels
from ml.o3.features import O3FeatureContractError, split_features_target, validate_inference_features


@dataclass(frozen=True)
class O3EvaluationResult:
    metrics: dict[str, Any]
    confusion_matrix: dict[str, Any]
    per_class: dict[str, dict[str, float | int]]
    sample_summary: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "metrics": self.metrics,
            "confusion_matrix": self.confusion_matrix,
            "per_class": self.per_class,
            "sample_summary": self.sample_summary,
        }


def evaluate_predictions(
    y_true: pd.Series | np.ndarray,
    y_pred: pd.Series | np.ndarray,
    labels: list[str] | None = None,
) -> O3EvaluationResult:
    y_true_array = np.asarray(y_true).astype(str)
    y_pred_array = np.asarray(y_pred).astype(str)
    if len(y_true_array) == 0:
        raise ValueError("Cannot evaluate O3 predictions with zero samples.")
    if len(y_true_array) != len(y_pred_array):
        raise ValueError("Prediction count does not match target count.")

    classes = labels or sorted(set(y_true_array) | set(y_pred_array))
    matrix = confusion_matrix(y_true_array, y_pred_array, labels=classes)
    precision, recall, f1, support = precision_recall_fscore_support(
        y_true_array,
        y_pred_array,
        labels=classes,
        zero_division=0,
    )
    per_class = {
        label: {
            "precision": float(precision[index]),
            "recall": float(recall[index]),
            "f1_score": float(f1[index]),
            "support": int(support[index]),
        }
        for index, label in enumerate(classes)
    }

    unique, counts = np.unique(y_true_array, return_counts=True)
    return O3EvaluationResult(
        metrics={
            "accuracy": float(accuracy_score(y_true_array, y_pred_array)),
            "macro_precision": float(
                precision_score(y_true_array, y_pred_array, average="macro", zero_division=0)
            ),
            "macro_recall": float(
                recall_score(y_true_array, y_pred_array, average="macro", zero_division=0)
            ),
            "macro_f1": float(
                f1_score(y_true_array, y_pred_array, average="macro", zero_division=0)
            ),
            "weighted_precision": float(
                precision_score(y_true_array, y_pred_array, average="weighted", zero_division=0)
            ),
            "weighted_recall": float(
                recall_score(y_true_array, y_pred_array, average="weighted", zero_division=0)
            ),
            "weighted_f1": float(
                f1_score(y_true_array, y_pred_array, average="weighted", zero_division=0)
            ),
        },
        confusion_matrix={
            "labels": classes,
            "matrix": matrix.astype(int).tolist(),
        },
        per_class=per_class,
        sample_summary={
            "total_samples": int(len(y_true_array)),
            "number_of_classes": int(len(classes)),
            "class_distribution": {
                str(label): int(count) for label, count in zip(unique, counts)
            },
        },
    )


def evaluate_model(
    model: object,
    dataset: pd.DataFrame,
    feature_columns: list[str],
    labels: list[str] | None = None,
) -> O3EvaluationResult:
    validate_inference_features(dataset, feature_columns)
    features, target = split_features_target(dataset, feature_columns, O3_TARGET_COLUMN)
    invalid = sorted(set(target) - set(known_o3_labels()))
    if invalid:
        raise O3FeatureContractError(f"Evaluation contains unknown normalized labels: {invalid}")
    predictions = model.predict(features)
    evaluation_labels = labels or [str(label) for label in getattr(model, "classes_", [])]
    return evaluate_predictions(target, predictions, evaluation_labels or None)


def measure_prediction_latency(
    model: object,
    samples: pd.DataFrame,
    feature_columns: list[str],
    trials: int,
) -> dict[str, Any]:
    if trials <= 0:
        raise ValueError("Latency trials must be greater than zero.")
    if samples.empty:
        raise O3FeatureContractError("Cannot measure O3 latency with an empty sample set.")
    validate_inference_features(samples, feature_columns)

    feature_frame = samples[feature_columns]
    durations_ms: list[float] = []
    for index in range(trials):
        row = feature_frame.iloc[[index % len(feature_frame)]]
        start = time.perf_counter()
        model.predict(row)
        durations_ms.append((time.perf_counter() - start) * 1000.0)

    values = np.asarray(durations_ms)
    return {
        "measurement_type": "o3_reference_local_inference",
        "official_acceptance_result": False,
        "trials": int(trials),
        "p50_ms": float(np.percentile(values, 50)),
        "p95_ms": float(np.percentile(values, 95)),
        "p99_ms": float(np.percentile(values, 99)),
        "min_ms": float(values.min()),
        "max_ms": float(values.max()),
    }


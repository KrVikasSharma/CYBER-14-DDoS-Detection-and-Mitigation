import time
from dataclasses import dataclass
from typing import Any

import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score

from ml.o2.config import O2_TARGET_COLUMN
from ml.o2.features import O2FeatureContractError, split_features_target


@dataclass(frozen=True)
class O2EvaluationResult:
    metrics: dict[str, Any]
    confusion_matrix: dict[str, int]
    sample_summary: dict[str, int]

    def to_dict(self) -> dict[str, Any]:
        return {
            "metrics": self.metrics,
            "confusion_matrix": self.confusion_matrix,
            "sample_summary": self.sample_summary,
        }


def evaluate_predictions(y_true: pd.Series | np.ndarray, y_pred: np.ndarray) -> O2EvaluationResult:
    y_true_array = np.asarray(y_true).astype(int)
    y_pred_array = np.asarray(y_pred).astype(int)
    if len(y_true_array) == 0:
        raise ValueError("Cannot evaluate O2 predictions with zero samples.")
    if len(y_true_array) != len(y_pred_array):
        raise ValueError("Prediction count does not match target count.")

    tn, fp, fn, tp = confusion_matrix(y_true_array, y_pred_array, labels=[0, 1]).ravel()
    false_positive_rate = fp / (fp + tn) if (fp + tn) else 0.0
    false_negative_rate = fn / (fn + tp) if (fn + tp) else 0.0

    return O2EvaluationResult(
        metrics={
            "accuracy": float(accuracy_score(y_true_array, y_pred_array)),
            "precision": float(precision_score(y_true_array, y_pred_array, zero_division=0)),
            "recall": float(recall_score(y_true_array, y_pred_array, zero_division=0)),
            "f1_score": float(f1_score(y_true_array, y_pred_array, zero_division=0)),
            "false_positive_rate": float(false_positive_rate),
            "false_negative_rate": float(false_negative_rate),
        },
        confusion_matrix={
            "true_negative": int(tn),
            "false_positive": int(fp),
            "false_negative": int(fn),
            "true_positive": int(tp),
        },
        sample_summary={
            "sample_count": int(len(y_true_array)),
            "attack_count": int((y_true_array == 1).sum()),
            "legitimate_count": int((y_true_array == 0).sum()),
        },
    )


def evaluate_model(model: object, dataset: pd.DataFrame, feature_columns: list[str]) -> O2EvaluationResult:
    features, target = split_features_target(dataset, feature_columns, O2_TARGET_COLUMN)
    predictions = model.predict(features)
    return evaluate_predictions(target, predictions)


def measure_prediction_latency(
    model: object,
    samples: pd.DataFrame,
    feature_columns: list[str],
    trials: int,
) -> dict[str, Any]:
    if trials <= 0:
        raise ValueError("Latency trials must be greater than zero.")
    if samples.empty:
        raise O2FeatureContractError("Cannot measure latency with an empty sample set.")
    missing = [column for column in feature_columns if column not in samples.columns]
    if missing:
        raise O2FeatureContractError(f"Latency samples are missing feature columns: {missing}")

    feature_frame = samples[feature_columns]
    durations_ms: list[float] = []
    for index in range(trials):
        row = feature_frame.iloc[[index % len(feature_frame)]]
        start = time.perf_counter()
        model.predict(row)
        durations_ms.append((time.perf_counter() - start) * 1000.0)

    values = np.asarray(durations_ms)
    return {
        "measurement_type": "o2_reference_local_inference",
        "official_acceptance_result": False,
        "trials": int(trials),
        "p50_ms": float(np.percentile(values, 50)),
        "p95_ms": float(np.percentile(values, 95)),
        "p99_ms": float(np.percentile(values, 99)),
        "min_ms": float(values.min()),
        "max_ms": float(values.max()),
    }


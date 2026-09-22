from collections import Counter
from typing import Any, Iterable


def _as_int_labels(values: Iterable[object]) -> list[int]:
    labels = [int(value) for value in values]
    if not labels:
        raise ValueError("metric inputs must contain at least one sample")
    if any(label not in {0, 1} for label in labels):
        raise ValueError("binary metrics require labels in {0, 1}")
    return labels


def binary_metrics(y_true: Iterable[object], y_pred: Iterable[object]) -> dict[str, Any]:
    actual = _as_int_labels(y_true)
    predicted = _as_int_labels(y_pred)
    if len(actual) != len(predicted):
        raise ValueError("metric inputs must have equal sample counts")

    tn = fp = fn = tp = 0
    for expected, observed in zip(actual, predicted):
        if expected == 0 and observed == 0:
            tn += 1
        elif expected == 0 and observed == 1:
            fp += 1
        elif expected == 1 and observed == 0:
            fn += 1
        else:
            tp += 1
    total = len(actual)
    return {
        "accuracy": (tn + tp) / total,
        "false_positive_rate": fp / (fp + tn) if fp + tn else 0.0,
        "false_negative_rate": fn / (fn + tp) if fn + tp else 0.0,
        "confusion_matrix": {
            "true_negative": tn,
            "false_positive": fp,
            "false_negative": fn,
            "true_positive": tp,
        },
        "sample_count": total,
        "class_distribution": dict(Counter(str(label) for label in actual)),
    }


def attack_path_metrics(expected_attack: Iterable[object], detected_attack: Iterable[object]) -> dict[str, Any]:
    expected = _as_int_labels(expected_attack)
    detected = _as_int_labels(detected_attack)
    if len(expected) != len(detected):
        raise ValueError("attack-path inputs must have equal sample counts")
    attack_count = sum(expected)
    caught_count = sum(1 for truth, observed in zip(expected, detected) if truth == 1 and observed == 1)
    return {
        "attack_samples": attack_count,
        "detected_attack_samples": caught_count,
        "detection_rate": caught_count / attack_count if attack_count else 0.0,
        "sample_count": len(expected),
    }


def percentage_points(candidate: float, reference: float) -> float:
    return (float(candidate) - float(reference)) * 100.0

from collections import Counter
from typing import Any, Iterable


def multiclass_confusion(
    y_true: Iterable[object],
    y_pred: Iterable[object],
    labels: list[str] | None = None,
) -> dict[str, Any]:
    actual = [str(value) for value in y_true]
    predicted = [str(value) for value in y_pred]
    if not actual or len(actual) != len(predicted):
        raise ValueError("confusion inputs must be non-empty and have equal sample counts")
    classes = labels or sorted(set(actual) | set(predicted))
    matrix = [[0 for _ in classes] for _ in classes]
    for expected, observed in zip(actual, predicted):
        matrix[classes.index(expected)][classes.index(observed)] += 1
    return {
        "labels": classes,
        "matrix": matrix,
        "sample_count": len(actual),
        "class_distribution": dict(Counter(actual)),
    }

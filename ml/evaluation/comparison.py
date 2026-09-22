from typing import Any


VALID_STATUSES = {"PASS", "FAIL", "NOT_EXECUTED", "BLOCKED"}


def compare_threshold(
    observed: float | int | None,
    threshold: float | int | None,
    *,
    direction: str,
    available: bool = True,
) -> dict[str, Any]:
    if direction not in {"at_least", "at_most", "equal"}:
        raise ValueError("direction must be at_least, at_most, or equal")
    if not available or observed is None or threshold is None:
        return {
            "status": "NOT_EXECUTED",
            "observed": observed,
            "threshold": threshold,
            "direction": direction,
            "reason": "Required observed value or official threshold is unavailable.",
        }
    if direction == "at_least":
        passed = observed >= threshold
    elif direction == "at_most":
        passed = observed <= threshold
    else:
        passed = observed == threshold
    return {
        "status": "PASS" if passed else "FAIL",
        "observed": observed,
        "threshold": threshold,
        "direction": direction,
        "reason": "Comparison executed against the supplied threshold.",
    }


def not_executed(reason: str, *, fixture_only: bool = False) -> dict[str, Any]:
    return {
        "status": "NOT_EXECUTED",
        "fixture_only": fixture_only,
        "reason": reason,
    }


def blocked(reason: str, *, fixture_only: bool = False) -> dict[str, Any]:
    return {
        "status": "BLOCKED",
        "fixture_only": fixture_only,
        "reason": reason,
    }

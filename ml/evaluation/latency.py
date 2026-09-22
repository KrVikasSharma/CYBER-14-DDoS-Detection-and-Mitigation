from time import perf_counter
from typing import Any, Callable

import numpy as np


class InsufficientTrialsError(ValueError):
    pass


def measure_latency(
    operation: Callable[[], object],
    trials: int,
    *,
    official: bool = False,
    minimum_official_trials: int = 30,
    minimum_successful_trials: int | None = None,
) -> dict[str, Any]:
    if trials <= 0:
        raise ValueError("trials must be greater than zero")
    if official and trials < minimum_official_trials:
        raise InsufficientTrialsError(
            f"official latency measurement requires at least {minimum_official_trials} trials"
        )
    required_successes = minimum_successful_trials
    if required_successes is None:
        required_successes = minimum_official_trials if official else 1
    if required_successes <= 0:
        raise ValueError("minimum_successful_trials must be greater than zero")

    successful_samples: list[float] = []
    failure_reasons: list[str] = []
    for _ in range(trials):
        started = perf_counter()
        try:
            operation()
        except Exception as exc:
            failure_reasons.append(f"{type(exc).__name__}: {exc}")
            continue
        successful_samples.append((perf_counter() - started) * 1000.0)

    successful_trials = len(successful_samples)
    failed_trials = len(failure_reasons)
    result: dict[str, Any] = {
        "trial_count": trials,
        "successful_trials": successful_trials,
        "failed_trials": failed_trials,
        "failures": failed_trials,
        "failure_reasons": failure_reasons,
        "successful_latency_samples": successful_samples,
        "minimum_successful_trials": required_successes,
        "official_measurement": official,
        "status": "NOT_EXECUTED" if successful_trials < required_successes else "PASS",
    }
    if successful_trials < required_successes:
        result.update(
            {
                "p50_ms": None,
                "p95_ms": None,
                "p99_ms": None,
                "minimum_ms": None,
                "maximum_ms": None,
            }
        )
        return result

    values = np.asarray(successful_samples, dtype=float)
    result.update(
        {
            "p50_ms": float(np.percentile(values, 50)),
            "p95_ms": float(np.percentile(values, 95)),
            "p99_ms": float(np.percentile(values, 99)),
            "minimum_ms": float(values.min()),
            "maximum_ms": float(values.max()),
        }
    )
    return result

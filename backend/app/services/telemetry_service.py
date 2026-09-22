from collections import Counter, deque
from threading import Lock
from time import monotonic
from typing import Any


class TelemetryStore:
    def __init__(self, max_samples: int = 500) -> None:
        self._started = monotonic()
        self._max_samples = max_samples
        self._latencies: deque[float] = deque(maxlen=max_samples)
        self._request_count = 0
        self._detection_count = 0
        self._error_count = 0
        self._simulator_events = 0
        self._mitigation_counts: Counter[str] = Counter()
        self._lock = Lock()

    def record_detection(self, latency_ms: float, decision: str, simulator: bool = False) -> None:
        with self._lock:
            self._request_count += 1
            self._detection_count += 1
            self._latencies.append(latency_ms)
            self._mitigation_counts[decision] += 1
            if simulator:
                self._simulator_events += 1

    def record_error(self) -> None:
        with self._lock:
            self._error_count += 1

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            values = sorted(self._latencies)
            return {
                "request_count": self._request_count,
                "detection_count": self._detection_count,
                "error_count": self._error_count,
                "simulator_events": self._simulator_events,
                "mitigation_decision_counts": dict(self._mitigation_counts),
                "latencies": values,
                "uptime_seconds": monotonic() - self._started,
            }


telemetry_store = TelemetryStore()

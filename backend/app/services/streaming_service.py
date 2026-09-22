import asyncio
import json
from collections import deque
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from time import monotonic
from typing import Any
from uuid import UUID, uuid4

from app.core.config import Settings, get_settings
from app.schemas.detection import DetectionAnalyzeRequest
from app.schemas.streaming import (
    StreamDetectionResponse,
    StreamErrorResponse,
    StreamSimulationRequest,
    StreamSimulationResponse,
)
from app.services.detection_service import (
    DetectionService,
    FeatureContractError,
    get_detection_service,
)


class StreamingMessageError(ValueError):
    def __init__(self, error_code: str, message: str, request_id: UUID | None = None) -> None:
        super().__init__(message)
        self.error_code = error_code
        self.request_id = request_id or uuid4()


class SimulatorDisabledError(RuntimeError):
    pass


@dataclass
class ConnectionState:
    connection_id: str
    message_times: deque[float]


class StreamingService:
    """Bounded WebSocket orchestration that delegates inference to DetectionService."""

    def __init__(self, settings: Settings, detection_service: DetectionService) -> None:
        self._settings = settings
        self._detection = detection_service
        self._connections: dict[str, ConnectionState] = {}
        self._demo_scenarios: dict[str, Any] | None = None

    def connect(self) -> str:
        connection_id = str(uuid4())
        self._connections[connection_id] = ConnectionState(connection_id, deque())
        return connection_id

    def disconnect(self, connection_id: str) -> None:
        self._connections.pop(connection_id, None)

    def connection_count(self) -> int:
        return len(self._connections)

    def process_message(self, connection_id: str, payload: str | bytes) -> dict[str, Any]:
        state = self._connections.get(connection_id)
        if state is None:
            return self._error("connection_not_found", "The streaming connection is not active.")

        raw_size = len(payload.encode("utf-8")) if isinstance(payload, str) else len(payload)
        if raw_size > self._settings.websocket_max_message_bytes:
            return self._error(
                "message_too_large",
                "The streaming message exceeds the configured size limit.",
            )
        if not isinstance(payload, str):
            try:
                payload = payload.decode("utf-8")
            except UnicodeDecodeError:
                return self._error("invalid_encoding", "Binary messages must contain UTF-8 JSON.")

        now = monotonic()
        window_start = now - 1.0
        while state.message_times and state.message_times[0] <= window_start:
            state.message_times.popleft()
        if len(state.message_times) >= self._settings.websocket_max_messages_per_second:
            return self._error("rate_limit_exceeded", "The per-connection message rate limit was exceeded.")
        state.message_times.append(now)

        request_id = uuid4()
        try:
            decoded = json.loads(payload)
        except json.JSONDecodeError:
            return self._error("invalid_json", "Message must contain valid JSON.", request_id)
        if not isinstance(decoded, dict):
            return self._error("invalid_message", "Message must be a JSON object.", request_id)

        # Application-level keepalive heartbeat
        if decoded.get("type") in {"ping", "heartbeat"} or decoded.get("action") in {"ping", "heartbeat"}:
            return {
                "type": "pong",
                "connection_id": connection_id,
                "timestamp": monotonic(),
            }

        try:
            request = DetectionAnalyzeRequest.model_validate(decoded)
            self._detection.validate_feature_contract(request)
            result = self._detection.analyze(request)
        except Exception as exc:
            if isinstance(exc, FeatureContractError):
                return self._error("invalid_observation", "The observation failed validation.", request_id)
            if exc.__class__.__name__ in {"PredictionFailureError", "DetectionServiceError"}:
                return self._error("analysis_failed", "The observation could not be analyzed.", request_id)
            return self._error("invalid_observation", "The observation failed validation.", request_id)

        result_payload = result.model_dump(mode="json")
        result_payload["request_id"] = str(request_id)
        return StreamDetectionResponse(
            response=result_payload,
            fixture_only=bool(
                result.artifact_scope.get("o2_fixture_only")
                or result.artifact_scope.get("o3_fixture_only")
            ),
            connection_id=connection_id,
        ).model_dump(mode="json")

    async def simulate(self, request: StreamSimulationRequest) -> StreamSimulationResponse:
        if not self._settings.stream_simulator_enabled:
            raise SimulatorDisabledError("The controlled stream simulator is disabled.")
        connection_id = self.connect()
        try:
            results: list[StreamDetectionResponse] = []
            for index in range(request.observations):
                observation = self._scenario_observation(request.scenario, index)
                result = self.process_message(connection_id, json.dumps(observation))
                if result.get("type") == "error":
                    raise StreamingMessageError(result["error_code"], result["message"])
                results.append(StreamDetectionResponse.model_validate(result))
                if request.interval_ms and index + 1 < request.observations:
                    await asyncio.sleep(request.interval_ms / 1000.0)
            return StreamSimulationResponse(
                scenario=request.scenario,
                observation_count=len(results),
                results=results,
            )
        finally:
            self.disconnect(connection_id)

    def _scenario_observation(self, scenario: str, index: int) -> dict[str, Any]:
        if getattr(self._settings, "demo_mode", False) or len(getattr(self._detection._o2, "feature_columns", [])) > 3:
            if self._demo_scenarios is None:
                demo_path = Path("data/demo/demo_scenarios.json")
                if demo_path.exists():
                    with open(demo_path, encoding="utf-8") as f:
                        self._demo_scenarios = json.load(f)
            if self._demo_scenarios and scenario in self._demo_scenarios:
                values = dict(self._demo_scenarios[scenario])
                meta = dict(values.get("metadata") or {})
                if meta:
                    base_port = meta.get("source_port") or 54321
                    meta["source_port"] = base_port + (index % 1000)
                    values["metadata"] = meta
                return {
                    "source_identifier": f"controlled_simulator:{scenario}:{index}",
                    **values,
                }
        observations = {
            "benign": {
                "traffic_rate": 10,
                "metadata": {
                    "source_ip": "192.168.1.50",
                    "source_port": 54321 + (index % 1000),
                    "destination_ip": "10.0.0.1",
                    "destination_port": 80,
                    "protocol": "TCP",
                    "timestamp": "2026-09-22T00:00:00Z",
                },
                "features": {"Flow Duration": 10, "Total Fwd Packets": 1, "Protocol": 6},
            },
            "flash_crowd": {
                "traffic_rate": 2000,
                "metadata": {
                    "source_ip": "192.168.1.60",
                    "source_port": 58922 + (index % 1000),
                    "destination_ip": "10.0.0.1",
                    "destination_port": 443,
                    "protocol": "TCP",
                    "timestamp": "2026-09-22T00:01:15Z",
                },
                "features": {"Flow Duration": 14, "Total Fwd Packets": 3, "Protocol": 6},
            },
            "attack_fixture": {
                "traffic_rate": 2000,
                "metadata": {
                    "source_ip": "198.51.100.15",
                    "source_port": 137,
                    "destination_ip": "10.0.0.1",
                    "destination_port": 137,
                    "protocol": "UDP",
                    "timestamp": "2026-09-22T00:02:30Z",
                },
                "features": {"Flow Duration": 50, "Total Fwd Packets": 20, "Protocol": 17},
            },
        }
        if scenario not in observations:
            raise StreamingMessageError("unknown_scenario", f"Unknown scenario: {scenario}")
        values = observations[scenario]
        return {
            "source_identifier": f"controlled_simulator:{scenario}:{index}",
            **values,
        }

    @staticmethod
    def _error(error_code: str, message: str, request_id: UUID | None = None) -> dict[str, Any]:
        return StreamErrorResponse(
            request_id=request_id or uuid4(),
            error_code=error_code,
            message=message,
        ).model_dump(mode="json")


@lru_cache
def get_streaming_service() -> StreamingService:
    settings = get_settings()
    return StreamingService(settings, get_detection_service())

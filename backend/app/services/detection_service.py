from dataclasses import dataclass
from functools import lru_cache
import logging
from pathlib import Path
from time import perf_counter
from typing import Any
from uuid import UUID, uuid4

import pandas as pd

from app.core.config import Settings, get_settings
from app.core.time import format_iso_utc, now_utc
from app.schemas.detection import (
    BinaryDetectionResponse,
    ClassificationResponse,
    DetectionAnalyzeRequest,
    DetectionAnalyzeResponse,
    FlowMetadata,
    LatencyResponse,
    MitigationResponse,
)
from ml.mitigation.config import MitigationConfig
from ml.mitigation.engine import MitigationEngine, MitigationExecutionError, MitigationInputError
from ml.mitigation.models import DetectionResult
from ml.o2.features import O2FeatureContractError
from ml.o2.predict import load_o2_artifact, predict_o2
from ml.o3.features import O3FeatureContractError
from ml.o3.predict import load_o3_artifact, predict_o3
from app.services.telemetry_service import telemetry_store


logger = logging.getLogger(__name__)


class DetectionServiceError(RuntimeError):
    """Base error for safe detection-service failures."""


class ModelUnavailableError(DetectionServiceError):
    pass


class IncompatibleModelError(DetectionServiceError):
    pass


class PredictionFailureError(DetectionServiceError):
    pass


class FeatureContractError(PredictionFailureError):
    pass


@dataclass(frozen=True)
class LoadedO2:
    model: object
    feature_columns: list[str]
    metadata: dict[str, Any]


@dataclass(frozen=True)
class LoadedO3:
    model: object
    feature_columns: list[str]
    feature_metadata: dict[str, Any]
    class_metadata: dict[str, Any]


class DetectionService:
    """Orchestrates configured O2, O3, and simulation-only mitigation components."""

    def __init__(
        self,
        settings: Settings,
        mitigation_engine: MitigationEngine | None = None,
    ) -> None:
        self._settings = settings
        o2_path = settings.o2_model_path
        o3_path = settings.o3_model_path
        if getattr(settings, "demo_mode", False):
            if o2_path is None and settings.demo_o2_model_path.exists():
                o2_path = settings.demo_o2_model_path
            if o3_path is None and settings.demo_o3_model_path.exists():
                o3_path = settings.demo_o3_model_path
        self._o2 = self._load_o2(o2_path)
        self._o3 = self._load_o3(o3_path)
        self._mitigation = mitigation_engine or MitigationEngine(config=MitigationConfig())

    def analyze(self, request: DetectionAnalyzeRequest) -> DetectionAnalyzeResponse:
        if isinstance(request, dict):
            try:
                request = DetectionAnalyzeRequest.model_validate(request)
            except Exception as exc:
                raise PredictionFailureError("Invalid detection request") from exc
        request_id = uuid4()
        started = perf_counter()
        self.validate_feature_contract(request)

        feature_started = perf_counter()
        frame = self._prepare_features(request)
        feature_latency = self._elapsed_ms(feature_started)

        o2_started = perf_counter()
        try:
            o2_prediction = predict_o2(self._o2.model, frame, self._o2.feature_columns)
            o2_label = int(o2_prediction.iloc[0])
            o2_confidence = self._prediction_confidence(
                self._o2.model, frame, self._o2.feature_columns, o2_label
            )
        except (O2FeatureContractError, ValueError, TypeError, AttributeError) as exc:
            logger.exception("O2 prediction failed for configured feature contract")
            raise PredictionFailureError("O2 prediction failed for the supplied feature contract") from exc
        o2_latency = self._elapsed_ms(o2_started)

        o3_latency = 0.0
        classification = ClassificationResponse(
            available=False,
            threshold=float(self._mitigation.config.confirmed_attack_confidence),
            decision_method="argmax_posterior_probability",
            model_version=self._o3.feature_metadata.get("model_version"),
        )
        attack_type = "BENIGN" if o2_label == 0 else None
        confidence = o2_confidence

        if o2_label == 1:
            o3_started = perf_counter()
            try:
                o3_prediction = predict_o3(
                    self._o3.model,
                    frame,
                    self._o3.feature_columns,
                    self._o3.feature_metadata,
                )
                attack_type = str(o3_prediction["predictions"][0])
                probabilities = o3_prediction["probabilities"]
                probability_row = probabilities[0] if probabilities else None
                confidence = max(probability_row.values()) if probability_row else o2_confidence
                classification = ClassificationResponse(
                    available=True,
                    attack_type=attack_type,
                    confidence=confidence,
                    probabilities=probability_row,
                    threshold=float(self._mitigation.config.confirmed_attack_confidence),
                    decision_method="argmax_posterior_probability",
                    model_version=self._o3.feature_metadata.get("model_version"),
                )
            except (O3FeatureContractError, ValueError, TypeError, AttributeError, KeyError) as exc:
                raise PredictionFailureError("O3 prediction failed for the supplied feature contract") from exc
            o3_latency = self._elapsed_ms(o3_started)

        mitigation_started = perf_counter()
        try:
            mitigation_decision = self._mitigation.analyze_detection(
                DetectionResult(
                    attack_type=attack_type or "UNKNOWN",
                    confidence=confidence,
                    traffic_rate=request.traffic_rate,
                    source_identifier=request.source_identifier,
                )
            )
            audit_event = self._mitigation.audit.events()[-1]
        except (MitigationInputError, MitigationExecutionError, IndexError, ValueError) as exc:
            raise PredictionFailureError("Mitigation decision failed safely") from exc
        mitigation_latency = self._elapsed_ms(mitigation_started)

        # Resolve flow metadata for observability (strictly excluded from ML features)
        src_ip = None
        src_port = None
        dst_ip = None
        dst_port = None
        proto_str = None
        flow_ts = None

        if request.metadata:
            src_ip = request.metadata.source_ip
            src_port = request.metadata.source_port
            dst_ip = request.metadata.destination_ip
            dst_port = request.metadata.destination_port
            proto_str = request.metadata.protocol
            flow_ts = request.metadata.timestamp

        src_ip = src_ip or request.source_ip
        src_port = src_port or request.source_port
        dst_ip = dst_ip or request.destination_ip
        dst_port = dst_port or request.destination_port
        proto_str = proto_str or request.protocol
        flow_ts = flow_ts or request.timestamp

        if not src_ip:
            if request.source_identifier.startswith("controlled_simulator:"):
                parts = request.source_identifier.split(":")
                scen = parts[1] if len(parts) > 1 else "benign"
                if "attack" in scen or "netbios" in scen:
                    src_ip = "198.51.100.15"
                    src_port = 137
                    dst_ip = dst_ip or "10.0.0.1"
                    dst_port = dst_port or 137
                    proto_str = proto_str or "UDP"
                elif "flash" in scen:
                    src_ip = "192.168.1.60"
                    src_port = 58922
                    dst_ip = dst_ip or "10.0.0.1"
                    dst_port = dst_port or 443
                    proto_str = proto_str or "TCP"
                else:
                    src_ip = "192.168.1.50"
                    src_port = 54321
                    dst_ip = dst_ip or "10.0.0.1"
                    dst_port = dst_port or 80
                    proto_str = proto_str or "UDP"
            elif request.source_identifier.startswith("demo:"):
                scen = request.source_identifier.split(":", 1)[1]
                if "attack" in scen or "netbios" in scen:
                    src_ip = "198.51.100.15"
                    src_port = 137
                    dst_ip = dst_ip or "10.0.0.1"
                    dst_port = dst_port or 137
                    proto_str = proto_str or "UDP"
                elif "flash" in scen:
                    src_ip = "192.168.1.60"
                    src_port = 58922
                    dst_ip = dst_ip or "10.0.0.1"
                    dst_port = dst_port or 443
                    proto_str = proto_str or "TCP"
                else:
                    src_ip = "192.168.1.50"
                    src_port = 54321
                    dst_ip = dst_ip or "10.0.0.1"
                    dst_port = dst_port or 80
                    proto_str = proto_str or "UDP"
            elif any(c.isdigit() for c in request.source_identifier) and "." in request.source_identifier:
                src_ip = request.source_identifier
            else:
                src_ip = "192.168.1.50"

        if not dst_ip:
            dst_ip = "10.0.0.1"
        if not src_port:
            src_port = 54321
        if not dst_port:
            proto_val = request.features.get("Protocol")
            if proto_val == 6.0:
                dst_port = 443
            elif proto_val == 17.0:
                dst_port = 53
            else:
                dst_port = 80
        if not proto_str:
            proto_val = request.features.get("Protocol")
            if proto_val == 6.0:
                proto_str = "TCP"
            elif proto_val == 17.0:
                proto_str = "UDP"
            elif proto_val == 0.0:
                proto_str = "HOPOPT"
            elif proto_val is not None:
                proto_str = f"Proto-{int(proto_val)}"
            else:
                proto_str = "TCP"
        if not flow_ts:
            flow_ts = format_iso_utc(self._utc_now())

        flow_metadata = FlowMetadata(
            source_ip=src_ip,
            source_port=src_port,
            destination_ip=dst_ip,
            destination_port=dst_port,
            protocol=proto_str,
            timestamp=flow_ts,
        )

        response = DetectionAnalyzeResponse(
            request_id=request_id,
            timestamp=self._utc_now(),
            source_identifier=request.source_identifier,
            traffic_rate=request.traffic_rate,
            metadata=flow_metadata,
            o2=BinaryDetectionResponse(
                detected=bool(o2_label),
                label=o2_label,
                confidence=o2_confidence,
                threshold=float(self._o2.metadata.get("decision_threshold", 0.50)),
                model_version=str(self._o2.metadata.get("model_version", "unknown")),
            ),
            o3=classification,
            mitigation=MitigationResponse(
                decision=mitigation_decision.decision.value,
                reason=mitigation_decision.reason,
                decision_id=mitigation_decision.decision_id,
                policy_version=mitigation_decision.policy_version,
                state=mitigation_decision.state.value,
                duration_seconds=int((mitigation_decision.expires_at - mitigation_decision.created_at).total_seconds()) if mitigation_decision.expires_at else None,
                expires_at=mitigation_decision.expires_at,
                executor_type=audit_event.executor_type,
                simulation_only=audit_event.executor_type == "simulated",
                audit_event_id=audit_event.event_id,
                parameters=dict(mitigation_decision.parameters or {}),
            ),
            latency=LatencyResponse(
                feature_preparation_ms=feature_latency,
                o2_inference_ms=o2_latency,
                o3_inference_ms=o3_latency,
                mitigation_decision_ms=mitigation_latency,
                total_analysis_ms=self._elapsed_ms(started),
            ),
            artifact_scope={
                "demo_mode": getattr(self._settings, "demo_mode", False),
                "dataset_note": "REAL CIC-DDoS2019 SAMPLE — NOT OFFICIAL ACCEPTANCE" if getattr(self._settings, "demo_mode", False) else ("FIXTURE ONLY" if self._settings.o2_fixture_only else "STANDARD"),
                "o2_fixture_only": self._settings.o2_fixture_only and not getattr(self._settings, "demo_mode", False),
                "o3_fixture_only": self._settings.o3_fixture_only and not getattr(self._settings, "demo_mode", False),
                "real_cic_ddos2019_evaluation_available": False,
            },
        )
        telemetry_store.record_detection(
            response.latency.total_analysis_ms,
            response.mitigation.decision,
            request.source_identifier.startswith("controlled_simulator:"),
        )
        # Database persistence integration (wrapped with safety guard)
        try:
            from app.db.database import get_session_factory
            from app.db.repository import persist_detection_event

            session_factory = get_session_factory()
            with session_factory() as db_session:
                persist_detection_event(db_session, response, actor="system")
        except Exception as exc:
            logger.warning("Database persistence skipped: %s", exc)

        return response

    def _load_o2(self, model_path: Path | None) -> LoadedO2:
        if model_path is None:
            raise ModelUnavailableError("O2 model artifact is not configured")
        try:
            model, feature_columns, metadata = load_o2_artifact(model_path)
        except Exception as exc:
            raise ModelUnavailableError("Configured O2 model artifact is unavailable") from exc
        if metadata.get("target_column") != "label_binary":
            raise IncompatibleModelError("Configured O2 artifact does not target label_binary")
        return LoadedO2(model, feature_columns, metadata)

    def _load_o3(self, model_path: Path | None) -> LoadedO3:
        if model_path is None:
            raise ModelUnavailableError("O3 model artifact is not configured")
        try:
            model, feature_columns, feature_metadata, class_metadata = load_o3_artifact(model_path)
        except Exception as exc:
            raise ModelUnavailableError("Configured O3 model artifact is unavailable") from exc
        if feature_metadata.get("target_column") != "label_normalized":
            raise IncompatibleModelError("Configured O3 artifact does not target label_normalized")
        if not class_metadata.get("available_classes"):
            raise IncompatibleModelError("Configured O3 artifact has no class metadata")
        return LoadedO3(model, feature_columns, feature_metadata, class_metadata)

    def validate_feature_contract(self, request: DetectionAnalyzeRequest) -> None:
        required = set(self._o2.feature_columns) | set(self._o3.feature_columns)
        supplied = set(request.features)
        missing = sorted(required - supplied)
        unexpected = sorted(supplied - required)
        if missing:
            raise FeatureContractError(f"Missing configured model features: {missing}")
        if unexpected:
            raise FeatureContractError(f"Unexpected configured model features: {unexpected}")

    @staticmethod
    def _prepare_features(request: DetectionAnalyzeRequest) -> pd.DataFrame:
        return pd.DataFrame([{name: value for name, value in request.features.items()}])

    @staticmethod
    def _prediction_confidence(
        model: object,
        frame: pd.DataFrame,
        feature_columns: list[str],
        label: int,
    ) -> float:
        if not hasattr(model, "predict_proba"):
            raise PredictionFailureError("Configured O2 model does not provide confidence probabilities")
        probabilities = model.predict_proba(frame[feature_columns])[0]
        classes = list(getattr(model, "classes_", []))
        if label not in classes:
            raise PredictionFailureError("Configured O2 model returned an incompatible class")
        return float(probabilities[classes.index(label)])

    @staticmethod
    def _elapsed_ms(started: float) -> float:
        return (perf_counter() - started) * 1000.0

    @staticmethod
    def _utc_now():
        return now_utc()


@lru_cache
def get_detection_service() -> DetectionService:
    return DetectionService(get_settings())

from datetime import datetime, timedelta, timezone
from threading import RLock
from typing import Callable, Protocol

from ml.mitigation.audit import AuditTrail, new_event_id
from ml.mitigation.config import MitigationConfig
from ml.mitigation.models import (
    AuditEvent,
    DecisionAction,
    DetectionResult,
    ExecutionResult,
    MitigationDecision,
    MitigationState,
    RecoveryRecord,
    utc_now,
)
from ml.mitigation.policy import MitigationPolicyError, decide_policy
from ml.mitigation.recovery import new_decision_id, recover_decision


class MitigationInputError(ValueError):
    """Raised when an input cannot be safely converted into a detection result."""


class MitigationExecutionError(RuntimeError):
    """Raised when the configured mitigation executor cannot record an action."""


class MitigationExecutor(Protocol):
    executor_type: str

    def execute(self, decision: MitigationDecision, now: datetime) -> ExecutionResult:
        """Record a safe action without changing external infrastructure."""


class SimulatedMitigationExecutor:
    """Sandbox executor: records actions in memory and performs no network operation."""

    executor_type = "simulated"

    def __init__(self) -> None:
        self._executions: list[ExecutionResult] = []
        self._lock = RLock()

    def execute(self, decision: MitigationDecision, now: datetime) -> ExecutionResult:
        result = ExecutionResult(
            executor_type=self.executor_type,
            action=decision.decision,
            success=True,
            executed_at=now,
        )
        with self._lock:
            self._executions.append(result)
        return result

    def executions(self) -> tuple[ExecutionResult, ...]:
        with self._lock:
            return tuple(self._executions)


class MitigationEngine:
    """Policy decision boundary for future O2/O3-to-service integration."""

    def __init__(
        self,
        config: MitigationConfig | None = None,
        executor: MitigationExecutor | None = None,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        if config is None:
            raise MitigationInputError("A mitigation policy configuration is required")
        self.config = config
        self.executor = executor or SimulatedMitigationExecutor()
        self.clock = clock
        self.audit = AuditTrail()
        self._decisions: dict[str, MitigationDecision] = {}
        self._recoveries: list[RecoveryRecord] = []
        self._lock = RLock()

    def analyze_detection(
        self,
        detection_result: DetectionResult | dict[str, object],
    ) -> MitigationDecision:
        detection = self._validate_detection(detection_result)
        now = self._now()
        self._expire_due(now)
        try:
            policy = decide_policy(detection, self.config)
        except MitigationPolicyError as exc:
            raise MitigationInputError(str(exc)) from exc

        expires_at = None
        if policy.duration_seconds is not None:
            duration = min(policy.duration_seconds, self.config.state_expiry_seconds)
            expires_at = now + timedelta(seconds=duration)

        decision = MitigationDecision(
            decision_id=new_decision_id(),
            decision=policy.action,
            reason=policy.reason,
            attack_type=detection.attack_type,
            confidence=detection.confidence,
            source_identifier=detection.source_identifier,
            created_at=now,
            expires_at=expires_at,
            policy_version=self.config.policy_version,
            state=MitigationState.ACTIVE,
            parameters=policy.parameters,
        )

        execution = self._execute(decision, now)
        with self._lock:
            self._decisions[decision.decision_id] = decision
        self._record_audit(
            decision=decision,
            event_type="DECISION",
            state_transition="NONE->ACTIVE",
            execution=execution,
        )
        return decision

    def get_active_state(self, source_identifier: str) -> MitigationDecision | None:
        if not source_identifier or source_identifier.strip() != source_identifier:
            raise MitigationInputError("source_identifier must be a non-empty printable identifier")
        now = self._now()
        self._expire_due(now)
        with self._lock:
            candidates = [
                decision
                for decision in self._decisions.values()
                if decision.source_identifier == source_identifier
                and decision.state is MitigationState.ACTIVE
                and decision.decision is not DecisionAction.ALLOW
            ]
        return candidates[-1] if candidates else None

    def revoke(self, decision_id: str) -> RecoveryRecord:
        if not decision_id:
            raise MitigationInputError("decision_id is required for revoke")
        now = self._now()
        self._expire_due(now)
        with self._lock:
            decision = self._decisions.get(decision_id)
        if decision is None:
            raise MitigationInputError(f"Unknown mitigation decision: {decision_id}")
        if decision.state is not MitigationState.ACTIVE or decision.expires_at is None:
            raise MitigationInputError(f"Decision {decision_id} is not an active temporary mitigation")

        recovery = recover_decision(decision, now, "Explicit mitigation revoke/reset")
        decision.state = recovery.new_state
        self._record_recovery(decision, recovery, now)
        return recovery

    def audit_records(self) -> list[dict[str, object]]:
        return self.audit.records()

    def recovery_records(self) -> tuple[RecoveryRecord, ...]:
        with self._lock:
            return tuple(self._recoveries)

    def _validate_detection(
        self,
        detection_result: DetectionResult | dict[str, object],
    ) -> DetectionResult:
        try:
            if isinstance(detection_result, DetectionResult):
                return detection_result
            if not isinstance(detection_result, dict):
                raise TypeError("detection result must be a DetectionResult or object mapping")
            return DetectionResult.model_validate(detection_result)
        except Exception as exc:
            raise MitigationInputError(f"Invalid detection result; no action taken: {exc}") from exc

    def _execute(self, decision: MitigationDecision, now: datetime) -> ExecutionResult:
        try:
            result = self.executor.execute(decision, now)
        except Exception as exc:
            self._record_audit(
                decision=decision,
                event_type="DECISION",
                state_transition="NONE->FAILED",
                execution=ExecutionResult(
                    executor_type=getattr(self.executor, "executor_type", "unknown"),
                    action=decision.decision,
                    success=False,
                    executed_at=now,
                    error=str(exc),
                ),
            )
            raise MitigationExecutionError(f"Mitigation action was not recorded: {exc}") from exc
        if not result.success:
            raise MitigationExecutionError(result.error or "Mitigation executor reported failure")
        return result

    def _record_audit(
        self,
        decision: MitigationDecision,
        event_type: str,
        state_transition: str,
        execution: ExecutionResult,
    ) -> None:
        self.audit.record(
            AuditEvent(
                event_id=new_event_id(),
                event_type=event_type,
                timestamp=execution.executed_at,
                decision_id=decision.decision_id,
                action=execution.action,
                reason=decision.reason,
                attack_type=decision.attack_type,
                confidence=decision.confidence,
                source_identifier=decision.source_identifier,
                policy_version=decision.policy_version,
                state_transition=state_transition,
                executor_type=execution.executor_type,
                success=execution.success,
                error=execution.error,
                expires_at=decision.expires_at,
            )
        )

    def _record_recovery(
        self,
        decision: MitigationDecision,
        recovery: RecoveryRecord,
        now: datetime,
    ) -> None:
        with self._lock:
            self._recoveries.append(recovery)
        execution = self.executor.execute(
            decision.model_copy(update={"decision": DecisionAction.ALLOW}),
            now,
        )
        self._record_audit(
            decision=decision,
            event_type="RECOVERY",
            state_transition=f"{recovery.previous_state}->{recovery.new_state}",
            execution=execution,
        )

    def _expire_due(self, now: datetime) -> None:
        with self._lock:
            due = [
                decision
                for decision in self._decisions.values()
                if decision.state is MitigationState.ACTIVE
                and decision.expires_at is not None
                and decision.expires_at <= now
            ]
        for decision in due:
            recovery = recover_decision(decision, now, "Temporary mitigation expired")
            decision.state = recovery.new_state
            self._record_recovery(decision, recovery, now)

    def _now(self) -> datetime:
        value = self.clock()
        if value.tzinfo is None or value.utcoffset() is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

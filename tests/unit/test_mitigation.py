from datetime import datetime, timedelta, timezone

import pytest

from ml.mitigation.config import MitigationConfig
from ml.mitigation.engine import MitigationEngine, MitigationInputError, SimulatedMitigationExecutor
from ml.mitigation.models import DecisionAction, DetectionResult, MitigationState
from ml.mitigation.policy import decide_policy


class ControlledClock:
    def __init__(self) -> None:
        self.value = datetime(2026, 9, 20, 12, 0, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.value

    def advance(self, seconds: int) -> None:
        self.value += timedelta(seconds=seconds)


def make_engine():
    clock = ControlledClock()
    executor = SimulatedMitigationExecutor()
    engine = MitigationEngine(config=MitigationConfig(), executor=executor, clock=clock)
    return engine, executor, clock


def detection(attack_type="BENIGN", confidence=0.99, traffic_rate=None, source="192.0.2.10"):
    return DetectionResult(
        attack_type=attack_type,
        confidence=confidence,
        traffic_rate=traffic_rate,
        source_identifier=source,
    )


def test_benign_is_allowed():
    engine, executor, _ = make_engine()
    decision = engine.analyze_detection(detection())
    assert decision.decision is DecisionAction.ALLOW
    assert decision.expires_at is None
    assert executor.executions()[0].action is DecisionAction.ALLOW
    assert engine.audit_records()[0]["policy_version"] == "mitigation-policy-0.1.0"


def test_legitimate_flash_crowd_is_rate_limited():
    engine, _, _ = make_engine()
    decision = engine.analyze_detection(
        detection(attack_type="BENIGN", confidence=0.95, traffic_rate=1500.0)
    )
    assert decision.decision is DecisionAction.RATE_LIMIT
    assert decision.parameters["requests_per_second"] == 100.0
    assert "flash-crowd" in decision.reason


def test_confirmed_ddos_is_blocked():
    engine, _, _ = make_engine()
    decision = engine.analyze_detection(
        detection(attack_type="DRDOS_DNS", confidence=0.95)
    )
    assert decision.decision is DecisionAction.BLOCK
    assert decision.expires_at is not None
    assert decision.expires_at - decision.created_at == timedelta(seconds=300)


def test_low_confidence_known_attack_is_contained_without_allow():
    engine, _, _ = make_engine()
    decision = engine.analyze_detection(detection(attack_type="SYN", confidence=0.4))
    assert decision.decision is DecisionAction.RATE_LIMIT


def test_unknown_attack_type_fails_securely():
    engine, executor, _ = make_engine()
    with pytest.raises(MitigationInputError, match="Unknown attack type"):
        engine.analyze_detection(detection(attack_type="UNKNOWN", confidence=0.99))
    assert executor.executions() == ()
    assert engine.audit_records() == []


def test_invalid_detection_payload_and_confidence_fail_securely():
    engine, executor, _ = make_engine()
    with pytest.raises(MitigationInputError, match="Invalid detection"):
        engine.analyze_detection({"attack_type": "BENIGN", "confidence": 1.5})
    with pytest.raises(MitigationInputError, match="Invalid detection"):
        engine.analyze_detection({"attack_type": "BENIGN"})
    with pytest.raises(MitigationInputError, match="Invalid detection"):
        engine.analyze_detection(
            {"attack_type": "BENIGN", "confidence": 0.9, "source_identifier": " bad "}
        )
    assert executor.executions() == ()


def test_expiry_recovers_state_and_records_audit():
    engine, executor, clock = make_engine()
    decision = engine.analyze_detection(detection(attack_type="DRDOS_DNS", confidence=0.99))
    assert engine.get_active_state("192.0.2.10") == decision
    clock.advance(301)
    assert engine.get_active_state("192.0.2.10") is None
    assert decision.state is MitigationState.RECOVERED
    assert engine.recovery_records()[0].reason == "Temporary mitigation expired"
    assert engine.audit_records()[-1]["event_type"] == "RECOVERY"
    assert executor.executions()[-1].action is DecisionAction.ALLOW


def test_explicit_revoke_recovers_state():
    engine, _, _ = make_engine()
    decision = engine.analyze_detection(detection(attack_type="SYN", confidence=0.99))
    recovery = engine.revoke(decision.decision_id)
    assert recovery.new_state is MitigationState.RECOVERED
    assert decision.state is MitigationState.RECOVERED
    assert engine.get_active_state("192.0.2.10") is None
    assert engine.audit_records()[-1]["state_transition"] == "ACTIVE->RECOVERED"


def test_audit_event_is_structured_and_contains_no_secrets():
    engine, _, _ = make_engine()
    decision = engine.analyze_detection(detection(attack_type="TFTP", confidence=0.91))
    event = engine.audit.events()[0]
    record = event.to_record()
    assert record["decision_id"] == decision.decision_id
    assert record["action"] == "BLOCK"
    assert record["executor_type"] == "simulated"
    assert record["success"] is True
    assert "password" not in record
    assert "token" not in record
    assert "secret" not in record


def test_decision_ids_are_unique_and_policy_is_deterministic():
    engine, _, _ = make_engine()
    first = engine.analyze_detection(detection(attack_type="BENIGN"))
    second = engine.analyze_detection(detection(attack_type="BENIGN"))
    assert first.decision_id != second.decision_id
    policy_a = decide_policy(detection(attack_type="DRDOS_DNS", confidence=0.9), engine.config)
    policy_b = decide_policy(detection(attack_type="DRDOS_DNS", confidence=0.9), engine.config)
    assert policy_a == policy_b


def test_expired_decisions_are_not_active_and_revoke_cannot_retain_stale_state():
    engine, _, clock = make_engine()
    decision = engine.analyze_detection(detection(attack_type="DRDOS_DNS", confidence=0.99))
    clock.advance(301)
    assert engine.get_active_state("192.0.2.10") is None
    with pytest.raises(MitigationInputError, match="not an active"):
        engine.revoke(decision.decision_id)


def test_simulated_executor_records_only_local_actions():
    engine, executor, _ = make_engine()
    engine.analyze_detection(detection(attack_type="DRDOS_DNS", confidence=0.99))
    assert executor.executor_type == "simulated"
    assert len(executor.executions()) == 1
    assert all(result.success for result in executor.executions())


def test_configuration_rejects_invalid_policy_values():
    with pytest.raises(ValueError, match="between 0 and 1"):
        MitigationConfig(confirmed_attack_confidence=2.0)
    with pytest.raises(ValueError, match="greater than zero"):
        MitigationConfig(block_duration_seconds=0)

from datetime import datetime, timezone
from uuid import uuid4

from ml.mitigation.models import MitigationDecision, MitigationState, RecoveryRecord


def recover_decision(
    decision: MitigationDecision,
    now: datetime,
    reason: str,
    new_state: MitigationState = MitigationState.RECOVERED,
) -> RecoveryRecord:
    if decision.state is not MitigationState.ACTIVE:
        raise ValueError(f"Decision {decision.decision_id} is not active")
    if now.tzinfo is None or now.utcoffset() is None:
        now = now.replace(tzinfo=timezone.utc)
    return RecoveryRecord(
        decision_id=decision.decision_id,
        source_identifier=decision.source_identifier,
        previous_state=decision.state,
        new_state=new_state,
        recovered_at=now.astimezone(timezone.utc),
        reason=reason,
    )


def new_decision_id() -> str:
    return str(uuid4())

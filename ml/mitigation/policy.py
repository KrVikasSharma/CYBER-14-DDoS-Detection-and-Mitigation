from dataclasses import dataclass

from ml.mitigation.config import MitigationConfig
from ml.mitigation.models import DecisionAction, DetectionResult


class MitigationPolicyError(ValueError):
    """Raised when a detection cannot be safely mapped to a mitigation action."""


@dataclass(frozen=True)
class PolicyDecision:
    action: DecisionAction
    reason: str
    duration_seconds: int | None
    parameters: dict[str, float | int | str]


def decide_policy(
    detection: DetectionResult,
    config: MitigationConfig,
) -> PolicyDecision:
    attack_type = detection.attack_type.upper()
    trusted = {label.upper() for label in config.trusted_classes}
    attacks = {label.upper() for label in config.known_attack_classes}

    if attack_type not in trusted and attack_type not in attacks:
        raise MitigationPolicyError(f"Unknown attack type cannot be safely mitigated: {attack_type}")

    if attack_type in trusted:
        if (
            detection.traffic_rate is not None
            and detection.traffic_rate > config.flash_crowd_rate_threshold
            and detection.confidence >= config.legitimate_confidence
        ):
            return PolicyDecision(
                action=DecisionAction.RATE_LIMIT,
                reason=(
                    "Trusted classification with sustained traffic above the configured "
                    "flash-crowd threshold; contain volume without treating it as malicious."
                ),
                duration_seconds=config.rate_limit_duration_seconds,
                parameters={
                    "requests_per_second": config.rate_limit_requests_per_second,
                    "traffic_rate_threshold": config.flash_crowd_rate_threshold,
                    "flash_crowd_rate_threshold": config.flash_crowd_rate_threshold,
                    "rate_limit_duration_seconds": config.rate_limit_duration_seconds,
                },
            )
        return PolicyDecision(
            action=DecisionAction.ALLOW,
            reason="Trusted legitimate classification is below the flash-crowd containment threshold.",
            duration_seconds=None,
            parameters={
                "traffic_rate_threshold": config.flash_crowd_rate_threshold,
                "flash_crowd_rate_threshold": config.flash_crowd_rate_threshold,
                "legitimate_confidence_threshold": config.legitimate_confidence,
            },
        )

    if detection.confidence >= config.confirmed_attack_confidence:
        return PolicyDecision(
            action=DecisionAction.BLOCK,
            reason="Known attack classification meets the confirmed-attack confidence threshold.",
            duration_seconds=config.block_duration_seconds,
            parameters={
                "confirmed_confidence_threshold": config.confirmed_attack_confidence,
                "block_duration_seconds": config.block_duration_seconds,
            },
        )

    action = DecisionAction(config.uncertain_attack_action)
    return PolicyDecision(
        action=action,
        reason=(
            "Known attack classification is below the confirmed threshold; use configured "
            "temporary containment while avoiding an unverified permanent block."
        ),
        duration_seconds=(
            config.rate_limit_duration_seconds
            if action is DecisionAction.RATE_LIMIT
            else config.block_duration_seconds
        ),
        parameters={
            "confirmed_confidence_threshold": config.confirmed_attack_confidence,
            "duration_seconds": (
                config.rate_limit_duration_seconds
                if action is DecisionAction.RATE_LIMIT
                else config.block_duration_seconds
            ),
        },
    )

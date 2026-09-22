from dataclasses import dataclass, field


@dataclass(frozen=True)
class MitigationConfig:
    """Defensive policy settings; no network credentials or infrastructure commands."""

    policy_version: str = "mitigation-policy-0.1.0"
    trusted_classes: tuple[str, ...] = ("BENIGN", "NORMAL", "LEGITIMATE")
    confirmed_attack_confidence: float = 0.80
    legitimate_confidence: float = 0.80
    flash_crowd_rate_threshold: float = 1000.0
    flash_crowd_action: str = "RATE_LIMIT"
    uncertain_attack_action: str = "RATE_LIMIT"
    rate_limit_requests_per_second: float = 100.0
    rate_limit_duration_seconds: int = 60
    block_duration_seconds: int = 300
    recovery_action: str = "ALLOW"
    state_expiry_seconds: int = 900
    known_attack_classes: tuple[str, ...] = field(
        default=(
            "DDOS",
            "DRDOS_DNS",
            "DRDOS_LDAP",
            "DRDOS_MSSQL",
            "DRDOS_NETBIOS",
            "DRDOS_NTP",
            "DRDOS_SNMP",
            "DRDOS_SSDP",
            "DRDOS_UDP",
            "SYN",
            "TFTP",
            "UDP-LAG",
            "UDPLAG",
            "WEB-DDOS",
            "WEBDDOS",
            "PORTMAP",
            "LDAP",
            "MSSQL",
            "NETBIOS",
            "UDP",
        )
    )

    def __post_init__(self) -> None:
        if not self.policy_version.strip():
            raise ValueError("policy_version must not be empty")
        if not 0.0 <= self.confirmed_attack_confidence <= 1.0:
            raise ValueError("confirmed_attack_confidence must be between 0 and 1")
        if not 0.0 <= self.legitimate_confidence <= 1.0:
            raise ValueError("legitimate_confidence must be between 0 and 1")
        if self.flash_crowd_rate_threshold <= 0:
            raise ValueError("flash_crowd_rate_threshold must be greater than zero")
        if self.flash_crowd_action not in {"RATE_LIMIT"}:
            raise ValueError("flash_crowd_action must be RATE_LIMIT")
        if self.uncertain_attack_action not in {"RATE_LIMIT", "BLOCK"}:
            raise ValueError("uncertain_attack_action must be RATE_LIMIT or BLOCK")
        if self.rate_limit_requests_per_second <= 0:
            raise ValueError("rate_limit_requests_per_second must be greater than zero")
        if self.rate_limit_duration_seconds <= 0:
            raise ValueError("rate_limit_duration_seconds must be greater than zero")
        if self.block_duration_seconds <= 0:
            raise ValueError("block_duration_seconds must be greater than zero")
        if self.state_expiry_seconds <= 0:
            raise ValueError("state_expiry_seconds must be greater than zero")
        if self.recovery_action != "ALLOW":
            raise ValueError("recovery_action must be ALLOW")

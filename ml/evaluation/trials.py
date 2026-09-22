from dataclasses import dataclass
from typing import Any, Callable, Iterable


@dataclass(frozen=True)
class OracleResult:
    expected_class: str | None = None
    expected_binary_attack: bool | None = None
    expected_mitigation: str | None = None


@dataclass(frozen=True)
class TrialResult:
    trial_id: str
    input_record: dict[str, Any]
    observed_record: dict[str, Any]
    oracle: OracleResult | None
    status: str
    error: str | None = None


def _oracle_mismatches(
    observed: dict[str, Any], oracle: OracleResult | None
) -> list[str]:
    if not isinstance(oracle, OracleResult):
        return ["oracle is missing or malformed"]

    expected = {
        "class": oracle.expected_class,
        "binary_attack": oracle.expected_binary_attack,
        "mitigation": oracle.expected_mitigation,
    }
    if all(value is None for value in expected.values()):
        return ["oracle does not define any expected result fields"]
    if oracle.expected_class is not None and not isinstance(oracle.expected_class, str):
        return ["oracle expected_class must be a string or null"]
    if oracle.expected_binary_attack is not None and not isinstance(oracle.expected_binary_attack, bool):
        return ["oracle expected_binary_attack must be a boolean or null"]
    if oracle.expected_mitigation is not None and not isinstance(oracle.expected_mitigation, str):
        return ["oracle expected_mitigation must be a string or null"]

    o2 = observed.get("o2")
    o3 = observed.get("o3")
    mitigation = observed.get("mitigation")
    actual = {
        "class": observed.get("attack_type", observed.get("class", o3.get("attack_type") if isinstance(o3, dict) else None)),
        "binary_attack": observed.get("binary_attack", observed.get("detected", o2.get("detected") if isinstance(o2, dict) else None)),
        "mitigation": observed.get("decision", mitigation.get("decision") if isinstance(mitigation, dict) else mitigation),
    }
    return [
        f"{field}: expected {expected[field]!r}, observed {actual[field]!r}"
        for field in expected
        if expected[field] is not None and actual[field] != expected[field]
    ]


def execute_trials(
    cases: Iterable[tuple[str, dict[str, Any], OracleResult | None]],
    operation: Callable[[dict[str, Any]], dict[str, Any]],
) -> list[TrialResult]:
    results: list[TrialResult] = []
    for trial_id, input_record, oracle in cases:
        try:
            observed = operation(input_record)
            mismatches = _oracle_mismatches(observed, oracle)
            results.append(TrialResult(
                trial_id,
                input_record,
                observed,
                oracle,
                "PASS" if not mismatches else "FAIL",
                None if not mismatches else "; ".join(mismatches),
            ))
        except Exception as exc:
            results.append(
                TrialResult(trial_id, input_record, {}, oracle, "FAIL", f"{type(exc).__name__}: {exc}")
            )
    return results

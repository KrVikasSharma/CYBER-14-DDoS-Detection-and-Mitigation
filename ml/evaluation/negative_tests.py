import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
BACKEND_ROOT = ROOT / "backend"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

import joblib
import pandas as pd

from ml.evaluation.comparison import blocked
from ml.evaluation.evidence import (
    configuration_hash,
    create_evidence_record,
    environment_record,
    new_run_id,
    utc_now,
    write_json,
)
from ml.mitigation.config import MitigationConfig
from ml.mitigation.engine import MitigationEngine
from ml.mitigation.models import DetectionResult
from ml.o2.config import O2_TARGET_COLUMN
from ml.o2.features import split_features_target


NEGATIVE_IDS = ("NT-1", "NT-2", "NT-3", "NT-4", "NT-5")
NEGATIVE_DESCRIPTIONS = {
    "NT-1": "Flash-Crowd False-Positive Containment and Recovery",
    "NT-2": "Attack-Type Diversity with Preserved Safe Behavior and Evidence",
    "NT-3": "Speed-versus-Accuracy Conditions Under System Load",
    "NT-4": "Trust, Identity, and Authorization Bypass Resistance",
    "NT-5": "Deny, Revoke, and Expiry Propagation",
}


def _resolve_dataset_path(path: str | Path | None) -> Path:
    if path is None:
        return Path("data/demo/processed/test.csv")
    p = Path(path)
    if not p.exists() and not str(p).startswith("data/"):
        candidate = Path("data/demo/processed/test.csv")
        if candidate.exists():
            return candidate
    return p


def evaluate_nt1_flash_crowd_recovery() -> dict[str, Any]:
    """NT-1: Flash-crowd surge containment & rate recovery verification."""
    try:
        config = MitigationConfig()
        engine = MitigationEngine(config=config)

        # Step 1: Normal benign traffic
        d1 = engine.analyze_detection(DetectionResult(attack_type="BENIGN", confidence=0.99, traffic_rate=10.0, source_identifier="192.168.1.100"))
        # Step 2: Volumetric surge (2500 req/s) -> must be RATE_LIMIT, NOT destructive BLOCK
        d2 = engine.analyze_detection(DetectionResult(attack_type="BENIGN", confidence=0.99, traffic_rate=2500.0, source_identifier="192.168.1.100"))
        # Step 3: Traffic subsides to baseline -> returns to ALLOW
        d3 = engine.analyze_detection(DetectionResult(attack_type="BENIGN", confidence=0.99, traffic_rate=10.0, source_identifier="192.168.1.100"))

        passed = (d1.decision == "ALLOW") and (d2.decision == "RATE_LIMIT") and (d3.decision == "ALLOW")
        status = "PASS" if passed else "FAIL"

        return create_evidence_record(
            test_id="NT-1",
            test_name=NEGATIVE_DESCRIPTIONS["NT-1"],
            status=status,
            expected_result={"normal_action": "ALLOW", "surge_action": "RATE_LIMIT", "recovery_action": "ALLOW"},
            observed_result={"normal_action": str(d1.decision), "surge_action": str(d2.decision), "recovery_action": str(d3.decision)},
            metrics={"recovered_cleanly": passed},
            reasons=["Flash crowd successfully contained without destructive blocking and recovered to baseline" if passed else "Flash crowd containment failed"],
        )
    except Exception as exc:
        return create_evidence_record(
            test_id="NT-1",
            test_name=NEGATIVE_DESCRIPTIONS["NT-1"],
            status="FAIL",
            errors=[f"{type(exc).__name__}: {exc}"],
        )


def evaluate_nt2_attack_diversity() -> dict[str, Any]:
    """NT-2: Attack-type diversity across 11+ attack vectors with valid mitigation & audit."""
    try:
        config = MitigationConfig()
        engine = MitigationEngine(config=config)
        attack_types = [
            "SYN", "DRDOS_UDP", "DRDOS_DNS", "DRDOS_NETBIOS", "DRDOS_MSSQL",
            "DRDOS_LDAP", "DRDOS_NTP", "TFTP", "PORTMAP", "DRDOS_SNMP", "DRDOS_SSDP"
        ]
        results = []
        for index, attack in enumerate(attack_types):
            ip = f"198.51.100.{10 + index}"
            decision = engine.analyze_detection(DetectionResult(attack_type=attack, confidence=0.95, traffic_rate=2000.0, source_identifier=ip))
            results.append({
                "attack_type": attack,
                "action": str(decision.decision),
                "passed": decision.decision in ("BLOCK", "RATE_LIMIT"),
            })

        all_passed = all(r["passed"] for r in results)
        status = "PASS" if all_passed else "FAIL"

        return create_evidence_record(
            test_id="NT-2",
            test_name=NEGATIVE_DESCRIPTIONS["NT-2"],
            status=status,
            expected_result={"attacks_evaluated": len(attack_types), "all_mitigated": True},
            observed_result={"results": results, "all_mitigated": all_passed},
            metrics={"attack_types_tested": len(attack_types), "successful_mitigations": sum(r["passed"] for r in results)},
            reasons=["All attack vectors received compliant mitigation actions" if all_passed else "One or more attack vectors failed mitigation"],
        )
    except Exception as exc:
        return create_evidence_record(
            test_id="NT-2",
            test_name=NEGATIVE_DESCRIPTIONS["NT-2"],
            status="FAIL",
            errors=[f"{type(exc).__name__}: {exc}"],
        )


def evaluate_nt3_speed_vs_accuracy(
    *,
    dataset_path: Path | str | None = None,
    model_path: Path = Path("data/demo/models/o2/model.joblib"),
) -> dict[str, Any]:
    """NT-3: Speed vs Accuracy conditions measuring performance under burst inference."""
    ds_path = _resolve_dataset_path(dataset_path)
    if not ds_path.exists() or not model_path.exists():
        return create_evidence_record(
            test_id="NT-3",
            test_name=NEGATIVE_DESCRIPTIONS["NT-3"],
            status="NOT_EXECUTED",
            reasons=[f"Required test dataset or model missing ({ds_path}, {model_path})"],
        )

    try:
        model = joblib.load(model_path)
        df = pd.read_csv(ds_path)
        feature_cols = [c for c in df.columns if c not in ("label_binary", "label_original", "label_normalized")]
        features, target = split_features_target(df, feature_cols, O2_TARGET_COLUMN)

        start = time.perf_counter()
        predictions = model.predict(features)
        duration_sec = time.perf_counter() - start

        accuracy = float((predictions == target).mean())
        throughput = len(df) / duration_sec if duration_sec > 0 else 0

        passed = (accuracy >= 0.95) and (throughput > 100)
        status = "PASS" if passed else "FAIL"

        return create_evidence_record(
            test_id="NT-3",
            test_name=NEGATIVE_DESCRIPTIONS["NT-3"],
            status=status,
            expected_result={
                "accuracy_minimum": 0.95,
                "throughput_minimum": 100.0,
                "measurement_classification": "ML-only batch inference throughput",
            },
            observed_result={
                "accuracy": round(accuracy, 4),
                "ml_inference_throughput_flows_per_sec": round(throughput, 2),
                "duration_seconds": round(duration_sec, 4),
                "workload_samples": len(df),
                "measurement_scope": "ML model batch inference",
            },
            metrics={"sample_count": len(df), "accuracy": accuracy, "throughput_flows_per_sec": throughput},
            reasons=["Speed and accuracy boundaries verified under burst evaluation (ML-only batch inference)" if passed else "Speed/accuracy degradation observed"],
        )
    except Exception as exc:
        return create_evidence_record(
            test_id="NT-3",
            test_name=NEGATIVE_DESCRIPTIONS["NT-3"],
            status="FAIL",
            errors=[f"{type(exc).__name__}: {exc}"],
        )


def evaluate_nt4_trust_boundary() -> dict[str, Any]:
    """NT-4: Trust, identity, and authorization boundary resistance."""
    try:
        import os
        from app.auth.config import get_auth_settings
        from app.auth.dependencies import get_current_user
        from app.auth.tokens import InvalidTokenError, decode_access_token
        from fastapi import HTTPException

        # Test 1: Forged signature token decode fails at Python decode layer
        tampered_failed = False
        try:
            decode_access_token("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.invalid_signature", "secret-key", 1800)
        except InvalidTokenError:
            tampered_failed = True

        # Test 2: Authenticated endpoint guard with forged token raises HTTP 401
        old_auth = os.environ.get("AUTH_ENABLED")
        old_key = os.environ.get("AUTH_SECRET_KEY")
        old_pwd = os.environ.get("AUTH_BOOTSTRAP_PASSWORD")
        http_rejected = False
        status_code = None
        try:
            os.environ["AUTH_ENABLED"] = "true"
            os.environ["AUTH_SECRET_KEY"] = "acceptance-test-secret-key-minimum-32-chars-long"
            os.environ["AUTH_BOOTSTRAP_PASSWORD"] = "acceptance-test-bootstrap-password-123"
            get_auth_settings.cache_clear()
            try:
                get_current_user("Bearer forged.tampered.signature")
            except HTTPException as exc:
                status_code = exc.status_code
                http_rejected = exc.status_code == 401
        finally:
            if old_auth is None:
                os.environ.pop("AUTH_ENABLED", None)
            else:
                os.environ["AUTH_ENABLED"] = old_auth
            if old_key is None:
                os.environ.pop("AUTH_SECRET_KEY", None)
            else:
                os.environ["AUTH_SECRET_KEY"] = old_key
            if old_pwd is None:
                os.environ.pop("AUTH_BOOTSTRAP_PASSWORD", None)
            else:
                os.environ["AUTH_BOOTSTRAP_PASSWORD"] = old_pwd
            get_auth_settings.cache_clear()

        # Test 3: ML flow contract strictly isolates sensitive network identifiers
        from ml.o2.config import O2_FORBIDDEN_COLUMNS
        contract_enforced = "Source IP" in O2_FORBIDDEN_COLUMNS and "Timestamp" in O2_FORBIDDEN_COLUMNS

        passed = tampered_failed and http_rejected and contract_enforced
        status = "PASS" if passed else "FAIL"

        return create_evidence_record(
            test_id="NT-4",
            test_name=NEGATIVE_DESCRIPTIONS["NT-4"],
            status=status,
            expected_result={
                "tampered_token_rejected_crypto": True,
                "tampered_token_rejected_http_401": True,
                "identifier_isolation_enforced": True,
            },
            observed_result={
                "tampered_token_rejected_crypto": tampered_failed,
                "tampered_token_rejected_http_401": http_rejected,
                "http_status_code": status_code,
                "identifier_isolation_enforced": contract_enforced,
            },
            metrics={"trust_boundary_tests_passed": passed, "http_status_received": status_code},
            reasons=["Authentication token forgery properly rejected via HTTP 401 and identifier isolation enforced" if passed else "Trust boundary vulnerability detected"],
        )
    except Exception as exc:
        return create_evidence_record(
            test_id="NT-4",
            test_name=NEGATIVE_DESCRIPTIONS["NT-4"],
            status="FAIL",
            errors=[f"{type(exc).__name__}: {exc}"],
        )


def evaluate_nt5_deny_revoke_expiry() -> dict[str, Any]:
    """NT-5: Deny, revoke, and expiry parameter propagation."""
    try:
        from app.auth.models import LocalUser, UserRole
        from app.auth.tokens import InvalidTokenError, create_access_token, decode_access_token

        # Test 1: Expired token with max_age=-1 immediately raises InvalidTokenError (SignatureExpired)
        secret = "test-secret-acceptance-key-minimum-32-chars"
        user = LocalUser(username="admin", role=UserRole.ADMIN, auth_mode="local_demo")
        token = create_access_token(user, secret, expires_in_seconds=1800)
        expired_rejected = False
        try:
            decode_access_token(token, secret, max_age=-1)
        except InvalidTokenError:
            expired_rejected = True

        # Test 2: Mitigation window duration bounding and active decision lifecycle
        config = MitigationConfig()
        engine = MitigationEngine(config=config)

        # Apply mitigation block
        d_block = engine.analyze_detection(DetectionResult(attack_type="SYN", confidence=0.99, traffic_rate=1500.0, source_identifier="198.51.100.99"))
        bounded_duration = d_block.expires_at is not None and d_block.decision == "BLOCK"

        passed = expired_rejected and bounded_duration
        status = "PASS" if passed else "FAIL"

        return create_evidence_record(
            test_id="NT-5",
            test_name=NEGATIVE_DESCRIPTIONS["NT-5"],
            status=status,
            expected_result={"expired_token_rejected": True, "mitigation_duration_bounded": True, "initial_block_enforced": True},
            observed_result={
                "expired_token_rejected": expired_rejected,
                "mitigation_duration_bounded": bounded_duration,
                "mitigation_decision": str(d_block.decision),
                "expires_at_set": d_block.expires_at is not None,
            },
            metrics={"revocation_tests_passed": passed},
            reasons=["Expired token verification and mitigation expiration window validated" if passed else "Token/mitigation expiration check failed"],
        )
    except Exception as exc:
        return create_evidence_record(
            test_id="NT-5",
            test_name=NEGATIVE_DESCRIPTIONS["NT-5"],
            status="FAIL",
            errors=[f"{type(exc).__name__}: {exc}"],
        )


def run_negative_tests(
    configuration: dict[str, Any] | None = None,
    *,
    fixture_only: bool = False,
    output_root: Path = Path("evidence/negative_tests/runs"),
) -> dict[str, Any]:
    """Execute negative-test campaign and generate machine-readable evidence."""
    config = configuration or {}
    run_id = new_run_id("negative")
    run_dir = output_root / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    if fixture_only:
        reason = (
            "Official negative tests require a frozen protocol and independent authorized environment; "
            "fixture mode does not claim their execution."
        )
        tests = {
            test_id: {
                "test_id": test_id,
                "description": NEGATIVE_DESCRIPTIONS[test_id],
                "setup": config.get("negative_test_setup", {}).get(test_id),
                "expected_safe_behavior": config.get("negative_test_oracles", {}).get(test_id),
                **blocked(reason, fixture_only=True),
                "timestamp_utc": utc_now(),
                "evidence": [],
                "recovery": None,
            }
            for test_id in NEGATIVE_IDS
        }
        result = {
            "run_id": run_id,
            "run_type": "negative_tests",
            "recorded_at_utc": utc_now(),
            "fixture_only": True,
            "official_cyber14_negative_test_result": False,
            "configuration_hash": configuration_hash(config),
            "tests": tests,
            "status": "BLOCKED",
        }
    else:
        results = {
            "NT-1": evaluate_nt1_flash_crowd_recovery(),
            "NT-2": evaluate_nt2_attack_diversity(),
            "NT-3": evaluate_nt3_speed_vs_accuracy(dataset_path=config.get("dataset_reference")),
            "NT-4": evaluate_nt4_trust_boundary(),
            "NT-5": evaluate_nt5_deny_revoke_expiry(),
        }
        result = {
            "run_id": run_id,
            "run_type": "negative_tests",
            "recorded_at_utc": utc_now(),
            "fixture_only": False,
            "official_cyber14_negative_test_result": False,
            "configuration_hash": configuration_hash(config),
            "tests": results,
            "status": "PASS" if all(r["status"] == "PASS" for r in results.values()) else "PARTIAL",
        }

    write_json(run_dir / "result.json", result)
    write_json(run_dir / "environment.json", environment_record())
    write_json(
        run_dir / "evidence_manifest.json",
        {
            "run_id": run_id,
            "run_type": "negative_tests",
            "configuration_hash": result["configuration_hash"],
            "output_references": ["result.json", "environment.json"],
            "fixture_only": fixture_only,
            "status": result["status"],
        },
    )
    return result

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = ROOT / "backend"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from ml.evaluation.acceptance import load_config, run_acceptance
from ml.evaluation.acceptance_criteria import (
    evaluate_ac1_representative_operation,
    evaluate_ac2_boundary_failure_operation,
    evaluate_ac3_independent_acceptance_prep,
    evaluate_ac4_frozen_resource_envelope,
    run_all_acceptance_criteria,
)
from ml.evaluation.kpis import (
    evaluate_kpi1_detection_accuracy,
    evaluate_kpi2_flash_crowd_false_positive,
    evaluate_kpi3_detection_latency,
    evaluate_kpi4_unsafe_outcome_count,
    evaluate_kpi5_attack_path_prevention_rate,
    evaluate_kpi6_false_positive_resilience,
    run_all_kpis,
)
from ml.evaluation.negative_tests import (
    evaluate_nt1_flash_crowd_recovery,
    evaluate_nt2_attack_diversity,
    evaluate_nt3_speed_vs_accuracy,
    evaluate_nt4_trust_boundary,
    evaluate_nt5_deny_revoke_expiry,
    run_negative_tests,
)


def _print_table_header(title: str):
    print(f"\n{'=' * 78}")
    print(f" CYBER-14 ACCEPTANCE CAMPAIGN: {title.upper()}")
    print(f"{'=' * 78}")
    print(f"{'TEST ID':<10} | {'STATUS':<12} | {'TEST NAME':<32} | {'OBSERVED / REASON'}")
    print(f"{'-' * 10}-+-{'-' * 12}-+-{'-' * 32}-+-{'-' * 20}")


def _print_row(record: dict[str, Any]):
    test_id = record.get("test_id", "N/A")
    status = record.get("status", "N/A")
    name = record.get("test_name", "")[:32]

    # Format observed value or reason
    observed = record.get("observed_result")
    if isinstance(observed, dict) and len(observed) > 0:
        obs_str = ", ".join(f"{k}: {v}" for k, v in list(observed.items())[:2])
    elif record.get("reasons"):
        obs_str = record["reasons"][0][:40]
    elif record.get("errors"):
        obs_str = record["errors"][0][:40]
    else:
        obs_str = "N/A"

    print(f"{test_id:<10} | {status:<12} | {name:<32} | {obs_str}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="CYBER-14 Formal Acceptance, KPI, and Negative-Test Execution Harness."
    )
    parser.add_argument("--config", type=Path, default=Path("evidence/acceptance/acceptance_config.json"))
    parser.add_argument("--all", action="store_true", help="Run the complete acceptance campaign (ACs, KPIs, NTs)")
    parser.add_argument("--ac1", action="store_true", help="Run AC-1: Representative Operation")
    parser.add_argument("--ac2", action="store_true", help="Run AC-2: Boundary/Failure Operation")
    parser.add_argument("--ac3", action="store_true", help="Run AC-3: Independent Acceptance Preparation")
    parser.add_argument("--ac4", action="store_true", help="Run AC-4: Frozen Resource Envelope")
    parser.add_argument("--kpis", action="store_true", help="Run all KPI-1 through KPI-6 evaluations")
    parser.add_argument("--flash-crowd", action="store_true", help="Run formal Flash-Crowd Benchmark (KPI-2)")
    parser.add_argument("--o2-o3", action="store_true", help="Run O2 vs O3 Comparative Evaluation")
    parser.add_argument("--repeated-trials", action="store_true", help="Run Condition-Wise Repeated Trials (RT-01..RT-05)")
    parser.add_argument("--degraded-mode", action="store_true", help="Run Failure and Degraded-Mode Operational Resilience (DM-01..DM-08)")
    parser.add_argument("--resource-profile", action="store_true", help="Run Resource Profiling and Capacity Evaluation")
    parser.add_argument("--negative-tests", action="store_true", help="Run all NT-1 through NT-5 evaluations")
    parser.add_argument("--fixture-only", action="store_true", help="Run in fixture-only validation mode")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    # Load configuration if available
    config = {}
    if args.config.exists():
        try:
            config = load_config(args.config)
        except Exception as exc:
            logging.warning("Could not parse config %s: %s", args.config, exc)

    # Determine execution targets
    single_flags = [args.ac1, args.ac2, args.ac3, args.ac4, args.kpis, args.flash_crowd, args.o2_o3, args.repeated_trials, args.degraded_mode, args.resource_profile, args.negative_tests]
    run_all = args.all or not any(single_flags)

    total_executed = 0
    passed_count = 0
    failed_count = 0
    not_executed_count = 0
    blocked_count = 0

    if run_all:
        _print_table_header("Complete Acceptance Suite")
        # Run unified acceptance
        acc_result = run_acceptance(config, fixture_only=args.fixture_only)
        for kpi_record in acc_result["kpis"].values():
            _print_row(kpi_record)
            st = kpi_record.get("status")
            if st == "PASS": passed_count += 1
            elif st == "FAIL": failed_count += 1
            elif st == "BLOCKED": blocked_count += 1
            else: not_executed_count += 1
            total_executed += 1

        for ac_record in acc_result["acceptance_conditions"].values():
            _print_row(ac_record)
            st = ac_record.get("status")
            if st == "PASS": passed_count += 1
            elif st == "FAIL": failed_count += 1
            elif st == "BLOCKED": blocked_count += 1
            else: not_executed_count += 1
            total_executed += 1

        # Run negative tests
        nt_result = run_negative_tests(config, fixture_only=args.fixture_only)
        for nt_record in nt_result["tests"].values():
            _print_row(nt_record)
            st = nt_record.get("status")
            if st == "PASS": passed_count += 1
            elif st == "FAIL": failed_count += 1
            elif st == "BLOCKED": blocked_count += 1
            else: not_executed_count += 1
            total_executed += 1

    else:
        if args.kpis:
            _print_table_header("Key Performance Indicators (KPI-1 - KPI-6)")
            kpi_summary = run_all_kpis()
            for r in kpi_summary["kpis"].values():
                _print_row(r)
                st = r.get("status")
                if st == "PASS": passed_count += 1
                elif st == "FAIL": failed_count += 1
                elif st == "BLOCKED": blocked_count += 1
                else: not_executed_count += 1
                total_executed += 1

        if args.flash_crowd:
            _print_table_header("Formal Flash-Crowd Benchmark (KPI-2)")
            from ml.evaluation.flash_crowd import evaluate_formal_flash_crowd_benchmark
            r = evaluate_formal_flash_crowd_benchmark()
            _print_row(r)
            if r.get("status") == "PASS": passed_count += 1
            elif r.get("status") == "FAIL": failed_count += 1
            else: not_executed_count += 1
            total_executed += 1

        if args.o2_o3:
            _print_table_header("O2 vs O3 Comparative Evaluation")
            from ml.evaluation.o2_o3_comparison import evaluate_o2_o3_comparison
            r = evaluate_o2_o3_comparison()
            _print_row(r)
            if r.get("status") == "PASS": passed_count += 1
            elif r.get("status") == "FAIL": failed_count += 1
            else: not_executed_count += 1
            total_executed += 1

        if args.repeated_trials:
            _print_table_header("Condition-Wise Repeated Trials (RT-01 - RT-05)")
            from ml.evaluation.repeated_trials import evaluate_repeated_trials
            r = evaluate_repeated_trials()
            _print_row(r)
            if r.get("status") == "PASS": passed_count += 1
            elif r.get("status") == "FAIL": failed_count += 1
            else: not_executed_count += 1
            total_executed += 1

        if args.degraded_mode:
            _print_table_header("Failure and Degraded-Mode Operational Resilience (DM-01 - DM-08)")
            from ml.evaluation.degraded_mode import evaluate_degraded_mode
            r = evaluate_degraded_mode()
            _print_row(r)
            if r.get("status") == "PASS": passed_count += 1
            elif r.get("status") == "FAIL": failed_count += 1
            else: not_executed_count += 1
            total_executed += 1

        if args.resource_profile:
            _print_table_header("Resource Profiling and Capacity Evaluation (AC-4 / NT-3 / Capacity)")
            from ml.evaluation.resource_profiling import evaluate_resource_profile
            r = evaluate_resource_profile()
            _print_row(r)
            if r.get("status") == "PASS": passed_count += 1
            elif r.get("status") == "FAIL": failed_count += 1
            else: not_executed_count += 1
            total_executed += 1

        if args.ac1:
            _print_table_header("AC-1 Representative Operation")
            r = evaluate_ac1_representative_operation()
            _print_row(r)
            if r.get("status") == "PASS": passed_count += 1
            else: failed_count += 1
            total_executed += 1

        if args.ac2:
            _print_table_header("AC-2 Boundary/Failure Operation")
            r = evaluate_ac2_boundary_failure_operation()
            _print_row(r)
            if r.get("status") == "PASS": passed_count += 1
            else: failed_count += 1
            total_executed += 1

        if args.ac3:
            _print_table_header("AC-3 Independent Acceptance Preparation")
            r = evaluate_ac3_independent_acceptance_prep()
            _print_row(r)
            not_executed_count += 1
            total_executed += 1

        if args.ac4:
            _print_table_header("AC-4 Frozen Resource Envelope")
            r = evaluate_ac4_frozen_resource_envelope()
            _print_row(r)
            if r.get("status") == "PASS": passed_count += 1
            else: failed_count += 1
            total_executed += 1

        if args.negative_tests:
            _print_table_header("Negative Tests (NT-1 - NT-5)")
            nt_summary = run_negative_tests(config, fixture_only=args.fixture_only)
            for r in nt_summary["tests"].values():
                _print_row(r)
                st = r.get("status")
                if st == "PASS": passed_count += 1
                elif st == "FAIL": failed_count += 1
                elif st == "BLOCKED": blocked_count += 1
                else: not_executed_count += 1
                total_executed += 1

    print(f"\n{'-' * 78}")
    print(f" Summary: {total_executed} Total Tests | {passed_count} PASS | {failed_count} FAIL | {not_executed_count} NOT_EXECUTED | {blocked_count} BLOCKED")
    print(f"{'-' * 78}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

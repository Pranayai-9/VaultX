"""
run_all_tests.py — CLI runner for VaultX Phase 3 End-to-End Validation Suite.

Executes all 10 Section 13 validation scenarios, prints a formatted SOC execution
summary table, and exports structured telemetry to:
    backend/validation/validation_results.json

Usage
-----
    python -m backend.validation.run_all_tests
    python backend/validation/run_all_tests.py --flows 5000 --output backend/validation/validation_results.json
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Ensure repository root is importable when invoked directly as a script
REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from backend.validation.e2e_validator import E2EValidator, ValidationSuiteReport

DEFAULT_OUTPUT_PATH = Path(__file__).resolve().parent / "validation_results.json"


def format_soc_summary_table(report: ValidationSuiteReport) -> str:
    """Render an ASCII-safe formatted SOC execution summary table."""
    lines: list[str] = []
    sep = "=" * 116
    subsep = "-" * 116

    lines.append(sep)
    lines.append(f"  {report.suite_name}")
    lines.append(f"  Organisation : {report.organisation}")
    lines.append(f"  Executed At  : {report.executed_at}")
    lines.append(sep)
    lines.append(
        f"{'ID':<9} | {'Validation Scenario':<52} | {'Status':<6} | {'Checks':<8} | {'Time (ms)':>10} | {'Key Metric'}"
    )
    lines.append(subsep)

    for res in report.results:
        status = "PASS" if res.passed else "FAIL"
        checks = f"{res.assertions_passed}/{res.assertions_total}"
        key_metric = _extract_key_metric(res.test_id, res.metrics, res.error)
        name = res.name[:52]
        lines.append(
            f"{res.test_id:<9} | {name:<52} | {status:<6} | {checks:<8} | {res.duration_ms:>10.1f} | {key_metric}"
        )

    lines.append(subsep)
    overall = "PASS" if report.failed_tests == 0 else "FAIL"
    lines.append(
        f"  SUMMARY: {report.passed_tests}/{report.total_tests} Scenarios Passed "
        f"({report.pass_rate_pct:.1f}%) | "
        f"Assertions: {report.total_assertions_passed}/{report.total_assertions} | "
        f"Total Time: {report.total_duration_ms:.1f} ms | "
        f"OVERALL: {overall}"
    )
    lines.append(sep)
    return "\n".join(lines)


def _extract_key_metric(test_id: str, metrics: dict, error: str | None) -> str:
    if error:
        return f"ERR: {error[:22]}"
    if test_id == "TEST-01":
        return f"{metrics.get('incident_reference', '-')}, rollback=OK"
    if test_id == "TEST-02":
        return f"VLAN70={metrics.get('vlan70_management_cidr', '-')}"
    if test_id == "TEST-03":
        return f"MITRE={','.join(metrics.get('correlated_incident_mitre', []))}"
    if test_id == "TEST-04":
        return f"up={metrics.get('upload_ratio', 0):.4f}, r={metrics.get('beacon_autocorrelation', 0):.2f}"
    if test_id == "TEST-05":
        return f"recall={metrics.get('overall_held_out_recall', 0):.1%}, FPR={metrics.get('benign_holdout_fpr', 0):.1%}"
    if test_id == "TEST-06":
        return f"4 CVEs, 4-stage ladder"
    if test_id == "TEST-07":
        return f"OT_BLOCKED, 2-Person=OK"
    if test_id == "TEST-08":
        lat = metrics.get("latency_ms", {})
        return f"{metrics.get('fps', 0):.0f} FPS, P99={lat.get('p99_ms', 0):.2f}ms"
    if test_id == "TEST-09":
        return f"7 classes, false_agent={metrics.get('false_agent_attributions', -1)}"
    if test_id == "TEST-10":
        return f"audit_sql={metrics.get('postgresql_audit_log_inserts', 0)}, rb=OK"
    return "-"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run all 10 VaultX Phase 3 End-to-End Validation Scenarios."
    )
    parser.add_argument(
        "--flows",
        type=int,
        default=5000,
        help="Number of synthetic flows for TEST-08 Stress Test (default: 5000).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT_PATH,
        help="Output JSON path (default: backend/validation/validation_results.json).",
    )
    args = parser.parse_args(argv)

    validator = E2EValidator(stress_flow_count=args.flows)
    report = validator.run_all()
    exported_path = validator.export_report(report, args.output)

    print(format_soc_summary_table(report))
    print(f"\nExported validation telemetry to: {exported_path}")
    return 0 if report.failed_tests == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())

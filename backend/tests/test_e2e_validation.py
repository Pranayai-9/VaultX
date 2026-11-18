"""
test_e2e_validation.py — Pytest & unittest Suite for VaultX Phase 3 End-to-End Validation.

Executes all 10 Section 13 validation scenarios via E2EValidator plus StressTester
telemetry and JSON report export verification.

Run with:
    pytest backend/tests/test_e2e_validation.py -v
    python -m unittest backend/tests/test_e2e_validation.py -v
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from backend.validation.e2e_validator import E2EValidator
from backend.validation.run_all_tests import format_soc_summary_table


class TestVaultXE2EValidationSuite(unittest.TestCase):
    """Comprehensive Section 13 End-to-End Validation Suite (10/10 scenarios)."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.validator = E2EValidator(stress_flow_count=5000)

    def test_01_third_party_credential_compromise_and_containment(self) -> None:
        res = self.validator.run_test_01_third_party_compromise()
        self.assertTrue(res.passed, f"TEST-01 failed: {res.summary} ({res.error})")
        self.assertEqual(res.metrics["incident_reference"], "INC-2026-001")
        self.assertEqual(res.metrics["correlation_rule"], "RULE-VENDOR-001")
        self.assertTrue(res.metrics["firewall_blocked_then_removed"])

    def test_02_suspicious_lateral_movement(self) -> None:
        res = self.validator.run_test_02_lateral_movement()
        self.assertTrue(res.passed, f"TEST-02 failed: {res.summary} ({res.error})")
        self.assertEqual(res.metrics["vlan70_management_cidr"], "10.10.70.0/24")
        self.assertGreaterEqual(res.metrics["distinct_targets_scanned"], 4)
        self.assertGreater(res.metrics["graph_nodes"], 50)

    def test_03_living_off_the_land_activity(self) -> None:
        res = self.validator.run_test_03_lotl_activity()
        self.assertTrue(res.passed, f"TEST-03 failed: {res.summary} ({res.error})")
        self.assertIn("T1059.001", res.metrics["powershell_mitre"])
        self.assertIn("T1105", res.metrics["certutil_mitre"])
        self.assertEqual(res.metrics["egress_window_minutes"], 15)

    def test_04_encrypted_data_transfer_without_decryption(self) -> None:
        res = self.validator.run_test_04_encrypted_exfil()
        self.assertTrue(res.passed, f"TEST-04 failed: {res.summary} ({res.error})")
        self.assertGreater(res.metrics["upload_ratio"], 0.99)
        self.assertEqual(res.metrics["flow_duration_hours"], 4.5)
        self.assertFalse(res.metrics["payload_decrypted"])
        self.assertGreaterEqual(res.metrics["beacon_autocorrelation"], 0.70)

    def test_05_unknown_attack_behaviour_held_out_family(self) -> None:
        res = self.validator.run_test_05_unknown_attack_heldout()
        self.assertTrue(res.passed, f"TEST-05 failed: {res.summary} ({res.error})")
        self.assertGreaterEqual(res.metrics["overall_held_out_recall"], 0.20)
        self.assertGreaterEqual(res.metrics["per_family_recall"]["ENCRYPTED_EXFIL"], 0.90)
        self.assertTrue(res.metrics["creates_alert_invariant_preserved"])

    def test_06_vulnerability_exposure_and_exploitation_ladder(self) -> None:
        res = self.validator.run_test_06_vulnerability_exploitation_ladder()
        self.assertTrue(res.passed, f"TEST-06 failed: {res.summary} ({res.error})")
        self.assertEqual(len(res.metrics["vulnerable_assets_matched"]), 4)
        self.assertEqual(
            res.metrics["ladder_progression"],
            [
                "VULNERABILITY_EXPOSED",
                "ATTACK_ATTEMPT_DETECTED",
                "POTENTIAL_EXPLOITATION",
                "CONFIRMED_COMPROMISE",
            ],
        )

    def test_07_industrial_network_anomaly_modbus_safety_interlock(self) -> None:
        res = self.validator.run_test_07_industrial_modbus_safety()
        self.assertTrue(res.passed, f"TEST-07 failed: {res.summary} ({res.error})")
        self.assertEqual(res.metrics["correlation_rule"], "RULE-OT-001")
        self.assertEqual(res.metrics["holding_register"], 40003)
        self.assertTrue(res.metrics["ot_safety_override_applied"])
        self.assertEqual(len(res.metrics["two_person_approvers"]), 2)

    def test_08_high_network_load_stress_test(self) -> None:
        res = self.validator.run_test_08_high_load_stress_test()
        self.assertTrue(res.passed, f"TEST-08 failed: {res.summary} ({res.error})")
        self.assertEqual(res.metrics["flows_processed"], 5000)
        self.assertGreater(res.metrics["fps"], 100.0)
        self.assertGreater(res.metrics["pps"], 1000.0)
        self.assertEqual(res.metrics["error_count"], 0)

    def test_09_human_vs_service_vs_agent_identity_classification(self) -> None:
        res = self.validator.run_test_09_identity_classification()
        self.assertTrue(res.passed, f"TEST-09 failed: {res.summary} ({res.error})")
        self.assertEqual(len(res.metrics["identity_categories_verified"]), 7)
        self.assertEqual(res.metrics["false_agent_attributions"], 0)

    def test_10_isolation_authorization_and_rollback_lifecycle(self) -> None:
        res = self.validator.run_test_10_isolation_authorization_rollback()
        self.assertTrue(res.passed, f"TEST-10 failed: {res.summary} ({res.error})")
        self.assertEqual(res.metrics["mandatory_proposal_fields_verified"], 10)
        self.assertGreaterEqual(res.metrics["postgresql_audit_log_inserts"], 3)
        self.assertEqual(res.metrics["active_firewall_rules_after_rollback"], 0)
        self.assertEqual(res.metrics["final_action_status"], "rolled_back")

    def test_full_suite_export_and_summary_formatting(self) -> None:
        light_validator = E2EValidator(stress_flow_count=500)
        report = light_validator.run_all()
        self.assertEqual(report.total_tests, 10)
        self.assertEqual(report.passed_tests, 10)
        self.assertEqual(report.failed_tests, 0)
        self.assertEqual(report.pass_rate_pct, 100.0)

        table = format_soc_summary_table(report)
        self.assertIn("TEST-01", table)
        self.assertIn("TEST-10", table)
        self.assertIn("OVERALL: PASS", table)

        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = light_validator.export_report(
                report, Path(tmpdir) / "validation_results.json"
            )
            self.assertTrue(out_file.exists())
            parsed = json.loads(out_file.read_text(encoding="utf-8"))
            self.assertEqual(parsed["overall_status"], "PASS")
            self.assertEqual(len(parsed["results"]), 10)


if __name__ == "__main__":
    unittest.main()

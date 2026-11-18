"""
test_detection.py — Comprehensive Unit Tests for VaultX Detection Engine.

Covers:
- test_signature_engine: EVE alert parsing, Suricata severity mapping, deduplication,
  alert storm detection, top-10 rule metrics, and Redis publishing.
- test_ml_classifier: mock and trained feature vectors, confidence calibration
  (< 0.65 -> UNCERTAIN), binary_label output, top-5 SHAP/importance features,
  Redis publishing gating, and analyst false-positive feedback tracking.
- test_anomaly_detector: normal vs anomalous feature scoring, baseline feature
  explainability, rolling per-asset/zone rates, investigation suggestions (never auto-alerts).
- test_encrypted_traffic_analyzer: C2 beacon autocorrelation detection, upload ratio flagging,
  multi-signal gating, TLS-absent QUIC/ECH mode, and threat_intel reputation check.
- test_model_registry: lifecycle transitions, metric threshold gating, human approval
  enforcement, promotion, comparison, and rollback + fallback loading.
- test_feature_store: >20% missing value rejection, persistence, training window query,
  and schema version mapping.
"""

from __future__ import annotations

import json
import pickle
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

import numpy as np

# Ensure repository root is importable
REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from backend.detection.anomaly_detector import AnomalyDetector
from backend.detection.detection_config import (
    ALL_LABELS,
    FEATURE_COLUMNS,
    ML_CONFIDENCE_THRESHOLD,
    MODEL_STATE_APPROVED,
    MODEL_STATE_CANDIDATE,
    MODEL_STATE_DEPLOYED,
    MODEL_STATE_RETIRED,
    REDIS_STREAM_ANOMALY_DETECTIONS,
    REDIS_STREAM_ENCRYPTED_TRAFFIC,
    REDIS_STREAM_ML_DETECTIONS,
    REDIS_STREAM_SIGNATURE_DETECTIONS,
    UNCERTAIN_LABEL,
)
from backend.detection.encrypted_traffic_analyzer import (
    EncryptedTrafficAnalyzer,
    compute_beacon_autocorrelation,
)
from backend.detection.feature_store import FeatureStore
from backend.detection.ml_classifier import MLClassifier
from backend.detection.model_registry import ModelRegistry
from backend.detection.signature_engine import SignatureEngine


# ---------------------------------------------------------------------------
# Lightweight Mocks
# ---------------------------------------------------------------------------


class FakeRedis:
    """In-memory mock Redis supporting xadd and xread."""

    def __init__(self) -> None:
        self.streams: Dict[str, List[Tuple[str, Dict[str, Any]]]] = {}
        self._seq = 0

    def xadd(self, stream: str, fields: Dict[str, Any]) -> str:
        self._seq += 1
        entry_id = f"1700000000000-{self._seq}"
        self.streams.setdefault(stream, []).append((entry_id, fields))
        return entry_id

    def xread(
        self,
        streams: Dict[str, str],
        count: int = 100,
        block: int = 0,
    ) -> List[Tuple[str, List[Tuple[str, Dict[str, Any]]]]]:
        out = []
        for name in streams:
            entries = self.streams.get(name, [])[:count]
            if entries:
                out.append((name, entries))
        return out


class FakeEnricher:
    """In-memory asset lookup for unit tests."""

    def __init__(self) -> None:
        self._assets = {
            "10.10.20.11": {
                "asset_id": "ENG-WS-001",
                "hostname": "eng-firmware-ws01",
                "vlan": 20,
                "network_segment": "Engineering",
                "criticality": "critical",
                "owner_department": "Engineering",
            },
            "10.10.30.11": {
                "asset_id": "OT-PLC-001",
                "hostname": "ot-smt-plc01",
                "vlan": 30,
                "network_segment": "OT",
                "criticality": "critical",
                "owner_department": "Manufacturing OT",
            },
            "10.10.50.2": {
                "asset_id": "DMZ-VPN-001",
                "hostname": "dmz-vendor-vpn",
                "vlan": 50,
                "network_segment": "DMZ",
                "criticality": "high",
                "owner_department": "IT Operations",
            },
        }

    def lookup(self, ip: str) -> Dict[str, Any] | None:
        return self._assets.get(ip)


class MockRFModel:
    """Deterministic mock classifier for confidence calibration unit testing."""

    def __init__(self, probs: List[float]) -> None:
        self.classes_ = np.array(ALL_LABELS)
        self._probs = np.array([probs], dtype=float)
        self.feature_importances_ = np.linspace(0.01, 0.20, len(FEATURE_COLUMNS))

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        return np.repeat(self._probs, len(X), axis=0)

    def predict(self, X: np.ndarray) -> np.ndarray:
        idx = int(np.argmax(self._probs[0]))
        return np.array([self.classes_[idx]] * len(X))


class MockIsolationForest:
    """Deterministic mock Isolation Forest scoring samples based on L2 norm."""

    def __init__(self, norm_threshold: float = 4.0) -> None:
        self.norm_threshold = norm_threshold

    def decision_function(self, X: np.ndarray) -> np.ndarray:
        norms = np.linalg.norm(X, axis=1)
        # Positive for normal (norm < threshold), negative for anomaly
        return (self.norm_threshold - norms) * 0.1

    def predict(self, X: np.ndarray) -> np.ndarray:
        scores = self.decision_function(X)
        return np.where(scores < 0, -1, 1)


class MockScaler:
    """Identity StandardScaler with explicit mean/scale for baseline z-score explainability."""

    def __init__(self, n_features: int) -> None:
        self.mean_ = np.zeros(n_features, dtype=float)
        self.scale_ = np.ones(n_features, dtype=float)

    def transform(self, X: np.ndarray) -> np.ndarray:
        return (X - self.mean_) / self.scale_


def _sample_feature_dict(**overrides: Any) -> Dict[str, Any]:
    base: Dict[str, Any] = {
        "source_port": 54321,
        "destination_port": 502,
        "connection_duration": 1.25,
        "total_fwd_packets": 12,
        "total_bwd_packets": 14,
        "total_fwd_bytes": 1800,
        "total_bwd_bytes": 2400,
        "packets_transferred": 26,
        "bytes_transferred": 4200,
        "flow_bytes_per_sec": 3360.0,
        "flow_packets_per_sec": 20.8,
        "source_vlan": 50,
        "destination_vlan": 30,
        "protocol": "TCP",
        "identity_classification": "THIRD_PARTY_IDENTITY",
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Test Cases
# ---------------------------------------------------------------------------


class TestDetectionEngine(unittest.TestCase):
    """Core unit test suite for all VaultX Phase 2 Detection Engine modules."""

    def test_signature_engine(self) -> None:
        """Test Suricata EVE alert parsing, severity mapping, asset enrichment, deduplication, and storm detection."""
        fake_redis = FakeRedis()
        enricher = FakeEnricher()
        engine = SignatureEngine(
            redis_client=fake_redis,
            db_session_factory=None,
            asset_enricher=enricher,
            dedup_window_seconds=60,
            storm_threshold=5,
        )

        # Verify severity mapping 1..4 -> critical/high/medium/low
        self.assertEqual(engine.map_severity(1), "critical")
        self.assertEqual(engine.map_severity(2), "high")
        self.assertEqual(engine.map_severity(3), "medium")
        self.assertEqual(engine.map_severity(4), "low")
        self.assertEqual(engine.map_severity(99), "low")

        # Non-alert EVE event should be ignored
        non_alert = {"event_type": "dns", "src_ip": "10.10.10.5", "dest_ip": "10.10.10.1"}
        self.assertIsNone(engine.process_event(non_alert, now=1000.0))

        # Valid Suricata alert
        eve_alert = {
            "timestamp": "2026-11-18T10:00:00Z",
            "event_type": "alert",
            "src_ip": "10.10.50.2",
            "dest_ip": "10.10.30.11",
            "src_port": 51234,
            "dest_port": 502,
            "proto": "TCP",
            "alert": {
                "signature_id": 2026001,
                "signature": "BECPL Unauthorized Modbus Write from Vendor VPN",
                "category": "OT Protocol Violation",
                "severity": 1,
            },
        }

        first = engine.process_event(eve_alert, now=1000.0)
        self.assertIsNotNone(first)
        assert first is not None
        self.assertEqual(first.signature_id, 2026001)
        self.assertEqual(first.severity, "critical")
        self.assertEqual(first.src_asset["asset_id"], "DMZ-VPN-001")
        self.assertEqual(first.dst_asset["asset_id"], "OT-PLC-001")
        self.assertFalse(first.is_duplicate)
        self.assertEqual(len(fake_redis.streams[REDIS_STREAM_SIGNATURE_DETECTIONS]), 1)

        # Identical alert within 60s window must be deduplicated (not re-published)
        dup = engine.process_event(eve_alert, now=1030.0)
        assert dup is not None
        self.assertTrue(dup.is_duplicate)
        self.assertEqual(len(fake_redis.streams[REDIS_STREAM_SIGNATURE_DETECTIONS]), 1)

        # Identical alert after 60s window expires must be emitted again
        after_window = engine.process_event(eve_alert, now=1065.0)
        assert after_window is not None
        self.assertFalse(after_window.is_duplicate)
        self.assertEqual(len(fake_redis.streams[REDIS_STREAM_SIGNATURE_DETECTIONS]), 2)

        # Alert storm detection (>5 alerts/min from same source IP)
        storm_detected = False
        for i in range(6):
            ev = dict(eve_alert)
            ev["dest_port"] = 5000 + i  # distinct dest ports so not deduplicated
            res = engine.process_event(ev, now=2000.0 + i)
            if res and res.is_storm:
                storm_detected = True
        self.assertTrue(storm_detected)
        self.assertGreaterEqual(len(engine.get_top_rules()), 1)

    def test_ml_classifier(self) -> None:
        """Test MLClassifier confidence calibration, UNCERTAIN gating, top-5 features, Redis publish, and FP feedback."""
        fake_redis = FakeRedis()

        # 1. High-confidence attack (0.88 >= 0.65) -> classified as attack, binary_label=1, published
        high_conf_probs = [0.02, 0.88, 0.02, 0.02, 0.02, 0.02, 0.01, 0.01]  # VENDOR_COMPROMISE
        clf_high = MLClassifier(
            model_object=MockRFModel(high_conf_probs),
            confidence_threshold=ML_CONFIDENCE_THRESHOLD,
            redis_client=fake_redis,
        )
        pred_attack = clf_high.predict(_sample_feature_dict(), event_id="evt-001")
        self.assertEqual(pred_attack.predicted_class, "VENDOR_COMPROMISE")
        self.assertEqual(pred_attack.binary_label, 1)
        self.assertFalse(pred_attack.is_uncertain)
        self.assertAlmostEqual(pred_attack.confidence_score, 0.88, places=4)
        self.assertEqual(len(pred_attack.top_features), 5)
        self.assertTrue(pred_attack.published)
        self.assertEqual(len(fake_redis.streams[REDIS_STREAM_ML_DETECTIONS]), 1)

        # 2. Low-confidence attack (0.52 < 0.65) -> calibrated to UNCERTAIN, binary_label=0, NOT published
        low_conf_probs = [0.18, 0.52, 0.05, 0.05, 0.05, 0.05, 0.05, 0.05]
        clf_low = MLClassifier(
            model_object=MockRFModel(low_conf_probs),
            confidence_threshold=ML_CONFIDENCE_THRESHOLD,
            redis_client=fake_redis,
        )
        pred_uncertain = clf_low.predict(_sample_feature_dict(), event_id="evt-002")
        self.assertEqual(pred_uncertain.predicted_class, UNCERTAIN_LABEL)
        self.assertEqual(pred_uncertain.raw_predicted_class, "VENDOR_COMPROMISE")
        self.assertEqual(pred_uncertain.binary_label, 0)
        self.assertTrue(pred_uncertain.is_uncertain)
        self.assertFalse(pred_uncertain.published)
        self.assertEqual(len(fake_redis.streams[REDIS_STREAM_ML_DETECTIONS]), 1)

        # 3. High-confidence BENIGN -> binary_label=0, NOT published to detections:ml
        benign_probs = [0.93, 0.01, 0.01, 0.01, 0.01, 0.01, 0.01, 0.01]
        clf_benign = MLClassifier(
            model_object=MockRFModel(benign_probs),
            confidence_threshold=ML_CONFIDENCE_THRESHOLD,
            redis_client=fake_redis,
        )
        pred_benign = clf_benign.predict(_sample_feature_dict(), event_id="evt-003")
        self.assertEqual(pred_benign.predicted_class, "BENIGN")
        self.assertEqual(pred_benign.binary_label, 0)
        self.assertFalse(pred_benign.published)

        # 4. Analyst false-positive feedback tracking
        fb = clf_high.record_analyst_feedback(
            event_id="evt-001",
            predicted_class="VENDOR_COMPROMISE",
            corrected_class="BENIGN",
            analyst_id="soc-analyst-01",
            notes="Scheduled vendor maintenance window",
            feature_vector=_sample_feature_dict(),
        )
        self.assertTrue(fb.is_false_positive)
        summary = clf_high.get_false_positive_summary()
        self.assertEqual(summary["false_positives"], 1)
        self.assertEqual(summary["false_positive_by_predicted_class"]["VENDOR_COMPROMISE"], 1)

    def test_anomaly_detector(self) -> None:
        """Test AnomalyDetector with normal vs anomalous feature vectors, explainability, and non-alert invariant."""
        fake_redis = FakeRedis()
        detector = AnomalyDetector(
            model_object=MockIsolationForest(norm_threshold=5.0),
            scaler_object=MockScaler(len(FEATURE_COLUMNS)),
            redis_client=fake_redis,
            investigation_rate_threshold=0.5,
            investigation_min_samples=4,
        )

        # Normal baseline-like vector (small L2 norm)
        normal_vec = np.zeros(len(FEATURE_COLUMNS), dtype=float)
        res_norm = detector.score(normal_vec, event_id="an-1", asset_id="OT-PLC-001", zone="OT", now=100.0)
        self.assertFalse(res_norm.is_anomaly)
        self.assertFalse(res_norm.creates_alert)
        self.assertLess(res_norm.anomaly_score, 0.5)
        self.assertTrue(res_norm.published)

        # Strongly anomalous vector (huge spike on bytes_transferred & flow_bytes_per_sec)
        anom_vec = np.zeros(len(FEATURE_COLUMNS), dtype=float)
        bytes_idx = FEATURE_COLUMNS.index("bytes_transferred")
        rate_idx = FEATURE_COLUMNS.index("flow_bytes_per_sec")
        anom_vec[bytes_idx] = 50.0
        anom_vec[rate_idx] = 35.0

        last_res = None
        for i in range(4):
            last_res = detector.score(
                anom_vec,
                event_id=f"an-anom-{i}",
                asset_id="OT-PLC-001",
                zone="OT",
                now=101.0 + i,
            )
        assert last_res is not None
        self.assertTrue(last_res.is_anomaly)
        self.assertFalse(last_res.creates_alert)  # NEVER auto-alerts
        self.assertGreater(last_res.anomaly_score, 0.5)
        self.assertGreater(len(last_res.anomalous_features), 0)
        self.assertEqual(last_res.anomalous_features[0]["feature"], "bytes_transferred")

        # Elevated anomaly rate on OT-PLC-001 should generate an investigation suggestion (auto_alert=False)
        self.assertIsNotNone(last_res.investigation_suggestion)
        assert last_res.investigation_suggestion is not None
        self.assertEqual(last_res.investigation_suggestion["type"], "investigation_suggestion")
        self.assertFalse(last_res.investigation_suggestion["auto_alert"])
        self.assertEqual(len(fake_redis.streams[REDIS_STREAM_ANOMALY_DETECTIONS]), 5)

    def test_encrypted_traffic_analyzer(self) -> None:
        """Test C2 beacon autocorrelation, upload ratio flagging, multi-signal gating, and QUIC/ECH mode."""
        # 1. Beacon autocorrelation unit test: periodic 60s intervals vs irregular intervals
        base_ts = 1763424000.0
        periodic_timestamps = [base_ts + i * 60.0 + (i % 2) * 0.5 for i in range(10)]
        beacon_res = compute_beacon_autocorrelation(periodic_timestamps)
        self.assertTrue(beacon_res["is_beacon"])
        self.assertGreaterEqual(beacon_res["correlation"], 0.7)

        irregular_timestamps = [base_ts, base_ts + 5, base_ts + 340, base_ts + 355, base_ts + 1900, base_ts + 1905]
        non_beacon_res = compute_beacon_autocorrelation(irregular_timestamps)
        self.assertFalse(non_beacon_res["is_beacon"])

        # 2. Multi-signal EncryptedTrafficAnalyzer
        fake_redis = FakeRedis()
        enricher = FakeEnricher()
        analyzer = EncryptedTrafficAnalyzer(
            redis_client=fake_redis,
            asset_enricher=enricher,
            blocklist_ips={"185.220.101.42": "tor_exit_node"},
            min_signals=2,
        )
        # Seed historical JA3 for ENG-WS-001 so a brand-new JA3 fires Signal 5
        analyzer.seed_ja3_history(
            "10.10.20.11",
            "known_good_ja3_abc123",
            seen_at=datetime(2026, 11, 10, 12, 0, tzinfo=timezone.utc),
        )

        # Single-signal flow (only high upload ratio during daytime, no other anomalies) -> NOT triggered
        single_sig_flow = {
            "flow_id": "flow-single-01",
            "src_ip": "10.10.10.50",
            "dst_ip": "93.184.216.34",
            "src_port": 55000,
            "dst_port": 443,
            "protocol": "QUIC",
            "flow_duration": 300.0,
            "bytes_up": 900_000,
            "bytes_down": 100_000,  # upload ratio = 0.90 > 0.80
            "packet_count": 800,
            "timestamp": "2026-11-18T14:00:00Z",
        }
        res_single = analyzer.analyze_flow(single_sig_flow)
        self.assertEqual(res_single.metadata_visibility, "flow_only_ech_quic")
        self.assertEqual(res_single.signal_count, 1)
        self.assertEqual(res_single.signals[0].signal_name, "high_upload_ratio")
        self.assertFalse(res_single.triggered_finding)
        self.assertFalse(res_single.published)

        # Multi-signal exfiltration flow at 04:00 UTC from critical Engineering workstation to Tor exit node
        # Fires: high_upload_ratio + long_duration_unseen_external + large_volume_critical_asset
        #        + unusual_hour_external_connection + unseen_ja3_fingerprint + suspicious_tls_certificate
        #        + malicious_destination_reputation
        exfil_flow = {
            "flow_id": "flow-exfil-01",
            "src_ip": "10.10.20.11",
            "dst_ip": "185.220.101.42",
            "src_port": 59999,
            "dst_port": 443,
            "protocol": "TLS",
            "flow_duration": 9000.0,  # 2.5 hours > 2h
            "bytes_up": 95_000_000,   # ~90 MB from critical Engineering workstation
            "bytes_down": 5_000_000,  # upload ratio = 0.95 > 0.80
            "packet_count": 72000,
            "timestamp": "2026-11-18T04:15:00Z",  # 3am-5am window
            "tls_metadata": {
                "tls_version": "TLSv1.3",
                "ja3_hash": "malicious_new_ja3_999",
                "cert_validity_days": 10,
                "self_signed": True,
                "sni": "cdn-update-sync.example",
            },
        }
        res_multi = analyzer.analyze_flow(exfil_flow)
        self.assertEqual(res_multi.metadata_visibility, "full_tls")
        self.assertTrue(res_multi.triggered_finding)
        self.assertTrue(res_multi.published)
        self.assertGreaterEqual(res_multi.signal_count, 6)
        signal_names = {s.signal_name for s in res_multi.signals}
        self.assertIn("high_upload_ratio", signal_names)
        self.assertIn("long_duration_unseen_external", signal_names)
        self.assertIn("large_volume_critical_asset", signal_names)
        self.assertIn("unusual_hour_external_connection", signal_names)
        self.assertIn("unseen_ja3_fingerprint", signal_names)
        self.assertIn("suspicious_tls_certificate", signal_names)
        self.assertIn("malicious_destination_reputation", signal_names)
        self.assertEqual(len(fake_redis.streams[REDIS_STREAM_ENCRYPTED_TRAFFIC]), 1)

        # Sequential beacon flows from internal host to external IP
        beacon_start = datetime(2026, 11, 18, 4, 0, 0, tzinfo=timezone.utc)
        last_beacon_finding = None
        for idx in range(7):
            b_flow = {
                "flow_id": f"flow-beacon-{idx}",
                "src_ip": "10.10.10.25",
                "dst_ip": "45.33.32.156",
                "src_port": 51000 + idx,
                "dst_port": 443,
                "protocol": "TLS",
                "flow_duration": 2.0,
                "bytes_up": 500,
                "bytes_down": 500,
                "packet_count": 10,
                "timestamp": (beacon_start + timedelta(seconds=idx * 60)).isoformat(),
            }
            last_beacon_finding = analyzer.analyze_flow(b_flow)
        assert last_beacon_finding is not None
        self.assertTrue(last_beacon_finding.beacon_analysis["is_beacon"])
        self.assertIn("c2_beacon_pattern", {s.signal_name for s in last_beacon_finding.signals})
        self.assertTrue(last_beacon_finding.triggered_finding)

    def test_model_registry(self) -> None:
        """Test model lifecycle governance, threshold gating, human approval, promotion, comparison, and rollback."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            # Create dummy serialized artifacts for v1 and v2
            for ver in ("1", "2"):
                with open(tmp_path / f"rf_classifier_v{ver}.pkl", "wb") as f:
                    pickle.dump({"model": MockRFModel([0.9, 0.1, 0, 0, 0, 0, 0, 0]), "version": ver}, f)

            registry = ModelRegistry(model_dir=tmp_path)

            # Register v1 with strong metrics
            v1_metrics = {
                "rf_classifier": {
                    "macro_f1": 0.92,
                    "weighted_f1": 0.96,
                    "false_positive_rate": 0.012,
                }
            }
            rec1 = registry.register_model("1", metrics=v1_metrics, actor="ml-engineer")
            self.assertEqual(rec1.state, MODEL_STATE_CANDIDATE)

            # Empty approver must be rejected
            with self.assertRaises(ValueError):
                registry.approve_model("1", approver_id="")

            # Promote v1 with human approver
            promoted1 = registry.promote_model("1", approver_id="sec-mgr-pune")
            self.assertEqual(promoted1.state, MODEL_STATE_DEPLOYED)
            self.assertTrue(promoted1.is_active)
            self.assertEqual(registry.get_active_model().version_id, "1")  # type: ignore[union-attr]

            # Register a weak candidate v_bad that fails thresholds -> approval must fail
            bad_metrics = {
                "rf_classifier": {
                    "macro_f1": 0.45,
                    "weighted_f1": 0.60,
                    "false_positive_rate": 0.18,
                }
            }
            registry.register_model("bad", metrics=bad_metrics)
            with self.assertRaises(ValueError):
                registry.approve_model("bad", approver_id="sec-mgr-pune")

            # Register v2 with improved metrics, compare against v1, approve and promote
            v2_metrics = {
                "rf_classifier": {
                    "macro_f1": 0.95,
                    "weighted_f1": 0.98,
                    "false_positive_rate": 0.008,
                }
            }
            registry.register_model("2", metrics=v2_metrics)
            comparison = registry.compare_models("2")
            self.assertTrue(comparison["recommend_promotion"])
            self.assertGreater(comparison["delta"]["macro_f1"], 0)

            promoted2 = registry.promote_model("2", approver_id="sec-mgr-pune")
            self.assertEqual(promoted2.state, MODEL_STATE_DEPLOYED)
            self.assertEqual(registry.get_active_model().version_id, "2")  # type: ignore[union-attr]
            # v1 should now be retired
            v1_after = [m for m in registry.list_models() if m.version_id == "1"][0]
            self.assertEqual(v1_after.state, MODEL_STATE_RETIRED)

            # Rollback from v2 -> v1
            rolled = registry.rollback_model(actor="sec-mgr-pune", reason="Elevated drift in staging")
            self.assertEqual(rolled.version_id, "1")
            self.assertEqual(registry.get_active_model().version_id, "1")  # type: ignore[union-attr]

            # Load fallback test: requesting missing version "99" falls back to previous deployed version
            loaded = registry.load_model("99")
            self.assertTrue(loaded.fallback_used)
            self.assertEqual(loaded.version_id, "1")

            # Audit log recorded every transition
            actions = [a["action"] for a in registry.get_audit_trail()]
            self.assertIn("model_registered", actions)
            self.assertIn("model_approved", actions)
            self.assertIn("model_deployed", actions)
            self.assertIn("model_rollback", actions)
            self.assertIn("model_load_fallback", actions)

    def test_feature_store(self) -> None:
        """Test FeatureStore >20% missing-value quality gate, schema versioning, and training retrieval."""
        store = FeatureStore(db_session_factory=None, max_missing_ratio=0.20)
        now = datetime.now(tz=timezone.utc)

        # Complete feature vector -> accepted
        accepted, vec_id = store.save_feature_vector(
            event_id="evt-fs-1",
            feature_vector=_sample_feature_dict(),
            label="VENDOR_COMPROMISE",
            event_timestamp=now,
        )
        self.assertTrue(accepted)
        self.assertIsNotNone(vec_id)

        # Vector with >20% missing values (5 of 15 missing = 33.3%) -> rejected
        sparse = _sample_feature_dict(
            source_port=None,
            destination_port=None,
            connection_duration=float("nan"),
            total_fwd_packets=None,
            bytes_transferred=None,
        )
        accepted_sparse, vec_id_sparse = store.save_feature_vector(
            event_id="evt-fs-2",
            feature_vector=sparse,
            label="BENIGN",
            event_timestamp=now,
        )
        self.assertFalse(accepted_sparse)
        self.assertIsNone(vec_id_sparse)
        self.assertEqual(store.rejected_count, 1)

        # Register schema v2 with mapping and query training DataFrame
        store.register_schema_version(
            "2.0.0",
            feature_columns=FEATURE_COLUMNS,
            column_mapping={"bytes_transferred": "total_bytes"},
            description="Renamed bytes_transferred -> total_bytes",
        )
        df = store.get_features_for_training(
            start_date=now - timedelta(hours=1),
            end_date=now + timedelta(hours=1),
            include_labels=True,
            target_schema_version="2.0.0",
        )
        self.assertEqual(len(df), 1)
        self.assertIn("total_bytes", df.columns)
        self.assertEqual(df.iloc[0]["label"], "VENDOR_COMPROMISE")

    def test_trained_v1_artifacts_inference(self) -> None:
        """Verify end-to-end inference using the real trained v1 RF, SHAP, and Isolation Forest artifacts."""
        model_dir = REPO_ROOT / "backend" / "models"
        rf_path = model_dir / "rf_classifier_v1.pkl"
        if_path = model_dir / "isolation_forest_v1.pkl"
        scaler_path = model_dir / "feature_scaler_v1.pkl"
        shap_path = model_dir / "shap_explainer_v1.pkl"

        if not rf_path.exists():
            self.skipTest("Trained v1 model artifacts not present")

        clf = MLClassifier(
            model_path=rf_path,
            shap_explainer_path=shap_path,
            confidence_threshold=ML_CONFIDENCE_THRESHOLD,
        )
        # Vendor compromise-like flow (DMZ VLAN 50 -> OT VLAN 30, Modbus port 502, THIRD_PARTY_IDENTITY)
        pred = clf.predict(
            _sample_feature_dict(
                source_vlan=50,
                destination_vlan=30,
                destination_port=502,
                identity_classification="THIRD_PARTY_IDENTITY",
            ),
            publish=False,
        )
        self.assertIn(pred.predicted_class, ALL_LABELS + [UNCERTAIN_LABEL])
        self.assertEqual(len(pred.top_features), 5)
        self.assertGreaterEqual(pred.confidence_score, 0.0)
        self.assertLessEqual(pred.confidence_score, 1.0)

        detector = AnomalyDetector(model_path=if_path, scaler_path=scaler_path)
        anom_res = detector.score(_sample_feature_dict(), asset_id="OT-PLC-001", zone="OT", publish=False)
        self.assertFalse(anom_res.creates_alert)
        self.assertGreaterEqual(anom_res.anomaly_score, 0.0)
        self.assertLessEqual(anom_res.anomaly_score, 1.0)


if __name__ == "__main__":
    unittest.main()

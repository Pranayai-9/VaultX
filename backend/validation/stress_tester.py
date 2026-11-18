"""
stress_tester.py — High-Throughput Burst Stress Tester for VaultX Phase 3 Validation.

Benchmarks the VaultX ingestion, normalisation, flow aggregation, feature extraction,
selective parallel routing, and ML/anomaly detection pipeline using 5,000 synthetic
BECPL network flows delivered in configurable bursts.

Measured Telemetry
------------------
* Flows Per Second (FPS) & Packets Per Second (PPS)
* Per-flow processing latency distribution: min, mean, P50, P95, P99, max (ms)
* Selective routing queue depth (peak, mean) & backpressure activation count
* Real v1 Random Forest + Isolation Forest micro-batch inference throughput
* Process & allocation memory footprint (tracemalloc peak MB + RSS MB if psutil present)
"""

from __future__ import annotations

import math
import pickle
import random
import statistics
import time
import tracemalloc
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Coroutine, Dict, List, Optional, Tuple, TypeVar

import numpy as np

from backend.detection.detection_config import (
    FEATURE_COLUMNS,
    IDENTITY_ENCODING,
    MODEL_DIR,
    PROTOCOL_ENCODING,
)
from backend.ingestion.models import (
    EnrichedSecurityEvent,
    ProcessingPriority,
    RiskFlag,
)
from backend.ingestion.normaliser import EventNormaliser
from backend.processing.feature_extractor import FeatureExtractor
from backend.processing.flow_aggregator import FlowAggregator
from backend.processing.parallel_processor import ParallelEventProcessor

T = TypeVar("T")


def _run_coro(coro: Coroutine[Any, Any, T]) -> T:
    """
    Execute an async coroutine deterministically without opening an OS event loop
    socketpair. Compatible with sandboxed Windows and standard POSIX environments.
    """
    try:
        coro.send(None)
    except StopIteration as exc:
        return exc.value
    raise RuntimeError("Coroutine yielded unexpectedly while running against synchronous mocks.")


class _InMemoryAsyncRedis:
    """Zero-latency in-memory async Redis stub for reproducible pipeline benchmarking."""

    def __init__(self) -> None:
        self.stream_counts: Dict[str, int] = {}
        self.kv: Dict[str, str] = {}

    async def xadd(self, stream: str, fields: Dict[str, Any]) -> str:
        count = self.stream_counts.get(stream, 0) + 1
        self.stream_counts[stream] = count
        return f"1763424000000-{count}"

    async def xlen(self, stream: str) -> int:
        return self.stream_counts.get(stream, 0)

    async def get(self, key: str) -> Optional[str]:
        return self.kv.get(key)

    async def setex(self, key: str, ttl: int, value: str) -> bool:
        self.kv[key] = value
        return True


def _percentile(sorted_values: List[float], pct: float) -> float:
    """Compute linear-interpolated percentile on an already-sorted list."""
    if not sorted_values:
        return 0.0
    if len(sorted_values) == 1:
        return sorted_values[0]
    rank = (pct / 100.0) * (len(sorted_values) - 1)
    lo = math.floor(rank)
    hi = math.ceil(rank)
    if lo == hi:
        return sorted_values[lo]
    weight = rank - lo
    return sorted_values[lo] * (1.0 - weight) + sorted_values[hi] * weight


@dataclass
class LatencyStats:
    """Per-flow processing latency statistics in milliseconds."""

    min_ms: float
    mean_ms: float
    p50_ms: float
    p95_ms: float
    p99_ms: float
    max_ms: float

    def to_dict(self) -> Dict[str, float]:
        return {k: round(v, 4) for k, v in asdict(self).items()}


@dataclass
class StressTestResult:
    """Complete benchmark telemetry produced by StressTester.run_benchmark()."""

    flows_requested: int
    flows_processed: int
    flows_completed: int
    total_packets: int
    total_bytes: int
    burst_size: int
    bursts_executed: int
    pipeline_duration_sec: float
    ml_inference_duration_sec: float
    total_duration_sec: float
    fps: float
    pps: float
    ml_inference_fps: float
    latency: LatencyStats
    peak_queue_depth: int
    mean_queue_depth: float
    backpressure_threshold: int
    backpressure_triggered_count: int
    routing_tier_counts: Dict[str, int]
    ml_predictions_count: int
    anomaly_scores_count: int
    memory_current_mb: float
    memory_peak_mb: float
    rss_mb: Optional[float]
    errors: List[str] = field(default_factory=list)
    passed: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "flows_requested": self.flows_requested,
            "flows_processed": self.flows_processed,
            "flows_completed": self.flows_completed,
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "burst_size": self.burst_size,
            "bursts_executed": self.bursts_executed,
            "pipeline_duration_sec": round(self.pipeline_duration_sec, 4),
            "ml_inference_duration_sec": round(self.ml_inference_duration_sec, 4),
            "total_duration_sec": round(self.total_duration_sec, 4),
            "fps": round(self.fps, 2),
            "pps": round(self.pps, 2),
            "ml_inference_fps": round(self.ml_inference_fps, 2),
            "latency_ms": self.latency.to_dict(),
            "peak_queue_depth": self.peak_queue_depth,
            "mean_queue_depth": round(self.mean_queue_depth, 2),
            "backpressure_threshold": self.backpressure_threshold,
            "backpressure_triggered_count": self.backpressure_triggered_count,
            "routing_tier_counts": dict(self.routing_tier_counts),
            "ml_predictions_count": self.ml_predictions_count,
            "anomaly_scores_count": self.anomaly_scores_count,
            "memory_current_mb": round(self.memory_current_mb, 3),
            "memory_peak_mb": round(self.memory_peak_mb, 3),
            "rss_mb": round(self.rss_mb, 3) if self.rss_mb is not None else None,
            "error_count": len(self.errors),
            "passed": self.passed,
        }


# BECPL VLAN traffic templates for realistic synthetic burst generation
_BECPL_TRAFFIC_PROFILES: Tuple[Dict[str, Any], ...] = (
    # Corporate IT workstation -> File Server SMB
    {
        "src_prefix": "10.10.10.",
        "dst_ip": "10.10.10.4",
        "dst_port": 445,
        "proto": "tcp",
        "service": "smb",
        "src_vlan": 10,
        "dst_vlan": 10,
        "src_zone": "Corporate_IT",
        "dst_zone": "Corporate_IT",
        "src_crit": "medium",
        "dst_crit": "high",
        "identity": "HUMAN_USER",
        "sensor_id": "SENSOR-CORP-01",
        "pkts_range": (8, 45),
        "bytes_range": (2_000, 85_000),
        "weight": 0.35,
    },
    # Corporate IT -> Warehouse ERP sync
    {
        "src_prefix": "10.10.10.",
        "dst_ip": "10.10.40.2",
        "dst_port": 8443,
        "proto": "tcp",
        "service": "ssl",
        "src_vlan": 10,
        "dst_vlan": 40,
        "src_zone": "Corporate_IT",
        "dst_zone": "Warehouse",
        "src_crit": "medium",
        "dst_crit": "medium",
        "identity": "SERVICE_ACCOUNT",
        "sensor_id": "SENSOR-CORP-01",
        "pkts_range": (10, 30),
        "bytes_range": (4_000, 32_000),
        "weight": 0.20,
    },
    # Engineering CI/CD -> Firmware Git
    {
        "src_prefix": "10.10.20.",
        "dst_ip": "10.10.20.3",
        "dst_port": 443,
        "proto": "tcp",
        "service": "ssl",
        "src_vlan": 20,
        "dst_vlan": 20,
        "src_zone": "Engineering",
        "dst_zone": "Engineering",
        "src_crit": "high",
        "dst_crit": "critical",
        "identity": "AUTOMATION_WORKLOAD",
        "sensor_id": "SENSOR-ENG-01",
        "pkts_range": (20, 120),
        "bytes_range": (15_000, 350_000),
        "weight": 0.15,
    },
    # OT HMI -> SMT PLC Modbus polling
    {
        "src_prefix": "10.10.30.",
        "dst_ip": "10.10.30.10",
        "dst_port": 502,
        "proto": "tcp",
        "service": "modbus",
        "src_vlan": 30,
        "dst_vlan": 30,
        "src_zone": "OT",
        "dst_zone": "OT",
        "src_crit": "critical",
        "dst_crit": "critical",
        "identity": "INDUSTRIAL_DEVICE",
        "sensor_id": "SENSOR-OT-01",
        "pkts_range": (2, 8),
        "bytes_range": (64, 512),
        "weight": 0.18,
    },
    # DMZ Vendor Bastion -> Engineering (cross-VLAN suspicious / priority)
    {
        "src_prefix": "10.10.50.",
        "dst_ip": "10.10.20.11",
        "dst_port": 22,
        "proto": "tcp",
        "service": "ssh",
        "src_vlan": 50,
        "dst_vlan": 20,
        "src_zone": "DMZ",
        "dst_zone": "Engineering",
        "src_crit": "high",
        "dst_crit": "high",
        "identity": "THIRD_PARTY_IDENTITY",
        "sensor_id": "SENSOR-DMZ-01",
        "pkts_range": (12, 60),
        "bytes_range": (3_500, 95_000),
        "weight": 0.07,
    },
    # Cloud AI Procurement Agent -> ERP API
    {
        "src_prefix": "10.10.60.",
        "dst_ip": "10.10.10.10",
        "dst_port": 443,
        "proto": "tcp",
        "service": "https",
        "src_vlan": 60,
        "dst_vlan": 10,
        "src_zone": "Cloud",
        "dst_zone": "Corporate_IT",
        "src_crit": "medium",
        "dst_crit": "high",
        "identity": "AI_AGENT",
        "sensor_id": "SENSOR-CLOUD-01",
        "pkts_range": (6, 24),
        "bytes_range": (1_500, 18_000),
        "weight": 0.05,
    },
)


class StressTester:
    """
    High-throughput burst stress tester for the VaultX ingestion & detection pipeline.

    Parameters
    ----------
    seed : int
        Random seed for reproducible synthetic flow generation.
    backpressure_threshold : int
        ML inference queue depth threshold at which ParallelEventProcessor switches
        to statistical-only backpressure mode (default 500, matching production).
    model_dir : Path | str | None
        Directory containing trained v1 ``rf_classifier_v1.pkl``,
        ``isolation_forest_v1.pkl``, and ``feature_scaler_v1.pkl``.
    """

    def __init__(
        self,
        seed: int = 42,
        backpressure_threshold: int = 500,
        model_dir: Optional[Path | str] = None,
    ) -> None:
        self.seed = seed
        self.backpressure_threshold = backpressure_threshold
        self.model_dir = Path(model_dir) if model_dir is not None else Path(MODEL_DIR)
        self._rf_model: Any = None
        self._if_model: Any = None
        self._scaler: Any = None
        self._load_ml_artifacts()

    def _load_ml_artifacts(self) -> None:
        rf_path = self.model_dir / "rf_classifier_v1.pkl"
        if_path = self.model_dir / "isolation_forest_v1.pkl"
        scaler_path = self.model_dir / "feature_scaler_v1.pkl"

        if rf_path.exists():
            with open(rf_path, "rb") as fh:
                obj = pickle.load(fh)
                self._rf_model = obj["model"] if isinstance(obj, dict) and "model" in obj else obj
        if if_path.exists():
            with open(if_path, "rb") as fh:
                obj = pickle.load(fh)
                self._if_model = obj["model"] if isinstance(obj, dict) and "model" in obj else obj
        if scaler_path.exists():
            with open(scaler_path, "rb") as fh:
                obj = pickle.load(fh)
                self._scaler = (
                    obj["standard_scaler"]
                    if isinstance(obj, dict) and "standard_scaler" in obj
                    else obj
                )

    def generate_synthetic_flows(
        self, num_flows: int = 5000
    ) -> List[Tuple[Dict[str, Any], Dict[str, Any]]]:
        """
        Generate ``num_flows`` raw Zeek conn.log JSON payloads paired with BECPL
        enrichment metadata across all manufacturing zones.
        """
        rng = random.Random(self.seed)
        weights = [p["weight"] for p in _BECPL_TRAFFIC_PROFILES]
        chosen_profiles = rng.choices(_BECPL_TRAFFIC_PROFILES, weights=weights, k=num_flows)

        base_ts = 1763424000.0  # 2026-11-18T00:00:00Z
        records: List[Tuple[Dict[str, Any], Dict[str, Any]]] = []

        for idx, profile in enumerate(chosen_profiles):
            src_host = rng.randint(15, 95)
            src_ip = f"{profile['src_prefix']}{src_host}"
            src_port = 10000 + (idx % 50000)
            orig_pkts = rng.randint(*profile["pkts_range"])
            resp_pkts = max(1, orig_pkts + rng.randint(-2, 4))
            orig_bytes = rng.randint(*profile["bytes_range"])
            resp_bytes = max(64, int(orig_bytes * rng.uniform(0.3, 1.8)))
            duration = round(rng.uniform(0.005, 4.5), 4)

            raw_zeek = {
                "ts": base_ts + idx * 0.001,
                "uid": f"CStress{idx:06d}",
                "id.orig_h": src_ip,
                "id.orig_p": src_port,
                "id.resp_h": profile["dst_ip"],
                "id.resp_p": profile["dst_port"],
                "proto": profile["proto"],
                "service": profile["service"],
                "duration": duration,
                "orig_bytes": orig_bytes,
                "resp_bytes": resp_bytes,
                "orig_pkts": orig_pkts,
                "resp_pkts": resp_pkts,
                "conn_state": "SF",
                "history": "ShADadFf",
            }
            meta = {
                "src_vlan": profile["src_vlan"],
                "dst_vlan": profile["dst_vlan"],
                "src_zone": profile["src_zone"],
                "dst_zone": profile["dst_zone"],
                "src_crit": profile["src_crit"],
                "dst_crit": profile["dst_crit"],
                "identity": profile["identity"],
                "sensor_id": profile["sensor_id"],
                "orig_pkts": orig_pkts,
                "resp_pkts": resp_pkts,
                "orig_bytes": orig_bytes,
                "resp_bytes": resp_bytes,
                "duration": duration,
            }
            records.append((raw_zeek, meta))
        return records

    @staticmethod
    def _get_rss_mb() -> Optional[float]:
        try:
            import psutil  # type: ignore

            return psutil.Process().memory_info().rss / (1024 * 1024)
        except Exception:
            return None

    def run_benchmark(
        self,
        num_flows: int = 5000,
        burst_size: int = 250,
    ) -> StressTestResult:
        """
        Execute the full high-load burst benchmark through normalisation,
        flow aggregation, feature extraction, selective parallel routing,
        and batch ML/Isolation Forest inference.
        """
        synthetic = self.generate_synthetic_flows(num_flows=num_flows)

        redis_stub = _InMemoryAsyncRedis()
        normaliser = EventNormaliser()
        flow_agg = FlowAggregator(redis_client=redis_stub, flow_timeout_seconds=60)
        extractor = FeatureExtractor()
        processor = ParallelEventProcessor(
            flow_aggregator=flow_agg,
            feature_extractor=extractor,
            redis_client=redis_stub,
            worker_count=4,
            ml_queue_backpressure_threshold=self.backpressure_threshold,
        )

        latencies_ms: List[float] = []
        queue_depths: List[int] = []
        routing_tiers: Dict[str, int] = {}
        ml_feature_rows: List[List[float]] = []
        errors: List[str] = []

        total_packets = 0
        total_bytes = 0
        flows_processed = 0
        flows_completed = 0
        bursts_executed = 0

        was_tracing = tracemalloc.is_tracing()
        if not was_tracing:
            tracemalloc.start()
        tracemalloc.reset_peak()

        t_total_start = time.perf_counter()
        t_pipe_start = t_total_start

        for burst_start in range(0, len(synthetic), max(1, burst_size)):
            burst = synthetic[burst_start : burst_start + max(1, burst_size)]
            bursts_executed += 1

            for raw_zeek, meta in burst:
                t0_ns = time.perf_counter_ns()
                try:
                    std_ev = normaliser.normalise(raw_zeek, sensor_id=meta["sensor_id"])

                    is_cross_vlan = meta["src_vlan"] != meta["dst_vlan"]
                    involves_critical = (
                        meta["src_crit"] == "critical" or meta["dst_crit"] == "critical"
                    )
                    risk_flags: List[str] = []
                    if is_cross_vlan:
                        risk_flags.append(RiskFlag.CROSS_VLAN.value)
                    if involves_critical:
                        risk_flags.append(RiskFlag.CRITICAL_ASSET_INVOLVED.value)
                    if meta["dst_vlan"] == 30:
                        risk_flags.append(RiskFlag.OT_DESTINATION.value)
                    if meta["src_vlan"] == 50:
                        risk_flags.append(RiskFlag.VENDOR_CONNECTION.value)

                    priority = (
                        ProcessingPriority.HIGH_PRIORITY
                        if (involves_critical and is_cross_vlan) or meta["dst_vlan"] == 30
                        else (
                            ProcessingPriority.SUSPICIOUS
                            if is_cross_vlan
                            else ProcessingPriority.NORMAL
                        )
                    )

                    enriched = EnrichedSecurityEvent(
                        sensor_id=std_ev.sensor_id,
                        timestamp=std_ev.timestamp,
                        source_ip=std_ev.source_ip,
                        destination_ip=std_ev.destination_ip,
                        source_port=std_ev.source_port,
                        destination_port=std_ev.destination_port,
                        protocol=std_ev.protocol,
                        event_type=std_ev.event_type,
                        detection_source=std_ev.detection_source,
                        connection_duration=std_ev.connection_duration,
                        bytes_transferred=std_ev.bytes_transferred,
                        packets_transferred=std_ev.packets_transferred,
                        source_vlan=meta["src_vlan"],
                        destination_vlan=meta["dst_vlan"],
                        source_zone=meta["src_zone"],
                        destination_zone=meta["dst_zone"],
                        source_criticality=meta["src_crit"],
                        destination_criticality=meta["dst_crit"],
                        is_cross_vlan=is_cross_vlan,
                        involves_critical_asset=involves_critical,
                        risk_flags=risk_flags,
                        processing_priority=priority,
                        evidence={"tcp_flags": "FIN,ACK"},
                    )

                    outcome = _run_coro(processor.process_event(enriched))
                    routing_tiers[outcome.routing_tier] = (
                        routing_tiers.get(outcome.routing_tier, 0) + 1
                    )
                    if outcome.completed_flow is not None:
                        flows_completed += 1

                    # Drain 1 item per 2 queued to simulate realistic async ML consumer cadence
                    if processor.ml_queue_depth > 0 and (flows_processed % 2 == 0):
                        try:
                            processor.ml_inference_queue.get_nowait()
                        except Exception:
                            pass
                    queue_depths.append(processor.ml_queue_depth)

                    # Build aligned 15-feature ML row for micro-batch inference
                    dur = max(meta["duration"], 1e-4)
                    pkts = meta["orig_pkts"] + meta["resp_pkts"]
                    byt = meta["orig_bytes"] + meta["resp_bytes"]
                    ml_feature_rows.append(
                        [
                            float(raw_zeek["id.orig_p"]),
                            float(raw_zeek["id.resp_p"]),
                            float(dur),
                            float(meta["orig_pkts"]),
                            float(meta["resp_pkts"]),
                            float(meta["orig_bytes"]),
                            float(meta["resp_bytes"]),
                            float(pkts),
                            float(byt),
                            float(byt / dur),
                            float(pkts / dur),
                            float(meta["src_vlan"]),
                            float(meta["dst_vlan"]),
                            float(PROTOCOL_ENCODING.get(raw_zeek["proto"].upper(), 0)),
                            float(IDENTITY_ENCODING.get(meta["identity"], 6)),
                        ]
                    )

                    total_packets += pkts
                    total_bytes += byt
                    flows_processed += 1
                except Exception as exc:  # pragma: no cover - captured in telemetry
                    errors.append(str(exc))

                latencies_ms.append((time.perf_counter_ns() - t0_ns) / 1_000_000.0)

        t_pipe_end = time.perf_counter()
        pipeline_duration_sec = max(t_pipe_end - t_pipe_start, 1e-6)

        # Micro-batch ML & Anomaly Detection inference on all extracted feature vectors
        t_ml_start = time.perf_counter()
        ml_predictions_count = 0
        anomaly_scores_count = 0
        if ml_feature_rows:
            X = np.asarray(ml_feature_rows, dtype=np.float64)
            assert X.shape[1] == len(FEATURE_COLUMNS)
            if self._rf_model is not None:
                rf_probs = self._rf_model.predict_proba(X)
                ml_predictions_count = int(len(rf_probs))
            if self._if_model is not None:
                X_scaled = self._scaler.transform(X) if self._scaler is not None else X
                if_scores = self._if_model.decision_function(X_scaled)
                anomaly_scores_count = int(len(if_scores))
        t_ml_end = time.perf_counter()
        ml_inference_duration_sec = max(t_ml_end - t_ml_start, 1e-6)
        total_duration_sec = max(t_ml_end - t_total_start, 1e-6)

        mem_current_bytes, mem_peak_bytes = tracemalloc.get_traced_memory()
        if not was_tracing:
            tracemalloc.stop()

        sorted_lat = sorted(latencies_ms)
        latency_stats = LatencyStats(
            min_ms=sorted_lat[0] if sorted_lat else 0.0,
            mean_ms=statistics.fmean(sorted_lat) if sorted_lat else 0.0,
            p50_ms=_percentile(sorted_lat, 50.0),
            p95_ms=_percentile(sorted_lat, 95.0),
            p99_ms=_percentile(sorted_lat, 99.0),
            max_ms=sorted_lat[-1] if sorted_lat else 0.0,
        )

        fps = flows_processed / total_duration_sec
        pps = total_packets / total_duration_sec
        ml_fps = (
            ml_predictions_count / ml_inference_duration_sec
            if ml_predictions_count > 0
            else 0.0
        )

        peak_q = max(queue_depths) if queue_depths else 0
        mean_q = statistics.fmean(queue_depths) if queue_depths else 0.0

        passed = (
            flows_processed == num_flows
            and len(errors) == 0
            and fps > 0.0
            and pps > 0.0
            and latency_stats.p99_ms < 100.0
        )

        return StressTestResult(
            flows_requested=num_flows,
            flows_processed=flows_processed,
            flows_completed=flows_completed,
            total_packets=total_packets,
            total_bytes=total_bytes,
            burst_size=burst_size,
            bursts_executed=bursts_executed,
            pipeline_duration_sec=pipeline_duration_sec,
            ml_inference_duration_sec=ml_inference_duration_sec,
            total_duration_sec=total_duration_sec,
            fps=fps,
            pps=pps,
            ml_inference_fps=ml_fps,
            latency=latency_stats,
            peak_queue_depth=peak_q,
            mean_queue_depth=mean_q,
            backpressure_threshold=self.backpressure_threshold,
            backpressure_triggered_count=processor.backpressure_degraded_count,
            routing_tier_counts=routing_tiers,
            ml_predictions_count=ml_predictions_count,
            anomaly_scores_count=anomaly_scores_count,
            memory_current_mb=mem_current_bytes / (1024 * 1024),
            memory_peak_mb=mem_peak_bytes / (1024 * 1024),
            rss_mb=self._get_rss_mb(),
            errors=errors,
            passed=passed,
        )

"""
VaultX NIDS - System Resource & Pipeline Health Monitor
Bharat Electronics Components Pvt. Ltd. (BECPL), Pune

Collects every 10 seconds:
  - CPU%, memory%, disk%, network throughput, Redis queue depths
  - Events processed/sec, processing latency P50/P95/P99, dropped events, sensor status
Stores metrics time-series in Redis (sliding 24-hour window).
Raises operational alerts to 'alerts:operational' Redis stream when:
  - CPU > 85%
  - Queue depth > 10000
  - Processing latency P95 > 5s
  - Any sensor has not reported health in > 5 minutes
Exposes /metrics endpoint in Prometheus-compatible text format.
"""
from __future__ import annotations

import asyncio
import json
import shutil
import time
from collections import deque
from datetime import datetime, timezone
from typing import Any, Deque, Dict, List, Optional

import structlog
from fastapi import APIRouter, Response

from backend.ingestion.models import AlertSeverity, BackpressureAlert, LatencyHistogram
from backend.ingestion.sensor_health_monitor import SensorHealthMonitor

logger = structlog.get_logger(__name__)

try:
    import psutil  # type: ignore
except ImportError:  # pragma: no cover
    psutil = None


class ResourceMonitor:
    """
    Collects host resource metrics and pipeline telemetry every 10 seconds,
    stores a 24-hour sliding time-series in Redis, raises operational alerts,
    and renders Prometheus-compatible metrics for ``/metrics``.
    """

    TIMESERIES_KEY = "vaultx:metrics:timeseries"
    OPERATIONAL_ALERTS_STREAM = "alerts:operational"
    WINDOW_24H_SECONDS = 86_400

    def __init__(
        self,
        redis_client: Any = None,
        sensor_monitor: Optional[SensorHealthMonitor] = None,
        monitored_streams: Optional[List[str]] = None,
        interval_seconds: int = 10,
        cpu_threshold_pct: float = 85.0,
        queue_depth_threshold: int = 10_000,
        latency_p95_threshold_seconds: float = 5.0,
        sensor_offline_threshold_seconds: int = 300,
    ) -> None:
        self._redis = redis_client
        self._sensor_monitor = sensor_monitor
        self._monitored_streams = monitored_streams or [
            "events:raw",
            "events:endpoint",
            "events:third_party",
            "events:simulation",
        ]
        self._interval = interval_seconds
        self._cpu_threshold = cpu_threshold_pct
        self._queue_threshold = queue_depth_threshold
        self._latency_p95_threshold = latency_p95_threshold_seconds
        self._sensor_offline_threshold = sensor_offline_threshold_seconds

        # Runtime pipeline counters fed by IngestionPipeline
        self._latencies_ms: Deque[float] = deque(maxlen=10_000)
        self._event_timestamps: Deque[float] = deque(maxlen=50_000)
        self.events_processed_total: int = 0
        self.dropped_events_total: int = 0
        self.latest_snapshot: Dict[str, Any] = {}

        # Network throughput delta tracking
        self._prev_net_bytes: Optional[int] = None
        self._prev_net_ts: Optional[float] = None

        self._running: bool = False
        self._task: Optional[asyncio.Task] = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._collect_loop(), name="resource-monitor")
        logger.info("resource_monitor.started", interval_seconds=self._interval)

    async def stop(self) -> None:
        self._running = False
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        logger.info("resource_monitor.stopped")

    # ------------------------------------------------------------------
    # Metric recording hooks (called by pipeline)
    # ------------------------------------------------------------------

    def record_event_processed(self, latency_ms: float) -> None:
        now = time.monotonic()
        self.events_processed_total += 1
        self._latencies_ms.append(max(0.0, float(latency_ms)))
        self._event_timestamps.append(now)

    def record_dropped_event(self, count: int = 1) -> None:
        self.dropped_events_total += max(1, count)

    def get_events_per_sec(self, window_seconds: float = 10.0) -> float:
        now = time.monotonic()
        cutoff = now - window_seconds
        while self._event_timestamps and self._event_timestamps[0] < cutoff:
            self._event_timestamps.popleft()
        return round(len(self._event_timestamps) / max(window_seconds, 1.0), 2)

    def get_latency_histogram(self) -> LatencyHistogram:
        samples = sorted(self._latencies_ms)
        n = len(samples)
        if n == 0:
            return LatencyHistogram()

        def _pct(p: float) -> float:
            idx = min(n - 1, max(0, int(round((p / 100.0) * (n - 1)))))
            return round(samples[idx], 3)

        return LatencyHistogram(
            p50_ms=_pct(50),
            p95_ms=_pct(95),
            p99_ms=_pct(99),
            mean_ms=round(sum(samples) / n, 3),
            max_ms=round(samples[-1], 3),
            sample_count=n,
        )

    # ------------------------------------------------------------------
    # Collection, storage & alerting
    # ------------------------------------------------------------------

    async def collect_once(self) -> Dict[str, Any]:
        """Collect one metrics snapshot, persist to Redis (24h window), and evaluate alerts."""
        now_dt = datetime.now(timezone.utc)
        now_epoch = now_dt.timestamp()

        sys_stats = self._collect_system_stats()
        queue_depths = await self._collect_redis_queue_depths()
        total_queue_depth = sum(queue_depths.values())
        latency = self.get_latency_histogram()
        eps = self.get_events_per_sec(window_seconds=float(self._interval))

        sensor_summary: Dict[str, Any] = {}
        offline_sensors: List[str] = []
        if self._sensor_monitor is not None:
            await self._sensor_monitor.check_sensors(now=now_dt)
            sensor_summary = self._sensor_monitor.get_health_summary()
            offline_sensors = self._sensor_monitor.get_offline_sensors()

        snapshot = {
            "timestamp": now_dt.isoformat(),
            "epoch": now_epoch,
            "cpu_percent": sys_stats["cpu_percent"],
            "memory_percent": sys_stats["memory_percent"],
            "disk_percent": sys_stats["disk_percent"],
            "network_bytes_per_sec": sys_stats["network_bytes_per_sec"],
            "redis_queue_depths": queue_depths,
            "total_queue_depth": total_queue_depth,
            "events_processed_per_sec": eps,
            "events_processed_total": self.events_processed_total,
            "dropped_events_total": self.dropped_events_total,
            "latency_p50_ms": latency.p50_ms,
            "latency_p95_ms": latency.p95_ms,
            "latency_p99_ms": latency.p99_ms,
            "sensors_online": sensor_summary.get("online", 0),
            "sensors_offline": len(offline_sensors),
            "offline_sensor_ids": offline_sensors,
        }
        self.latest_snapshot = snapshot

        await self._store_timeseries_point(now_epoch, snapshot)
        await self._evaluate_alert_rules(snapshot)
        return snapshot

    def render_prometheus_metrics(self) -> str:
        """Render current resource and pipeline telemetry in Prometheus text exposition format."""
        snap = self.latest_snapshot or {
            "cpu_percent": 0.0,
            "memory_percent": 0.0,
            "disk_percent": 0.0,
            "network_bytes_per_sec": 0.0,
            "total_queue_depth": 0,
            "redis_queue_depths": {},
            "events_processed_per_sec": self.get_events_per_sec(),
            "events_processed_total": self.events_processed_total,
            "dropped_events_total": self.dropped_events_total,
            "latency_p50_ms": 0.0,
            "latency_p95_ms": 0.0,
            "latency_p99_ms": 0.0,
            "sensors_online": 0,
            "sensors_offline": 0,
        }

        lines = [
            "# HELP vaultx_system_cpu_percent Host CPU utilization percentage",
            "# TYPE vaultx_system_cpu_percent gauge",
            f"vaultx_system_cpu_percent {snap['cpu_percent']}",
            "# HELP vaultx_system_memory_percent Host memory utilization percentage",
            "# TYPE vaultx_system_memory_percent gauge",
            f"vaultx_system_memory_percent {snap['memory_percent']}",
            "# HELP vaultx_system_disk_percent Host disk utilization percentage",
            "# TYPE vaultx_system_disk_percent gauge",
            f"vaultx_system_disk_percent {snap['disk_percent']}",
            "# HELP vaultx_system_network_bytes_per_sec Network throughput in bytes per second",
            "# TYPE vaultx_system_network_bytes_per_sec gauge",
            f"vaultx_system_network_bytes_per_sec {snap['network_bytes_per_sec']}",
            "# HELP vaultx_ingestion_events_per_sec Events processed per second",
            "# TYPE vaultx_ingestion_events_per_sec gauge",
            f"vaultx_ingestion_events_per_sec {snap['events_processed_per_sec']}",
            "# HELP vaultx_ingestion_events_processed_total Total events processed",
            "# TYPE vaultx_ingestion_events_processed_total counter",
            f"vaultx_ingestion_events_processed_total {snap['events_processed_total']}",
            "# HELP vaultx_ingestion_events_dropped_total Total dropped events",
            "# TYPE vaultx_ingestion_events_dropped_total counter",
            f"vaultx_ingestion_events_dropped_total {snap['dropped_events_total']}",
            "# HELP vaultx_ingestion_latency_ms Processing latency percentiles in milliseconds",
            "# TYPE vaultx_ingestion_latency_ms gauge",
            f'vaultx_ingestion_latency_ms{{quantile="0.5"}} {snap["latency_p50_ms"]}',
            f'vaultx_ingestion_latency_ms{{quantile="0.95"}} {snap["latency_p95_ms"]}',
            f'vaultx_ingestion_latency_ms{{quantile="0.99"}} {snap["latency_p99_ms"]}',
            "# HELP vaultx_redis_queue_depth Current Redis stream queue depth",
            "# TYPE vaultx_redis_queue_depth gauge",
            f'vaultx_redis_queue_depth{{stream="total"}} {snap["total_queue_depth"]}',
        ]
        for stream_name, depth in snap.get("redis_queue_depths", {}).items():
            safe_stream = stream_name.replace('"', "")
            lines.append(f'vaultx_redis_queue_depth{{stream="{safe_stream}"}} {depth}')

        lines.extend([
            "# HELP vaultx_sensors_online Number of online passive sensors",
            "# TYPE vaultx_sensors_online gauge",
            f"vaultx_sensors_online {snap['sensors_online']}",
            "# HELP vaultx_sensors_offline Number of offline passive sensors",
            "# TYPE vaultx_sensors_offline gauge",
            f"vaultx_sensors_offline {snap['sensors_offline']}",
            "",
        ])
        return "\n".join(lines)

    def create_metrics_router(self) -> APIRouter:
        """Create a FastAPI APIRouter exposing Prometheus-compatible ``GET /metrics``."""
        router = APIRouter()

        @router.get("/metrics")
        async def metrics_endpoint() -> Response:
            body = self.render_prometheus_metrics()
            return Response(content=body, media_type="text/plain; version=0.0.4; charset=utf-8")

        return router

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    async def _collect_loop(self) -> None:
        while self._running:
            try:
                await self.collect_once()
                await asyncio.sleep(self._interval)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.warning("resource_monitor.collect_error", error=str(exc))
                await asyncio.sleep(self._interval)

    def _collect_system_stats(self) -> Dict[str, float]:
        cpu_pct = 0.0
        mem_pct = 0.0
        disk_pct = 0.0
        net_bps = 0.0

        if psutil is not None:
            try:
                cpu_pct = float(psutil.cpu_percent(interval=None))
                mem_pct = float(psutil.virtual_memory().percent)
                disk_pct = float(psutil.disk_usage("/").percent)
                net = psutil.net_io_counters()
                now = time.monotonic()
                total_bytes = net.bytes_sent + net.bytes_recv
                if self._prev_net_bytes is not None and self._prev_net_ts is not None:
                    dt = max(0.001, now - self._prev_net_ts)
                    net_bps = max(0.0, (total_bytes - self._prev_net_bytes) / dt)
                self._prev_net_bytes = total_bytes
                self._prev_net_ts = now
            except Exception:
                pass
        else:
            try:
                usage = shutil.disk_usage(".")
                disk_pct = round((usage.used / usage.total) * 100.0, 2) if usage.total else 0.0
            except Exception:
                pass

        return {
            "cpu_percent": round(cpu_pct, 2),
            "memory_percent": round(mem_pct, 2),
            "disk_percent": round(disk_pct, 2),
            "network_bytes_per_sec": round(net_bps, 2),
        }

    async def _collect_redis_queue_depths(self) -> Dict[str, int]:
        depths: Dict[str, int] = {}
        if self._redis is None:
            return depths
        for stream in self._monitored_streams:
            try:
                depths[stream] = int(await self._redis.xlen(stream))
            except Exception:
                depths[stream] = 0
        return depths

    async def _store_timeseries_point(self, epoch: float, snapshot: Dict[str, Any]) -> None:
        if self._redis is None:
            return
        try:
            await self._redis.zadd(self.TIMESERIES_KEY, {json.dumps(snapshot): epoch})
            cutoff = epoch - self.WINDOW_24H_SECONDS
            await self._redis.zremrangebyscore(self.TIMESERIES_KEY, "-inf", cutoff)
        except Exception as exc:
            logger.debug("resource_monitor.timeseries_store_error", error=str(exc))

    async def _evaluate_alert_rules(self, snapshot: Dict[str, Any]) -> List[BackpressureAlert]:
        alerts: List[BackpressureAlert] = []

        if snapshot["cpu_percent"] > self._cpu_threshold:
            alerts.append(BackpressureAlert(
                alert_type="CPU_HIGH",
                severity=AlertSeverity.HIGH,
                source_component="resource-monitor",
                metric_value=snapshot["cpu_percent"],
                threshold=self._cpu_threshold,
                message=f"CPU utilization {snapshot['cpu_percent']}% exceeds threshold {self._cpu_threshold}%",
            ))

        if snapshot["total_queue_depth"] > self._queue_threshold:
            alerts.append(BackpressureAlert(
                alert_type="BACKPRESSURE",
                severity=AlertSeverity.HIGH,
                source_component="resource-monitor",
                metric_value=float(snapshot["total_queue_depth"]),
                threshold=float(self._queue_threshold),
                message=f"Redis queue depth {snapshot['total_queue_depth']} exceeds threshold {self._queue_threshold}",
                details={"stream_depths": snapshot["redis_queue_depths"]},
            ))

        latency_p95_sec = snapshot["latency_p95_ms"] / 1000.0
        if latency_p95_sec > self._latency_p95_threshold:
            alerts.append(BackpressureAlert(
                alert_type="LATENCY_HIGH",
                severity=AlertSeverity.HIGH,
                source_component="resource-monitor",
                metric_value=latency_p95_sec,
                threshold=self._latency_p95_threshold,
                message=f"Processing latency P95 ({latency_p95_sec:.2f}s) exceeds {self._latency_p95_threshold}s",
            ))

        if snapshot["sensors_offline"] > 0 and self._sensor_monitor is None:
            alerts.append(BackpressureAlert(
                alert_type="SENSOR_OFFLINE",
                severity=AlertSeverity.CRITICAL,
                source_component="resource-monitor",
                metric_value=float(snapshot["sensors_offline"]),
                threshold=0.0,
                message=f"{snapshot['sensors_offline']} sensor(s) offline",
                details={"offline_sensor_ids": snapshot["offline_sensor_ids"]},
            ))

        for alert in alerts:
            await self._publish_alert(alert)

        return alerts

    async def _publish_alert(self, alert: BackpressureAlert) -> None:
        logger.warning("resource_monitor.operational_alert", alert_type=alert.alert_type, message=alert.message)
        if self._redis is None:
            return
        try:
            await self._redis.xadd(
                self.OPERATIONAL_ALERTS_STREAM,
                {"payload": json.dumps(alert.to_dict())},
            )
        except Exception as exc:
            logger.debug("resource_monitor.alert_publish_error", error=str(exc))

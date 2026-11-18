"""
VaultX NIDS - Sensor Connection Health Monitor
Bharat Electronics Components Pvt. Ltd. (BECPL), Pune

Tracks heartbeat timestamps, event rates, packet drop rates, and Zeek/Suricata
process status for every sensor registered in ``sensors/sensor_config.yml``.
Raises 'SENSOR_OFFLINE' alerts when a sensor misses heartbeats for > 5 minutes,
writes summaries to Redis hash 'sensor:status', and reports to the /health endpoint.
"""
from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import structlog

from backend.ingestion.models import (
    AlertSeverity,
    BackpressureAlert,
    SensorHealthStatus,
    SensorState,
)

logger = structlog.get_logger(__name__)

# Default BECPL sensors if sensor_config.yml is unavailable
DEFAULT_SENSORS = [
    {"sensor_id": "SENSOR-CORP-01", "description": "Corporate IT passive sensor", "monitored_vlan": 10, "monitored_subnet": "172.20.10.0/24", "priority": "medium"},
    {"sensor_id": "SENSOR-ENG-01", "description": "Engineering & Firmware sensor", "monitored_vlan": 20, "monitored_subnet": "172.20.20.0/24", "priority": "high"},
    {"sensor_id": "SENSOR-OT-01", "description": "Manufacturing OT sensor", "monitored_vlan": 30, "monitored_subnet": "172.20.30.0/24", "priority": "critical"},
    {"sensor_id": "SENSOR-WH-01", "description": "Warehouse & Logistics sensor", "monitored_vlan": 40, "monitored_subnet": "172.20.40.0/24", "priority": "medium"},
    {"sensor_id": "SENSOR-DMZ-01", "description": "DMZ & Vendor ingress sensor", "monitored_vlan": 50, "monitored_subnet": "172.20.50.0/24", "priority": "high"},
    {"sensor_id": "SENSOR-SEC-01", "description": "Security Management VLAN sensor", "monitored_vlan": 70, "monitored_subnet": "172.20.70.0/24", "priority": "high"},
]


class SensorHealthMonitor:
    """
    Monitors liveness and capture health of distributed BECPL passive sensors.

    Responsibilities:
    - Loads known sensors from ``sensor_config.yml``
    - Records heartbeat pings (events/min, packet drop rate, Zeek & Suricata status)
    - Raises ``SENSOR_OFFLINE`` alert to ``alerts:operational`` if silent > 300s
    - Writes sensor health summary to Redis hash ``sensor:status``
    - Exposes structured health dictionary for FastAPI ``/health`` endpoint
    """

    SENSOR_STATUS_HASH = "sensor:status"
    OPERATIONAL_ALERTS_STREAM = "alerts:operational"

    def __init__(
        self,
        redis_client: Any = None,
        sensor_config_path: str = "sensors/sensor_config.yml",
        offline_threshold_seconds: int = 300,
        check_interval_seconds: int = 30,
    ) -> None:
        self._redis = redis_client
        self._config_path = Path(sensor_config_path)
        self._offline_threshold = offline_threshold_seconds
        self._check_interval = check_interval_seconds

        self._sensors: Dict[str, SensorHealthStatus] = {}
        self._running: bool = False
        self._task: Optional[asyncio.Task] = None

        self._load_known_sensors()

    # ------------------------------------------------------------------
    # Configuration loading
    # ------------------------------------------------------------------

    def _load_known_sensors(self) -> None:
        sensor_defs: List[Dict[str, Any]] = []
        if self._config_path.exists():
            try:
                import yaml
                with self._config_path.open("r", encoding="utf-8") as fh:
                    parsed = yaml.safe_load(fh) or {}
                sensor_defs = parsed.get("sensors", [])
            except Exception as exc:
                logger.warning(
                    "sensor_health.config_load_failed",
                    path=str(self._config_path),
                    error=str(exc),
                )

        if not sensor_defs:
            sensor_defs = DEFAULT_SENSORS

        for cfg in sensor_defs:
            sid = cfg.get("sensor_id")
            if not sid:
                continue
            self._sensors[sid] = SensorHealthStatus(
                sensor_id=sid,
                description=cfg.get("description", ""),
                monitored_vlan=cfg.get("monitored_vlan"),
                monitored_subnet=cfg.get("monitored_subnet"),
                priority=cfg.get("priority", "medium"),
                state=SensorState.UNKNOWN,
            )

        logger.info("sensor_health.sensors_loaded", count=len(self._sensors))

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        self._running = True
        self._task = asyncio.create_task(self._monitor_loop(), name="sensor-health-monitor")
        logger.info("sensor_health.started", threshold_seconds=self._offline_threshold)

    async def stop(self) -> None:
        self._running = False
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        logger.info("sensor_health.stopped")

    # ------------------------------------------------------------------
    # Heartbeat & evaluation
    # ------------------------------------------------------------------

    async def record_heartbeat(
        self,
        sensor_id: str,
        events_per_min: float = 0.0,
        packet_drop_rate: float = 0.0,
        zeek_status: str = "running",
        suricata_status: str = "running",
        timestamp: Optional[datetime] = None,
    ) -> SensorHealthStatus:
        """Record an incoming sensor heartbeat and update Redis ``sensor:status``."""
        now = timestamp or datetime.now(timezone.utc)
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)

        if sensor_id not in self._sensors:
            self._sensors[sensor_id] = SensorHealthStatus(
                sensor_id=sensor_id,
                description="Dynamically registered sensor",
            )

        status = self._sensors[sensor_id]
        status.last_heartbeat = now
        status.seconds_since_heartbeat = 0.0
        status.events_per_min = float(events_per_min)
        status.packet_drop_rate = float(packet_drop_rate)
        status.zeek_status = zeek_status
        status.suricata_status = suricata_status
        status.is_offline = False
        status.offline_alert_sent = False

        if zeek_status != "running" or suricata_status != "running" or packet_drop_rate > 5.0:
            status.state = SensorState.DEGRADED
        else:
            status.state = SensorState.ONLINE

        await self._write_sensor_status_to_redis(status)
        return status

    async def check_sensors(self, now: Optional[datetime] = None) -> List[BackpressureAlert]:
        """
        Evaluate all known sensors against the offline threshold.
        Emits SENSOR_OFFLINE alerts for newly offline sensors and updates Redis.
        """
        ref_now = now or datetime.now(timezone.utc)
        if ref_now.tzinfo is None:
            ref_now = ref_now.replace(tzinfo=timezone.utc)

        alerts_raised: List[BackpressureAlert] = []

        for sensor_id, status in self._sensors.items():
            if status.last_heartbeat is None:
                # Never reported yet — remain UNKNOWN until first ping or explicit tracking
                continue

            elapsed = (ref_now - status.last_heartbeat).total_seconds()
            status.seconds_since_heartbeat = max(0.0, elapsed)

            if elapsed > self._offline_threshold:
                status.state = SensorState.OFFLINE
                status.is_offline = True

                if not status.offline_alert_sent:
                    severity = AlertSeverity.CRITICAL if status.priority == "critical" else AlertSeverity.HIGH
                    alert = BackpressureAlert(
                        alert_type="SENSOR_OFFLINE",
                        severity=severity,
                        timestamp=ref_now,
                        source_component="sensor-health-monitor",
                        metric_value=elapsed,
                        threshold=float(self._offline_threshold),
                        message=(
                            f"Sensor {sensor_id} (VLAN {status.monitored_vlan}) has not sent a "
                            f"heartbeat in {int(elapsed)}s (threshold {self._offline_threshold}s)"
                        ),
                        details={
                            "sensor_id": sensor_id,
                            "monitored_vlan": status.monitored_vlan,
                            "last_heartbeat": status.last_heartbeat.isoformat(),
                            "seconds_since_heartbeat": elapsed,
                        },
                    )
                    await self._publish_alert(alert)
                    status.offline_alert_sent = True
                    alerts_raised.append(alert)
                    logger.error(
                        "sensor_health.sensor_offline",
                        sensor_id=sensor_id,
                        seconds_silent=int(elapsed),
                    )

            await self._write_sensor_status_to_redis(status)

        return alerts_raised

    def get_health_summary(self) -> Dict[str, Any]:
        """Return sensor health report formatted for the /health API endpoint."""
        now = datetime.now(timezone.utc)
        sensors_out: Dict[str, Any] = {}
        online = 0
        degraded = 0
        offline = 0
        unknown = 0

        for sid, status in self._sensors.items():
            if status.last_heartbeat is not None:
                status.seconds_since_heartbeat = max(0.0, (now - status.last_heartbeat).total_seconds())
            if status.state == SensorState.ONLINE:
                online += 1
            elif status.state == SensorState.DEGRADED:
                degraded += 1
            elif status.state == SensorState.OFFLINE:
                offline += 1
            else:
                unknown += 1
            sensors_out[sid] = status.model_dump(mode="json")

        return {
            "total_sensors": len(self._sensors),
            "online": online,
            "degraded": degraded,
            "offline": offline,
            "unknown": unknown,
            "offline_threshold_seconds": self._offline_threshold,
            "sensors": sensors_out,
        }

    def get_offline_sensors(self) -> List[str]:
        return [sid for sid, st in self._sensors.items() if st.is_offline]

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    async def _monitor_loop(self) -> None:
        while self._running:
            try:
                await asyncio.sleep(self._check_interval)
                await self.check_sensors()
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.warning("sensor_health.loop_error", error=str(exc))

    async def _write_sensor_status_to_redis(self, status: SensorHealthStatus) -> None:
        if self._redis is None:
            return
        try:
            await self._redis.hset(
                self.SENSOR_STATUS_HASH,
                status.sensor_id,
                status.model_dump_json(),
            )
        except Exception as exc:
            logger.debug("sensor_health.redis_hset_error", sensor_id=status.sensor_id, error=str(exc))

    async def _publish_alert(self, alert: BackpressureAlert) -> None:
        if self._redis is None:
            return
        try:
            await self._redis.xadd(
                self.OPERATIONAL_ALERTS_STREAM,
                {"payload": json.dumps(alert.to_dict())},
            )
        except Exception as exc:
            logger.warning("sensor_health.alert_publish_error", error=str(exc))

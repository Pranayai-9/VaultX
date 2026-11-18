"""
signature_engine.py — Suricata-based signature detection wrapper for VaultX.

BECPL (Bharat Electronics Components Pvt. Ltd.), Pune — Manufacturing-Aware Hybrid NIDS.

Responsibilities
----------------
* Loads Suricata EVE JSON alerts from Redis stream ``events:raw`` (``event_type == 'alert'``).
* Parses Suricata alert fields: ``signature_id``, ``signature``, ``category``, ``severity``,
  ``proto``, ``src_ip``, ``dst_ip`` (or ``dest_ip``), ``src_port``, ``dst_port`` (or ``dest_port``).
* Maps Suricata severity (1–4) to BECPL severity (``critical`` / ``high`` / ``medium`` / ``low``).
* Enriches alerts with asset context via an asset enricher lookup.
* Creates a ``SignatureAlert`` object and writes to PostgreSQL ``becpl_nids.security_events``.
* Publishes enriched alerts to Redis stream ``detections:signature`` for the correlation engine.
* Tracks alerts/min per rule, top-10 triggered rules, and alert storm detection
  (> ``ALERT_STORM_THRESHOLD`` alerts/min from the same source IP).
* Deduplicates repeated identical alerts within a 60-second sliding window.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
import uuid
from collections import defaultdict, deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

try:
    import sqlalchemy as sa
except ImportError:  # pragma: no cover
    sa = None  # type: ignore[assignment]

try:
    from backend.detection.detection_config import (
        ALERT_STORM_THRESHOLD,
        REDIS_STREAM_RAW_EVENTS,
        REDIS_STREAM_SIGNATURE_DETECTIONS,
        SIGNATURE_DEDUP_WINDOW_SECONDS,
        SURICATA_SEVERITY_MAP,
    )
except ImportError:
    from detection_config import (  # type: ignore[no-redef]
        ALERT_STORM_THRESHOLD,
        REDIS_STREAM_RAW_EVENTS,
        REDIS_STREAM_SIGNATURE_DETECTIONS,
        SIGNATURE_DEDUP_WINDOW_SECONDS,
        SURICATA_SEVERITY_MAP,
    )

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class SignatureAlert:
    """Structured Suricata alert enriched with BECPL asset metadata."""

    alert_id: str
    signature_id: int
    signature: str
    category: str
    severity: str
    suricata_severity: int
    proto: str
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    timestamp: datetime
    sensor_id: str = "suricata-sensor"
    raw_event: Dict[str, Any] = field(default_factory=dict)
    src_asset: Optional[Dict[str, Any]] = None
    dst_asset: Optional[Dict[str, Any]] = None
    is_duplicate: bool = False
    is_storm: bool = False

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat()
        return d


# ---------------------------------------------------------------------------
# Sliding-window helpers
# ---------------------------------------------------------------------------


class DeduplicationTracker:
    """Suppresses identical (signature_id, src_ip, dst_ip, dst_port) alerts within a window."""

    def __init__(self, window_seconds: int = SIGNATURE_DEDUP_WINDOW_SECONDS) -> None:
        self.window_seconds = window_seconds
        self._seen: Dict[str, float] = {}

    @staticmethod
    def make_key(
        signature_id: int,
        src_ip: str,
        dst_ip: str,
        dst_port: Optional[int],
    ) -> str:
        raw = f"{signature_id}|{src_ip}|{dst_ip}|{dst_port}"
        return hashlib.sha1(raw.encode("utf-8")).hexdigest()

    def is_duplicate(self, key: str, now: Optional[float] = None) -> bool:
        ts = time.monotonic() if now is None else now
        last_seen = self._seen.get(key)
        if last_seen is not None and (ts - last_seen) < self.window_seconds:
            return True
        self._seen[key] = ts
        # Lazy cleanup of expired keys
        expired = [k for k, t in self._seen.items() if (ts - t) >= self.window_seconds]
        for k in expired:
            del self._seen[k]
        return False


class AlertStormDetector:
    """Detects > threshold alerts/min originating from a single source IP."""

    def __init__(self, threshold_per_min: int = ALERT_STORM_THRESHOLD) -> None:
        self.threshold_per_min = threshold_per_min
        self._source_windows: Dict[str, deque[float]] = defaultdict(deque)

    def record(self, src_ip: str, now: Optional[float] = None) -> bool:
        ts = time.monotonic() if now is None else now
        dq = self._source_windows[src_ip]
        dq.append(ts)
        while dq and (ts - dq[0]) > 60.0:
            dq.popleft()
        return len(dq) > self.threshold_per_min

    def current_rate(self, src_ip: str, now: Optional[float] = None) -> int:
        ts = time.monotonic() if now is None else now
        dq = self._source_windows.get(src_ip)
        if not dq:
            return 0
        while dq and (ts - dq[0]) > 60.0:
            dq.popleft()
        return len(dq)


class RuleMetricsTracker:
    """Tracks alerts/min per rule and top-10 triggered Suricata rules."""

    def __init__(self) -> None:
        self._windows: Dict[int, deque[float]] = defaultdict(deque)
        self._totals: Dict[int, int] = defaultdict(int)
        self._names: Dict[int, str] = {}

    def record(
        self,
        signature_id: int,
        signature_name: str = "",
        now: Optional[float] = None,
    ) -> int:
        ts = time.monotonic() if now is None else now
        dq = self._windows[signature_id]
        dq.append(ts)
        while dq and (ts - dq[0]) > 60.0:
            dq.popleft()
        self._totals[signature_id] += 1
        if signature_name:
            self._names[signature_id] = signature_name
        return len(dq)

    def alerts_per_minute(self, signature_id: int, now: Optional[float] = None) -> int:
        ts = time.monotonic() if now is None else now
        dq = self._windows.get(signature_id)
        if not dq:
            return 0
        while dq and (ts - dq[0]) > 60.0:
            dq.popleft()
        return len(dq)

    def top_triggered_rules(self, limit: int = 10) -> List[Dict[str, Any]]:
        ranked = sorted(self._totals.items(), key=lambda item: item[1], reverse=True)[:limit]
        return [
            {
                "signature_id": sig_id,
                "signature": self._names.get(sig_id, ""),
                "total_count": count,
                "alerts_per_min": self.alerts_per_minute(sig_id),
            }
            for sig_id, count in ranked
        ]


# ---------------------------------------------------------------------------
# Main Signature Engine
# ---------------------------------------------------------------------------


class SignatureEngine:
    """
    Suricata EVE JSON signature detection engine.

    Parameters
    ----------
    redis_client:
        Redis client supporting ``xread`` and ``xadd`` (or ``None`` for offline/unit testing).
    db_session_factory:
        Callable returning a SQLAlchemy session (or ``None`` if running without PostgreSQL).
    asset_enricher:
        Object with ``lookup(ip: str) -> Optional[dict]`` or ``enrich_ip(ip: str)`` method.
    dedup_window_seconds:
        Deduplication window in seconds (default 60).
    storm_threshold:
        Alerts/min from one source IP that triggers storm status (default 100).
    """

    def __init__(
        self,
        redis_client: Any = None,
        db_session_factory: Optional[Callable[[], Any]] = None,
        asset_enricher: Any = None,
        dedup_window_seconds: int = SIGNATURE_DEDUP_WINDOW_SECONDS,
        storm_threshold: int = ALERT_STORM_THRESHOLD,
    ) -> None:
        self._redis = redis_client
        self._db_factory = db_session_factory
        self._enricher = asset_enricher
        self._dedup = DeduplicationTracker(window_seconds=dedup_window_seconds)
        self._storm = AlertStormDetector(threshold_per_min=storm_threshold)
        self._rule_metrics = RuleMetricsTracker()
        self._last_id: str = "$"

    @staticmethod
    def map_severity(suricata_severity: int) -> str:
        """Map Suricata severity (1–4) to BECPL severity strings."""
        return SURICATA_SEVERITY_MAP.get(int(suricata_severity), "low")

    def parse_eve_alert(self, event: Dict[str, Any]) -> Optional[SignatureAlert]:
        """Parse a Suricata EVE JSON alert dictionary into a ``SignatureAlert``."""
        if event.get("event_type") != "alert":
            return None

        alert_block = event.get("alert") or {}
        try:
            sig_id = int(alert_block.get("signature_id", event.get("signature_id", 0)))
            suricata_sev = int(alert_block.get("severity", event.get("severity", 4)))
        except (TypeError, ValueError):
            logger.warning("Malformed Suricata alert numeric fields: %s", event)
            return None

        ts_raw = event.get("timestamp")
        if isinstance(ts_raw, datetime):
            ts = ts_raw if ts_raw.tzinfo else ts_raw.replace(tzinfo=timezone.utc)
        elif isinstance(ts_raw, str) and ts_raw:
            try:
                ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
            except ValueError:
                ts = datetime.now(tz=timezone.utc)
        else:
            ts = datetime.now(tz=timezone.utc)

        src_ip = str(event.get("src_ip") or event.get("source_ip") or "")
        dst_ip = str(event.get("dest_ip") or event.get("dst_ip") or event.get("destination_ip") or "")
        src_port = event.get("src_port") if event.get("src_port") is not None else event.get("source_port")
        dst_port = (
            event.get("dest_port")
            if event.get("dest_port") is not None
            else event.get("dst_port", event.get("destination_port"))
        )

        return SignatureAlert(
            alert_id=str(uuid.uuid4()),
            signature_id=sig_id,
            signature=str(alert_block.get("signature", event.get("signature", ""))),
            category=str(alert_block.get("category", event.get("category", ""))),
            severity=self.map_severity(suricata_sev),
            suricata_severity=suricata_sev,
            proto=str(event.get("proto") or event.get("protocol") or "UNKNOWN").upper(),
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=int(src_port) if src_port is not None and str(src_port) != "" else None,
            dst_port=int(dst_port) if dst_port is not None and str(dst_port) != "" else None,
            timestamp=ts,
            sensor_id=str(event.get("sensor_id", "SEC-SENSOR-01")),
            raw_event=event,
        )

    def _lookup_asset(self, ip: str) -> Optional[Dict[str, Any]]:
        if not ip or self._enricher is None:
            return None
        try:
            if hasattr(self._enricher, "lookup"):
                return self._enricher.lookup(ip)
            if hasattr(self._enricher, "enrich_ip"):
                return self._enricher.enrich_ip(ip)
            if callable(self._enricher):
                return self._enricher(ip)
        except Exception as exc:
            logger.debug("Asset enricher lookup failed for %s: %s", ip, exc)
        return None

    def process_event(
        self,
        event: Dict[str, Any],
        now: Optional[float] = None,
    ) -> Optional[SignatureAlert]:
        """
        Process a single parsed EVE JSON event:
        parse -> track metrics/storm -> deduplicate -> enrich -> persist -> publish.

        Returns the ``SignatureAlert`` if processed (including storm/duplicate flags),
        or ``None`` if the event is not a Suricata alert.
        """
        alert = self.parse_eve_alert(event)
        if alert is None:
            return None

        # Track per-rule rate & alert storms before deduplication suppression
        self._rule_metrics.record(alert.signature_id, alert.signature, now=now)
        alert.is_storm = self._storm.record(alert.src_ip, now=now)

        # Deduplication within 60-second sliding window
        dedup_key = DeduplicationTracker.make_key(
            alert.signature_id, alert.src_ip, alert.dst_ip, alert.dst_port
        )
        alert.is_duplicate = self._dedup.is_duplicate(dedup_key, now=now)
        if alert.is_duplicate:
            logger.debug(
                "Suppressing duplicate Suricata alert sig=%d %s -> %s:%s",
                alert.signature_id,
                alert.src_ip,
                alert.dst_ip,
                alert.dst_port,
            )
            return alert

        if alert.is_storm:
            logger.warning(
                "Alert storm detected from %s (>%d alerts/min)",
                alert.src_ip,
                self._storm.threshold_per_min,
            )

        # Asset enrichment
        alert.src_asset = self._lookup_asset(alert.src_ip)
        alert.dst_asset = self._lookup_asset(alert.dst_ip)

        # Persist to PostgreSQL and publish to Redis
        self._persist_alert(alert)
        self._publish_alert(alert)
        return alert

    def _persist_alert(self, alert: SignatureAlert) -> None:
        """Write enriched alert to PostgreSQL ``becpl_nids.security_events``."""
        if self._db_factory is None or sa is None:
            return

        session = None
        try:
            session = self._db_factory()
            src_asset_id = (alert.src_asset or {}).get("asset_id")
            dst_asset_id = (alert.dst_asset or {}).get("asset_id")
            network_zone = (
                (alert.src_asset or {}).get("network_segment")
                or (alert.dst_asset or {}).get("network_segment")
            )
            evidence = {
                "signature_id": alert.signature_id,
                "signature": alert.signature,
                "category": alert.category,
                "suricata_severity": alert.suricata_severity,
                "is_storm": alert.is_storm,
                "src_asset": alert.src_asset,
                "dst_asset": alert.dst_asset,
            }
            provenance = {
                "source_system": alert.sensor_id,
                "collection_method": "redis_stream",
                "raw_log_ref": REDIS_STREAM_RAW_EVENTS,
                "pipeline_version": "2.0.0",
            }
            session.execute(
                sa.text(
                    """
                    INSERT INTO becpl_nids.security_events (
                        event_id, timestamp, sensor_id,
                        source_ip, destination_ip, source_port, destination_port, protocol,
                        network_zone, source_asset_id, destination_asset_id,
                        event_type, detection_source, severity, confidence,
                        evidence, processing_status, event_provenance, detection_rule_version
                    ) VALUES (
                        CAST(:event_id AS UUID), :timestamp, :sensor_id,
                        CAST(:source_ip AS INET), CAST(:destination_ip AS INET),
                        :source_port, :destination_port, :protocol,
                        :network_zone, :source_asset_id, :destination_asset_id,
                        'alert', 'suricata', :severity, :confidence,
                        CAST(:evidence AS JSONB), 'alerted',
                        CAST(:provenance AS JSONB), :rule_version
                    )
                    ON CONFLICT (event_id, timestamp) DO NOTHING
                    """
                ),
                {
                    "event_id": alert.alert_id,
                    "timestamp": alert.timestamp,
                    "sensor_id": alert.sensor_id,
                    "source_ip": alert.src_ip or None,
                    "destination_ip": alert.dst_ip or None,
                    "source_port": alert.src_port,
                    "destination_port": alert.dst_port,
                    "protocol": alert.proto,
                    "network_zone": network_zone,
                    "source_asset_id": src_asset_id,
                    "destination_asset_id": dst_asset_id,
                    "severity": alert.severity,
                    "confidence": 1.0,
                    "evidence": json.dumps(evidence),
                    "provenance": json.dumps(provenance),
                    "rule_version": f"sid-{alert.signature_id}",
                },
            )
            session.commit()
        except Exception as exc:
            logger.error("Failed to persist SignatureAlert %s: %s", alert.alert_id, exc)
            if session is not None:
                try:
                    session.rollback()
                except Exception:
                    pass
        finally:
            if session is not None:
                try:
                    session.close()
                except Exception:
                    pass

    def _publish_alert(self, alert: SignatureAlert) -> None:
        """Publish enriched alert to Redis stream ``detections:signature``."""
        if self._redis is None:
            return
        try:
            payload = {
                "alert_id": alert.alert_id,
                "signature_id": str(alert.signature_id),
                "signature": alert.signature,
                "category": alert.category,
                "severity": alert.severity,
                "suricata_severity": str(alert.suricata_severity),
                "proto": alert.proto,
                "src_ip": alert.src_ip,
                "dst_ip": alert.dst_ip,
                "src_port": "" if alert.src_port is None else str(alert.src_port),
                "dst_port": "" if alert.dst_port is None else str(alert.dst_port),
                "timestamp": alert.timestamp.isoformat(),
                "is_storm": "true" if alert.is_storm else "false",
                "src_asset": json.dumps(alert.src_asset or {}),
                "dst_asset": json.dumps(alert.dst_asset or {}),
            }
            self._redis.xadd(REDIS_STREAM_SIGNATURE_DETECTIONS, payload)
        except Exception as exc:
            logger.error("Failed to publish SignatureAlert to Redis: %s", exc)

    def _decode_stream_entry(self, entry_data: Dict[Any, Any]) -> Optional[Dict[str, Any]]:
        raw = entry_data.get(b"payload") or entry_data.get("payload") or entry_data.get(b"data") or entry_data.get("data")
        if raw is not None:
            if isinstance(raw, bytes):
                raw = raw.decode("utf-8", errors="replace")
            try:
                return json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                return None
        # Fallback: flat dictionary entry
        decoded: Dict[str, Any] = {}
        for k, v in entry_data.items():
            dk = k.decode("utf-8") if isinstance(k, bytes) else str(k)
            dv = v.decode("utf-8") if isinstance(v, bytes) else v
            if isinstance(dv, str) and (dv.startswith("{") or dv.startswith("[")):
                try:
                    dv = json.loads(dv)
                except json.JSONDecodeError:
                    pass
            decoded[dk] = dv
        return decoded

    def run_once(self, block_ms: int = 1000, count: int = 100) -> List[SignatureAlert]:
        """Read one batch from Redis ``events:raw`` and return processed alerts."""
        if self._redis is None:
            return []
        processed: List[SignatureAlert] = []
        messages = self._redis.xread(
            {REDIS_STREAM_RAW_EVENTS: self._last_id},
            count=count,
            block=block_ms,
        )
        if not messages:
            return processed
        for _stream, entries in messages:
            for entry_id, entry_data in entries:
                self._last_id = (
                    entry_id.decode("utf-8") if isinstance(entry_id, bytes) else str(entry_id)
                )
                event = self._decode_stream_entry(entry_data)
                if event:
                    result = self.process_event(event)
                    if result is not None and not result.is_duplicate:
                        processed.append(result)
        return processed

    def run(self, block_ms: int = 5000) -> None:
        """Long-running consumer loop reading Suricata alerts from ``events:raw``."""
        logger.info("SignatureEngine started — consuming %s", REDIS_STREAM_RAW_EVENTS)
        while True:
            try:
                self.run_once(block_ms=block_ms)
            except KeyboardInterrupt:
                logger.info("SignatureEngine shutting down")
                break
            except Exception as exc:
                logger.error("SignatureEngine loop error: %s", exc, exc_info=True)
                time.sleep(1.0)

    def get_rule_rate(self, signature_id: int) -> int:
        """Current alerts/min for a specific Suricata signature ID."""
        return self._rule_metrics.alerts_per_minute(signature_id)

    def get_top_rules(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Top N triggered Suricata rules."""
        return self._rule_metrics.top_triggered_rules(limit=limit)

    def get_source_rate(self, src_ip: str) -> int:
        """Current alerts/min from a specific source IP."""
        return self._storm.current_rate(src_ip)

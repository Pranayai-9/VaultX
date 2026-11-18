"""
encrypted_traffic_analyzer.py — Metadata-Only Encrypted Traffic Intelligence Engine for VaultX.

BECPL (Bharat Electronics Components Pvt. Ltd.), Pune — Manufacturing-Aware Hybrid NIDS.

IMPORTANT VISIBILITY NOTICE
---------------------------
TLS 1.3, ECH and QUIC can restrict available metadata. Features extracted depend on what
passive monitoring can observe. Do not assume full TLS metadata visibility.

Overview
--------
* Analyses TLS / HTTPS / QUIC flows strictly via **observable network and handshake metadata**
  (never decrypts traffic and never assumes payload inspection).
* Always-available flow metadata:
  ``src_ip``, ``dst_ip``, ``src_port``, ``dst_port``, ``flow_duration``, ``bytes_up``,
  ``bytes_down``, ``packet_count``, ``inter_packet_interval`` stats, ``timestamp``
  (time-of-day, day-of-week).
* Optional Zeek ``tls.log`` metadata (when observable):
  ``tls_version``, ``cipher_suite``, ``sni``, ``cert_issuer``, ``cert_subject``,
  ``cert_validity_days``, ``ja3_hash``, ``ja3s_hash``.
* When TLS metadata is restricted (TLS 1.3 ECH / QUIC), operates gracefully on flow metadata only.
* **Multi-signal correlation gate**: requires MULTIPLE distinct anomaly signals (default >= 2)
  before publishing a finding to Redis stream ``detections:encrypted_traffic``.
* Includes destination reputation lookup (CISA KEV source IPs & Tor exit nodes in PostgreSQL
  ``becpl_nids.threat_intel`` table) and autocorrelation-based C2 beacon detection.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import math
import uuid
from collections import defaultdict, deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

import numpy as np

try:
    import sqlalchemy as sa
except ImportError:  # pragma: no cover
    sa = None  # type: ignore[assignment]

try:
    from backend.detection.detection_config import (
        BEACON_INTERVAL_CORRELATION_THRESHOLD,
        CRITICAL_ASSET_VOLUME_THRESHOLD_BYTES,
        ENCRYPTED_TRAFFIC_DURATION_THRESHOLD_HOURS,
        ENCRYPTED_TRAFFIC_MIN_SIGNALS,
        ENCRYPTED_TRAFFIC_UPLOAD_RATIO_THRESHOLD,
        JA3_HISTORY_DAYS,
        REDIS_STREAM_ENCRYPTED_TRAFFIC,
        SHORT_CERT_VALIDITY_DAYS,
        UNUSUAL_HOURS_END,
        UNUSUAL_HOURS_START,
    )
except ImportError:
    from detection_config import (  # type: ignore[no-redef]
        BEACON_INTERVAL_CORRELATION_THRESHOLD,
        CRITICAL_ASSET_VOLUME_THRESHOLD_BYTES,
        ENCRYPTED_TRAFFIC_DURATION_THRESHOLD_HOURS,
        ENCRYPTED_TRAFFIC_MIN_SIGNALS,
        ENCRYPTED_TRAFFIC_UPLOAD_RATIO_THRESHOLD,
        JA3_HISTORY_DAYS,
        REDIS_STREAM_ENCRYPTED_TRAFFIC,
        SHORT_CERT_VALIDITY_DAYS,
        UNUSUAL_HOURS_END,
        UNUSUAL_HOURS_START,
    )

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers & Data Models
# ---------------------------------------------------------------------------


def is_external_ip(ip_str: str) -> bool:
    """Return True if ``ip_str`` is a routable external (non-RFC1918 / non-loopback) IP."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return not (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_reserved
        )
    except ValueError:
        return False


def is_internal_ip(ip_str: str) -> bool:
    """Return True if ``ip_str`` is an internal BECPL/private IP address."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return addr.is_private
    except ValueError:
        return False


@dataclass
class EncryptedTrafficSignal:
    """Single observable anomaly indicator extracted from encrypted flow metadata."""

    signal_name: str
    score: float
    description: str
    evidence: Dict[str, Any] = field(default_factory=dict)


@dataclass
class EncryptedTrafficFinding:
    """Finding emitted by ``EncryptedTrafficAnalyzer`` when multiple signals fire."""

    finding_id: str
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    timestamp: str
    metadata_visibility: str  # "full_tls", "partial_tls", or "flow_only_ech_quic"
    signals: List[EncryptedTrafficSignal]
    signal_count: int
    triggered_finding: bool
    destination_reputation: Dict[str, Any]
    beacon_analysis: Dict[str, Any]
    evidence: Dict[str, Any]
    published: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "flow_id": self.flow_id,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "timestamp": self.timestamp,
            "metadata_visibility": self.metadata_visibility,
            "signals": [asdict(s) for s in self.signals],
            "signal_count": self.signal_count,
            "triggered_finding": self.triggered_finding,
            "destination_reputation": self.destination_reputation,
            "beacon_analysis": self.beacon_analysis,
            "evidence": self.evidence,
            "published": self.published,
        }


# ---------------------------------------------------------------------------
# C2 Beacon Autocorrelation Detector
# ---------------------------------------------------------------------------


def compute_beacon_autocorrelation(
    connection_timestamps: List[float],
    min_connections: int = 5,
) -> Dict[str, Any]:
    """
    Detect periodic C2 beaconing using autocorrelation of inter-connection intervals.

    Parameters
    ----------
    connection_timestamps:
        Sequence of Unix timestamps (seconds) of sequential connections from one
        internal source to the same external destination.
    min_connections:
        Minimum sequential connections required before computing periodicity.

    Returns
    -------
    dict with ``is_beacon``, ``correlation``, ``mean_interval_s``, ``std_interval_s``,
    ``cv`` (coefficient of variation), and ``sample_intervals``.
    """
    if len(connection_timestamps) < min_connections:
        return {
            "is_beacon": False,
            "correlation": 0.0,
            "mean_interval_s": 0.0,
            "std_interval_s": 0.0,
            "cv": 1.0,
            "sample_intervals": len(connection_timestamps) - 1 if connection_timestamps else 0,
        }

    ordered = sorted(float(t) for t in connection_timestamps)
    intervals = np.diff(ordered)
    intervals = intervals[intervals > 0]
    if len(intervals) < (min_connections - 1):
        return {
            "is_beacon": False,
            "correlation": 0.0,
            "mean_interval_s": 0.0,
            "std_interval_s": 0.0,
            "cv": 1.0,
            "sample_intervals": int(len(intervals)),
        }

    mean_iv = float(np.mean(intervals))
    std_iv = float(np.std(intervals))
    cv = (std_iv / mean_iv) if mean_iv > 0 else 1.0

    # Case 1: Strictly or tightly periodic beaconing (constant interval +/- low jitter).
    # When variance approaches zero, Pearson autocorrelation is undefined (0/0),
    # yet regularity is maximal — capture regularity explicitly via (1 - cv).
    if mean_iv >= 1.0 and cv < 0.15:
        regularity_corr = max(0.0, min(1.0, 1.0 - cv))
    else:
        regularity_corr = 0.0

    # Case 2: Standard normalized autocorrelation across lags 1 .. len//2
    # Captures alternating/multi-phase periodic beacon patterns as well.
    centered = intervals - mean_iv
    denom = float(np.dot(centered, centered))
    max_autocorr = 0.0
    if denom > 1e-12:
        max_lag = max(1, len(intervals) // 2)
        for lag in range(1, max_lag + 1):
            a = centered[:-lag]
            b = centered[lag:]
            norm = math.sqrt(float(np.dot(a, a)) * float(np.dot(b, b)))
            if norm > 1e-12:
                r = float(np.dot(a, b) / norm)
                if r > max_autocorr:
                    max_autocorr = r

    # Also compute histogram/pulse-train autocorrelation on binned timestamps for jittered beacons
    effective_corr = round(max(regularity_corr, max_autocorr), 4)
    is_beacon = effective_corr >= BEACON_INTERVAL_CORRELATION_THRESHOLD

    return {
        "is_beacon": is_beacon,
        "correlation": effective_corr,
        "mean_interval_s": round(mean_iv, 3),
        "std_interval_s": round(std_iv, 3),
        "cv": round(cv, 4),
        "sample_intervals": int(len(intervals)),
    }


# ---------------------------------------------------------------------------
# Main Encrypted Traffic Analyzer
# ---------------------------------------------------------------------------


class EncryptedTrafficAnalyzer:
    """
    Analyses encrypted network flows (TLS / HTTPS / QUIC) using observable metadata only.

    TLS 1.3, ECH and QUIC can restrict available metadata. Features extracted depend on what
    passive monitoring can observe. Do not assume full TLS metadata visibility.
    """

    def __init__(
        self,
        redis_client: Any = None,
        db_session_factory: Optional[Callable[[], Any]] = None,
        asset_enricher: Any = None,
        blocklist_ips: Optional[Dict[str, str]] = None,
        upload_ratio_threshold: float = ENCRYPTED_TRAFFIC_UPLOAD_RATIO_THRESHOLD,
        duration_threshold_hours: float = ENCRYPTED_TRAFFIC_DURATION_THRESHOLD_HOURS,
        beacon_correlation_threshold: float = BEACON_INTERVAL_CORRELATION_THRESHOLD,
        min_signals: int = ENCRYPTED_TRAFFIC_MIN_SIGNALS,
        critical_volume_bytes: int = CRITICAL_ASSET_VOLUME_THRESHOLD_BYTES,
    ) -> None:
        self._redis = redis_client
        self._db_factory = db_session_factory
        self._enricher = asset_enricher

        self.upload_ratio_threshold = float(upload_ratio_threshold)
        self.duration_threshold_hours = float(duration_threshold_hours)
        self.beacon_correlation_threshold = float(beacon_correlation_threshold)
        self.min_signals = int(min_signals)
        self.critical_volume_bytes = int(critical_volume_bytes)

        # Local reputation cache: ip -> source/reason (e.g. "cisa_kev", "tor_exit_node")
        self._blocklist: Dict[str, str] = dict(blocklist_ips or {})

        # Historical state per asset / pair
        self._known_external_dests: Dict[str, Set[str]] = defaultdict(set)
        # asset_key -> {ja3_hash: last_seen_datetime}
        self._ja3_history: Dict[str, Dict[str, datetime]] = defaultdict(dict)
        # (src_ip, dst_ip) -> deque of connection Unix timestamps
        self._connection_times: Dict[Tuple[str, str], deque[float]] = defaultdict(
            lambda: deque(maxlen=100)
        )

    def seed_known_destination(self, src_ip: str, dst_ip: str) -> None:
        """Register an external destination as previously seen for ``src_ip``."""
        self._known_external_dests[src_ip].add(dst_ip)

    def seed_ja3_history(
        self,
        src_ip: str,
        ja3_hash: str,
        seen_at: Optional[datetime] = None,
    ) -> None:
        """Record a known-good JA3 hash for ``src_ip`` within the 30-day history."""
        ts = seen_at or datetime.now(tz=timezone.utc)
        self._ja3_history[src_ip][ja3_hash] = ts

    def add_blocklist_ip(self, ip_address: str, source: str = "cisa_kev") -> None:
        """Add an IP address to the local threat intelligence reputation blocklist."""
        self._blocklist[ip_address] = source

    def check_destination_reputation(self, dst_ip: str) -> Dict[str, Any]:
        """
        Check ``dst_ip`` against local blocklist and PostgreSQL ``becpl_nids.threat_intel``
        (CISA KEV source IPs and Tor exit nodes).
        """
        if dst_ip in self._blocklist:
            return {
                "is_malicious": True,
                "source": self._blocklist[dst_ip],
                "indicator": dst_ip,
            }

        if self._db_factory is not None and sa is not None:
            session = None
            try:
                session = self._db_factory()
                row = session.execute(
                    sa.text(
                        """
                        SELECT source, indicator_type, description
                        FROM becpl_nids.threat_intel
                        WHERE indicator_value = :ip
                          AND is_active = TRUE
                        LIMIT 1
                        """
                    ),
                    {"ip": dst_ip},
                ).fetchone()
                if row is not None:
                    src = str(row[0])
                    self._blocklist[dst_ip] = src
                    return {
                        "is_malicious": True,
                        "source": src,
                        "indicator": dst_ip,
                        "description": str(row[2]) if len(row) > 2 and row[2] else "",
                    }
            except Exception as exc:
                logger.debug("threat_intel DB lookup skipped/failed for %s: %s", dst_ip, exc)
            finally:
                if session is not None:
                    try:
                        session.close()
                    except Exception:
                        pass

        return {"is_malicious": False, "source": None, "indicator": dst_ip}

    def _lookup_asset(self, ip: str, flow: Dict[str, Any]) -> Dict[str, Any]:
        if isinstance(flow.get("src_asset"), dict):
            return flow["src_asset"]
        if self._enricher is not None:
            try:
                if hasattr(self._enricher, "lookup"):
                    res = self._enricher.lookup(ip)
                    if res:
                        return res
                elif callable(self._enricher):
                    res = self._enricher(ip)
                    if res:
                        return res
            except Exception:
                pass
        return {}

    def _parse_timestamp(self, raw_ts: Any) -> datetime:
        if isinstance(raw_ts, datetime):
            return raw_ts if raw_ts.tzinfo else raw_ts.replace(tzinfo=timezone.utc)
        if isinstance(raw_ts, (int, float)):
            return datetime.fromtimestamp(float(raw_ts), tz=timezone.utc)
        if isinstance(raw_ts, str) and raw_ts:
            try:
                return datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
            except ValueError:
                pass
        return datetime.now(tz=timezone.utc)

    def _classify_metadata_visibility(self, tls_meta: Dict[str, Any], proto: str) -> str:
        has_ja3 = bool(tls_meta.get("ja3_hash"))
        has_cert = (
            tls_meta.get("cert_validity_days") is not None
            or bool(tls_meta.get("cert_subject"))
            or bool(tls_meta.get("cert_issuer"))
        )
        has_sni = bool(tls_meta.get("sni") or tls_meta.get("SNI"))
        if proto.upper() == "QUIC" or (not has_ja3 and not has_cert and not has_sni):
            return "flow_only_ech_quic"
        if has_ja3 and has_cert:
            return "full_tls"
        return "partial_tls"

    def analyze_flow(
        self,
        flow: Dict[str, Any],
        publish: bool = True,
    ) -> EncryptedTrafficFinding:
        """
        Analyse a single encrypted flow using observable metadata only.

        Evaluates all 7 anomaly signals + destination reputation. Emits a finding
        (``triggered_finding=True``) and publishes to ``detections:encrypted_traffic``
        ONLY when ``len(signals) >= self.min_signals``.
        """
        flow_id = str(flow.get("flow_id") or flow.get("event_id") or uuid.uuid4())
        src_ip = str(flow.get("src_ip") or flow.get("source_ip") or "")
        dst_ip = str(flow.get("dst_ip") or flow.get("destination_ip") or "")
        src_port = flow.get("src_port", flow.get("source_port"))
        dst_port = flow.get("dst_port", flow.get("destination_port"))
        proto = str(flow.get("protocol") or flow.get("proto") or "TLS")

        duration_s = float(flow.get("flow_duration") or flow.get("connection_duration") or 0.0)
        bytes_up = float(flow.get("bytes_up") or flow.get("total_fwd_bytes") or 0.0)
        bytes_down = float(flow.get("bytes_down") or flow.get("total_bwd_bytes") or 0.0)
        packet_count = int(flow.get("packet_count") or flow.get("packets_transferred") or 0)
        ipi_stats = flow.get("inter_packet_interval") or {}
        ts = self._parse_timestamp(flow.get("timestamp"))

        # Optional TLS metadata (may be absent for TLS 1.3 ECH / QUIC)
        tls_meta: Dict[str, Any] = dict(flow.get("tls_metadata") or flow.get("encryption_metadata") or {})
        for key in (
            "tls_version",
            "cipher_suite",
            "sni",
            "SNI",
            "cert_issuer",
            "cert_subject",
            "cert_validity_days",
            "self_signed",
            "ja3_hash",
            "ja3s_hash",
        ):
            if key in flow and key not in tls_meta:
                tls_meta[key] = flow[key]

        visibility = self._classify_metadata_visibility(tls_meta, proto)
        dst_external = is_external_ip(dst_ip)
        src_internal = is_internal_ip(src_ip)
        src_asset = self._lookup_asset(src_ip, flow)

        signals: List[EncryptedTrafficSignal] = []

        # ------------------------------------------------------------------
        # Signal 1: High upload/download ratio (> 0.8 upload) to external IP
        # ------------------------------------------------------------------
        total_bytes = bytes_up + bytes_down
        upload_ratio = (bytes_up / total_bytes) if total_bytes > 0 else 0.0
        if dst_external and total_bytes > 0 and upload_ratio > self.upload_ratio_threshold:
            signals.append(
                EncryptedTrafficSignal(
                    signal_name="high_upload_ratio",
                    score=min(1.0, upload_ratio),
                    description=(
                        f"Upload ratio {upload_ratio:.2f} exceeds threshold "
                        f"{self.upload_ratio_threshold:.2f} to external IP {dst_ip}"
                    ),
                    evidence={
                        "bytes_up": bytes_up,
                        "bytes_down": bytes_down,
                        "upload_ratio": round(upload_ratio, 4),
                    },
                )
            )

        # ------------------------------------------------------------------
        # Signal 2: Long-duration flows (> 2 hours) to previously unseen external dest
        # ------------------------------------------------------------------
        duration_hours = duration_s / 3600.0
        was_known_dest = dst_ip in self._known_external_dests[src_ip]
        if dst_external and (not was_known_dest) and duration_hours > self.duration_threshold_hours:
            signals.append(
                EncryptedTrafficSignal(
                    signal_name="long_duration_unseen_external",
                    score=min(1.0, duration_hours / (self.duration_threshold_hours * 2.0)),
                    description=(
                        f"Flow lasted {duration_hours:.2f}h (>{self.duration_threshold_hours}h) "
                        f"to previously unseen external destination {dst_ip}"
                    ),
                    evidence={
                        "duration_hours": round(duration_hours, 3),
                        "dst_ip": dst_ip,
                    },
                )
            )

        # ------------------------------------------------------------------
        # Signal 3: Unusually large data volumes from critical assets
        # (engineering workstations, firmware servers, criticality == critical/high)
        # ------------------------------------------------------------------
        asset_crit = str(src_asset.get("criticality", "")).lower()
        asset_dept = str(src_asset.get("owner_department", "")).lower()
        asset_role = str(src_asset.get("network_segment", "")).lower()
        asset_notes = str(src_asset.get("hostname", "")).lower()
        is_critical_asset = (
            asset_crit == "critical"
            or "engineering" in asset_dept
            or "engineering" in asset_role
            or "firmware" in asset_notes
            or "eng-" in asset_notes
            or bool(flow.get("is_critical_asset", False))
        )
        if is_critical_asset and bytes_up >= self.critical_volume_bytes:
            signals.append(
                EncryptedTrafficSignal(
                    signal_name="large_volume_critical_asset",
                    score=min(1.0, bytes_up / (self.critical_volume_bytes * 2.0)),
                    description=(
                        f"Critical asset {src_asset.get('asset_id') or src_ip} transferred "
                        f"{bytes_up / (1024 * 1024):.1f} MB outbound"
                    ),
                    evidence={
                        "asset_id": src_asset.get("asset_id"),
                        "bytes_up": bytes_up,
                        "threshold_bytes": self.critical_volume_bytes,
                    },
                )
            )

        # ------------------------------------------------------------------
        # Signal 4: Connections at unusual hours (03:00–05:59) from internal to external
        # ------------------------------------------------------------------
        if src_internal and dst_external and (UNUSUAL_HOURS_START <= ts.hour <= UNUSUAL_HOURS_END):
            signals.append(
                EncryptedTrafficSignal(
                    signal_name="unusual_hour_external_connection",
                    score=0.6,
                    description=(
                        f"Outbound encrypted flow at unusual hour ({ts.strftime('%H:%M')} UTC, "
                        f"day={ts.strftime('%A')}) from {src_ip} to {dst_ip}"
                    ),
                    evidence={
                        "hour_utc": ts.hour,
                        "day_of_week": ts.strftime("%A"),
                    },
                )
            )

        # ------------------------------------------------------------------
        # Signal 5: JA3 hash not seen in previous 30 days from this asset
        # (only evaluated when TLS metadata exposes ja3_hash)
        # ------------------------------------------------------------------
        ja3_hash = tls_meta.get("ja3_hash")
        if ja3_hash:
            history = self._ja3_history[src_ip]
            cutoff = ts - timedelta(days=JA3_HISTORY_DAYS)
            # Prune entries older than 30 days
            expired_ja3 = [h for h, seen in history.items() if seen < cutoff]
            for h in expired_ja3:
                del history[h]
            # Flag novel JA3 when asset has established history and this hash is unseen
            if history and ja3_hash not in history:
                signals.append(
                    EncryptedTrafficSignal(
                        signal_name="unseen_ja3_fingerprint",
                        score=0.65,
                        description=(
                            f"JA3 fingerprint {ja3_hash} not seen in past {JA3_HISTORY_DAYS} days "
                            f"from {src_ip}"
                        ),
                        evidence={
                            "ja3_hash": ja3_hash,
                            "known_ja3_count": len(history),
                        },
                    )
                )
            history[ja3_hash] = ts

        # ------------------------------------------------------------------
        # Signal 6: Short-lived (<30 days) or self-signed TLS cert to external IP
        # (only evaluated when TLS certificate metadata is observable)
        # ------------------------------------------------------------------
        cert_validity = tls_meta.get("cert_validity_days")
        cert_issuer = tls_meta.get("cert_issuer")
        cert_subject = tls_meta.get("cert_subject")
        is_self_signed = bool(tls_meta.get("self_signed", False)) or (
            bool(cert_issuer) and bool(cert_subject) and str(cert_issuer) == str(cert_subject)
        )
        short_cert = cert_validity is not None and float(cert_validity) < SHORT_CERT_VALIDITY_DAYS
        if dst_external and (short_cert or is_self_signed):
            reasons = []
            if short_cert:
                reasons.append(f"validity={cert_validity}d (<{SHORT_CERT_VALIDITY_DAYS}d)")
            if is_self_signed:
                reasons.append("self-signed certificate")
            signals.append(
                EncryptedTrafficSignal(
                    signal_name="suspicious_tls_certificate",
                    score=0.75,
                    description=f"Suspicious TLS certificate to external IP {dst_ip}: {', '.join(reasons)}",
                    evidence={
                        "cert_validity_days": cert_validity,
                        "self_signed": is_self_signed,
                        "cert_issuer": cert_issuer,
                        "cert_subject": cert_subject,
                        "sni": tls_meta.get("sni") or tls_meta.get("SNI"),
                    },
                )
            )

        # ------------------------------------------------------------------
        # Signal 7: C2 Beacon Detection (periodic sequential connections)
        # ------------------------------------------------------------------
        pair_key = (src_ip, dst_ip)
        conn_deque = self._connection_times[pair_key]
        conn_deque.append(ts.timestamp())
        beacon_info = compute_beacon_autocorrelation(list(conn_deque))
        if dst_external and beacon_info["correlation"] >= self.beacon_correlation_threshold:
            beacon_info["is_beacon"] = True
            signals.append(
                EncryptedTrafficSignal(
                    signal_name="c2_beacon_pattern",
                    score=min(1.0, beacon_info["correlation"]),
                    description=(
                        f"Periodic C2 beacon pattern detected to {dst_ip} "
                        f"(correlation={beacon_info['correlation']:.2f}, "
                        f"mean_interval={beacon_info['mean_interval_s']:.1f}s)"
                    ),
                    evidence=beacon_info,
                )
            )

        # ------------------------------------------------------------------
        # Destination reputation check (CISA KEV / Tor exit nodes)
        # ------------------------------------------------------------------
        reputation = self.check_destination_reputation(dst_ip) if dst_external else {
            "is_malicious": False,
            "source": None,
            "indicator": dst_ip,
        }
        if reputation["is_malicious"]:
            signals.append(
                EncryptedTrafficSignal(
                    signal_name="malicious_destination_reputation",
                    score=0.95,
                    description=(
                        f"Destination {dst_ip} matched threat_intel blocklist "
                        f"({reputation['source']})"
                    ),
                    evidence=reputation,
                )
            )

        # Update seen destinations AFTER evaluating Signal 2
        if dst_external:
            self._known_external_dests[src_ip].add(dst_ip)

        # Multi-signal gate: require MULTIPLE signals (>= min_signals)
        triggered = len(signals) >= self.min_signals

        evidence_dict = {
            "flow_metadata": {
                "flow_duration_s": duration_s,
                "bytes_up": bytes_up,
                "bytes_down": bytes_down,
                "upload_ratio": round(upload_ratio, 4),
                "packet_count": packet_count,
                "inter_packet_interval": ipi_stats,
                "hour_utc": ts.hour,
                "day_of_week": ts.strftime("%A"),
            },
            "tls_metadata_observed": {
                k: v for k, v in tls_meta.items() if v is not None
            },
            "metadata_visibility": visibility,
            "signals": [asdict(s) for s in signals],
            "destination_reputation": reputation,
            "beacon_analysis": beacon_info,
        }

        finding = EncryptedTrafficFinding(
            finding_id=str(uuid.uuid4()),
            flow_id=flow_id,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=int(src_port) if src_port is not None else None,
            dst_port=int(dst_port) if dst_port is not None else None,
            timestamp=ts.isoformat(),
            metadata_visibility=visibility,
            signals=signals,
            signal_count=len(signals),
            triggered_finding=triggered,
            destination_reputation=reputation,
            beacon_analysis=beacon_info,
            evidence=evidence_dict,
        )

        if triggered and publish:
            finding.published = self._publish_finding(finding)

        return finding

    def _publish_finding(self, finding: EncryptedTrafficFinding) -> bool:
        """Publish multi-signal encrypted traffic finding to Redis ``detections:encrypted_traffic``."""
        if self._redis is None:
            return False
        try:
            payload = {
                "finding_id": finding.finding_id,
                "flow_id": finding.flow_id,
                "src_ip": finding.src_ip,
                "dst_ip": finding.dst_ip,
                "src_port": "" if finding.src_port is None else str(finding.src_port),
                "dst_port": "" if finding.dst_port is None else str(finding.dst_port),
                "timestamp": finding.timestamp,
                "metadata_visibility": finding.metadata_visibility,
                "signal_count": str(finding.signal_count),
                "evidence": json.dumps(finding.evidence),
            }
            self._redis.xadd(REDIS_STREAM_ENCRYPTED_TRAFFIC, payload)
            return True
        except Exception as exc:
            logger.error("Failed to publish encrypted traffic finding to Redis: %s", exc)
            return False

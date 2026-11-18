"""
VaultX - Behavioural Deviation Detector
BECPL Manufacturing-Aware Hybrid NIDS - Phase 2

Scores an enriched event against its asset/identity baseline using 8 signals:
  1. new_destination        - IP/domain not in normal_destinations (scored by dest criticality)
  2. unusual_port           - destination port not in normal_ports (0.3 base)
  3. time_anomaly           - activity outside normal_hours (0.4 base)
  4. volume_anomaly         - bytes transferred > mean + 3*std (proportional to z-score)
  5. frequency_anomaly      - connections/hour > mean + 3*std (0.5 base)
  6. new_peer               - peer asset not in normal_peers (scored by peer criticality)
  7. cross_vlan_unexpected  - connection to VLAN not normally accessed (0.6 base)
  8. maintenance_window_check - dampens all signal scores by MAINTENANCE_WINDOW_SCORE_REDUCTION (0.5)

False-positive reduction policy:
  - Single deviation signal              -> OBSERVATION (logged, NOT an alert)
  - Score > 0.50 AND >= 2 signals        -> LOW anomaly indicator
  - Score > 0.70 AND >= 3 signals        -> MEDIUM anomaly indicator
  - Score > 0.85 AND >= 4 signals        -> HIGH anomaly indicator
  - Approved firmware deployment window  -> SUPPRESSED
  - All anomaly indicators are EVIDENCE for the correlation engine, never standalone alerts.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set, Union

from backend.behavioural.baseline_engine import (
    AssetBaseline,
    IdentityBaseline,
    ip_to_vlan,
)
from backend.behavioural.behaviour_config import (
    APPROVED_ENGINEERING_ENTITY_TYPES,
    CRITICALITY_SCORES,
    DEVIATION_ALERT_THRESHOLD_HIGH,
    DEVIATION_ALERT_THRESHOLD_LOW,
    DEVIATION_ALERT_THRESHOLD_MEDIUM,
    DEVIATION_MIN_SIGNALS_HIGH,
    DEVIATION_MIN_SIGNALS_LOW,
    DEVIATION_MIN_SIGNALS_MEDIUM,
    ENGINEERING_VLAN_ID,
    MAINTENANCE_WINDOW_SCORE_REDUCTION,
    OT_VLAN_ID,
    SIGNAL_WEIGHTS,
)

logger = logging.getLogger(__name__)

IST = timezone(timedelta(hours=5, minutes=30))

# Optionally load overrides from backend.detection.detection_config if available
try:
    from backend.detection import detection_config as _det_cfg  # type: ignore

    _EXTERNAL_WEIGHTS: Dict[str, float] = getattr(
        _det_cfg, "DEVIATION_SIGNAL_WEIGHTS", SIGNAL_WEIGHTS
    )
except Exception:
    _EXTERNAL_WEIGHTS = SIGNAL_WEIGHTS


@dataclass
class DeviationSignal:
    """Single behavioural deviation signal emitted by the detector."""

    name: str
    score: float
    description: str
    raw_score: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "score": round(self.score, 4),
            "raw_score": round(self.raw_score, 4),
            "description": self.description,
            "metadata": self.metadata,
        }


@dataclass
class DeviationResult:
    """
    Aggregated behavioural deviation evaluation result.

    All non-suppressed indicators with severity LOW/MEDIUM/HIGH are emitted as
    evidence for the correlation engine (`is_evidence_only=True`), never as
    standalone alerts.
    """

    asset_id: Optional[str]
    identity_id: Optional[str]
    signals: List[DeviationSignal]
    combined_score: float
    severity: str  # NONE | OBSERVATION | LOW | MEDIUM | HIGH | SUPPRESSED
    suppress_reason: Optional[str] = None
    in_maintenance_window: bool = False
    is_evidence_only: bool = True

    @property
    def is_anomaly_indicator(self) -> bool:
        """True if this result qualifies as a LOW/MEDIUM/HIGH correlation indicator."""
        return self.severity in ("LOW", "MEDIUM", "HIGH")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "identity_id": self.identity_id,
            "signals": [s.to_dict() for s in self.signals],
            "signal_count": len(self.signals),
            "combined_score": round(self.combined_score, 4),
            "severity": self.severity,
            "suppress_reason": self.suppress_reason,
            "in_maintenance_window": self.in_maintenance_window,
            "is_evidence_only": self.is_evidence_only,
        }


class DeviationDetector:
    """
    Evaluates enriched network/security events against an AssetBaseline or
    IdentityBaseline and produces a DeviationResult.
    """

    def __init__(
        self,
        weights: Optional[Dict[str, float]] = None,
        approved_engineering_assets: Optional[Set[str]] = None,
        approved_firmware_identities: Optional[Set[str]] = None,
    ) -> None:
        self._weights: Dict[str, float] = dict(weights or _EXTERNAL_WEIGHTS)
        self._approved_eng_assets: Set[str] = set(approved_engineering_assets or set())
        self._approved_firmware_identities: Set[str] = set(
            approved_firmware_identities or set()
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evaluate(
        self,
        event: Dict[str, Any],
        baseline: Union[AssetBaseline, IdentityBaseline],
    ) -> DeviationResult:
        """
        Compute deviation signals, apply maintenance window dampening and
        firmware deployment suppression, and classify severity.

        Expected event fields (all optional where sensible):
          - asset_id / source_asset_id
          - identity_id
          - timestamp (datetime or ISO str)
          - dst_ip / destination_ip / dst_domain
          - dst_criticality (critical|high|medium|low)
          - dst_port / destination_port
          - bytes_transferred / hourly_bytes
          - connections_per_hour
          - peer_asset_id / destination_asset_id
          - peer_criticality (critical|high|medium|low)
          - src_vlan / source_vlan
          - dst_vlan / destination_vlan
          - is_approved_engineering_system (bool, optional)
          - is_approved_firmware_identity (bool, optional)
        """
        asset_id = event.get("asset_id") or event.get("source_asset_id") or getattr(
            baseline, "asset_id", None
        )
        identity_id = event.get("identity_id") or getattr(baseline, "identity_id", None)
        ts = self._parse_timestamp(event.get("timestamp"))

        # Check approved maintenance window
        mw = baseline.is_in_maintenance_window(ts)
        in_maintenance = mw is not None

        # Check OT firmware deployment suppression rule
        suppress_reason = self._check_firmware_deployment_suppression(
            event=event,
            baseline=baseline,
            asset_id=asset_id,
            identity_id=identity_id,
            in_maintenance=in_maintenance,
        )
        if suppress_reason is not None:
            logger.info(
                "Suppressed deviation for asset=%s identity=%s: %s",
                asset_id,
                identity_id,
                suppress_reason,
            )
            return DeviationResult(
                asset_id=asset_id,
                identity_id=identity_id,
                signals=[],
                combined_score=0.0,
                severity="SUPPRESSED",
                suppress_reason=suppress_reason,
                in_maintenance_window=in_maintenance,
                is_evidence_only=True,
            )

        # Evaluate signals 1..7
        signals: List[DeviationSignal] = []

        sig_dest = self._check_new_destination(event, baseline)
        if sig_dest is not None:
            signals.append(sig_dest)

        sig_port = self._check_unusual_port(event, baseline)
        if sig_port is not None:
            signals.append(sig_port)

        sig_time = self._check_time_anomaly(ts, baseline)
        if sig_time is not None:
            signals.append(sig_time)

        sig_vol = self._check_volume_anomaly(event, baseline)
        if sig_vol is not None:
            signals.append(sig_vol)

        sig_freq = self._check_frequency_anomaly(event, baseline)
        if sig_freq is not None:
            signals.append(sig_freq)

        sig_peer = self._check_new_peer(event, baseline)
        if sig_peer is not None:
            signals.append(sig_peer)

        sig_vlan = self._check_cross_vlan_unexpected(event, baseline)
        if sig_vlan is not None:
            signals.append(sig_vlan)

        # Signal 8: Maintenance window check -> reduce all scores by 0.5
        if in_maintenance and signals:
            factor = 1.0 - MAINTENANCE_WINDOW_SCORE_REDUCTION
            for sig in signals:
                sig.score = round(sig.score * factor, 4)
                sig.metadata["maintenance_window_dampened"] = True
                sig.metadata["maintenance_window"] = mw.description if mw else ""

        # Combined weighted deviation score, clamped to [0.0, 1.0]
        combined_score = self._compute_combined_score(signals)

        # False-positive reduction classification
        severity = self._classify_severity(combined_score, len(signals))

        if severity == "OBSERVATION":
            logger.info(
                "Single deviation signal observation for asset=%s signal=%s score=%.3f (no alert)",
                asset_id,
                signals[0].name if signals else "none",
                combined_score,
            )

        return DeviationResult(
            asset_id=asset_id,
            identity_id=identity_id,
            signals=signals,
            combined_score=combined_score,
            severity=severity,
            suppress_reason=None,
            in_maintenance_window=in_maintenance,
            is_evidence_only=True,
        )

    # ------------------------------------------------------------------
    # Individual deviation signals
    # ------------------------------------------------------------------

    def _check_new_destination(
        self, event: Dict[str, Any], baseline: Union[AssetBaseline, IdentityBaseline]
    ) -> Optional[DeviationSignal]:
        dst = (
            event.get("dst_ip")
            or event.get("destination_ip")
            or event.get("dst_domain")
        )
        if not dst or not baseline.normal_destinations:
            return None
        dst_str = str(dst)
        if dst_str in baseline.normal_destinations:
            return None

        crit = str(event.get("dst_criticality", "medium")).lower()
        score = CRITICALITY_SCORES.get(crit, 0.5)
        return DeviationSignal(
            name="new_destination",
            score=score,
            raw_score=score,
            description=(
                f"Destination {dst_str} (criticality={crit}) not seen in "
                f"7-day baseline ({len(baseline.normal_destinations)} known destinations)"
            ),
            metadata={"destination": dst_str, "criticality": crit},
        )

    def _check_unusual_port(
        self, event: Dict[str, Any], baseline: Union[AssetBaseline, IdentityBaseline]
    ) -> Optional[DeviationSignal]:
        port = event.get("dst_port")
        if port is None:
            port = event.get("destination_port")
        if port is None or not baseline.normal_ports:
            return None
        port_int = int(port)
        if port_int in baseline.normal_ports:
            return None

        score = 0.3
        return DeviationSignal(
            name="unusual_port",
            score=score,
            raw_score=score,
            description=f"Destination port {port_int} not in baseline normal_ports",
            metadata={"dst_port": port_int},
        )

    def _check_time_anomaly(
        self, ts: datetime, baseline: Union[AssetBaseline, IdentityBaseline]
    ) -> Optional[DeviationSignal]:
        if not baseline.normal_hours:
            return None
        hour_ist = ts.astimezone(IST).hour
        if hour_ist in baseline.normal_hours:
            return None

        score = 0.4
        return DeviationSignal(
            name="time_anomaly",
            score=score,
            raw_score=score,
            description=(
                f"Activity at {hour_ist:02d}:00 IST is outside entity's "
                f"normal active hours"
            ),
            metadata={"hour_ist": hour_ist, "normal_hours": sorted(baseline.normal_hours)},
        )

    def _check_volume_anomaly(
        self, event: Dict[str, Any], baseline: Union[AssetBaseline, IdentityBaseline]
    ) -> Optional[DeviationSignal]:
        bytes_val = event.get("hourly_bytes")
        if bytes_val is None:
            bytes_val = event.get("bytes_transferred")
        if bytes_val is None:
            return None

        bytes_f = float(bytes_val)
        mean = baseline.bytes_per_hour_mean
        std = baseline.bytes_per_hour_std

        if std <= 0.0:
            # No variance recorded; fall back to > 3x mean if mean > 0
            if mean > 0.0 and bytes_f > 3.0 * mean:
                ratio = bytes_f / mean
                score = min(1.0, 0.4 + 0.1 * (ratio - 3.0))
                return DeviationSignal(
                    name="volume_anomaly",
                    score=score,
                    raw_score=score,
                    description=(
                        f"Volume {bytes_f:.0f} bytes exceeds 3x baseline mean "
                        f"({mean:.0f} bytes/hr)"
                    ),
                    metadata={"bytes": bytes_f, "mean": mean, "std": std},
                )
            return None

        threshold = mean + 3.0 * std
        if bytes_f <= threshold:
            return None

        z_score = (bytes_f - mean) / std
        # Proportional to deviation: z=3 -> 0.4, z>=9 -> 1.0
        score = min(1.0, max(0.4, 0.4 + (z_score - 3.0) * 0.1))
        return DeviationSignal(
            name="volume_anomaly",
            score=score,
            raw_score=score,
            description=(
                f"Volume {bytes_f:.0f} bytes exceeds mean+3*std "
                f"({threshold:.0f} bytes, z={z_score:.2f})"
            ),
            metadata={
                "bytes": bytes_f,
                "mean": mean,
                "std": std,
                "z_score": round(z_score, 2),
            },
        )

    def _check_frequency_anomaly(
        self, event: Dict[str, Any], baseline: Union[AssetBaseline, IdentityBaseline]
    ) -> Optional[DeviationSignal]:
        cph = event.get("connections_per_hour")
        if cph is None:
            return None

        cph_f = float(cph)
        mean = baseline.connections_per_hour_mean
        std = baseline.connections_per_hour_std
        threshold = mean + 3.0 * std

        if std <= 0.0:
            if mean > 0.0 and cph_f > 3.0 * mean:
                score = 0.5
                return DeviationSignal(
                    name="frequency_anomaly",
                    score=score,
                    raw_score=score,
                    description=(
                        f"Connection rate {cph_f:.1f}/hr exceeds 3x baseline mean "
                        f"({mean:.1f}/hr)"
                    ),
                    metadata={"connections_per_hour": cph_f, "mean": mean, "std": std},
                )
            return None

        if cph_f <= threshold:
            return None

        score = 0.5
        return DeviationSignal(
            name="frequency_anomaly",
            score=score,
            raw_score=score,
            description=(
                f"Connection rate {cph_f:.1f}/hr exceeds mean+3*std "
                f"({threshold:.1f}/hr)"
            ),
            metadata={
                "connections_per_hour": cph_f,
                "mean": mean,
                "std": std,
                "threshold": threshold,
            },
        )

    def _check_new_peer(
        self, event: Dict[str, Any], baseline: Union[AssetBaseline, IdentityBaseline]
    ) -> Optional[DeviationSignal]:
        peer = event.get("peer_asset_id") or event.get("destination_asset_id")
        if not peer or not baseline.normal_peers:
            return None
        peer_str = str(peer)
        if peer_str in baseline.normal_peers:
            return None

        crit = str(event.get("peer_criticality", "medium")).lower()
        score = CRITICALITY_SCORES.get(crit, 0.5)
        return DeviationSignal(
            name="new_peer",
            score=score,
            raw_score=score,
            description=(
                f"Communication with previously unseen peer asset {peer_str} "
                f"(criticality={crit})"
            ),
            metadata={"peer_asset_id": peer_str, "criticality": crit},
        )

    def _check_cross_vlan_unexpected(
        self, event: Dict[str, Any], baseline: Union[AssetBaseline, IdentityBaseline]
    ) -> Optional[DeviationSignal]:
        dst_vlan = event.get("dst_vlan")
        if dst_vlan is None:
            dst_vlan = event.get("destination_vlan")
        if dst_vlan is None:
            dst_ip = event.get("dst_ip") or event.get("destination_ip")
            dst_vlan = ip_to_vlan(str(dst_ip)) if dst_ip else None

        if dst_vlan is None or not baseline.normal_vlans:
            return None
        dst_vlan_int = int(dst_vlan)
        if dst_vlan_int in baseline.normal_vlans:
            return None

        score = 0.6
        return DeviationSignal(
            name="cross_vlan_unexpected",
            score=score,
            raw_score=score,
            description=(
                f"Unexpected cross-VLAN traffic to VLAN {dst_vlan_int} "
                f"(normal VLANs: {sorted(baseline.normal_vlans)})"
            ),
            metadata={
                "dst_vlan": dst_vlan_int,
                "normal_vlans": sorted(baseline.normal_vlans),
            },
        )

    # ------------------------------------------------------------------
    # Scoring, suppression & classification
    # ------------------------------------------------------------------

    def _check_firmware_deployment_suppression(
        self,
        event: Dict[str, Any],
        baseline: Union[AssetBaseline, IdentityBaseline],
        asset_id: Optional[str],
        identity_id: Optional[str],
        in_maintenance: bool,
    ) -> Optional[str]:
        """
        Suppress anomalies for authorized OT firmware deployments:
          - source is an approved engineering system (VLAN 20 / engineering_workstation / allowlisted)
          - destination is OT VLAN (VLAN 30)
          - approved identity
          - within an approved maintenance window
        """
        if not in_maintenance:
            return None

        dst_vlan = event.get("dst_vlan") or event.get("destination_vlan")
        if dst_vlan is None:
            dst_ip = event.get("dst_ip") or event.get("destination_ip")
            dst_vlan = ip_to_vlan(str(dst_ip)) if dst_ip else None
        if dst_vlan != OT_VLAN_ID:
            return None

        src_vlan = event.get("src_vlan") or event.get("source_vlan")
        if src_vlan is None:
            src_ip = event.get("src_ip") or event.get("source_ip")
            src_vlan = ip_to_vlan(str(src_ip)) if src_ip else None

        is_eng_source = bool(
            event.get("is_approved_engineering_system")
            or (asset_id and asset_id in self._approved_eng_assets)
            or (
                src_vlan == ENGINEERING_VLAN_ID
                and baseline.entity_type in APPROVED_ENGINEERING_ENTITY_TYPES
            )
        )
        if not is_eng_source:
            return None

        is_approved_identity = bool(
            event.get("is_approved_firmware_identity")
            or (identity_id and identity_id in self._approved_firmware_identities)
        )
        if not is_approved_identity:
            return None

        return (
            "Approved OT firmware deployment from engineering system "
            "by authorized identity during scheduled maintenance window"
        )

    def _compute_combined_score(self, signals: List[DeviationSignal]) -> float:
        if not signals:
            return 0.0
        total = sum(
            sig.score * self._weights.get(sig.name, 1.0) for sig in signals
        )
        return round(min(1.0, max(0.0, total)), 4)

    @staticmethod
    def _classify_severity(combined_score: float, signal_count: int) -> str:
        """
        Apply false-positive reduction thresholds:
          - 0 signals -> NONE
          - 1 signal  -> OBSERVATION (logged, never an alert)
          - Score > 0.85 AND >= 4 signals -> HIGH
          - Score > 0.70 AND >= 3 signals -> MEDIUM
          - Score > 0.50 AND >= 2 signals -> LOW
          - Otherwise -> OBSERVATION
        """
        if signal_count == 0:
            return "NONE"
        if signal_count == 1:
            return "OBSERVATION"
        if (
            combined_score > DEVIATION_ALERT_THRESHOLD_HIGH
            and signal_count >= DEVIATION_MIN_SIGNALS_HIGH
        ):
            return "HIGH"
        if (
            combined_score > DEVIATION_ALERT_THRESHOLD_MEDIUM
            and signal_count >= DEVIATION_MIN_SIGNALS_MEDIUM
        ):
            return "MEDIUM"
        if (
            combined_score > DEVIATION_ALERT_THRESHOLD_LOW
            and signal_count >= DEVIATION_MIN_SIGNALS_LOW
        ):
            return "LOW"
        return "OBSERVATION"

    @staticmethod
    def _parse_timestamp(ts_raw: Any) -> datetime:
        if isinstance(ts_raw, datetime):
            return ts_raw if ts_raw.tzinfo else ts_raw.replace(tzinfo=timezone.utc)
        if isinstance(ts_raw, str):
            dt = datetime.fromisoformat(ts_raw)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc)

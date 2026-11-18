"""
VaultX - Asset & Identity Behavioural Baseline Engine
BECPL Manufacturing-Aware Hybrid NIDS - Phase 2

Maintains behavioural baselines for 11 canonical entity types across BECPL's
IT/Engineering/OT/Warehouse/DMZ/Cloud/Security environment:
  1. engineering_workstation
  2. corporate_workstation
  3. industrial_controller (PLCs)
  4. hmi
  5. mes_server
  6. erp_system
  7. warehouse_system
  8. vendor_connection
  9. service_account
 10. automation_agent
 11. ai_agent

Baselines are computed from the trailing 7 days of PostgreSQL
`becpl_nids.network_flows`, recomputed every 6 hours, cached in Redis as JSON
with a 7-hour TTL, and persisted to `becpl_nids.asset_baselines` and
`becpl_nids.identity_baselines`.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import math
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

try:
    import psycopg2
    import psycopg2.extras
except ImportError:  # pragma: no cover - allows offline unit testing
    psycopg2 = None  # type: ignore[assignment]

from backend.behavioural.behaviour_config import (
    BASELINE_ASSET_REDIS_PREFIX,
    BASELINE_IDENTITY_REDIS_PREFIX,
    BASELINE_LOOKBACK_DAYS,
    BASELINE_MIN_SAMPLES,
    BASELINE_RECOMPUTE_INTERVAL_HOURS,
    BASELINE_REDIS_TTL_SECONDS,
    SUPPORTED_ENTITY_TYPES,
    VLAN_MAP,
)

logger = logging.getLogger(__name__)

IST = timezone(timedelta(hours=5, minutes=30))


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class MaintenanceWindow:
    """Approved maintenance window from `becpl_nids.maintenance_windows`."""

    start_datetime: datetime
    end_datetime: datetime
    description: str = ""
    asset_id: Optional[str] = None
    vlan_id: Optional[int] = None
    approved_by: Optional[str] = None

    def contains(self, ts: datetime) -> bool:
        """Return True if timestamp `ts` falls inside [start_datetime, end_datetime]."""
        t = _ensure_utc(ts)
        start = _ensure_utc(self.start_datetime)
        end = _ensure_utc(self.end_datetime)
        return start <= t <= end

    def to_tuple(self) -> Tuple[datetime, datetime, str]:
        return (self.start_datetime, self.end_datetime, self.description)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "start_datetime": _ensure_utc(self.start_datetime).isoformat(),
            "end_datetime": _ensure_utc(self.end_datetime).isoformat(),
            "description": self.description,
            "asset_id": self.asset_id,
            "vlan_id": self.vlan_id,
            "approved_by": self.approved_by,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "MaintenanceWindow":
        return cls(
            start_datetime=datetime.fromisoformat(data["start_datetime"]),
            end_datetime=datetime.fromisoformat(data["end_datetime"]),
            description=data.get("description", ""),
            asset_id=data.get("asset_id"),
            vlan_id=data.get("vlan_id"),
            approved_by=data.get("approved_by"),
        )


@dataclass
class AssetBaseline:
    """7-day behavioural profile for a network asset."""

    asset_id: str
    entity_type: str
    normal_destinations: Set[str] = field(default_factory=set)
    normal_ports: Set[int] = field(default_factory=set)
    normal_protocols: Set[str] = field(default_factory=set)
    bytes_per_hour_mean: float = 0.0
    bytes_per_hour_std: float = 0.0
    connections_per_hour_mean: float = 0.0
    connections_per_hour_std: float = 0.0
    normal_hours: Set[int] = field(default_factory=set)
    normal_peers: Set[str] = field(default_factory=set)
    normal_vlans: Set[int] = field(default_factory=set)
    approved_maintenance_windows: List[MaintenanceWindow] = field(default_factory=list)
    computed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    sample_count: int = 0

    def is_in_maintenance_window(self, ts: datetime) -> Optional[MaintenanceWindow]:
        """Return the matching MaintenanceWindow if `ts` falls in one, else None."""
        for window in self.approved_maintenance_windows:
            if window.contains(ts):
                return window
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "entity_type": self.entity_type,
            "normal_destinations": sorted(self.normal_destinations),
            "normal_ports": sorted(self.normal_ports),
            "normal_protocols": sorted(self.normal_protocols),
            "bytes_per_hour_mean": self.bytes_per_hour_mean,
            "bytes_per_hour_std": self.bytes_per_hour_std,
            "connections_per_hour_mean": self.connections_per_hour_mean,
            "connections_per_hour_std": self.connections_per_hour_std,
            "normal_hours": sorted(self.normal_hours),
            "normal_peers": sorted(self.normal_peers),
            "normal_vlans": sorted(self.normal_vlans),
            "approved_maintenance_windows": [
                w.to_dict() for w in self.approved_maintenance_windows
            ],
            "computed_at": _ensure_utc(self.computed_at).isoformat(),
            "sample_count": self.sample_count,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AssetBaseline":
        windows = [
            MaintenanceWindow.from_dict(w)
            for w in data.get("approved_maintenance_windows", [])
        ]
        computed_raw = data.get("computed_at")
        computed_at = (
            datetime.fromisoformat(computed_raw)
            if isinstance(computed_raw, str)
            else datetime.now(timezone.utc)
        )
        return cls(
            asset_id=data["asset_id"],
            entity_type=data.get("entity_type", "corporate_workstation"),
            normal_destinations=set(data.get("normal_destinations", [])),
            normal_ports={int(p) for p in data.get("normal_ports", [])},
            normal_protocols=set(data.get("normal_protocols", [])),
            bytes_per_hour_mean=float(data.get("bytes_per_hour_mean", 0.0)),
            bytes_per_hour_std=float(data.get("bytes_per_hour_std", 0.0)),
            connections_per_hour_mean=float(data.get("connections_per_hour_mean", 0.0)),
            connections_per_hour_std=float(data.get("connections_per_hour_std", 0.0)),
            normal_hours={int(h) for h in data.get("normal_hours", [])},
            normal_peers=set(data.get("normal_peers", [])),
            normal_vlans={int(v) for v in data.get("normal_vlans", [])},
            approved_maintenance_windows=windows,
            computed_at=computed_at,
            sample_count=int(data.get("sample_count", 0)),
        )


@dataclass
class IdentityBaseline:
    """7-day behavioural profile for a human or non-human identity."""

    identity_id: str
    entity_type: str = "service_account"
    normal_destinations: Set[str] = field(default_factory=set)
    normal_ports: Set[int] = field(default_factory=set)
    normal_protocols: Set[str] = field(default_factory=set)
    bytes_per_hour_mean: float = 0.0
    bytes_per_hour_std: float = 0.0
    connections_per_hour_mean: float = 0.0
    connections_per_hour_std: float = 0.0
    normal_hours: Set[int] = field(default_factory=set)
    normal_peers: Set[str] = field(default_factory=set)
    normal_vlans: Set[int] = field(default_factory=set)
    approved_maintenance_windows: List[MaintenanceWindow] = field(default_factory=list)
    computed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    sample_count: int = 0

    def is_in_maintenance_window(self, ts: datetime) -> Optional[MaintenanceWindow]:
        for window in self.approved_maintenance_windows:
            if window.contains(ts):
                return window
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "identity_id": self.identity_id,
            "entity_type": self.entity_type,
            "normal_destinations": sorted(self.normal_destinations),
            "normal_ports": sorted(self.normal_ports),
            "normal_protocols": sorted(self.normal_protocols),
            "bytes_per_hour_mean": self.bytes_per_hour_mean,
            "bytes_per_hour_std": self.bytes_per_hour_std,
            "connections_per_hour_mean": self.connections_per_hour_mean,
            "connections_per_hour_std": self.connections_per_hour_std,
            "normal_hours": sorted(self.normal_hours),
            "normal_peers": sorted(self.normal_peers),
            "normal_vlans": sorted(self.normal_vlans),
            "approved_maintenance_windows": [
                w.to_dict() for w in self.approved_maintenance_windows
            ],
            "computed_at": _ensure_utc(self.computed_at).isoformat(),
            "sample_count": self.sample_count,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "IdentityBaseline":
        windows = [
            MaintenanceWindow.from_dict(w)
            for w in data.get("approved_maintenance_windows", [])
        ]
        computed_raw = data.get("computed_at")
        computed_at = (
            datetime.fromisoformat(computed_raw)
            if isinstance(computed_raw, str)
            else datetime.now(timezone.utc)
        )
        return cls(
            identity_id=data["identity_id"],
            entity_type=data.get("entity_type", "service_account"),
            normal_destinations=set(data.get("normal_destinations", [])),
            normal_ports={int(p) for p in data.get("normal_ports", [])},
            normal_protocols=set(data.get("normal_protocols", [])),
            bytes_per_hour_mean=float(data.get("bytes_per_hour_mean", 0.0)),
            bytes_per_hour_std=float(data.get("bytes_per_hour_std", 0.0)),
            connections_per_hour_mean=float(data.get("connections_per_hour_mean", 0.0)),
            connections_per_hour_std=float(data.get("connections_per_hour_std", 0.0)),
            normal_hours={int(h) for h in data.get("normal_hours", [])},
            normal_peers=set(data.get("normal_peers", [])),
            normal_vlans={int(v) for v in data.get("normal_vlans", [])},
            approved_maintenance_windows=windows,
            computed_at=computed_at,
            sample_count=int(data.get("sample_count", 0)),
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ensure_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _mean(values: List[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def _std(values: List[float], mean: Optional[float] = None) -> float:
    if len(values) < 2:
        return 0.0
    m = mean if mean is not None else _mean(values)
    variance = sum((v - m) ** 2 for v in values) / (len(values) - 1)
    return math.sqrt(variance)


def ip_to_vlan(ip_str: Optional[str]) -> Optional[int]:
    """Map an IPv4 address string to one of BECPL's 7 VLAN IDs, or None."""
    if not ip_str:
        return None
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return None
    for vlan_id, meta in VLAN_MAP.items():
        if ip_obj in ipaddress.ip_network(meta["cidr"]):
            return vlan_id
    return None


def classify_entity_type(
    device_type: Optional[str] = None,
    vlan_id: Optional[int] = None,
    application: Optional[str] = None,
    identity_classification: Optional[str] = None,
) -> str:
    """
    Resolve an asset or identity record into one of the 11 canonical entity types.
    """
    id_cls = (identity_classification or "").upper()
    dev = (device_type or "").lower()
    app = (application or "").lower()

    if id_cls == "AI_AGENT":
        return "ai_agent"
    if id_cls == "AUTOMATION_WORKLOAD":
        return "automation_agent"
    if id_cls == "THIRD_PARTY_IDENTITY":
        return "vendor_connection"
    if dev == "plc" or "plc" in app:
        return "industrial_controller"
    if dev == "hmi" or "hmi" in app:
        return "hmi"
    if "mes" in app:
        return "mes_server"
    if "erp" in app:
        return "erp_system"
    if vlan_id == 40 or "warehouse" in app or dev == "scanner":
        return "warehouse_system"
    if vlan_id == 20 and dev == "workstation":
        return "engineering_workstation"
    if dev == "workstation":
        return "corporate_workstation"
    if id_cls == "SERVICE_ACCOUNT":
        return "service_account"
    return "corporate_workstation"


# ---------------------------------------------------------------------------
# BaselineEngine
# ---------------------------------------------------------------------------


class BaselineEngine:
    """
    Computes, caches (Redis, 7h TTL), and persists (PostgreSQL) asset and
    identity behavioural baselines.

    Recomputation runs every BASELINE_RECOMPUTE_INTERVAL_HOURS (6 hours) over
    the last BASELINE_LOOKBACK_DAYS (7 days) of `becpl_nids.network_flows`.
    """

    RECOMPUTE_INTERVAL_HOURS = BASELINE_RECOMPUTE_INTERVAL_HOURS
    LOOKBACK_DAYS = BASELINE_LOOKBACK_DAYS
    MIN_SAMPLES = BASELINE_MIN_SAMPLES
    ENTITY_TYPES = SUPPORTED_ENTITY_TYPES

    def __init__(
        self,
        pg_dsn: Optional[str] = None,
        redis_client: Optional[Any] = None,
        min_samples: int = BASELINE_MIN_SAMPLES,
    ) -> None:
        self._pg_dsn = pg_dsn
        self._redis = redis_client
        self._min_samples = min_samples

    # ------------------------------------------------------------------
    # Pure computation (DB-independent, ideal for batch jobs & testing)
    # ------------------------------------------------------------------

    def compute_asset_baseline_from_flows(
        self,
        asset_id: str,
        entity_type: str,
        flows: Iterable[Dict[str, Any]],
        maintenance_windows: Optional[List[MaintenanceWindow]] = None,
        now: Optional[datetime] = None,
    ) -> Optional[AssetBaseline]:
        """
        Build an AssetBaseline from an iterable of flow dictionaries.

        Each flow dict should contain keys matching `becpl_nids.network_flows`:
          - timestamp (datetime or ISO str)
          - dst_ip (str)
          - dst_port (int, optional)
          - protocol (str, optional)
          - orig_bytes (int, optional)
          - resp_bytes (int, optional)
          - destination_asset_id (str, optional)
          - dst_vlan (int, optional; inferred from dst_ip if omitted)
        Returns None if sample count < self._min_samples.
        """
        flow_list = list(flows)
        if len(flow_list) < self._min_samples:
            logger.info(
                "Insufficient samples for asset %s (%d < %d); skipping baseline",
                asset_id,
                len(flow_list),
                self._min_samples,
            )
            return None

        destinations: Set[str] = set()
        ports: Set[int] = set()
        protocols: Set[str] = set()
        hours: Set[int] = set()
        peers: Set[str] = set()
        vlans: Set[int] = set()
        hourly_bytes: Dict[int, float] = {}
        hourly_conns: Dict[int, int] = {}

        for flow in flow_list:
            dst_ip = flow.get("dst_ip") or flow.get("destination_ip")
            if dst_ip:
                destinations.add(str(dst_ip))
            if flow.get("dst_asn"):
                destinations.add(str(flow["dst_asn"]))

            dst_port = flow.get("dst_port") or flow.get("destination_port")
            if dst_port is not None:
                ports.add(int(dst_port))

            proto = flow.get("protocol")
            if proto:
                protocols.add(str(proto).upper())

            peer = flow.get("destination_asset_id") or flow.get("peer_asset_id")
            if peer:
                peers.add(str(peer))

            dst_vlan = flow.get("dst_vlan")
            if dst_vlan is None and dst_ip:
                dst_vlan = ip_to_vlan(str(dst_ip))
            if dst_vlan is not None:
                vlans.add(int(dst_vlan))

            ts_raw = flow.get("timestamp")
            if isinstance(ts_raw, str):
                ts = datetime.fromisoformat(ts_raw)
            elif isinstance(ts_raw, datetime):
                ts = ts_raw
            else:
                ts = now or datetime.now(timezone.utc)

            ts_utc = _ensure_utc(ts)
            ts_ist = ts_utc.astimezone(IST)
            hours.add(ts_ist.hour)

            epoch_hour = int(ts_utc.timestamp()) // 3600
            total_bytes = float(flow.get("orig_bytes") or 0) + float(
                flow.get("resp_bytes") or 0
            )
            if total_bytes == 0.0 and flow.get("bytes_transferred"):
                total_bytes = float(flow["bytes_transferred"])
            hourly_bytes[epoch_hour] = hourly_bytes.get(epoch_hour, 0.0) + total_bytes
            hourly_conns[epoch_hour] = hourly_conns.get(epoch_hour, 0) + 1

        bytes_vals = list(hourly_bytes.values())
        conn_vals = [float(c) for c in hourly_conns.values()]
        bph_mean = _mean(bytes_vals)
        bph_std = _std(bytes_vals, bph_mean)
        cph_mean = _mean(conn_vals)
        cph_std = _std(conn_vals, cph_mean)

        baseline = AssetBaseline(
            asset_id=asset_id,
            entity_type=entity_type,
            normal_destinations=destinations,
            normal_ports=ports,
            normal_protocols=protocols,
            bytes_per_hour_mean=bph_mean,
            bytes_per_hour_std=bph_std,
            connections_per_hour_mean=cph_mean,
            connections_per_hour_std=cph_std,
            normal_hours=hours,
            normal_peers=peers,
            normal_vlans=vlans,
            approved_maintenance_windows=list(maintenance_windows or []),
            computed_at=now or datetime.now(timezone.utc),
            sample_count=len(flow_list),
        )
        return baseline

    def compute_identity_baseline_from_flows(
        self,
        identity_id: str,
        entity_type: str,
        flows: Iterable[Dict[str, Any]],
        maintenance_windows: Optional[List[MaintenanceWindow]] = None,
        now: Optional[datetime] = None,
    ) -> Optional[IdentityBaseline]:
        """Build an IdentityBaseline from an iterable of flow/event dicts."""
        asset_bl = self.compute_asset_baseline_from_flows(
            asset_id=identity_id,
            entity_type=entity_type,
            flows=flows,
            maintenance_windows=maintenance_windows,
            now=now,
        )
        if asset_bl is None:
            return None
        return IdentityBaseline(
            identity_id=identity_id,
            entity_type=entity_type,
            normal_destinations=asset_bl.normal_destinations,
            normal_ports=asset_bl.normal_ports,
            normal_protocols=asset_bl.normal_protocols,
            bytes_per_hour_mean=asset_bl.bytes_per_hour_mean,
            bytes_per_hour_std=asset_bl.bytes_per_hour_std,
            connections_per_hour_mean=asset_bl.connections_per_hour_mean,
            connections_per_hour_std=asset_bl.connections_per_hour_std,
            normal_hours=asset_bl.normal_hours,
            normal_peers=asset_bl.normal_peers,
            normal_vlans=asset_bl.normal_vlans,
            approved_maintenance_windows=asset_bl.approved_maintenance_windows,
            computed_at=asset_bl.computed_at,
            sample_count=asset_bl.sample_count,
        )

    # ------------------------------------------------------------------
    # Cache & DB Retrieval
    # ------------------------------------------------------------------

    def get_asset_baseline(self, asset_id: str) -> Optional[AssetBaseline]:
        """Fast lookup from Redis (TTL 7h); falls back to PostgreSQL."""
        if self._redis is not None:
            raw = self._redis.get(f"{BASELINE_ASSET_REDIS_PREFIX}{asset_id}")
            if raw:
                if isinstance(raw, bytes):
                    raw = raw.decode("utf-8")
                try:
                    return AssetBaseline.from_dict(json.loads(raw))
                except Exception as exc:
                    logger.warning("Corrupt Redis asset baseline %s: %s", asset_id, exc)

        baseline = self._load_asset_baseline_from_pg(asset_id)
        if baseline is not None:
            self.cache_asset_baseline(baseline)
        return baseline

    def get_identity_baseline(self, identity_id: str) -> Optional[IdentityBaseline]:
        """Fast lookup from Redis (TTL 7h); falls back to PostgreSQL."""
        if self._redis is not None:
            raw = self._redis.get(f"{BASELINE_IDENTITY_REDIS_PREFIX}{identity_id}")
            if raw:
                if isinstance(raw, bytes):
                    raw = raw.decode("utf-8")
                try:
                    return IdentityBaseline.from_dict(json.loads(raw))
                except Exception as exc:
                    logger.warning(
                        "Corrupt Redis identity baseline %s: %s", identity_id, exc
                    )

        baseline = self._load_identity_baseline_from_pg(identity_id)
        if baseline is not None:
            self.cache_identity_baseline(baseline)
        return baseline

    def cache_asset_baseline(self, baseline: AssetBaseline) -> None:
        if self._redis is None:
            return
        key = f"{BASELINE_ASSET_REDIS_PREFIX}{baseline.asset_id}"
        self._redis.setex(
            key, BASELINE_REDIS_TTL_SECONDS, json.dumps(baseline.to_dict())
        )

    def cache_identity_baseline(self, baseline: IdentityBaseline) -> None:
        if self._redis is None:
            return
        key = f"{BASELINE_IDENTITY_REDIS_PREFIX}{baseline.identity_id}"
        self._redis.setex(
            key, BASELINE_REDIS_TTL_SECONDS, json.dumps(baseline.to_dict())
        )

    # ------------------------------------------------------------------
    # PostgreSQL-backed recomputation
    # ------------------------------------------------------------------

    def recompute_asset_baseline(
        self, asset_id: str, entity_type: str
    ) -> Optional[AssetBaseline]:
        """Recompute asset baseline from last 7 days of `becpl_nids.network_flows`."""
        if not self._pg_dsn or psycopg2 is None:
            raise RuntimeError("PostgreSQL DSN and psycopg2 are required for DB recompute")

        lookback_start = datetime.now(timezone.utc) - timedelta(
            days=BASELINE_LOOKBACK_DAYS
        )

        with psycopg2.connect(self._pg_dsn) as conn:
            conn.autocommit = False
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT
                        timestamp,
                        dst_ip::text AS dst_ip,
                        dst_port,
                        protocol,
                        COALESCE(orig_bytes, 0) AS orig_bytes,
                        COALESCE(resp_bytes, 0) AS resp_bytes,
                        destination_asset_id
                    FROM becpl_nids.network_flows
                    WHERE source_asset_id = %s
                      AND timestamp >= %s
                    ORDER BY timestamp
                    """,
                    (asset_id, lookback_start),
                )
                rows = [dict(r) for r in cur.fetchall()]
                windows = self._fetch_maintenance_windows(cur, asset_id)

                baseline = self.compute_asset_baseline_from_flows(
                    asset_id=asset_id,
                    entity_type=entity_type,
                    flows=rows,
                    maintenance_windows=windows,
                )
                if baseline is None:
                    return None

                self._persist_asset_baseline(cur, baseline)
                conn.commit()

        self.cache_asset_baseline(baseline)
        logger.info(
            "Recomputed asset baseline for %s (%d samples)",
            asset_id,
            baseline.sample_count,
        )
        return baseline

    def recompute_identity_baseline(
        self, identity_id: str, entity_type: str = "service_account"
    ) -> Optional[IdentityBaseline]:
        """Recompute identity baseline from last 7 days of `becpl_nids.security_events`."""
        if not self._pg_dsn or psycopg2 is None:
            raise RuntimeError("PostgreSQL DSN and psycopg2 are required for DB recompute")

        lookback_start = datetime.now(timezone.utc) - timedelta(
            days=BASELINE_LOOKBACK_DAYS
        )

        with psycopg2.connect(self._pg_dsn) as conn:
            conn.autocommit = False
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT
                        timestamp,
                        destination_ip::text AS dst_ip,
                        destination_port AS dst_port,
                        protocol,
                        COALESCE(bytes_transferred, 0) AS orig_bytes,
                        0 AS resp_bytes,
                        destination_asset_id
                    FROM becpl_nids.security_events
                    WHERE identity_id = %s::uuid
                      AND timestamp >= %s
                    ORDER BY timestamp
                    """,
                    (identity_id, lookback_start),
                )
                rows = [dict(r) for r in cur.fetchall()]
                windows = self._fetch_maintenance_windows(cur, None)

                baseline = self.compute_identity_baseline_from_flows(
                    identity_id=identity_id,
                    entity_type=entity_type,
                    flows=rows,
                    maintenance_windows=windows,
                )
                if baseline is None:
                    return None

                self._persist_identity_baseline(cur, baseline)
                conn.commit()

        self.cache_identity_baseline(baseline)
        return baseline

    def recompute_all_baselines(self) -> Dict[str, int]:
        """
        Recompute baselines for all active assets and identities.
        Intended to be scheduled every BASELINE_RECOMPUTE_INTERVAL_HOURS (6h).
        """
        if not self._pg_dsn or psycopg2 is None:
            raise RuntimeError("PostgreSQL DSN and psycopg2 are required for DB recompute")

        updated_assets = 0
        updated_identities = 0

        with psycopg2.connect(self._pg_dsn) as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT asset_id, device_type, vlan_id,
                           primary_application, identity_classification
                    FROM becpl_nids.assets
                    WHERE is_active = TRUE
                    """
                )
                assets = cur.fetchall()
                cur.execute(
                    """
                    SELECT identity_id::text AS identity_id, principal_type
                    FROM becpl_nids.identities
                    WHERE is_active = TRUE
                    """
                )
                identities = cur.fetchall()

        for row in assets:
            etype = classify_entity_type(
                device_type=row["device_type"],
                vlan_id=row["vlan_id"],
                application=row["primary_application"],
                identity_classification=row["identity_classification"],
            )
            try:
                if self.recompute_asset_baseline(row["asset_id"], etype) is not None:
                    updated_assets += 1
            except Exception as exc:
                logger.error("Failed baseline recompute for asset %s: %s", row["asset_id"], exc)

        for row in identities:
            etype = classify_entity_type(identity_classification=row["principal_type"])
            try:
                if self.recompute_identity_baseline(row["identity_id"], etype) is not None:
                    updated_identities += 1
            except Exception as exc:
                logger.error(
                    "Failed baseline recompute for identity %s: %s",
                    row["identity_id"],
                    exc,
                )

        return {"assets": updated_assets, "identities": updated_identities}

    # ------------------------------------------------------------------
    # Private PostgreSQL helpers
    # ------------------------------------------------------------------

    def _fetch_maintenance_windows(
        self, cur: Any, asset_id: Optional[str]
    ) -> List[MaintenanceWindow]:
        try:
            if asset_id:
                cur.execute(
                    """
                    SELECT start_datetime, end_datetime, description,
                           asset_id, vlan_id, approved_by
                    FROM becpl_nids.maintenance_windows
                    WHERE (asset_id = %s OR asset_id IS NULL)
                      AND is_approved = TRUE
                      AND end_datetime >= NOW() - INTERVAL '1 day'
                    ORDER BY start_datetime
                    """,
                    (asset_id,),
                )
            else:
                cur.execute(
                    """
                    SELECT start_datetime, end_datetime, description,
                           asset_id, vlan_id, approved_by
                    FROM becpl_nids.maintenance_windows
                    WHERE is_approved = TRUE
                      AND end_datetime >= NOW() - INTERVAL '1 day'
                    ORDER BY start_datetime
                    """
                )
            return [
                MaintenanceWindow(
                    start_datetime=r["start_datetime"],
                    end_datetime=r["end_datetime"],
                    description=r["description"] or "",
                    asset_id=r["asset_id"],
                    vlan_id=r["vlan_id"],
                    approved_by=r["approved_by"],
                )
                for r in cur.fetchall()
            ]
        except Exception as exc:
            logger.warning("Could not query maintenance_windows: %s", exc)
            return []

    def _persist_asset_baseline(self, cur: Any, baseline: AssetBaseline) -> None:
        cur.execute(
            """
            UPDATE becpl_nids.asset_baselines
            SET is_active = FALSE
            WHERE asset_id = %s AND is_active = TRUE
            """,
            (baseline.asset_id,),
        )
        cur.execute(
            """
            INSERT INTO becpl_nids.asset_baselines
              (baseline_id, asset_id, computed_at, baseline_json, sample_count, is_active)
            VALUES (%s::uuid, %s, %s, %s::jsonb, %s, TRUE)
            """,
            (
                str(uuid.uuid4()),
                baseline.asset_id,
                baseline.computed_at,
                json.dumps(baseline.to_dict()),
                baseline.sample_count,
            ),
        )

    def _persist_identity_baseline(self, cur: Any, baseline: IdentityBaseline) -> None:
        cur.execute(
            """
            UPDATE becpl_nids.identity_baselines
            SET is_active = FALSE
            WHERE identity_id = %s::uuid AND is_active = TRUE
            """,
            (baseline.identity_id,),
        )
        cur.execute(
            """
            INSERT INTO becpl_nids.identity_baselines
              (baseline_id, identity_id, computed_at, baseline_json, sample_count, is_active)
            VALUES (%s::uuid, %s::uuid, %s, %s::jsonb, %s, TRUE)
            """,
            (
                str(uuid.uuid4()),
                baseline.identity_id,
                baseline.computed_at,
                json.dumps(baseline.to_dict()),
                baseline.sample_count,
            ),
        )

    def _load_asset_baseline_from_pg(self, asset_id: str) -> Optional[AssetBaseline]:
        if not self._pg_dsn or psycopg2 is None:
            return None
        with psycopg2.connect(self._pg_dsn) as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT baseline_json
                    FROM becpl_nids.asset_baselines
                    WHERE asset_id = %s AND is_active = TRUE
                    ORDER BY computed_at DESC
                    LIMIT 1
                    """,
                    (asset_id,),
                )
                row = cur.fetchone()
                if not row:
                    return None
                data = row["baseline_json"]
                if isinstance(data, str):
                    data = json.loads(data)
                return AssetBaseline.from_dict(data)

    def _load_identity_baseline_from_pg(
        self, identity_id: str
    ) -> Optional[IdentityBaseline]:
        if not self._pg_dsn or psycopg2 is None:
            return None
        with psycopg2.connect(self._pg_dsn) as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT baseline_json
                    FROM becpl_nids.identity_baselines
                    WHERE identity_id = %s::uuid AND is_active = TRUE
                    ORDER BY computed_at DESC
                    LIMIT 1
                    """,
                    (identity_id,),
                )
                row = cur.fetchone()
                if not row:
                    return None
                data = row["baseline_json"]
                if isinstance(data, str):
                    data = json.loads(data)
                return IdentityBaseline.from_dict(data)

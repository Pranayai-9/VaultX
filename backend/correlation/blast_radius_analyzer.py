"""
VaultX Phase 2 - Blast Radius Analysis Engine
BECPL (Bharat Electronics Components Pvt. Ltd.), Pune

Computes operational blast radius for a security incident:
- Uses asset communication_peers from infra/topology/assets.json
- Queries recent network_flows (last 24 hours) for actual communication patterns
- Computes:
  * directly_affected_assets
  * potentially_affected_assets (1-hop peers)
  * related_zones
  * associated_identities
- Per affected asset includes: criticality, production_impact, isolation_difficulty
- For OT PLC/HMI assets adds mandatory safety_note:
    "Isolation may impact production line. Requires safety assessment."
- Persists blast_radius_json to PostgreSQL `incidents` table
- Publishes to Redis stream 'incidents:blast_radius'
"""

from __future__ import annotations

import inspect
import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from .infrastructure_graph import InfrastructureGraph

logger = logging.getLogger("vaultx.correlation.blast_radius")

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_ASSETS_PATH = REPO_ROOT / "infra" / "topology" / "assets.json"
REDIS_STREAM_BLAST_RADIUS = "incidents:blast_radius"

OT_SAFETY_NOTE = "Isolation may impact production line. Requires safety assessment."

VLAN_ZONE_NAMES: Dict[int, str] = {
    10: "Corporate IT",
    20: "Engineering & Firmware",
    30: "Manufacturing OT",
    40: "Warehouse & Logistics",
    50: "DMZ & Vendor Access",
    60: "Cloud & External Integrations",
    70: "Security Management",
}


@dataclass
class AffectedAssetDetail:
    asset_id: str
    hostname: str
    vlan: Optional[int]
    network_segment: str
    device_type: str
    criticality: str
    production_impact: str
    isolation_difficulty: str
    relationship: str  # direct | 1-hop-peer | 1-hop-observed-flow
    safety_note: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class BlastRadiusResult:
    incident_id: str
    computed_at: str
    directly_affected_assets: List[Dict[str, Any]] = field(default_factory=list)
    potentially_affected_assets: List[Dict[str, Any]] = field(default_factory=list)
    related_zones: List[str] = field(default_factory=list)
    associated_identities: List[str] = field(default_factory=list)
    ot_impact_detected: bool = False
    safety_notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class BlastRadiusAnalyzer:
    """Computes incident blast radius from topology peers + 24h observed network flows."""

    def __init__(
        self,
        assets_path: Optional[Path | str] = None,
        graph: Optional[InfrastructureGraph] = None,
        db_client: Any = None,
        redis_client: Any = None,
    ) -> None:
        self.assets_path = Path(assets_path) if assets_path else DEFAULT_ASSETS_PATH
        self.db_client = db_client
        self.redis_client = redis_client
        self.graph = graph or InfrastructureGraph(assets_path=self.assets_path)
        self.assets: Dict[str, Dict[str, Any]] = dict(self.graph.assets_by_id)

        if not self.assets and self.assets_path.exists():
            for a in json.loads(self.assets_path.read_text(encoding="utf-8")):
                if a.get("asset_id"):
                    self.assets[a["asset_id"]] = a

    # ------------------------------------------------------------------
    # Impact & Isolation Heuristics
    # ------------------------------------------------------------------
    @staticmethod
    def _production_impact(asset: Dict[str, Any]) -> str:
        vlan = asset.get("vlan")
        device_type = str(asset.get("device_type", "")).lower()
        criticality = str(asset.get("criticality", "medium")).lower()

        if vlan == 30 or device_type in ("plc", "hmi"):
            return "CRITICAL - Direct SMT/THT manufacturing line halt or safety disruption"
        if criticality == "critical":
            return "HIGH - Core business, engineering IP, or plant operations disruption"
        if criticality == "high":
            return "MODERATE - Departmental workflow or build/logistics slowdown"
        return "LOW - Localized workstation or auxiliary device disruption"

    @staticmethod
    def _isolation_difficulty(asset: Dict[str, Any]) -> str:
        vlan = asset.get("vlan")
        device_type = str(asset.get("device_type", "")).lower()
        criticality = str(asset.get("criticality", "medium")).lower()

        if device_type in ("plc", "hmi") or (vlan == 30 and criticality == "critical"):
            return "VERY_HIGH - Physical safety verification & plant floor supervisor sign-off required"
        if device_type in ("firewall", "router", "switch") or criticality == "critical":
            return "HIGH - Shared dependency; requires staged failover or controlled ACL restriction"
        if device_type in ("server", "gateway", "storage"):
            return "MEDIUM - Requires service dependency review before VLAN quarantine"
        return "LOW - Standard endpoint VLAN quarantine or NAC port isolation"

    @staticmethod
    def _is_ot_plc_or_hmi(asset: Dict[str, Any]) -> bool:
        device_type = str(asset.get("device_type", "")).lower()
        asset_id = str(asset.get("asset_id", "")).upper()
        return (
            device_type in ("plc", "hmi")
            or "PLC" in asset_id
            or "HMI" in asset_id
            or (asset.get("vlan") == 30 and device_type in ("plc", "hmi", "sensor", "gateway"))
        )

    def _build_asset_detail(
        self, asset_id: str, relationship: str
    ) -> AffectedAssetDetail:
        asset = self.assets.get(asset_id) or {
            "asset_id": asset_id,
            "hostname": asset_id.lower(),
            "vlan": 30 if asset_id.upper().startswith("OT-") else None,
            "network_segment": "Manufacturing OT"
            if asset_id.upper().startswith("OT-")
            else "Unknown",
            "device_type": "plc"
            if "PLC" in asset_id.upper()
            else "hmi"
            if "HMI" in asset_id.upper()
            else "unknown",
            "criticality": "critical" if asset_id.upper().startswith("OT-") else "medium",
        }
        vlan = asset.get("vlan")
        segment = asset.get("network_segment") or VLAN_ZONE_NAMES.get(vlan, "Unknown")
        safety_note = OT_SAFETY_NOTE if self._is_ot_plc_or_hmi(asset) else None

        return AffectedAssetDetail(
            asset_id=asset_id,
            hostname=str(asset.get("hostname", asset_id)),
            vlan=vlan,
            network_segment=segment,
            device_type=str(asset.get("device_type", "unknown")),
            criticality=str(asset.get("criticality", "medium")).lower(),
            production_impact=self._production_impact(asset),
            isolation_difficulty=self._isolation_difficulty(asset),
            relationship=relationship,
            safety_note=safety_note,
        )

    # ------------------------------------------------------------------
    # Core Blast Radius Computation
    # ------------------------------------------------------------------
    def analyze(
        self,
        incident_id: str,
        affected_assets: List[str],
        recent_flows_24h: Optional[List[Dict[str, Any]]] = None,
        associated_identities: Optional[List[str]] = None,
        publish: bool = True,
    ) -> BlastRadiusResult:
        """
        Compute the blast radius for an incident synchronously from topology + 24h flows.
        """
        direct_set: Set[str] = {a for a in affected_assets if a}
        one_hop_peers: Dict[str, str] = {}  # asset_id -> relationship label

        # 1. Topology communication_peers (from assets.json) & graph 1-hop neighbors
        for asset_id in sorted(direct_set):
            asset = self.assets.get(asset_id, {})
            for peer_id in asset.get("communication_peers") or []:
                if peer_id not in direct_set:
                    one_hop_peers.setdefault(peer_id, "1-hop-peer")
            # Reverse peers: assets that list asset_id as a peer
            for other_id, other_meta in self.assets.items():
                if other_id not in direct_set and asset_id in (
                    other_meta.get("communication_peers") or []
                ):
                    one_hop_peers.setdefault(other_id, "1-hop-peer")

            # Also consult InfrastructureGraph 1-hop connected assets
            for neighbor in self.graph.connected_assets(asset_id, hops=1, undirected=True):
                if neighbor not in direct_set:
                    one_hop_peers.setdefault(neighbor, "1-hop-peer")

        # 2. Recent 24h network_flows (actual observed communication)
        identities: Set[str] = set(associated_identities or [])
        for flow in recent_flows_24h or []:
            src = flow.get("source_asset_id") or flow.get("src_asset")
            dst = flow.get("destination_asset_id") or flow.get("dst_asset")
            ident = flow.get("identity") or flow.get("principal_name") or flow.get("identity_id")
            if src in direct_set and dst and dst not in direct_set:
                one_hop_peers[str(dst)] = "1-hop-observed-flow"
                if ident:
                    identities.add(str(ident))
            elif dst in direct_set and src and src not in direct_set:
                one_hop_peers[str(src)] = "1-hop-observed-flow"
                if ident:
                    identities.add(str(ident))

        # 3. Build detailed asset entries, collect zones, identities & OT safety notes
        direct_details = [self._build_asset_detail(aid, "direct") for aid in sorted(direct_set)]
        potential_details = [
            self._build_asset_detail(aid, rel) for aid, rel in sorted(one_hop_peers.items())
        ]

        zones: Set[str] = set()
        safety_notes: List[str] = []
        ot_impact = False

        for detail in direct_details + potential_details:
            if detail.network_segment and detail.network_segment != "Unknown":
                zones.add(detail.network_segment)
            asset_meta = self.assets.get(detail.asset_id, {})
            id_class = asset_meta.get("identity_classification")
            if id_class and detail.relationship == "direct":
                identities.add(f"{detail.asset_id} ({id_class})")
            if detail.vlan == 30 or detail.safety_note:
                ot_impact = True
            if detail.safety_note:
                note_entry = f"{detail.asset_id}: {detail.safety_note}"
                if note_entry not in safety_notes:
                    safety_notes.append(note_entry)

        result = BlastRadiusResult(
            incident_id=str(incident_id),
            computed_at=datetime.now(timezone.utc).isoformat(),
            directly_affected_assets=[d.to_dict() for d in direct_details],
            potentially_affected_assets=[d.to_dict() for d in potential_details],
            related_zones=sorted(zones),
            associated_identities=sorted(identities),
            ot_impact_detected=ot_impact,
            safety_notes=safety_notes,
        )

        if publish:
            self._publish_redis_sync(result)
            self._persist_blast_radius_sync(result)

        return result

    async def analyze_incident_async(self, incident_id: str) -> BlastRadiusResult:
        """
        Async entry point: loads incident affected_assets and last 24h network_flows
        from PostgreSQL, computes blast radius, updates incidents.blast_radius_json,
        and publishes to Redis stream 'incidents:blast_radius'.
        """
        affected_assets: List[str] = []
        identities: List[str] = []
        recent_flows: List[Dict[str, Any]] = []

        if self.db_client is not None and hasattr(self.db_client, "fetchrow"):
            row = await self.db_client.fetchrow(
                "SELECT affected_assets FROM becpl_nids.incidents WHERE incident_id = $1",
                incident_id,
            )
            if row and row["affected_assets"]:
                affected_assets = list(row["affected_assets"])

            if affected_assets and hasattr(self.db_client, "fetch"):
                flow_rows = await self.db_client.fetch(
                    """
                    SELECT source_asset_id, destination_asset_id, protocol, dst_port, timestamp
                    FROM becpl_nids.network_flows
                    WHERE timestamp >= NOW() - INTERVAL '24 hours'
                      AND (source_asset_id = ANY($1) OR destination_asset_id = ANY($1))
                    """,
                    affected_assets,
                )
                recent_flows = [dict(r) for r in flow_rows]

                id_rows = await self.db_client.fetch(
                    """
                    SELECT DISTINCT principal_name
                    FROM becpl_nids.identities
                    WHERE associated_asset_id = ANY($1)
                    """,
                    affected_assets,
                )
                identities = [r["principal_name"] for r in id_rows]

        result = self.analyze(
            incident_id=incident_id,
            affected_assets=affected_assets,
            recent_flows_24h=recent_flows,
            associated_identities=identities,
            publish=False,
        )
        await self.persist_blast_radius(result)
        await self.publish_blast_radius(result)
        return result

    # ------------------------------------------------------------------
    # Persistence & Redis Publishing
    # ------------------------------------------------------------------
    def _publish_redis_sync(self, result: BlastRadiusResult) -> None:
        if self.redis_client is None:
            return
        xadd = getattr(self.redis_client, "xadd", None)
        if xadd is None or inspect.iscoroutinefunction(xadd):
            return
        try:
            xadd(
                REDIS_STREAM_BLAST_RADIUS,
                {
                    "incident_id": result.incident_id,
                    "ot_impact_detected": str(result.ot_impact_detected).lower(),
                    "payload": json.dumps(result.to_dict()),
                },
            )
        except Exception as exc:
            logger.error("Failed publishing blast radius to Redis: %s", exc)

    async def publish_blast_radius(self, result: BlastRadiusResult) -> None:
        if self.redis_client is None:
            return
        res = self.redis_client.xadd(
            REDIS_STREAM_BLAST_RADIUS,
            {
                "incident_id": result.incident_id,
                "ot_impact_detected": str(result.ot_impact_detected).lower(),
                "payload": json.dumps(result.to_dict()),
            },
        )
        if inspect.isawaitable(res):
            await res

    def _persist_blast_radius_sync(self, result: BlastRadiusResult) -> None:
        if self.db_client is None:
            return
        execute = getattr(self.db_client, "execute", None)
        if execute is None or inspect.iscoroutinefunction(execute):
            return
        try:
            execute(
                "UPDATE becpl_nids.incidents SET blast_radius_json = %s WHERE incident_id = %s",
                (json.dumps(result.to_dict()), result.incident_id),
            )
        except Exception as exc:
            logger.error("Failed persisting blast_radius_json: %s", exc)

    async def persist_blast_radius(self, result: BlastRadiusResult) -> None:
        if self.db_client is None:
            return
        res = self.db_client.execute(
            "UPDATE becpl_nids.incidents SET blast_radius_json = $1::jsonb WHERE incident_id = $2",
            json.dumps(result.to_dict()),
            result.incident_id,
        )
        if inspect.isawaitable(res):
            await res

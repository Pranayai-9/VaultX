"""
VaultX Phase 2 - Infrastructure Relationship Graph
BECPL (Bharat Electronics Components Pvt. Ltd.), Pune

Builds an in-memory directed graph (using NetworkX when available, with a
full-featured pure-Python adjacency fallback) representing:
- Nodes: assets, identities, services, vendors, VLANs
- Edges: approved communication paths (from infra/topology/communication_matrix.json)
         and observed network flows (from PostgreSQL network_flows table or live ingestion)
- Edge attributes: protocol, port, observed_frequency, last_seen, is_approved

Queries:
- shortest_path(src_asset, dst_asset)    -> attack path candidates
- connected_assets(asset_id, hops=2)     -> blast radius neighborhood
- anomalous_edges()                      -> observed edges NOT in approved communication matrix
- vendor_connected_assets(vendor_id)     -> all assets a vendor can reach

Rebuilds periodically every 6 hours from database, caches adjacency JSON in Redis,
and exports NetworkX node-link JSON for the AI analysis service.
"""

from __future__ import annotations

import asyncio
from collections import deque
import inspect
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    import networkx as nx  # type: ignore

    HAS_NETWORKX = True
except ImportError:  # pragma: no cover
    nx = None
    HAS_NETWORKX = False

logger = logging.getLogger("vaultx.correlation.infrastructure_graph")

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_ASSETS_PATH = REPO_ROOT / "infra" / "topology" / "assets.json"
DEFAULT_COMM_MATRIX_PATH = REPO_ROOT / "infra" / "topology" / "communication_matrix.json"
REDIS_KEY_GRAPH_CACHE = "graph:infrastructure:adjacency"
DEFAULT_REBUILD_INTERVAL_SECONDS = 6 * 3600  # 6 hours

VLAN_NAMES: Dict[int, str] = {
    10: "VLAN_10_Corporate_IT",
    20: "VLAN_20_Engineering",
    30: "VLAN_30_Manufacturing_OT",
    40: "VLAN_40_Warehouse",
    50: "VLAN_50_DMZ_Vendor",
    60: "VLAN_60_Cloud",
    70: "VLAN_70_Security",
}


class InfrastructureGraph:
    """
    Infrastructure relationship graph supporting attack path computation,
    multi-hop blast radius queries, unapproved communication detection,
    and vendor reachability analysis.
    """

    def __init__(
        self,
        assets_path: Optional[Path | str] = None,
        comm_matrix_path: Optional[Path | str] = None,
        db_client: Any = None,
        redis_client: Any = None,
        rebuild_interval_seconds: int = DEFAULT_REBUILD_INTERVAL_SECONDS,
        auto_build: bool = True,
    ) -> None:
        self.assets_path = Path(assets_path) if assets_path else DEFAULT_ASSETS_PATH
        self.comm_matrix_path = (
            Path(comm_matrix_path) if comm_matrix_path else DEFAULT_COMM_MATRIX_PATH
        )
        self.db_client = db_client
        self.redis_client = redis_client
        self.rebuild_interval_seconds = rebuild_interval_seconds

        # Pure-Python canonical backing store (always kept in sync; mirrored to NetworkX if present)
        self._nodes: Dict[str, Dict[str, Any]] = {}
        self._adj: Dict[str, Dict[str, Dict[str, Any]]] = {}  # src -> dst -> edge_attrs
        self._nx_graph: Any = nx.DiGraph() if HAS_NETWORKX else None

        # Lookup indexes
        self.assets_by_id: Dict[str, Dict[str, Any]] = {}
        self.approved_pairs: Set[Tuple[str, str]] = set()
        self.last_rebuilt: Optional[datetime] = None

        if auto_build:
            self.build_from_static_topology()

    # ------------------------------------------------------------------
    # Low-Level Node & Edge Operations
    # ------------------------------------------------------------------
    def add_node(self, node_id: str, node_type: str, **attrs: Any) -> None:
        props = {"id": node_id, "node_type": node_type, **attrs}
        if node_id in self._nodes:
            self._nodes[node_id].update(props)
        else:
            self._nodes[node_id] = props
        self._adj.setdefault(node_id, {})
        if self._nx_graph is not None:
            self._nx_graph.add_node(node_id, **self._nodes[node_id])

    def add_edge(
        self,
        src: str,
        dst: str,
        protocol: str = "TCP",
        port: Optional[int] = None,
        observed_frequency: int = 0,
        last_seen: Optional[str] = None,
        is_approved: bool = False,
        **extra: Any,
    ) -> None:
        if src not in self._nodes:
            self.add_node(src, "asset")
        if dst not in self._nodes:
            self.add_node(dst, "asset")

        existing = self._adj.setdefault(src, {}).get(dst)
        if existing:
            existing["observed_frequency"] = (
                int(existing.get("observed_frequency", 0)) + int(observed_frequency)
            )
            if last_seen:
                existing["last_seen"] = last_seen
            if is_approved:
                existing["is_approved"] = True
            if protocol and not existing.get("protocol"):
                existing["protocol"] = protocol
            if port is not None and existing.get("port") is None:
                existing["port"] = port
            existing.update(extra)
            edge_data = existing
        else:
            edge_data = {
                "protocol": protocol,
                "port": port,
                "observed_frequency": int(observed_frequency),
                "last_seen": last_seen,
                "is_approved": bool(is_approved),
                **extra,
            }
            self._adj[src][dst] = edge_data

        if is_approved:
            self.approved_pairs.add((src, dst))

        if self._nx_graph is not None:
            self._nx_graph.add_edge(src, dst, **edge_data)

    # ------------------------------------------------------------------
    # Topology & Flow Loading
    # ------------------------------------------------------------------
    def build_from_static_topology(self) -> Dict[str, int]:
        """Build graph nodes and approved edges from assets.json and communication_matrix.json."""
        self._nodes.clear()
        self._adj.clear()
        self.approved_pairs.clear()
        if self._nx_graph is not None:
            self._nx_graph.clear()

        # 1. VLAN nodes
        for vlan_id, vlan_label in VLAN_NAMES.items():
            self.add_node(vlan_label, "vlan", vlan_id=vlan_id)

        # 2. Asset, Identity, Service, and Vendor nodes from assets.json
        if self.assets_path.exists():
            try:
                asset_list = json.loads(self.assets_path.read_text(encoding="utf-8"))
            except Exception as exc:
                logger.error("Failed loading assets.json: %s", exc)
                asset_list = []

            for asset in asset_list:
                asset_id = asset.get("asset_id")
                if not asset_id:
                    continue
                self.assets_by_id[asset_id] = asset
                vlan_id = asset.get("vlan")
                is_vendor = asset_id.upper().startswith("VEND-") or (
                    asset.get("identity_classification") == "THIRD_PARTY_IDENTITY"
                )
                node_type = "vendor" if is_vendor else "asset"
                self.add_node(
                    asset_id,
                    node_type,
                    hostname=asset.get("hostname"),
                    ip_address=asset.get("ip_address"),
                    vlan=vlan_id,
                    network_segment=asset.get("network_segment"),
                    device_type=asset.get("device_type"),
                    criticality=asset.get("criticality", "medium"),
                    identity_classification=asset.get("identity_classification"),
                )

                # Link asset to its VLAN node
                vlan_node = VLAN_NAMES.get(vlan_id)
                if vlan_node:
                    self.add_edge(
                        asset_id,
                        vlan_node,
                        protocol="L2",
                        is_approved=True,
                        relationship="member_of",
                    )

                # Create service node for primary application if present
                app = asset.get("application")
                if app:
                    svc_node = f"SVC:{asset_id}"
                    self.add_node(svc_node, "service", application=app, host_asset=asset_id)
                    self.add_edge(
                        asset_id,
                        svc_node,
                        protocol="LOCAL",
                        is_approved=True,
                        relationship="hosts_service",
                    )

                # Add communication_peers as approved topology edges
                for peer_id in asset.get("communication_peers") or []:
                    self.add_edge(
                        asset_id,
                        peer_id,
                        protocol="ANY",
                        is_approved=True,
                        source_ref="assets.communication_peers",
                    )

        # 3. Approved communication paths from communication_matrix.json
        if self.comm_matrix_path.exists():
            try:
                rules = json.loads(self.comm_matrix_path.read_text(encoding="utf-8"))
            except Exception as exc:
                logger.error("Failed loading communication_matrix.json: %s", exc)
                rules = []

            for rule in rules:
                action = str(rule.get("action", "")).upper()
                if action not in ("ALLOW", "RESTRICT"):
                    continue
                src = str(rule.get("source", ""))
                dst = str(rule.get("destination", ""))
                if not src or not dst or src.upper() == "ANY" or dst.upper() == "ANY":
                    continue
                port = rule.get("port") if isinstance(rule.get("port"), int) else None
                self.add_edge(
                    src,
                    dst,
                    protocol=str(rule.get("protocol", "TCP")),
                    port=port,
                    is_approved=True,
                    rule_id=rule.get("rule_id"),
                    action=action,
                )

        self.last_rebuilt = datetime.now(timezone.utc)
        self._cache_to_redis_sync()
        return {"nodes": len(self._nodes), "edges": self.edge_count()}

    def ingest_observed_flows(self, flows: List[Dict[str, Any]]) -> int:
        """
        Incorporate observed network flows into the graph.
        Edges not present in approved communication matrix remain `is_approved=False`.
        """
        added = 0
        for flow in flows:
            src = str(flow.get("source_asset_id") or flow.get("src_asset") or "")
            dst = str(flow.get("destination_asset_id") or flow.get("dst_asset") or "")
            if not src or not dst:
                continue
            protocol = str(flow.get("protocol", "TCP"))
            port = flow.get("dst_port") or flow.get("destination_port") or flow.get("port")
            last_seen = str(
                flow.get("timestamp")
                or flow.get("last_seen")
                or datetime.now(timezone.utc).isoformat()
            )
            freq = int(flow.get("frequency", 1))
            is_approved = (src, dst) in self.approved_pairs
            self.add_edge(
                src,
                dst,
                protocol=protocol,
                port=int(port) if port is not None else None,
                observed_frequency=freq,
                last_seen=last_seen,
                is_approved=is_approved,
            )
            added += 1

        if added:
            self._cache_to_redis_sync()
        return added

    def add_vendor_link(
        self,
        vendor_id: str,
        target_asset_id: str,
        protocol: str = "HTTPS",
        port: Optional[int] = 443,
        is_approved: bool = True,
    ) -> None:
        """Explicitly link a vendor node to an accessible internal asset."""
        self.add_node(vendor_id, "vendor")
        self.add_edge(
            vendor_id,
            target_asset_id,
            protocol=protocol,
            port=port,
            is_approved=is_approved,
        )

    def add_identity_link(self, identity_id: str, asset_id: str, principal_type: str = "HUMAN_USER") -> None:
        """Link an identity node to an asset it authenticates from or accesses."""
        self.add_node(identity_id, "identity", principal_type=principal_type)
        self.add_edge(identity_id, asset_id, protocol="AUTH", is_approved=True)

    async def rebuild_from_database(self) -> Dict[str, int]:
        """Rebuild graph from static topology + recent PostgreSQL network_flows & vendors."""
        self.build_from_static_topology()

        if self.db_client is not None and hasattr(self.db_client, "fetch"):
            try:
                rows = await self.db_client.fetch(
                    """
                    SELECT source_asset_id, destination_asset_id, protocol, dst_port,
                           COUNT(*) AS frequency, MAX(timestamp) AS last_seen
                    FROM becpl_nids.network_flows
                    WHERE timestamp >= NOW() - INTERVAL '24 hours'
                      AND source_asset_id IS NOT NULL
                      AND destination_asset_id IS NOT NULL
                    GROUP BY source_asset_id, destination_asset_id, protocol, dst_port
                    """
                )
                self.ingest_observed_flows([dict(r) for r in rows])
            except Exception as exc:
                logger.warning("Database flow rebuild failed: %s", exc)

        await self.cache_to_redis()
        return {"nodes": len(self._nodes), "edges": self.edge_count()}

    async def run_periodic_rebuild(self, stop_event: Optional[asyncio.Event] = None) -> None:
        """Background task rebuilding the graph every 6 hours."""
        while stop_event is None or not stop_event.is_set():
            await self.rebuild_from_database()
            await asyncio.sleep(self.rebuild_interval_seconds)

    # ------------------------------------------------------------------
    # Graph Query API
    # ------------------------------------------------------------------
    def _asset_neighbors(
        self, node_id: str, undirected: bool = False, include_non_assets: bool = False
    ) -> List[str]:
        neighbors: Set[str] = set()
        for dst in self._adj.get(node_id, {}):
            if include_non_assets or self._nodes.get(dst, {}).get("node_type") in ("asset", "vendor"):
                neighbors.add(dst)
        if undirected:
            for src, targets in self._adj.items():
                if node_id in targets:
                    if include_non_assets or self._nodes.get(src, {}).get("node_type") in ("asset", "vendor"):
                        neighbors.add(src)
        return sorted(neighbors)

    def shortest_path(
        self, src_asset: str, dst_asset: str, undirected: bool = False
    ) -> List[str]:
        """
        Compute shortest path between src_asset and dst_asset (attack path candidate).
        Returns empty list if no path exists.
        """
        if src_asset not in self._nodes or dst_asset not in self._nodes:
            return []
        if src_asset == dst_asset:
            return [src_asset]

        queue: deque[List[str]] = deque([[src_asset]])
        visited: Set[str] = {src_asset}
        while queue:
            path = queue.popleft()
            current = path[-1]
            for nxt in self._asset_neighbors(current, undirected=undirected):
                if nxt == dst_asset:
                    return path + [nxt]
                if nxt not in visited:
                    visited.add(nxt)
                    queue.append(path + [nxt])
        return []

    def connected_assets(
        self, asset_id: str, hops: int = 2, undirected: bool = True
    ) -> Dict[str, int]:
        """
        Return all assets reachable from asset_id within `hops` hops as {asset_id: hop_distance}.
        Excludes the starting asset_id itself.
        """
        if asset_id not in self._nodes or hops <= 0:
            return {}

        distances: Dict[str, int] = {}
        queue: deque[Tuple[str, int]] = deque([(asset_id, 0)])
        visited: Set[str] = {asset_id}

        while queue:
            curr, dist = queue.popleft()
            if dist >= hops:
                continue
            for nxt in self._asset_neighbors(curr, undirected=undirected):
                if nxt not in visited:
                    visited.add(nxt)
                    distances[nxt] = dist + 1
                    queue.append((nxt, dist + 1))

        return distances

    def anomalous_edges(self) -> List[Dict[str, Any]]:
        """Return all observed edges present in actual flows that are NOT in the approved matrix."""
        anomalies: List[Dict[str, Any]] = []
        for src, targets in self._adj.items():
            for dst, attrs in targets.items():
                if not attrs.get("is_approved", False) and int(attrs.get("observed_frequency", 0)) > 0:
                    anomalies.append(
                        {
                            "source": src,
                            "destination": dst,
                            "protocol": attrs.get("protocol"),
                            "port": attrs.get("port"),
                            "observed_frequency": attrs.get("observed_frequency", 0),
                            "last_seen": attrs.get("last_seen"),
                            "is_approved": False,
                        }
                    )
        return anomalies

    def vendor_connected_assets(self, vendor_id: str, max_hops: int = 3) -> List[str]:
        """Return all asset IDs reachable from a vendor node within max_hops."""
        if vendor_id not in self._nodes:
            return []

        reachable: Set[str] = set()
        queue: deque[Tuple[str, int]] = deque([(vendor_id, 0)])
        visited: Set[str] = {vendor_id}

        while queue:
            curr, depth = queue.popleft()
            if depth >= max_hops:
                continue
            for nxt in self._asset_neighbors(curr, undirected=False):
                if nxt not in visited:
                    visited.add(nxt)
                    if self._nodes.get(nxt, {}).get("node_type") == "asset":
                        reachable.add(nxt)
                    queue.append((nxt, depth + 1))

        return sorted(reachable)

    # ------------------------------------------------------------------
    # Serialization & Redis Caching
    # ------------------------------------------------------------------
    def edge_count(self) -> int:
        return sum(len(targets) for targets in self._adj.values())

    def to_adjacency_dict(self) -> Dict[str, Any]:
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "node_count": len(self._nodes),
            "edge_count": self.edge_count(),
            "nodes": self._nodes,
            "adjacency": self._adj,
        }

    def to_networkx_json(self) -> Dict[str, Any]:
        """Return NetworkX node-link JSON representation for the AI analysis service."""
        nodes = [dict(attrs) for attrs in self._nodes.values()]
        links: List[Dict[str, Any]] = []
        for src, targets in self._adj.items():
            for dst, attrs in targets.items():
                links.append({"source": src, "target": dst, **attrs})
        return {
            "directed": True,
            "multigraph": False,
            "graph": {
                "name": "BECPL_Infrastructure_Graph",
                "last_rebuilt": self.last_rebuilt.isoformat() if self.last_rebuilt else None,
                "networkx_backend": HAS_NETWORKX,
            },
            "nodes": nodes,
            "links": links,
        }

    def _cache_to_redis_sync(self) -> None:
        if self.redis_client is None:
            return
        set_fn = getattr(self.redis_client, "set", None)
        if set_fn is None or inspect.iscoroutinefunction(set_fn):
            return
        try:
            set_fn(REDIS_KEY_GRAPH_CACHE, json.dumps(self.to_adjacency_dict()))
        except Exception as exc:
            logger.debug("Redis graph cache sync failed: %s", exc)

    async def cache_to_redis(self) -> None:
        if self.redis_client is None:
            return
        result = self.redis_client.set(
            REDIS_KEY_GRAPH_CACHE, json.dumps(self.to_adjacency_dict())
        )
        if inspect.isawaitable(result):
            await result

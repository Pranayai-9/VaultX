"""
VaultX NIDS - Asset & Identity Enrichment Service
Bharat Electronics Components Pvt. Ltd. (BECPL), Pune

Enriches normalized StandardSecurityEvent objects with:
  - Asset registry metadata (Redis cache TTL=60s backed by PostgreSQL becpl_nids.assets)
  - Identity registry metadata (auth events / explicit principal_name only)
  - Cross-VLAN and CRITICAL-asset risk flags for priority processing

IMPORTANT POLICY:
  Falls back to PrincipalType.UNKNOWN_IDENTITY if no identity match is found.
  NEVER infers identity from packet behaviour alone.
"""
from __future__ import annotations

import json
import uuid
from ipaddress import ip_address
from typing import Any, Dict, List, Optional

import structlog

from backend.ingestion.event_schema import (
    DetectionSource,
    EventType,
    PrincipalType,
    ProcessingStatus,
    StandardSecurityEvent,
)
from backend.ingestion.models import (
    AssetEnrichment,
    EnrichedSecurityEvent,
    ProcessingPriority,
    RiskFlag,
)

logger = structlog.get_logger(__name__)

# BECPL 7-VLAN zone map
VLAN_ZONE_MAP: Dict[int, str] = {
    10: "Corporate_IT",
    20: "Engineering",
    30: "OT",
    40: "Warehouse",
    50: "DMZ",
    60: "Cloud",
    70: "Security_Mgmt",
}

OT_ZONE_NAMES = {"ot", "manufacturing_ot", "vlan_ot", "manufacturing ot"}
VENDOR_ZONE_NAMES = {"dmz", "dmz_vendor", "vendor", "vlan_dmz"}


class AssetIdentityEnricher:
    """
    Enriches StandardSecurityEvent instances into EnrichedSecurityEvent instances.

    Uses a Redis cache (TTL=60s) populated from PostgreSQL ``becpl_nids.assets``
    and ``becpl_nids.identities``.
    """

    ASSET_CACHE_PREFIX = "vaultx:cache:asset:ip:"
    IDENTITY_CACHE_PREFIX = "vaultx:cache:identity:name:"

    def __init__(
        self,
        redis_client: Any = None,
        db_pool: Any = None,
        cache_ttl_seconds: int = 60,
    ) -> None:
        self._redis = redis_client
        self._db_pool = db_pool
        self._cache_ttl = cache_ttl_seconds

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def enrich(
        self,
        event: StandardSecurityEvent,
        dedup_hash: Optional[str] = None,
    ) -> EnrichedSecurityEvent:
        """Enrich a normalized StandardSecurityEvent with asset, zone, criticality, and identity data."""
        src_asset = await self.lookup_asset(event.source_ip) if event.source_ip else None
        dst_asset = await self.lookup_asset(event.destination_ip) if event.destination_ip else None

        risk_flags: List[str] = []
        is_cross_vlan = False
        involves_critical = False

        src_zone = src_asset.zone if src_asset else None
        dst_zone = dst_asset.zone if dst_asset else None

        # Cross-VLAN detection
        if src_zone and dst_zone and src_zone != dst_zone:
            is_cross_vlan = True
            risk_flags.append(RiskFlag.CROSS_VLAN.value)

        # Critical asset detection
        if (src_asset and src_asset.is_critical) or (dst_asset and dst_asset.is_critical):
            involves_critical = True
            risk_flags.append(RiskFlag.CRITICAL_ASSET_INVOLVED.value)

        # OT / vendor / external flags
        if dst_asset and dst_asset.is_ot:
            risk_flags.append(RiskFlag.OT_DESTINATION.value)
        if src_asset and src_asset.is_ot:
            risk_flags.append(RiskFlag.OT_SOURCE.value)
        if (src_asset and src_asset.is_vendor) or (dst_asset and dst_asset.is_vendor):
            risk_flags.append(RiskFlag.VENDOR_CONNECTION.value)
        if dst_asset and dst_asset.is_external:
            risk_flags.append(RiskFlag.EXTERNAL_DESTINATION.value)

        # Suricata alert / encryption flags
        if event.detection_source == DetectionSource.SURICATA or event.event_type == EventType.ALERT:
            risk_flags.append(RiskFlag.SURICATA_ALERT.value)
        if event.encryption_metadata is not None:
            risk_flags.append(RiskFlag.ENCRYPTED_TRAFFIC.value)

        # Identity enrichment (ONLY via explicit principal_name on auth / endpoint events;
        # NEVER inferred from packet behaviour alone)
        identity_id = event.identity_id
        principal_type = PrincipalType.UNKNOWN_IDENTITY

        principal_name = self._extract_principal_name(event)
        if principal_name:
            identity_rec = await self.lookup_identity(principal_name)
            if identity_rec is not None:
                identity_id = identity_rec["identity_id"]
                principal_type = identity_rec["principal_type"]
            else:
                identity_id = None
                principal_type = PrincipalType.UNKNOWN_IDENTITY
        else:
            # Explicit policy: fall back to UNKNOWN_IDENTITY; never infer from packets
            principal_type = PrincipalType.UNKNOWN_IDENTITY

        # Determine processing priority
        priority = self._determine_priority(
            risk_flags=risk_flags,
            is_cross_vlan=is_cross_vlan,
            involves_critical=involves_critical,
        )

        # Preserve deduplicated list of risk flags in stable order
        unique_flags = list(dict.fromkeys(risk_flags))

        base_data = event.model_dump()
        base_data["identity_id"] = identity_id
        base_data["principal_type"] = principal_type
        base_data["processing_status"] = ProcessingStatus.ENRICHED
        if src_asset and src_asset.asset_id:
            base_data["source_asset"] = src_asset.asset_id
        if dst_asset and dst_asset.asset_id:
            base_data["destination_asset"] = dst_asset.asset_id
        if src_zone:
            base_data["network_zone"] = src_zone
        elif dst_zone:
            base_data["network_zone"] = dst_zone

        return EnrichedSecurityEvent(
            **base_data,
            source_asset_id=src_asset.asset_id if src_asset else None,
            source_zone=src_zone,
            source_vlan=src_asset.vlan_id if src_asset else None,
            source_criticality=src_asset.criticality if src_asset else None,
            source_enrichment=src_asset,
            destination_asset_id=dst_asset.asset_id if dst_asset else None,
            destination_zone=dst_zone,
            destination_vlan=dst_asset.vlan_id if dst_asset else None,
            destination_criticality=dst_asset.criticality if dst_asset else None,
            destination_enrichment=dst_asset,
            risk_flags=unique_flags,
            is_cross_vlan=is_cross_vlan,
            involves_critical_asset=involves_critical,
            processing_priority=priority,
            dedup_hash=dedup_hash,
        )

    async def warm_cache_from_db(self) -> int:
        """Pre-load active assets from PostgreSQL into the Redis cache (TTL=60s)."""
        if not self._db_pool or not self._redis:
            return 0
        count = 0
        try:
            async with self._db_pool.acquire() as conn:
                rows = await conn.fetch(
                    """
                    SELECT a.asset_id, a.hostname, host(a.ip_address) AS ip_str,
                           a.vlan_id, a.device_type, a.criticality,
                           a.owner_department, a.identity_classification,
                           z.zone_name, z.zone_type
                    FROM becpl_nids.assets a
                    LEFT JOIN becpl_nids.network_zones z
                           ON a.zone_id = z.zone_id OR a.vlan_id = z.vlan_id
                    WHERE a.is_active = TRUE AND a.ip_address IS NOT NULL
                    """
                )
            for row in rows:
                enrichment = self._row_to_asset_enrichment(dict(row))
                if enrichment.ip_address:
                    await self._cache_asset(enrichment.ip_address, enrichment)
                    count += 1
            logger.info("enricher.cache_warmed", assets_cached=count)
        except Exception as exc:
            logger.warning("enricher.cache_warm_failed", error=str(exc))
        return count

    # ------------------------------------------------------------------
    # Asset & Identity Lookups
    # ------------------------------------------------------------------

    async def lookup_asset(self, ip: str) -> Optional[AssetEnrichment]:
        """Look up asset by IP using Redis cache (TTL=60s), falling back to PostgreSQL."""
        if not ip:
            return None
        cache_key = f"{self.ASSET_CACHE_PREFIX}{ip}"

        # 1. Check Redis cache
        if self._redis is not None:
            try:
                cached = await self._redis.get(cache_key)
                if cached is not None:
                    raw_str = cached.decode("utf-8") if isinstance(cached, bytes) else str(cached)
                    if raw_str == "MISS":
                        return self._fallback_external_asset(ip)
                    return AssetEnrichment(**json.loads(raw_str))
            except Exception as exc:
                logger.debug("enricher.redis_asset_get_error", ip=ip, error=str(exc))

        # 2. Query PostgreSQL
        if self._db_pool is not None:
            try:
                async with self._db_pool.acquire() as conn:
                    row = await conn.fetchrow(
                        """
                        SELECT a.asset_id, a.hostname, host(a.ip_address) AS ip_str,
                               a.vlan_id, a.device_type, a.criticality,
                               a.owner_department, a.identity_classification,
                               z.zone_name, z.zone_type
                        FROM becpl_nids.assets a
                        LEFT JOIN becpl_nids.network_zones z
                               ON a.zone_id = z.zone_id OR a.vlan_id = z.vlan_id
                        WHERE a.ip_address = $1::inet AND a.is_active = TRUE
                        LIMIT 1
                        """,
                        ip,
                    )
                if row is not None:
                    enrichment = self._row_to_asset_enrichment(dict(row))
                    await self._cache_asset(ip, enrichment)
                    return enrichment
                # Negative-cache misses briefly to prevent DB hammering
                if self._redis is not None:
                    try:
                        await self._redis.setex(cache_key, self._cache_ttl, "MISS")
                    except Exception:
                        pass
            except Exception as exc:
                logger.warning("enricher.db_asset_lookup_error", ip=ip, error=str(exc))

        return self._fallback_external_asset(ip)

    async def lookup_identity(self, principal_name: str) -> Optional[Dict[str, Any]]:
        """Look up identity by principal_name via Redis cache -> PostgreSQL."""
        if not principal_name:
            return None
        cache_key = f"{self.IDENTITY_CACHE_PREFIX}{principal_name}"

        if self._redis is not None:
            try:
                cached = await self._redis.get(cache_key)
                if cached is not None:
                    raw_str = cached.decode("utf-8") if isinstance(cached, bytes) else str(cached)
                    if raw_str == "MISS":
                        return None
                    parsed = json.loads(raw_str)
                    return {
                        "identity_id": uuid.UUID(parsed["identity_id"]) if parsed.get("identity_id") else None,
                        "principal_name": parsed.get("principal_name", principal_name),
                        "principal_type": PrincipalType(parsed.get("principal_type", PrincipalType.UNKNOWN_IDENTITY.value)),
                    }
            except Exception as exc:
                logger.debug("enricher.redis_identity_get_error", principal=principal_name, error=str(exc))

        if self._db_pool is not None:
            try:
                async with self._db_pool.acquire() as conn:
                    row = await conn.fetchrow(
                        """
                        SELECT identity_id::text AS identity_id, principal_name, principal_type
                        FROM becpl_nids.identities
                        WHERE principal_name = $1 AND is_active = TRUE
                        LIMIT 1
                        """,
                        principal_name,
                    )
                if row is not None:
                    record = {
                        "identity_id": uuid.UUID(row["identity_id"]),
                        "principal_name": row["principal_name"],
                        "principal_type": PrincipalType(row["principal_type"]),
                    }
                    if self._redis is not None:
                        try:
                            await self._redis.setex(
                                cache_key,
                                self._cache_ttl,
                                json.dumps({
                                    "identity_id": str(record["identity_id"]),
                                    "principal_name": record["principal_name"],
                                    "principal_type": record["principal_type"].value,
                                }),
                            )
                        except Exception:
                            pass
                    return record
            except Exception as exc:
                logger.warning("enricher.db_identity_lookup_error", principal=principal_name, error=str(exc))

        return None

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    async def _cache_asset(self, ip: str, enrichment: AssetEnrichment) -> None:
        if self._redis is None:
            return
        cache_key = f"{self.ASSET_CACHE_PREFIX}{ip}"
        try:
            await self._redis.setex(cache_key, self._cache_ttl, enrichment.model_dump_json())
        except Exception as exc:
            logger.debug("enricher.redis_asset_set_error", ip=ip, error=str(exc))

    @staticmethod
    def _row_to_asset_enrichment(row: Dict[str, Any]) -> AssetEnrichment:
        vlan_id = row.get("vlan_id")
        zone_name = row.get("zone_name") or VLAN_ZONE_MAP.get(vlan_id or -1) or "Unknown"
        zone_type = str(row.get("zone_type") or "").lower()
        criticality = str(row.get("criticality") or "low").lower()
        id_class = row.get("identity_classification")

        is_ot = (vlan_id == 30) or (zone_type == "ot") or (zone_name.lower() in OT_ZONE_NAMES)
        is_vendor = (
            (id_class == PrincipalType.THIRD_PARTY_IDENTITY.value)
            or (vlan_id == 50)
            or (zone_type == "dmz")
            or (zone_name.lower() in VENDOR_ZONE_NAMES)
        )
        is_external = (vlan_id == 60) or (zone_type == "cloud")

        return AssetEnrichment(
            asset_id=row.get("asset_id"),
            hostname=row.get("hostname"),
            ip_address=row.get("ip_str") or str(row.get("ip_address", "")).split("/")[0] or None,
            vlan_id=vlan_id,
            zone=zone_name,
            criticality=criticality,
            device_type=row.get("device_type"),
            owner_department=row.get("owner_department"),
            identity_classification=id_class,
            is_critical=(criticality == "critical"),
            is_ot=is_ot,
            is_vendor=is_vendor,
            is_external=is_external,
        )

    @staticmethod
    def _fallback_external_asset(ip: str) -> Optional[AssetEnrichment]:
        """Classify public IPs as External zone without fabricating an asset_id or identity."""
        try:
            parsed = ip_address(ip)
            if not (parsed.is_private or parsed.is_loopback or parsed.is_link_local):
                return AssetEnrichment(
                    ip_address=ip,
                    zone="External",
                    criticality="low",
                    is_external=True,
                )
        except ValueError:
            pass
        return None

    @staticmethod
    def _extract_principal_name(event: StandardSecurityEvent) -> Optional[str]:
        """Extract explicit principal_name only from auth/endpoint evidence (never network heuristics)."""
        if not event.evidence:
            return None
        if event.event_type in (EventType.AUTH_EVENT, EventType.ENDPOINT_EVENT, EventType.HTTP_EVENT):
            for key in ("principal_name", "vpn_user", "username", "user", "acct"):
                val = event.evidence.get(key)
                if val and str(val).strip():
                    return str(val).strip()
        return None

    @staticmethod
    def _determine_priority(
        risk_flags: List[str],
        is_cross_vlan: bool,
        involves_critical: bool,
    ) -> ProcessingPriority:
        flag_set = set(risk_flags)
        if (
            RiskFlag.OT_DESTINATION.value in flag_set
            or RiskFlag.OT_SOURCE.value in flag_set
            or RiskFlag.VENDOR_CONNECTION.value in flag_set
            or involves_critical
        ):
            return ProcessingPriority.HIGH_PRIORITY
        if RiskFlag.SURICATA_ALERT.value in flag_set or is_cross_vlan:
            return ProcessingPriority.SUSPICIOUS
        return ProcessingPriority.NORMAL


# Backwards-compatible alias
Enricher = AssetIdentityEnricher

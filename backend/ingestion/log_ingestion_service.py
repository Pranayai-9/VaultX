"""
VaultX NIDS - High-Throughput Log Ingestion Service
Bharat Electronics Components Pvt. Ltd. (BECPL), Pune

Features:
1. Connects to Redis Streams (XREAD / XREADGROUP on 'events:raw' stream)
2. Validates incoming events against StandardSecurityEvent schema
3. In-memory cached asset & zone enrichment (IP -> asset_id, zone, identity)
4. Classifies identity (uses principal_type from event or asset inventory, falls back to UNKNOWN_IDENTITY)
5. Writes validated events in micro-batches to PostgreSQL security_events table
6. Writes network flows to network_flows table
7. Publishes processed enriched events to Redis stream 'events:processed'
8. Handles backpressure, exponential backoff retries, and graceful shutdown
9. Logs structured ingestion metrics (throughput, drop rate, latency)
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import sys
import time
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network
from typing import Any, Dict, List, Optional, Set, Tuple

import asyncpg
import redis.asyncio as aioredis
from pydantic import ValidationError

from event_schema import (
    DetectionSource,
    EventType,
    NetworkFlowRecord,
    PrincipalType,
    ProcessingStatus,
    Severity,
    StandardSecurityEvent,
)
from suricata_parser import SuricataParser
from zeek_parser import ZeekParser

# Configure structured logging
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("vaultx.ingestion")

# Configuration constants
POSTGRES_HOST = os.getenv("POSTGRES_HOST", "127.0.0.1")
POSTGRES_PORT = int(os.getenv("POSTGRES_PORT", "5432"))
POSTGRES_DB = os.getenv("POSTGRES_DB", "vaultx_nids")
POSTGRES_USER = os.getenv("POSTGRES_USER", "vaultx_admin")
POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD", "VaultX_SecAdmin_2026!")

REDIS_HOST = os.getenv("REDIS_HOST", "127.0.0.1")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", "VaultX_RedisStream_2026!")

STREAM_RAW = os.getenv("STREAM_RAW", "events:raw")
STREAM_PROCESSED = os.getenv("STREAM_PROCESSED", "events:processed")
CONSUMER_GROUP = os.getenv("CONSUMER_GROUP", "vaultx_ingest_grp")
CONSUMER_NAME = os.getenv("CONSUMER_NAME", f"worker-{os.getpid()}")

BATCH_SIZE = int(os.getenv("BATCH_SIZE", "100"))
BLOCK_TIME_MS = int(os.getenv("BLOCK_TIME_MS", "2000"))
MAX_RETRIES = int(os.getenv("MAX_RETRIES", "3"))


class AssetCache:
    """In-memory cache for ultra-fast asset and zone enrichment during wire-speed ingestion."""

    def __init__(self):
        self.ip_to_asset: Dict[str, Dict[str, Any]] = {}
        self.cidrs_to_zone: List[Tuple[Any, str, int]] = []
        self.last_updated: float = 0.0

    async def refresh(self, pool: asyncpg.Pool) -> None:
        """Fetch asset catalog and network zones from PostgreSQL."""
        try:
            async with pool.acquire() as conn:
                # 1. Load Zones
                zones = await conn.fetch(
                    "SELECT zone_name, vlan_id, cidr_range FROM becpl_nids.network_zones WHERE cidr_range IS NOT NULL"
                )
                new_cidrs = []
                for z in zones:
                    try:
                        net = ip_network(str(z["cidr_range"]), strict=False)
                        new_cidrs.append((net, z["zone_name"], z["vlan_id"]))
                    except ValueError:
                        pass
                self.cidrs_to_zone = new_cidrs

                # 2. Load Assets
                assets = await conn.fetch(
                    """
                    SELECT a.asset_id, a.hostname, a.ip_address, a.vlan_id,
                           a.identity_classification, a.criticality, z.zone_name
                    FROM becpl_nids.assets a
                    LEFT JOIN becpl_nids.network_zones z ON a.zone_id = z.zone_id
                    WHERE a.is_active = TRUE AND a.ip_address IS NOT NULL
                    """
                )
                new_assets = {}
                for a in assets:
                    ip_str = str(a["ip_address"]).split("/")[0]
                    new_assets[ip_str] = {
                        "asset_id": a["asset_id"],
                        "hostname": a["hostname"],
                        "vlan_id": a["vlan_id"],
                        "zone_name": a["zone_name"],
                        "identity_classification": a["identity_classification"],
                        "criticality": a["criticality"],
                    }
                self.ip_to_asset = new_assets
                self.last_updated = time.time()
                logger.info(
                    "Asset cache refreshed: %d assets, %d zone CIDRs loaded",
                    len(self.ip_to_asset),
                    len(self.cidrs_to_zone),
                )
        except Exception as e:
            logger.error("Failed to refresh asset cache: %s", e)

    def lookup_ip(self, ip_str: Optional[str]) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """
        Returns (asset_id, zone_name, identity_classification)
        """
        if not ip_str:
            return None, None, None

        clean_ip = ip_str.split("/")[0].strip()

        # Direct asset table hit
        if clean_ip in self.ip_to_asset:
            info = self.ip_to_asset[clean_ip]
            return info["asset_id"], info["zone_name"], info["identity_classification"]

        # Subnet match for zone
        try:
            addr = ip_address(clean_ip)
            for net, zone_name, _ in self.cidrs_to_zone:
                if addr in net:
                    return None, zone_name, None
        except ValueError:
            pass

        return None, None, None


class IngestionService:
    """Async Redis Stream Consumer and PostgreSQL Batch Persister."""

    def __init__(self):
        self.pg_pool: Optional[asyncpg.Pool] = None
        self.redis_client: Optional[aioredis.Redis] = None
        self.asset_cache = AssetCache()
        self.zeek_parser = ZeekParser()
        self.suricata_parser = SuricataParser()
        self.is_running = False

        # Ingestion Metrics
        self.metrics = {
            "events_read": 0,
            "events_validated": 0,
            "events_written": 0,
            "flows_written": 0,
            "validation_errors": 0,
            "db_errors": 0,
            "batches_processed": 0,
            "start_time": time.time(),
        }

    async def start(self) -> None:
        """Initialize database pools, redis connection, and consumer groups."""
        logger.info("Initializing VaultX Ingestion Service...")

        # 1. Connect to PostgreSQL
        self.pg_pool = await asyncpg.create_pool(
            host=POSTGRES_HOST,
            port=POSTGRES_PORT,
            database=POSTGRES_DB,
            user=POSTGRES_USER,
            password=POSTGRES_PASSWORD,
            min_size=5,
            max_size=20,
            command_timeout=60,
        )
        logger.info("Connected to PostgreSQL at %s:%d/%s", POSTGRES_HOST, POSTGRES_PORT, POSTGRES_DB)

        # 2. Connect to Redis
        self.redis_client = aioredis.Redis(
            host=REDIS_HOST,
            port=REDIS_PORT,
            password=REDIS_PASSWORD,
            decode_responses=True,
        )
        await self.redis_client.ping()
        logger.info("Connected to Redis at %s:%d", REDIS_HOST, REDIS_PORT)

        # 3. Ensure Consumer Group exists for backpressure management
        try:
            await self.redis_client.xgroup_create(
                name=STREAM_RAW, groupname=CONSUMER_GROUP, id="0", mkstream=True
            )
            logger.info("Created consumer group '%s' on stream '%s'", CONSUMER_GROUP, STREAM_RAW)
        except aioredis.ResponseError as e:
            if "BUSYGROUP" in str(e):
                logger.info("Consumer group '%s' already exists", CONSUMER_GROUP)
            else:
                logger.warning("Consumer group setup notice: %s", e)

        # 4. Populate Asset Cache
        await self.asset_cache.refresh(self.pg_pool)
        self.is_running = True

    async def stop(self) -> None:
        """Graceful shutdown of pools and streams."""
        logger.info("Stopping Ingestion Service...")
        self.is_running = False
        if self.redis_client:
            await self.redis_client.close()
        if self.pg_pool:
            await self.pg_pool.close()
        logger.info("Ingestion Service stopped cleanly.")

    def _normalize_incoming_payload(self, raw_data: Dict[str, Any]) -> Tuple[Optional[StandardSecurityEvent], Optional[NetworkFlowRecord]]:
        """Parses raw stream payload which might be native format, Zeek, or Suricata."""
        # Check if already a standardized event dict
        if "event_type" in raw_data and "sensor_id" in raw_data and "timestamp" in raw_data:
            try:
                event = StandardSecurityEvent.model_validate(raw_data)
                return event, None
            except ValidationError as ve:
                logger.debug("Standard model validation error: %s", ve)

        # Check for Suricata EVE
        if "event_type" in raw_data and ("alert" in raw_data or "flow" in raw_data or "in_iface" in raw_data):
            try:
                res = self.suricata_parser.parse_eve_record(raw_data)
                if isinstance(res, tuple):
                    return res[0], res[1]
                return res, None
            except Exception as se:
                logger.debug("Suricata parse error: %s", se)

        # Check for Zeek log
        if "id.orig_h" in raw_data or ("ts" in raw_data and "uid" in raw_data):
            log_type = raw_data.get("_zeek_type", "conn")
            try:
                res = self.zeek_parser.dispatch(log_type, raw_data)
                if isinstance(res, tuple):
                    return res[0], res[1]
                return res, None
            except Exception as ze:
                logger.debug("Zeek parse error: %s", ze)

        # Fallback: attempt direct dict conversion with defaults
        try:
            return StandardSecurityEvent.model_validate(raw_data), None
        except Exception:
            return None, None

    def enrich_event(self, event: StandardSecurityEvent) -> StandardSecurityEvent:
        """
        Enriches event with:
        - Source & destination asset lookups
        - Network zone resolution
        - Identity classification (principal_type)
        - Processing status transition
        """
        # Source lookup
        src_asset, src_zone, src_identity = self.asset_cache.lookup_ip(event.source_ip)
        if src_asset:
            event.source_asset = src_asset
        if src_zone and not event.network_zone:
            event.network_zone = src_zone

        # Destination lookup
        dst_asset, dst_zone, _ = self.asset_cache.lookup_ip(event.destination_ip)
        if dst_asset:
            event.destination_asset = dst_asset

        # Classify Identity: Use explicit from event, or infer from asset, or fallback to UNKNOWN_IDENTITY
        if event.principal_type == PrincipalType.UNKNOWN_IDENTITY and src_identity:
            try:
                event.principal_type = PrincipalType(src_identity)
            except ValueError:
                event.principal_type = PrincipalType.UNKNOWN_IDENTITY

        event.processing_status = ProcessingStatus.ENRICHED
        return event

    async def _write_batch_to_postgres(
        self,
        events: List[StandardSecurityEvent],
        flows: List[NetworkFlowRecord]
    ) -> bool:
        """Execute batch inserts into becpl_nids.security_events and network_flows."""
        if not events and not flows:
            return True

        for attempt in range(1, MAX_RETRIES + 1):
            try:
                async with self.pg_pool.acquire() as conn:
                    async with conn.transaction():
                        # 1. Batch Insert Security Events
                        if events:
                            event_rows = [
                                (
                                    e.event_id,
                                    e.timestamp,
                                    e.sensor_id,
                                    e.source_ip,
                                    e.destination_ip,
                                    e.source_port,
                                    e.destination_port,
                                    e.protocol,
                                    e.network_zone,
                                    e.source_asset,
                                    e.destination_asset,
                                    e.identity_id,
                                    e.principal_type.value if e.principal_type else "UNKNOWN_IDENTITY",
                                    e.application,
                                    e.flow_id,
                                    e.connection_duration,
                                    e.bytes_transferred,
                                    e.packets_transferred,
                                    json.dumps(e.encryption_metadata.model_dump(mode="json")) if e.encryption_metadata else None,
                                    e.event_type.value if e.event_type else "network_flow",
                                    e.detection_source.value if e.detection_source else "zeek",
                                    e.severity.value if e.severity else "informational",
                                    e.confidence,
                                    json.dumps(e.evidence),
                                    e.processing_status.value,
                                    json.dumps(e.event_provenance.model_dump(mode="json")) if e.event_provenance else None,
                                    e.model_version,
                                    e.detection_rule_version,
                                    e.incident_association,
                                    e.response_action_identifier,
                                )
                                for e in events
                            ]

                            await conn.executemany(
                                """
                                INSERT INTO becpl_nids.security_events (
                                    event_id, timestamp, sensor_id, source_ip, destination_ip,
                                    source_port, destination_port, protocol, network_zone,
                                    source_asset_id, destination_asset_id, identity_id,
                                    principal_type, application, flow_id, connection_duration_ms,
                                    bytes_transferred, packets_transferred, encryption_metadata,
                                    event_type, detection_source, severity, confidence, evidence,
                                    processing_status, event_provenance, model_version,
                                    detection_rule_version, incident_id, response_action_id
                                ) VALUES (
                                    $1, $2, $3, $4::inet, $5::inet, $6, $7, $8, $9, $10, $11, $12,
                                    $13, $14, $15, $16, $17, $18, $19::jsonb, $20, $21, $22, $23,
                                    $24::jsonb, $25, $26::jsonb, $27, $28, $29, $30
                                ) ON CONFLICT DO NOTHING
                                """,
                                event_rows,
                            )

                        # 2. Batch Insert Network Flows
                        if flows:
                            flow_rows = [
                                (
                                    f.flow_id,
                                    f.timestamp,
                                    f.sensor_id,
                                    f.src_ip,
                                    f.dst_ip,
                                    f.src_port,
                                    f.dst_port,
                                    f.protocol,
                                    f.duration_ms,
                                    f.orig_bytes,
                                    f.resp_bytes,
                                    f.orig_packets,
                                    f.resp_packets,
                                    f.conn_state,
                                    f.missed_bytes,
                                    f.history,
                                    f.source_asset_id,
                                    f.destination_asset_id,
                                    f.source_zone,
                                    f.destination_zone,
                                    f.tls_version,
                                    f.tls_cipher,
                                    f.tls_server_name,
                                    f.dns_query,
                                    f.http_method,
                                    f.http_host,
                                    f.http_uri,
                                    f.http_status,
                                    f.detection_flags,
                                    f.zeek_uid,
                                )
                                for f in flows
                            ]

                            await conn.executemany(
                                """
                                INSERT INTO becpl_nids.network_flows (
                                    flow_id, timestamp, sensor_id, src_ip, dst_ip, src_port,
                                    dst_port, protocol, duration_ms, orig_bytes, resp_bytes,
                                    orig_packets, resp_packets, conn_state, missed_bytes, history,
                                    source_asset_id, destination_asset_id, source_zone, destination_zone,
                                    tls_version, tls_cipher, tls_server_name, dns_query, http_method,
                                    http_host, http_uri, http_status, detection_flags, zeek_uid
                                ) VALUES (
                                    $1, $2, $3, $4::inet, $5::inet, $6, $7, $8, $9, $10, $11, $12,
                                    $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24,
                                    $25, $26, $27, $28, $29, $30
                                ) ON CONFLICT DO NOTHING
                                """,
                                flow_rows,
                            )

                self.metrics["events_written"] += len(events)
                self.metrics["flows_written"] += len(flows)
                return True

            except Exception as e:
                self.metrics["db_errors"] += 1
                logger.warning(
                    "DB write error on attempt %d/%d: %s. Retrying in %0.2fs...",
                    attempt,
                    MAX_RETRIES,
                    e,
                    2 ** attempt,
                )
                await asyncio.sleep(2 ** attempt)

        logger.error("Exhausted retries writing batch of %d events to database!", len(events))
        return False

    async def _publish_processed_events(self, events: List[StandardSecurityEvent]) -> None:
        """Publishes enriched events to Redis stream 'events:processed'."""
        if not events:
            return

        pipe = self.redis_client.pipeline()
        for ev in events:
            payload = {"payload": json.dumps(ev.to_dict())}
            pipe.xadd(STREAM_PROCESSED, payload, maxlen=100000)

        await pipe.execute()

    async def run(self) -> None:
        """Main event ingestion loop with Redis XREAD / XREADGROUP."""
        logger.info(
            "Starting ingestion loop listening on stream '%s' (batch_size=%d)...",
            STREAM_RAW,
            BATCH_SIZE,
        )

        last_cache_refresh = time.time()
        last_metrics_log = time.time()

        while self.is_running:
            try:
                # Periodic cache refresh every 5 minutes
                if time.time() - last_cache_refresh > 300:
                    await self.asset_cache.refresh(self.pg_pool)
                    last_cache_refresh = time.time()

                # Read batch from Redis Stream
                # Use XREADGROUP for persistent offset tracking and auto-failover
                try:
                    entries = await self.redis_client.xreadgroup(
                        groupname=CONSUMER_GROUP,
                        consumername=CONSUMER_NAME,
                        streams={STREAM_RAW: ">"},
                        count=BATCH_SIZE,
                        block=BLOCK_TIME_MS,
                    )
                except aioredis.ResponseError:
                    # Fallback to direct XREAD if consumer group not available
                    entries = await self.redis_client.xread(
                        streams={STREAM_RAW: "$"},
                        count=BATCH_SIZE,
                        block=BLOCK_TIME_MS,
                    )

                if not entries:
                    await asyncio.sleep(0.05)
                    continue

                events_to_write: List[StandardSecurityEvent] = []
                flows_to_write: List[NetworkFlowRecord] = []
                message_ids_to_ack: List[str] = []

                for stream_name, message_list in entries:
                    for msg_id, raw_fields in message_list:
                        self.metrics["events_read"] += 1
                        message_ids_to_ack.append(msg_id)

                        # Decode payload JSON
                        payload_str = raw_fields.get("payload") or raw_fields.get("data")
                        if payload_str:
                            try:
                                record = json.loads(payload_str)
                            except Exception:
                                record = raw_fields
                        else:
                            record = raw_fields

                        # Validate & Parse
                        event, flow = self._normalize_incoming_payload(record)
                        if event:
                            self.enrich_event(event)
                            events_to_write.append(event)
                            self.metrics["events_validated"] += 1
                        else:
                            self.metrics["validation_errors"] += 1

                        if flow:
                            flows_to_write.append(flow)

                # Persist batch to PostgreSQL
                if events_to_write or flows_to_write:
                    success = await self._write_batch_to_postgres(events_to_write, flows_to_write)
                    if success:
                        # Publish enriched events to downstream stream
                        await self._publish_processed_events(events_to_write)

                        # Acknowledge messages in Redis group
                        if message_ids_to_ack:
                            try:
                                await self.redis_client.xack(
                                    STREAM_RAW, CONSUMER_GROUP, *message_ids_to_ack
                                )
                            except Exception:
                                pass
                        self.metrics["batches_processed"] += 1

                # Periodically log operational metrics
                if time.time() - last_metrics_log > 30:
                    uptime = time.time() - self.metrics["start_time"]
                    eps = self.metrics["events_written"] / max(uptime, 1)
                    logger.info(
                        "[METRICS] Events Read: %d | Written: %d | Flows: %d | Validation Errs: %d | DB Errs: %d | Rate: %.1f eps",
                        self.metrics["events_read"],
                        self.metrics["events_written"],
                        self.metrics["flows_written"],
                        self.metrics["validation_errors"],
                        self.metrics["db_errors"],
                        eps,
                    )
                    last_metrics_log = time.time()

            except asyncio.CancelledError:
                break
            except Exception as loop_err:
                logger.error("Unhandled error in ingestion loop: %s", loop_err, exc_info=True)
                await asyncio.sleep(1.0)


async def main():
    service = IngestionService()
    loop = asyncio.get_running_loop()

    # Handle termination signals
    def shutdown_handler():
        logger.info("Signal received, initiating graceful shutdown...")
        service.is_running = False

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, shutdown_handler)
        except NotImplementedError:
            # Signal handling on Windows
            pass

    await service.start()
    try:
        await service.run()
    finally:
        await service.stop()


if __name__ == "__main__":
    asyncio.run(main())

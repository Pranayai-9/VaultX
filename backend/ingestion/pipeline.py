"""
VaultX NIDS - Central Event Ingestion Orchestrator (Phase 2)
Bharat Electronics Components Pvt. Ltd. (BECPL), Pune

Responsibilities:
 1. Connects to Redis Streams (XREADGROUP with consumer groups)
 2. Reads from multiple streams: events:raw, events:endpoint, events:third_party, events:simulation
 3. Dispatches events through Normaliser -> DedupCache -> Enricher -> Persistence -> ParallelProcessor
 4. Implements XACK strictly AFTER successful persistence
 5. Creates consumer groups automatically (MKSTREAM) if they do not exist
 6. Tracks processing checkpoints in Redis and PostgreSQL via CheckpointManager
 7. Monitors queue depth and emits BackpressureAlert to alerts:operational above threshold
 8. Handles burst traffic gracefully via configurable batch size (default 100)
 9. Logs structured ingestion metrics (events/sec, latency, error rate, queue depth)
10. Exposes FastAPI /health endpoint (stream lag, consumer group info, latency histogram, sensor health)
    and Prometheus /metrics endpoint.
"""
from __future__ import annotations

import asyncio
import json
import signal
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import asyncpg
import redis.asyncio as aioredis
import structlog
import uvicorn
from fastapi import FastAPI

from backend.ingestion.checkpoint_manager import CheckpointManager
from backend.ingestion.config import IngestionConfig, settings
from backend.ingestion.dedup_cache import DedupCache
from backend.ingestion.event_schema import EventType
from backend.ingestion.enricher import AssetIdentityEnricher
from backend.ingestion.models import (
    AlertSeverity,
    BackpressureAlert,
    EnrichedSecurityEvent,
    PipelineMetrics,
    StreamLagInfo,
)
from backend.ingestion.normaliser import EventNormaliser, NormalisationError
from backend.ingestion.sensor_health_monitor import SensorHealthMonitor
from backend.processing.feature_extractor import FeatureExtractor
from backend.processing.flow_aggregator import FlowAggregator
from backend.processing.parallel_processor import ParallelEventProcessor
from backend.processing.resource_monitor import ResourceMonitor

logger = structlog.get_logger(__name__)


class IngestionPipeline:
    """Central asyncio orchestrator for the VaultX Phase 2 ingestion pipeline."""

    def __init__(
        self,
        config: Optional[IngestionConfig] = None,
        redis_client: Optional[Any] = None,
        db_pool: Optional[Any] = None,
    ) -> None:
        self.config = config or settings
        self._redis: Optional[Any] = redis_client
        self._db_pool: Optional[Any] = db_pool
        self._owns_redis: bool = redis_client is None
        self._owns_db: bool = db_pool is None

        # Sub-components initialized in start() or lazily
        self.dedup_cache: Optional[DedupCache] = None
        self.normaliser: Optional[EventNormaliser] = None
        self.enricher: Optional[AssetIdentityEnricher] = None
        self.checkpoint_manager: Optional[CheckpointManager] = None
        self.sensor_monitor: Optional[SensorHealthMonitor] = None
        self.flow_aggregator: Optional[FlowAggregator] = None
        self.feature_extractor: FeatureExtractor = FeatureExtractor()
        self.parallel_processor: Optional[ParallelEventProcessor] = None
        self.resource_monitor: Optional[ResourceMonitor] = None

        # Pipeline counters
        self.events_ingested_total: int = 0
        self.events_persisted_total: int = 0
        self.duplicates_filtered_total: int = 0
        self.normalisation_errors_total: int = 0
        self.enrichment_errors_total: int = 0
        self.persistence_errors_total: int = 0
        self.backpressure_active: bool = False
        self._last_backpressure_alert_ts: float = 0.0
        self._last_metrics_log_ts: float = time.monotonic()

        # Per-sensor observed lag (ms between event timestamp and ingest time)
        self._sensor_lag_ms: Dict[str, float] = {}

        self._running: bool = False
        self._loop_task: Optional[asyncio.Task] = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def initialize(self) -> None:
        """Connect external clients, wire pipeline components, and ensure consumer groups."""
        if self._redis is None:
            self._redis = aioredis.from_url(
                self.config.REDIS_URL,
                encoding="utf-8",
                decode_responses=True,
            )

        if self._db_pool is None and self.config.POSTGRES_DSN:
            try:
                self._db_pool = await asyncpg.create_pool(
                    dsn=self.config.POSTGRES_DSN,
                    min_size=2,
                    max_size=10,
                )
            except Exception as exc:
                logger.warning("pipeline.postgres_connect_failed", error=str(exc))
                self._db_pool = None

        self.dedup_cache = DedupCache(
            redis_client=self._redis,
            ttl_seconds=self.config.DEDUP_WINDOW_SECONDS,
        )
        self.normaliser = EventNormaliser(dedup_cache=self.dedup_cache)
        self.enricher = AssetIdentityEnricher(
            redis_client=self._redis,
            db_pool=self._db_pool,
            cache_ttl_seconds=self.config.ASSET_CACHE_TTL_SECONDS,
        )
        self.checkpoint_manager = CheckpointManager(
            redis_client=self._redis,
            db_pool=self._db_pool,
            consumer_group=self.config.CONSUMER_GROUP,
            consumer_name=self.config.CONSUMER_NAME,
            flush_interval_seconds=self.config.CHECKPOINT_INTERVAL_SECONDS,
        )
        self.sensor_monitor = SensorHealthMonitor(
            redis_client=self._redis,
            sensor_config_path=self.config.SENSOR_CONFIG_PATH,
            offline_threshold_seconds=self.config.SENSOR_OFFLINE_THRESHOLD_SECONDS,
        )
        self.flow_aggregator = FlowAggregator(
            redis_client=self._redis,
            flow_timeout_seconds=self.config.FLOW_TIMEOUT_SECONDS,
            completed_stream=self.config.COMPLETED_FLOWS_STREAM,
        )
        self.parallel_processor = ParallelEventProcessor(
            flow_aggregator=self.flow_aggregator,
            feature_extractor=self.feature_extractor,
            redis_client=self._redis,
            worker_count=self.config.WORKER_COUNT,
            ml_queue_backpressure_threshold=self.config.ML_QUEUE_BACKPRESSURE_THRESHOLD,
            ml_inference_stream=self.config.ML_INFERENCE_STREAM,
            ml_priority_stream=self.config.ML_PRIORITY_STREAM,
            operational_alerts_stream=self.config.OPERATIONAL_ALERTS_STREAM,
        )
        self.resource_monitor = ResourceMonitor(
            redis_client=self._redis,
            sensor_monitor=self.sensor_monitor,
            monitored_streams=list(self.config.INPUT_STREAMS),
            interval_seconds=self.config.RESOURCE_MONITOR_INTERVAL_SECONDS,
            cpu_threshold_pct=self.config.CPU_ALERT_THRESHOLD,
            queue_depth_threshold=self.config.BACKPRESSURE_THRESHOLD,
            latency_p95_threshold_seconds=self.config.LATENCY_P95_ALERT_SECONDS,
            sensor_offline_threshold_seconds=self.config.SENSOR_OFFLINE_THRESHOLD_SECONDS,
        )

        await self.ensure_consumer_groups()
        await self.enricher.warm_cache_from_db()

    async def start(self) -> None:
        """Start background services and the main Redis Streams consumption loop."""
        if self._running:
            return
        await self.initialize()
        await self.checkpoint_manager.start()
        await self.sensor_monitor.start()
        await self.flow_aggregator.start()
        await self.parallel_processor.start()
        await self.resource_monitor.start()

        self._running = True
        self._loop_task = asyncio.create_task(self._consume_loop(), name="ingestion-consume-loop")
        logger.info(
            "pipeline.started",
            streams=self.config.INPUT_STREAMS,
            consumer_group=self.config.CONSUMER_GROUP,
            consumer_name=self.config.CONSUMER_NAME,
            batch_size=self.config.BATCH_SIZE,
        )

    async def stop(self) -> None:
        """Gracefully shut down consumption loop and flush buffers/checkpoints."""
        self._running = False
        if self._loop_task is not None:
            self._loop_task.cancel()
            try:
                await self._loop_task
            except asyncio.CancelledError:
                pass
            self._loop_task = None

        if self.parallel_processor:
            await self.parallel_processor.stop()
        if self.flow_aggregator:
            await self.flow_aggregator.stop()
        if self.resource_monitor:
            await self.resource_monitor.stop()
        if self.sensor_monitor:
            await self.sensor_monitor.stop()
        if self.checkpoint_manager:
            await self.checkpoint_manager.stop()

        if self._owns_db and self._db_pool is not None:
            await self._db_pool.close()
        if self._owns_redis and self._redis is not None:
            await self._redis.aclose()

        logger.info(
            "pipeline.stopped",
            events_ingested=self.events_ingested_total,
            events_persisted=self.events_persisted_total,
            duplicates_filtered=self.duplicates_filtered_total,
        )

    # ------------------------------------------------------------------
    # Consumer Group Setup
    # ------------------------------------------------------------------

    async def ensure_consumer_groups(self) -> None:
        """Create Redis Streams consumer groups (MKSTREAM) if not already present."""
        if self._redis is None:
            return
        for stream in self.config.INPUT_STREAMS:
            try:
                await self._redis.xgroup_create(
                    name=stream,
                    groupname=self.config.CONSUMER_GROUP,
                    id="0",
                    mkstream=True,
                )
                logger.info(
                    "pipeline.consumer_group_created",
                    stream=stream,
                    group=self.config.CONSUMER_GROUP,
                )
            except Exception as exc:
                if "BUSYGROUP" in str(exc):
                    logger.debug(
                        "pipeline.consumer_group_exists",
                        stream=stream,
                        group=self.config.CONSUMER_GROUP,
                    )
                else:
                    logger.warning(
                        "pipeline.consumer_group_error",
                        stream=stream,
                        error=str(exc),
                    )

    # ------------------------------------------------------------------
    # Main Consumption Loop & Batch Processing
    # ------------------------------------------------------------------

    async def _consume_loop(self) -> None:
        streams_map = {stream: ">" for stream in self.config.INPUT_STREAMS}

        while self._running:
            try:
                # 1. Monitor queue depth & emit backpressure alerts if needed
                await self.check_backpressure()

                # 2. Read batch across all 4 input streams using XREADGROUP
                response = await self._redis.xreadgroup(
                    groupname=self.config.CONSUMER_GROUP,
                    consumername=self.config.CONSUMER_NAME,
                    streams=streams_map,
                    count=self.config.BATCH_SIZE,
                    block=self.config.BLOCK_MS,
                )

                if response:
                    await self.process_stream_batch(response)

                # 3. Periodically log ingestion metrics
                now_mono = time.monotonic()
                if now_mono - self._last_metrics_log_ts >= 30.0:
                    await self._log_metrics()
                    self._last_metrics_log_ts = now_mono

            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("pipeline.consume_loop_error", error=str(exc))
                await asyncio.sleep(1.0)

    async def process_stream_batch(
        self,
        stream_entries: List[Tuple[str, List[Tuple[str, Dict[str, Any]]]]],
    ) -> int:
        """
        Process a batch returned by XREADGROUP:
        - Skip already-checkpointed messages
        - Normalise & deduplicate
        - Enrich with asset & identity data
        - Persist to PostgreSQL & 'events:processed'
        - XACK ONLY after successful persistence
        - Dispatch enriched events to ParallelEventProcessor
        """
        assert self.normaliser is not None
        assert self.enricher is not None
        assert self.checkpoint_manager is not None
        assert self.parallel_processor is not None
        assert self.resource_monitor is not None

        enriched_batch: List[Tuple[str, str, EnrichedSecurityEvent, float]] = []
        ack_immediately: List[Tuple[str, str]] = []  # duplicates / malformed / health pings

        for stream_name_raw, messages in stream_entries:
            stream_name = (
                stream_name_raw.decode("utf-8")
                if isinstance(stream_name_raw, bytes)
                else str(stream_name_raw)
            )
            for msg_id_raw, fields in messages:
                msg_id = msg_id_raw.decode("utf-8") if isinstance(msg_id_raw, bytes) else str(msg_id_raw)
                start_mono = time.perf_counter()

                # Prevent duplicate reprocessing after restart
                if self.checkpoint_manager.is_already_processed(stream_name, msg_id):
                    ack_immediately.append((stream_name, msg_id))
                    continue

                self.events_ingested_total += 1

                # Parse payload dict from stream fields
                raw_payload, source_hint, sensor_id = self._decode_stream_message(fields)

                # Intercept sensor heartbeat events
                if isinstance(raw_payload, dict) and raw_payload.get("event_type") == EventType.SENSOR_HEALTH.value:
                    if self.sensor_monitor is not None:
                        await self.sensor_monitor.record_heartbeat(
                            sensor_id=raw_payload.get("sensor_id") or sensor_id,
                            events_per_min=float(raw_payload.get("events_per_min", 0.0)),
                            packet_drop_rate=float(raw_payload.get("packet_drop_rate", 0.0)),
                            zeek_status=str(raw_payload.get("zeek_status", "running")),
                            suricata_status=str(raw_payload.get("suricata_status", "running")),
                        )
                    ack_immediately.append((stream_name, msg_id))
                    continue

                # Step 1: Normalise + Deduplicate
                try:
                    std_event, is_dup, dedup_hash = await self.normaliser.normalise_and_check_duplicate(
                        raw_payload,
                        source=source_hint,
                        sensor_id=sensor_id,
                    )
                except NormalisationError as exc:
                    self.normalisation_errors_total += 1
                    self.resource_monitor.record_dropped_event()
                    logger.warning(
                        "pipeline.normalisation_error",
                        stream=stream_name,
                        msg_id=msg_id,
                        source=exc.source,
                        error=str(exc),
                    )
                    ack_immediately.append((stream_name, msg_id))
                    continue

                if is_dup:
                    self.duplicates_filtered_total += 1
                    ack_immediately.append((stream_name, msg_id))
                    continue

                # Track per-sensor lag
                lag_ms = max(0.0, (datetime.now(timezone.utc) - std_event.timestamp).total_seconds() * 1000.0)
                self._sensor_lag_ms[std_event.sensor_id] = round(lag_ms, 2)

                # Step 2: Enrich
                try:
                    enriched = await self.enricher.enrich(std_event, dedup_hash=dedup_hash)
                except Exception as exc:
                    self.enrichment_errors_total += 1
                    self.resource_monitor.record_dropped_event()
                    logger.error(
                        "pipeline.enrichment_error",
                        stream=stream_name,
                        msg_id=msg_id,
                        error=str(exc),
                    )
                    continue

                enriched_batch.append((stream_name, msg_id, enriched, start_mono))

        # Step 3: Acknowledge filtered duplicates / health messages / malformed dead-letters
        for stream_name, msg_id in ack_immediately:
            await self._ack_and_checkpoint(stream_name, msg_id)

        if not enriched_batch:
            return 0

        # Step 4: Persist enriched batch BEFORE acknowledging (at-least-once guarantee)
        persisted_items = await self._persist_events(enriched_batch)

        # Step 5: XACK + update checkpoint ONLY for persisted items, then dispatch to parallel processor
        persisted_events: List[EnrichedSecurityEvent] = []
        for stream_name, msg_id, enriched, start_mono in persisted_items:
            await self._ack_and_checkpoint(stream_name, msg_id)
            latency_ms = (time.perf_counter() - start_mono) * 1000.0
            self.resource_monitor.record_event_processed(latency_ms)
            self.events_persisted_total += 1
            persisted_events.append(enriched)

        if persisted_events:
            await self.parallel_processor.process_batch(persisted_events)

        return len(persisted_events)

    # ------------------------------------------------------------------
    # Persistence & Acknowledgment
    # ------------------------------------------------------------------

    async def _persist_events(
        self,
        items: List[Tuple[str, str, EnrichedSecurityEvent, float]],
    ) -> List[Tuple[str, str, EnrichedSecurityEvent, float]]:
        """
        Persist enriched events to PostgreSQL ``becpl_nids.security_events`` and
        publish to Redis ``events:processed``. Only successfully persisted events
        are returned for XACK.
        """
        persisted: List[Tuple[str, str, EnrichedSecurityEvent, float]] = []

        # 1. PostgreSQL batch insert
        if self._db_pool is not None:
            records = [
                (
                    ev.event_id,
                    ev.timestamp,
                    ev.sensor_id,
                    ev.source_ip,
                    ev.destination_ip,
                    ev.source_port,
                    ev.destination_port,
                    ev.protocol,
                    ev.network_zone,
                    ev.source_asset_id or ev.source_asset,
                    ev.destination_asset_id or ev.destination_asset,
                    ev.identity_id,
                    ev.principal_type.value,
                    ev.application,
                    ev.flow_id,
                    ev.connection_duration,
                    ev.bytes_transferred,
                    ev.packets_transferred,
                    json.dumps(ev.encryption_metadata.model_dump(mode="json")) if ev.encryption_metadata else None,
                    ev.event_type.value,
                    ev.detection_source.value,
                    ev.severity.value,
                    ev.confidence,
                    json.dumps(ev.evidence),
                    ev.processing_status.value,
                    json.dumps(ev.event_provenance.model_dump(mode="json")) if ev.event_provenance else None,
                    ev.model_version,
                    ev.detection_rule_version,
                )
                for _, _, ev, _ in items
            ]
            try:
                async with self._db_pool.acquire() as conn:
                    await conn.executemany(
                        """
                        INSERT INTO becpl_nids.security_events (
                            event_id, timestamp, sensor_id, source_ip, destination_ip,
                            source_port, destination_port, protocol, network_zone,
                            source_asset_id, destination_asset_id, identity_id, principal_type,
                            application, flow_id, connection_duration_ms, bytes_transferred,
                            packets_transferred, encryption_metadata, event_type, detection_source,
                            severity, confidence, evidence, processing_status, event_provenance,
                            model_version, detection_rule_version
                        )
                        VALUES (
                            $1, $2, $3, $4::inet, $5::inet,
                            $6, $7, $8, $9,
                            $10, $11, $12, $13,
                            $14, $15, $16, $17,
                            $18, $19::jsonb, $20, $21,
                            $22, $23, $24::jsonb, $25, $26::jsonb,
                            $27, $28
                        )
                        ON CONFLICT (event_id, timestamp) DO NOTHING
                        """,
                        records,
                    )
            except Exception as exc:
                self.persistence_errors_total += len(items)
                logger.error("pipeline.postgres_persist_failed", count=len(items), error=str(exc))
                # Do NOT return items for XACK so Redis Streams can redeliver them
                return []

        # 2. Publish to Redis downstream processed stream
        for item in items:
            _, _, ev, _ = item
            try:
                if self._redis is not None:
                    await self._redis.xadd(
                        self.config.PROCESSED_STREAM,
                        {"payload": json.dumps(ev.to_dict())},
                    )
                persisted.append(item)
            except Exception as exc:
                self.persistence_errors_total += 1
                logger.error(
                    "pipeline.redis_processed_publish_failed",
                    event_id=str(ev.event_id),
                    error=str(exc),
                )

        return persisted

    async def _ack_and_checkpoint(self, stream_name: str, msg_id: str) -> None:
        if self._redis is not None:
            try:
                await self._redis.xack(stream_name, self.config.CONSUMER_GROUP, msg_id)
            except Exception as exc:
                logger.warning("pipeline.xack_failed", stream=stream_name, msg_id=msg_id, error=str(exc))
        if self.checkpoint_manager is not None:
            await self.checkpoint_manager.update_checkpoint(stream_name, msg_id)

    # ------------------------------------------------------------------
    # Queue Depth Monitoring & Backpressure
    # ------------------------------------------------------------------

    async def get_stream_lags(self) -> List[StreamLagInfo]:
        lags: List[StreamLagInfo] = []
        if self._redis is None:
            return lags

        for stream in self.config.INPUT_STREAMS:
            stream_len = 0
            pending = 0
            lag = 0
            last_delivered = None
            consumers = 0
            try:
                stream_len = int(await self._redis.xlen(stream))
            except Exception:
                pass
            try:
                groups = await self._redis.xinfo_groups(stream)
                for grp in groups:
                    name = grp.get("name")
                    if isinstance(name, bytes):
                        name = name.decode("utf-8")
                    if name == self.config.CONSUMER_GROUP:
                        pending = int(grp.get("pending", 0))
                        lag = int(grp.get("lag") or pending)
                        consumers = int(grp.get("consumers", 0))
                        ld = grp.get("last-delivered-id")
                        last_delivered = ld.decode("utf-8") if isinstance(ld, bytes) else ld
                        break
            except Exception:
                lag = stream_len

            lags.append(StreamLagInfo(
                stream_name=stream,
                consumer_group=self.config.CONSUMER_GROUP,
                stream_length=stream_len,
                pending_count=pending,
                lag=lag,
                last_delivered_id=last_delivered,
                consumers_count=consumers,
            ))
        return lags

    async def check_backpressure(self) -> bool:
        lags = await self.get_stream_lags()
        total_depth = sum(item.stream_length for item in lags)
        if total_depth > self.config.BACKPRESSURE_THRESHOLD:
            self.backpressure_active = True
            now = time.monotonic()
            if now - self._last_backpressure_alert_ts >= 60.0:
                self._last_backpressure_alert_ts = now
                alert = BackpressureAlert(
                    alert_type="BACKPRESSURE",
                    severity=AlertSeverity.HIGH,
                    source_component="ingestion-pipeline",
                    metric_value=float(total_depth),
                    threshold=float(self.config.BACKPRESSURE_THRESHOLD),
                    message=(
                        f"Total ingestion queue depth ({total_depth}) exceeded threshold "
                        f"({self.config.BACKPRESSURE_THRESHOLD})"
                    ),
                    details={"streams": [s.model_dump() for s in lags]},
                )
                logger.warning("pipeline.backpressure_alert", total_depth=total_depth)
                if self._redis is not None:
                    try:
                        await self._redis.xadd(
                            self.config.OPERATIONAL_ALERTS_STREAM,
                            {"payload": json.dumps(alert.to_dict())},
                        )
                    except Exception:
                        pass
            return True

        self.backpressure_active = False
        return False

    # ------------------------------------------------------------------
    # Metrics & Health
    # ------------------------------------------------------------------

    async def get_metrics(self) -> PipelineMetrics:
        lags = await self.get_stream_lags()
        total_errors = (
            self.normalisation_errors_total
            + self.enrichment_errors_total
            + self.persistence_errors_total
        )
        error_rate = (
            round(total_errors / self.events_ingested_total, 6)
            if self.events_ingested_total > 0
            else 0.0
        )
        latency = (
            self.resource_monitor.get_latency_histogram()
            if self.resource_monitor
            else PipelineMetrics().processing_latency
        )
        eps = self.resource_monitor.get_events_per_sec() if self.resource_monitor else 0.0

        return PipelineMetrics(
            events_per_sec=eps,
            events_ingested_total=self.events_ingested_total,
            events_persisted_total=self.events_persisted_total,
            events_dropped_total=(
                self.resource_monitor.dropped_events_total if self.resource_monitor else 0
            ),
            duplicates_filtered_total=self.duplicates_filtered_total,
            normalisation_errors_total=self.normalisation_errors_total,
            enrichment_errors_total=self.enrichment_errors_total,
            persistence_errors_total=self.persistence_errors_total,
            error_rate=error_rate,
            total_queue_depth=sum(s.stream_length for s in lags),
            ml_queue_depth=self.parallel_processor.ml_queue_depth if self.parallel_processor else 0,
            backpressure_active=self.backpressure_active,
            processing_latency=latency,
            stream_lags=lags,
            pipeline_version=self.config.PIPELINE_VERSION,
        )

    async def get_health_payload(self) -> Dict[str, Any]:
        """Build JSON payload for FastAPI ``GET /health`` endpoint."""
        metrics = await self.get_metrics()
        sensor_health = (
            self.sensor_monitor.get_health_summary()
            if self.sensor_monitor
            else {"total_sensors": 0, "sensors": {}}
        )
        status = "degraded" if (self.backpressure_active or sensor_health.get("offline", 0) > 0) else "healthy"

        return {
            "status": status,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "pipeline_version": self.config.PIPELINE_VERSION,
            "consumer_group": {
                "group_name": self.config.CONSUMER_GROUP,
                "consumer_name": self.config.CONSUMER_NAME,
                "batch_size": self.config.BATCH_SIZE,
                "worker_count": self.config.WORKER_COUNT,
                "checkpoints": self.checkpoint_manager.snapshot() if self.checkpoint_manager else {},
            },
            "stream_lag_per_stream": [s.model_dump() for s in metrics.stream_lags],
            "stream_lag_per_sensor_ms": dict(self._sensor_lag_ms),
            "processing_latency_histogram": metrics.processing_latency.model_dump(),
            "throughput": {
                "events_per_sec": metrics.events_per_sec,
                "events_ingested_total": metrics.events_ingested_total,
                "events_persisted_total": metrics.events_persisted_total,
                "duplicates_filtered_total": metrics.duplicates_filtered_total,
                "error_rate": metrics.error_rate,
                "total_queue_depth": metrics.total_queue_depth,
                "ml_queue_depth": metrics.ml_queue_depth,
                "backpressure_active": metrics.backpressure_active,
            },
            "sensor_health": sensor_health,
        }

    async def _log_metrics(self) -> None:
        metrics = await self.get_metrics()
        logger.info(
            "pipeline.metrics",
            events_per_sec=metrics.events_per_sec,
            latency_p50_ms=metrics.processing_latency.p50_ms,
            latency_p95_ms=metrics.processing_latency.p95_ms,
            latency_p99_ms=metrics.processing_latency.p99_ms,
            error_rate=metrics.error_rate,
            queue_depth=metrics.total_queue_depth,
            duplicates_filtered=metrics.duplicates_filtered_total,
            active_flows=self.flow_aggregator.active_flow_count if self.flow_aggregator else 0,
        )

    @staticmethod
    def _decode_stream_message(fields: Dict[Any, Any]) -> Tuple[Any, Optional[str], str]:
        decoded: Dict[str, Any] = {
            (k.decode("utf-8") if isinstance(k, bytes) else str(k)): (
                v.decode("utf-8") if isinstance(v, bytes) else v
            )
            for k, v in fields.items()
        }
        source_hint = decoded.get("source") or decoded.get("_source")
        sensor_id = str(decoded.get("sensor_id") or "UNKNOWN-SENSOR")

        payload = decoded.get("payload") or decoded.get("data") or decoded.get("event")
        if payload is not None:
            if isinstance(payload, str):
                stripped = payload.strip()
                if stripped.startswith("{"):
                    try:
                        parsed = json.loads(stripped)
                        if isinstance(parsed, dict):
                            return parsed, source_hint or parsed.get("source"), str(parsed.get("sensor_id") or sensor_id)
                    except json.JSONDecodeError:
                        pass
                return payload, source_hint, sensor_id
            return payload, source_hint, sensor_id

        return decoded, source_hint, sensor_id


# ---------------------------------------------------------------------------
# FastAPI Application Factory (/health and /metrics)
# ---------------------------------------------------------------------------

def create_app(pipeline: Optional[IngestionPipeline] = None) -> FastAPI:
    """Create FastAPI app exposing /health and Prometheus /metrics endpoints."""
    managed_pipeline = pipeline or IngestionPipeline()

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        if not managed_pipeline._running:
            await managed_pipeline.start()
        if managed_pipeline.resource_monitor is not None:
            _app.include_router(managed_pipeline.resource_monitor.create_metrics_router())
        try:
            yield
        finally:
            await managed_pipeline.stop()

    app = FastAPI(
        title="VaultX Event Ingestion & Processing Pipeline",
        version=managed_pipeline.config.PIPELINE_VERSION,
        lifespan=lifespan,
    )

    @app.get("/health")
    async def health_endpoint() -> Dict[str, Any]:
        return await managed_pipeline.get_health_payload()

    @app.get("/metrics/json")
    async def json_metrics_endpoint() -> Dict[str, Any]:
        return (await managed_pipeline.get_metrics()).model_dump(mode="json")

    if managed_pipeline.resource_monitor is not None:
        app.include_router(managed_pipeline.resource_monitor.create_metrics_router())

    return app


def main() -> None:  # pragma: no cover
    app = create_app()
    uvicorn.run(
        app,
        host=settings.API_HOST,
        port=settings.API_PORT,
        log_level=settings.LOG_LEVEL.lower(),
    )


if __name__ == "__main__":  # pragma: no cover
    main()

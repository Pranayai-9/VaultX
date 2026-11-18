"""
VaultX NIDS - Parallel Event Processing Coordinator
Bharat Electronics Components Pvt. Ltd. (BECPL), Pune

Uses Python 3.11+ asyncio.TaskGroup to process enriched security events concurrently
across configurable async workers while:
  - Preserving per-flow timestamp ordering via deterministic flow partitioning
  - Applying selective inference routing (ALL -> lightweight, SUSPICIOUS -> ML queue,
    HIGH-PRIORITY -> immediate ML inference)
  - Enforcing ML queue backpressure (> 500 items -> temporary statistical-only mode)
"""
from __future__ import annotations

import asyncio
import json
import zlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Dict, List, Optional

import structlog

from backend.ingestion.event_schema import DetectionSource, EventType, Severity
from backend.ingestion.models import (
    AlertSeverity,
    BackpressureAlert,
    EnrichedSecurityEvent,
    FlowRecord,
    ProcessingPriority,
    RiskFlag,
)
from backend.processing.feature_extractor import FeatureExtractor
from backend.processing.flow_aggregator import FlowAggregator

logger = structlog.get_logger(__name__)

# Simple lightweight signature watchlist (fast O(1) checks)
HIGH_RISK_PORTS = {23, 445, 3389, 5900, 4444, 502, 102, 20000, 4840}


@dataclass
class ProcessingOutcome:
    """Result of processing a single enriched event through the selective router."""

    event_id: str
    flow_key: str
    routing_tier: str  # lightweight | ml_queue | immediate_ml | statistical_only_backpressure
    signature_hits: List[str] = field(default_factory=list)
    completed_flow: Optional[FlowRecord] = None
    features: Optional[Dict[str, Any]] = None


class ParallelEventProcessor:
    """
    Concurrent event processor backed by ``asyncio.TaskGroup`` and partitioned
    per-worker queues so events belonging to the same ``flow_id`` are always
    processed sequentially in timestamp order.
    """

    def __init__(
        self,
        flow_aggregator: FlowAggregator,
        feature_extractor: Optional[FeatureExtractor] = None,
        redis_client: Any = None,
        worker_count: int = 4,
        ml_queue_backpressure_threshold: int = 500,
        ml_inference_stream: str = "events:ml_inference",
        ml_priority_stream: str = "events:ml_priority",
        operational_alerts_stream: str = "alerts:operational",
        immediate_ml_callback: Optional[Callable[[EnrichedSecurityEvent, Optional[Dict[str, Any]]], Awaitable[Any]]] = None,
    ) -> None:
        self._flow_aggregator = flow_aggregator
        self._feature_extractor = feature_extractor or FeatureExtractor()
        self._redis = redis_client
        self._worker_count = max(1, worker_count)
        self._ml_bp_threshold = ml_queue_backpressure_threshold
        self._ml_inference_stream = ml_inference_stream
        self._ml_priority_stream = ml_priority_stream
        self._alerts_stream = operational_alerts_stream
        self._immediate_ml_callback = immediate_ml_callback

        # Partitioned worker queues guarantee same-flow ordering
        self._worker_queues: List[asyncio.Queue[Optional[EnrichedSecurityEvent]]] = [
            asyncio.Queue() for _ in range(self._worker_count)
        ]
        # Internal ML queue for backpressure tracking & downstream ML consumer
        self.ml_inference_queue: asyncio.Queue[Dict[str, Any]] = asyncio.Queue()

        # Per-flow last seen timestamp to enforce/track ordering
        self._last_flow_ts: Dict[str, datetime] = {}

        # Counters
        self.processed_total: int = 0
        self.lightweight_only_count: int = 0
        self.ml_queued_count: int = 0
        self.immediate_ml_count: int = 0
        self.backpressure_degraded_count: int = 0
        self.ml_backpressure_active: bool = False

        self._running: bool = False
        self._runner_task: Optional[asyncio.Task] = None

    @property
    def ml_queue_depth(self) -> int:
        return self.ml_inference_queue.qsize()

    # ------------------------------------------------------------------
    # Lifecycle (asyncio.TaskGroup)
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Start the TaskGroup-managed worker pool in the background."""
        if self._running:
            return
        self._running = True
        self._runner_task = asyncio.create_task(self._run_worker_group(), name="parallel-processor-tg")
        logger.info("parallel_processor.started", workers=self._worker_count)

    async def stop(self) -> None:
        """Drain queues and shut down the TaskGroup cleanly."""
        if not self._running:
            return
        self._running = False
        for q in self._worker_queues:
            await q.put(None)
        if self._runner_task is not None:
            await self._runner_task
            self._runner_task = None
        logger.info("parallel_processor.stopped", processed_total=self.processed_total)

    async def _run_worker_group(self) -> None:
        async with asyncio.TaskGroup() as tg:
            for worker_id in range(self._worker_count):
                tg.create_task(
                    self._worker_loop(worker_id),
                    name=f"event-worker-{worker_id}",
                )

    # ------------------------------------------------------------------
    # Batch & single-event submission
    # ------------------------------------------------------------------

    async def submit(self, event: EnrichedSecurityEvent) -> int:
        """Route a single event to its deterministic flow partition queue."""
        worker_idx = self._partition_index(self._flow_key(event))
        await self._worker_queues[worker_idx].put(event)
        return worker_idx

    async def process_batch(self, events: List[EnrichedSecurityEvent]) -> List[ProcessingOutcome]:
        """
        Concurrently process a batch of events using ``asyncio.TaskGroup``.
        Events sharing the same flow_id are sorted by timestamp and executed
        in strict chronological order within their partition.
        """
        if not events:
            return []

        partitions: Dict[int, List[EnrichedSecurityEvent]] = {i: [] for i in range(self._worker_count)}
        for ev in events:
            idx = self._partition_index(self._flow_key(ev))
            partitions[idx].append(ev)

        # Ensure chronological order per flow within each partition
        for idx in partitions:
            partitions[idx].sort(key=lambda e: e.timestamp)

        results: List[ProcessingOutcome] = []

        async def _run_partition(partition_events: List[EnrichedSecurityEvent]) -> None:
            for ev in partition_events:
                outcome = await self.process_event(ev)
                results.append(outcome)

        async with asyncio.TaskGroup() as tg:
            for idx, part_events in partitions.items():
                if part_events:
                    tg.create_task(_run_partition(part_events), name=f"batch-partition-{idx}")

        return results

    # ------------------------------------------------------------------
    # Selective Inference Pipeline per Event
    # ------------------------------------------------------------------

    async def process_event(self, event: EnrichedSecurityEvent) -> ProcessingOutcome:
        """
        Execute selective inference for one event:
        1. ALL events -> flow aggregation + lightweight signature check
        2. HIGH-PRIORITY (OT network, vendor connections, critical asset) -> immediate ML inference
        3. SUSPICIOUS (Suricata alert OR cross-VLAN OR critical asset) -> ML inference queue
           (falls back to statistical-only if ML queue > threshold)
        """
        flow_key = self._flow_key(event)
        self._last_flow_ts[flow_key] = event.timestamp

        # Step 1: Lightweight flow aggregation + signature check (ALL events)
        completed_flow = await self._flow_aggregator.add_event(event)
        features = self._feature_extractor.extract(completed_flow) if completed_flow else None
        sig_hits = self._lightweight_signature_check(event)

        # Classify routing tier
        tier = self.classify_event(event, sig_hits)

        if tier == "high_priority":
            await self._dispatch_immediate_ml(event, features)
            self.immediate_ml_count += 1
            routing_tier = "immediate_ml"
        elif tier == "suspicious":
            if self.ml_inference_queue.qsize() >= self._ml_bp_threshold:
                # Backpressure engaged: route to statistical-only processing temporarily
                if not self.ml_backpressure_active:
                    self.ml_backpressure_active = True
                    await self._emit_ml_backpressure_alert(self.ml_inference_queue.qsize())
                self.backpressure_degraded_count += 1
                routing_tier = "statistical_only_backpressure"
            else:
                if self.ml_backpressure_active and self.ml_inference_queue.qsize() < int(self._ml_bp_threshold * 0.7):
                    self.ml_backpressure_active = False
                await self._enqueue_ml_inference(event, features)
                self.ml_queued_count += 1
                routing_tier = "ml_queue"
        else:
            self.lightweight_only_count += 1
            routing_tier = "lightweight"

        self.processed_total += 1
        return ProcessingOutcome(
            event_id=str(event.event_id),
            flow_key=flow_key,
            routing_tier=routing_tier,
            signature_hits=sig_hits,
            completed_flow=completed_flow,
            features=features,
        )

    def classify_event(self, event: EnrichedSecurityEvent, signature_hits: Optional[List[str]] = None) -> str:
        """
        Determine selective inference tier:
        - 'high_priority': OT network, vendor connections, or critical asset
        - 'suspicious': Suricata alert OR cross-VLAN OR critical asset OR signature hits
        - 'normal': lightweight processing only
        """
        flags = set(event.risk_flags or [])

        is_high_priority = (
            event.processing_priority == ProcessingPriority.HIGH_PRIORITY
            or event.involves_critical_asset
            or RiskFlag.OT_DESTINATION.value in flags
            or RiskFlag.OT_SOURCE.value in flags
            or RiskFlag.VENDOR_CONNECTION.value in flags
            or RiskFlag.CRITICAL_ASSET_INVOLVED.value in flags
            or (event.source_zone or "").lower() == "ot"
            or (event.destination_zone or "").lower() == "ot"
        )
        if is_high_priority:
            return "high_priority"

        is_suspicious = (
            event.processing_priority == ProcessingPriority.SUSPICIOUS
            or event.detection_source == DetectionSource.SURICATA
            or event.event_type == EventType.ALERT
            or event.is_cross_vlan
            or RiskFlag.SURICATA_ALERT.value in flags
            or RiskFlag.CROSS_VLAN.value in flags
            or bool(signature_hits)
        )
        if is_suspicious:
            return "suspicious"

        return "normal"

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    async def _worker_loop(self, worker_id: int) -> None:
        queue = self._worker_queues[worker_id]
        while True:
            event = await queue.get()
            if event is None:
                queue.task_done()
                break
            try:
                await self.process_event(event)
            except Exception as exc:
                logger.error(
                    "parallel_processor.worker_error",
                    worker_id=worker_id,
                    event_id=str(event.event_id),
                    error=str(exc),
                )
            finally:
                queue.task_done()

    @staticmethod
    def _lightweight_signature_check(event: EnrichedSecurityEvent) -> List[str]:
        hits: List[str] = []
        if event.destination_port in HIGH_RISK_PORTS:
            hits.append(f"HIGH_RISK_PORT:{event.destination_port}")
        if event.severity in (Severity.CRITICAL, Severity.HIGH):
            hits.append(f"HIGH_SEVERITY:{event.severity.value}")
        if event.is_cross_vlan and (event.destination_zone or "").lower() == "ot":
            hits.append("CROSS_VLAN_TO_OT")
        return hits

    async def _enqueue_ml_inference(
        self,
        event: EnrichedSecurityEvent,
        features: Optional[Dict[str, Any]],
    ) -> None:
        item = {
            "event_id": str(event.event_id),
            "priority": "suspicious",
            "event": event.to_dict(),
            "features": features,
            "enqueued_at": datetime.now(timezone.utc).isoformat(),
        }
        await self.ml_inference_queue.put(item)
        if self._redis is not None:
            try:
                await self._redis.xadd(self._ml_inference_stream, {"payload": json.dumps(item)})
            except Exception as exc:
                logger.debug("parallel_processor.ml_stream_error", error=str(exc))

    async def _dispatch_immediate_ml(
        self,
        event: EnrichedSecurityEvent,
        features: Optional[Dict[str, Any]],
    ) -> None:
        item = {
            "event_id": str(event.event_id),
            "priority": "high_priority",
            "event": event.to_dict(),
            "features": features,
            "dispatched_at": datetime.now(timezone.utc).isoformat(),
        }
        if self._immediate_ml_callback is not None:
            try:
                await self._immediate_ml_callback(event, features)
            except Exception as exc:
                logger.warning("parallel_processor.immediate_ml_cb_error", error=str(exc))
        if self._redis is not None:
            try:
                await self._redis.xadd(self._ml_priority_stream, {"payload": json.dumps(item)})
            except Exception as exc:
                logger.debug("parallel_processor.ml_priority_stream_error", error=str(exc))

    async def _emit_ml_backpressure_alert(self, depth: int) -> None:
        alert = BackpressureAlert(
            alert_type="ML_BACKPRESSURE",
            severity=AlertSeverity.HIGH,
            source_component="parallel-processor",
            stream_name=self._ml_inference_stream,
            metric_value=float(depth),
            threshold=float(self._ml_bp_threshold),
            message=(
                f"ML inference queue depth ({depth}) exceeded threshold ({self._ml_bp_threshold}); "
                "temporarily routing suspicious events to statistical-only processing"
            ),
        )
        logger.warning("parallel_processor.ml_backpressure", queue_depth=depth, threshold=self._ml_bp_threshold)
        if self._redis is not None:
            try:
                await self._redis.xadd(self._alerts_stream, {"payload": json.dumps(alert.to_dict())})
            except Exception:
                pass

    @staticmethod
    def _flow_key(event: EnrichedSecurityEvent) -> str:
        if event.flow_id:
            return str(event.flow_id)
        return f"{event.source_ip}:{event.source_port}->{event.destination_ip}:{event.destination_port}:{event.protocol}"

    def _partition_index(self, flow_key: str) -> int:
        return zlib.crc32(flow_key.encode("utf-8")) % self._worker_count

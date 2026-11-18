"""
VaultX NIDS - Network Flow Aggregator
Bharat Electronics Components Pvt. Ltd. (BECPL), Pune

Groups individual connection/packet events into bidirectional 5-tuple network flows
in memory, computes lightweight statistical features (no per-packet ML inference),
and emits completed FlowRecord objects to Redis stream 'flows:completed' on idle
timeout or TCP FIN/RST closure.
"""
from __future__ import annotations

import asyncio
import json
import math
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

import structlog

from backend.ingestion.event_schema import StandardSecurityEvent
from backend.ingestion.models import EnrichedSecurityEvent, FlowRecord, RiskFlag

logger = structlog.get_logger(__name__)

CanonicalFlowKey = Tuple[Tuple[str, int], Tuple[str, int], str]


def make_canonical_flow_key(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    protocol: str,
) -> CanonicalFlowKey:
    """Order-independent bidirectional 5-tuple key."""
    ep_a = (src_ip, int(src_port))
    ep_b = (dst_ip, int(dst_port))
    proto = protocol.upper()
    return (ep_a, ep_b, proto) if ep_a <= ep_b else (ep_b, ep_a, proto)


@dataclass
class _ActiveFlow:
    """Mutable in-memory accumulator for an active bidirectional network flow."""

    flow_id: uuid.UUID
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    start_time: datetime
    last_seen: datetime

    fwd_packets: int = 0
    bwd_packets: int = 0
    fwd_bytes: int = 0
    bwd_bytes: int = 0

    fwd_timestamps: List[float] = field(default_factory=list)
    bwd_timestamps: List[float] = field(default_factory=list)
    all_timestamps: List[float] = field(default_factory=list)
    packet_lengths: List[int] = field(default_factory=list)

    psh_flag_count: int = 0
    ack_flag_count: int = 0
    syn_flag_count: int = 0
    fin_flag_count: int = 0
    rst_flag_count: int = 0

    # Asset / zone metadata
    sensor_id: Optional[str] = None
    source_asset_id: Optional[str] = None
    destination_asset_id: Optional[str] = None
    source_zone: Optional[str] = None
    destination_zone: Optional[str] = None
    source_vlan: Optional[int] = None
    dest_vlan: Optional[int] = None
    source_criticality: Optional[str] = None
    dest_criticality: Optional[str] = None
    is_cross_vlan: bool = False
    is_vendor_connection: bool = False
    is_ot_destination: bool = False
    is_external_dest: bool = False

    # TLS metadata
    tls_version: Optional[str] = None
    sni: Optional[str] = None
    cert_issuer: Optional[str] = None
    cert_issuer_known: Optional[bool] = None
    ja3_hash: Optional[str] = None
    ja3s_hash: Optional[str] = None


class FlowAggregator:
    """
    Lightweight in-memory bidirectional 5-tuple network flow aggregator.

    - Tracks active flows keyed by bidirectional 5-tuple (src_ip, dst_ip, src_port, dst_port, protocol)
    - Computes packet/byte counts, duration, rates, IAT stats, upload/download ratio, initiating direction
    - Closes flows on idle timeout (default 60s) or TCP FIN/RST signals
    - Emits completed FlowRecord to Redis Stream 'flows:completed'
    """

    COMPLETED_STREAM = "flows:completed"
    _KNOWN_CERT_ISSUERS = (
        "let's encrypt", "digicert", "sectigo", "globalsign",
        "amazon", "google trust", "microsoft", "entrust", "godaddy", "becpl",
    )

    def __init__(
        self,
        redis_client: Any = None,
        flow_timeout_seconds: int = 60,
        completed_stream: str = COMPLETED_STREAM,
        on_flow_completed: Optional[Callable[[FlowRecord], Any]] = None,
    ) -> None:
        self._redis = redis_client
        self._timeout = flow_timeout_seconds
        self._completed_stream = completed_stream
        self._on_flow_completed = on_flow_completed

        self._active_flows: Dict[CanonicalFlowKey, _ActiveFlow] = {}
        self._running: bool = False
        self._reaper_task: Optional[asyncio.Task] = None

        self.flows_completed_total: int = 0
        self.events_aggregated_total: int = 0

    @property
    def active_flow_count(self) -> int:
        return len(self._active_flows)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        self._running = True
        self._reaper_task = asyncio.create_task(self._timeout_reaper_loop(), name="flow-timeout-reaper")
        logger.info("flow_aggregator.started", timeout_seconds=self._timeout)

    async def stop(self) -> List[FlowRecord]:
        self._running = False
        if self._reaper_task is not None:
            self._reaper_task.cancel()
            try:
                await self._reaper_task
            except asyncio.CancelledError:
                pass
            self._reaper_task = None
        return await self.flush_all()

    # ------------------------------------------------------------------
    # Event ingestion
    # ------------------------------------------------------------------

    async def add_event(
        self,
        event: Union[EnrichedSecurityEvent, StandardSecurityEvent],
    ) -> Optional[FlowRecord]:
        """
        Incorporate a connection/network event into the active flow table.

        If the event carries TCP FIN or RST closure indicators, the flow is
        immediately closed, emitted to Redis 'flows:completed', and returned.
        """
        if not event.source_ip or not event.destination_ip:
            return None

        src_ip = event.source_ip
        dst_ip = event.destination_ip
        src_port = event.source_port if event.source_port is not None else 0
        dst_port = event.destination_port if event.destination_port is not None else 0
        proto = (event.protocol or "TCP").upper()

        key = make_canonical_flow_key(src_ip, dst_ip, src_port, dst_port, proto)
        ts = event.timestamp if event.timestamp.tzinfo else event.timestamp.replace(tzinfo=timezone.utc)
        ts_epoch = ts.timestamp()

        flow = self._active_flows.get(key)
        is_forward = True

        if flow is None:
            flow = _ActiveFlow(
                flow_id=event.flow_id or uuid.uuid4(),
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=proto,
                start_time=ts,
                last_seen=ts,
                sensor_id=event.sensor_id,
            )
            self._active_flows[key] = flow
            is_forward = True
        else:
            is_forward = (src_ip == flow.src_ip and src_port == flow.src_port)
            if ts < flow.start_time:
                flow.start_time = ts
            if ts > flow.last_seen:
                flow.last_seen = ts

        # Update bidirectional packet and byte counters
        evidence = event.evidence or {}
        orig_bytes = evidence.get("orig_bytes")
        resp_bytes = evidence.get("resp_bytes")
        orig_pkts = evidence.get("orig_pkts")
        resp_pkts = evidence.get("resp_pkts")

        if orig_bytes is not None or resp_bytes is not None:
            # Bidirectional summary event (e.g., Zeek conn.log)
            ob = max(0, int(orig_bytes or 0))
            rb = max(0, int(resp_bytes or 0))
            op = max(1 if ob > 0 else 0, int(orig_pkts or 0))
            rp = max(1 if rb > 0 else 0, int(resp_pkts or 0))
            if is_forward:
                flow.fwd_bytes += ob
                flow.bwd_bytes += rb
                flow.fwd_packets += op
                flow.bwd_packets += rp
            else:
                flow.bwd_bytes += ob
                flow.fwd_bytes += rb
                flow.bwd_packets += op
                flow.fwd_packets += rp
            if op > 0:
                flow.packet_lengths.append(int(ob / op))
            if rp > 0:
                flow.packet_lengths.append(int(rb / rp))
        else:
            ev_bytes = max(0, int(event.bytes_transferred or 0))
            ev_pkts = max(1, int(event.packets_transferred or 1))
            if is_forward:
                flow.fwd_bytes += ev_bytes
                flow.fwd_packets += ev_pkts
                flow.fwd_timestamps.append(ts_epoch)
            else:
                flow.bwd_bytes += ev_bytes
                flow.bwd_packets += ev_pkts
                flow.bwd_timestamps.append(ts_epoch)
            flow.packet_lengths.append(int(ev_bytes / ev_pkts) if ev_pkts > 0 else ev_bytes)

        flow.all_timestamps.append(ts_epoch)

        # Incorporate connection duration if reported on a single Zeek summary record
        if event.connection_duration and event.connection_duration > 0:
            est_end = datetime.fromtimestamp(
                flow.start_time.timestamp() + (event.connection_duration / 1000.0),
                tz=timezone.utc,
            )
            if est_end > flow.last_seen:
                flow.last_seen = est_end

        # Extract TCP flags from evidence (explicit flags or Zeek history string)
        close_reason = self._update_tcp_flags(flow, evidence)

        # Attach BECPL enrichment metadata if available
        self._merge_enrichment(flow, event)

        # Attach TLS metadata if present
        self._merge_tls_metadata(flow, event)

        self.events_aggregated_total += 1

        if close_reason is not None:
            return await self._close_flow(key, close_reason=close_reason)

        return None

    async def expire_timed_out_flows(self, now: Optional[datetime] = None) -> List[FlowRecord]:
        """Close and emit all active flows idle longer than ``flow_timeout_seconds``."""
        ref_now = now or datetime.now(timezone.utc)
        if ref_now.tzinfo is None:
            ref_now = ref_now.replace(tzinfo=timezone.utc)

        expired_keys = [
            key
            for key, fl in self._active_flows.items()
            if (ref_now - fl.last_seen).total_seconds() >= self._timeout
        ]

        completed: List[FlowRecord] = []
        for key in expired_keys:
            record = await self._close_flow(key, close_reason="timeout")
            if record is not None:
                completed.append(record)
        return completed

    async def flush_all(self) -> List[FlowRecord]:
        """Force-close and emit all currently active flows."""
        keys = list(self._active_flows.keys())
        completed: List[FlowRecord] = []
        for key in keys:
            record = await self._close_flow(key, close_reason="flush")
            if record is not None:
                completed.append(record)
        return completed

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    async def _timeout_reaper_loop(self) -> None:
        check_interval = max(1.0, min(5.0, self._timeout / 4.0))
        while self._running:
            try:
                await asyncio.sleep(check_interval)
                await self.expire_timed_out_flows()
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.warning("flow_aggregator.reaper_error", error=str(exc))

    async def _close_flow(self, key: CanonicalFlowKey, close_reason: str) -> Optional[FlowRecord]:
        flow = self._active_flows.pop(key, None)
        if flow is None:
            return None

        record = self._build_flow_record(flow, close_reason=close_reason)
        self.flows_completed_total += 1

        # Emit to Redis stream 'flows:completed'
        if self._redis is not None:
            try:
                await self._redis.xadd(
                    self._completed_stream,
                    {"payload": json.dumps(record.to_dict())},
                )
            except Exception as exc:
                logger.warning("flow_aggregator.emit_error", flow_id=str(record.flow_id), error=str(exc))

        if self._on_flow_completed is not None:
            res = self._on_flow_completed(record)
            if asyncio.iscoroutine(res):
                await res

        return record

    def _build_flow_record(self, flow: _ActiveFlow, close_reason: str) -> FlowRecord:
        duration_sec = max(0.0, (flow.last_seen - flow.start_time).total_seconds())
        duration_ms = duration_sec * 1000.0
        eff_duration = duration_sec if duration_sec > 0.0 else 1e-3  # avoid division by zero

        total_packets = flow.fwd_packets + flow.bwd_packets
        total_bytes = flow.fwd_bytes + flow.bwd_bytes

        flow_bytes_per_sec = total_bytes / eff_duration
        flow_packets_per_sec = total_packets / eff_duration
        fwd_pps = flow.fwd_packets / eff_duration
        bwd_pps = flow.bwd_packets / eff_duration

        upload_download_ratio = (
            flow.fwd_bytes / flow.bwd_bytes
            if flow.bwd_bytes > 0
            else float(flow.fwd_bytes)
        )
        down_up_ratio = (
            flow.bwd_bytes / flow.fwd_bytes
            if flow.fwd_bytes > 0
            else 0.0
        )

        fwd_iat_mean, _ = self._compute_iat_stats(flow.fwd_timestamps)
        bwd_iat_mean, _ = self._compute_iat_stats(flow.bwd_timestamps)
        all_iat_mean, all_iat_std = self._compute_iat_stats(flow.all_timestamps)

        pkt_mean, pkt_std, pkt_min, pkt_max = self._compute_length_stats(flow.packet_lengths)

        return FlowRecord(
            flow_id=flow.flow_id,
            src_ip=flow.src_ip,
            dst_ip=flow.dst_ip,
            src_port=flow.src_port,
            dst_port=flow.dst_port,
            protocol=flow.protocol,
            start_time=flow.start_time,
            end_time=flow.last_seen,
            duration_ms=duration_ms,
            initiating_direction="forward",
            fwd_packets=flow.fwd_packets,
            bwd_packets=flow.bwd_packets,
            fwd_bytes=flow.fwd_bytes,
            bwd_bytes=flow.bwd_bytes,
            total_packets=total_packets,
            total_bytes=total_bytes,
            flow_bytes_per_sec=round(flow_bytes_per_sec, 4),
            flow_packets_per_sec=round(flow_packets_per_sec, 4),
            fwd_packets_per_sec=round(fwd_pps, 4),
            bwd_packets_per_sec=round(bwd_pps, 4),
            upload_download_ratio=round(upload_download_ratio, 4),
            down_up_ratio=round(down_up_ratio, 4),
            fwd_iat_mean=round(fwd_iat_mean, 6),
            bwd_iat_mean=round(bwd_iat_mean, 6),
            inter_packet_interval_mean=round(all_iat_mean, 6),
            inter_packet_interval_std=round(all_iat_std, 6),
            psh_flag_count=flow.psh_flag_count,
            ack_flag_count=flow.ack_flag_count,
            syn_flag_count=flow.syn_flag_count,
            fin_flag_count=flow.fin_flag_count,
            rst_flag_count=flow.rst_flag_count,
            pkt_len_mean=round(pkt_mean, 4),
            pkt_len_std=round(pkt_std, 4),
            pkt_len_min=pkt_min,
            pkt_len_max=pkt_max,
            sensor_id=flow.sensor_id,
            source_asset_id=flow.source_asset_id,
            destination_asset_id=flow.destination_asset_id,
            source_zone=flow.source_zone,
            destination_zone=flow.destination_zone,
            source_vlan=flow.source_vlan,
            dest_vlan=flow.dest_vlan,
            source_criticality=flow.source_criticality,
            dest_criticality=flow.dest_criticality,
            is_cross_vlan=flow.is_cross_vlan,
            is_vendor_connection=flow.is_vendor_connection,
            is_ot_destination=flow.is_ot_destination,
            is_external_dest=flow.is_external_dest,
            tls_version=flow.tls_version,
            sni=flow.sni,
            cert_issuer=flow.cert_issuer,
            cert_issuer_known=flow.cert_issuer_known,
            ja3_hash=flow.ja3_hash,
            ja3s_hash=flow.ja3s_hash,
            close_reason=close_reason,
        )

    @staticmethod
    def _update_tcp_flags(flow: _ActiveFlow, evidence: Dict[str, Any]) -> Optional[str]:
        """Update TCP flag counters and return 'FIN' or 'RST' if the flow closed."""
        flags = evidence.get("tcp_flags") or ""
        if isinstance(flags, list):
            flags_str = ",".join(str(f).upper() for f in flags)
        else:
            flags_str = str(flags).upper()

        history = str(evidence.get("history") or "")
        conn_state = str(evidence.get("conn_state") or "").upper()

        if "SYN" in flags_str or "S" in history or "s" in history:
            flow.syn_flag_count += 1
        if "ACK" in flags_str or "A" in history or "a" in history:
            flow.ack_flag_count += 1
        if "PSH" in flags_str or "D" in history or "d" in history:
            flow.psh_flag_count += 1

        if "RST" in flags_str or "R" in history or "r" in history or conn_state in ("RSTO", "RSTR", "RSTOS0", "RSTRH", "REJ"):
            flow.rst_flag_count += 1
            return "RST"
        if "FIN" in flags_str or ("F" in history and "f" in history) or conn_state in ("SF", "SH", "SHR"):
            flow.fin_flag_count += 1
            return "FIN"
        if "FIN" in flags_str or "F" in history or "f" in history:
            flow.fin_flag_count += 1
            return "FIN"

        return None

    @staticmethod
    def _merge_enrichment(flow: _ActiveFlow, event: Union[EnrichedSecurityEvent, StandardSecurityEvent]) -> None:
        if isinstance(event, EnrichedSecurityEvent):
            flow.source_asset_id = flow.source_asset_id or event.source_asset_id
            flow.destination_asset_id = flow.destination_asset_id or event.destination_asset_id
            flow.source_zone = flow.source_zone or event.source_zone
            flow.destination_zone = flow.destination_zone or event.destination_zone
            flow.source_vlan = flow.source_vlan if flow.source_vlan is not None else event.source_vlan
            flow.dest_vlan = flow.dest_vlan if flow.dest_vlan is not None else event.destination_vlan
            flow.source_criticality = flow.source_criticality or event.source_criticality
            flow.dest_criticality = flow.dest_criticality or event.destination_criticality
            flow.is_cross_vlan = flow.is_cross_vlan or event.is_cross_vlan
            flags = set(event.risk_flags or [])
            if RiskFlag.VENDOR_CONNECTION.value in flags:
                flow.is_vendor_connection = True
            if RiskFlag.OT_DESTINATION.value in flags:
                flow.is_ot_destination = True
            if RiskFlag.EXTERNAL_DESTINATION.value in flags:
                flow.is_external_dest = True

    def _merge_tls_metadata(self, flow: _ActiveFlow, event: Union[EnrichedSecurityEvent, StandardSecurityEvent]) -> None:
        meta = event.encryption_metadata
        if meta is None:
            return
        flow.tls_version = flow.tls_version or meta.tls_version
        flow.sni = flow.sni or meta.sni
        flow.cert_issuer = flow.cert_issuer or meta.cert_issuer
        flow.ja3_hash = flow.ja3_hash or meta.ja3_hash
        flow.ja3s_hash = flow.ja3s_hash or meta.ja3s_hash
        if flow.cert_issuer and flow.cert_issuer_known is None:
            issuer_lower = flow.cert_issuer.lower()
            flow.cert_issuer_known = any(k in issuer_lower for k in self._KNOWN_CERT_ISSUERS)
        elif meta.cert_valid is not None and flow.cert_issuer_known is None:
            flow.cert_issuer_known = bool(meta.cert_valid)

    @staticmethod
    def _compute_iat_stats(timestamps: List[float]) -> Tuple[float, float]:
        if len(timestamps) < 2:
            return 0.0, 0.0
        ordered = sorted(timestamps)
        diffs = [max(0.0, ordered[i] - ordered[i - 1]) for i in range(1, len(ordered))]
        mean = sum(diffs) / len(diffs)
        variance = sum((d - mean) ** 2 for d in diffs) / len(diffs)
        return mean, math.sqrt(variance)

    @staticmethod
    def _compute_length_stats(lengths: List[int]) -> Tuple[float, float, int, int]:
        if not lengths:
            return 0.0, 0.0, 0, 0
        mean = sum(lengths) / len(lengths)
        variance = sum((x - mean) ** 2 for x in lengths) / len(lengths)
        return mean, math.sqrt(variance), min(lengths), max(lengths)

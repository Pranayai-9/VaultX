"""
VaultX NIDS - Phase 2 Ingestion & Processing Pydantic Models
Bharat Electronics Components Pvt. Ltd. (BECPL), Pune

Extends Phase 1 StandardSecurityEvent with enrichment fields, risk flags,
flow records, pipeline metrics, sensor health, and operational alerts.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from backend.ingestion.event_schema import StandardSecurityEvent


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class RiskFlag(str, Enum):
    CROSS_VLAN = "CROSS_VLAN"
    CRITICAL_ASSET_INVOLVED = "CRITICAL_ASSET_INVOLVED"
    OT_DESTINATION = "OT_DESTINATION"
    OT_SOURCE = "OT_SOURCE"
    VENDOR_CONNECTION = "VENDOR_CONNECTION"
    EXTERNAL_DESTINATION = "EXTERNAL_DESTINATION"
    SURICATA_ALERT = "SURICATA_ALERT"
    HIGH_VOLUME_FLOW = "HIGH_VOLUME_FLOW"
    ENCRYPTED_TRAFFIC = "ENCRYPTED_TRAFFIC"


class ProcessingPriority(str, Enum):
    NORMAL = "normal"
    SUSPICIOUS = "suspicious"
    HIGH_PRIORITY = "high_priority"


class SensorState(str, Enum):
    ONLINE = "ONLINE"
    DEGRADED = "DEGRADED"
    OFFLINE = "OFFLINE"
    UNKNOWN = "UNKNOWN"


class AlertSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# ---------------------------------------------------------------------------
# Asset Enrichment & EnrichedSecurityEvent
# ---------------------------------------------------------------------------

class AssetEnrichment(BaseModel):
    """Structured asset metadata resolved from PostgreSQL / Redis cache."""

    model_config = ConfigDict(extra="allow")

    asset_id: Optional[str] = None
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    vlan_id: Optional[int] = None
    zone: Optional[str] = None
    criticality: Optional[str] = None  # critical | high | medium | low
    device_type: Optional[str] = None
    owner_department: Optional[str] = None
    identity_classification: Optional[str] = None
    is_critical: bool = False
    is_ot: bool = False
    is_vendor: bool = False
    is_external: bool = False


class EnrichedSecurityEvent(StandardSecurityEvent):
    """
    Extends Phase 1 StandardSecurityEvent with asset/zone/criticality enrichment,
    risk flags, deduplication fingerprint, and routing metadata.
    """

    model_config = ConfigDict(extra="allow")

    # Source asset enrichment fields
    source_asset_id: Optional[str] = None
    source_zone: Optional[str] = None
    source_vlan: Optional[int] = None
    source_criticality: Optional[str] = None
    source_enrichment: Optional[AssetEnrichment] = None

    # Destination asset enrichment fields
    destination_asset_id: Optional[str] = None
    destination_zone: Optional[str] = None
    destination_vlan: Optional[int] = None
    destination_criticality: Optional[str] = None
    destination_enrichment: Optional[AssetEnrichment] = None

    # Flags & routing
    risk_flags: List[str] = Field(default_factory=list)
    is_cross_vlan: bool = False
    involves_critical_asset: bool = False
    processing_priority: ProcessingPriority = ProcessingPriority.NORMAL

    # Deduplication
    dedup_hash: Optional[str] = None

    # Enrichment metadata
    enriched_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    enrichment_version: str = "2.0.0"

    def to_dict(self) -> Dict[str, Any]:
        result = super().to_dict()
        result["enriched_at"] = self.enriched_at.isoformat()
        return result


# ---------------------------------------------------------------------------
# FlowRecord
# ---------------------------------------------------------------------------

class FlowRecord(BaseModel):
    """
    Aggregated bidirectional network flow record emitted by FlowAggregator
    when a flow closes (idle timeout or TCP FIN/RST).
    """

    model_config = ConfigDict(extra="allow")

    flow_id: uuid.UUID = Field(default_factory=uuid.uuid4)

    # 5-tuple (from initiating direction)
    src_ip: str
    dst_ip: str
    src_port: int = Field(ge=0, le=65535)
    dst_port: int = Field(ge=0, le=65535)
    protocol: str

    # Timing
    start_time: datetime
    end_time: datetime
    duration_ms: float = Field(default=0.0, ge=0.0)

    # Bidirectional counters (fwd = initiator -> responder, bwd = responder -> initiator)
    initiating_direction: str = Field(default="forward")
    fwd_packets: int = Field(default=0, ge=0)
    bwd_packets: int = Field(default=0, ge=0)
    fwd_bytes: int = Field(default=0, ge=0)
    bwd_bytes: int = Field(default=0, ge=0)
    total_packets: int = Field(default=0, ge=0)
    total_bytes: int = Field(default=0, ge=0)

    # Rates & ratios
    flow_bytes_per_sec: float = Field(default=0.0, ge=0.0)
    flow_packets_per_sec: float = Field(default=0.0, ge=0.0)
    fwd_packets_per_sec: float = Field(default=0.0, ge=0.0)
    bwd_packets_per_sec: float = Field(default=0.0, ge=0.0)
    upload_download_ratio: float = Field(default=0.0, ge=0.0)
    down_up_ratio: float = Field(default=0.0, ge=0.0)

    # Inter-arrival times (seconds)
    fwd_iat_mean: float = Field(default=0.0, ge=0.0)
    bwd_iat_mean: float = Field(default=0.0, ge=0.0)
    inter_packet_interval_mean: float = Field(default=0.0, ge=0.0)
    inter_packet_interval_std: float = Field(default=0.0, ge=0.0)

    # TCP flag counters
    psh_flag_count: int = Field(default=0, ge=0)
    ack_flag_count: int = Field(default=0, ge=0)
    syn_flag_count: int = Field(default=0, ge=0)
    fin_flag_count: int = Field(default=0, ge=0)
    rst_flag_count: int = Field(default=0, ge=0)

    # Packet length statistics (bytes)
    pkt_len_mean: float = Field(default=0.0, ge=0.0)
    pkt_len_std: float = Field(default=0.0, ge=0.0)
    pkt_len_min: int = Field(default=0, ge=0)
    pkt_len_max: int = Field(default=0, ge=0)

    # BECPL asset & zone context
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

    # Optional TLS metadata
    tls_version: Optional[str] = None
    sni: Optional[str] = None
    cert_issuer: Optional[str] = None
    cert_issuer_known: Optional[bool] = None
    ja3_hash: Optional[str] = None
    ja3s_hash: Optional[str] = None

    # Closure metadata
    close_reason: str = Field(default="timeout")  # timeout | FIN | RST | flush

    def to_dict(self) -> Dict[str, Any]:
        result = self.model_dump(mode="json")
        result["flow_id"] = str(self.flow_id)
        result["start_time"] = self.start_time.isoformat()
        result["end_time"] = self.end_time.isoformat()
        return result


# ---------------------------------------------------------------------------
# PipelineMetrics
# ---------------------------------------------------------------------------

class LatencyHistogram(BaseModel):
    p50_ms: float = 0.0
    p95_ms: float = 0.0
    p99_ms: float = 0.0
    mean_ms: float = 0.0
    max_ms: float = 0.0
    sample_count: int = 0


class StreamLagInfo(BaseModel):
    stream_name: str
    consumer_group: str
    stream_length: int = 0
    pending_count: int = 0
    lag: int = 0
    last_delivered_id: Optional[str] = None
    consumers_count: int = 0


class PipelineMetrics(BaseModel):
    """Ingestion pipeline performance and health counters."""

    snapshot_time: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    events_per_sec: float = 0.0
    events_ingested_total: int = 0
    events_persisted_total: int = 0
    events_dropped_total: int = 0
    duplicates_filtered_total: int = 0
    normalisation_errors_total: int = 0
    enrichment_errors_total: int = 0
    persistence_errors_total: int = 0
    error_rate: float = 0.0
    total_queue_depth: int = 0
    ml_queue_depth: int = 0
    backpressure_active: bool = False
    processing_latency: LatencyHistogram = Field(default_factory=LatencyHistogram)
    stream_lags: List[StreamLagInfo] = Field(default_factory=list)
    pipeline_version: str = "2.0.0"


# ---------------------------------------------------------------------------
# SensorHealthStatus
# ---------------------------------------------------------------------------

class SensorHealthStatus(BaseModel):
    """Per-sensor health and capture status."""

    sensor_id: str
    description: str = ""
    monitored_vlan: Optional[int] = None
    monitored_subnet: Optional[str] = None
    priority: str = "medium"
    state: SensorState = SensorState.UNKNOWN
    last_heartbeat: Optional[datetime] = None
    seconds_since_heartbeat: Optional[float] = None
    events_per_min: float = 0.0
    packet_drop_rate: float = 0.0
    zeek_status: str = "unknown"      # running | stopped | degraded | unknown
    suricata_status: str = "unknown"  # running | stopped | degraded | unknown
    is_offline: bool = False
    offline_alert_sent: bool = False


# ---------------------------------------------------------------------------
# BackpressureAlert
# ---------------------------------------------------------------------------

class BackpressureAlert(BaseModel):
    """Operational alert emitted to the 'alerts:operational' Redis Stream."""

    alert_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    alert_type: str  # BACKPRESSURE | CPU_HIGH | LATENCY_HIGH | SENSOR_OFFLINE | ML_BACKPRESSURE
    severity: AlertSeverity = AlertSeverity.HIGH
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source_component: str = "ingestion-pipeline"
    stream_name: Optional[str] = None
    metric_value: Optional[float] = None
    threshold: Optional[float] = None
    message: str = ""
    details: Dict[str, Any] = Field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        result = self.model_dump(mode="json")
        result["alert_id"] = str(self.alert_id)
        result["timestamp"] = self.timestamp.isoformat()
        return result

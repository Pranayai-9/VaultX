"""
VaultX NIDS - Standard Event Schema
Bharat Electronics Components Pvt. Ltd. (BECPL), Pune

Standardized security event schema across Zeek, Suricata, Sysmon, Auditd,
and network sensors for MSME manufacturing environments.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field, field_validator, model_validator


class PrincipalType(str, Enum):
    HUMAN_USER = "HUMAN_USER"
    SERVICE_ACCOUNT = "SERVICE_ACCOUNT"
    AUTOMATION_WORKLOAD = "AUTOMATION_WORKLOAD"
    AI_AGENT = "AI_AGENT"
    INDUSTRIAL_DEVICE = "INDUSTRIAL_DEVICE"
    THIRD_PARTY_IDENTITY = "THIRD_PARTY_IDENTITY"
    UNKNOWN_IDENTITY = "UNKNOWN_IDENTITY"


class EventType(str, Enum):
    NETWORK_FLOW = "network_flow"
    ALERT = "alert"
    AUTH_EVENT = "auth_event"
    ENDPOINT_EVENT = "endpoint_event"
    DNS_EVENT = "dns_event"
    HTTP_EVENT = "http_event"
    TLS_EVENT = "tls_event"
    SENSOR_HEALTH = "sensor_health"
    POLICY_VIOLATION = "policy_violation"
    MANUAL = "manual"


class DetectionSource(str, Enum):
    ZEEK = "zeek"
    SURICATA = "suricata"
    SYSMON = "sysmon"
    AUDITD = "auditd"
    WINDOWS_EVENT = "windows_event"
    NETFLOW = "netflow"
    SNMP = "snmp"
    MANUAL = "manual"
    SYNTHETIC = "synthetic"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class ProcessingStatus(str, Enum):
    PENDING = "pending"
    VALIDATED = "validated"
    ENRICHED = "enriched"
    ALERTED = "alerted"
    ARCHIVED = "archived"
    ERROR = "error"


class EncryptionMetadata(BaseModel):
    """TLS / Cryptographic metadata extracted from network connections."""
    tls_version: Optional[str] = None
    cipher_suite: Optional[str] = None
    sni: Optional[str] = None
    cert_issuer: Optional[str] = None
    cert_subject: Optional[str] = None
    cert_valid: Optional[bool] = None
    ja3_hash: Optional[str] = None
    ja3s_hash: Optional[str] = None

    class Config:
        extra = "allow"


class EventProvenance(BaseModel):
    """Full data lineage and origin traceability."""
    source_system: str = Field(..., description="Sensor or collector node name")
    collection_method: str = Field(..., description="SPAN, TAP, agent, syslog, file_beat")
    raw_log_reference: Optional[str] = Field(None, description="Original log identifier or file path")
    pipeline_version: str = Field(default="1.0.0", description="Ingestion pipeline release tag")
    captured_at: Optional[datetime] = None

    class Config:
        extra = "allow"


class StandardSecurityEvent(BaseModel):
    """
    Standard Security Event schema encompassing all fields from the VaultX project brief:
    - event_id, timestamp, sensor_id
    - source_ip, destination_ip, source_port, destination_port, protocol
    - network_zone, source_asset, destination_asset
    - identity_id, principal_type, application
    - flow_id, connection_duration, bytes_transferred, packets_transferred
    - encryption_metadata (TLS version, cipher, SNI)
    - event_type, detection_source, severity, confidence, evidence
    - processing_status
    - event_provenance (source_system, collection_method, raw_log_reference)
    - sensor_identifier, model_version, detection_rule_version
    - incident_association, response_action_identifier
    """

    # Identifiers & Temporal
    event_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    sensor_id: str = Field(..., description="Unique sensor host identifier (e.g., SEC-SENSOR-01)")
    sensor_identifier: Optional[str] = None

    # Network Tuples
    source_ip: Optional[str] = Field(None, description="IPv4 or IPv6 source address")
    destination_ip: Optional[str] = Field(None, description="IPv4 or IPv6 destination address")
    source_port: Optional[int] = Field(None, ge=0, le=65535)
    destination_port: Optional[int] = Field(None, ge=0, le=65535)
    protocol: Optional[str] = Field(None, description="TCP, UDP, ICMP, MODBUS, S7COMM, etc.")

    # Zone & Asset Attribution
    network_zone: Optional[str] = Field(None, description="Derived or labeled network zone name")
    source_asset: Optional[str] = Field(None, description="Source asset ID (e.g. CORP-WS-101)")
    destination_asset: Optional[str] = Field(None, description="Destination asset ID (e.g. OT-SMT-PLC01)")

    # Identity Classification
    identity_id: Optional[uuid.UUID] = None
    principal_type: PrincipalType = Field(default=PrincipalType.UNKNOWN_IDENTITY)
    application: Optional[str] = Field(None, description="Identified application or service")

    # Flow Telemetry
    flow_id: Optional[uuid.UUID] = Field(default_factory=uuid.uuid4)
    connection_duration: Optional[int] = Field(None, description="Connection duration in milliseconds")
    bytes_transferred: Optional[int] = Field(None, ge=0, description="Total bytes exchanged")
    packets_transferred: Optional[int] = Field(None, ge=0, description="Total packet count")

    # Cryptographic Attributes
    encryption_metadata: Optional[EncryptionMetadata] = None

    # Detection & Triage
    event_type: EventType = Field(default=EventType.NETWORK_FLOW)
    detection_source: DetectionSource = Field(default=DetectionSource.ZEEK)
    severity: Severity = Field(default=Severity.INFORMATIONAL)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Confidence score [0.0 - 1.0]")
    evidence: Dict[str, Any] = Field(default_factory=dict, description="Raw signatures, payloads, alert details")

    # Lifecycle & Provenance
    processing_status: ProcessingStatus = Field(default=ProcessingStatus.PENDING)
    event_provenance: Optional[EventProvenance] = None
    model_version: Optional[str] = Field(None, description="Version of ML model that scored this event")
    detection_rule_version: Optional[str] = Field(None, description="Version of rule set or Sigma rule")

    # Incident Linkage
    incident_association: Optional[uuid.UUID] = Field(None, description="Linked incident ID")
    response_action_identifier: Optional[uuid.UUID] = Field(None, description="Linked response action ID")

    # Validators
    @field_validator("source_ip", "destination_ip", mode="before")
    def validate_ip(cls, v: Any) -> Optional[str]:
        if v is None or v == "" or v == "-":
            return None
        # Handle string or IPAddress object
        if isinstance(v, (IPv4Address, IPv6Address)):
            return str(v)
        try:
            parsed = ip_address(str(v).strip())
            return str(parsed)
        except ValueError:
            # Allow unresolved hostnames or special values if needed, otherwise return None
            return str(v).strip()

    @field_validator("protocol", mode="before")
    def normalize_protocol(cls, v: Any) -> Optional[str]:
        if v is None:
            return None
        return str(v).strip().upper()

    @field_validator("timestamp", mode="before")
    def parse_timestamp(cls, v: Any) -> datetime:
        if isinstance(v, datetime):
            if v.tzinfo is None:
                return v.replace(tzinfo=timezone.utc)
            return v
        if isinstance(v, (int, float)):
            # Epoch timestamp (support seconds and milliseconds)
            if v > 1e11:  # likely millisecond
                v = v / 1000.0
            return datetime.fromtimestamp(v, tz=timezone.utc)
        if isinstance(v, str):
            # Parse ISO-8601 or common formats
            try:
                from dateutil import parser
                parsed = parser.parse(v)
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                return parsed
            except Exception:
                pass
        return datetime.now(timezone.utc)

    @model_validator(mode="after")
    def align_sensor_identifier(self) -> StandardSecurityEvent:
        if not self.sensor_identifier and self.sensor_id:
            self.sensor_identifier = self.sensor_id
        elif not self.sensor_id and self.sensor_identifier:
            self.sensor_id = self.sensor_identifier
        return self

    def to_dict(self) -> Dict[str, Any]:
        """Convert to a JSON-serializable dictionary with ISO timestamps and UUID strings."""
        result = self.model_dump(mode="json")
        # Ensure UUIDs and Datetimes are strings
        result["event_id"] = str(self.event_id)
        result["timestamp"] = self.timestamp.isoformat()
        if self.flow_id:
            result["flow_id"] = str(self.flow_id)
        if self.identity_id:
            result["identity_id"] = str(self.identity_id)
        if self.incident_association:
            result["incident_association"] = str(self.incident_association)
        if self.response_action_identifier:
            result["response_action_identifier"] = str(self.response_action_identifier)
        return result


class NetworkFlowRecord(BaseModel):
    """Direct mapping to network_flows database table."""
    flow_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    sensor_id: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    duration_ms: Optional[int] = 0
    orig_bytes: Optional[int] = 0
    resp_bytes: Optional[int] = 0
    orig_packets: Optional[int] = 0
    resp_packets: Optional[int] = 0
    conn_state: Optional[str] = None
    missed_bytes: Optional[int] = 0
    history: Optional[str] = None
    source_asset_id: Optional[str] = None
    destination_asset_id: Optional[str] = None
    source_zone: Optional[str] = None
    destination_zone: Optional[str] = None
    tls_version: Optional[str] = None
    tls_cipher: Optional[str] = None
    tls_server_name: Optional[str] = None
    dns_query: Optional[str] = None
    http_method: Optional[str] = None
    http_host: Optional[str] = None
    http_uri: Optional[str] = None
    http_status: Optional[int] = None
    detection_flags: List[str] = Field(default_factory=list)
    zeek_uid: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        result = self.model_dump(mode="json")
        result["flow_id"] = str(self.flow_id)
        result["timestamp"] = self.timestamp.isoformat()
        return result

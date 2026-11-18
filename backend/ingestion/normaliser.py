"""
VaultX NIDS - Event Normalisation Service
Bharat Electronics Components Pvt. Ltd. (BECPL), Pune

Accepts raw events from Zeek, Suricata, Sysmon, auditd, VPN, Cloud, API GW,
and generic sources, normalising them into StandardSecurityEvent with full
event provenance and Redis-backed 5-minute deduplication.
"""
from __future__ import annotations

import hashlib
import json
import re
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Union
from xml.etree import ElementTree as ET

import structlog

from backend.ingestion.dedup_cache import DedupCache
from backend.ingestion.event_schema import (
    DetectionSource,
    EncryptionMetadata,
    EventProvenance,
    EventType,
    PrincipalType,
    ProcessingStatus,
    Severity,
    StandardSecurityEvent,
)

logger = structlog.get_logger(__name__)

# Alias matching brief terminology
SecurityEvent = StandardSecurityEvent


class NormalisationError(Exception):
    """Raised when a raw event cannot be parsed or mapped to StandardSecurityEvent."""

    def __init__(self, message: str, source: str = "unknown", raw_event: Any = None) -> None:
        super().__init__(message)
        self.source = source
        self.raw_event = raw_event


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _parse_timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        ts_val = float(value)
        if ts_val > 1e11:
            ts_val /= 1000.0
        return datetime.fromtimestamp(ts_val, tz=timezone.utc)
    if isinstance(value, str) and value.strip() and value.strip() != "-":
        raw = value.strip()
        try:
            num = float(raw)
            if num > 1e11:
                num /= 1000.0
            return datetime.fromtimestamp(num, tz=timezone.utc)
        except ValueError:
            pass
        try:
            from dateutil import parser as dateutil_parser
            parsed = dateutil_parser.parse(raw)
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except Exception:
            pass
    return datetime.now(timezone.utc)


def _safe_int(value: Any, default: Optional[int] = None) -> Optional[int]:
    if value is None or value == "" or value == "-":
        return default
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


def _safe_float(value: Any, default: Optional[float] = None) -> Optional[float]:
    if value is None or value == "" or value == "-":
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _clean_str(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return None if text in ("", "-", "(empty)") else text


# ---------------------------------------------------------------------------
# Abstract Base Normaliser
# ---------------------------------------------------------------------------

class BaseNormaliser(ABC):
    """Abstract base class for all VaultX source-specific normalisers."""

    source_name: str = "generic"
    default_collection_method: str = "agent"

    @abstractmethod
    def can_handle(self, raw: Union[Dict[str, Any], str]) -> bool:
        """Return True if this normaliser recognises the raw event payload."""

    @abstractmethod
    def normalise(self, raw: Union[Dict[str, Any], str], sensor_id: str = "UNKNOWN-SENSOR") -> StandardSecurityEvent:
        """Transform raw payload into a validated StandardSecurityEvent."""

    def _build_provenance(
        self,
        sensor_id: str,
        collection_method: Optional[str] = None,
        raw_log_reference: Optional[str] = None,
    ) -> EventProvenance:
        return EventProvenance(
            source_system=self.source_name,
            collection_method=collection_method or self.default_collection_method,
            raw_log_reference=raw_log_reference,
            sensor_id=sensor_id,
            pipeline_version="2.0.0",
            captured_at=datetime.now(timezone.utc),
        )


# ---------------------------------------------------------------------------
# 1. Zeek Normaliser (conn.log / ssl.log / dns.log / http.log - JSON or TSV)
# ---------------------------------------------------------------------------

class ZeekNormaliser(BaseNormaliser):
    source_name = "zeek"
    default_collection_method = "SPAN"

    _CONN_TSV_FIELDS = [
        "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
        "proto", "service", "duration", "orig_bytes", "resp_bytes",
        "conn_state", "local_orig", "local_resp", "missed_bytes",
        "history", "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes",
    ]

    def can_handle(self, raw: Union[Dict[str, Any], str]) -> bool:
        if isinstance(raw, str):
            text = raw.strip()
            if text.startswith("{"):
                try:
                    data = json.loads(text)
                    return self.can_handle(data)
                except json.JSONDecodeError:
                    return False
            parts = text.split("\t")
            return len(parts) >= 12 and not text.startswith("#")
        if isinstance(raw, dict):
            src = str(raw.get("source") or raw.get("_source") or raw.get("detection_source") or "").lower()
            if src == "zeek":
                return True
            return any(k in raw for k in ("id.orig_h", "orig_bytes", "conn_state", "zeek_uid"))
        return False

    def normalise(self, raw: Union[Dict[str, Any], str], sensor_id: str = "SENSOR-ZEEK") -> StandardSecurityEvent:
        try:
            data = self._coerce_dict(raw)
            sid = _clean_str(data.get("sensor_id")) or sensor_id
            ts = _parse_timestamp(data.get("ts") or data.get("timestamp"))

            src_ip = _clean_str(data.get("id.orig_h") or data.get("src_ip") or data.get("source_ip"))
            dst_ip = _clean_str(data.get("id.resp_h") or data.get("dst_ip") or data.get("destination_ip"))
            if not src_ip and not dst_ip:
                raise NormalisationError("Zeek event missing source and destination IP", self.source_name, raw)

            src_port = _safe_int(data.get("id.orig_p") or data.get("src_port") or data.get("source_port"))
            dst_port = _safe_int(data.get("id.resp_p") or data.get("dst_port") or data.get("destination_port"))
            proto = _clean_str(data.get("proto") or data.get("protocol"))

            duration_s = _safe_float(data.get("duration"))
            duration_ms = int(duration_s * 1000) if duration_s is not None and duration_s >= 0 else None

            orig_bytes = _safe_int(data.get("orig_bytes"), 0) or 0
            resp_bytes = _safe_int(data.get("resp_bytes"), 0) or 0
            orig_pkts = _safe_int(data.get("orig_pkts"), 0) or 0
            resp_pkts = _safe_int(data.get("resp_pkts"), 0) or 0

            log_type = str(data.get("_path") or data.get("log_type") or "conn").lower()
            event_type = EventType.NETWORK_FLOW
            if "dns" in log_type or "query" in data:
                event_type = EventType.DNS_EVENT
            elif "http" in log_type or "uri" in data:
                event_type = EventType.HTTP_EVENT
            elif "ssl" in log_type or "tls" in log_type or "ja3" in data:
                event_type = EventType.TLS_EVENT

            enc_meta: Optional[EncryptionMetadata] = None
            if any(k in data for k in ("version", "cipher", "server_name", "ja3", "ja3s", "sni")):
                enc_meta = EncryptionMetadata(
                    tls_version=_clean_str(data.get("version") or data.get("tls_version")),
                    cipher_suite=_clean_str(data.get("cipher") or data.get("cipher_suite")),
                    sni=_clean_str(data.get("server_name") or data.get("sni")),
                    cert_issuer=_clean_str(data.get("issuer") or data.get("cert_issuer")),
                    cert_subject=_clean_str(data.get("subject") or data.get("cert_subject")),
                    ja3_hash=_clean_str(data.get("ja3") or data.get("ja3_hash")),
                    ja3s_hash=_clean_str(data.get("ja3s") or data.get("ja3s_hash")),
                )

            conn_state = _clean_str(data.get("conn_state"))
            severity = Severity.LOW if conn_state in ("REJ", "RSTO", "RSTR", "S0") else Severity.INFORMATIONAL

            zeek_uid = _clean_str(data.get("uid") or data.get("zeek_uid"))
            identity_hint = _clean_str(data.get("username") or data.get("principal_name"))
            evidence: Dict[str, Any] = {
                "zeek_uid": zeek_uid,
                "conn_state": conn_state,
                "history": _clean_str(data.get("history")),
                "service": _clean_str(data.get("service")),
                "orig_bytes": orig_bytes,
                "resp_bytes": resp_bytes,
                "orig_pkts": orig_pkts,
                "resp_pkts": resp_pkts,
                "missed_bytes": _safe_int(data.get("missed_bytes"), 0),
                "raw_log": data,
            }
            if identity_hint:
                evidence["principal_name"] = identity_hint

            return StandardSecurityEvent(
                sensor_id=sid,
                timestamp=ts,
                source_ip=src_ip,
                destination_ip=dst_ip,
                source_port=src_port,
                destination_port=dst_port,
                protocol=proto,
                application=_clean_str(data.get("service")),
                connection_duration=duration_ms,
                bytes_transferred=orig_bytes + resp_bytes,
                packets_transferred=orig_pkts + resp_pkts,
                encryption_metadata=enc_meta,
                event_type=event_type,
                detection_source=DetectionSource.ZEEK,
                severity=severity,
                principal_type=PrincipalType.UNKNOWN_IDENTITY,
                evidence=evidence,
                processing_status=ProcessingStatus.VALIDATED,
                event_provenance=self._build_provenance(
                    sensor_id=sid,
                    collection_method="SPAN",
                    raw_log_reference=zeek_uid or f"zeek:{log_type}.log",
                ),
            )
        except NormalisationError:
            raise
        except Exception as exc:
            raise NormalisationError(f"Failed to normalise Zeek event: {exc}", self.source_name, raw) from exc

    def _coerce_dict(self, raw: Union[Dict[str, Any], str]) -> Dict[str, Any]:
        if isinstance(raw, dict):
            return raw
        text = raw.strip()
        if text.startswith("{"):
            return json.loads(text)
        parts = text.split("\t")
        if len(parts) < 6:
            raise NormalisationError("Malformed Zeek TSV line", self.source_name, raw)
        return {
            field: parts[idx]
            for idx, field in enumerate(self._CONN_TSV_FIELDS)
            if idx < len(parts)
        }


# ---------------------------------------------------------------------------
# 2. Suricata Normaliser (EVE JSON alerts & flows)
# ---------------------------------------------------------------------------

class SuricataNormaliser(BaseNormaliser):
    source_name = "suricata"
    default_collection_method = "SPAN"

    _SEV_MAP = {
        1: Severity.CRITICAL,
        2: Severity.HIGH,
        3: Severity.MEDIUM,
        4: Severity.LOW,
    }

    def can_handle(self, raw: Union[Dict[str, Any], str]) -> bool:
        if isinstance(raw, str):
            text = raw.strip()
            if not text.startswith("{"):
                return False
            try:
                raw = json.loads(text)
            except json.JSONDecodeError:
                return False
        if isinstance(raw, dict):
            src = str(raw.get("source") or raw.get("_source") or raw.get("detection_source") or "").lower()
            if src == "suricata":
                return True
            return "alert" in raw or (raw.get("event_type") == "alert" and "dest_ip" in raw)
        return False

    def normalise(self, raw: Union[Dict[str, Any], str], sensor_id: str = "SENSOR-SURICATA") -> StandardSecurityEvent:
        try:
            data = json.loads(raw) if isinstance(raw, str) else raw
            if not isinstance(data, dict):
                raise NormalisationError("Suricata payload must be JSON object", self.source_name, raw)

            sid = _clean_str(data.get("sensor_id") or data.get("host")) or sensor_id
            ts = _parse_timestamp(data.get("timestamp"))
            alert = data.get("alert") or {}

            src_ip = _clean_str(data.get("src_ip") or data.get("source_ip"))
            dst_ip = _clean_str(data.get("dest_ip") or data.get("dst_ip") or data.get("destination_ip"))
            if not src_ip and not dst_ip:
                raise NormalisationError("Suricata event missing IP addresses", self.source_name, raw)

            suri_sev = _safe_int(alert.get("severity"), 3) or 3
            severity = self._SEV_MAP.get(suri_sev, Severity.MEDIUM)

            sig_id = alert.get("signature_id")
            signature = _clean_str(alert.get("signature"))
            category = _clean_str(alert.get("category"))
            app_proto = _clean_str(data.get("app_proto"))

            tls = data.get("tls")
            enc_meta: Optional[EncryptionMetadata] = None
            if isinstance(tls, dict):
                enc_meta = EncryptionMetadata(
                    tls_version=_clean_str(tls.get("version")),
                    sni=_clean_str(tls.get("sni")),
                    cert_issuer=_clean_str(tls.get("issuerdn")),
                    cert_subject=_clean_str(tls.get("subject")),
                    ja3_hash=_clean_str((tls.get("ja3") or {}).get("hash") if isinstance(tls.get("ja3"), dict) else tls.get("ja3")),
                    ja3s_hash=_clean_str((tls.get("ja3s") or {}).get("hash") if isinstance(tls.get("ja3s"), dict) else tls.get("ja3s")),
                )

            flow = data.get("flow") or {}
            bytes_total = (_safe_int(flow.get("bytes_toserver"), 0) or 0) + (_safe_int(flow.get("bytes_toclient"), 0) or 0)
            pkts_total = (_safe_int(flow.get("pkts_toserver"), 0) or 0) + (_safe_int(flow.get("pkts_toclient"), 0) or 0)

            evidence = {
                "signature_id": sig_id,
                "signature": signature,
                "category": category,
                "action": _clean_str(alert.get("action")),
                "rev": alert.get("rev"),
                "suricata_flow_id": data.get("flow_id"),
                "in_iface": data.get("in_iface"),
                "metadata": alert.get("metadata", {}),
                "raw_log": data,
            }

            return StandardSecurityEvent(
                sensor_id=sid,
                timestamp=ts,
                source_ip=src_ip,
                destination_ip=dst_ip,
                source_port=_safe_int(data.get("src_port")),
                destination_port=_safe_int(data.get("dest_port") or data.get("dst_port")),
                protocol=_clean_str(data.get("proto") or data.get("protocol")),
                application=app_proto,
                bytes_transferred=bytes_total or None,
                packets_transferred=pkts_total or None,
                encryption_metadata=enc_meta,
                event_type=EventType.ALERT if alert or data.get("event_type") == "alert" else EventType.NETWORK_FLOW,
                detection_source=DetectionSource.SURICATA,
                severity=severity,
                confidence=0.9,
                detection_rule_version=f"sid:{sig_id}:rev:{alert.get('rev', 1)}" if sig_id else None,
                principal_type=PrincipalType.UNKNOWN_IDENTITY,
                evidence=evidence,
                processing_status=ProcessingStatus.VALIDATED,
                event_provenance=self._build_provenance(
                    sensor_id=sid,
                    collection_method="SPAN",
                    raw_log_reference=f"suricata:eve:flow:{data.get('flow_id', 'unknown')}",
                ),
            )
        except NormalisationError:
            raise
        except Exception as exc:
            raise NormalisationError(f"Failed to normalise Suricata event: {exc}", self.source_name, raw) from exc


# ---------------------------------------------------------------------------
# 3. Sysmon Normaliser (Windows Event XML or parsed dict)
# ---------------------------------------------------------------------------

class SysmonNormaliser(BaseNormaliser):
    source_name = "sysmon"
    default_collection_method = "endpoint_agent"

    def can_handle(self, raw: Union[Dict[str, Any], str]) -> bool:
        if isinstance(raw, str):
            text = raw.strip()
            return "<Event" in text and ("Sysmon" in text or "<EventData>" in text)
        if isinstance(raw, dict):
            src = str(raw.get("source") or raw.get("_source") or raw.get("detection_source") or "").lower()
            if src == "sysmon":
                return True
            if "_xml" in raw or "xml" in raw:
                return True
            return "EventID" in raw or "Microsoft-Windows-Sysmon" in str(raw.get("Channel", ""))
        return False

    def normalise(self, raw: Union[Dict[str, Any], str], sensor_id: str = "ENDPOINT-SYSMON") -> StandardSecurityEvent:
        try:
            if isinstance(raw, str):
                event_id, computer, ts, data = self._parse_xml(raw)
                raw_ref = f"sysmon:xml:eventid:{event_id}"
            elif isinstance(raw, dict) and ("_xml" in raw or "xml" in raw):
                xml_payload = raw.get("_xml") or raw.get("xml")
                event_id, computer, ts, data = self._parse_xml(str(xml_payload))
                raw_ref = f"sysmon:xml:eventid:{event_id}"
                computer = _clean_str(raw.get("sensor_id")) or computer
            elif isinstance(raw, dict):
                event_id = _safe_int(raw.get("EventID") or raw.get("event_id"), 0) or 0
                computer = _clean_str(raw.get("Computer") or raw.get("sensor_id")) or sensor_id
                ts = _parse_timestamp(raw.get("TimeCreated") or raw.get("UtcTime") or raw.get("timestamp"))
                data = raw.get("EventData") if isinstance(raw.get("EventData"), dict) else raw
                raw_ref = f"sysmon:dict:eventid:{event_id}"
            else:
                raise NormalisationError("Unsupported Sysmon payload type", self.source_name, raw)

            sid = computer or sensor_id
            user = _clean_str(data.get("User"))
            event_type = EventType.NETWORK_FLOW if event_id == 3 else EventType.ENDPOINT_EVENT
            if event_id == 22:
                event_type = EventType.DNS_EVENT

            src_ip = _clean_str(data.get("SourceIp") or data.get("src_ip"))
            dst_ip = _clean_str(data.get("DestinationIp") or data.get("dst_ip"))
            src_port = _safe_int(data.get("SourcePort") or data.get("src_port"))
            dst_port = _safe_int(data.get("DestinationPort") or data.get("dst_port"))
            proto = _clean_str(data.get("Protocol") or data.get("protocol"))

            evidence: Dict[str, Any] = {
                "event_id": event_id,
                "computer": computer,
                "image": _clean_str(data.get("Image")),
                "command_line": _clean_str(data.get("CommandLine")),
                "parent_image": _clean_str(data.get("ParentImage")),
                "process_id": _safe_int(data.get("ProcessId")),
                "user": user,
                "hashes": _clean_str(data.get("Hashes")),
                "raw_event_data": data,
            }
            if user:
                evidence["principal_name"] = user

            return StandardSecurityEvent(
                sensor_id=sid,
                timestamp=ts,
                source_ip=src_ip,
                destination_ip=dst_ip,
                source_port=src_port,
                destination_port=dst_port,
                protocol=proto,
                application=_clean_str(data.get("Image")),
                event_type=event_type,
                detection_source=DetectionSource.SYSMON,
                severity=Severity.INFORMATIONAL,
                principal_type=PrincipalType.UNKNOWN_IDENTITY,
                evidence=evidence,
                processing_status=ProcessingStatus.VALIDATED,
                event_provenance=self._build_provenance(
                    sensor_id=sid,
                    collection_method="endpoint_agent",
                    raw_log_reference=raw_ref,
                ),
            )
        except NormalisationError:
            raise
        except Exception as exc:
            raise NormalisationError(f"Failed to normalise Sysmon event: {exc}", self.source_name, raw) from exc

    @staticmethod
    def _parse_xml(xml_str: str) -> Tuple[int, str, datetime, Dict[str, Any]]:
        root = ET.fromstring(xml_str.strip())

        def _strip_ns(tag: str) -> str:
            return tag.split("}", 1)[-1] if "}" in tag else tag

        system_el = None
        event_data_el = None
        for child in root:
            local = _strip_ns(child.tag)
            if local == "System":
                system_el = child
            elif local == "EventData":
                event_data_el = child

        event_id = 0
        computer = "ENDPOINT-SYSMON"
        ts = datetime.now(timezone.utc)

        if system_el is not None:
            for item in system_el:
                local = _strip_ns(item.tag)
                if local == "EventID" and item.text:
                    event_id = int(item.text.strip())
                elif local == "Computer" and item.text:
                    computer = item.text.strip()
                elif local == "TimeCreated":
                    sys_time = item.attrib.get("SystemTime")
                    if sys_time:
                        ts = _parse_timestamp(sys_time)

        data: Dict[str, Any] = {}
        if event_data_el is not None:
            for item in event_data_el:
                name = item.attrib.get("Name")
                if name:
                    data[name] = item.text or ""

        if "UtcTime" in data and system_el is None:
            ts = _parse_timestamp(data["UtcTime"])

        return event_id, computer, ts, data


# ---------------------------------------------------------------------------
# 4. Auditd Normaliser (Linux auditd log line or dict)
# ---------------------------------------------------------------------------

class AuditdNormaliser(BaseNormaliser):
    source_name = "auditd"
    default_collection_method = "endpoint_agent"

    _KV_RE = re.compile(r'(\w+)=(?:"([^"]*)"|\'([^\']*)\'|(\S+))')
    _AUDIT_MSG_TS_RE = re.compile(r"audit\((\d+(?:\.\d+)?):(\d+)\)")

    def can_handle(self, raw: Union[Dict[str, Any], str]) -> bool:
        if isinstance(raw, str):
            return "type=" in raw and "msg=audit(" in raw
        if isinstance(raw, dict):
            src = str(raw.get("source") or raw.get("_source") or raw.get("detection_source") or "").lower()
            if src == "auditd":
                return True
            line = str(raw.get("_line") or raw.get("raw_line") or "")
            return "type=" in line and "msg=audit(" in line
        return False

    def normalise(self, raw: Union[Dict[str, Any], str], sensor_id: str = "ENDPOINT-AUDITD") -> StandardSecurityEvent:
        try:
            if isinstance(raw, str):
                fields = self._parse_line(raw)
                sid = sensor_id
                raw_line = raw
            elif isinstance(raw, dict):
                raw_line = raw.get("_line") or raw.get("raw_line")
                fields = self._parse_line(str(raw_line)) if raw_line else dict(raw)
                sid = _clean_str(raw.get("sensor_id") or fields.get("node")) or sensor_id
            else:
                raise NormalisationError("Unsupported auditd payload", self.source_name, raw)

            audit_type = _clean_str(fields.get("type"))
            if not audit_type:
                raise NormalisationError("Auditd record missing type= field", self.source_name, raw)

            msg_str = str(fields.get("msg") or "")
            ts, serial = self._extract_audit_ts(msg_str, fields.get("timestamp"))

            is_auth = audit_type.upper() in {
                "USER_AUTH", "USER_LOGIN", "USER_LOGOUT", "USER_ACCT",
                "CRED_ACQ", "CRED_DISP", "USER_START", "USER_END",
            }
            event_type = EventType.AUTH_EVENT if is_auth else EventType.ENDPOINT_EVENT

            acct = _clean_str(fields.get("acct"))
            auid = _clean_str(fields.get("auid"))
            uid = _clean_str(fields.get("uid"))
            principal_hint = acct or (auid if auid not in ("-1", "4294967295", "unset") else None) or uid

            src_ip = _clean_str(fields.get("addr") or fields.get("src_ip"))
            if src_ip == "?":
                src_ip = None

            res = str(fields.get("res") or fields.get("success") or "").lower()
            severity = Severity.MEDIUM if res in ("failed", "no") and is_auth else Severity.INFORMATIONAL

            evidence: Dict[str, Any] = {
                "audit_type": audit_type,
                "audit_serial": serial,
                "syscall": fields.get("syscall"),
                "exe": _clean_str(fields.get("exe")),
                "comm": _clean_str(fields.get("comm")),
                "pid": _safe_int(fields.get("pid")),
                "ppid": _safe_int(fields.get("ppid")),
                "uid": uid,
                "auid": auid,
                "acct": acct,
                "key": _clean_str(fields.get("key")),
                "result": res or None,
                "raw_line": raw_line,
            }
            if principal_hint:
                evidence["principal_name"] = principal_hint

            return StandardSecurityEvent(
                sensor_id=sid,
                timestamp=ts,
                source_ip=src_ip,
                application=_clean_str(fields.get("comm") or fields.get("exe")),
                event_type=event_type,
                detection_source=DetectionSource.AUDITD,
                severity=severity,
                principal_type=PrincipalType.UNKNOWN_IDENTITY,
                evidence=evidence,
                processing_status=ProcessingStatus.VALIDATED,
                event_provenance=self._build_provenance(
                    sensor_id=sid,
                    collection_method="endpoint_agent",
                    raw_log_reference=f"auditd:{serial}" if serial else "auditd:log",
                ),
            )
        except NormalisationError:
            raise
        except Exception as exc:
            raise NormalisationError(f"Failed to normalise auditd event: {exc}", self.source_name, raw) from exc

    def _parse_line(self, line: str) -> Dict[str, str]:
        parsed: Dict[str, str] = {}
        # Expand nested msg='...' inner key-values as well
        for match in self._KV_RE.finditer(line):
            key = match.group(1)
            val = match.group(2) if match.group(2) is not None else (
                match.group(3) if match.group(3) is not None else match.group(4)
            )
            parsed[key] = val
            if key == "msg" and "'" in line:
                for inner in self._KV_RE.finditer(val):
                    ik = inner.group(1)
                    iv = inner.group(2) if inner.group(2) is not None else (
                        inner.group(3) if inner.group(3) is not None else inner.group(4)
                    )
                    parsed.setdefault(ik, iv)
        return parsed

    def _extract_audit_ts(self, msg_str: str, fallback_ts: Any) -> Tuple[datetime, Optional[str]]:
        match = self._AUDIT_MSG_TS_RE.search(msg_str)
        if match:
            epoch = float(match.group(1))
            return datetime.fromtimestamp(epoch, tz=timezone.utc), match.group(2)
        return _parse_timestamp(fallback_ts), None


# ---------------------------------------------------------------------------
# 5. VPN Normaliser
# ---------------------------------------------------------------------------

class VPNNormaliser(BaseNormaliser):
    source_name = "vpn"
    default_collection_method = "syslog"

    def can_handle(self, raw: Union[Dict[str, Any], str]) -> bool:
        if isinstance(raw, str):
            return False
        if isinstance(raw, dict):
            src = str(raw.get("source") or raw.get("_source") or raw.get("log_type") or "").lower()
            return src in ("vpn", "openvpn", "wireguard", "ssl_vpn") or "vpn_user" in raw
        return False

    def normalise(self, raw: Union[Dict[str, Any], str], sensor_id: str = "GW-VPN-01") -> StandardSecurityEvent:
        try:
            data = json.loads(raw) if isinstance(raw, str) else raw
            sid = _clean_str(data.get("sensor_id") or data.get("gateway")) or sensor_id
            ts = _parse_timestamp(data.get("timestamp") or data.get("ts"))
            username = _clean_str(data.get("vpn_user") or data.get("username") or data.get("user"))
            action = str(data.get("action") or data.get("event") or "connect").lower()
            status = str(data.get("status") or "success").lower()

            severity = Severity.MEDIUM if status in ("failed", "denied", "rejected") else Severity.INFORMATIONAL
            evidence: Dict[str, Any] = {
                "vpn_user": username,
                "action": action,
                "status": status,
                "tunnel_ip": _clean_str(data.get("tunnel_ip")),
                "mfa_verified": data.get("mfa_verified"),
                "vendor_name": _clean_str(data.get("vendor_name")),
                "raw_log": data,
            }
            if username:
                evidence["principal_name"] = username

            bytes_sent = _safe_int(data.get("bytes_sent"), 0) or 0
            bytes_recv = _safe_int(data.get("bytes_recv"), 0) or 0

            return StandardSecurityEvent(
                sensor_id=sid,
                timestamp=ts,
                source_ip=_clean_str(data.get("remote_ip") or data.get("src_ip") or data.get("client_ip")),
                destination_ip=_clean_str(data.get("gateway_ip") or data.get("dst_ip") or data.get("server_ip")),
                source_port=_safe_int(data.get("src_port")),
                destination_port=_safe_int(data.get("dst_port") or data.get("port"), 443),
                protocol=_clean_str(data.get("protocol")) or "TLS",
                application="vpn",
                connection_duration=_safe_int(data.get("session_duration_ms")),
                bytes_transferred=(bytes_sent + bytes_recv) or None,
                event_type=EventType.AUTH_EVENT,
                detection_source=DetectionSource.MANUAL,
                severity=severity,
                principal_type=PrincipalType.UNKNOWN_IDENTITY,
                evidence=evidence,
                processing_status=ProcessingStatus.VALIDATED,
                event_provenance=self._build_provenance(
                    sensor_id=sid,
                    collection_method="syslog",
                    raw_log_reference=_clean_str(data.get("session_id")) or "vpn:gateway",
                ),
            )
        except NormalisationError:
            raise
        except Exception as exc:
            raise NormalisationError(f"Failed to normalise VPN event: {exc}", self.source_name, raw) from exc


# ---------------------------------------------------------------------------
# 6. Cloud Normaliser (AWS CloudTrail / Azure / GCP audit logs)
# ---------------------------------------------------------------------------

class CloudNormaliser(BaseNormaliser):
    source_name = "cloud"
    default_collection_method = "cloud_api"

    def can_handle(self, raw: Union[Dict[str, Any], str]) -> bool:
        if isinstance(raw, dict):
            src = str(raw.get("source") or raw.get("_source") or raw.get("log_type") or "").lower()
            return src in ("cloud", "cloudtrail", "aws", "azure") or "eventSource" in raw or "operationName" in raw
        return False

    def normalise(self, raw: Union[Dict[str, Any], str], sensor_id: str = "CLOUD-CONNECTOR-01") -> StandardSecurityEvent:
        try:
            data = json.loads(raw) if isinstance(raw, str) else raw
            sid = _clean_str(data.get("sensor_id")) or sensor_id
            ts = _parse_timestamp(data.get("eventTime") or data.get("time") or data.get("timestamp"))

            user_identity = data.get("userIdentity") or {}
            principal = _clean_str(
                user_identity.get("userName")
                or user_identity.get("arn")
                or data.get("caller")
                or data.get("principal_name")
            )
            src_ip = _clean_str(data.get("sourceIPAddress") or data.get("callerIpAddress") or data.get("src_ip"))
            error_code = _clean_str(data.get("errorCode"))
            severity = Severity.MEDIUM if error_code in ("AccessDenied", "UnauthorizedOperation") else Severity.INFORMATIONAL

            evidence: Dict[str, Any] = {
                "event_source": _clean_str(data.get("eventSource")),
                "event_name": _clean_str(data.get("eventName") or data.get("operationName")),
                "aws_region": _clean_str(data.get("awsRegion")),
                "error_code": error_code,
                "error_message": _clean_str(data.get("errorMessage")),
                "request_id": _clean_str(data.get("requestID") or data.get("correlationId")),
                "raw_log": data,
            }
            if principal:
                evidence["principal_name"] = principal

            return StandardSecurityEvent(
                sensor_id=sid,
                timestamp=ts,
                source_ip=src_ip,
                destination_ip=_clean_str(data.get("dst_ip")),
                destination_port=443,
                protocol="HTTPS",
                application=_clean_str(data.get("eventSource")) or "cloud",
                event_type=EventType.AUTH_EVENT,
                detection_source=DetectionSource.MANUAL,
                severity=severity,
                principal_type=PrincipalType.UNKNOWN_IDENTITY,
                evidence=evidence,
                processing_status=ProcessingStatus.VALIDATED,
                event_provenance=self._build_provenance(
                    sensor_id=sid,
                    collection_method="cloud_api",
                    raw_log_reference=_clean_str(data.get("eventID") or data.get("requestID")) or "cloud:audit",
                ),
            )
        except NormalisationError:
            raise
        except Exception as exc:
            raise NormalisationError(f"Failed to normalise Cloud event: {exc}", self.source_name, raw) from exc


# ---------------------------------------------------------------------------
# 7. API Gateway Normaliser
# ---------------------------------------------------------------------------

class ApiGwNormaliser(BaseNormaliser):
    source_name = "api_gw"
    default_collection_method = "api_gateway"

    def can_handle(self, raw: Union[Dict[str, Any], str]) -> bool:
        if isinstance(raw, dict):
            src = str(raw.get("source") or raw.get("_source") or raw.get("log_type") or "").lower()
            if src in ("api_gw", "apigw", "api_gateway"):
                return True
            return "request_id" in raw and ("http_method" in raw or "method" in raw)
        return False

    def normalise(self, raw: Union[Dict[str, Any], str], sensor_id: str = "APIGW-01") -> StandardSecurityEvent:
        try:
            data = json.loads(raw) if isinstance(raw, str) else raw
            sid = _clean_str(data.get("sensor_id")) or sensor_id
            ts = _parse_timestamp(data.get("timestamp") or data.get("request_time"))
            status = _safe_int(data.get("status") or data.get("status_code"), 200) or 200

            severity = Severity.INFORMATIONAL
            if status in (401, 403, 429):
                severity = Severity.MEDIUM
            elif status >= 500:
                severity = Severity.LOW

            principal = _clean_str(data.get("api_client") or data.get("principal_name") or data.get("user"))
            evidence: Dict[str, Any] = {
                "request_id": _clean_str(data.get("request_id")),
                "http_method": _clean_str(data.get("http_method") or data.get("method")),
                "path": _clean_str(data.get("path") or data.get("uri")),
                "status_code": status,
                "latency_ms": _safe_int(data.get("latency_ms") or data.get("response_time_ms")),
                "user_agent": _clean_str(data.get("user_agent")),
                "raw_log": data,
            }
            if principal:
                evidence["principal_name"] = principal

            return StandardSecurityEvent(
                sensor_id=sid,
                timestamp=ts,
                source_ip=_clean_str(data.get("client_ip") or data.get("source_ip") or data.get("src_ip")),
                destination_ip=_clean_str(data.get("upstream_ip") or data.get("dst_ip")),
                destination_port=_safe_int(data.get("dst_port"), 443),
                protocol="HTTPS",
                application="api_gateway",
                connection_duration=_safe_int(data.get("latency_ms")),
                bytes_transferred=_safe_int(data.get("response_bytes")),
                event_type=EventType.HTTP_EVENT,
                detection_source=DetectionSource.MANUAL,
                severity=severity,
                principal_type=PrincipalType.UNKNOWN_IDENTITY,
                evidence=evidence,
                processing_status=ProcessingStatus.VALIDATED,
                event_provenance=self._build_provenance(
                    sensor_id=sid,
                    collection_method="api_gateway",
                    raw_log_reference=_clean_str(data.get("request_id")) or "apigw:access",
                ),
            )
        except NormalisationError:
            raise
        except Exception as exc:
            raise NormalisationError(f"Failed to normalise API GW event: {exc}", self.source_name, raw) from exc


# ---------------------------------------------------------------------------
# 8. Generic Fallback Normaliser
# ---------------------------------------------------------------------------

class GenericNormaliser(BaseNormaliser):
    source_name = "generic"
    default_collection_method = "generic"

    def can_handle(self, raw: Union[Dict[str, Any], str]) -> bool:
        return isinstance(raw, (dict, str))

    def normalise(self, raw: Union[Dict[str, Any], str], sensor_id: str = "SENSOR-GENERIC") -> StandardSecurityEvent:
        try:
            if isinstance(raw, str):
                text = raw.strip()
                if not text:
                    raise NormalisationError("Empty raw event string", self.source_name, raw)
                try:
                    data = json.loads(text)
                    if not isinstance(data, dict):
                        data = {"message": text}
                except json.JSONDecodeError:
                    data = {"message": text}
            elif isinstance(raw, dict):
                if not raw:
                    raise NormalisationError("Empty raw event dictionary", self.source_name, raw)
                data = raw
            else:
                raise NormalisationError(f"Unsupported event payload type: {type(raw)}", self.source_name, raw)

            sid = _clean_str(data.get("sensor_id")) or sensor_id
            ts = _parse_timestamp(data.get("timestamp") or data.get("ts") or data.get("time"))

            ev_type_raw = str(data.get("event_type") or "network_flow").lower()
            try:
                ev_type = EventType(ev_type_raw)
            except ValueError:
                ev_type = EventType.NETWORK_FLOW

            evidence: Dict[str, Any] = {"raw_log": data}
            principal = _clean_str(data.get("principal_name") or data.get("username") or data.get("user"))
            if principal:
                evidence["principal_name"] = principal

            return StandardSecurityEvent(
                sensor_id=sid,
                timestamp=ts,
                source_ip=_clean_str(data.get("source_ip") or data.get("src_ip") or data.get("src")),
                destination_ip=_clean_str(data.get("destination_ip") or data.get("dst_ip") or data.get("dst")),
                source_port=_safe_int(data.get("source_port") or data.get("src_port") or data.get("sport")),
                destination_port=_safe_int(data.get("destination_port") or data.get("dst_port") or data.get("dport")),
                protocol=_clean_str(data.get("protocol") or data.get("proto")),
                bytes_transferred=_safe_int(data.get("bytes_transferred") or data.get("bytes")),
                packets_transferred=_safe_int(data.get("packets_transferred") or data.get("packets")),
                event_type=ev_type,
                detection_source=DetectionSource.MANUAL,
                severity=Severity.INFORMATIONAL,
                principal_type=PrincipalType.UNKNOWN_IDENTITY,
                evidence=evidence,
                processing_status=ProcessingStatus.VALIDATED,
                event_provenance=self._build_provenance(
                    sensor_id=sid,
                    collection_method=_clean_str(data.get("collection_method")) or "generic",
                    raw_log_reference=_clean_str(data.get("raw_log_reference")),
                ),
            )
        except NormalisationError:
            raise
        except Exception as exc:
            raise NormalisationError(f"Failed to normalise generic event: {exc}", self.source_name, raw) from exc


# ---------------------------------------------------------------------------
# Normalisation Orchestrator (Dispatcher + Deduplication)
# ---------------------------------------------------------------------------

class EventNormaliser:
    """
    Central event normalisation dispatcher supporting all VaultX telemetry sources
    plus optional Redis-backed 5-minute deduplication.
    """

    def __init__(self, dedup_cache: Optional[DedupCache] = None) -> None:
        self._dedup_cache = dedup_cache
        self._handlers: List[BaseNormaliser] = [
            SuricataNormaliser(),
            ZeekNormaliser(),
            SysmonNormaliser(),
            AuditdNormaliser(),
            VPNNormaliser(),
            CloudNormaliser(),
            ApiGwNormaliser(),
            GenericNormaliser(),
        ]
        self._by_source: Dict[str, BaseNormaliser] = {
            h.source_name: h for h in self._handlers
        }

    def normalise(
        self,
        raw: Union[Dict[str, Any], str],
        source: Optional[str] = None,
        sensor_id: str = "UNKNOWN-SENSOR",
    ) -> StandardSecurityEvent:
        """
        Synchronously normalise a raw event into StandardSecurityEvent.
        Raises NormalisationError on malformed input.
        """
        if raw is None or (isinstance(raw, str) and not raw.strip()) or (isinstance(raw, dict) and not raw):
            raise NormalisationError("Cannot normalise empty event", source or "unknown", raw)

        if source and source.lower() in self._by_source:
            return self._by_source[source.lower()].normalise(raw, sensor_id=sensor_id)

        for handler in self._handlers:
            if handler.can_handle(raw):
                return handler.normalise(raw, sensor_id=sensor_id)

        raise NormalisationError("No normaliser matched raw event", source or "unknown", raw)

    @staticmethod
    def compute_event_hash(event: StandardSecurityEvent) -> str:
        """
        Compute SHA-256 hash of (timestamp_bucket + source_ip + dest_ip + event_type)
        for quick deduplication fingerprinting.
        """
        ts_bucket = str(int(event.timestamp.timestamp()) // 60)
        payload = f"{ts_bucket}|{event.source_ip or ''}|{event.destination_ip or ''}|{event.event_type.value}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    async def normalise_and_check_duplicate(
        self,
        raw: Union[Dict[str, Any], str],
        source: Optional[str] = None,
        sensor_id: str = "UNKNOWN-SENSOR",
    ) -> Tuple[StandardSecurityEvent, bool, str]:
        """
        Normalise raw event and check against the 5-minute Redis deduplication window.

        Returns
        -------
        (event, is_duplicate, dedup_hash)
        """
        event = self.normalise(raw, source=source, sensor_id=sensor_id)
        if self._dedup_cache is not None:
            is_dup, dedup_hash = await self._dedup_cache.check_and_record(
                timestamp=event.timestamp,
                src_ip=event.source_ip,
                dst_ip=event.destination_ip,
                src_port=event.source_port,
                dst_port=event.destination_port,
                event_type=event.event_type.value,
            )
            return event, is_dup, dedup_hash

        return event, False, self.compute_event_hash(event)


# Backwards-compatible alias
NormaliserPipeline = EventNormaliser

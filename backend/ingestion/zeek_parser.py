"""
VaultX NIDS - Zeek Log Parser
Bharat Electronics Components Pvt. Ltd. (BECPL), Pune

Parses Zeek (Bro) network analysis logs (conn.log, dns.log, http.log, tls.log, notice.log)
supporting both JSON streaming format and TSV ASCII format with headers (#fields).
Maps telemetry into StandardSecurityEvent and NetworkFlowRecord.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Union

from event_schema import (
    DetectionSource,
    EncryptionMetadata,
    EventProvenance,
    EventType,
    NetworkFlowRecord,
    PrincipalType,
    ProcessingStatus,
    Severity,
    StandardSecurityEvent,
)


# ==============================================================================
# Zeek Field Mappings Reference
# ==============================================================================
ZEEK_FIELD_MAPPINGS: Dict[str, Dict[str, str]] = {
    "conn": {
        "ts": "timestamp",
        "uid": "flow_id",
        "id.orig_h": "source_ip",
        "id.orig_p": "source_port",
        "id.resp_h": "destination_ip",
        "id.resp_p": "destination_port",
        "proto": "protocol",
        "service": "application",
        "duration": "connection_duration_ms",
        "orig_bytes": "orig_bytes",
        "resp_bytes": "resp_bytes",
        "conn_state": "conn_state",
        "orig_pkts": "orig_packets",
        "resp_pkts": "resp_packets",
        "history": "history",
    },
    "dns": {
        "ts": "timestamp",
        "uid": "flow_id",
        "id.orig_h": "source_ip",
        "id.orig_p": "source_port",
        "id.resp_h": "destination_ip",
        "id.resp_p": "destination_port",
        "proto": "protocol",
        "query": "dns_query",
        "qtype_name": "dns_type",
        "answers": "dns_answers",
        "rcode_name": "dns_rcode",
    },
    "http": {
        "ts": "timestamp",
        "uid": "flow_id",
        "id.orig_h": "source_ip",
        "id.orig_p": "source_port",
        "id.resp_h": "destination_ip",
        "id.resp_p": "destination_port",
        "method": "http_method",
        "host": "http_host",
        "uri": "http_uri",
        "status_code": "http_status",
        "user_agent": "http_user_agent",
        "response_body_len": "http_response_body_len",
    },
    "tls": {
        "ts": "timestamp",
        "uid": "flow_id",
        "id.orig_h": "source_ip",
        "id.orig_p": "source_port",
        "id.resp_h": "destination_ip",
        "id.resp_p": "destination_port",
        "version": "tls_version",
        "cipher": "cipher_suite",
        "server_name": "sni",
        "subject": "cert_subject",
        "issuer": "cert_issuer",
        "ja3": "ja3_hash",
        "ja3s": "ja3s_hash",
        "validation_status": "cert_valid",
    },
    "notice": {
        "ts": "timestamp",
        "uid": "flow_id",
        "id.orig_h": "source_ip",
        "id.orig_p": "source_port",
        "id.resp_h": "destination_ip",
        "id.resp_p": "destination_port",
        "note": "notice_type",
        "msg": "message",
        "sub": "sub_message",
        "actions": "actions",
    },
}


def _clean_val(v: Any) -> Any:
    """Normalize Zeek null values ('-' or empty strings)."""
    if v is None or v == "-" or v == "(empty)":
        return None
    return v


def _parse_epoch_ts(ts_raw: Any) -> datetime:
    """Parse Zeek timestamp (float epoch seconds)."""
    if ts_raw is None:
        return datetime.now(timezone.utc)
    try:
        f = float(ts_raw)
        return datetime.fromtimestamp(f, tz=timezone.utc)
    except (ValueError, TypeError):
        return datetime.now(timezone.utc)


def parse_zeek_tsv_line(line: str, fields: List[str]) -> Dict[str, Any]:
    """Parse a single TSV line according to the Zeek #fields specification."""
    parts = line.strip().split("\t")
    row: Dict[str, Any] = {}
    for i, field in enumerate(fields):
        if i < len(parts):
            row[field] = _clean_val(parts[i])
        else:
            row[field] = None
    return row


class ZeekParser:
    """Production-grade Zeek log parser supporting JSON and TSV records."""

    def __init__(self, default_sensor_id: str = "SEC-SENSOR-01"):
        self.default_sensor_id = default_sensor_id

    def _normalize_record(self, raw: Union[str, Dict[str, Any]], field_list: Optional[List[str]] = None) -> Dict[str, Any]:
        """Convert input JSON string, dict, or TSV line to standard key-value dictionary."""
        if isinstance(raw, dict):
            # Flatten potential nested fields like "id.orig_h" if passed as {"id": {"orig_h": ...}}
            flat: Dict[str, Any] = {}
            for k, v in raw.items():
                if isinstance(v, dict) and k == "id":
                    flat["id.orig_h"] = v.get("orig_h")
                    flat["id.orig_p"] = v.get("orig_p")
                    flat["id.resp_h"] = v.get("resp_h")
                    flat["id.resp_p"] = v.get("resp_p")
                else:
                    flat[k] = _clean_val(v)
            return flat
        elif isinstance(raw, str):
            line = raw.strip()
            if line.startswith("{") and line.endswith("}"):
                data = json.loads(line)
                return self._normalize_record(data)
            elif field_list:
                return parse_zeek_tsv_line(line, field_list)
            else:
                # Tab-separated without known fields fallback
                raise ValueError("TSV parsing requires a field_list from Zeek #fields header")
        else:
            raise TypeError(f"Unsupported record type: {type(raw)}")

    def parse_conn(self, raw: Union[str, Dict[str, Any]], sensor_id: Optional[str] = None) -> Tuple[StandardSecurityEvent, NetworkFlowRecord]:
        """Parse Zeek conn.log entry into StandardSecurityEvent and NetworkFlowRecord."""
        data = self._normalize_record(raw)
        sid = sensor_id or self.default_sensor_id

        ts = _parse_epoch_ts(data.get("ts"))
        orig_h = data.get("id.orig_h")
        resp_h = data.get("id.resp_h")
        orig_p = int(data["id.orig_p"]) if data.get("id.orig_p") is not None else None
        resp_p = int(data["id.resp_p"]) if data.get("id.resp_p") is not None else None
        proto = (data.get("proto") or "TCP").upper()
        service = data.get("service")

        duration_sec = float(data.get("duration") or 0.0)
        duration_ms = int(duration_sec * 1000)
        orig_bytes = int(data.get("orig_bytes") or 0)
        resp_bytes = int(data.get("resp_bytes") or 0)
        total_bytes = orig_bytes + resp_bytes
        orig_pkts = int(data.get("orig_pkts") or 0)
        resp_pkts = int(data.get("resp_pkts") or 0)
        total_pkts = orig_pkts + resp_pkts
        conn_state = data.get("conn_state")
        history = data.get("history")
        zeek_uid = str(data.get("uid") or "")

        # Deterministic UUID from Zeek UID if available, else new UUID
        flow_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, f"zeek:{zeek_uid}") if zeek_uid else uuid.uuid4()

        event = StandardSecurityEvent(
            timestamp=ts,
            sensor_id=sid,
            source_ip=orig_h,
            destination_ip=resp_h,
            source_port=orig_p,
            destination_port=resp_p,
            protocol=proto,
            application=service,
            flow_id=flow_uuid,
            connection_duration=duration_ms,
            bytes_transferred=total_bytes,
            packets_transferred=total_pkts,
            event_type=EventType.NETWORK_FLOW,
            detection_source=DetectionSource.ZEEK,
            severity=Severity.INFORMATIONAL,
            confidence=1.0,
            evidence={
                "zeek_uid": zeek_uid,
                "conn_state": conn_state,
                "history": history,
                "orig_bytes": orig_bytes,
                "resp_bytes": resp_bytes,
                "orig_pkts": orig_pkts,
                "resp_pkts": resp_pkts,
            },
            processing_status=ProcessingStatus.VALIDATED,
            event_provenance=EventProvenance(
                source_system=sid,
                collection_method="SPAN",
                raw_log_reference=f"conn.log:{zeek_uid}",
                pipeline_version="1.0.0",
                captured_at=ts,
            ),
        )

        flow_record = NetworkFlowRecord(
            flow_id=flow_uuid,
            timestamp=ts,
            sensor_id=sid,
            src_ip=orig_h,
            dst_ip=resp_h,
            src_port=orig_p,
            dst_port=resp_p,
            protocol=proto,
            duration_ms=duration_ms,
            orig_bytes=orig_bytes,
            resp_bytes=resp_bytes,
            orig_packets=orig_pkts,
            resp_packets=resp_pkts,
            conn_state=conn_state,
            history=history,
            zeek_uid=zeek_uid,
        )

        return event, flow_record

    def parse_dns(self, raw: Union[str, Dict[str, Any]], sensor_id: Optional[str] = None) -> StandardSecurityEvent:
        """Parse Zeek dns.log entry into StandardSecurityEvent."""
        data = self._normalize_record(raw)
        sid = sensor_id or self.default_sensor_id

        ts = _parse_epoch_ts(data.get("ts"))
        orig_h = data.get("id.orig_h")
        resp_h = data.get("id.resp_h")
        orig_p = int(data["id.orig_p"]) if data.get("id.orig_p") is not None else None
        resp_p = int(data["id.resp_p"]) if data.get("id.resp_p") is not None else 53
        zeek_uid = str(data.get("uid") or "")
        flow_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, f"zeek:{zeek_uid}") if zeek_uid else uuid.uuid4()

        query = data.get("query")
        answers = data.get("answers")
        if isinstance(answers, str):
            answers_list = [a.strip() for a in answers.split(",") if a.strip()]
        elif isinstance(answers, list):
            answers_list = answers
        else:
            answers_list = []

        return StandardSecurityEvent(
            timestamp=ts,
            sensor_id=sid,
            source_ip=orig_h,
            destination_ip=resp_h,
            source_port=orig_p,
            destination_port=resp_p,
            protocol="UDP",
            application="DNS",
            flow_id=flow_uuid,
            event_type=EventType.DNS_EVENT,
            detection_source=DetectionSource.ZEEK,
            severity=Severity.INFORMATIONAL,
            confidence=1.0,
            evidence={
                "zeek_uid": zeek_uid,
                "query": query,
                "qtype_name": data.get("qtype_name"),
                "answers": answers_list,
                "rcode_name": data.get("rcode_name"),
            },
            processing_status=ProcessingStatus.VALIDATED,
            event_provenance=EventProvenance(
                source_system=sid,
                collection_method="SPAN",
                raw_log_reference=f"dns.log:{zeek_uid}",
                captured_at=ts,
            ),
        )

    def parse_http(self, raw: Union[str, Dict[str, Any]], sensor_id: Optional[str] = None) -> StandardSecurityEvent:
        """Parse Zeek http.log entry into StandardSecurityEvent."""
        data = self._normalize_record(raw)
        sid = sensor_id or self.default_sensor_id

        ts = _parse_epoch_ts(data.get("ts"))
        orig_h = data.get("id.orig_h")
        resp_h = data.get("id.resp_h")
        orig_p = int(data["id.orig_p"]) if data.get("id.orig_p") is not None else None
        resp_p = int(data["id.resp_p"]) if data.get("id.resp_p") is not None else 80
        zeek_uid = str(data.get("uid") or "")
        flow_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, f"zeek:{zeek_uid}") if zeek_uid else uuid.uuid4()

        method = data.get("method")
        host = data.get("host")
        uri = data.get("uri")
        status = int(data["status_code"]) if data.get("status_code") is not None else None

        return StandardSecurityEvent(
            timestamp=ts,
            sensor_id=sid,
            source_ip=orig_h,
            destination_ip=resp_h,
            source_port=orig_p,
            destination_port=resp_p,
            protocol="TCP",
            application="HTTP",
            flow_id=flow_uuid,
            event_type=EventType.HTTP_EVENT,
            detection_source=DetectionSource.ZEEK,
            severity=Severity.INFORMATIONAL,
            confidence=1.0,
            evidence={
                "zeek_uid": zeek_uid,
                "method": method,
                "host": host,
                "uri": uri,
                "status_code": status,
                "user_agent": data.get("user_agent"),
                "response_body_len": data.get("response_body_len"),
            },
            processing_status=ProcessingStatus.VALIDATED,
            event_provenance=EventProvenance(
                source_system=sid,
                collection_method="SPAN",
                raw_log_reference=f"http.log:{zeek_uid}",
                captured_at=ts,
            ),
        )

    def parse_tls(self, raw: Union[str, Dict[str, Any]], sensor_id: Optional[str] = None) -> StandardSecurityEvent:
        """Parse Zeek tls.log entry with encryption metadata."""
        data = self._normalize_record(raw)
        sid = sensor_id or self.default_sensor_id

        ts = _parse_epoch_ts(data.get("ts"))
        orig_h = data.get("id.orig_h")
        resp_h = data.get("id.resp_h")
        orig_p = int(data["id.orig_p"]) if data.get("id.orig_p") is not None else None
        resp_p = int(data["id.resp_p"]) if data.get("id.resp_p") is not None else 443
        zeek_uid = str(data.get("uid") or "")
        flow_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, f"zeek:{zeek_uid}") if zeek_uid else uuid.uuid4()

        enc_meta = EncryptionMetadata(
            tls_version=data.get("version"),
            cipher_suite=data.get("cipher"),
            sni=data.get("server_name"),
            cert_subject=data.get("subject"),
            cert_issuer=data.get("issuer"),
            cert_valid=bool(data.get("validation_status") == "ok") if data.get("validation_status") else None,
            ja3_hash=data.get("ja3"),
            ja3s_hash=data.get("ja3s"),
        )

        return StandardSecurityEvent(
            timestamp=ts,
            sensor_id=sid,
            source_ip=orig_h,
            destination_ip=resp_h,
            source_port=orig_p,
            destination_port=resp_p,
            protocol="TCP",
            application="TLS",
            flow_id=flow_uuid,
            encryption_metadata=enc_meta,
            event_type=EventType.TLS_EVENT,
            detection_source=DetectionSource.ZEEK,
            severity=Severity.INFORMATIONAL,
            confidence=1.0,
            evidence={
                "zeek_uid": zeek_uid,
                "server_name": data.get("server_name"),
                "subject": data.get("subject"),
                "issuer": data.get("issuer"),
            },
            processing_status=ProcessingStatus.VALIDATED,
            event_provenance=EventProvenance(
                source_system=sid,
                collection_method="SPAN",
                raw_log_reference=f"tls.log:{zeek_uid}",
                captured_at=ts,
            ),
        )

    def parse_notice(self, raw: Union[str, Dict[str, Any]], sensor_id: Optional[str] = None) -> StandardSecurityEvent:
        """Parse Zeek notice.log entry into an alert event."""
        data = self._normalize_record(raw)
        sid = sensor_id or self.default_sensor_id

        ts = _parse_epoch_ts(data.get("ts"))
        orig_h = data.get("id.orig_h")
        resp_h = data.get("id.resp_h")
        orig_p = int(data["id.orig_p"]) if data.get("id.orig_p") is not None else None
        resp_p = int(data["id.resp_p"]) if data.get("id.resp_p") is not None else None
        zeek_uid = str(data.get("uid") or "")
        flow_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, f"zeek:{zeek_uid}") if zeek_uid else uuid.uuid4()

        note = data.get("note") or "Notice"
        msg = data.get("msg") or ""

        # Map Zeek Notice severity
        severity = Severity.MEDIUM
        if any(term in note.lower() for term in ["attack", "exploit", "compromise", "backdoor", "scanner"]):
            severity = Severity.HIGH
        elif any(term in note.lower() for term in ["drop", "heartbleed", "cve"]):
            severity = Severity.CRITICAL
        elif "policy" in note.lower():
            severity = Severity.LOW

        return StandardSecurityEvent(
            timestamp=ts,
            sensor_id=sid,
            source_ip=orig_h,
            destination_ip=resp_h,
            source_port=orig_p,
            destination_port=resp_p,
            protocol="TCP",
            flow_id=flow_uuid,
            event_type=EventType.ALERT,
            detection_source=DetectionSource.ZEEK,
            severity=severity,
            confidence=0.85,
            evidence={
                "zeek_uid": zeek_uid,
                "notice_type": note,
                "message": msg,
                "sub": data.get("sub"),
                "actions": data.get("actions"),
            },
            processing_status=ProcessingStatus.VALIDATED,
            detection_rule_version=note,
            event_provenance=EventProvenance(
                source_system=sid,
                collection_method="SPAN",
                raw_log_reference=f"notice.log:{zeek_uid}",
                captured_at=ts,
            ),
        )

    def dispatch(self, log_type: str, record: Union[str, Dict[str, Any]], sensor_id: Optional[str] = None) -> Union[StandardSecurityEvent, Tuple[StandardSecurityEvent, NetworkFlowRecord]]:
        """Dispatch record based on Zeek log stream type."""
        lt = log_type.lower()
        if lt == "conn":
            return self.parse_conn(record, sensor_id)
        elif lt == "dns":
            return self.parse_dns(record, sensor_id)
        elif lt == "http":
            return self.parse_http(record, sensor_id)
        elif lt == "tls":
            return self.parse_tls(record, sensor_id)
        elif lt == "notice":
            return self.parse_notice(record, sensor_id)
        else:
            raise ValueError(f"Unknown or unsupported Zeek log type: {log_type}")

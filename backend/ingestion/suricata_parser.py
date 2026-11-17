"""
VaultX NIDS - Suricata EVE JSON Parser
Bharat Electronics Components Pvt. Ltd. (BECPL), Pune

Parses Suricata Extensible Event (EVE) JSON logs for:
- alert events (with signature ID, GID, rule category, and full signature metadata)
- flow records (bi-directional bytes, packets, durations)
- dns, http, tls, and anomaly events
Maps into StandardSecurityEvent and NetworkFlowRecord.
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


class SuricataParser:
    """Parser for Suricata EVE JSON stream entries."""

    def __init__(self, default_sensor_id: str = "SEC-SENSOR-01"):
        self.default_sensor_id = default_sensor_id

    def _parse_ts(self, ts_str: Any) -> datetime:
        """Parse Suricata ISO timestamp (e.g., 2026-11-17T14:32:01.123456+0000)."""
        if not ts_str:
            return datetime.now(timezone.utc)
        if isinstance(ts_str, datetime):
            return ts_str if ts_str.tzinfo else ts_str.replace(tzinfo=timezone.utc)
        try:
            from dateutil import parser
            dt = parser.parse(str(ts_str))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception:
            return datetime.now(timezone.utc)

    def _map_suricata_severity(self, suri_sev: Optional[int]) -> Severity:
        """
        Map Suricata integer severity:
        1 -> Critical (High threat)
        2 -> High
        3 -> Medium
        4 -> Low
        Other -> Informational
        """
        if suri_sev == 1:
            return Severity.CRITICAL
        elif suri_sev == 2:
            return Severity.HIGH
        elif suri_sev == 3:
            return Severity.MEDIUM
        elif suri_sev == 4:
            return Severity.LOW
        return Severity.INFORMATIONAL

    def parse_eve_record(
        self,
        record: Union[str, Dict[str, Any]],
        sensor_id: Optional[str] = None
    ) -> Union[StandardSecurityEvent, Tuple[StandardSecurityEvent, NetworkFlowRecord]]:
        """
        Parse a single Suricata EVE JSON record into a StandardSecurityEvent.
        If event_type == 'flow', returns a tuple (StandardSecurityEvent, NetworkFlowRecord).
        """
        if isinstance(record, str):
            data = json.loads(record.strip())
        elif isinstance(record, dict):
            data = record
        else:
            raise TypeError(f"Expected str or dict, got {type(record)}")

        sid = sensor_id or self.default_sensor_id
        event_type_raw = str(data.get("event_type", "alert")).lower()
        ts = self._parse_ts(data.get("timestamp"))

        src_ip = data.get("src_ip")
        dest_ip = data.get("dest_ip")
        src_port = data.get("src_port")
        dest_port = data.get("dest_port")
        proto = (data.get("proto") or "TCP").upper()
        flow_id_raw = data.get("flow_id")
        flow_uuid = (
            uuid.uuid5(uuid.NAMESPACE_DNS, f"suricata:{flow_id_raw}")
            if flow_id_raw is not None
            else uuid.uuid4()
        )

        in_iface = data.get("in_iface") or "eth0"

        # ----------------------------------------------------------------------
        # 1. ALERT Events
        # ----------------------------------------------------------------------
        if event_type_raw == "alert":
            alert_info = data.get("alert", {})
            sig_id = alert_info.get("signature_id")
            gid = alert_info.get("gid", 1)
            rev = alert_info.get("rev", 1)
            sig_name = alert_info.get("signature", "Unknown Suricata Alert")
            category = alert_info.get("category", "General")
            suri_sev = alert_info.get("severity", 2)
            action = alert_info.get("action", "allowed")

            severity = self._map_suricata_severity(suri_sev)
            rule_ref = f"{gid}:{sig_id}:{rev}"

            evidence: Dict[str, Any] = {
                "suricata_gid": gid,
                "suricata_sid": sig_id,
                "suricata_rev": rev,
                "signature": sig_name,
                "category": category,
                "rule_ref": rule_ref,
                "action": action,
                "flow_id": flow_id_raw,
                "raw_alert": alert_info,
            }
            if "payload_printable" in data:
                evidence["payload_snippet"] = data["payload_printable"][:512]
            if "packet" in data:
                evidence["packet_b64_len"] = len(data["packet"])

            event = StandardSecurityEvent(
                timestamp=ts,
                sensor_id=sid,
                source_ip=src_ip,
                destination_ip=dest_ip,
                source_port=src_port,
                destination_port=dest_port,
                protocol=proto,
                flow_id=flow_uuid,
                event_type=EventType.ALERT,
                detection_source=DetectionSource.SURICATA,
                severity=severity,
                confidence=0.92,
                evidence=evidence,
                processing_status=ProcessingStatus.VALIDATED,
                detection_rule_version=rule_ref,
                event_provenance=EventProvenance(
                    source_system=sid,
                    collection_method=f"TAP:{in_iface}",
                    raw_log_reference=f"eve.json:alert:{rule_ref}",
                    captured_at=ts,
                ),
            )
            return event

        # ----------------------------------------------------------------------
        # 2. FLOW Events
        # ----------------------------------------------------------------------
        elif event_type_raw == "flow":
            flow_info = data.get("flow", {})
            pkts_to_server = flow_info.get("pkts_toserver", 0)
            pkts_to_client = flow_info.get("pkts_toclient", 0)
            bytes_to_server = flow_info.get("bytes_toserver", 0)
            bytes_to_client = flow_info.get("bytes_toclient", 0)
            age = flow_info.get("age", 0)
            duration_ms = int(age * 1000)
            total_bytes = bytes_to_server + bytes_to_client
            total_pkts = pkts_to_server + pkts_to_client
            state = flow_info.get("state", "closed")

            event = StandardSecurityEvent(
                timestamp=ts,
                sensor_id=sid,
                source_ip=src_ip,
                destination_ip=dest_ip,
                source_port=src_port,
                destination_port=dest_port,
                protocol=proto,
                flow_id=flow_uuid,
                connection_duration=duration_ms,
                bytes_transferred=total_bytes,
                packets_transferred=total_pkts,
                event_type=EventType.NETWORK_FLOW,
                detection_source=DetectionSource.SURICATA,
                severity=Severity.INFORMATIONAL,
                confidence=1.0,
                evidence={
                    "flow_id": flow_id_raw,
                    "bytes_to_server": bytes_to_server,
                    "bytes_to_client": bytes_to_client,
                    "pkts_to_server": pkts_to_server,
                    "pkts_to_client": pkts_to_client,
                    "state": state,
                    "reason": flow_info.get("reason"),
                },
                processing_status=ProcessingStatus.VALIDATED,
                event_provenance=EventProvenance(
                    source_system=sid,
                    collection_method=f"TAP:{in_iface}",
                    raw_log_reference=f"eve.json:flow:{flow_id_raw}",
                    captured_at=ts,
                ),
            )

            flow_record = NetworkFlowRecord(
                flow_id=flow_uuid,
                timestamp=ts,
                sensor_id=sid,
                src_ip=src_ip,
                dst_ip=dest_ip,
                src_port=src_port,
                dst_port=dest_port,
                protocol=proto,
                duration_ms=duration_ms,
                orig_bytes=bytes_to_server,
                resp_bytes=bytes_to_client,
                orig_packets=pkts_to_server,
                resp_packets=pkts_to_client,
                conn_state=state,
            )
            return event, flow_record

        # ----------------------------------------------------------------------
        # 3. DNS Events
        # ----------------------------------------------------------------------
        elif event_type_raw == "dns":
            dns_info = data.get("dns", {})
            query = dns_info.get("rrname")
            qtype = dns_info.get("rrtype")
            rcode = dns_info.get("rcode")
            answers = dns_info.get("answers", [])

            return StandardSecurityEvent(
                timestamp=ts,
                sensor_id=sid,
                source_ip=src_ip,
                destination_ip=dest_ip,
                source_port=src_port,
                destination_port=dest_port or 53,
                protocol=proto,
                application="DNS",
                flow_id=flow_uuid,
                event_type=EventType.DNS_EVENT,
                detection_source=DetectionSource.SURICATA,
                severity=Severity.INFORMATIONAL,
                confidence=1.0,
                evidence={
                    "query": query,
                    "qtype": qtype,
                    "rcode": rcode,
                    "answers": answers,
                    "flow_id": flow_id_raw,
                },
                processing_status=ProcessingStatus.VALIDATED,
                event_provenance=EventProvenance(
                    source_system=sid,
                    collection_method=f"TAP:{in_iface}",
                    raw_log_reference=f"eve.json:dns:{flow_id_raw}",
                    captured_at=ts,
                ),
            )

        # ----------------------------------------------------------------------
        # 4. HTTP Events
        # ----------------------------------------------------------------------
        elif event_type_raw == "http":
            http_info = data.get("http", {})
            method = http_info.get("http_method")
            hostname = http_info.get("hostname")
            url = http_info.get("url")
            status = http_info.get("status")
            length = http_info.get("length")

            return StandardSecurityEvent(
                timestamp=ts,
                sensor_id=sid,
                source_ip=src_ip,
                destination_ip=dest_ip,
                source_port=src_port,
                destination_port=dest_port or 80,
                protocol=proto,
                application="HTTP",
                flow_id=flow_uuid,
                event_type=EventType.HTTP_EVENT,
                detection_source=DetectionSource.SURICATA,
                severity=Severity.INFORMATIONAL,
                confidence=1.0,
                evidence={
                    "http_method": method,
                    "hostname": hostname,
                    "url": url,
                    "status": status,
                    "user_agent": http_info.get("http_user_agent"),
                    "length": length,
                    "flow_id": flow_id_raw,
                },
                processing_status=ProcessingStatus.VALIDATED,
                event_provenance=EventProvenance(
                    source_system=sid,
                    collection_method=f"TAP:{in_iface}",
                    raw_log_reference=f"eve.json:http:{flow_id_raw}",
                    captured_at=ts,
                ),
            )

        # ----------------------------------------------------------------------
        # 5. TLS Events
        # ----------------------------------------------------------------------
        elif event_type_raw == "tls":
            tls_info = data.get("tls", {})
            version = tls_info.get("version")
            sni = tls_info.get("sni")
            subject = tls_info.get("subject")
            issuer = tls_info.get("issuerdn")
            ja3 = tls_info.get("ja3")
            ja3s = tls_info.get("ja3s")

            enc_meta = EncryptionMetadata(
                tls_version=version,
                sni=sni,
                cert_subject=subject,
                cert_issuer=issuer,
                ja3_hash=ja3.get("hash") if isinstance(ja3, dict) else str(ja3) if ja3 else None,
                ja3s_hash=ja3s.get("hash") if isinstance(ja3s, dict) else str(ja3s) if ja3s else None,
            )

            return StandardSecurityEvent(
                timestamp=ts,
                sensor_id=sid,
                source_ip=src_ip,
                destination_ip=dest_ip,
                source_port=src_port,
                destination_port=dest_port or 443,
                protocol=proto,
                application="TLS",
                flow_id=flow_uuid,
                encryption_metadata=enc_meta,
                event_type=EventType.TLS_EVENT,
                detection_source=DetectionSource.SURICATA,
                severity=Severity.INFORMATIONAL,
                confidence=1.0,
                evidence={
                    "sni": sni,
                    "subject": subject,
                    "issuer": issuer,
                    "flow_id": flow_id_raw,
                },
                processing_status=ProcessingStatus.VALIDATED,
                event_provenance=EventProvenance(
                    source_system=sid,
                    collection_method=f"TAP:{in_iface}",
                    raw_log_reference=f"eve.json:tls:{flow_id_raw}",
                    captured_at=ts,
                ),
            )

        # ----------------------------------------------------------------------
        # Fallback / Generic Event
        # ----------------------------------------------------------------------
        else:
            return StandardSecurityEvent(
                timestamp=ts,
                sensor_id=sid,
                source_ip=src_ip,
                destination_ip=dest_ip,
                source_port=src_port,
                destination_port=dest_port,
                protocol=proto,
                flow_id=flow_uuid,
                event_type=EventType.ALERT if "alert" in data else EventType.NETWORK_FLOW,
                detection_source=DetectionSource.SURICATA,
                severity=Severity.INFORMATIONAL,
                confidence=0.8,
                evidence={"raw_data": data},
                processing_status=ProcessingStatus.VALIDATED,
                event_provenance=EventProvenance(
                    source_system=sid,
                    collection_method=f"TAP:{in_iface}",
                    raw_log_reference=f"eve.json:{event_type_raw}",
                    captured_at=ts,
                ),
            )

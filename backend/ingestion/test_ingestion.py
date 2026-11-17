"""
VaultX NIDS - Unit Tests for Event Schema, Zeek Parser, and Suricata Parser
"""

import json
import uuid
from datetime import datetime, timezone

import pytest
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


def test_standard_event_schema_creation_and_dict():
    event = StandardSecurityEvent(
        sensor_id="SEC-SENSOR-01",
        source_ip="10.10.10.101",
        destination_ip="10.10.30.20",
        source_port=54321,
        destination_port=502,
        protocol="tcp",
        event_type=EventType.ALERT,
        severity=Severity.CRITICAL,
        confidence=0.98,
        principal_type=PrincipalType.HUMAN_USER,
        evidence={"alert_rule": "RULE-SMT-MODBUS-WRITE"},
    )

    d = event.to_dict()
    assert d["sensor_id"] == "SEC-SENSOR-01"
    assert d["source_ip"] == "10.10.10.101"
    assert d["destination_ip"] == "10.10.30.20"
    assert d["protocol"] == "TCP"
    assert d["severity"] == "critical"
    assert d["principal_type"] == "HUMAN_USER"
    assert "event_id" in d
    assert "timestamp" in d


def test_zeek_conn_parser():
    parser = ZeekParser(default_sensor_id="SEC-SENSOR-01")
    conn_json = {
        "ts": 1700000000.123,
        "uid": "CHhAvV3sG8vXyZ123",
        "id.orig_h": "10.10.10.101",
        "id.orig_p": 49152,
        "id.resp_h": "10.10.30.20",
        "id.resp_p": 502,
        "proto": "tcp",
        "service": "modbus",
        "duration": 0.45,
        "orig_bytes": 128,
        "resp_bytes": 256,
        "conn_state": "SF",
        "orig_pkts": 4,
        "resp_pkts": 4,
        "history": "ShADadFf",
    }

    event, flow = parser.parse_conn(conn_json)
    assert event.source_ip == "10.10.10.101"
    assert event.destination_ip == "10.10.30.20"
    assert event.destination_port == 502
    assert event.protocol == "TCP"
    assert event.application == "modbus"
    assert event.bytes_transferred == 384
    assert event.connection_duration == 450

    assert flow.src_ip == "10.10.10.101"
    assert flow.dst_ip == "10.10.30.20"
    assert flow.conn_state == "SF"


def test_zeek_dns_and_tls_parser():
    parser = ZeekParser(default_sensor_id="SEC-SENSOR-01")

    dns_json = {
        "ts": 1700000005.0,
        "uid": "CDns12345",
        "id.orig_h": "10.10.20.101",
        "id.orig_p": 53000,
        "id.resp_h": "10.10.70.5",
        "id.resp_p": 53,
        "proto": "udp",
        "query": "git.eng.becpl.local",
        "answers": "10.10.20.10",
        "rcode_name": "NOERROR",
    }
    dns_event = parser.parse_dns(dns_json)
    assert dns_event.event_type == EventType.DNS_EVENT
    assert dns_event.evidence["query"] == "git.eng.becpl.local"
    assert "10.10.20.10" in dns_event.evidence["answers"]

    tls_json = {
        "ts": 1700000010.0,
        "uid": "CTls67890",
        "id.orig_h": "10.10.50.10",
        "id.orig_p": 54100,
        "id.resp_h": "10.10.30.10",
        "id.resp_p": 443,
        "version": "TLSv1.3",
        "cipher": "TLS_AES_256_GCM_SHA384",
        "server_name": "scada-gateway.ot.becpl.local",
        "validation_status": "ok",
    }
    tls_event = parser.parse_tls(tls_json)
    assert tls_event.event_type == EventType.TLS_EVENT
    assert tls_event.encryption_metadata is not None
    assert tls_event.encryption_metadata.tls_version == "TLSv1.3"
    assert tls_event.encryption_metadata.sni == "scada-gateway.ot.becpl.local"
    assert tls_event.encryption_metadata.cert_valid is True


def test_suricata_alert_parser():
    parser = SuricataParser(default_sensor_id="SEC-SENSOR-01")
    suri_json = {
        "timestamp": "2026-11-17T18:00:00.543210+0000",
        "flow_id": 987654321,
        "in_iface": "eth1",
        "event_type": "alert",
        "src_ip": "10.10.10.101",
        "src_port": 49999,
        "dest_ip": "10.10.30.20",
        "dest_port": 502,
        "proto": "TCP",
        "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": 2026001,
            "rev": 1,
            "signature": "VAULTX SMT PLC Write attempt outside Engineering VLAN",
            "category": "Industrial Protocol Attack",
            "severity": 1,
        },
    }

    event = parser.parse_eve_record(suri_json)
    assert event.event_type == EventType.ALERT
    assert event.detection_source == DetectionSource.SURICATA
    assert event.severity == Severity.CRITICAL
    assert event.evidence["suricata_sid"] == 2026001
    assert event.detection_rule_version == "1:2026001:1"
    assert event.source_ip == "10.10.10.101"
    assert event.destination_ip == "10.10.30.20"


def test_suricata_flow_parser():
    parser = SuricataParser(default_sensor_id="SEC-SENSOR-01")
    suri_flow = {
        "timestamp": "2026-11-17T18:05:00.000000+0000",
        "flow_id": 11223344,
        "event_type": "flow",
        "src_ip": "10.10.20.15",
        "src_port": 8088,
        "dest_ip": "10.10.30.10",
        "dest_port": 8088,
        "proto": "TCP",
        "flow": {
            "pkts_toserver": 150,
            "pkts_toclient": 120,
            "bytes_toserver": 105000,
            "bytes_toclient": 54000,
            "start": "2026-11-17T18:04:30.000000+0000",
            "end": "2026-11-17T18:05:00.000000+0000",
            "age": 30,
            "state": "closed",
        },
    }

    event, flow = parser.parse_eve_record(suri_flow)
    assert event.bytes_transferred == 159000
    assert event.packets_transferred == 270
    assert event.connection_duration == 30000
    assert flow.orig_bytes == 105000
    assert flow.resp_bytes == 54000

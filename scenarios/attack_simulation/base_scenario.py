"""
VaultX Base Attack Scenario Generator
Author: Attack Scenarios & Dataset Engineer, VaultX NIDS Project
Enterprise: Bharat Electronics Components Pvt. Ltd. (BECPL), Pune
"""

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("vaultx.simulation.base")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")


class BaseScenario:
    """
    Abstract base class for all VaultX attack scenario simulations.
    Provides standard schemas for generating Auth, Network (Zeek/Suricata),
    and Endpoint (Sysmon) telemetry records with precise labelling.
    """

    def __init__(
        self,
        scenario_id: str,
        name: str,
        redis_client: Optional[Any] = None,
        asset_registry: Optional[Dict[str, Any]] = None,
    ):
        self.scenario_id = scenario_id
        self.name = name
        self.redis_client = redis_client
        self.asset_registry = asset_registry or {}
        self.generated_events: List[Dict[str, Any]] = []

    def generate_events(self) -> List[Dict[str, Any]]:
        """
        Generate scenario-specific sequence of labelled events.
        Must be implemented by subclasses.
        """
        raise NotImplementedError("Subclasses must implement generate_events()")

    def publish_events(
        self, events: List[Dict[str, Any]], stream: str = "events:simulation"
    ) -> int:
        """
        Publish generated events to Redis Stream or queue.
        Falls back to local logging if redis_client is unavailable.
        """
        published_count = 0
        for event in events:
            payload = json.dumps(event)
            if self.redis_client:
                try:
                    self.redis_client.xadd(stream, {"payload": payload})
                    published_count += 1
                except Exception as ex:
                    logger.warning("Failed to publish to Redis stream %s: %s", stream, ex)
            else:
                logger.debug("Simulation Event [%s]: %s", stream, payload)
                published_count += 1

        logger.info(
            "Scenario %s: Successfully emitted %d events to stream '%s'",
            self.scenario_id,
            published_count,
            stream,
        )
        return published_count

    def generate_auth_event(
        self,
        principal: str,
        source_ip: str,
        target: str,
        success: bool,
        anomalous: bool = False,
        auth_type: str = "VPN",
        geo_country: str = "IN",
        asn: str = "AS55836 (Jio Business)",
        timestamp: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Generate a standardized Authentication Event record.
        """
        ts = timestamp or datetime.now(timezone.utc).isoformat()
        event = {
            "event_id": f"AUTH-{uuid.uuid4().hex[:8].upper()}",
            "scenario_id": self.scenario_id,
            "timestamp": ts,
            "event_domain": "AUTHENTICATION",
            "principal": principal,
            "source_ip": source_ip,
            "target_system": target,
            "auth_type": auth_type,
            "success": success,
            "anomalous": anomalous,
            "is_malicious": anomalous,
            "geo_location": geo_country,
            "asn": asn,
            "label": "ATTACK" if anomalous else "BENIGN",
            "metadata": metadata or {},
        }
        self.generated_events.append(event)
        return event

    def generate_network_event(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: str,
        bytes_sent: int,
        bytes_received: int = 0,
        duration_seconds: float = 0.1,
        conn_state: str = "SF",
        anomalous: bool = False,
        protocol_details: Optional[Dict[str, Any]] = None,
        timestamp: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Generate a standardized Network Flow / Packet Event record (Zeek conn.log style).
        """
        ts = timestamp or datetime.now(timezone.utc).isoformat()
        event = {
            "event_id": f"NET-{uuid.uuid4().hex[:8].upper()}",
            "scenario_id": self.scenario_id,
            "timestamp": ts,
            "event_domain": "NETWORK",
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol.upper(),
            "duration": duration_seconds,
            "orig_bytes": bytes_sent,
            "resp_bytes": bytes_received,
            "conn_state": conn_state,
            "anomalous": anomalous,
            "is_malicious": anomalous,
            "label": "ATTACK" if anomalous else "BENIGN",
            "protocol_details": protocol_details or {},
        }
        self.generated_events.append(event)
        return event

    def generate_endpoint_event(
        self,
        host: str,
        process: str,
        cmdline: str,
        parent_process: str,
        user: str = "SYSTEM",
        event_id_sysmon: int = 1,
        anomalous: bool = False,
        timestamp: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Generate a standardized Endpoint / Sysmon Event record.
        """
        ts = timestamp or datetime.now(timezone.utc).isoformat()
        event = {
            "event_id": f"EP-{uuid.uuid4().hex[:8].upper()}",
            "scenario_id": self.scenario_id,
            "timestamp": ts,
            "event_domain": "ENDPOINT",
            "host": host,
            "sysmon_event_id": event_id_sysmon,
            "process_name": process,
            "command_line": cmdline,
            "parent_process": parent_process,
            "user": user,
            "anomalous": anomalous,
            "is_malicious": anomalous,
            "label": "ATTACK" if anomalous else "BENIGN",
            "metadata": metadata or {},
        }
        self.generated_events.append(event)
        return event

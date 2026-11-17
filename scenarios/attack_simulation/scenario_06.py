"""
Scenario 06 Simulation: Manufacturing OT Network Anomaly & Industrial Parameter Manipulation
Author: Attack Scenarios & Dataset Engineer, VaultX NIDS Project
Enterprise: Bharat Electronics Components Pvt. Ltd. (BECPL), Pune
"""

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from base_scenario import BaseScenario


class Scenario06OTAnomaly(BaseScenario):
    """
    Simulation of SCN-006: Manufacturing Network Anomaly (Safety-Critical OT Scenario).
    Simulates:
    1. Normal baseline: SMT Line A HMI (10.10.30.20) reads registers 40001-40005 from PLC (10.10.30.10) every 10s via Modbus FC3.
    2. Anomaly A: Unauthorized Engineering Station (10.10.20.30) writes to Register 40003 (conveyor speed) using Modbus FC6.
    3. Anomaly B: Unknown Rogue IP (10.10.30.95) sends Modbus FC8 (Diagnostics / Force Listen).
    4. Safety Guardrail: Includes safety flags ensuring automated disconnection is blocked without human sign-off.
    """

    def __init__(self, redis_client: Optional[Any] = None, asset_registry: Optional[Dict[str, Any]] = None):
        super().__init__(
            scenario_id="SCN-006",
            name="Manufacturing OT Network Anomaly",
            redis_client=redis_client,
            asset_registry=asset_registry,
        )

    def generate_events(self, base_time: Optional[datetime] = None) -> List[Dict[str, Any]]:
        self.generated_events.clear()
        start = base_time or datetime.now(timezone.utc).replace(hour=10, minute=30, second=0, microsecond=0)

        # 1. Normal Baseline: Regular HMI polling every 10 seconds (5 polling cycles = 10 network events)
        hmi_ip = "10.10.30.20"
        plc_ip = "10.10.30.10"

        for cycle in range(5):
            t_req = start + timedelta(seconds=cycle * 10)
            t_resp = t_req + timedelta(milliseconds=15)

            # Modbus FC3 Request
            self.generate_network_event(
                src_ip=hmi_ip,
                dst_ip=plc_ip,
                src_port=50200 + cycle,
                dst_port=502,
                protocol="TCP",
                bytes_sent=12,
                bytes_received=0,
                duration_seconds=0.015,
                conn_state="SF",
                anomalous=False,
                protocol_details={
                    "service": "modbus",
                    "unit_id": 1,
                    "function_code": 3,
                    "function_name": "Read Holding Registers",
                    "start_register": 40001,
                    "register_count": 5,
                    "safety_critical": False,
                },
                timestamp=t_req.isoformat(),
            )

            # Modbus FC3 Response (Conveyor speed is normal 120 cm/min -> 1200)
            self.generate_network_event(
                src_ip=plc_ip,
                dst_ip=hmi_ip,
                src_port=502,
                dst_port=50200 + cycle,
                protocol="TCP",
                bytes_sent=23,
                bytes_received=0,
                duration_seconds=0.005,
                conn_state="SF",
                anomalous=False,
                protocol_details={
                    "service": "modbus",
                    "unit_id": 1,
                    "function_code": 3,
                    "byte_count": 10,
                    "register_values": [1, 0, 1200, 1850 + cycle, 2450],
                    "safety_critical": False,
                },
                timestamp=t_resp.isoformat(),
            )

        # 2. Anomalous Activity 1: Cross-VLAN Unauthorized TCP Handshake from Engineering Workstation
        t_eng = start + timedelta(minutes=2, seconds=15)
        eng_ip = "10.10.20.30"

        self.generate_network_event(
            src_ip=eng_ip,
            dst_ip=plc_ip,
            src_port=49201,
            dst_port=502,
            protocol="TCP",
            bytes_sent=60,
            bytes_received=60,
            duration_seconds=0.01,
            conn_state="SF",
            anomalous=True,
            protocol_details={
                "service": "modbus_transport",
                "violation": "Cross-VLAN connection to PLC from Engineering Subnet (FW-030 deny bypass attempt)",
                "safety_critical": True,
                "human_approval_required": True,
            },
            timestamp=t_eng.isoformat(),
        )

        # 3. Anomalous Activity 2: Unauthorized Modbus FC6 (Write Single Register 40003 -> 2800)
        t_write = t_eng + timedelta(seconds=1)
        self.generate_network_event(
            src_ip=eng_ip,
            dst_ip=plc_ip,
            src_port=49201,
            dst_port=502,
            protocol="TCP",
            bytes_sent=12,
            bytes_received=0,
            duration_seconds=0.02,
            conn_state="SF",
            anomalous=True,
            protocol_details={
                "service": "modbus",
                "unit_id": 1,
                "function_code": 6,
                "function_name": "Write Single Register",
                "target_register": 40003,
                "register_meaning": "SMT Line A Conveyor Speed Setpoint",
                "written_value": 2800,
                "normal_range": [1000, 1400],
                "safety_critical": True,
                "human_approval_required": True,
                "inhibit_automated_port_shutdown": True,
                "safety_hazard": "Over-speed conveyor risk: component throw-off & reflow jam",
            },
            timestamp=t_write.isoformat(),
        )

        # 4. PLC Acknowledgement of Malicious Register Write
        self.generate_network_event(
            src_ip=plc_ip,
            dst_ip=eng_ip,
            src_port=502,
            dst_port=49201,
            protocol="TCP",
            bytes_sent=12,
            bytes_received=0,
            duration_seconds=0.005,
            conn_state="SF",
            anomalous=True,
            protocol_details={
                "service": "modbus",
                "unit_id": 1,
                "function_code": 6,
                "target_register": 40003,
                "acknowledged_value": 2800,
                "safety_critical": True,
                "human_approval_required": True,
            },
            timestamp=(t_write + timedelta(milliseconds=12)).isoformat(),
        )

        # 5. Subsequent HMI Read showing altered value (Alarms on HMI console)
        t_hmi_alert = t_write + timedelta(seconds=8)
        self.generate_network_event(
            src_ip=hmi_ip,
            dst_ip=plc_ip,
            src_port=50210,
            dst_port=502,
            protocol="TCP",
            bytes_sent=12,
            bytes_received=23,
            duration_seconds=0.012,
            conn_state="SF",
            anomalous=False,
            protocol_details={
                "service": "modbus",
                "unit_id": 1,
                "function_code": 3,
                "register_values": [1, 2, 2800, 1855, 2450],
                "hmi_status": "ALARM_SPEED_DEVIATION_HIGH",
            },
            timestamp=t_hmi_alert.isoformat(),
        )

        # 6. Anomalous Activity 3: Rogue IP probing PLC with Modbus FC8 (Diagnostics)
        t_fc8 = start + timedelta(minutes=4, seconds=30)
        rogue_ip = "10.10.30.95"

        self.generate_network_event(
            src_ip=rogue_ip,
            dst_ip=plc_ip,
            src_port=55102,
            dst_port=502,
            protocol="TCP",
            bytes_sent=14,
            bytes_received=0,
            duration_seconds=0.01,
            conn_state="SF",
            anomalous=True,
            protocol_details={
                "service": "modbus",
                "unit_id": 1,
                "function_code": 8,
                "function_name": "Diagnostics",
                "sub_function": 4,
                "sub_function_name": "Force Listen Only Mode",
                "safety_critical": True,
                "human_approval_required": True,
                "threat_type": "PLC denial of telemetry / stealth mode injection",
            },
            timestamp=t_fc8.isoformat(),
        )

        # 7. Diagnostic Response
        self.generate_network_event(
            src_ip=plc_ip,
            dst_ip=rogue_ip,
            src_port=502,
            dst_port=55102,
            protocol="TCP",
            bytes_sent=14,
            bytes_received=0,
            duration_seconds=0.005,
            conn_state="SF",
            anomalous=True,
            protocol_details={
                "service": "modbus",
                "function_code": 8,
                "status": "Diagnostic acknowledged",
                "safety_critical": True,
            },
            timestamp=(t_fc8 + timedelta(milliseconds=10)).isoformat(),
        )

        # 8. OT Safety Guardrail Interlock Event
        t_guardrail = t_fc8 + timedelta(seconds=5)
        guardrail_event = {
            "event_id": f"SAFETY-{t_guardrail.strftime('%H%M%S')}",
            "scenario_id": self.scenario_id,
            "timestamp": t_guardrail.isoformat(),
            "event_domain": "OT_SAFETY_INTERLOCK",
            "target_system": "OT-PLC-SMTA-01 (10.10.30.10)",
            "action_attempted": "CONTAINMENT_SWITCHPORT_SHUTDOWN",
            "action_status": "INHIBITED_BY_SAFETY_POLICY",
            "inhibit_reason": "Industrial safety rule: Automated port shutdown on SMT production line PLC is forbidden",
            "required_approval": "TWO_MAN_RULE (Plant Manager + Security Lead)",
            "is_malicious": False,
            "label": "SAFETY_GUARDRAIL",
            "metadata": {
                "active_line": "SMT Line A",
                "current_product": "IoT Smart Sensor PCB Batch #78",
                "estimated_line_halt_loss_inr": 2500000,
                "dispatch_notification_to": ["plant_ops_pager@becpl.internal", "ciso_pager@becpl.internal"],
            },
        }
        self.generated_events.append(guardrail_event)

        return self.generated_events


if __name__ == "__main__":
    sim = Scenario06OTAnomaly()
    events = sim.generate_events()
    print(f"Generated {len(events)} events for Scenario 06 (OT Anomaly).")
    malicious = [e for e in events if e.get("is_malicious")]
    guardrails = [e for e in events if e.get("event_domain") == "OT_SAFETY_INTERLOCK"]
    print(f"Malicious events: {len(malicious)} | Guardrail events: {len(guardrails)} | Total: {len(events)}")
    sim.publish_events(events)
    print("Sample Guardrail Interlock Event:\n", json.dumps(guardrails[0], indent=2))

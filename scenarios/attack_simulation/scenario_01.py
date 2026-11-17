"""
Scenario 01 Simulation: Compromised Third-Party Vendor Access
Author: Attack Scenarios & Dataset Engineer, VaultX NIDS Project
Enterprise: Bharat Electronics Components Pvt. Ltd. (BECPL), Pune
"""

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from base_scenario import BaseScenario


class Scenario01VendorCompromise(BaseScenario):
    """
    Simulation of SCN-001: Compromised Third-Party Vendor Access.
    Follows attack path:
    1. Foreign/Off-hours SSL-VPN login (techmaintain_ext_eng)
    2. SSH login to DMZ Bastion (DMZ-BASTION01)
    3. Cross-VLAN pivot to Manufacturing Execution System (OT-MES01)
    4. Modbus reconnaissance and setpoint interrogation on SMT Line A PLC (OT-PLC-SMTA-01)
    """

    def __init__(self, redis_client: Optional[Any] = None, asset_registry: Optional[Dict[str, Any]] = None):
        super().__init__(
            scenario_id="SCN-001",
            name="Compromised Third-Party Vendor Access",
            redis_client=redis_client,
            asset_registry=asset_registry,
        )

    def generate_events(self, base_time: Optional[datetime] = None) -> List[Dict[str, Any]]:
        self.generated_events.clear()
        start = base_time or datetime.now(timezone.utc).replace(hour=2, minute=15, second=0, microsecond=0)

        # Baseline Benign Periodic Events during same window
        # 1. Normal NTP sync from Domain Controller to internal master
        self.generate_network_event(
            src_ip="10.10.10.2",
            dst_ip="10.10.70.10",
            src_port=123,
            dst_port=123,
            protocol="UDP",
            bytes_sent=76,
            bytes_received=76,
            duration_seconds=0.01,
            conn_state="SF",
            anomalous=False,
            protocol_details={"service": "ntp", "stratum": 2},
            timestamp=(start + timedelta(minutes=1)).isoformat(),
        )

        # 2. Normal ERP to DB heartbeat
        self.generate_network_event(
            src_ip="10.10.10.10",
            dst_ip="10.10.10.4",
            src_port=54322,
            dst_port=445,
            protocol="TCP",
            bytes_sent=450,
            bytes_received=1200,
            duration_seconds=0.15,
            conn_state="SF",
            anomalous=False,
            protocol_details={"service": "smb", "share": "ERP_DATA"},
            timestamp=(start + timedelta(minutes=2)).isoformat(),
        )

        # --- ATTACK CHAIN BEGINS ---
        # 3. Off-hours VPN authentication from foreign ASN (Tor exit node / Russian VPS)
        self.generate_auth_event(
            principal="techmaintain_ext_eng",
            source_ip="185.220.101.45",
            target="DMZ-VPN-GW01 (10.10.50.10)",
            success=True,
            anomalous=True,
            auth_type="SSL-VPN-FORTICLIENT",
            geo_country="NL",
            asn="AS208323 (Hosting Provider / Tor Exit)",
            timestamp=(start + timedelta(minutes=3, seconds=10)).isoformat(),
            metadata={
                "assigned_tunnel_ip": "10.10.50.112",
                "vendor_org": "TechMaintain Solutions Pvt. Ltd.",
                "policy_window": "09:00-18:00 IST",
                "risk_reason": "Off-hours login outside authorized maintenance window from foreign ASN",
            },
        )

        # 4. VPN session establishment network flow
        self.generate_network_event(
            src_ip="185.220.101.45",
            dst_ip="103.25.68.2",
            src_port=49152,
            dst_port=443,
            protocol="TCP",
            bytes_sent=15420,
            bytes_received=38200,
            duration_seconds=120.0,
            conn_state="SF",
            anomalous=True,
            protocol_details={"service": "ssl_vpn", "tunnel_id": "tun0-50112"},
            timestamp=(start + timedelta(minutes=3, seconds=15)).isoformat(),
        )

        # 5. SSH connection from leased VPN IP to DMZ Bastion Host
        self.generate_network_event(
            src_ip="10.10.50.112",
            dst_ip="10.10.50.2",
            src_port=51224,
            dst_port=22,
            protocol="TCP",
            bytes_sent=2840,
            bytes_received=4510,
            duration_seconds=45.0,
            conn_state="SF",
            anomalous=True,
            protocol_details={"service": "ssh", "auth_method": "publickey+password"},
            timestamp=(start + timedelta(minutes=5, seconds=0)).isoformat(),
        )

        # 6. Syslog auth event on DMZ Bastion
        self.generate_auth_event(
            principal="techmaintain_ext_eng",
            source_ip="10.10.50.112",
            target="DMZ-BASTION01",
            success=True,
            anomalous=True,
            auth_type="SSH-KEY",
            geo_country="IN (Internal Subnet)",
            asn="Internal-DMZ",
            timestamp=(start + timedelta(minutes=5, seconds=5)).isoformat(),
            metadata={"session_id": "pts/2", "auth_user": "techmaintain_ext_eng"},
        )

        # 7. Benign DNS query from Bastion
        self.generate_network_event(
            src_ip="10.10.50.2",
            dst_ip="10.10.10.5",
            src_port=49812,
            dst_port=53,
            protocol="UDP",
            bytes_sent=68,
            bytes_received=124,
            duration_seconds=0.005,
            conn_state="SF",
            anomalous=False,
            protocol_details={"query": "ot-mes01.becpl.internal", "qtype": "A"},
            timestamp=(start + timedelta(minutes=8, seconds=10)).isoformat(),
        )

        # 8. Cross-VLAN pivot: Unauthorized SSH connection from DMZ Bastion to MES Server
        self.generate_network_event(
            src_ip="10.10.50.2",
            dst_ip="10.10.30.3",
            src_port=53412,
            dst_port=22,
            protocol="TCP",
            bytes_sent=18200,
            bytes_received=24100,
            duration_seconds=300.0,
            conn_state="SF",
            anomalous=True,
            protocol_details={
                "service": "ssh",
                "policy_violation": "FW-053: DMZ to OT VLAN direct connection prohibited",
            },
            timestamp=(start + timedelta(minutes=9, seconds=0)).isoformat(),
        )

        # 9. Endpoint execution on OT-MES01: Lateral tool transfer & extraction
        self.generate_endpoint_event(
            host="OT-MES01 (10.10.30.3)",
            process="scp",
            cmdline="scp -t /tmp/recon_modbus.py",
            parent_process="sshd: techmaintain_ext_eng@pts/0",
            user="techmaintain_ext_eng",
            event_id_sysmon=1,
            anomalous=True,
            timestamp=(start + timedelta(minutes=12, seconds=30)).isoformat(),
            metadata={"file_dropped": "/tmp/recon_modbus.py", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
        )

        # 10. Python execution of Modbus scan script on MES server
        self.generate_endpoint_event(
            host="OT-MES01 (10.10.30.3)",
            process="python3",
            cmdline="python3 /tmp/recon_modbus.py --target 10.10.30.0/24 --ports 502",
            parent_process="bash",
            user="techmaintain_ext_eng",
            event_id_sysmon=1,
            anomalous=True,
            timestamp=(start + timedelta(minutes=16, seconds=0)).isoformat(),
        )

        # 11. Ping sweep discovery across OT VLAN (Zeek ICMP log)
        for i, target_ip in enumerate(["10.10.30.1", "10.10.30.10", "10.10.30.11", "10.10.30.20"]):
            self.generate_network_event(
                src_ip="10.10.30.3",
                dst_ip=target_ip,
                src_port=0,
                dst_port=0,
                protocol="ICMP",
                bytes_sent=64,
                bytes_received=64,
                duration_seconds=0.002,
                conn_state="OTH",
                anomalous=True,
                protocol_details={"icmp_type": 8, "icmp_code": 0, "recon_type": "sweep"},
                timestamp=(start + timedelta(minutes=16, seconds=10 + i * 2)).isoformat(),
            )

        # 12. Legitimate HMI polling to PLC (interleaved benign traffic)
        self.generate_network_event(
            src_ip="10.10.30.20",
            dst_ip="10.10.30.10",
            src_port=50201,
            dst_port=502,
            protocol="TCP",
            bytes_sent=12,
            bytes_received=25,
            duration_seconds=0.015,
            conn_state="SF",
            anomalous=False,
            protocol_details={"service": "modbus", "fc": 3, "registers": [40001, 40005]},
            timestamp=(start + timedelta(minutes=20, seconds=0)).isoformat(),
        )

        # 13. Unauthorized Modbus Connection Attempt to SMT Line A PLC (10.10.30.10 / 172.20.30.12)
        self.generate_network_event(
            src_ip="10.10.30.3",
            dst_ip="10.10.30.10",
            src_port=48102,
            dst_port=502,
            protocol="TCP",
            bytes_sent=60,
            bytes_received=60,
            duration_seconds=0.005,
            conn_state="SF",
            anomalous=True,
            protocol_details={
                "service": "modbus",
                "unit_id": 1,
                "function_code": 3,
                "start_addr": 40001,
                "quantity": 10,
                "violation": "Unauthorized Modbus client IP. MES server not authorized for direct Modbus queries",
            },
            timestamp=(start + timedelta(minutes=22, seconds=15)).isoformat(),
        )

        # 14. Modbus response from PLC back to MES server
        self.generate_network_event(
            src_ip="10.10.30.10",
            dst_ip="10.10.30.3",
            src_port=502,
            dst_port=48102,
            protocol="TCP",
            bytes_sent=35,
            bytes_received=12,
            duration_seconds=0.005,
            conn_state="SF",
            anomalous=True,
            protocol_details={
                "service": "modbus",
                "function_code": 3,
                "byte_count": 20,
                "data": "0001000004b0073a0992",
            },
            timestamp=(start + timedelta(minutes=22, seconds=16)).isoformat(),
        )

        # 15. Modbus FC16 Write Attempt to change speed parameter
        self.generate_network_event(
            src_ip="10.10.30.3",
            dst_ip="10.10.30.10",
            src_port=48110,
            dst_port=502,
            protocol="TCP",
            bytes_sent=75,
            bytes_received=60,
            duration_seconds=0.008,
            conn_state="SF",
            anomalous=True,
            protocol_details={
                "service": "modbus",
                "unit_id": 1,
                "function_code": 16,
                "start_addr": 40003,
                "val": [2500],
                "threat_type": "Unauthorized setpoint modification attempt",
            },
            timestamp=(start + timedelta(minutes=28, seconds=0)).isoformat(),
        )

        # 16. Legitimate periodic Syslog push from OT Gateway to Security Manager
        self.generate_network_event(
            src_ip="10.10.30.2",
            dst_ip="10.10.70.2",
            src_port=514,
            dst_port=514,
            protocol="UDP",
            bytes_sent=310,
            bytes_received=0,
            duration_seconds=0.001,
            conn_state="OTH",
            anomalous=False,
            protocol_details={"service": "syslog", "facility": "daemon"},
            timestamp=(start + timedelta(minutes=30, seconds=0)).isoformat(),
        )

        # 17. VaultX Mitigation Response: FortiGate API VPN Session Invalidation
        self.generate_network_event(
            src_ip="10.10.70.3",
            dst_ip="10.10.50.10",
            src_port=52340,
            dst_port=8443,
            protocol="TCP",
            bytes_sent=420,
            bytes_received=150,
            duration_seconds=0.05,
            conn_state="SF",
            anomalous=False,
            protocol_details={"service": "https", "action": "POST /api/v2/monitor/vpn/ssl/kill_session"},
            timestamp=(start + timedelta(minutes=30, seconds=20)).isoformat(),
        )

        # 18. VaultX Mitigation Response: Active Directory user disable
        self.generate_network_event(
            src_ip="10.10.70.3",
            dst_ip="10.10.10.2",
            src_port=52342,
            dst_port=636,
            protocol="TCP",
            bytes_sent=820,
            bytes_received=340,
            duration_seconds=0.08,
            conn_state="SF",
            anomalous=False,
            protocol_details={"service": "ldaps", "action": "modify userAccountControl: ACCOUNTDISABLE"},
            timestamp=(start + timedelta(minutes=30, seconds=22)).isoformat(),
        )

        return self.generated_events


if __name__ == "__main__":
    sim = Scenario01VendorCompromise()
    events = sim.generate_events()
    print(f"Generated {len(events)} events for Scenario 01.")
    malicious = [e for e in events if e.get("is_malicious")]
    print(f"Malicious events: {len(malicious)} | Benign events: {len(events) - len(malicious)}")
    sim.publish_events(events)
    print("Sample Event:\n", json.dumps(events[2], indent=2))

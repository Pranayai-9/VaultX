#!/usr/bin/env python3
"""
VaultX — Normal Background Traffic Generator
Bharat Electronics Components Pvt. Ltd. (BECPL), Pune

Generates realistic normal baseline traffic between simulated hosts:
- DNS queries (A records for internal hostnames like erp.becpl.internal, cad.becpl.internal)
- HTTP/REST requests between services (ERP -> DB, WMS -> Inventory API)
- SSH administrative sessions and keepalives (SecOps Jump host -> Engineering)
- Modbus TCP register polling (SCADA HMI -> OT PLCs: Holding register reads FC 0x03)
- SMB / File server access (Engineering CAD files, Corporate reports)

Labels each event:
  "traffic_type": "legitimate"
  "label": "benign"

Emits to Redis stream 'events:simulation'. Supports live packet crafting (Scapy)
with graceful fallback to structured network flow simulation.
"""

import os
import sys
import time
import json
import random
import socket
import logging
import argparse
from datetime import datetime, timezone
from typing import Dict, Any, List

try:
    import redis
except ImportError:
    redis = None

try:
    from scapy.all import IP, TCP, UDP, DNS, DNSQR, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [NormalTrafficGen] %(message)s"
)
logger = logging.getLogger("normal_traffic")

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
STREAM_NAME = "events:simulation"

# BECPL Asset Definitions for Traffic Simulation
HOSTS = {
    "dns_server": "172.20.10.2",
    "erp_server": "172.20.10.20",
    "erp_clients": [f"172.20.10.{i}" for i in range(101, 115)],
    "file_server": "172.20.10.25",
    "eda_workstations": [f"172.20.20.{i}" for i in range(10, 20)],
    "firmware_repo": "172.20.20.30",
    "scada_hmi": "172.20.30.10",
    "ot_plcs": ["172.20.30.20", "172.20.30.21", "172.20.30.22", "172.20.30.23"],
    "wms_server": "172.20.40.20",
    "barcode_scanners": [f"172.20.40.{i}" for i in range(101, 110)],
    "secops_bastion": "172.20.70.15"
}

INTERNAL_DOMAINS = [
    "erp.becpl.internal",
    "mes-gw.becpl.internal",
    "firmware.becpl.internal",
    "wms-scanner.becpl.internal",
    "cad-vault.becpl.internal",
    "dns.becpl.internal"
]

class NormalTrafficGenerator:
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
                logger.info(f"Connected to Redis for simulation stream '{self.stream_name}'")
            except Exception as e:
                logger.warning(f"Redis connection failed: {e}. Outputting to stdout.")
                self.r = None

    def publish(self, event: Dict[str, Any]):
        event["traffic_type"] = "legitimate"
        event["label"] = "benign"
        event["simulation_timestamp"] = datetime.now(timezone.utc).isoformat()

        if self.r:
            try:
                self.r.xadd(self.stream_name, {"event": json.dumps(event)}, maxlen=100000, approximate=True)
            except Exception as e:
                logger.error(f"Redis publish error: {e}")
        else:
            print(json.dumps(event))

    def generate_dns_traffic(self) -> Dict[str, Any]:
        src_ip = random.choice(HOSTS["erp_clients"] + HOSTS["eda_workstations"])
        dst_ip = HOSTS["dns_server"]
        qname = random.choice(INTERNAL_DOMAINS)
        tx_id = random.randint(1000, 65000)

        return {
            "protocol": "DNS",
            "transport": "UDP",
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": random.randint(49152, 65535),
            "dst_port": 53,
            "dns_query": qname,
            "qtype": "A",
            "transaction_id": tx_id,
            "response_code": "NOERROR",
            "response_ip": f"172.20.{random.choice([10, 20, 30])}.{random.randint(10, 50)}",
            "bytes": random.randint(64, 128)
        }

    def generate_http_traffic(self) -> Dict[str, Any]:
        # ERP client talking to ERP web server or WMS scanner to WMS
        is_wms = random.random() < 0.35
        if is_wms:
            src = random.choice(HOSTS["barcode_scanners"])
            dst = HOSTS["wms_server"]
            path = f"/api/inventory/scan?bin=A{random.randint(1,9)}-{random.randint(10,99)}"
            method = "POST"
        else:
            src = random.choice(HOSTS["erp_clients"])
            dst = HOSTS["erp_server"]
            path = random.choice(["/erp/dashboard", "/erp/inventory/items", "/erp/production/orders", "/erp/reports"])
            method = "GET"

        return {
            "protocol": "HTTP",
            "transport": "TCP",
            "src_ip": src,
            "dst_ip": dst,
            "src_port": random.randint(49152, 65535),
            "dst_port": 80,
            "http_method": method,
            "uri": path,
            "http_status": 200,
            "response_time_ms": random.randint(12, 85),
            "bytes_sent": random.randint(300, 1200),
            "bytes_received": random.randint(800, 15000)
        }

    def generate_ssh_traffic(self) -> Dict[str, Any]:
        # SecOps Bastion managing Engineering or ERP node
        src = HOSTS["secops_bastion"]
        dst = random.choice([HOSTS["firmware_repo"], HOSTS["erp_server"]] + HOSTS["eda_workstations"][:3])
        return {
            "protocol": "SSH",
            "transport": "TCP",
            "src_ip": src,
            "dst_ip": dst,
            "src_port": random.randint(49152, 65535),
            "dst_port": 22,
            "ssh_version": "SSH-2.0-OpenSSH_8.9p1",
            "auth_type": "publickey",
            "session_duration_s": random.randint(60, 1800),
            "bytes": random.randint(4096, 500000)
        }

    def generate_modbus_traffic(self) -> Dict[str, Any]:
        # SCADA HMI regularly polling OT PLCs for sensor and motor telemetry
        src = HOSTS["scada_hmi"]
        dst = random.choice(HOSTS["ot_plcs"])
        start_reg = random.choice([1000, 2000, 3000, 4000])
        count = random.randint(2, 20)

        return {
            "protocol": "MODBUS_TCP",
            "transport": "TCP",
            "src_ip": src,
            "dst_ip": dst,
            "src_port": random.randint(49152, 65535),
            "dst_port": 502,
            "unit_id": 1,
            "function_code": 3,
            "function_name": "Read Holding Registers",
            "start_register": start_reg,
            "register_count": count,
            "is_authorized": True,
            "status": "SUCCESS",
            "bytes": 64
        }

    def generate_file_server_traffic(self) -> Dict[str, Any]:
        # EDA Workstation pulling schematic/Gerber files from file server
        src = random.choice(HOSTS["eda_workstations"] + HOSTS["erp_clients"][:3])
        dst = HOSTS["file_server"]
        return {
            "protocol": "SMB",
            "transport": "TCP",
            "src_ip": src,
            "dst_ip": dst,
            "src_port": random.randint(49152, 65535),
            "dst_port": 445,
            "share_name": "\\\\CORP-FS-01\\cad_designs",
            "action": "SMB2_CREATE_READ",
            "bytes": random.randint(50000, 8000000)
        }

    def run(self, rate_hz: float = 4.0, count: int = 0):
        logger.info(f"Generating benign network traffic at {rate_hz} Hz...")
        generators = [
            (self.generate_dns_traffic, 0.25),
            (self.generate_http_traffic, 0.40),
            (self.generate_modbus_traffic, 0.20),
            (self.generate_ssh_traffic, 0.05),
            (self.generate_file_server_traffic, 0.10)
        ]
        
        sleep_dur = 1.0 / max(0.1, rate_hz)
        generated = 0

        try:
            while True:
                r = random.random()
                accum = 0.0
                fn = generators[0][0]
                for g_fn, weight in generators:
                    accum += weight
                    if r <= accum:
                        fn = g_fn
                        break

                event = fn()
                self.publish(event)
                generated += 1

                if count > 0 and generated >= count:
                    logger.info(f"Generated {generated} benign traffic events.")
                    break

                time.sleep(sleep_dur)
        except KeyboardInterrupt:
            logger.info("Traffic generation terminated.")

def main():
    parser = argparse.ArgumentParser(description="VaultX Normal Background Traffic Generator")
    parser.add_argument("--redis", default=REDIS_URL, help="Redis URL")
    parser.add_argument("--rate", type=float, default=5.0, help="Events per second")
    parser.add_argument("--count", type=int, default=0, help="Number of events (0 for continuous)")
    args = parser.parse_args()

    gen = NormalTrafficGenerator(args.redis)
    gen.run(args.rate, args.count)

if __name__ == "__main__":
    main()

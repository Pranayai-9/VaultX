#!/usr/bin/env python3
"""
VaultX — Third-Party Telemetry Simulator
Bharat Electronics Components Pvt. Ltd. (BECPL), Pune

Simulates realistic external & third-party identity telemetry streams:
1. SSL-VPN Authentication Events (FortiGate / OpenVPN format):
   - External vendors (PrecisionTech SMT Maintenance, BlueDart Logistics)
   - Successful MFA logins vs repeated credential stuffing / off-hours logins.
2. API Gateway Logs (Kong / Envoy format):
   - Supplier component catalogs, order status webhooks, EDI integrations.
   - HTTP methods, response codes, token scopes, rate limiting headers.
3. Machine / Service Account Activity Logs:
   - ERP batch synchronization (svc-erp-sync), Automated CAD build pipelines.
   - Normal periodic scheduled jobs vs anomalous high-privilege resource queries.
4. Cloud Audit Events (AWS CloudTrail / Azure Activity Log format):
   - S3 bucket read/write of PCB Gerber files and manufacturing specs.
   - IAM role assumptions, KMS decryption requests.

Publishes all events to Redis Stream: 'events:third_party'
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
    format="%(asctime)s [%(levelname)s] [ThirdPartySim] %(message)s"
)
logger = logging.getLogger("third_party_sim")

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
STREAM_NAME = "events:third_party"

VENDORS = [
    {"id": "VEND-SMT-MAINT", "name": "PrecisionTech SMT Maintenance", "ip": "203.0.113.45", "user": "maint_tech_rajesh"},
    {"id": "VEND-LOGISTICS-01", "name": "BlueDart Express API Integration", "ip": "198.51.100.12", "user": "api_bluedart_sync"},
    {"id": "VEND-FIRMWARE-DEV", "name": "Cygnus Embedded Labs Pune", "ip": "115.112.44.89", "user": "dev_consultant_amit"},
    {"id": "VEND-HVAC-CHILLER", "name": "Voltas Industrial HVAC Facility", "ip": "182.74.15.220", "user": "facility_iot_agent"}
]

SERVICE_ACCOUNTS = [
    {"name": "svc_erp_mes_sync", "purpose": "ERP to MES batch sync", "normal_hour_start": 6, "normal_hour_end": 22},
    {"name": "svc_cad_build_pipeline", "purpose": "EDA layout automated checks", "normal_hour_start": 8, "normal_hour_end": 19},
    {"name": "svc_backup_s3_uploader", "purpose": "Offsite encrypted backup", "normal_hour_start": 1, "normal_hour_end": 4},
    {"name": "svc_db_replication", "purpose": "Secondary DB streaming", "normal_hour_start": 0, "normal_hour_end": 24}
]

class ThirdPartyTelemetrySimulator:
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
                logger.info(f"Connected to Redis stream '{self.stream_name}' at {self.redis_url}")
            except Exception as e:
                logger.warning(f"Redis unavailable ({e}); running in console output mode.")
                self.r = None

    def publish(self, event_data: Dict[str, Any]):
        serialized = {"event": json.dumps(event_data)}
        if self.r:
            try:
                self.r.xadd(self.stream_name, serialized, maxlen=50000, approximate=True)
            except Exception as e:
                logger.error(f"Redis publish failure: {e}")
        else:
            print(json.dumps(event_data))

    def generate_vpn_event(self, anomalous: bool = False) -> Dict[str, Any]:
        vendor = random.choice(VENDORS)
        now_iso = datetime.now(timezone.utc).isoformat()

        if anomalous:
            status = "FAILED"
            reason = random.choice(["INVALID_MFA_TOKEN", "ACCOUNT_LOCKED_OUT", "IP_GEO_MISMATCH", "OUTSIDE_MAINTENANCE_WINDOW"])
            assigned_ip = "0.0.0.0"
            duration = 0
            bytes_xfer = 0
        else:
            status = "SUCCESS"
            reason = "MFA_VERIFIED"
            assigned_ip = f"172.20.50.{random.randint(100, 150)}"
            duration = random.randint(300, 7200)
            bytes_xfer = random.randint(50000, 15000000)

        return {
            "telemetry_type": "third_party_vpn",
            "timestamp": now_iso,
            "session_id": str(uuid.uuid4())[:8],
            "vendor_id": vendor["id"],
            "vendor_name": vendor["name"],
            "username": vendor["user"],
            "src_ip": vendor["ip"],
            "assigned_tunnel_ip": assigned_ip,
            "auth_status": status,
            "auth_reason": reason,
            "duration_seconds": duration,
            "bytes_transferred": bytes_xfer,
            "mfa_method": "TOTP_HARD_TOKEN",
            "is_anomaly": anomalous
        }

    def generate_api_gateway_log(self, anomalous: bool = False) -> Dict[str, Any]:
        vendor = random.choice(VENDORS)
        now_iso = datetime.now(timezone.utc).isoformat()
        
        endpoints = [
            ("/api/v1/logistics/dispatch-status", "GET", 200),
            ("/api/v1/inventory/component-stock", "GET", 200),
            ("/api/v1/manufacturing/line-telemetry", "POST", 201),
            ("/api/v1/orders/webhook", "POST", 200)
        ]
        
        if anomalous:
            path, method, _ = random.choice([
                ("/api/v1/admin/export-all-firmware", "GET", 403),
                ("/api/v1/auth/internal-tokens", "GET", 401),
                ("/api/v1/plc/raw-register-write", "POST", 403),
                ("/api/v1/database/backup.sql", "GET", 404)
            ])
            status_code = random.choice([401, 403, 404, 429])
            latency_ms = random.randint(5, 50)
        else:
            path, method, status_code = random.choice(endpoints)
            latency_ms = random.randint(25, 250)

        return {
            "telemetry_type": "api_gateway_access",
            "timestamp": now_iso,
            "request_id": f"req-{uuid.uuid4().hex[:12]}",
            "client_id": vendor["id"],
            "client_ip": vendor["ip"],
            "method": method,
            "uri_path": path,
            "status_code": status_code,
            "latency_ms": latency_ms,
            "user_agent": "BECPL-VendorAPI-Agent/2.4",
            "is_anomaly": anomalous
        }

    def generate_service_account_activity(self, anomalous: bool = False) -> Dict[str, Any]:
        sa = random.choice(SERVICE_ACCOUNTS)
        now_iso = datetime.now(timezone.utc).isoformat()

        if anomalous:
            action = "UNAUTHORIZED_SENSITIVE_DATA_EXPORT"
            target_resource = "s3://becpl-confidential-patents/gerber_rev4.zip"
            status = "DENIED_BY_POLICY"
        else:
            action = "SCHEDULED_BATCH_SYNC"
            target_resource = f"internal-db://erp-prod/inventory_items_{random.randint(1, 10)}"
            status = "COMPLETED"

        return {
            "telemetry_type": "service_account_log",
            "timestamp": now_iso,
            "service_account": sa["name"],
            "purpose": sa["purpose"],
            "action": action,
            "target_resource": target_resource,
            "status": status,
            "execution_node": "corp-srv-mes01.becpl.internal",
            "is_anomaly": anomalous
        }

    def generate_cloud_audit_event(self, anomalous: bool = False) -> Dict[str, Any]:
        now_iso = datetime.now(timezone.utc).isoformat()
        if anomalous:
            event_name = "PutBucketPolicy"
            user_identity = "arn:aws:iam::123456789012:user/vendor-contractor"
            source_ip = "185.220.101.5" # Tor or unusual external IP
            err_code = "AccessDenied"
        else:
            event_name = "GetObject"
            user_identity = "arn:aws:iam::123456789012:role/becpl-s3-backup-role"
            source_ip = "172.20.70.10"
            err_code = None

        return {
            "telemetry_type": "cloud_audit",
            "timestamp": now_iso,
            "event_source": "s3.amazonaws.com",
            "event_name": event_name,
            "aws_region": "ap-south-1", # AWS Asia Pacific (Mumbai)
            "user_identity": user_identity,
            "source_ip": source_ip,
            "error_code": err_code,
            "bucket_name": "becpl-eda-firmware-vault",
            "is_anomaly": anomalous
        }

    def run_simulation(self, event_rate_hz: float = 2.0, count: int = 0, anomaly_ratio: float = 0.05):
        logger.info(f"Starting Third-Party Telemetry stream at {event_rate_hz} Hz (anomaly ratio: {anomaly_ratio:.1%})...")
        generated = 0
        sleep_dur = 1.0 / max(0.1, event_rate_hz)

        try:
            while True:
                is_anomaly = (random.random() < anomaly_ratio)
                choice = random.choice(["vpn", "api", "service_account", "cloud"])

                if choice == "vpn":
                    ev = self.generate_vpn_event(is_anomaly)
                elif choice == "api":
                    ev = self.generate_api_gateway_log(is_anomaly)
                elif choice == "service_account":
                    ev = self.generate_service_account_activity(is_anomaly)
                else:
                    ev = self.generate_cloud_audit_event(is_anomaly)

                self.publish(ev)
                generated += 1

                if count > 0 and generated >= count:
                    logger.info(f"Finished generating {generated} third-party events.")
                    break

                time.sleep(sleep_dur)
        except KeyboardInterrupt:
            logger.info("Simulation halted by operator.")

def main():
    parser = argparse.ArgumentParser(description="VaultX Third-Party Telemetry Simulator")
    parser.add_argument("--redis", default=REDIS_URL, help="Redis URL")
    parser.add_argument("--rate", type=float, default=2.0, help="Events per second")
    parser.add_argument("--count", type=int, default=0, help="Total events (0 for continuous)")
    parser.add_argument("--anomaly-ratio", type=float, default=0.08, help="Ratio of anomalous/attack events")
    args = parser.parse_args()

    sim = ThirdPartyTelemetrySimulator(args.redis)
    sim.run_simulation(args.rate, args.count, args.anomaly_ratio)

if __name__ == "__main__":
    main()

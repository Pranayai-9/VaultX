"""
BECPL Manufacturing-Aware Synthetic Traffic Generator
Author: Attack Scenarios & Dataset Engineer, VaultX NIDS Project
Enterprise: Bharat Electronics Components Pvt. Ltd. (BECPL), Pune
"""

import argparse
import csv
import hashlib
import logging
import math
import os
import random
import sys
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Tuple

logger = logging.getLogger("vaultx.traffic_gen")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# BECPL Network Asset Reference
CORP_DCS = ["10.10.10.2", "10.10.10.3"]
CORP_FS = "10.10.10.4"
CORP_DNS = "10.10.10.5"
CORP_WORKSTATIONS = [f"10.10.10.{i}" for i in range(20, 36)]
ENG_BUILD_SVR = "10.10.20.2"
ENG_GIT_SVR = "10.10.20.3"
ENG_OTA_SVR = "10.10.20.4"
ENG_NAS = "10.10.20.6"
ENG_WORKSTATIONS = [f"10.10.20.{i}" for i in range(10, 16)]
OT_SCADA = "10.10.30.2"
OT_MES = "10.10.30.3"
OT_PLCS = ["10.10.30.10", "10.10.30.11", "10.10.30.12", "10.10.30.13", "10.10.30.14"]
OT_HMIS = ["10.10.30.20", "10.10.30.21", "10.10.30.22"]
WH_WMS = "10.10.40.2"
WH_SCANNERS = [f"10.10.40.{i}" for i in range(10, 15)]
DMZ_BASTION = "10.10.50.2"
DMZ_VPN_GW = "10.10.50.10"
CLOUD_PROXY = "10.10.60.2"
SEC_SIEM = "10.10.70.2"
SEC_NTP = "10.10.70.10"

EXTERNAL_IPS = [
    "103.25.68.1", "140.82.121.4", "185.196.8.121", "185.220.101.45",
    "45.142.214.88", "194.38.20.14", "8.8.8.8", "1.1.1.1"
]

COLUMNS = [
    "flow_id",
    "timestamp",
    "source_ip",
    "destination_ip",
    "source_port",
    "destination_port",
    "protocol",
    "connection_duration",
    "total_fwd_packets",
    "total_bwd_packets",
    "total_fwd_bytes",
    "total_bwd_bytes",
    "packets_transferred",
    "bytes_transferred",
    "flow_bytes_per_sec",
    "flow_packets_per_sec",
    "source_vlan",
    "destination_vlan",
    "identity_classification",
    "label",
    "binary_label",
]


def get_vlan(ip: str) -> int:
    if ip.startswith("10.10.10."):
        return 10
    elif ip.startswith("10.10.20."):
        return 20
    elif ip.startswith("10.10.30."):
        return 30
    elif ip.startswith("10.10.40."):
        return 40
    elif ip.startswith("10.10.50."):
        return 50
    elif ip.startswith("10.10.60."):
        return 60
    elif ip.startswith("10.10.70."):
        return 70
    return 0  # External or internet


def make_flow_id(src: str, dst: str, sport: int, dport: int, proto: str, ts: str) -> str:
    raw = f"{src}-{dst}-{sport}-{dport}-{proto}-{ts}"
    return hashlib.md5(raw.encode("utf-8")).hexdigest()[:16]


def generate_normal_record(base_time: datetime) -> Dict[str, Any]:
    """Generates realistic normal manufacturing/enterprise traffic record."""
    traffic_type = random.choices(
        ["MODBUS_READ", "ERP_API", "DNS_QUERY", "SMB_FILE", "CICD_BUILD", "NTP_SYNC", "WMS_SCAN"],
        weights=[30, 20, 15, 15, 10, 5, 5],
        k=1,
    )[0]

    ts = (base_time + timedelta(seconds=random.randint(0, 86400))).isoformat()

    if traffic_type == "MODBUS_READ":
        src = random.choice(OT_HMIS)
        dst = random.choice(OT_PLCS)
        sport = random.randint(49152, 65535)
        dport = 502
        proto = "TCP"
        dur = round(random.uniform(0.005, 0.025), 4)
        fwd_pkts = random.randint(1, 2)
        bwd_pkts = random.randint(1, 2)
        fwd_bytes = random.randint(12, 24)
        bwd_bytes = random.randint(25, 60)
        ident = "INDUSTRIAL_DEVICE"

    elif traffic_type == "ERP_API":
        src = random.choice(CORP_WORKSTATIONS)
        dst = WH_WMS
        sport = random.randint(49152, 65535)
        dport = 8443
        proto = "TCP"
        dur = round(random.uniform(0.040, 0.350), 4)
        fwd_pkts = random.randint(4, 12)
        bwd_pkts = random.randint(6, 18)
        fwd_bytes = random.randint(800, 2500)
        bwd_bytes = random.randint(4000, 25000)
        ident = "SERVICE_ACCOUNT" if random.random() < 0.6 else "HUMAN_USER"

    elif traffic_type == "DNS_QUERY":
        src = random.choice(CORP_WORKSTATIONS + ENG_WORKSTATIONS)
        dst = CORP_DNS
        sport = random.randint(49152, 65535)
        dport = 53
        proto = "UDP"
        dur = round(random.uniform(0.001, 0.008), 4)
        fwd_pkts = 1
        bwd_pkts = 1
        fwd_bytes = random.randint(40, 85)
        bwd_bytes = random.randint(80, 220)
        ident = "HUMAN_USER"

    elif traffic_type == "SMB_FILE":
        src = random.choice(CORP_WORKSTATIONS)
        dst = CORP_FS
        sport = random.randint(49152, 65535)
        dport = 445
        proto = "TCP"
        dur = round(random.uniform(0.1, 3.5), 4)
        fwd_pkts = random.randint(10, 80)
        bwd_pkts = random.randint(15, 120)
        fwd_bytes = random.randint(2000, 45000)
        bwd_bytes = random.randint(5000, 150000)
        ident = "HUMAN_USER"

    elif traffic_type == "CICD_BUILD":
        src = ENG_BUILD_SVR
        dst = ENG_GIT_SVR
        sport = random.randint(49152, 65535)
        dport = 443
        proto = "TCP"
        dur = round(random.uniform(0.5, 8.0), 4)
        fwd_pkts = random.randint(50, 300)
        bwd_pkts = random.randint(80, 500)
        fwd_bytes = random.randint(10000, 80000)
        bwd_bytes = random.randint(50000, 500000)
        ident = "AUTOMATION_WORKLOAD"

    elif traffic_type == "NTP_SYNC":
        src = random.choice(CORP_DCS + [OT_SCADA, CLOUD_PROXY])
        dst = SEC_NTP
        sport = 123
        dport = 123
        proto = "UDP"
        dur = round(random.uniform(0.001, 0.005), 4)
        fwd_pkts = 1
        bwd_pkts = 1
        fwd_bytes = 48
        bwd_bytes = 48
        ident = "AUTOMATION_WORKLOAD"

    else:  # WMS_SCAN
        src = random.choice(WH_SCANNERS)
        dst = WH_WMS
        sport = random.randint(49152, 65535)
        dport = 8443
        proto = "TCP"
        dur = round(random.uniform(0.02, 0.15), 4)
        fwd_pkts = random.randint(3, 8)
        bwd_pkts = random.randint(3, 8)
        fwd_bytes = random.randint(300, 1200)
        bwd_bytes = random.randint(500, 2000)
        ident = "INDUSTRIAL_DEVICE"

    tot_pkts = fwd_pkts + bwd_pkts
    tot_bytes = fwd_bytes + bwd_bytes
    safe_dur = max(dur, 0.0001)
    bytes_per_sec = round(tot_bytes / safe_dur, 2)
    pkts_per_sec = round(tot_pkts / safe_dur, 2)

    return {
        "flow_id": make_flow_id(src, dst, sport, dport, proto, ts),
        "timestamp": ts,
        "source_ip": src,
        "destination_ip": dst,
        "source_port": sport,
        "destination_port": dport,
        "protocol": proto,
        "connection_duration": dur,
        "total_fwd_packets": fwd_pkts,
        "total_bwd_packets": bwd_pkts,
        "total_fwd_bytes": fwd_bytes,
        "total_bwd_bytes": bwd_bytes,
        "packets_transferred": tot_pkts,
        "bytes_transferred": tot_bytes,
        "flow_bytes_per_sec": bytes_per_sec,
        "flow_packets_per_sec": pkts_per_sec,
        "source_vlan": get_vlan(src),
        "destination_vlan": get_vlan(dst),
        "identity_classification": ident,
        "label": "BENIGN",
        "binary_label": 0,
    }


def generate_attack_record(base_time: datetime) -> Dict[str, Any]:
    """Generates realistic attack traffic record matching the 7 scenarios."""
    scenario = random.choices(
        [
            "VENDOR_COMPROMISE",
            "SERVICE_MISUSE",
            "LATERAL_MOVEMENT",
            "LOTL",
            "ENCRYPTED_EXFIL",
            "OT_ANOMALY",
            "VULNERABILITY_SCAN",
        ],
        weights=[15, 15, 20, 10, 15, 10, 15],
        k=1,
    )[0]

    ts = (base_time + timedelta(seconds=random.randint(0, 86400))).isoformat()

    if scenario == "VENDOR_COMPROMISE":
        src = random.choice([DMZ_BASTION, "10.10.50.112", OT_MES])
        dst = random.choice(OT_PLCS + [OT_MES])
        sport = random.randint(49152, 65535)
        dport = random.choice([22, 502])
        proto = "TCP"
        dur = round(random.uniform(0.01, 15.0), 4)
        fwd_pkts = random.randint(8, 40)
        bwd_pkts = random.randint(8, 35)
        fwd_bytes = random.randint(500, 4000)
        bwd_bytes = random.randint(600, 5000)
        ident = "THIRD_PARTY_IDENTITY"

    elif scenario == "SERVICE_MISUSE":
        src = random.choice(["10.10.10.35", CORP_WORKSTATIONS[0]])
        dst = random.choice([WH_WMS, "194.38.20.14"])
        sport = random.randint(49152, 65535)
        dport = 8443
        proto = "TCP"
        dur = round(random.uniform(0.05, 1.2), 4)
        fwd_pkts = random.randint(15, 60)
        bwd_pkts = random.randint(10, 40)
        fwd_bytes = random.randint(4000, 35000)
        bwd_bytes = random.randint(2000, 12000)
        ident = "SERVICE_ACCOUNT"

    elif scenario == "LATERAL_MOVEMENT":
        src = "10.10.10.21"  # CORP-WS-002
        dst = random.choice(CORP_WORKSTATIONS + ENG_WORKSTATIONS + [CORP_FS, OT_MES])
        sport = random.randint(49152, 65535)
        dport = random.choice([3389, 445, 22])
        proto = "TCP"
        dur = round(random.uniform(0.002, 0.8), 4)
        fwd_pkts = random.randint(2, 6)
        bwd_pkts = random.randint(1, 3)
        fwd_bytes = random.randint(120, 800)
        bwd_bytes = random.randint(60, 400)
        ident = "HUMAN_USER"

    elif scenario == "LOTL":
        src = "10.10.10.22"  # CORP-WS-003
        dst = "45.142.214.88"
        sport = random.randint(49152, 65535)
        dport = 80
        proto = "TCP"
        dur = round(random.uniform(0.5, 4.5), 4)
        fwd_pkts = random.randint(20, 80)
        bwd_pkts = random.randint(40, 150)
        fwd_bytes = random.randint(1500, 6000)
        bwd_bytes = random.randint(50000, 250000)
        ident = "UNKNOWN_IDENTITY"

    elif scenario == "ENCRYPTED_EXFIL":
        src = "10.10.20.10"  # ENG-WS-001
        dst = "185.196.8.121"
        sport = random.randint(49152, 65535)
        dport = 443
        proto = "TCP"
        dur = round(random.uniform(600.0, 7200.0), 2)  # High duration
        fwd_pkts = random.randint(5000, 25000)
        bwd_pkts = random.randint(1000, 4000)
        fwd_bytes = random.randint(2000000, 45000000)  # Extreme outbound bytes
        bwd_bytes = random.randint(50000, 300000)
        ident = "HUMAN_USER"

    elif scenario == "OT_ANOMALY":
        src = random.choice(["10.10.20.30", "10.10.30.95"])
        dst = "10.10.30.10"  # SMT Line A PLC
        sport = random.randint(49152, 65535)
        dport = 502
        proto = "TCP"
        dur = round(random.uniform(0.005, 0.05), 4)
        fwd_pkts = random.randint(2, 4)
        bwd_pkts = random.randint(1, 3)
        fwd_bytes = random.randint(60, 150)
        bwd_bytes = random.randint(40, 80)
        ident = "UNKNOWN_IDENTITY"

    else:  # VULNERABILITY_SCAN
        src = "10.10.50.98"
        dst = random.choice(["10.10.10.30", "10.10.20.11", OT_MES, ENG_NAS])
        sport = random.randint(49152, 65535)
        dport = random.choice([21, 22, 80, 443, 445, 502, 3389, 5000, 8080])
        proto = "TCP"
        dur = round(random.uniform(0.001, 0.01), 4)
        fwd_pkts = random.randint(1, 2)
        bwd_pkts = random.randint(0, 1)
        fwd_bytes = random.randint(40, 74)
        bwd_bytes = 0 if bwd_pkts == 0 else random.randint(40, 60)
        ident = "UNKNOWN_IDENTITY"

    tot_pkts = fwd_pkts + bwd_pkts
    tot_bytes = fwd_bytes + bwd_bytes
    safe_dur = max(dur, 0.0001)
    bytes_per_sec = round(tot_bytes / safe_dur, 2)
    pkts_per_sec = round(tot_pkts / safe_dur, 2)

    return {
        "flow_id": make_flow_id(src, dst, sport, dport, proto, ts),
        "timestamp": ts,
        "source_ip": src,
        "destination_ip": dst,
        "source_port": sport,
        "destination_port": dport,
        "protocol": proto,
        "connection_duration": dur,
        "total_fwd_packets": fwd_pkts,
        "total_bwd_packets": bwd_pkts,
        "total_fwd_bytes": fwd_bytes,
        "total_bwd_bytes": bwd_bytes,
        "packets_transferred": tot_pkts,
        "bytes_transferred": tot_bytes,
        "flow_bytes_per_sec": bytes_per_sec,
        "flow_packets_per_sec": pkts_per_sec,
        "source_vlan": get_vlan(src),
        "destination_vlan": get_vlan(dst),
        "identity_classification": ident,
        "label": scenario,
        "binary_label": 1,
    }


def generate_dataset(total_records: int = 50000, benign_count: int = 40000, output_path: str = "datasets/processed/becpl_synthetic_traffic_50k.csv", seed: int = 42):
    random.seed(seed)
    attack_count = total_records - benign_count
    logger.info("Generating %d total synthetic records (Benign: %d, Attack: %d)...", total_records, benign_count, attack_count)

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    base_time = datetime(2026, 11, 17, 8, 0, 0, tzinfo=timezone.utc)

    records = []
    # Generate benign
    for i in range(benign_count):
        records.append(generate_normal_record(base_time))
        if (i + 1) % 10000 == 0:
            logger.info("Generated %d / %d benign records...", i + 1, benign_count)

    # Generate attacks
    for i in range(attack_count):
        records.append(generate_attack_record(base_time))
        if (i + 1) % 5000 == 0:
            logger.info("Generated %d / %d attack records...", i + 1, attack_count)

    # Shuffle to simulate realistic interleaved capture
    logger.info("Shuffling generated records...")
    random.shuffle(records)

    logger.info("Writing output CSV to: %s", output_path)
    with open(output_path, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(records)

    file_size_mb = os.path.getsize(output_path) / (1024 * 1024)
    logger.info("Done! Wrote %d records to %s (%.2f MB)", len(records), output_path, file_size_mb)


def main():
    parser = argparse.ArgumentParser(description="Generate synthetic BECPL manufacturing traffic dataset")
    parser.add_argument("--total", type=int, default=50000, help="Total records to generate (default: 50,000)")
    parser.add_argument("--benign", type=int, default=40000, help="Benign records to generate (default: 40,000)")
    parser.add_argument("--output", "-o", type=str, default="C:\\Users\\ASUS\\VaultX\\datasets\\processed\\becpl_synthetic_traffic_50k.csv")
    parser.add_argument("--seed", type=int, default=42)

    args = parser.parse_args()
    generate_dataset(args.total, args.benign, args.output, args.seed)


if __name__ == "__main__":
    main()

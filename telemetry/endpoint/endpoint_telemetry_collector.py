#!/usr/bin/env python3
"""
VaultX — Endpoint Telemetry Collector
Bharat Electronics Components Pvt. Ltd. (BECPL), Pune

Collects, parses, and normalizes endpoint security events from:
- Windows Sysmon (XML event exports or live winevt logs)
- Linux auditd (/var/log/audit/audit.log)

Normalizes events into a unified VaultX Endpoint Security Schema and publishes
them to Redis Streams ('events:endpoint').

Configurable via:
  ENDPOINT_TYPE = windows | linux
  LOG_SOURCE_PATH = path to XML file / directory or audit.log
  REDIS_URL = redis connection string
"""

import os
import sys
import re
import time
import json
import socket
import logging
import argparse
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, Any, Generator, Optional

try:
    import redis
except ImportError:
    redis = None

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [EndpointCollector] %(message)s"
)
logger = logging.getLogger("endpoint_collector")

ENDPOINT_TYPE = os.getenv("ENDPOINT_TYPE", "windows").lower()
LOG_SOURCE_PATH = os.getenv("LOG_SOURCE_PATH", "")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
STREAM_NAME = os.getenv("STREAM_NAME", "events:endpoint")
HOSTNAME = socket.gethostname()

# -----------------------------------------------------------------------------
# Parser: Windows Sysmon XML
# -----------------------------------------------------------------------------
class SysmonParser:
    """Parses Sysmon Event XML strings into normalized dicts."""
    
    EVENT_TYPE_MAP = {
        "1": "process_create",
        "3": "network_connect",
        "7": "image_load",
        "10": "process_access",
        "11": "file_create",
        "12": "registry_event",
        "13": "registry_set_value",
        "22": "dns_query"
    }

    @staticmethod
    def parse_event_xml(xml_content: str) -> Optional[Dict[str, Any]]:
        try:
            # Strip XML namespaces for simplified element access
            clean_xml = re.sub(r'xmlns(:\w+)?="[^"]+"', '', xml_content)
            root = ET.fromstring(clean_xml)

            # System element
            system = root.find("System")
            event_id_elem = system.find("EventID") if system is not None else None
            event_id = event_id_elem.text if event_id_elem is not None else "0"
            time_created_elem = system.find("TimeCreated") if system is not None else None
            ts_created = time_created_elem.attrib.get("SystemTime", "") if time_created_elem is not None else ""
            computer_elem = system.find("Computer") if system is not None else None
            host = computer_elem.text if computer_elem is not None else HOSTNAME

            # EventData element
            event_data = {}
            event_data_elem = root.find("EventData")
            if event_data_elem is not None:
                for data_item in event_data_elem.findall("Data"):
                    name = data_item.attrib.get("Name")
                    if name:
                        event_data[name] = data_item.text or ""

            # Normalization
            normalized = {
                "telemetry_source": "sysmon",
                "os": "windows",
                "host": host,
                "event_id": event_id,
                "event_type": SysmonParser.EVENT_TYPE_MAP.get(event_id, f"sysmon_eid_{event_id}"),
                "timestamp": ts_created or time.time(),
                "user": event_data.get("User", ""),
                "process_id": event_data.get("ProcessId", ""),
                "process_name": event_data.get("Image", ""),
                "command_line": event_data.get("CommandLine", ""),
                "parent_process": event_data.get("ParentImage", ""),
                "parent_command_line": event_data.get("ParentCommandLine", ""),
                "current_directory": event_data.get("CurrentDirectory", ""),
                "hashes": event_data.get("Hashes", ""),
                "src_ip": event_data.get("SourceIp", ""),
                "dst_ip": event_data.get("DestinationIp", ""),
                "src_port": event_data.get("SourcePort", ""),
                "dst_port": event_data.get("DestinationPort", ""),
                "target_filename": event_data.get("TargetFilename", ""),
                "target_object": event_data.get("TargetObject", ""),
                "query_name": event_data.get("QueryName", ""),
                "raw_event_data": event_data
            }
            return normalized
        except Exception as e:
            logger.debug(f"Sysmon XML parsing failed: {e}")
            return None

# -----------------------------------------------------------------------------
# Parser: Linux auditd
# -----------------------------------------------------------------------------
class AuditdParser:
    """Parses auditd log lines (type=SYSCALL, EXECVE, PROCTITLE, etc.)"""

    @staticmethod
    def parse_line(line: str) -> Optional[Dict[str, Any]]:
        if not line or not ("type=" in line and "audit(" in line):
            return None

        fields = {}
        # Parse key=value pairs taking quotes into account
        matches = re.findall(r'(\w+)=(?:"([^"]*)"|([^\s]+))', line)
        for key, val_quoted, val_unquoted in matches:
            fields[key] = val_quoted if val_quoted else val_unquoted

        # Extract timestamp from audit(1620000000.123:456)
        ts_match = re.search(r'audit\((\d+\.\d+):', line)
        ts = float(ts_match.group(1)) if ts_match else time.time()

        event_type = fields.get("type", "UNKNOWN")
        key_tag = fields.get("key", "")

        # Categorize action
        action_cat = "auditd_event"
        if "priv_cmd" in key_tag:
            action_cat = "privilege_escalation"
        elif "net_socket" in key_tag:
            action_cat = "network_socket"
        elif "identity" in key_tag or "shadow" in key_tag:
            action_cat = "credential_access"
        elif "cron" in key_tag or "systemd" in key_tag:
            action_cat = "persistence_tamper"
        elif "kernel" in key_tag:
            action_cat = "kernel_module"
        elif event_type == "EXECVE":
            action_cat = "process_execute"

        normalized = {
            "telemetry_source": "auditd",
            "os": "linux",
            "host": HOSTNAME,
            "event_id": fields.get("syscall", event_type),
            "event_type": action_cat,
            "timestamp": ts,
            "user": fields.get("auid", fields.get("uid", "")),
            "effective_uid": fields.get("euid", ""),
            "process_id": fields.get("pid", ""),
            "process_name": fields.get("exe", fields.get("comm", "")),
            "command_line": fields.get("proctitle", fields.get("a0", "")),
            "parent_process_id": fields.get("ppid", ""),
            "cwd": fields.get("cwd", ""),
            "success": fields.get("success", ""),
            "audit_key": key_tag,
            "raw_fields": fields
        }
        return normalized

# -----------------------------------------------------------------------------
# Main Collector Service
# -----------------------------------------------------------------------------
class EndpointCollector:
    def __init__(self, endpoint_type: str, log_path: str, redis_url: str):
        self.endpoint_type = endpoint_type
        self.log_path = log_path
        self.redis_url = redis_url
        self.r = None
        self._init_redis()

    def _init_redis(self):
        if redis:
            try:
                self.r = redis.from_url(self.redis_url)
                self.r.ping()
                logger.info(f"Connected to Redis at {self.redis_url}")
            except Exception as e:
                logger.warning(f"Could not connect to Redis: {e}. Output will be printed to stdout.")
                self.r = None

    def publish_event(self, event: Dict[str, Any]):
        if self.r:
            try:
                self.r.xadd(STREAM_NAME, {"event": json.dumps(event)}, maxlen=100000, approximate=True)
            except Exception as e:
                logger.error(f"Failed to publish to stream {STREAM_NAME}: {e}")
        else:
            print(json.dumps(event))

    def run_windows(self):
        logger.info(f"Starting Windows Sysmon collector on {self.log_path or 'sample generator'}")
        if self.log_path and os.path.exists(self.log_path):
            with open(self.log_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
                # Split multiple <Event>...</Event> blocks
                events = re.findall(r'<Event[\s\S]*?<\/Event>', content)
                for ev_str in events:
                    parsed = SysmonParser.parse_event_xml(ev_str)
                    if parsed:
                        self.publish_event(parsed)
        else:
            # Demonstration event generator for test verification
            sample_xml = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
              <System>
                <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385F-C22A-43E0-BF4C-06F5698FFBD9}" />
                <EventID>1</EventID>
                <TimeCreated SystemTime="2026-11-17T12:00:00.000Z" />
                <Computer>CORP-WS-005.becpl.internal</Computer>
              </System>
              <EventData>
                <Data Name="User">BECPL\\rajesh.sharma</Data>
                <Data Name="ProcessId">4128</Data>
                <Data Name="Image">C:\\Windows\\System32\\powershell.exe</Data>
                <Data Name="CommandLine">powershell.exe -ExecutionPolicy Bypass -enc SQBFAFgA</Data>
                <Data Name="ParentImage">C:\\Windows\\explorer.exe</Data>
              </EventData>
            </Event>"""
            ev = SysmonParser.parse_event_xml(sample_xml)
            if ev:
                self.publish_event(ev)

    def run_linux(self):
        logger.info(f"Starting Linux auditd collector on {self.log_path or 'sample generator'}")
        if self.log_path and os.path.exists(self.log_path):
            with open(self.log_path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    ev = AuditdParser.parse_line(line.strip())
                    if ev:
                        self.publish_event(ev)
        else:
            sample_line = 'type=SYSCALL msg=audit(1763378400.120:942): arch=c000003e syscall=59 success=yes exit=0 a0=55a8e a1=7ffd a2=7ffd a3=8 items=2 ppid=1420 pid=2945 auid=1001 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=4 comm="sudo" exe="/usr/bin/sudo" key="priv_cmd_sudo"'
            ev = AuditdParser.parse_line(sample_line)
            if ev:
                self.publish_event(ev)

    def start(self):
        if self.endpoint_type == "windows":
            self.run_windows()
        elif self.endpoint_type == "linux":
            self.run_linux()
        else:
            logger.error(f"Unknown ENDPOINT_TYPE: {self.endpoint_type}")

def main():
    parser = argparse.ArgumentParser(description="VaultX Endpoint Telemetry Collector")
    parser.add_argument("--type", choices=["windows", "linux"], default=ENDPOINT_TYPE, help="Endpoint OS type")
    parser.add_argument("--log-path", default=LOG_SOURCE_PATH, help="Path to input log or XML")
    parser.add_argument("--redis", default=REDIS_URL, help="Redis URL")
    args = parser.parse_args()

    collector = EndpointCollector(args.type, args.log_path, args.redis)
    collector.start()

if __name__ == "__main__":
    main()

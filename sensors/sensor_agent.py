#!/usr/bin/env python3
"""
VaultX — Sensor Telemetry Agent
Bharat Electronics Components Pvt. Ltd. (BECPL), Pune

Responsibilities:
1. Monitors Zeek and Suricata log directories for new lines (tail/polling/inotify).
2. Parses events (Zeek JSON, Suricata EVE JSON).
3. Enriches events with sensor metadata (sensor_id, monitored_vlan, timestamp_collected, host_ip).
4. Publishes real-time events to Redis Streams ('events:raw').
5. Dispatches sensor health heartbeat ('sensor:health') every 60 seconds.
6. Robust backpressure & offline buffering: Buffers to local disk (up to 1GB) when Redis is unreachable,
   flushing buffered events on reconnect.
7. Fully configurable via environment variables or YAML config.
"""

import os
import sys
import glob
import time
import json
import socket
import logging
import sqlite3
import asyncio
from pathlib import Path
from typing import Dict, Any, Optional, List

try:
    import redis.asyncio as aioredis
except ImportError:
    import redis as aioredis  # Fallback type reference

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------
SENSOR_ID = os.getenv("SENSOR_ID", "SENSOR-CORP-01")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
MONITORED_VLAN = int(os.getenv("MONITORED_VLAN", "10"))
ZEEK_LOG_DIR = os.getenv("ZEEK_LOG_DIR", "/var/log/zeek/logs")
SURICATA_LOG_DIR = os.getenv("SURICATA_LOG_DIR", "/var/log/suricata")
BUFFER_DIR = os.getenv("BUFFER_DIR", "/var/lib/sensor/buffer")
MAX_BUFFER_SIZE_BYTES = int(os.getenv("MAX_BUFFER_SIZE_MB", "1024")) * 1024 * 1024  # 1GB default
POLL_INTERVAL_SECS = float(os.getenv("POLL_INTERVAL_SECS", "0.5"))
HEALTH_INTERVAL_SECS = float(os.getenv("HEALTH_INTERVAL_SECS", "60.0"))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [SensorAgent:%(name)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("agent")

# -----------------------------------------------------------------------------
# Disk Backpressure Buffer (SQLite-backed persistent queue)
# -----------------------------------------------------------------------------
class DiskBuffer:
    def __init__(self, db_path: str, max_size_bytes: int):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.max_size_bytes = max_size_bytes
        self.conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._init_db()

    def _init_db(self):
        with self.conn:
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS event_buffer (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    stream TEXT NOT NULL,
                    event_data TEXT NOT NULL,
                    created_at REAL NOT NULL
                )
            """)
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_buf_id ON event_buffer(id)")

    def push(self, stream: str, event_data: dict) -> bool:
        # Check current disk size
        if self.db_path.exists() and self.db_path.stat().st_size > self.max_size_bytes:
            # Purge oldest 1000 records to prevent disk exhaustion
            logger.warning("Local buffer exceeded limit! Purging oldest records.")
            with self.conn:
                self.conn.execute("DELETE FROM event_buffer WHERE id IN (SELECT id FROM event_buffer ORDER BY id ASC LIMIT 1000)")

        with self.conn:
            self.conn.execute(
                "INSERT INTO event_buffer (stream, event_data, created_at) VALUES (?, ?, ?)",
                (stream, json.dumps(event_data), time.time())
            )
        return True

    def fetch_batch(self, limit: int = 200) -> List[tuple]:
        cursor = self.conn.cursor()
        cursor.execute("SELECT id, stream, event_data FROM event_buffer ORDER BY id ASC LIMIT ?", (limit,))
        return cursor.fetchall()

    def delete_batch(self, ids: List[int]):
        if not ids:
            return
        placeholders = ",".join("?" for _ in ids)
        with self.conn:
            self.conn.execute(f"DELETE FROM event_buffer WHERE id IN ({placeholders})", ids)

    def count(self) -> int:
        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM event_buffer")
        res = cursor.fetchone()
        return res[0] if res else 0

# -----------------------------------------------------------------------------
# File Tailer for Log Streams
# -----------------------------------------------------------------------------
class LogFileTailer:
    """Tails active log files without blocking, tracking file inode/size."""
    def __init__(self, file_path: str, source_type: str):
        self.file_path = file_path
        self.source_type = source_type
        self.last_pos = 0
        self.last_inode = None
        self._open_file()

    def _open_file(self):
        if os.path.exists(self.file_path):
            stat = os.stat(self.file_path)
            self.last_inode = stat.st_ino if hasattr(stat, 'st_ino') else None
            # Seek to end on startup to avoid re-reading huge historical logs
            self.last_pos = stat.st_size
        else:
            self.last_pos = 0

    def read_lines(self) -> List[str]:
        if not os.path.exists(self.file_path):
            return []

        try:
            stat = os.stat(self.file_path)
            current_inode = stat.st_ino if hasattr(stat, 'st_ino') else None
            
            # File rotated
            if (self.last_inode and current_inode != self.last_inode) or stat.st_size < self.last_pos:
                self.last_pos = 0
                self.last_inode = current_inode

            lines = []
            with open(self.file_path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(self.last_pos)
                while True:
                    line = f.readline()
                    if not line:
                        break
                    line_str = line.strip()
                    if line_str:
                        lines.append(line_str)
                self.last_pos = f.tell()
            return lines
        except Exception as e:
            logger.error(f"Error reading {self.file_path}: {e}")
            return []

# -----------------------------------------------------------------------------
# Sensor Agent Core
# -----------------------------------------------------------------------------
class SensorAgent:
    def __init__(self):
        self.sensor_id = SENSOR_ID
        self.vlan = MONITORED_VLAN
        self.redis_url = REDIS_URL
        self.redis: Optional[aioredis.Redis] = None
        self.buffer = DiskBuffer(os.path.join(BUFFER_DIR, f"{self.sensor_id}_buffer.db"), MAX_BUFFER_SIZE_BYTES)
        self.tailers: Dict[str, LogFileTailer] = {}
        self.events_processed = 0
        self.events_buffered = 0
        self.start_time = time.time()
        self.is_connected = False

    async def connect_redis(self):
        while True:
            try:
                self.redis = aioredis.from_url(self.redis_url, decode_responses=True)
                await self.redis.ping()
                self.is_connected = True
                logger.info(f"Connected to Redis at {self.redis_url}")
                return
            except Exception as e:
                self.is_connected = False
                logger.warning(f"Unable to connect to Redis ({e}). Retrying in 5s...")
                await asyncio.sleep(5)

    def init_tailers(self):
        # Zeek JSON logs: conn.log, notice.log, becpl_modbus.log, becpl_lateral.log, identity_enrichment.log
        zeek_files = [
            ("conn.log", "zeek:conn"),
            ("notice.log", "zeek:notice"),
            ("becpl_modbus.log", "zeek:modbus"),
            ("becpl_lateral.log", "zeek:lateral"),
            ("identity_enrichment.log", "zeek:identity"),
            ("dns.log", "zeek:dns"),
            ("http.log", "zeek:http"),
            ("ssl.log", "zeek:ssl")
        ]
        for fname, tag in zeek_files:
            path = os.path.join(ZEEK_LOG_DIR, fname)
            self.tailers[tag] = LogFileTailer(path, tag)

        # Suricata EVE JSON log
        suricata_eve = os.path.join(SURICATA_LOG_DIR, "eve.json")
        self.tailers["suricata:eve"] = LogFileTailer(suricata_eve, "suricata:eve")
        logger.info(f"Initialized {len(self.tailers)} log tailers.")

    def enrich_event(self, source_type: str, raw_event: dict) -> dict:
        return {
            "sensor_id": self.sensor_id,
            "monitored_vlan": self.vlan,
            "source_type": source_type,
            "timestamp_collected": time.time(),
            "collector_host": socket.gethostname(),
            "payload": raw_event
        }

    async def dispatch_event(self, event: dict):
        stream_name = "events:raw"
        serialized = {"event": json.dumps(event)}

        if self.is_connected and self.redis:
            try:
                await self.redis.xadd(stream_name, serialized, maxlen=200000, approximate=True)
                self.events_processed += 1
                return
            except Exception as e:
                logger.error(f"Redis publish error ({e}), redirecting to local buffer.")
                self.is_connected = False

        # If disconnected or Redis failed, push to local SQLite buffer
        self.buffer.push(stream_name, event)
        self.events_buffered += 1

    async def flush_buffer(self):
        """Flushes buffered records to Redis once connection is restored."""
        if not self.is_connected or not self.redis:
            return

        buffered_count = self.buffer.count()
        if buffered_count == 0:
            return

        logger.info(f"Draining local disk buffer: {buffered_count} events pending...")
        while self.is_connected:
            batch = self.buffer.fetch_batch(limit=100)
            if not batch:
                break

            ids_to_del = []
            try:
                pipe = self.redis.pipeline()
                for rec_id, stream, data_str in batch:
                    pipe.xadd(stream, {"event": data_str}, maxlen=200000, approximate=True)
                    ids_to_del.append(rec_id)
                await pipe.execute()
                self.buffer.delete_batch(ids_to_del)
                self.events_processed += len(ids_to_del)
            except Exception as e:
                logger.error(f"Failed to flush buffer batch: {e}")
                self.is_connected = False
                break

    async def poll_logs_loop(self):
        while True:
            for tag, tailer in self.tailers.items():
                lines = tailer.read_lines()
                for line in lines:
                    try:
                        raw_json = json.loads(line)
                        enriched = self.enrich_event(tag, raw_json)
                        await self.dispatch_event(enriched)
                    except json.JSONDecodeError:
                        continue
                    except Exception as err:
                        logger.error(f"Processing error on {tag}: {err}")

            await self.flush_buffer()
            await asyncio.sleep(POLL_INTERVAL_SECS)

    async def health_report_loop(self):
        while True:
            await asyncio.sleep(HEALTH_INTERVAL_SECS)
            health_payload = {
                "sensor_id": self.sensor_id,
                "monitored_vlan": self.vlan,
                "status": "HEALTHY",
                "uptime_seconds": round(time.time() - self.start_time, 2),
                "events_processed": self.events_processed,
                "buffered_events_count": self.buffer.count(),
                "hostname": socket.gethostname(),
                "timestamp": time.time()
            }
            if self.is_connected and self.redis:
                try:
                    await self.redis.hset("sensor:health", self.sensor_id, json.dumps(health_payload))
                    logger.info(f"Health heartbeat sent: processed={self.events_processed}, buffered={health_payload['buffered_events_count']}")
                except Exception as e:
                    logger.warning(f"Could not submit health status: {e}")
                    self.is_connected = False

    async def connection_watchdog_loop(self):
        while True:
            await asyncio.sleep(5)
            if not self.is_connected or not self.redis:
                try:
                    self.redis = aioredis.from_url(self.redis_url, decode_responses=True)
                    await self.redis.ping()
                    self.is_connected = True
                    logger.info("Watchdog: Redis connection re-established.")
                except Exception:
                    self.is_connected = False

    async def run(self):
        logger.info(f"Starting VaultX Sensor Agent [{self.sensor_id}] on VLAN {self.vlan}")
        self.init_tailers()
        await self.connect_redis()
        await asyncio.gather(
            self.poll_logs_loop(),
            self.health_report_loop(),
            self.connection_watchdog_loop()
        )

def main():
    agent = SensorAgent()
    try:
        asyncio.run(agent.run())
    except KeyboardInterrupt:
        logger.info("Sensor agent stopped by user.")

if __name__ == "__main__":
    main()

"""
VaultX NIDS - Redis-backed Deduplication Cache
Bharat Electronics Components Pvt. Ltd. (BECPL), Pune

Implements a sliding 5-minute deduplication window using Redis SETEX (TTL=300)
keyed on SHA-256(timestamp_bucket + src_ip + dst_ip + src_port + dst_port + event_type).
"""
from __future__ import annotations

import hashlib
import time
from collections import deque
from datetime import datetime, timezone
from typing import Any, Deque, Dict, Optional, Tuple

import structlog

logger = structlog.get_logger(__name__)


class DedupCache:
    """
    Redis-backed event deduplication cache with a sliding TTL window.

    Key formula:
        SHA-256(f"{timestamp_bucket}|{src_ip}|{dst_ip}|{src_port}|{dst_port}|{event_type}")

    Uses Redis SETEX with TTL=300 (configurable) to track seen event hashes
    and tracks duplicates filtered per minute.
    """

    KEY_PREFIX = "vaultx:dedup:"
    STATS_KEY = "vaultx:dedup:stats"

    def __init__(
        self,
        redis_client: Any,
        ttl_seconds: int = 300,
        bucket_seconds: int = 60,
    ) -> None:
        self._redis = redis_client
        self._ttl = ttl_seconds
        self._bucket_seconds = max(1, bucket_seconds)

        # Sliding 60-second window timestamps of filtered duplicates
        self._dup_timestamps: Deque[float] = deque()
        self.duplicates_filtered_total: int = 0
        self.events_checked_total: int = 0

    # ------------------------------------------------------------------
    # Hash computation
    # ------------------------------------------------------------------

    def compute_hash(
        self,
        timestamp: datetime | float | int | str,
        src_ip: Optional[str],
        dst_ip: Optional[str],
        src_port: Optional[int | str] = "",
        dst_port: Optional[int | str] = "",
        event_type: str = "",
    ) -> str:
        """Compute deterministic SHA-256 dedup fingerprint for an event."""
        epoch = self._to_epoch(timestamp)
        timestamp_bucket = str(int(epoch) // self._bucket_seconds)
        payload = (
            f"{timestamp_bucket}|"
            f"{src_ip or ''}|"
            f"{dst_ip or ''}|"
            f"{'' if src_port is None else src_port}|"
            f"{'' if dst_port is None else dst_port}|"
            f"{event_type or ''}"
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def is_duplicate(
        self,
        timestamp: datetime | float | int | str,
        src_ip: Optional[str],
        dst_ip: Optional[str],
        src_port: Optional[int | str] = "",
        dst_port: Optional[int | str] = "",
        event_type: str = "",
    ) -> bool:
        """
        Return True if the event fingerprint was already seen within the TTL window,
        otherwise store it via SETEX and return False.
        """
        is_dup, _ = await self.check_and_record(
            timestamp=timestamp,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            event_type=event_type,
        )
        return is_dup

    async def check_and_record(
        self,
        timestamp: datetime | float | int | str,
        src_ip: Optional[str],
        dst_ip: Optional[str],
        src_port: Optional[int | str] = "",
        dst_port: Optional[int | str] = "",
        event_type: str = "",
    ) -> Tuple[bool, str]:
        """
        Check if an event is a duplicate and record it if new.

        Returns
        -------
        (is_duplicate, dedup_hash)
        """
        self.events_checked_total += 1
        dedup_hash = self.compute_hash(
            timestamp=timestamp,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            event_type=event_type,
        )
        redis_key = f"{self.KEY_PREFIX}{dedup_hash}"

        try:
            existing = await self._redis.get(redis_key)
            if existing is not None:
                self._record_duplicate()
                await self._increment_redis_stat("duplicates_filtered")
                return True, dedup_hash

            # Record hash with sliding TTL using SETEX
            await self._redis.setex(redis_key, self._ttl, "1")
            await self._increment_redis_stat("new_events")
            return False, dedup_hash
        except Exception as exc:
            # Fail open on transient Redis error so security telemetry is not dropped
            logger.warning("dedup_cache.redis_error", error=str(exc))
            return False, dedup_hash

    def duplicates_per_minute(self) -> int:
        """Return the count of duplicate events filtered in the last 60 seconds."""
        now = time.monotonic()
        cutoff = now - 60.0
        while self._dup_timestamps and self._dup_timestamps[0] < cutoff:
            self._dup_timestamps.popleft()
        return len(self._dup_timestamps)

    def get_stats(self) -> Dict[str, int]:
        """Return local deduplication statistics snapshot."""
        return {
            "events_checked_total": self.events_checked_total,
            "duplicates_filtered_total": self.duplicates_filtered_total,
            "duplicates_filtered_per_minute": self.duplicates_per_minute(),
            "ttl_seconds": self._ttl,
        }

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _record_duplicate(self) -> None:
        self.duplicates_filtered_total += 1
        now = time.monotonic()
        self._dup_timestamps.append(now)
        cutoff = now - 60.0
        while self._dup_timestamps and self._dup_timestamps[0] < cutoff:
            self._dup_timestamps.popleft()

    async def _increment_redis_stat(self, field: str) -> None:
        try:
            if hasattr(self._redis, "hincrby"):
                await self._redis.hincrby(self.STATS_KEY, field, 1)
        except Exception:
            pass

    @staticmethod
    def _to_epoch(ts: datetime | float | int | str) -> float:
        if isinstance(ts, datetime):
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            return ts.timestamp()
        if isinstance(ts, (int, float)):
            return float(ts) / 1000.0 if ts > 1e11 else float(ts)
        if isinstance(ts, str):
            try:
                from dateutil import parser as dateutil_parser
                parsed = dateutil_parser.parse(ts)
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                return parsed.timestamp()
            except Exception:
                pass
        return datetime.now(timezone.utc).timestamp()

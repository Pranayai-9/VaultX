"""
VaultX NIDS - Processing Checkpoint Manager
Bharat Electronics Components Pvt. Ltd. (BECPL), Pune

Tracks the last successfully processed Redis Streams message ID per stream per consumer,
caches checkpoints in Redis, and persists checkpoints to PostgreSQL ``becpl_nids.audit_log``
every 60 seconds for at-least-once delivery and crash recovery.
"""
from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import structlog

logger = structlog.get_logger(__name__)


class CheckpointManager:
    """
    Manages Redis Streams consumption checkpoints with periodic PostgreSQL durability.

    Guarantees:
    - Tracks last persisted message ID per stream per consumer
    - Persists checkpoints to ``becpl_nids.audit_log`` every 60 seconds
    - Recovers last checkpoint on restart to resume without data loss
    - Compares message IDs to prevent duplicate reprocessing after restart
    """

    REDIS_KEY_PREFIX = "vaultx:checkpoints"
    AUDIT_ACTION = "ingestion_checkpoint"

    def __init__(
        self,
        redis_client: Any,
        db_pool: Any = None,
        consumer_group: str = "vaultx-ingestion-group",
        consumer_name: str = "ingestion-worker-1",
        flush_interval_seconds: int = 60,
    ) -> None:
        self._redis = redis_client
        self._db_pool = db_pool
        self._consumer_group = consumer_group
        self._consumer_name = consumer_name
        self._flush_interval = flush_interval_seconds

        self._checkpoints: Dict[str, str] = {}
        self._dirty: bool = False
        self._running: bool = False
        self._task: Optional[asyncio.Task] = None

    @property
    def redis_hash_key(self) -> str:
        return f"{self.REDIS_KEY_PREFIX}:{self._consumer_group}:{self._consumer_name}"

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> Dict[str, str]:
        """Recover existing checkpoints from Redis and PostgreSQL and start flush loop."""
        await self.recover_checkpoints()
        self._running = True
        self._task = asyncio.create_task(self._periodic_flush_loop(), name="checkpoint-flush-loop")
        logger.info(
            "checkpoint_manager.started",
            consumer_group=self._consumer_group,
            consumer_name=self._consumer_name,
            recovered_streams=list(self._checkpoints.keys()),
        )
        return dict(self._checkpoints)

    async def stop(self) -> None:
        """Stop periodic flush loop and perform final checkpoint flush."""
        self._running = False
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        await self.flush_now()
        logger.info("checkpoint_manager.stopped")

    # ------------------------------------------------------------------
    # Checkpoint operations
    # ------------------------------------------------------------------

    async def update_checkpoint(self, stream_name: str, message_id: str) -> None:
        """
        Record ``message_id`` as successfully persisted for ``stream_name``.
        Updates Redis immediately and marks dirty for the next PostgreSQL flush.
        """
        current = self._checkpoints.get(stream_name)
        if current and self._compare_stream_ids(message_id, current) <= 0:
            return

        self._checkpoints[stream_name] = message_id
        self._dirty = True

        if self._redis is not None:
            try:
                await self._redis.hset(self.redis_hash_key, stream_name, message_id)
            except Exception as exc:
                logger.warning("checkpoint_manager.redis_hset_error", stream=stream_name, error=str(exc))

    def get_checkpoint(self, stream_name: str) -> Optional[str]:
        """Return the last persisted message ID for ``stream_name``, or None."""
        return self._checkpoints.get(stream_name)

    def is_already_processed(self, stream_name: str, message_id: str) -> bool:
        """Return True if ``message_id`` is at or behind the recovered checkpoint."""
        last_id = self._checkpoints.get(stream_name)
        if not last_id:
            return False
        return self._compare_stream_ids(message_id, last_id) <= 0

    def snapshot(self) -> Dict[str, str]:
        return dict(self._checkpoints)

    # ------------------------------------------------------------------
    # Recovery & Persistence
    # ------------------------------------------------------------------

    async def recover_checkpoints(self) -> Dict[str, str]:
        """Recover latest checkpoints from Redis and PostgreSQL audit_log."""
        # 1. Load from Redis
        if self._redis is not None:
            try:
                raw = await self._redis.hgetall(self.redis_hash_key)
                for k, v in raw.items():
                    stream = k.decode("utf-8") if isinstance(k, bytes) else str(k)
                    msg_id = v.decode("utf-8") if isinstance(v, bytes) else str(v)
                    self._checkpoints[stream] = msg_id
            except Exception as exc:
                logger.warning("checkpoint_manager.redis_recover_error", error=str(exc))

        # 2. Load from PostgreSQL becpl_nids.audit_log (take newest message ID per stream)
        if self._db_pool is not None:
            try:
                async with self._db_pool.acquire() as conn:
                    rows = await conn.fetch(
                        """
                        SELECT DISTINCT ON (target_id)
                               target_id, new_value
                        FROM becpl_nids.audit_log
                        WHERE action = $1
                          AND actor = $2
                          AND target_table = 'redis_streams'
                          AND outcome = 'success'
                        ORDER BY target_id, timestamp DESC
                        """,
                        self.AUDIT_ACTION,
                        self._consumer_name,
                    )
                for row in rows:
                    payload = row["new_value"]
                    if isinstance(payload, str):
                        payload = json.loads(payload)
                    if isinstance(payload, dict):
                        stream = payload.get("stream_name")
                        msg_id = payload.get("last_message_id")
                        group = payload.get("consumer_group")
                        if stream and msg_id and group == self._consumer_group:
                            existing = self._checkpoints.get(stream)
                            if not existing or self._compare_stream_ids(msg_id, existing) > 0:
                                self._checkpoints[stream] = msg_id
            except Exception as exc:
                logger.warning("checkpoint_manager.postgres_recover_error", error=str(exc))

        return dict(self._checkpoints)

    async def flush_now(self) -> int:
        """Persist current checkpoints to Redis and PostgreSQL ``becpl_nids.audit_log``."""
        if not self._checkpoints:
            return 0

        flushed = 0
        # Sync Redis hash
        if self._redis is not None:
            try:
                for stream, msg_id in self._checkpoints.items():
                    await self._redis.hset(self.redis_hash_key, stream, msg_id)
            except Exception as exc:
                logger.warning("checkpoint_manager.redis_flush_error", error=str(exc))

        # Persist to PostgreSQL audit_log (matches database/schema/03_incident_tables.sql)
        if self._db_pool is not None:
            now = datetime.now(timezone.utc)
            try:
                async with self._db_pool.acquire() as conn:
                    for stream, msg_id in self._checkpoints.items():
                        new_val = json.dumps({
                            "stream_name": stream,
                            "consumer_group": self._consumer_group,
                            "consumer_name": self._consumer_name,
                            "last_message_id": msg_id,
                            "saved_at": now.isoformat(),
                        })
                        await conn.execute(
                            """
                            INSERT INTO becpl_nids.audit_log (
                                timestamp, actor, actor_type, action,
                                target_table, target_id, new_value, outcome
                            )
                            VALUES ($1, $2, 'system', $3, 'redis_streams', $4, $5::jsonb, 'success')
                            """,
                            now,
                            self._consumer_name,
                            self.AUDIT_ACTION,
                            f"{self._consumer_group}:{stream}",
                            new_val,
                        )
                        flushed += 1
                self._dirty = False
                logger.debug("checkpoint_manager.postgres_flushed", count=flushed)
            except Exception as exc:
                logger.warning("checkpoint_manager.postgres_flush_error", error=str(exc))
        else:
            self._dirty = False
            flushed = len(self._checkpoints)

        return flushed

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    async def _periodic_flush_loop(self) -> None:
        while self._running:
            try:
                await asyncio.sleep(self._flush_interval)
                if self._dirty:
                    await self.flush_now()
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.warning("checkpoint_manager.flush_loop_error", error=str(exc))

    @staticmethod
    def _compare_stream_ids(id_a: str, id_b: str) -> int:
        """Compare two Redis Streams IDs ('<ms>-<seq>'). Returns -1, 0, or 1."""
        def _split(sid: str) -> tuple[int, int]:
            parts = sid.split("-", 1)
            ms = int(parts[0])
            seq = int(parts[1]) if len(parts) > 1 else 0
            return ms, seq

        try:
            a, b = _split(id_a), _split(id_b)
            return -1 if a < b else (1 if a > b else 0)
        except (ValueError, IndexError):
            return -1 if id_a < id_b else (1 if id_a > id_b else 0)

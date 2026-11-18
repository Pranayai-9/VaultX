"""
VaultX NIDS - Ingestion Pipeline Configuration
Bharat Electronics Components Pvt. Ltd. (BECPL), Pune

Configuration via environment variables using Pydantic Settings.
"""
from __future__ import annotations

from typing import List, Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class IngestionConfig(BaseSettings):
    """Central configuration for the VaultX Phase 2 ingestion & processing pipeline."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Redis connection & streams
    REDIS_URL: str = Field(
        default="redis://localhost:6379",
        description="Redis connection URL",
    )
    CONSUMER_GROUP: str = Field(
        default="vaultx-ingestion-group",
        description="Redis Streams consumer group name",
    )
    CONSUMER_NAME: str = Field(
        default="ingestion-worker-1",
        description="Unique consumer name inside the consumer group",
    )
    INPUT_STREAMS: List[str] = Field(
        default=[
            "events:raw",
            "events:endpoint",
            "events:third_party",
            "events:simulation",
        ],
        description="Redis Streams consumed by the ingestion pipeline",
    )
    PROCESSED_STREAM: str = Field(
        default="events:processed",
        description="Redis Stream for enriched & persisted events",
    )
    COMPLETED_FLOWS_STREAM: str = Field(
        default="flows:completed",
        description="Redis Stream for completed network flows",
    )
    OPERATIONAL_ALERTS_STREAM: str = Field(
        default="alerts:operational",
        description="Redis Stream for operational & backpressure alerts",
    )
    ML_INFERENCE_STREAM: str = Field(
        default="events:ml_inference",
        description="Redis Stream for suspicious events queued for ML inference",
    )
    ML_PRIORITY_STREAM: str = Field(
        default="events:ml_priority",
        description="Redis Stream for high-priority events requiring immediate ML inference",
    )

    # PostgreSQL
    POSTGRES_DSN: Optional[str] = Field(
        default="postgresql://vaultx_admin:VaultX_SecAdmin_2026!@localhost:5432/vaultx_nids",
        description="PostgreSQL DSN for asyncpg connection pool",
    )

    # Batching & concurrency
    BATCH_SIZE: int = Field(
        default=100,
        ge=1,
        le=10_000,
        description="Maximum number of events fetched per XREADGROUP batch",
    )
    BLOCK_MS: int = Field(
        default=2000,
        ge=100,
        description="Block timeout in milliseconds for XREADGROUP",
    )
    WORKER_COUNT: int = Field(
        default=4,
        ge=1,
        le=64,
        description="Number of concurrent async processing workers",
    )

    # Deduplication
    DEDUP_WINDOW_SECONDS: int = Field(
        default=300,
        ge=1,
        description="Sliding deduplication window in seconds (default 5 minutes)",
    )

    # Backpressure thresholds
    BACKPRESSURE_THRESHOLD: int = Field(
        default=10_000,
        ge=1,
        description="Total Redis queue depth above which backpressure alerts trigger",
    )
    ML_QUEUE_BACKPRESSURE_THRESHOLD: int = Field(
        default=500,
        ge=1,
        description="ML inference queue depth above which events degrade to statistical-only",
    )

    # Flow aggregation
    FLOW_TIMEOUT_SECONDS: int = Field(
        default=60,
        ge=1,
        description="Idle timeout in seconds before an active flow is closed",
    )

    # Sensor health monitoring
    SENSOR_OFFLINE_THRESHOLD_SECONDS: int = Field(
        default=300,
        ge=10,
        description="Seconds without heartbeat before SENSOR_OFFLINE alert is raised",
    )
    SENSOR_CONFIG_PATH: str = Field(
        default="sensors/sensor_config.yml",
        description="Path to sensor deployment YAML configuration",
    )

    # Checkpointing & resource monitoring
    CHECKPOINT_INTERVAL_SECONDS: int = Field(
        default=60,
        ge=5,
        description="Interval in seconds for persisting checkpoints to PostgreSQL",
    )
    RESOURCE_MONITOR_INTERVAL_SECONDS: int = Field(
        default=10,
        ge=1,
        description="Interval in seconds for collecting system & pipeline resource metrics",
    )
    CPU_ALERT_THRESHOLD: float = Field(
        default=85.0,
        ge=1.0,
        le=100.0,
        description="CPU utilization percentage triggering operational alert",
    )
    LATENCY_P95_ALERT_SECONDS: float = Field(
        default=5.0,
        ge=0.1,
        description="P95 processing latency threshold (seconds) triggering alert",
    )

    # Enricher cache
    ASSET_CACHE_TTL_SECONDS: int = Field(
        default=60,
        ge=5,
        description="Redis cache TTL in seconds for asset and identity lookups",
    )

    # Health & metrics HTTP server
    API_HOST: str = Field(default="0.0.0.0", description="Bind host for health/metrics API")
    API_PORT: int = Field(default=8080, ge=1, le=65535, description="Bind port for health/metrics API")

    # Logging & metadata
    LOG_LEVEL: str = Field(
        default="INFO",
        description="Logging verbosity (DEBUG, INFO, WARNING, ERROR, CRITICAL)",
    )
    PIPELINE_VERSION: str = Field(
        default="2.0.0",
        description="Ingestion pipeline software version",
    )


settings = IngestionConfig()

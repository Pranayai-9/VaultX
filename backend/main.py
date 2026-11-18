"""
backend/main.py — Central FastAPI Application Entrypoint & Modular Router Mount
VaultX Hybrid NIDS for BECPL (Bharat Electronics Components Pvt. Ltd.), Pune
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
import time
import uuid
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator, Dict, Optional

from fastapi import FastAPI, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# Router imports
from backend.api.routers.behavioural import router as behavioural_router
from backend.api.routers.containment import router as containment_router
from backend.api.routers.detection import router as detection_router
from backend.api.routers.health import router as health_router
from backend.api.routers.identity import router as identity_router
from backend.api.routers.incidents import router as incidents_router
from backend.api.routers.ingestion import router as ingestion_router
from backend.api.routers.models import router as models_router
from backend.api.routers.risk import router as risk_router
from backend.api.routers.threat_intel import router as threat_intel_router

# Configure structured logging
logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] [%(name)s] [cid:%(correlation_id)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)

# Filter to inject correlation ID into standard log records
class CorrelationFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if not hasattr(record, "correlation_id"):
            record.correlation_id = "-"
        return True

for handler in logging.root.handlers:
    handler.addFilter(CorrelationFilter())

logger = logging.getLogger("vaultx.api.main")


# ---------------------------------------------------------------------------
# Lifespan Context Manager
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    Manages application startup and graceful shutdown:
    1. Attempts async connection pool initialization to PostgreSQL (asyncpg)
    2. Attempts async connection to Redis Streams (redis.asyncio)
    3. Falls back gracefully to simulation in-memory data store when offline
    4. Cleans up connection pools upon termination
    """
    logger.info("Initializing VaultX Central Security Backend for BECPL Pune...", extra={"correlation_id": "startup"})

    app.state.db_pool = None
    app.state.redis_client = None

    enable_live = os.environ.get("VAULTX_ENABLE_LIVE_DB", "false").lower() in ("true", "1")
    if enable_live:
        # 1. PostgreSQL Connection Attempt
        pg_host = os.environ.get("POSTGRES_HOST", "localhost")
        pg_port = int(os.environ.get("POSTGRES_PORT", "5432"))
        pg_user = os.environ.get("POSTGRES_USER", "vaultx_user")
        pg_pass = os.environ.get("POSTGRES_PASSWORD", "vaultx_secure_pass")
        pg_db = os.environ.get("POSTGRES_DB", "vaultx")

        try:
            import asyncpg
            logger.info(f"Attempting PostgreSQL connection pool on {pg_host}:{pg_port}/{pg_db}...", extra={"correlation_id": "startup"})
            pool_coro = asyncpg.create_pool(
                host=pg_host,
                port=pg_port,
                user=pg_user,
                password=pg_pass,
                database=pg_db,
                min_size=2,
                max_size=10,
                command_timeout=5,
            )
            app.state.db_pool = await asyncio.wait_for(pool_coro, timeout=1.5)
            logger.info("PostgreSQL connection pool established successfully.", extra={"correlation_id": "startup"})
        except Exception as e:
            logger.warning(
                f"PostgreSQL unreachable ({e}). Operating in simulation fallback mode with in-memory state.",
                extra={"correlation_id": "startup"},
            )
            app.state.db_pool = None

        # 2. Redis Connection Attempt
        redis_host = os.environ.get("REDIS_HOST", "localhost")
        redis_port = int(os.environ.get("REDIS_PORT", "6379"))

        try:
            import redis.asyncio as aioredis
            logger.info(f"Attempting Redis connection on {redis_host}:{redis_port}...", extra={"correlation_id": "startup"})
            r_client = aioredis.Redis(
                host=redis_host,
                port=redis_port,
                socket_timeout=1.5,
                decode_responses=True,
            )
            await asyncio.wait_for(r_client.ping(), timeout=1.5)
            app.state.redis_client = r_client
            logger.info("Redis Streams connection established successfully.", extra={"correlation_id": "startup"})
        except Exception as e:
            logger.warning(
                f"Redis unreachable ({e}). Operating in simulation fallback mode with in-memory state.",
                extra={"correlation_id": "startup"},
            )
            app.state.redis_client = None
    else:
        logger.info(
            "Operating with high-fidelity in-memory digital twin state (set VAULTX_ENABLE_LIVE_DB=true to connect to PostgreSQL/Redis).",
            extra={"correlation_id": "startup"}
        )

    logger.info("VaultX Phase 2 API startup complete. Ready to receive requests.", extra={"correlation_id": "startup"})
    yield

    # Shutdown logic
    logger.info("Initiating VaultX API shutdown sequence...", extra={"correlation_id": "shutdown"})
    if app.state.db_pool is not None:
        await app.state.db_pool.close()
        logger.info("PostgreSQL connection pool closed.", extra={"correlation_id": "shutdown"})
    if app.state.redis_client is not None:
        await app.state.redis_client.close()
        logger.info("Redis client disconnected.", extra={"correlation_id": "shutdown"})
    logger.info("VaultX API shutdown complete.", extra={"correlation_id": "shutdown"})


# ---------------------------------------------------------------------------
# FastAPI Application Factory
# ---------------------------------------------------------------------------

app = FastAPI(
    title="VaultX Central Security Backend API — BECPL MSME NIDS",
    description="""
## Manufacturing-Aware Hybrid NIDS for BECPL (Pune, Maharashtra)

VaultX Phase 2 delivers a unified REST API for industrial threat detection, multi-source telemetry ingestion, 
dynamic risk evaluation across 6 manufacturing zones, machine learning classification, and policy-driven OT-safe containment.

### Core Architectural Pillars
1. **Passive Distributed Sensors**: Non-intrusive Zeek & Suricata taps across all 7 VLANs.
2. **7-Way Multi-Source Identity**: Unified accounting for humans, services, agents, and vendor contractors.
3. **OT Safety Interlocks**: Mandatory 2-person approval and zero unvalidated disruptions to shopfloor PLCs.
4. **Offline ML Retraining**: Continuous model improvement with strict human governance before deployment.
    """,
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)


# ---------------------------------------------------------------------------
# Middleware: CORS, Correlation ID & Request Timing
# ---------------------------------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def correlation_and_timing_middleware(request: Request, call_next):
    """
    Attaches unique Correlation ID to every incoming request and calculates execution latency.
    Exposes X-Correlation-ID and X-Response-Time-Ms on response headers.
    """
    cid = request.headers.get("X-Correlation-ID") or str(uuid.uuid4())
    request.state.correlation_id = cid

    start_time = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception as exc:
        process_time_ms = (time.perf_counter() - start_time) * 1000.0
        logger.error(
            f"Unhandled server error on {request.method} {request.url.path}: {exc}",
            exc_info=True,
            extra={"correlation_id": cid},
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": "InternalServerError",
                "message": "An unhandled exception occurred processing the request.",
                "correlation_id": cid,
                "detail": str(exc),
            },
            headers={
                "X-Correlation-ID": cid,
                "X-Response-Time-Ms": f"{process_time_ms:.2f}",
            },
        )

    process_time_ms = (time.perf_counter() - start_time) * 1000.0
    response.headers["X-Correlation-ID"] = cid
    response.headers["X-Response-Time-Ms"] = f"{process_time_ms:.2f}"
    return response


# ---------------------------------------------------------------------------
# Exception Handlers
# ---------------------------------------------------------------------------

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    cid = getattr(request.state, "correlation_id", "unknown")
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": "HTTPException",
            "status_code": exc.status_code,
            "message": exc.detail,
            "correlation_id": cid,
        },
        headers={"X-Correlation-ID": cid},
    )


# ---------------------------------------------------------------------------
# Router Mounting (v1 API & Metrics)
# ---------------------------------------------------------------------------

API_V1_PREFIX = "/api/v1"

app.include_router(health_router, prefix=API_V1_PREFIX)
app.include_router(ingestion_router, prefix=API_V1_PREFIX)
app.include_router(detection_router, prefix=API_V1_PREFIX)
app.include_router(behavioural_router, prefix=API_V1_PREFIX)
app.include_router(identity_router, prefix=API_V1_PREFIX)
app.include_router(threat_intel_router, prefix=API_V1_PREFIX)
app.include_router(incidents_router, prefix=API_V1_PREFIX)
app.include_router(risk_router, prefix=API_V1_PREFIX)
app.include_router(containment_router, prefix=API_V1_PREFIX)
app.include_router(models_router, prefix=API_V1_PREFIX)

# Also expose /metrics at the top level for Prometheus collectors
@app.get("/metrics", include_in_schema=False)
async def metrics_root():
    from backend.api.routers.health import get_prometheus_metrics
    return await get_prometheus_metrics()


# ---------------------------------------------------------------------------
# Root and Heartbeat Endpoints
# ---------------------------------------------------------------------------

@app.get("/", tags=["System"])
async def root_index():
    """Root landing endpoint displaying NIDS status and documentation links."""
    return {
        "title": "VaultX Central Security Backend API",
        "enterprise": "Bharat Electronics Components Pvt. Ltd. (BECPL)",
        "location": "Bhosari MIDC, Pune, Maharashtra",
        "version": "2.0.0",
        "phase": "Phase 2 — Core Engine & Unified Integration",
        "documentation": {
            "swagger_ui": "/docs",
            "redoc": "/redoc",
            "openapi_json": "/openapi.json",
        },
        "endpoints_prefix": "/api/v1",
        "status": "operational",
    }


@app.get("/healthz", tags=["System"])
async def healthz():
    """Lightweight Kubernetes / container readiness probe."""
    return {"status": "ok"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)

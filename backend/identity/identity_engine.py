"""
VaultX - Human, Agent & Non-Human Identity Intelligence Engine
BECPL Manufacturing-Aware Hybrid NIDS - Phase 2

Processes authentication events from Redis stream `events:raw` (event_type == 'auth')
and endpoint events for identity correlation.

Design principles:
  * All identity fields are captured from explicit authentication/audit telemetry,
    NEVER inferred from raw network packets.
  * Raw authentication tokens/secrets are NEVER stored or logged; only their
    SHA-256 hex fingerprint (`token_fingerprint`) is persisted.
  * Writes normalized records to PostgreSQL `becpl_nids.auth_events`.
  * Publishes identity anomalies to Redis stream `detections:identity`.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import math
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Deque, Dict, List, Optional, Set, Tuple

try:
    import psycopg2
except ImportError:  # pragma: no cover
    psycopg2 = None  # type: ignore[assignment]

try:
    import geoip2.database  # type: ignore
except ImportError:  # pragma: no cover
    geoip2 = None  # type: ignore[assignment]

from backend.behavioural.behaviour_config import (
    BRUTE_FORCE_FAILURE_THRESHOLD,
    BRUTE_FORCE_WINDOW_MINUTES,
    HUMAN_BUSINESS_HOUR_END_IST,
    HUMAN_BUSINESS_HOUR_START_IST,
    IDENTITY_DETECTION_STREAM,
    IMPOSSIBLE_TRAVEL_MAX_SPEED_KMH,
    IMPOSSIBLE_TRAVEL_WINDOW_HOURS,
    RAW_EVENTS_STREAM,
    VLAN_MAP,
)

logger = logging.getLogger(__name__)

IST = timezone(timedelta(hours=5, minutes=30))

VALID_IDENTITY_CATEGORIES = frozenset(
    {
        "HUMAN_USER",
        "SERVICE_ACCOUNT",
        "AUTOMATION_WORKLOAD",
        "AI_AGENT",
        "INDUSTRIAL_DEVICE",
        "THIRD_PARTY_IDENTITY",
        "UNKNOWN_IDENTITY",
    }
)

INTERACTIVE_AUTH_METHODS = frozenset(
    {
        "password",
        "interactive",
        "rdp",
        "ssh_password",
        "mfa",
        "mfa_totp",
        "sso_interactive",
        "console",
    }
)

NON_INTERACTIVE_SERVICE_METHODS = frozenset(
    {
        "certificate",
        "api_key",
        "kerberos",
        "mtls",
        "hmac_token",
    }
)

# Built-in fallback IP-prefix / CIDR -> (country_code, city, lat, lon) table
# Used when MaxMind GeoLite2 DB is not mounted in the environment.
DEFAULT_GEO_PREFIXES: List[Tuple[str, str, str, float, float]] = [
    ("10.10.0.0/16", "IN", "Pune (BECPL LAN)", 18.5204, 73.8567),
    ("103.21.0.0/16", "IN", "Pune", 18.5204, 73.8567),
    ("49.36.0.0/16", "IN", "Mumbai", 19.0760, 72.8777),
    ("122.160.0.0/16", "IN", "Bengaluru", 12.9716, 77.5946),
    ("185.220.0.0/16", "DE", "Frankfurt", 50.1109, 8.6821),
    ("198.51.100.0/24", "US", "New York", 40.7128, -74.0060),
    ("203.0.113.0/24", "SG", "Singapore", 1.3521, 103.8198),
    ("114.114.0.0/16", "CN", "Shenzhen", 22.5431, 114.0579),
    ("91.108.0.0/16", "NL", "Amsterdam", 52.3676, 4.9041),
    ("52.95.0.0/16", "GB", "London", 51.5074, -0.1278),
]


# ---------------------------------------------------------------------------
# Helpers & Data Models
# ---------------------------------------------------------------------------


def fingerprint_token(raw_token: Optional[str]) -> Optional[str]:
    """Return SHA-256 hex digest of a token; NEVER store or return raw token."""
    if not raw_token:
        return None
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    r = 6371.0
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    d_phi = math.radians(lat2 - lat1)
    d_lam = math.radians(lon2 - lon1)
    a = (
        math.sin(d_phi / 2.0) ** 2
        + math.cos(phi1) * math.cos(phi2) * math.sin(d_lam / 2.0) ** 2
    )
    return 2.0 * r * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))


def _resolve_zone_from_ip(ip_str: Optional[str]) -> str:
    if not ip_str:
        return "unknown"
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return "unknown"
    for vlan_id, meta in VLAN_MAP.items():
        if ip_obj in ipaddress.ip_network(meta["cidr"]):
            return f"VLAN_{vlan_id}_{meta['name'].replace(' ', '_')}"
    return "external"


@dataclass
class GeoLocation:
    country: str
    city: str
    latitude: float
    longitude: float


@dataclass
class AuthEventRecord:
    """Normalized authentication record captured from explicit auth telemetry."""

    auth_id: str
    timestamp: datetime
    principal_id: str
    principal_name: str
    identity_category: str
    auth_method: str
    device_id: Optional[str]
    session_id: Optional[str]
    token_fingerprint: Optional[str]  # SHA-256 hex ONLY, never raw token
    source_ip: str
    source_zone: str
    target_resource: str
    requested_operation: str
    success: bool
    failure_reason: Optional[str] = None
    is_privileged: bool = False
    mfa_used: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "auth_id": self.auth_id,
            "timestamp": self.timestamp.isoformat(),
            "principal_id": self.principal_id,
            "principal_name": self.principal_name,
            "identity_category": self.identity_category,
            "auth_method": self.auth_method,
            "device_id": self.device_id,
            "session_id": self.session_id,
            "token_fingerprint": self.token_fingerprint,
            "source_ip": self.source_ip,
            "source_zone": self.source_zone,
            "target_resource": self.target_resource,
            "requested_operation": self.requested_operation,
            "success": self.success,
            "failure_reason": self.failure_reason,
            "is_privileged": self.is_privileged,
            "mfa_used": self.mfa_used,
        }


@dataclass
class IdentityAnomaly:
    """Identity-based anomaly published to Redis stream `detections:identity`."""

    anomaly_id: str
    timestamp: datetime
    anomaly_type: str
    principal_id: str
    principal_name: str
    identity_category: str
    severity: str
    score: float
    description: str
    source_ip: str
    target_resource: str
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "anomaly_id": self.anomaly_id,
            "timestamp": self.timestamp.isoformat(),
            "anomaly_type": self.anomaly_type,
            "principal_id": self.principal_id,
            "principal_name": self.principal_name,
            "identity_category": self.identity_category,
            "severity": self.severity,
            "score": round(self.score, 4),
            "description": self.description,
            "source_ip": self.source_ip,
            "target_resource": self.target_resource,
            "evidence": self.evidence,
        }


# ---------------------------------------------------------------------------
# IdentityEngine
# ---------------------------------------------------------------------------


class IdentityEngine:
    """
    Processes authentication and endpoint events, writes `auth_events` to
    PostgreSQL, and runs 5 identity anomaly detectors:
      1. brute_force_indicator (> 5 failures in 5 min from same principal)
      2. impossible_travel (geographically distant logins within 1 hour)
      3. off_hours_human_login (HUMAN_USER outside 07:00-22:00 IST)
      4. service_account_interactive_login (SERVICE_ACCOUNT via interactive method)
      5. privileged_account_unusual_location (privileged identity from unseen IP)
    """

    def __init__(
        self,
        pg_dsn: Optional[str] = None,
        redis_client: Optional[Any] = None,
        identity_registry: Optional[Dict[str, Dict[str, Any]]] = None,
        asset_registry: Optional[Dict[str, str]] = None,
        geoip_db_path: Optional[str] = None,
        custom_geo_map: Optional[Dict[str, GeoLocation]] = None,
    ) -> None:
        self._pg_dsn = pg_dsn
        self._redis = redis_client
        # principal_name or principal_id -> {identity_id, principal_type, is_privileged, known_ips}
        self._identity_registry: Dict[str, Dict[str, Any]] = dict(
            identity_registry or {}
        )
        # ip_address or hostname -> asset_id
        self._asset_registry: Dict[str, str] = dict(asset_registry or {})
        self._custom_geo_map: Dict[str, GeoLocation] = dict(custom_geo_map or {})
        self._geoip_reader = None
        if geoip_db_path and geoip2 is not None:
            try:
                self._geoip_reader = geoip2.database.Reader(geoip_db_path)
            except Exception as exc:
                logger.warning("Could not open MaxMind GeoIP DB %s: %s", geoip_db_path, exc)

        # In-memory sliding state for real-time correlation
        self._failed_attempts: Dict[str, Deque[datetime]] = defaultdict(deque)
        self._last_login_geo: Dict[str, Tuple[datetime, str, GeoLocation]] = {}
        self._known_privileged_ips: Dict[str, Set[str]] = defaultdict(set)
        self._endpoint_identity_map: Dict[str, Dict[str, Any]] = {}

        # Seed known privileged IPs from identity registry if supplied
        for key, rec in self._identity_registry.items():
            pid = str(rec.get("identity_id") or key)
            for ip in rec.get("known_ips", []):
                self._known_privileged_ips[pid].add(str(ip))

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def process_auth_event(
        self, raw_event: Dict[str, Any], persist: bool = True, publish: bool = True
    ) -> Tuple[AuthEventRecord, List[IdentityAnomaly]]:
        """
        Normalize an auth event, write it to PostgreSQL `becpl_nids.auth_events`,
        evaluate all 5 identity anomaly rules, and publish anomalies to
        Redis stream `detections:identity`.
        """
        record = self._normalize_auth_event(raw_event)

        if persist and self._pg_dsn and psycopg2 is not None:
            self._write_auth_event_pg(record)

        anomalies: List[IdentityAnomaly] = []

        # 1. Brute-force detection (> 5 failures in 5 minutes)
        bf = self._check_brute_force(record)
        if bf is not None:
            anomalies.append(bf)

        # 2. Impossible travel (distant IPs within 1 hour)
        travel = self._check_impossible_travel(record)
        if travel is not None:
            anomalies.append(travel)

        # 3. Off-hours human login (outside 07:00-22:00 IST)
        off_hours = self._check_off_hours_human(record)
        if off_hours is not None:
            anomalies.append(off_hours)

        # 4. Service account interactive login
        svc_interactive = self._check_service_account_interactive(record)
        if svc_interactive is not None:
            anomalies.append(svc_interactive)

        # 5. Privileged account from unusual location
        priv_loc = self._check_privileged_unusual_location(record)
        if priv_loc is not None:
            anomalies.append(priv_loc)

        if publish and self._redis is not None:
            for anomaly in anomalies:
                self._publish_anomaly(anomaly)

        return record, anomalies

    def correlate_endpoint_event(self, endpoint_event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Correlate an endpoint event with the identity registry so downstream
        engines can tie host process/logon activity back to a principal_id.
        """
        user_name = str(endpoint_event.get("user_name") or "").strip()
        asset_id = endpoint_event.get("asset_id") or self._asset_registry.get(
            str(endpoint_event.get("hostname") or "")
        )
        reg = self._lookup_identity(user_name)
        correlation = {
            "asset_id": asset_id,
            "hostname": endpoint_event.get("hostname"),
            "user_name": user_name,
            "principal_id": reg.get("identity_id", user_name or "unknown"),
            "identity_category": reg.get("principal_type", "UNKNOWN_IDENTITY"),
            "is_privileged": bool(reg.get("is_privileged", False)),
            "last_seen": self._parse_timestamp(endpoint_event.get("timestamp")).isoformat(),
        }
        if asset_id:
            self._endpoint_identity_map[str(asset_id)] = correlation
        return correlation

    def consume_raw_stream_once(
        self, last_id: str = "$", count: int = 100, block_ms: int = 1000
    ) -> List[IdentityAnomaly]:
        """Consume auth events from Redis stream `events:raw` (event_type == 'auth')."""
        if self._redis is None:
            raise RuntimeError("Redis client is required to consume events:raw")

        entries = self._redis.xread(
            {RAW_EVENTS_STREAM: last_id}, count=count, block=block_ms
        )
        all_anomalies: List[IdentityAnomaly] = []
        for _stream, messages in entries or []:
            for _msg_id, fields in messages:
                payload = self._decode_stream_fields(fields)
                etype = str(payload.get("event_type", "")).lower()
                if etype in ("auth", "auth_event"):
                    _, anomalies = self.process_auth_event(payload)
                    all_anomalies.extend(anomalies)
                elif etype == "endpoint_event":
                    self.correlate_endpoint_event(payload)
        return all_anomalies

    # ------------------------------------------------------------------
    # Normalization
    # ------------------------------------------------------------------

    def _normalize_auth_event(self, event: Dict[str, Any]) -> AuthEventRecord:
        principal_name = str(
            event.get("principal_name")
            or event.get("username")
            or event.get("principal_id")
            or "unknown"
        )
        reg = self._lookup_identity(
            str(event.get("principal_id") or principal_name)
        )

        principal_id = str(
            event.get("principal_id")
            or reg.get("identity_id")
            or principal_name
        )
        category = str(
            event.get("identity_category")
            or event.get("principal_type")
            or reg.get("principal_type")
            or "UNKNOWN_IDENTITY"
        ).upper()
        if category not in VALID_IDENTITY_CATEGORIES:
            category = "UNKNOWN_IDENTITY"

        source_ip = str(event.get("source_ip") or event.get("src_ip") or "0.0.0.0")
        source_zone = str(
            event.get("source_zone") or _resolve_zone_from_ip(source_ip)
        )
        device_id = (
            event.get("device_id")
            or event.get("source_asset_id")
            or self._asset_registry.get(source_ip)
            or reg.get("associated_asset_id")
        )

        # NEVER store raw token; always compute SHA-256 fingerprint
        raw_token = event.get("token") or event.get("raw_token") or event.get("auth_token")
        token_fp = event.get("token_fingerprint")
        if raw_token is not None:
            token_fp = fingerprint_token(str(raw_token))

        is_privileged = bool(
            event.get("is_privileged")
            if event.get("is_privileged") is not None
            else reg.get("is_privileged", False)
        )

        success = bool(event.get("success", True))
        failure_reason = None if success else str(event.get("failure_reason") or "authentication_failed")

        return AuthEventRecord(
            auth_id=str(event.get("auth_id") or uuid.uuid4()),
            timestamp=self._parse_timestamp(event.get("timestamp")),
            principal_id=principal_id,
            principal_name=principal_name,
            identity_category=category,
            auth_method=str(event.get("auth_method") or "unknown").lower(),
            device_id=device_id,
            session_id=event.get("session_id"),
            token_fingerprint=token_fp,
            source_ip=source_ip,
            source_zone=source_zone,
            target_resource=str(
                event.get("target_resource") or event.get("target_system") or "unknown"
            ),
            requested_operation=str(event.get("requested_operation") or "login"),
            success=success,
            failure_reason=failure_reason,
            is_privileged=is_privileged,
            mfa_used=bool(event.get("mfa_used", False)),
        )

    # ------------------------------------------------------------------
    # Anomaly detectors
    # ------------------------------------------------------------------

    def _check_brute_force(self, record: AuthEventRecord) -> Optional[IdentityAnomaly]:
        if record.success:
            return None
        window = timedelta(minutes=BRUTE_FORCE_WINDOW_MINUTES)
        attempts = self._failed_attempts[record.principal_id]
        attempts.append(record.timestamp)

        # Prune entries outside trailing 5-minute window
        cutoff = record.timestamp - window
        while attempts and attempts[0] < cutoff:
            attempts.popleft()

        if len(attempts) > BRUTE_FORCE_FAILURE_THRESHOLD:
            return IdentityAnomaly(
                anomaly_id=str(uuid.uuid4()),
                timestamp=record.timestamp,
                anomaly_type="brute_force_indicator",
                principal_id=record.principal_id,
                principal_name=record.principal_name,
                identity_category=record.identity_category,
                severity="HIGH",
                score=0.85,
                description=(
                    f"Principal {record.principal_name} had {len(attempts)} failed "
                    f"logins within {BRUTE_FORCE_WINDOW_MINUTES} minutes "
                    f"(threshold > {BRUTE_FORCE_FAILURE_THRESHOLD})"
                ),
                source_ip=record.source_ip,
                target_resource=record.target_resource,
                evidence={
                    "failure_count": len(attempts),
                    "window_minutes": BRUTE_FORCE_WINDOW_MINUTES,
                    "failure_reason": record.failure_reason,
                },
            )
        return None

    def _check_impossible_travel(
        self, record: AuthEventRecord
    ) -> Optional[IdentityAnomaly]:
        if not record.success:
            return None
        curr_geo = self.geolocate_ip(record.source_ip)
        if curr_geo is None:
            return None

        prev = self._last_login_geo.get(record.principal_id)
        self._last_login_geo[record.principal_id] = (
            record.timestamp,
            record.source_ip,
            curr_geo,
        )
        if prev is None:
            return None

        prev_ts, prev_ip, prev_geo = prev
        if prev_ip == record.source_ip:
            return None

        elapsed_hours = abs((record.timestamp - prev_ts).total_seconds()) / 3600.0
        if elapsed_hours > IMPOSSIBLE_TRAVEL_WINDOW_HOURS:
            return None

        distance_km = _haversine_km(
            prev_geo.latitude, prev_geo.longitude, curr_geo.latitude, curr_geo.longitude
        )
        # Flag if distant (> 500 km) within 1 hour or implied speed > 800 km/h
        effective_hours = max(elapsed_hours, 1.0 / 60.0)
        speed_kmh = distance_km / effective_hours
        if distance_km > 500.0 and speed_kmh > IMPOSSIBLE_TRAVEL_MAX_SPEED_KMH:
            return IdentityAnomaly(
                anomaly_id=str(uuid.uuid4()),
                timestamp=record.timestamp,
                anomaly_type="impossible_travel",
                principal_id=record.principal_id,
                principal_name=record.principal_name,
                identity_category=record.identity_category,
                severity="HIGH",
                score=0.90,
                description=(
                    f"Impossible travel for {record.principal_name}: "
                    f"{prev_geo.city} ({prev_geo.country}) -> "
                    f"{curr_geo.city} ({curr_geo.country}), "
                    f"{distance_km:.0f} km in {elapsed_hours * 60:.1f} min"
                ),
                source_ip=record.source_ip,
                target_resource=record.target_resource,
                evidence={
                    "previous_ip": prev_ip,
                    "previous_country": prev_geo.country,
                    "previous_city": prev_geo.city,
                    "current_country": curr_geo.country,
                    "current_city": curr_geo.city,
                    "distance_km": round(distance_km, 1),
                    "elapsed_minutes": round(elapsed_hours * 60.0, 1),
                },
            )
        return None

    def _check_off_hours_human(
        self, record: AuthEventRecord
    ) -> Optional[IdentityAnomaly]:
        if record.identity_category != "HUMAN_USER":
            return None
        ts_ist = record.timestamp.astimezone(IST)
        hour_ist = ts_ist.hour
        # Normal business/extended window is 07:00 <= hour < 22:00 IST
        if HUMAN_BUSINESS_HOUR_START_IST <= hour_ist < HUMAN_BUSINESS_HOUR_END_IST:
            return None

        return IdentityAnomaly(
            anomaly_id=str(uuid.uuid4()),
            timestamp=record.timestamp,
            anomaly_type="off_hours_human_login",
            principal_id=record.principal_id,
            principal_name=record.principal_name,
            identity_category=record.identity_category,
            severity="MEDIUM",
            score=0.60,
            description=(
                f"HUMAN_USER {record.principal_name} authenticated at "
                f"{ts_ist.strftime('%H:%M')} IST (outside 07:00-22:00 IST)"
            ),
            source_ip=record.source_ip,
            target_resource=record.target_resource,
            evidence={
                "hour_ist": hour_ist,
                "timestamp_ist": ts_ist.isoformat(),
                "allowed_window_ist": f"{HUMAN_BUSINESS_HOUR_START_IST:02d}:00-{HUMAN_BUSINESS_HOUR_END_IST:02d}:00",
            },
        )

    def _check_service_account_interactive(
        self, record: AuthEventRecord
    ) -> Optional[IdentityAnomaly]:
        if record.identity_category != "SERVICE_ACCOUNT":
            return None
        if record.auth_method in NON_INTERACTIVE_SERVICE_METHODS:
            return None
        if record.auth_method not in INTERACTIVE_AUTH_METHODS:
            return None

        return IdentityAnomaly(
            anomaly_id=str(uuid.uuid4()),
            timestamp=record.timestamp,
            anomaly_type="service_account_interactive_login",
            principal_id=record.principal_id,
            principal_name=record.principal_name,
            identity_category=record.identity_category,
            severity="HIGH",
            score=0.85,
            description=(
                f"SERVICE_ACCOUNT {record.principal_name} used interactive auth "
                f"method '{record.auth_method}' (expected certificate/api_key)"
            ),
            source_ip=record.source_ip,
            target_resource=record.target_resource,
            evidence={
                "auth_method": record.auth_method,
                "expected_methods": sorted(NON_INTERACTIVE_SERVICE_METHODS),
            },
        )

    def _check_privileged_unusual_location(
        self, record: AuthEventRecord
    ) -> Optional[IdentityAnomaly]:
        if not record.is_privileged:
            return None
        known = self._known_privileged_ips[record.principal_id]
        if not known:
            # Bootstrap first known IP without alerting
            known.add(record.source_ip)
            return None
        if record.source_ip in known:
            return None

        anomaly = IdentityAnomaly(
            anomaly_id=str(uuid.uuid4()),
            timestamp=record.timestamp,
            anomaly_type="privileged_account_unusual_location",
            principal_id=record.principal_id,
            principal_name=record.principal_name,
            identity_category=record.identity_category,
            severity="HIGH",
            score=0.80,
            description=(
                f"Privileged identity {record.principal_name} authenticated "
                f"from unseen source IP {record.source_ip}"
            ),
            source_ip=record.source_ip,
            target_resource=record.target_resource,
            evidence={
                "unseen_ip": record.source_ip,
                "known_ips": sorted(known),
            },
        )
        return anomaly

    # ------------------------------------------------------------------
    # GeoIP & Persistence helpers
    # ------------------------------------------------------------------

    def geolocate_ip(self, ip_str: str) -> Optional[GeoLocation]:
        if ip_str in self._custom_geo_map:
            return self._custom_geo_map[ip_str]

        if self._geoip_reader is not None:
            try:
                resp = self._geoip_reader.city(ip_str)
                if resp.location.latitude is not None and resp.location.longitude is not None:
                    return GeoLocation(
                        country=resp.country.iso_code or "XX",
                        city=resp.city.name or "Unknown",
                        latitude=float(resp.location.latitude),
                        longitude=float(resp.location.longitude),
                    )
            except Exception:
                pass

        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            return None

        for cidr, country, city, lat, lon in DEFAULT_GEO_PREFIXES:
            if ip_obj in ipaddress.ip_network(cidr):
                return GeoLocation(
                    country=country, city=city, latitude=lat, longitude=lon
                )
        return None

    def _lookup_identity(self, key: str) -> Dict[str, Any]:
        if key in self._identity_registry:
            return self._identity_registry[key]
        for rec in self._identity_registry.values():
            if rec.get("principal_name") == key or rec.get("identity_id") == key:
                return rec
        return {}

    def _write_auth_event_pg(self, record: AuthEventRecord) -> None:
        try:
            identity_uuid = None
            try:
                uuid.UUID(record.principal_id)
                identity_uuid = record.principal_id
            except ValueError:
                identity_uuid = None

            with psycopg2.connect(self._pg_dsn) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO becpl_nids.auth_events (
                            auth_id, timestamp, identity_id, principal_name,
                            principal_type, auth_method, source_ip, source_asset_id,
                            target_system, success, failure_reason, mfa_used,
                            session_id, event_provenance, raw_event
                        )
                        VALUES (
                            %s::uuid, %s, %s::uuid, %s,
                            %s, %s, %s::inet, %s,
                            %s, %s, %s, %s,
                            %s, %s::jsonb, %s::jsonb
                        )
                        """,
                        (
                            record.auth_id,
                            record.timestamp,
                            identity_uuid,
                            record.principal_name,
                            record.identity_category,
                            record.auth_method,
                            record.source_ip,
                            record.device_id,
                            record.target_resource,
                            record.success,
                            record.failure_reason,
                            record.mfa_used,
                            record.session_id,
                            json.dumps(
                                {
                                    "source_zone": record.source_zone,
                                    "requested_operation": record.requested_operation,
                                    "token_fingerprint": record.token_fingerprint,
                                }
                            ),
                            json.dumps(record.to_dict()),
                        ),
                    )
                conn.commit()
        except Exception as exc:
            logger.error("Failed writing auth_event %s to PostgreSQL: %s", record.auth_id, exc)

    def _publish_anomaly(self, anomaly: IdentityAnomaly) -> None:
        self._redis.xadd(
            IDENTITY_DETECTION_STREAM,
            {
                "anomaly_id": anomaly.anomaly_id,
                "anomaly_type": anomaly.anomaly_type,
                "principal_id": anomaly.principal_id,
                "severity": anomaly.severity,
                "score": str(anomaly.score),
                "payload": json.dumps(anomaly.to_dict()),
            },
        )

    @staticmethod
    def _decode_stream_fields(fields: Dict[Any, Any]) -> Dict[str, Any]:
        decoded: Dict[str, Any] = {}
        for k, v in fields.items():
            key = k.decode("utf-8") if isinstance(k, bytes) else str(k)
            val = v.decode("utf-8") if isinstance(v, bytes) else v
            decoded[key] = val
        if "payload" in decoded and isinstance(decoded["payload"], str):
            try:
                return json.loads(decoded["payload"])
            except json.JSONDecodeError:
                pass
        return decoded

    @staticmethod
    def _parse_timestamp(ts_raw: Any) -> datetime:
        if isinstance(ts_raw, datetime):
            return ts_raw if ts_raw.tzinfo else ts_raw.replace(tzinfo=timezone.utc)
        if isinstance(ts_raw, str):
            dt = datetime.fromisoformat(ts_raw)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc)

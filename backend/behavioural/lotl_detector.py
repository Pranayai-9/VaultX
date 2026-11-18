"""
VaultX - Living-off-the-Land (LOTL) Detector
BECPL Manufacturing-Aware Hybrid NIDS - Phase 2

Monitors endpoint events (Sysmon Event ID 1 / process creation) from Redis
stream `events:endpoint`, matches against 8 high-fidelity LOTL patterns with
MITRE ATT&CK technique IDs, correlates with the trailing 15 minutes of
PostgreSQL `becpl_nids.network_flows` for external network connections, and
publishes combined `LotlIndicator` records to Redis stream `detections:lotl`.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional

try:
    import psycopg2
    import psycopg2.extras
except ImportError:  # pragma: no cover
    psycopg2 = None  # type: ignore[assignment]

from backend.behavioural.behaviour_config import (
    LOTL_DETECTION_STREAM,
    LOTL_ENDPOINT_STREAM,
    LOTL_NETWORK_CORRELATION_WINDOW_MINUTES,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants & detection rules
# ---------------------------------------------------------------------------

OFFICE_PARENTS = frozenset(
    {
        "winword.exe",
        "excel.exe",
        "powerpnt.exe",
        "outlook.exe",
        "msaccess.exe",
        "visio.exe",
    }
)

SHELL_CHILDREN = frozenset(
    {
        "cmd.exe",
        "powershell.exe",
        "pwsh.exe",
        "wscript.exe",
        "cscript.exe",
    }
)

BENIGN_WMIC_CHILDREN = frozenset(
    {
        "wmiprvse.exe",
        "mofcomp.exe",
        "scrcons.exe",
    }
)

URL_REGEX = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)


@dataclass
class LotlPatternMatch:
    """Single matched LOTL rule on a process creation event."""

    pattern_id: str
    pattern_name: str
    mitre_technique: str
    suspicion_score: float
    matched_detail: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pattern_id": self.pattern_id,
            "pattern_name": self.pattern_name,
            "mitre_technique": self.mitre_technique,
            "suspicion_score": round(self.suspicion_score, 4),
            "matched_detail": self.matched_detail,
        }


@dataclass
class LotlIndicator:
    """Combined endpoint LOTL suspicion + network correlation indicator."""

    indicator_id: str
    timestamp: datetime
    asset_id: Optional[str]
    hostname: Optional[str]
    user_name: Optional[str]
    process_name: str
    parent_process_name: Optional[str]
    command_line: str
    matches: List[LotlPatternMatch]
    endpoint_suspicion_score: float
    external_connections: List[Dict[str, Any]] = field(default_factory=list)
    network_correlated: bool = False
    combined_score: float = 0.0
    mitre_techniques: List[str] = field(default_factory=list)
    severity: str = "MEDIUM"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "indicator_id": self.indicator_id,
            "timestamp": self.timestamp.isoformat(),
            "asset_id": self.asset_id,
            "hostname": self.hostname,
            "user_name": self.user_name,
            "process_name": self.process_name,
            "parent_process_name": self.parent_process_name,
            "command_line": self.command_line,
            "matches": [m.to_dict() for m in self.matches],
            "endpoint_suspicion_score": round(self.endpoint_suspicion_score, 4),
            "external_connections": self.external_connections,
            "network_correlated": self.network_correlated,
            "combined_score": round(self.combined_score, 4),
            "mitre_techniques": self.mitre_techniques,
            "severity": self.severity,
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _basename_lower(path_or_name: Optional[str]) -> str:
    if not path_or_name:
        return ""
    # Handle both Windows backslashes and POSIX slashes
    cleaned = path_or_name.replace("\\", "/")
    return os.path.basename(cleaned).strip().lower()


def is_external_ip(ip_str: Optional[str]) -> bool:
    """Return True if `ip_str` is a routable public/external IP address."""
    if not ip_str:
        return False
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return not (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj.is_reserved
    )


# ---------------------------------------------------------------------------
# LotlDetector
# ---------------------------------------------------------------------------


class LotlDetector:
    """
    Detects Living-off-the-Land techniques in Sysmon Event ID 1 / process
    creation events, correlates with PostgreSQL network_flows over a 15-minute
    lookback window, and publishes detections to Redis `detections:lotl`.
    """

    def __init__(
        self,
        pg_dsn: Optional[str] = None,
        redis_client: Optional[Any] = None,
        network_fetcher: Optional[
            Callable[[Optional[str], Optional[str], datetime, int], List[Dict[str, Any]]]
        ] = None,
        correlation_window_minutes: int = LOTL_NETWORK_CORRELATION_WINDOW_MINUTES,
    ) -> None:
        self._pg_dsn = pg_dsn
        self._redis = redis_client
        self._network_fetcher = network_fetcher
        self._window_minutes = correlation_window_minutes

    # ------------------------------------------------------------------
    # Pattern evaluation
    # ------------------------------------------------------------------

    def match_patterns(self, event: Dict[str, Any]) -> List[LotlPatternMatch]:
        """Evaluate an endpoint process-creation event against all 8 LOTL rules."""
        # Only inspect process creation events (Sysmon Event ID 1) if event_type/event_id is provided
        event_type = str(event.get("event_type", "process_create")).lower()
        event_id_raw = event.get("event_id_raw") or event.get("event_id")
        if event_id_raw is not None and int(event_id_raw) != 1:
            return []
        if event_type not in ("process_create", "sysmon_1", "process_creation", ""):
            return []

        proc = _basename_lower(event.get("process_name"))
        parent = _basename_lower(
            event.get("parent_process_name") or event.get("parent_process")
        )
        cmdline = str(event.get("command_line") or event.get("cmdline") or "")
        cmdline_lower = cmdline.lower()

        matches: List[LotlPatternMatch] = []

        # 1. PowerShell with encoded commands
        if proc in ("powershell.exe", "pwsh.exe") or "powershell" in cmdline_lower:
            if (
                re.search(r"(?:^|\s)-(?:enc|encodedcommand)(?:\s|$)", cmdline_lower)
                or "frombase64string" in cmdline_lower
            ):
                matches.append(
                    LotlPatternMatch(
                        pattern_id="LOTL-001",
                        pattern_name="PowerShell Encoded Command",
                        mitre_technique="T1059.001",
                        suspicion_score=0.85,
                        matched_detail="Encoded PowerShell command (-enc/-EncodedCommand/FromBase64String)",
                    )
                )

        # 2. CertUtil download / encode / decode abuse
        if proc == "certutil.exe":
            certutil_flags = ("-urlcache", "/urlcache", "-decode", "/decode", "-encode", "/encode")
            has_flag = any(flag in cmdline_lower for flag in certutil_flags)
            has_url = bool(URL_REGEX.search(cmdline))
            if has_flag or has_url:
                matches.append(
                    LotlPatternMatch(
                        pattern_id="LOTL-002",
                        pattern_name="CertUtil Abuse / Ingress Tool Transfer",
                        mitre_technique="T1105",
                        suspicion_score=0.90 if has_url else 0.75,
                        matched_detail="certutil.exe invoked with download/decode/encode flags or external URL",
                    )
                )

        # 3. WMIC spawning unexpected child processes
        if parent == "wmiprvse.exe" and proc and proc not in BENIGN_WMIC_CHILDREN:
            matches.append(
                LotlPatternMatch(
                    pattern_id="LOTL-003",
                    pattern_name="WMI Provider Spawning Child Process",
                    mitre_technique="T1047",
                    suspicion_score=0.80,
                    matched_detail=f"wmiprvse.exe spawned unexpected child process '{proc}'",
                )
            )

        # 4. Mshta executing remote/inline scripts
        if proc == "mshta.exe":
            if URL_REGEX.search(cmdline) or any(
                tok in cmdline_lower for tok in ("vbscript:", "javascript:", ".hta")
            ):
                matches.append(
                    LotlPatternMatch(
                        pattern_id="LOTL-004",
                        pattern_name="Mshta Script Execution",
                        mitre_technique="T1218.005",
                        suspicion_score=0.90,
                        matched_detail="mshta.exe executing remote URL or script payload",
                    )
                )

        # 5. Regsvr32 with remote scripts (Squiblydoo)
        if proc == "regsvr32.exe":
            has_s = "/s" in cmdline_lower or "-s" in cmdline_lower
            has_u = "/u" in cmdline_lower or "-u" in cmdline_lower
            has_remote_i = bool(re.search(r"[/-]i:https?://", cmdline_lower))
            if has_remote_i and (has_s or has_u):
                matches.append(
                    LotlPatternMatch(
                        pattern_id="LOTL-005",
                        pattern_name="Regsvr32 Remote Script Execution (Squiblydoo)",
                        mitre_technique="T1218.010",
                        suspicion_score=0.95,
                        matched_detail="regsvr32.exe invoked with /s /u /i:http remote scriptlet",
                    )
                )

        # 6. Scheduled task creation
        if re.search(r"\bschtasks(?:\.exe)?\b.*(?:[/-]create)\b", cmdline_lower):
            matches.append(
                LotlPatternMatch(
                    pattern_id="LOTL-006",
                    pattern_name="Scheduled Task Creation",
                    mitre_technique="T1053.005",
                    suspicion_score=0.70,
                    matched_detail="schtasks /create persistence or lateral execution attempt",
                )
            )

        # 7. Net user /add or net localgroup administrators
        if re.search(r"\bnet1?(?:\.exe)?\s+user\b.*[/-]add\b", cmdline_lower) or re.search(
            r"\bnet1?(?:\.exe)?\s+localgroup\s+administrators\b", cmdline_lower
        ):
            matches.append(
                LotlPatternMatch(
                    pattern_id="LOTL-007",
                    pattern_name="Local Account / Admin Group Manipulation",
                    mitre_technique="T1136.001",
                    suspicion_score=0.85,
                    matched_detail="net user /add or net localgroup administrators modification",
                )
            )

        # 8. Suspicious parent-child: Office apps spawning cmd.exe / powershell.exe
        if parent in OFFICE_PARENTS and proc in SHELL_CHILDREN:
            matches.append(
                LotlPatternMatch(
                    pattern_id="LOTL-008",
                    pattern_name="Office Application Spawning Command Shell",
                    mitre_technique="T1566.001",
                    suspicion_score=0.90,
                    matched_detail=f"Office application '{parent}' spawned '{proc}'",
                )
            )

        return matches

    # ------------------------------------------------------------------
    # Full analysis + network correlation + Redis publish
    # ------------------------------------------------------------------

    def analyze_event(
        self, event: Dict[str, Any], publish: bool = True
    ) -> Optional[LotlIndicator]:
        """
        Inspect an endpoint event. If any LOTL pattern matches, correlate with
        recent network activity (last 15 min) and publish to `detections:lotl`.
        """
        matches = self.match_patterns(event)
        if not matches:
            return None

        ts = self._parse_timestamp(event.get("timestamp"))
        asset_id = event.get("asset_id")
        hostname = event.get("hostname")
        src_ip = event.get("source_ip") or event.get("host_ip")

        # Network correlation: look back 15 minutes for external connections
        recent_flows = self._fetch_recent_network_events(asset_id, src_ip, ts)
        external_conns = [
            f for f in recent_flows if is_external_ip(str(f.get("dst_ip") or ""))
        ]
        network_correlated = len(external_conns) > 0

        # Endpoint score: highest pattern score + small bonus for multiple matches
        base_score = max(m.suspicion_score for m in matches)
        multi_bonus = min(0.10, 0.05 * (len(matches) - 1))
        endpoint_score = min(1.0, base_score + multi_bonus)

        # Network correlation boosts combined score
        net_boost = 0.15 if network_correlated else 0.0
        combined_score = round(min(1.0, endpoint_score + net_boost), 4)

        if combined_score >= 0.90 or (network_correlated and combined_score >= 0.80):
            severity = "CRITICAL" if network_correlated and combined_score >= 0.95 else "HIGH"
        elif combined_score >= 0.70:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        indicator = LotlIndicator(
            indicator_id=str(uuid.uuid4()),
            timestamp=ts,
            asset_id=asset_id,
            hostname=hostname,
            user_name=event.get("user_name"),
            process_name=str(event.get("process_name") or ""),
            parent_process_name=event.get("parent_process_name")
            or event.get("parent_process"),
            command_line=str(event.get("command_line") or event.get("cmdline") or ""),
            matches=matches,
            endpoint_suspicion_score=round(endpoint_score, 4),
            external_connections=external_conns,
            network_correlated=network_correlated,
            combined_score=combined_score,
            mitre_techniques=sorted({m.mitre_technique for m in matches}),
            severity=severity,
        )

        if publish and self._redis is not None:
            self._publish_indicator(indicator)

        return indicator

    def consume_stream_once(
        self,
        last_id: str = "$",
        count: int = 100,
        block_ms: int = 1000,
    ) -> List[LotlIndicator]:
        """Read a batch of endpoint events from Redis stream `events:endpoint`."""
        if self._redis is None:
            raise RuntimeError("Redis client is required to consume events:endpoint")

        entries = self._redis.xread(
            {LOTL_ENDPOINT_STREAM: last_id}, count=count, block=block_ms
        )
        indicators: List[LotlIndicator] = []
        for _stream, messages in entries or []:
            for _msg_id, fields in messages:
                payload = self._decode_stream_fields(fields)
                ind = self.analyze_event(payload, publish=True)
                if ind is not None:
                    indicators.append(ind)
        return indicators

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _fetch_recent_network_events(
        self,
        asset_id: Optional[str],
        src_ip: Optional[str],
        ts: datetime,
    ) -> List[Dict[str, Any]]:
        if self._network_fetcher is not None:
            return self._network_fetcher(asset_id, src_ip, ts, self._window_minutes)

        if not self._pg_dsn or psycopg2 is None or (not asset_id and not src_ip):
            return []

        window_start = ts - timedelta(minutes=self._window_minutes)
        try:
            with psycopg2.connect(self._pg_dsn) as conn:
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                    if asset_id:
                        cur.execute(
                            """
                            SELECT timestamp, src_ip::text AS src_ip,
                                   dst_ip::text AS dst_ip, dst_port, protocol,
                                   orig_bytes, resp_bytes
                            FROM becpl_nids.network_flows
                            WHERE source_asset_id = %s
                              AND timestamp BETWEEN %s AND %s
                            ORDER BY timestamp DESC
                            LIMIT 200
                            """,
                            (asset_id, window_start, ts),
                        )
                    else:
                        cur.execute(
                            """
                            SELECT timestamp, src_ip::text AS src_ip,
                                   dst_ip::text AS dst_ip, dst_port, protocol,
                                   orig_bytes, resp_bytes
                            FROM becpl_nids.network_flows
                            WHERE src_ip = %s::inet
                              AND timestamp BETWEEN %s AND %s
                            ORDER BY timestamp DESC
                            LIMIT 200
                            """,
                            (src_ip, window_start, ts),
                        )
                    rows = []
                    for r in cur.fetchall():
                        d = dict(r)
                        if isinstance(d.get("timestamp"), datetime):
                            d["timestamp"] = d["timestamp"].isoformat()
                        rows.append(d)
                    return rows
        except Exception as exc:
            logger.warning("Failed PostgreSQL LOTL network correlation: %s", exc)
            return []

    def _publish_indicator(self, indicator: LotlIndicator) -> None:
        self._redis.xadd(
            LOTL_DETECTION_STREAM,
            {
                "indicator_id": indicator.indicator_id,
                "asset_id": indicator.asset_id or "",
                "severity": indicator.severity,
                "combined_score": str(indicator.combined_score),
                "network_correlated": str(indicator.network_correlated).lower(),
                "payload": json.dumps(indicator.to_dict()),
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

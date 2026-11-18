"""
VaultX Phase 2 - Threat Intelligence Feed Manager
BECPL (Bharat Electronics Components Pvt. Ltd.), Pune

Manages local threat intelligence data (no external API calls required):
- IP blocklist (data/threat_intel/ip_blocklist.txt)
- Malicious JA3 fingerprints (data/threat_intel/malicious_ja3.txt)
- CISA Known Exploited Vulnerabilities (data/threat_intel/cisa_kev.json)
- Offline CVE subset relevant to BECPL assets (data/threat_intel/cve_subset.json)

Loads feeds into Redis hashes at startup for O(1) lookup with an in-memory cache fallback:
- 'threat_intel:ip_blocklist'  -> {ip: {source, threat_type, added_date}}
- 'threat_intel:ja3_blocklist' -> {ja3_hash: {malware_family, source}}
- 'threat_intel:cisa_kev'      -> {cve_id: {vuln_name, date_added, ransomware_use}}
"""

from __future__ import annotations

import inspect
import json
import logging
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("vaultx.threat_intel.feeds")

DEFAULT_DATA_DIR = Path(__file__).resolve().parents[2] / "data" / "threat_intel"

REDIS_KEY_IP_BLOCKLIST = "threat_intel:ip_blocklist"
REDIS_KEY_JA3_BLOCKLIST = "threat_intel:ja3_blocklist"
REDIS_KEY_CISA_KEV = "threat_intel:cisa_kev"
REDIS_KEY_CVE_SUBSET = "threat_intel:cve_subset"


@dataclass
class ThreatIndicator:
    """Normalized threat intelligence lookup match."""

    indicator_type: str  # ip_blocklist | ja3_blocklist | cisa_kev | cve
    value: str
    source: str
    threat_type: str
    severity: str = "high"
    details: Dict[str, Any] = field(default_factory=dict)
    simulated: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ThreatIntelFeedManager:
    """
    Loads local threat intelligence feeds from disk and populates Redis hashes
    for fast lookups during packet/flow enrichment and correlation.
    """

    def __init__(
        self,
        data_dir: Optional[Path | str] = None,
        redis_client: Any = None,
        auto_load: bool = True,
    ) -> None:
        self.data_dir = Path(data_dir) if data_dir else DEFAULT_DATA_DIR
        self.redis_client = redis_client

        # In-memory lookup dictionaries (always maintained alongside Redis)
        self.ip_blocklist: Dict[str, Dict[str, Any]] = {}
        self.ja3_blocklist: Dict[str, Dict[str, Any]] = {}
        self.cisa_kev: Dict[str, Dict[str, Any]] = {}
        self.cve_catalog: Dict[str, Dict[str, Any]] = {}

        if auto_load:
            self.load_all_feeds()

    # ------------------------------------------------------------------
    # Feed Loading
    # ------------------------------------------------------------------
    def load_all_feeds(self) -> Dict[str, int]:
        """Load all local threat intelligence files from data_dir."""
        ip_count = self._load_ip_blocklist(self.data_dir / "ip_blocklist.txt")
        ja3_count = self._load_ja3_blocklist(self.data_dir / "malicious_ja3.txt")
        kev_count = self._load_cisa_kev(self.data_dir / "cisa_kev.json")
        cve_count = self._load_cve_subset(self.data_dir / "cve_subset.json")

        counts = {
            "ip_blocklist": ip_count,
            "ja3_blocklist": ja3_count,
            "cisa_kev": kev_count,
            "cve_subset": cve_count,
        }
        logger.info("Loaded threat intelligence feeds: %s", counts)

        # Synchronize immediately if a synchronous Redis client is attached
        if self.redis_client is not None and not inspect.iscoroutinefunction(
            getattr(self.redis_client, "hset", None)
        ):
            self.sync_to_redis_sync()

        return counts

    def _load_ip_blocklist(self, filepath: Path) -> int:
        self.ip_blocklist.clear()
        if not filepath.exists():
            logger.warning("IP blocklist file not found: %s", filepath)
            return 0
        for raw_line in filepath.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            parts = [p.strip() for p in line.split("|")]
            ip = parts[0]
            source = parts[1] if len(parts) > 1 else "local_blocklist"
            threat_type = parts[2] if len(parts) > 2 else "malicious_ip"
            added_date = parts[3] if len(parts) > 3 else ""
            self.ip_blocklist[ip] = {
                "source": source,
                "threat_type": threat_type,
                "added_date": added_date,
                "simulated": True,
            }
        return len(self.ip_blocklist)

    def _load_ja3_blocklist(self, filepath: Path) -> int:
        self.ja3_blocklist.clear()
        if not filepath.exists():
            logger.warning("JA3 blocklist file not found: %s", filepath)
            return 0
        for raw_line in filepath.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            parts = [p.strip() for p in line.split("|")]
            ja3_hash = parts[0].lower()
            malware_family = parts[1] if len(parts) > 1 else "unknown_malware"
            source = parts[2] if len(parts) > 2 else "local_ja3_list"
            self.ja3_blocklist[ja3_hash] = {
                "malware_family": malware_family,
                "source": source,
                "simulated": True,
            }
        return len(self.ja3_blocklist)

    def _load_cisa_kev(self, filepath: Path) -> int:
        self.cisa_kev.clear()
        if not filepath.exists():
            logger.warning("CISA KEV file not found: %s", filepath)
            return 0
        payload = json.loads(filepath.read_text(encoding="utf-8"))
        entries = payload.get("vulnerabilities", []) if isinstance(payload, dict) else payload
        for item in entries:
            cve_id = str(item.get("cveID") or item.get("cve_id") or "").upper()
            if not cve_id:
                continue
            self.cisa_kev[cve_id] = {
                "vuln_name": item.get("vulnerabilityName") or item.get("vuln_name", ""),
                "vendor_project": item.get("vendorProject", ""),
                "product": item.get("product", ""),
                "date_added": item.get("dateAdded") or item.get("date_added", ""),
                "due_date": item.get("dueDate", ""),
                "short_description": item.get("shortDescription", ""),
                "required_action": item.get("requiredAction", ""),
                "ransomware_use": item.get("knownRansomwareCampaignUse")
                or item.get("ransomware_use", "Unknown"),
                "simulated": bool(payload.get("simulated", True))
                if isinstance(payload, dict)
                else True,
            }
        return len(self.cisa_kev)

    def _load_cve_subset(self, filepath: Path) -> int:
        self.cve_catalog.clear()
        if not filepath.exists():
            logger.warning("CVE subset file not found: %s", filepath)
            return 0
        payload = json.loads(filepath.read_text(encoding="utf-8"))
        entries = payload.get("cves", []) if isinstance(payload, dict) else payload
        for item in entries:
            cve_id = str(item.get("cve_id") or "").upper()
            if not cve_id:
                continue
            self.cve_catalog[cve_id] = item
        return len(self.cve_catalog)

    # ------------------------------------------------------------------
    # Redis Synchronization (Sync & Async)
    # ------------------------------------------------------------------
    def sync_to_redis_sync(self) -> Dict[str, int]:
        """Populate Redis hashes synchronously for O(1) runtime lookups."""
        if self.redis_client is None:
            return {"ip_blocklist": 0, "ja3_blocklist": 0, "cisa_kev": 0}

        if self.ip_blocklist:
            self.redis_client.hset(
                REDIS_KEY_IP_BLOCKLIST,
                mapping={ip: json.dumps(meta) for ip, meta in self.ip_blocklist.items()},
            )
        if self.ja3_blocklist:
            self.redis_client.hset(
                REDIS_KEY_JA3_BLOCKLIST,
                mapping={h: json.dumps(meta) for h, meta in self.ja3_blocklist.items()},
            )
        if self.cisa_kev:
            self.redis_client.hset(
                REDIS_KEY_CISA_KEV,
                mapping={cve: json.dumps(meta) for cve, meta in self.cisa_kev.items()},
            )
        if self.cve_catalog:
            self.redis_client.hset(
                REDIS_KEY_CVE_SUBSET,
                mapping={cve: json.dumps(meta) for cve, meta in self.cve_catalog.items()},
            )
        return {
            "ip_blocklist": len(self.ip_blocklist),
            "ja3_blocklist": len(self.ja3_blocklist),
            "cisa_kev": len(self.cisa_kev),
            "cve_subset": len(self.cve_catalog),
        }

    async def sync_to_redis(self) -> Dict[str, int]:
        """Populate Redis hashes asynchronously (compatible with redis.asyncio / aioredis)."""
        if self.redis_client is None:
            return {"ip_blocklist": 0, "ja3_blocklist": 0, "cisa_kev": 0}

        async def _hset(key: str, mapping: Dict[str, str]) -> None:
            if not mapping:
                return
            result = self.redis_client.hset(key, mapping=mapping)
            if inspect.isawaitable(result):
                await result

        await _hset(
            REDIS_KEY_IP_BLOCKLIST,
            {ip: json.dumps(meta) for ip, meta in self.ip_blocklist.items()},
        )
        await _hset(
            REDIS_KEY_JA3_BLOCKLIST,
            {h: json.dumps(meta) for h, meta in self.ja3_blocklist.items()},
        )
        await _hset(
            REDIS_KEY_CISA_KEV,
            {cve: json.dumps(meta) for cve, meta in self.cisa_kev.items()},
        )
        await _hset(
            REDIS_KEY_CVE_SUBSET,
            {cve: json.dumps(meta) for cve, meta in self.cve_catalog.items()},
        )
        return {
            "ip_blocklist": len(self.ip_blocklist),
            "ja3_blocklist": len(self.ja3_blocklist),
            "cisa_kev": len(self.cisa_kev),
            "cve_subset": len(self.cve_catalog),
        }

    # ------------------------------------------------------------------
    # Lookup API
    # ------------------------------------------------------------------
    def _redis_hget_sync(self, key: str, field_name: str) -> Optional[Dict[str, Any]]:
        if self.redis_client is None:
            return None
        hget = getattr(self.redis_client, "hget", None)
        if hget is None or inspect.iscoroutinefunction(hget):
            return None
        try:
            raw = hget(key, field_name)
            if raw is None:
                return None
            if isinstance(raw, bytes):
                raw = raw.decode("utf-8")
            return json.loads(raw)
        except Exception as exc:  # pragma: no cover
            logger.debug("Redis hget fallback (%s:%s): %s", key, field_name, exc)
            return None

    def check_ip(self, ip: str) -> Optional[ThreatIndicator]:
        """Check whether an IP address appears on the local/Redis threat blocklist."""
        if not ip:
            return None
        ip_clean = ip.strip()
        meta = self._redis_hget_sync(REDIS_KEY_IP_BLOCKLIST, ip_clean) or self.ip_blocklist.get(
            ip_clean
        )
        if not meta:
            return None

        threat_type = meta.get("threat_type", "malicious_ip")
        severity = (
            "critical"
            if threat_type == "command_and_control"
            else "high"
            if threat_type in ("malware_distribution", "phishing", "tor_exit_node")
            else "medium"
        )
        return ThreatIndicator(
            indicator_type="ip_blocklist",
            value=ip_clean,
            source=meta.get("source", "local_blocklist"),
            threat_type=threat_type,
            severity=severity,
            details=meta,
            simulated=bool(meta.get("simulated", True)),
        )

    def check_ja3(self, ja3_hash: str) -> Optional[ThreatIndicator]:
        """Check whether a TLS JA3 hash matches known malicious fingerprints."""
        if not ja3_hash:
            return None
        normalized = ja3_hash.strip().lower()
        meta = self._redis_hget_sync(
            REDIS_KEY_JA3_BLOCKLIST, normalized
        ) or self.ja3_blocklist.get(normalized)
        if not meta:
            return None

        return ThreatIndicator(
            indicator_type="ja3_blocklist",
            value=normalized,
            source=meta.get("source", "local_ja3_list"),
            threat_type=meta.get("malware_family", "malicious_ja3"),
            severity="high",
            details=meta,
            simulated=bool(meta.get("simulated", True)),
        )

    def check_cve(self, cve_id: str) -> Optional[ThreatIndicator]:
        """
        Check a CVE ID against CISA KEV and the local BECPL CVE catalog.
        Returns a ThreatIndicator with KEV metadata if known-exploited or cataloged.
        """
        if not cve_id:
            return None
        normalized = cve_id.strip().upper()
        kev_meta = self._redis_hget_sync(REDIS_KEY_CISA_KEV, normalized) or self.cisa_kev.get(
            normalized
        )
        cve_meta = self.cve_catalog.get(normalized)

        if not kev_meta and not cve_meta:
            return None

        details: Dict[str, Any] = {}
        if cve_meta:
            details.update(cve_meta)
        if kev_meta:
            details["cisa_kev"] = kev_meta
            details["is_kev"] = True
        else:
            details["is_kev"] = False

        severity = "critical" if kev_meta else str((cve_meta or {}).get("severity", "high"))
        return ThreatIndicator(
            indicator_type="cisa_kev" if kev_meta else "cve",
            value=normalized,
            source="cisa_kev" if kev_meta else "local_cve_subset",
            threat_type="known_exploited_vulnerability" if kev_meta else "known_cve",
            severity=severity,
            details=details,
            simulated=True,
        )

    def is_kev(self, cve_id: str) -> bool:
        """Return True if the CVE appears in the CISA KEV catalog."""
        return cve_id.strip().upper() in self.cisa_kev

    def get_cve_catalog(self) -> List[Dict[str, Any]]:
        """Return all CVEs in the local catalog."""
        return list(self.cve_catalog.values())

    def get_kev_catalog(self) -> Dict[str, Dict[str, Any]]:
        """Return all loaded CISA KEV entries keyed by CVE ID."""
        return dict(self.cisa_kev)

    def summary(self) -> Dict[str, Any]:
        """Summary counts for health/API reporting."""
        return {
            "ip_blocklist_count": len(self.ip_blocklist),
            "ja3_blocklist_count": len(self.ja3_blocklist),
            "cisa_kev_count": len(self.cisa_kev),
            "cve_catalog_count": len(self.cve_catalog),
            "data_dir": str(self.data_dir),
            "simulated": True,
        }

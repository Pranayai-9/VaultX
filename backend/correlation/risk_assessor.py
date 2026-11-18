"""
VaultX Phase 2 - Infrastructure Section-Level Risk Assessor
BECPL (Bharat Electronics Components Pvt. Ltd.), Pune

Evaluates each of the 6 operational infrastructure sections:
  1. Corporate IT           (VLAN 10)
  2. Engineering/Firmware   (VLAN 20)
  3. Manufacturing OT       (VLAN 30)
  4. Warehouse/Logistics    (VLAN 40)
  5. Third-Party            (VLAN 50 / Vendors)
  6. Cloud                  (VLAN 60)

Per section, computes:
  - active_incident_count
  - critical_asset_count_in_incidents
  - vulnerability_exposure_score
  - anomaly_rate_24h
  - communication_anomaly_count

Section risk levels:
  - SECURE     : no active incidents and no elevated anomalies
  - ELEVATED   : anomalies or elevated vulnerability exposure present, no active incidents
  - THREATENED : active incident present (non-critical)
  - CRITICAL   : critical incident OR OT compromise / OT safety flag

Writes section risk summary to Redis hash 'risk:sections' (refreshed every 2 minutes)
and writes historical records to PostgreSQL security_events (event_type='risk_assessment').
"""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("vaultx.correlation.risk_assessor")

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_ASSETS_PATH = REPO_ROOT / "infra" / "topology" / "assets.json"
REDIS_HASH_RISK_SECTIONS = "risk:sections"
DEFAULT_REFRESH_INTERVAL_SECONDS = 120  # 2 minutes

INFRASTRUCTURE_SECTIONS: Tuple[str, ...] = (
    "Corporate IT",
    "Engineering/Firmware",
    "Manufacturing OT",
    "Warehouse/Logistics",
    "Third-Party",
    "Cloud",
)

SECTION_TO_VLAN: Dict[str, int] = {
    "Corporate IT": 10,
    "Engineering/Firmware": 20,
    "Manufacturing OT": 30,
    "Warehouse/Logistics": 40,
    "Third-Party": 50,
    "Cloud": 60,
}

ZONE_ALIAS_TO_SECTION: Dict[str, str] = {
    "corporate it": "Corporate IT",
    "corporate": "Corporate IT",
    "vlan 10": "Corporate IT",
    "engineering & firmware": "Engineering/Firmware",
    "engineering/firmware": "Engineering/Firmware",
    "engineering": "Engineering/Firmware",
    "vlan 20": "Engineering/Firmware",
    "manufacturing ot": "Manufacturing OT",
    "ot": "Manufacturing OT",
    "ot manufacturing": "Manufacturing OT",
    "vlan 30": "Manufacturing OT",
    "warehouse & logistics": "Warehouse/Logistics",
    "warehouse/logistics": "Warehouse/Logistics",
    "warehouse": "Warehouse/Logistics",
    "vlan 40": "Warehouse/Logistics",
    "dmz & vendor access": "Third-Party",
    "third-party": "Third-Party",
    "third party": "Third-Party",
    "dmz": "Third-Party",
    "vendor": "Third-Party",
    "vlan 50": "Third-Party",
    "cloud & external integrations": "Cloud",
    "cloud": "Cloud",
    "vlan 60": "Cloud",
}


class SectionRiskLevel(str, Enum):
    SECURE = "SECURE"
    ELEVATED = "ELEVATED"
    THREATENED = "THREATENED"
    CRITICAL = "CRITICAL"


@dataclass
class SectionRiskAssessment:
    section: str
    vlan_id: int
    risk_level: SectionRiskLevel
    active_incident_count: int
    critical_asset_count_in_incidents: int
    vulnerability_exposure_score: float
    anomaly_rate_24h: float
    communication_anomaly_count: int
    recommended_actions: List[str] = field(default_factory=list)
    assessed_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["risk_level"] = self.risk_level.value
        return data


class RiskAssessor:
    """Computes real-time risk levels and actionable recommendations across BECPL's 6 sections."""

    def __init__(
        self,
        assets_path: Optional[Path | str] = None,
        db_client: Any = None,
        redis_client: Any = None,
        refresh_interval_seconds: int = DEFAULT_REFRESH_INTERVAL_SECONDS,
    ) -> None:
        self.assets_path = Path(assets_path) if assets_path else DEFAULT_ASSETS_PATH
        self.db_client = db_client
        self.redis_client = redis_client
        self.refresh_interval_seconds = refresh_interval_seconds
        self.assets: Dict[str, Dict[str, Any]] = {}
        self.latest_assessments: Dict[str, SectionRiskAssessment] = {}
        self._load_assets()

    def _load_assets(self) -> None:
        if not self.assets_path.exists():
            return
        try:
            for asset in json.loads(self.assets_path.read_text(encoding="utf-8")):
                aid = asset.get("asset_id")
                if aid:
                    self.assets[aid] = asset
        except Exception as exc:
            logger.warning("Failed loading assets.json for RiskAssessor: %s", exc)

    def _map_asset_to_section(self, asset_id: str) -> Optional[str]:
        if asset_id in self.assets:
            vlan = self.assets[asset_id].get("vlan")
            for sec, sec_vlan in SECTION_TO_VLAN.items():
                if vlan == sec_vlan:
                    return sec
            seg = str(self.assets[asset_id].get("network_segment", "")).lower()
            if seg in ZONE_ALIAS_TO_SECTION:
                return ZONE_ALIAS_TO_SECTION[seg]

        upper = asset_id.upper()
        if upper.startswith("CORP-"):
            return "Corporate IT"
        if upper.startswith("ENG-") or "FIRMWARE" in upper:
            return "Engineering/Firmware"
        if upper.startswith("OT-") or "MES" in upper or "PLC" in upper or "HMI" in upper:
            return "Manufacturing OT"
        if upper.startswith("WH-"):
            return "Warehouse/Logistics"
        if upper.startswith("DMZ-") or upper.startswith("VEND-"):
            return "Third-Party"
        if upper.startswith("CLOUD-") or upper.startswith("EXT-"):
            return "Cloud"
        return None

    def _map_zone_to_section(self, zone: Optional[str]) -> Optional[str]:
        if not zone:
            return None
        return ZONE_ALIAS_TO_SECTION.get(zone.strip().lower())

    def _sections_for_incident(self, incident: Dict[str, Any]) -> List[str]:
        sections = set()
        for zone in incident.get("affected_zones") or []:
            mapped = self._map_zone_to_section(zone)
            if mapped:
                sections.add(mapped)
        for aid in incident.get("affected_assets") or []:
            mapped = self._map_asset_to_section(str(aid))
            if mapped:
                sections.add(mapped)
        if str(incident.get("rule_id", "")).startswith("RULE-VENDOR-"):
            sections.add("Third-Party")
        if incident.get("ot_safety_flag"):
            sections.add("Manufacturing OT")
        return sorted(sections)

    def _is_critical_asset(self, asset_id: str) -> bool:
        if asset_id in self.assets:
            return str(self.assets[asset_id].get("criticality", "")).lower() == "critical"
        upper = asset_id.upper()
        return any(tok in upper for tok in ("PLC", "HMI", "SCADA", "MES", "DC-", "GIT", "OTA"))

    # ------------------------------------------------------------------
    # Section Risk Evaluation
    # ------------------------------------------------------------------
    def assess_all_sections(
        self,
        incidents: Optional[List[Dict[str, Any]]] = None,
        vulnerabilities: Optional[List[Dict[str, Any]]] = None,
        anomalies_24h: Optional[List[Dict[str, Any]]] = None,
        communication_anomalies: Optional[List[Dict[str, Any]]] = None,
        publish: bool = True,
    ) -> Dict[str, SectionRiskAssessment]:
        """Compute risk posture for all 6 sections."""
        active_incidents = [
            inc
            for inc in (incidents or [])
            if str(inc.get("status", "open")).lower() in ("open", "investigating")
        ]

        results: Dict[str, SectionRiskAssessment] = {}
        for section in INFRASTRUCTURE_SECTIONS:
            sec_incidents = [
                inc for inc in active_incidents if section in self._sections_for_incident(inc)
            ]
            sec_vulns = [
                v
                for v in (vulnerabilities or [])
                if self._map_asset_to_section(str(v.get("asset_id", ""))) == section
            ]
            sec_anoms = [
                a
                for a in (anomalies_24h or [])
                if (
                    self._map_zone_to_section(a.get("network_zone") or a.get("section")) == section
                    or self._map_asset_to_section(
                        str(a.get("source_asset_id") or a.get("destination_asset_id") or a.get("asset_id") or "")
                    )
                    == section
                )
            ]
            sec_comm_anoms = [
                c
                for c in (communication_anomalies or [])
                if (
                    self._map_asset_to_section(str(c.get("source", ""))) == section
                    or self._map_asset_to_section(str(c.get("destination", ""))) == section
                    or self._map_zone_to_section(c.get("section")) == section
                )
            ]

            critical_assets_in_inc = {
                aid
                for inc in sec_incidents
                for aid in (inc.get("affected_assets") or [])
                if self._is_critical_asset(str(aid))
            }

            vuln_score = round(
                sum(float(v.get("risk_score") or v.get("cvss_score") or 0.0) for v in sec_vulns),
                2,
            )
            anomaly_rate_24h = round(len(sec_anoms) / 24.0, 3)
            comm_anom_count = len(sec_comm_anoms)

            has_critical_incident = any(
                str(inc.get("severity", "")).lower() == "critical" for inc in sec_incidents
            )
            has_ot_compromise = section == "Manufacturing OT" and any(
                bool(inc.get("ot_safety_flag")) or str(inc.get("severity", "")).lower() == "critical"
                for inc in sec_incidents
            )

            if has_critical_incident or has_ot_compromise:
                level = SectionRiskLevel.CRITICAL
            elif len(sec_incidents) > 0:
                level = SectionRiskLevel.THREATENED
            elif len(sec_anoms) > 0 or comm_anom_count > 0 or vuln_score >= 15.0:
                level = SectionRiskLevel.ELEVATED
            else:
                level = SectionRiskLevel.SECURE

            recommendations = self._generate_recommendations(
                section=section,
                risk_level=level,
                incidents=sec_incidents,
                vulns=sec_vulns,
                comm_anoms=sec_comm_anoms,
                anomaly_count=len(sec_anoms),
            )

            assessment = SectionRiskAssessment(
                section=section,
                vlan_id=SECTION_TO_VLAN[section],
                risk_level=level,
                active_incident_count=len(sec_incidents),
                critical_asset_count_in_incidents=len(critical_assets_in_inc),
                vulnerability_exposure_score=vuln_score,
                anomaly_rate_24h=anomaly_rate_24h,
                communication_anomaly_count=comm_anom_count,
                recommended_actions=recommendations,
            )
            results[section] = assessment

        self.latest_assessments = results
        if publish:
            self._publish_redis_sync(results)
            self._persist_history_sync(results)

        return results

    @staticmethod
    def _generate_recommendations(
        section: str,
        risk_level: SectionRiskLevel,
        incidents: List[Dict[str, Any]],
        vulns: List[Dict[str, Any]],
        comm_anoms: List[Dict[str, Any]],
        anomaly_count: int,
    ) -> List[str]:
        actions: List[str] = []

        for inc in incidents:
            ref = inc.get("incident_reference") or inc.get("incident_id", "INC")
            assets = ", ".join(inc.get("affected_assets") or ["affected host"])
            if inc.get("ot_safety_flag") or section == "Manufacturing OT":
                actions.append(
                    f"Review firewall rule for VLAN 30 Modbus access and verify OT safety before isolating {assets} ({ref})"
                )
            elif section == "Third-Party":
                actions.append(
                    f"Investigate unusual vendor connection involving {assets} and audit VPN session logs ({ref})"
                )
            else:
                actions.append(
                    f"Investigate active {inc.get('severity', 'high')} incident {ref} on {assets}"
                )

        for comm in comm_anoms[:3]:
            src = comm.get("source", "unknown")
            dst = comm.get("destination", "unknown")
            actions.append(
                f"Review unapproved communication path from {src} to {dst} against communication_matrix.json"
            )

        kev_vulns = [v for v in vulns if v.get("is_kev")]
        for kv in kev_vulns[:3]:
            actions.append(
                f"Prioritize remediation of CISA KEV {kv.get('cve_id')} on {kv.get('asset_id')}"
            )

        if not actions and anomaly_count > 0:
            actions.append(
                f"Triage {anomaly_count} recent anomaly indicator(s) in {section} over the last 24 hours"
            )
        if not actions and risk_level == SectionRiskLevel.SECURE:
            actions.append(f"Maintain routine passive monitoring for {section}")

        return actions

    # ------------------------------------------------------------------
    # Redis & PostgreSQL Sync/Async Writers
    # ------------------------------------------------------------------
    def _publish_redis_sync(self, assessments: Dict[str, SectionRiskAssessment]) -> None:
        if self.redis_client is None:
            return
        hset = getattr(self.redis_client, "hset", None)
        if hset is None or inspect.iscoroutinefunction(hset):
            return
        try:
            mapping = {sec: json.dumps(a.to_dict()) for sec, a in assessments.items()}
            hset(REDIS_HASH_RISK_SECTIONS, mapping=mapping)
        except Exception as exc:
            logger.error("Failed writing risk:sections hash to Redis: %s", exc)

    async def publish_to_redis(self, assessments: Dict[str, SectionRiskAssessment]) -> None:
        if self.redis_client is None:
            return
        mapping = {sec: json.dumps(a.to_dict()) for sec, a in assessments.items()}
        res = self.redis_client.hset(REDIS_HASH_RISK_SECTIONS, mapping=mapping)
        if inspect.isawaitable(res):
            await res

    def _persist_history_sync(self, assessments: Dict[str, SectionRiskAssessment]) -> None:
        if self.db_client is None:
            return
        execute = getattr(self.db_client, "execute", None)
        if execute is None or inspect.iscoroutinefunction(execute):
            return
        sql = """
            INSERT INTO becpl_nids.security_events (
                event_id, timestamp, sensor_id, network_zone,
                event_type, detection_source, severity, confidence, evidence
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        for section, a in assessments.items():
            sev = (
                "critical"
                if a.risk_level == SectionRiskLevel.CRITICAL
                else "high"
                if a.risk_level == SectionRiskLevel.THREATENED
                else "medium"
                if a.risk_level == SectionRiskLevel.ELEVATED
                else "informational"
            )
            try:
                execute(
                    sql,
                    (
                        str(uuid.uuid4()),
                        a.assessed_at,
                        "vaultx-risk-assessor",
                        section,
                        "risk_assessment",
                        "manual",
                        sev,
                        1.0,
                        json.dumps(a.to_dict()),
                    ),
                )
            except Exception as exc:
                logger.error("Failed persisting risk_assessment for %s: %s", section, exc)

    async def persist_history(self, assessments: Dict[str, SectionRiskAssessment]) -> None:
        if self.db_client is None:
            return
        sql = """
            INSERT INTO becpl_nids.security_events (
                event_id, timestamp, sensor_id, network_zone,
                event_type, detection_source, severity, confidence, evidence
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        """
        for section, a in assessments.items():
            sev = (
                "critical"
                if a.risk_level == SectionRiskLevel.CRITICAL
                else "high"
                if a.risk_level == SectionRiskLevel.THREATENED
                else "medium"
                if a.risk_level == SectionRiskLevel.ELEVATED
                else "informational"
            )
            res = self.db_client.execute(
                sql,
                str(uuid.uuid4()),
                a.assessed_at,
                "vaultx-risk-assessor",
                section,
                "risk_assessment",
                "manual",
                sev,
                1.0,
                json.dumps(a.to_dict()),
            )
            if inspect.isawaitable(res):
                await res

    async def run_periodic(
        self, data_provider: Any, stop_event: Optional[asyncio.Event] = None
    ) -> None:
        """Periodically recompute section risk every 2 minutes."""
        while stop_event is None or not stop_event.is_set():
            snapshot = data_provider()
            if inspect.isawaitable(snapshot):
                snapshot = await snapshot
            assessments = self.assess_all_sections(
                incidents=snapshot.get("incidents", []),
                vulnerabilities=snapshot.get("vulnerabilities", []),
                anomalies_24h=snapshot.get("anomalies_24h", []),
                communication_anomalies=snapshot.get("communication_anomalies", []),
                publish=False,
            )
            await self.publish_to_redis(assessments)
            await self.persist_history(assessments)
            await asyncio.sleep(self.refresh_interval_seconds)

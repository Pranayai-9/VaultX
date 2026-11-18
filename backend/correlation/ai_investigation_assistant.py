"""
VaultX Phase 2 - AI-Assisted Systemic Investigation Assistant
BECPL (Bharat Electronics Components Pvt. Ltd.), Pune

STRICT OPERATING BOUNDARY:
  EXPLANATION ONLY — NO AUTONOMOUS ACTION.
  - Retrieves stored evidence from PostgreSQL (or supplied evidence provider).
  - Generates structured investigation summary with 9 mandatory fields grounded
    exclusively in stored event_ids and database records (never fabricates claims).
  - Works offline via deterministic templates without any LLM dependency.
  - Optional LLM integration hook: if OPENAI_API_KEY or GEMINI_API_KEY is set,
    sends ONLY the structured evidence dict to generate a human-readable narrative
    stored in `incident.investigation_narrative`, explicitly marked:
      "AI-assisted analysis — verify with original evidence"
  - LLM strictly cannot modify incident records or trigger containment actions.
  - Writes structured summary to `incidents.investigation_summary` (JSONB).
"""

from __future__ import annotations

import inspect
import json
import logging
import os
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from .blast_radius_analyzer import BlastRadiusAnalyzer, OT_SAFETY_NOTE

logger = logging.getLogger("vaultx.correlation.ai_investigation")

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_ASSETS_PATH = REPO_ROOT / "infra" / "topology" / "assets.json"
AI_DISCLAIMER = "AI-assisted analysis — verify with original evidence"


@dataclass
class InvestigationSummary:
    """Structured 9-field evidence-grounded investigation summary."""

    incident_id: str
    incident_reference: str
    generated_at: str
    # 9 Mandatory Fields:
    what_happened: str
    where: Dict[str, Any]
    first_indicator: Dict[str, Any]
    affected_assets: List[Dict[str, Any]]
    involved_identities: List[Dict[str, Any]]
    related_events: List[Dict[str, Any]]
    potential_impact: Dict[str, Any]
    investigation_recommendations: List[str]
    containment_options: List[Dict[str, Any]]
    # Optional narrative produced via external LLM hook (never alters evidence)
    investigation_narrative: Optional[str] = None
    autonomous_action_taken: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class AIInvestigationAssistant:
    """
    Produces evidence-backed 9-field incident investigation summaries and
    optional LLM-assisted narratives without ever executing autonomous actions.
    """

    def __init__(
        self,
        db_client: Any = None,
        assets_path: Optional[Path | str] = None,
        blast_radius_analyzer: Optional[BlastRadiusAnalyzer] = None,
        enable_llm_hook: bool = True,
    ) -> None:
        self.db_client = db_client
        self.assets_path = Path(assets_path) if assets_path else DEFAULT_ASSETS_PATH
        self.blast_radius_analyzer = blast_radius_analyzer or BlastRadiusAnalyzer(
            assets_path=self.assets_path, db_client=db_client
        )
        self.enable_llm_hook = enable_llm_hook
        self.assets: Dict[str, Dict[str, Any]] = dict(self.blast_radius_analyzer.assets)

    # ------------------------------------------------------------------
    # Investigation Generation (Sync + Async)
    # ------------------------------------------------------------------
    def investigate(
        self,
        incident: Dict[str, Any],
        related_events: List[Dict[str, Any]],
        identities: Optional[List[Dict[str, Any]]] = None,
        blast_radius: Optional[Dict[str, Any]] = None,
        persist: bool = True,
    ) -> InvestigationSummary:
        """
        Build a complete 9-field investigation summary grounded strictly in stored
        incident data and related event records.
        """
        incident_id = str(incident.get("incident_id", ""))
        incident_ref = str(incident.get("incident_reference") or incident_id)
        rule_id = str(incident.get("rule_id") or "UNSPECIFIED_RULE")
        severity = str(incident.get("severity", "medium")).lower()
        ot_safety_flag = bool(incident.get("ot_safety_flag", False))

        # Sort stored events chronologically so first_indicator is strictly accurate
        sorted_events = sorted(
            related_events,
            key=lambda e: str(e.get("timestamp") or ""),
        )
        event_ids = [str(e.get("event_id")) for e in sorted_events if e.get("event_id")]

        # 1. Affected assets with criticality & production impact
        asset_ids = list(incident.get("affected_assets") or [])
        for ev in sorted_events:
            for key in ("source_asset_id", "destination_asset_id", "asset_id"):
                val = ev.get(key)
                if val and str(val) not in asset_ids:
                    asset_ids.append(str(val))

        if blast_radius is None:
            br_obj = self.blast_radius_analyzer.analyze(
                incident_id=incident_id,
                affected_assets=asset_ids,
                publish=False,
            )
            blast_radius = br_obj.to_dict()

        affected_assets_list = blast_radius.get("directly_affected_assets", [])
        zones = sorted(
            set(incident.get("affected_zones") or [])
            | set(blast_radius.get("related_zones") or [])
        )

        # 2. Involved identities grounded in events + identity records
        involved_identities = self._collect_identities(sorted_events, identities or [])

        # 3. First indicator (earliest stored event)
        if sorted_events:
            earliest = sorted_events[0]
            first_indicator = {
                "event_id": str(earliest.get("event_id", "")),
                "timestamp": str(earliest.get("timestamp", incident.get("first_seen", ""))),
                "event_type": str(
                    earliest.get("event_type")
                    or earliest.get("indicator_type")
                    or "security_event"
                ),
                "source_asset": earliest.get("source_asset_id") or earliest.get("source_ip"),
                "destination_asset": earliest.get("destination_asset_id")
                or earliest.get("destination_ip"),
                "summary": str(
                    earliest.get("signature")
                    or earliest.get("description")
                    or earliest.get("indicator_type")
                    or earliest.get("event_type")
                    or "Initial correlated indicator"
                ),
            }
        else:
            first_indicator = {
                "event_id": None,
                "timestamp": str(incident.get("first_seen", "")),
                "event_type": "unknown",
                "summary": "No raw event records attached to this incident yet.",
            }

        # 4. Related events list (strictly referencing stored event_ids & timestamps)
        formatted_events = [
            {
                "event_id": str(ev.get("event_id", "")),
                "timestamp": str(ev.get("timestamp", "")),
                "event_type": str(
                    ev.get("event_type") or ev.get("indicator_type") or "security_event"
                ),
                "detection_source": str(ev.get("detection_source") or ev.get("_stream") or "vaultx"),
                "severity": str(ev.get("severity", severity)),
                "source_asset": ev.get("source_asset_id") or ev.get("source_ip"),
                "destination_asset": ev.get("destination_asset_id") or ev.get("destination_ip"),
            }
            for ev in sorted_events
        ]

        # 5. Factual what_happened template citing event_ids
        mitre = incident.get("mitre_techniques") or []
        mitre_str = ", ".join(mitre) if mitre else str(incident.get("mitre_technique") or "N/A")
        what_happened = (
            f"Incident {incident_ref} ({rule_id}, severity={severity.upper()}, MITRE={mitre_str}): "
            f"{incident.get('description') or incident.get('title') or 'Correlated threat activity detected.'} "
            f"Supported by {len(event_ids)} stored event(s): [{', '.join(event_ids[:10])}]."
        )

        # 6. Where
        where = {
            "affected_assets": asset_ids,
            "affected_zones": zones,
            "potentially_affected_1hop_assets": [
                a["asset_id"] for a in blast_radius.get("potentially_affected_assets", [])
            ],
        }

        # 7. Potential operational impact (grounded in asset criticality & OT flags)
        critical_assets = [
            a["asset_id"] for a in affected_assets_list if a.get("criticality") == "critical"
        ]
        ot_assets = [
            a["asset_id"]
            for a in affected_assets_list
            if a.get("vlan") == 30 or a.get("safety_note")
        ]
        potential_impact = {
            "overall_severity": severity,
            "critical_assets_affected": critical_assets,
            "ot_assets_affected": ot_assets,
            "ot_safety_flag": ot_safety_flag or bool(ot_assets),
            "safety_warnings": blast_radius.get("safety_notes", [])
            or ([OT_SAFETY_NOTE] if (ot_safety_flag or ot_assets) else []),
            "operational_summary": self._summarize_impact(
                affected_assets_list, ot_safety_flag or bool(ot_assets)
            ),
            "supporting_event_ids": event_ids,
        }

        # 8. Specific analyst investigation recommendations
        recommendations = self._build_recommendations(
            rule_id=rule_id,
            asset_ids=asset_ids,
            identities=involved_identities,
            event_ids=event_ids,
            ot_safety=ot_safety_flag or bool(ot_assets),
        )

        # 9. Containment options (aligned with backend/containment policy engine categories — proposal only!)
        containment_options = self._build_containment_options(
            affected_assets_list=affected_assets_list,
            identities=involved_identities,
            ot_safety=ot_safety_flag or bool(ot_assets),
        )

        summary = InvestigationSummary(
            incident_id=incident_id,
            incident_reference=incident_ref,
            generated_at=datetime.now(timezone.utc).isoformat(),
            what_happened=what_happened,
            where=where,
            first_indicator=first_indicator,
            affected_assets=affected_assets_list,
            involved_identities=involved_identities,
            related_events=formatted_events,
            potential_impact=potential_impact,
            investigation_recommendations=recommendations,
            containment_options=containment_options,
            investigation_narrative=None,
            autonomous_action_taken=False,
        )

        # Optional LLM narrative hook (read-only; strictly cannot modify incident fields or execute actions)
        if self.enable_llm_hook:
            narrative = self._generate_llm_narrative_if_configured(summary.to_dict())
            if narrative:
                summary.investigation_narrative = narrative

        if persist:
            self._persist_investigation_sync(summary)

        return summary

    async def investigate_incident_async(self, incident_id: str) -> InvestigationSummary:
        """Load incident + all related security_events from PostgreSQL and generate investigation."""
        incident: Dict[str, Any] = {"incident_id": incident_id}
        related_events: List[Dict[str, Any]] = []
        identities: List[Dict[str, Any]] = []

        if self.db_client is not None and hasattr(self.db_client, "fetchrow"):
            row = await self.db_client.fetchrow(
                "SELECT * FROM becpl_nids.incidents WHERE incident_id = $1",
                incident_id,
            )
            if row:
                incident = dict(row)

            event_ids = incident.get("evidence") or []
            if isinstance(event_ids, str):
                event_ids = json.loads(event_ids)

            if hasattr(self.db_client, "fetch"):
                if event_ids:
                    ev_rows = await self.db_client.fetch(
                        """
                        SELECT event_id, timestamp, event_type, detection_source, severity,
                               source_ip, destination_ip, source_asset_id, destination_asset_id,
                               principal_type, evidence
                        FROM becpl_nids.security_events
                        WHERE event_id::text = ANY($1) OR incident_id = $2
                        ORDER BY timestamp ASC
                        """,
                        [str(e) for e in event_ids],
                        incident_id,
                    )
                else:
                    ev_rows = await self.db_client.fetch(
                        """
                        SELECT event_id, timestamp, event_type, detection_source, severity,
                               source_ip, destination_ip, source_asset_id, destination_asset_id,
                               principal_type, evidence
                        FROM becpl_nids.security_events
                        WHERE incident_id = $1
                        ORDER BY timestamp ASC
                        """,
                        incident_id,
                    )
                related_events = [dict(r) for r in ev_rows]

                assets = incident.get("affected_assets") or []
                if assets:
                    id_rows = await self.db_client.fetch(
                        """
                        SELECT principal_name, principal_type, department, is_privileged
                        FROM becpl_nids.identities
                        WHERE associated_asset_id = ANY($1)
                        """,
                        assets,
                    )
                    identities = [dict(r) for r in id_rows]

        summary = self.investigate(
            incident=incident,
            related_events=related_events,
            identities=identities,
            persist=False,
        )
        await self.persist_investigation(summary)
        return summary

    # ------------------------------------------------------------------
    # Evidence Grounding Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _collect_identities(
        events: List[Dict[str, Any]], db_identities: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        seen: Dict[str, Dict[str, Any]] = {}
        for rec in db_identities:
            name = str(rec.get("principal_name") or rec.get("identity") or "")
            if not name:
                continue
            seen[name] = {
                "identity": name,
                "identity_type": str(rec.get("principal_type") or "UNKNOWN_IDENTITY"),
                "anomalous_behaviours": [],
                "supporting_event_ids": [],
            }

        for ev in events:
            name = str(
                ev.get("identity")
                or ev.get("principal_name")
                or ev.get("vendor_id")
                or ""
            )
            if not name:
                continue
            entry = seen.setdefault(
                name,
                {
                    "identity": name,
                    "identity_type": str(
                        ev.get("principal_type")
                        or ("THIRD_PARTY_IDENTITY" if ev.get("vendor_id") else "UNKNOWN_IDENTITY")
                    ),
                    "anomalous_behaviours": [],
                    "supporting_event_ids": [],
                },
            )
            behaviour = str(
                ev.get("indicator_type")
                or ev.get("anomaly_type")
                or ev.get("event_type")
                or "observed_in_incident"
            )
            if behaviour not in entry["anomalous_behaviours"]:
                entry["anomalous_behaviours"].append(behaviour)
            eid = ev.get("event_id")
            if eid and str(eid) not in entry["supporting_event_ids"]:
                entry["supporting_event_ids"].append(str(eid))

        return list(seen.values())

    @staticmethod
    def _summarize_impact(affected_assets: List[Dict[str, Any]], ot_safety: bool) -> str:
        if ot_safety:
            return (
                "HIGH/CRITICAL OT PRODUCTION RISK: Industrial OT assets are implicated. "
                + OT_SAFETY_NOTE
            )
        crit_count = sum(1 for a in affected_assets if a.get("criticality") == "critical")
        if crit_count > 0:
            return (
                f"HIGH OPERATIONAL IMPACT: {crit_count} critical asset(s) affected; "
                "potential exposure of firmware IP, ERP operations, or core identity services."
            )
        return (
            f"MODERATE OPERATIONAL IMPACT: {len(affected_assets)} asset(s) involved with "
            "localized departmental impact if contained promptly."
        )

    @staticmethod
    def _build_recommendations(
        rule_id: str,
        asset_ids: List[str],
        identities: List[Dict[str, Any]],
        event_ids: List[str],
        ot_safety: bool,
    ) -> List[str]:
        recs: List[str] = [
            f"Verify raw telemetry for supporting event IDs ({', '.join(event_ids[:5]) or 'none attached'}) in PostgreSQL security_events."
        ]
        if asset_ids:
            recs.append(
                f"Inspect host process trees, active network sockets, and recent authentication logs on: {', '.join(asset_ids)}."
            )
        if identities:
            names = ", ".join(i["identity"] for i in identities)
            recs.append(
                f"Validate recent MFA challenges, VPN sessions, and role scopes for identities: {names}."
            )
        if ot_safety:
            recs.append(
                "Coordinate immediately with Manufacturing Plant Floor Supervisor before applying any OT network or PLC/HMI containment."
            )
        if rule_id.startswith("RULE-VENDOR-"):
            recs.append(
                "Review vendor access policy compliance, check approved maintenance schedules, and audit DMZ bastion session recordings."
            )
        if rule_id in ("RULE-ENG-001", "RULE-EXFIL-001"):
            recs.append(
                "Capture TLS JA3/SNI metadata and inspect outbound destination IPs against threat_intel:ip_blocklist."
            )
        return recs

    @staticmethod
    def _build_containment_options(
        affected_assets_list: List[Dict[str, Any]],
        identities: List[Dict[str, Any]],
        ot_safety: bool,
    ) -> List[Dict[str, Any]]:
        """
        Return read-only containment option templates compatible with backend/containment/policy_engine.py.
        All options require explicit human operator proposal & approval (MODE 3).
        """
        options: List[Dict[str, Any]] = []

        if ot_safety:
            options.append(
                {
                    "action_category": "OT_BOUNDARY_RESTRICTION",
                    "description": "Enforce strict IT-to-OT firewall allowlist at VLAN 30 boundary without disrupting internal PLC/HMI polling.",
                    "requires_human_approval": True,
                    "required_role": "SECURITY_MANAGER",
                    "two_person_rule": True,
                    "safety_note": OT_SAFETY_NOTE,
                }
            )

        for asset in affected_assets_list:
            if asset.get("vlan") != 30:
                options.append(
                    {
                        "action_category": "ENDPOINT_QUARANTINE",
                        "target_asset_id": asset["asset_id"],
                        "description": f"Quarantine {asset['asset_id']} to isolated quarantine VLAN.",
                        "requires_human_approval": True,
                        "required_role": "SECURITY_MANAGER"
                        if asset.get("criticality") == "critical"
                        else "APPROVER",
                    }
                )

        for ident in identities:
            is_vendor = ident.get("identity_type") == "THIRD_PARTY_IDENTITY"
            options.append(
                {
                    "action_category": "THIRD_PARTY_CONTAINMENT"
                    if is_vendor
                    else "IDENTITY_CONTAINMENT",
                    "target_identity": ident["identity"],
                    "description": (
                        f"Suspend vendor VPN session for {ident['identity']}."
                        if is_vendor
                        else f"Revoke active sessions and require password/MFA reset for {ident['identity']}."
                    ),
                    "requires_human_approval": True,
                    "required_role": "SECURITY_MANAGER" if is_vendor else "APPROVER",
                }
            )

        options.append(
            {
                "action_category": "NETWORK_CONTAINMENT",
                "description": "Block suspicious source-destination flow via perimeter/internal firewall ACL.",
                "requires_human_approval": True,
                "required_role": "APPROVER",
            }
        )
        return options

    # ------------------------------------------------------------------
    # Optional LLM Narrative Hook (Read-Only, Evidence-Only Input)
    # ------------------------------------------------------------------
    def _generate_llm_narrative_if_configured(
        self, structured_evidence: Dict[str, Any]
    ) -> Optional[str]:
        """
        If OPENAI_API_KEY or GEMINI_API_KEY is present in the environment, call the
        configured LLM with ONLY the structured evidence dict to produce an analyst
        narrative clearly marked with AI_DISCLAIMER. Never alters incident state.
        """
        openai_key = os.getenv("OPENAI_API_KEY")
        gemini_key = os.getenv("GEMINI_API_KEY")
        if not openai_key and not gemini_key:
            return None

        prompt = (
            "You are a SOC analyst assistant for an electronics manufacturing NIDS (VaultX). "
            "Summarize ONLY the facts present in the structured evidence JSON below. "
            "Cite exact event_ids. Do NOT invent indicators or take actions.\n\n"
            + json.dumps(structured_evidence, default=str)
        )

        raw_text: Optional[str] = None
        try:
            if gemini_key:
                raw_text = self._call_gemini(gemini_key, prompt)
            elif openai_key:
                raw_text = self._call_openai(openai_key, prompt)
        except Exception as exc:
            logger.warning("Optional LLM narrative hook failed gracefully: %s", exc)
            return None

        if not raw_text:
            return None
        return f"[{AI_DISCLAIMER}]\n\n{raw_text.strip()}"

    @staticmethod
    def _call_openai(api_key: str, prompt: str) -> Optional[str]:
        url = "https://api.openai.com/v1/chat/completions"
        payload = json.dumps(
            {
                "model": os.getenv("VAULTX_OPENAI_MODEL", "gpt-4o-mini"),
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.1,
                "max_tokens": 500,
            }
        ).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}",
            },
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        return body["choices"][0]["message"]["content"]

    @staticmethod
    def _call_gemini(api_key: str, prompt: str) -> Optional[str]:
        model = os.getenv("VAULTX_GEMINI_MODEL", "gemini-2.0-flash")
        url = (
            f"https://generativelanguage.googleapis.com/v1beta/models/"
            f"{model}:generateContent?key={api_key}"
        )
        payload = json.dumps(
            {"contents": [{"parts": [{"text": prompt}]}]}
        ).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        return body["candidates"][0]["content"]["parts"][0]["text"]

    # ------------------------------------------------------------------
    # Persistence to incidents table
    # ------------------------------------------------------------------
    def _persist_investigation_sync(self, summary: InvestigationSummary) -> None:
        if self.db_client is None:
            return
        execute = getattr(self.db_client, "execute", None)
        if execute is None or inspect.iscoroutinefunction(execute):
            return
        try:
            execute(
                """
                UPDATE becpl_nids.incidents
                SET investigation_summary = %s::jsonb,
                    investigation_narrative = %s
                WHERE incident_id = %s
                """,
                (
                    json.dumps(summary.to_dict()),
                    summary.investigation_narrative,
                    summary.incident_id,
                ),
            )
        except Exception as exc:
            logger.error("Failed persisting investigation_summary: %s", exc)

    async def persist_investigation(self, summary: InvestigationSummary) -> None:
        if self.db_client is None:
            return
        res = self.db_client.execute(
            """
            UPDATE becpl_nids.incidents
            SET investigation_summary = $1::jsonb,
                investigation_narrative = $2
            WHERE incident_id = $3
            """,
            json.dumps(summary.to_dict()),
            summary.investigation_narrative,
            summary.incident_id,
        )
        if inspect.isawaitable(res):
            await res

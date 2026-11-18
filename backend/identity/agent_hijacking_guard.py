"""
agent_hijacking_guard.py — AI Supply-Chain Agent Hijacking & Tool Injection Guardrail for VaultX Phase 3.

BECPL (Bharat Electronics Components Pvt. Ltd.), Pune — Manufacturing-Aware Hybrid NIDS.

Context & Architectural Principle
---------------------------------
Complements ``backend/identity/ai_agent_monitor.py`` (Phase 2 static allowlist checks).
Cannot detect AI agent hijacking from raw network packets alone — operates on structured
agent tool-invocation telemetry, untrusted document ingestion context (vendor invoices,
purchase orders, ANSI X12 / EDIFACT EDI messages), and session invocation graphs.

Core Capabilities
-----------------
1. **Indirect Prompt Injection (IPI) Detection**:
   - Scans unstructured vendor payloads and tool arguments for instruction overrides,
     role/delimiter injection, tool-hijack directives (exfiltration, inventory/PO tampering,
     interlock bypass), zero-width/BiDi Unicode obfuscation, and base64-encoded hidden
     instructions.
2. **Tool Invocation Sequence & Privilege Escalation Guard**:
   - Tracks per-``(agent_id, session_id)`` invocation chains and untrusted-input taint state.
   - Detects taint propagation from untrusted supply-chain inputs (``vendor_invoice``,
     ``edi_x12``, ``edi_edifact``, ``purchase_order``, ``vendor_email``) to privileged write,
     payment, inventory mutation, shell/SQL execution, or OT control sinks without an
     intervening human-in-the-loop (HITL) approval marker.
   - Detects privilege tier jumps and high-risk multi-step escalation chains
     (e.g., ``parse_vendor_invoice -> fetch_credentials -> query_internal_api``).
3. **Unauthorized Internal API & SSRF Probing Analyzer**:
   - Recursively extracts URLs, IP addresses, ports, and paths from tool arguments.
   - Blocks/flags SSRF to cloud metadata endpoints (``169.254.169.254``), BECPL OT VLAN
     (``10.10.30.0/24``, ``172.20.30.0/24``), Security Management VLAN (``10.10.70.0/24``,
     ``172.20.70.0/24``), Firmware Build/OTA servers (``10.10.20.2-4``), loopback/dangerous
     schemes (``file://``, ``gopher://``), sensitive internal routes (``/api/v1/containment``,
     ``/admin``, ``/.env``), and multi-host internal reconnaissance sweeps.

Publishes structured evidence findings to Redis stream ``detections:identity`` (default)
or ``detections:agent_hijacking``.
"""

from __future__ import annotations

import base64
import ipaddress
import json
import logging
import re
import uuid
from collections import defaultdict, deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Deque, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

REDIS_STREAM_AGENT_HIJACKING: str = "detections:agent_hijacking"

# Privilege tiers for manufacturing AI agent tools
TIER_READ_UNTRUSTED: int = 0      # Parsing external vendor invoices, POs, EDI, emails
TIER_READ_INTERNAL: int = 1       # Querying read-only ERP/WMS/catalog records
TIER_WRITE_BUSINESS: int = 2      # Mutating inventory, POs, vendor bank details, ERP records
TIER_PRIVILEGED_OT_ADMIN: int = 3 # Secrets, shell/SQL exec, OT/PLC writes, containment, firmware

# Untrusted external data sources that taint a session upon ingestion
UNTRUSTED_INPUT_SOURCES: frozenset[str] = frozenset({
    "vendor_invoice",
    "purchase_order",
    "edi_x12",
    "edi_edifact",
    "vendor_email",
    "untrusted_pdf",
    "external_webhook",
    "supplier_portal_upload",
})

# Default BECPL sensitive / restricted networks that MES/WMS AI agents must never probe
DEFAULT_FORBIDDEN_CIDRS: Tuple[str, ...] = (
    "10.10.30.0/24",    # BECPL VLAN 30 — Manufacturing OT (Production)
    "172.20.30.0/24",   # BECPL VLAN 30 — Manufacturing OT (Simulation)
    "10.10.70.0/24",    # BECPL VLAN 70 — Security Management (Production)
    "172.20.70.0/24",   # BECPL VLAN 70 — Security Management (Simulation)
    "169.254.169.254/32",  # AWS / Cloud IMDSv1/v2 metadata
    "169.254.170.2/32",    # AWS ECS task metadata
    "127.0.0.0/8",         # Loopback
    "0.0.0.0/8",
)

DEFAULT_FORBIDDEN_HOSTS: frozenset[str] = frozenset({
    "localhost",
    "metadata.google.internal",
    "metadata.goog",
    "10.10.20.2",  # ENG-BUILDSVR01 (Firmware CI/CD)
    "10.10.20.3",  # ENG-GITSVR01 (Local Git Mirror)
    "10.10.20.4",  # ENG-OTA-STG01 (OTA Firmware Staging)
})

SENSITIVE_INTERNAL_PORTS: frozenset[int] = frozenset({
    22,     # SSH
    102,    # Siemens S7comm
    502,    # Modbus TCP
    2375,   # Docker unencrypted daemon
    3389,   # RDP
    5432,   # PostgreSQL
    6379,   # Redis
    8883,   # OT MQTT-TLS staging
    9200,   # OpenSearch / Elasticsearch
    44818,  # EtherNet/IP
})

SENSITIVE_PATH_PATTERNS: Tuple[re.Pattern[str], ...] = (
    re.compile(r"/api/v\d+/containment", re.IGNORECASE),
    re.compile(r"/api/v\d+/(?:secrets|keys|tokens|credentials|admin)", re.IGNORECASE),
    re.compile(r"/latest/meta-data", re.IGNORECASE),
    re.compile(r"/computeMetadata/v1", re.IGNORECASE),
    re.compile(r"/(?:\.env|\.git|etc/passwd|etc/shadow|actuator|metrics|debug)", re.IGNORECASE),
    re.compile(r"/admin(?:/|$)", re.IGNORECASE),
)

DANGEROUS_URI_SCHEMES: frozenset[str] = frozenset({"file", "gopher", "dict", "ldap", "ftp", "smb"})

# Tool semantic classification sets for sequence / privilege escalation analysis
CREDENTIAL_READ_TOOLS: frozenset[str] = frozenset({
    "read_secrets",
    "get_api_key",
    "fetch_credentials",
    "read_env",
    "vault_read",
    "get_service_token",
})

PRIVILEGED_WRITE_OR_EXEC_TOOLS: frozenset[str] = frozenset({
    "update_inventory_record",
    "alter_inventory",
    "modify_erp_bom",
    "approve_purchase_order",
    "update_vendor_bank_details",
    "initiate_wire_transfer",
    "execute_sql",
    "run_shell_command",
    "write_plc_register",
    "push_ota_firmware",
    "modify_firewall_rule",
    "disable_safety_interlock",
})

NETWORK_EGRESS_OR_PROBE_TOOLS: frozenset[str] = frozenset({
    "http_request",
    "http_fetch",
    "query_internal_api",
    "webhook_post",
    "send_external_http",
    "curl_endpoint",
    "erp_api_call",
})

# Indirect Prompt Injection (IPI) regex signatures
IPI_OVERRIDE_PATTERNS: Tuple[Tuple[str, re.Pattern[str]], ...] = (
    (
        "instruction_override",
        re.compile(
            r"(?:ignore|disregard|forget|override|bypass)\s+(?:all\s+)?(?:previous|prior|above|system|safety|security)\s+(?:instructions?|prompts?|rules?|policies|guardrails?)",
            re.IGNORECASE,
        ),
    ),
    (
        "role_hijack",
        re.compile(
            r"(?:you\s+are\s+now|act\s+as|switch\s+to|enter)\s+(?:an?\s+)?(?:unrestricted|admin|root|developer\s+mode|system\s+override|privileged\s+agent)",
            re.IGNORECASE,
        ),
    ),
    (
        "delimiter_spoofing",
        re.compile(
            r"(?:<\|im_start\|>|<\|system\|>|<<SYS>>|\[SYSTEM\s*(?:PROMPT|OVERRIDE|DIRECTIVE)?\]|###\s*(?:SYSTEM|NEW\s+INSTRUCTION))",
            re.IGNORECASE,
        ),
    ),
    (
        "tool_hijack_directive",
        re.compile(
            r"(?:immediately\s+|silently\s+)?(?:invoke|call|execute|run|use)\s+(?:the\s+)?(?:tool|function|endpoint|api)\s+[`'\"]?[a-zA-Z0-9_./:-]+",
            re.IGNORECASE,
        ),
    ),
    (
        "supply_chain_fraud_or_exfil",
        re.compile(
            r"(?:exfiltrate|send\s+(?:all\s+)?(?:secrets|credentials|inventory|gerber|bom)|change\s+vendor\s+bank|wire\s+funds\s+to|approve\s+without\s+(?:human|manager)\s+review|disable\s+(?:safety\s+)?interlock)",
            re.IGNORECASE,
        ),
    ),
)

# Zero-width & BiDi Unicode obfuscation characters used to bypass naive keyword filters
OBFUSCATION_UNICODE_CHARS: frozenset[str] = frozenset({
    "\u200b",  # Zero-width space
    "\u200c",  # Zero-width non-joiner
    "\u200d",  # Zero-width joiner
    "\ufeff",  # Zero-width no-break space / BOM
    "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",  # BiDi overrides (RLO etc.)
    "\u2060", "\u2066", "\u2067", "\u2068", "\u2069",
})

# Candidate base64 blob regex (at least 24 base64 chars)
_B64_CANDIDATE_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")
_URL_RE = re.compile(r"\b(?:https?|file|gopher|dict|ldap|ftp|smb)://[^\s'\"<>]+", re.IGNORECASE)
_IP_PORT_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})(?::(\d{1,5}))?\b")


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------


@dataclass
class AgentGuardPolicy:
    """Security guardrail policy for a manufacturing AI agent."""

    agent_id: str
    agent_role: str = "supply_chain_assistant"
    max_privilege_tier: int = TIER_READ_INTERNAL
    allowed_tools: Set[str] = field(default_factory=set)
    hitl_required_tools: Set[str] = field(
        default_factory=lambda: set(PRIVILEGED_WRITE_OR_EXEC_TOOLS)
    )
    allowed_internal_hosts: Set[str] = field(default_factory=set)
    forbidden_cidrs: List[str] = field(default_factory=lambda: list(DEFAULT_FORBIDDEN_CIDRS))
    forbidden_hosts: Set[str] = field(default_factory=lambda: set(DEFAULT_FORBIDDEN_HOSTS))
    max_unique_internal_targets_per_session: int = 4


@dataclass
class AgentToolInvocation:
    """Single observed tool invocation event emitted by an AI agent runtime/gateway."""

    agent_id: str
    session_id: str
    tool_name: str
    tool_args: Dict[str, Any] = field(default_factory=dict)
    privilege_tier: int = TIER_READ_INTERNAL
    input_source: str = "internal_user"
    raw_input_text: Optional[str] = None
    target_url_or_endpoint: Optional[str] = None
    human_approved: bool = False
    source_ip: str = ""
    timestamp: Any = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class HijackSignal:
    """Single detected indicator of AI agent hijacking or unsafe tool behavior."""

    signal_type: str
    severity: str  # "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    score: float
    taxonomy_tags: List[str]  # OWASP LLM / Agentic + MITRE ATT&CK
    description: str
    evidence: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AgentHijackAssessment:
    """Complete risk assessment and enforcement decision for a single tool invocation."""

    assessment_id: str
    agent_id: str
    session_id: str
    tool_name: str
    timestamp: str
    risk_score: float
    severity: str
    recommended_action: str  # "ALLOW" | "FLAG_AND_MONITOR" | "REQUIRE_HITL_APPROVAL" | "BLOCK_TOOL_CALL"
    session_tainted: bool
    taint_sources: List[str]
    signals: List[HijackSignal]
    published: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "assessment_id": self.assessment_id,
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "tool_name": self.tool_name,
            "timestamp": self.timestamp,
            "risk_score": round(self.risk_score, 4),
            "severity": self.severity,
            "recommended_action": self.recommended_action,
            "session_tainted": self.session_tainted,
            "taint_sources": self.taint_sources,
            "signals": [asdict(s) for s in self.signals],
            "published": self.published,
        }


@dataclass
class _SessionState:
    tainted: bool = False
    taint_sources: List[str] = field(default_factory=list)
    tool_history: Deque[Tuple[str, int, str]] = field(default_factory=lambda: deque(maxlen=50))
    probed_internal_targets: Set[str] = field(default_factory=set)
    ipi_hits: int = 0
    highest_tier_seen: int = 0


# ---------------------------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------------------------


def _parse_iso_ts(raw_ts: Any) -> str:
    if isinstance(raw_ts, datetime):
        dt = raw_ts if raw_ts.tzinfo else raw_ts.replace(tzinfo=timezone.utc)
        return dt.isoformat()
    if isinstance(raw_ts, (int, float)):
        return datetime.fromtimestamp(float(raw_ts), tz=timezone.utc).isoformat()
    if isinstance(raw_ts, str) and raw_ts:
        return raw_ts
    return datetime.now(tz=timezone.utc).isoformat()


def _flatten_strings(obj: Any) -> List[str]:
    """Recursively extract all string values from nested dicts/lists."""
    out: List[str] = []
    if isinstance(obj, str):
        out.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            out.extend(_flatten_strings(v))
    elif isinstance(obj, (list, tuple, set)):
        for item in obj:
            out.extend(_flatten_strings(item))
    return out


def _strip_obfuscation_chars(text: str) -> Tuple[str, int]:
    """Remove invisible Unicode obfuscation characters and return ``(cleaned, count_removed)``."""
    removed = sum(1 for ch in text if ch in OBFUSCATION_UNICODE_CHARS)
    if removed == 0:
        return text, 0
    cleaned = "".join(ch for ch in text if ch not in OBFUSCATION_UNICODE_CHARS)
    return cleaned, removed


def _decode_suspicious_base64_blobs(text: str) -> List[Tuple[str, str]]:
    """Find base64-like strings that decode cleanly to printable UTF-8 text."""
    decoded_pairs: List[Tuple[str, str]] = []
    for match in _B64_CANDIDATE_RE.finditer(text):
        blob = match.group(0)
        if len(blob) % 4 != 0:
            continue
        try:
            raw = base64.b64decode(blob, validate=True)
            decoded = raw.decode("utf-8")
        except Exception:
            continue
        printable = sum(1 for c in decoded if 32 <= ord(c) <= 126 or c in "\r\n\t")
        if len(decoded) >= 12 and (printable / float(len(decoded))) >= 0.85:
            decoded_pairs.append((blob, decoded))
    return decoded_pairs


def _ip_in_cidrs(ip_str: str, cidrs: List[str]) -> Optional[str]:
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return None
    for cidr in cidrs:
        try:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return cidr
        except ValueError:
            continue
    return None


def _is_private_or_internal_ip(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Main AI Agent Hijacking Guard
# ---------------------------------------------------------------------------


class AgentHijackingGuard:
    """
    Runtime guardrail & forensic analyzer for AI agents operating in BECPL
    manufacturing pipelines (MES, WMS, ERP, Procurement, Vendor EDI).

    Evaluates every ``AgentToolInvocation`` across three orthogonal lenses:
    1. Indirect Prompt Injection (IPI) & obfuscation scanning
    2. Tool invocation sequence / untrusted taint propagation / privilege escalation
    3. Unauthorized internal API / SSRF / OT-VLAN probing
    """

    def __init__(
        self,
        policies: Optional[Dict[str, AgentGuardPolicy]] = None,
        redis_client: Any = None,
        stream_name: str = REDIS_STREAM_AGENT_HIJACKING,
    ) -> None:
        self._policies: Dict[str, AgentGuardPolicy] = dict(policies or {})
        self._redis = redis_client
        self._stream = stream_name
        self._sessions: Dict[Tuple[str, str], _SessionState] = defaultdict(_SessionState)
        self._assessment_counts: Dict[str, int] = defaultdict(int)

    def register_policy(self, policy: AgentGuardPolicy) -> None:
        """Register or replace an ``AgentGuardPolicy`` for an agent ID."""
        self._policies[policy.agent_id] = policy

    def get_session_state(self, agent_id: str, session_id: str) -> Dict[str, Any]:
        """Inspect current taint and tool-chain lineage for a session."""
        st = self._sessions.get((agent_id, session_id))
        if st is None:
            return {"exists": False}
        return {
            "exists": True,
            "tainted": st.tainted,
            "taint_sources": list(st.taint_sources),
            "tool_history": [
                {"tool": t, "tier": tier, "source": src} for t, tier, src in st.tool_history
            ],
            "probed_internal_targets": sorted(st.probed_internal_targets),
            "ipi_hits": st.ipi_hits,
            "highest_tier_seen": st.highest_tier_seen,
        }

    def evaluate_invocation(
        self,
        invocation: AgentToolInvocation,
        publish: bool = True,
    ) -> AgentHijackAssessment:
        """Analyze a single agent tool invocation and produce a risk & action verdict."""
        ts = _parse_iso_ts(invocation.timestamp)
        policy = self._policies.get(
            invocation.agent_id, AgentGuardPolicy(agent_id=invocation.agent_id)
        )
        sess_key = (invocation.agent_id, invocation.session_id)
        session = self._sessions[sess_key]

        signals: List[HijackSignal] = []

        # Mark session taint if this invocation ingests an untrusted external source
        src_lower = invocation.input_source.strip().lower()
        if src_lower in UNTRUSTED_INPUT_SOURCES:
            session.tainted = True
            if src_lower not in session.taint_sources:
                session.taint_sources.append(src_lower)

        # ------------------------------------------------------------------
        # Lens 1: Indirect Prompt Injection (IPI) & Obfuscation Analysis
        # ------------------------------------------------------------------
        texts_to_scan: List[str] = []
        if invocation.raw_input_text:
            texts_to_scan.append(invocation.raw_input_text)
        texts_to_scan.extend(_flatten_strings(invocation.tool_args))

        ipi_signals = self._scan_prompt_injection(texts_to_scan, src_lower)
        if ipi_signals:
            session.tainted = True
            session.ipi_hits += len(ipi_signals)
            if "indirect_prompt_injection" not in session.taint_sources:
                session.taint_sources.append("indirect_prompt_injection")
            signals.extend(ipi_signals)

        # ------------------------------------------------------------------
        # Lens 2: Tool Sequence Privilege Escalation & Taint Sink Check
        # ------------------------------------------------------------------
        seq_signals = self._analyze_tool_sequence(invocation, policy, session)
        signals.extend(seq_signals)

        # ------------------------------------------------------------------
        # Lens 3: Unauthorized Internal API / SSRF / OT Probing
        # ------------------------------------------------------------------
        probe_signals = self._analyze_internal_api_probing(invocation, policy, session)
        signals.extend(probe_signals)

        # Update session history AFTER sequence checks
        session.tool_history.append(
            (invocation.tool_name, int(invocation.privilege_tier), src_lower)
        )
        session.highest_tier_seen = max(session.highest_tier_seen, int(invocation.privilege_tier))

        # Aggregate composite risk score (probabilistic noisy-OR so multiple signals reinforce)
        if not signals:
            risk_score = 0.0
            severity = "LOW"
            action = "ALLOW"
        else:
            no_risk_prob = 1.0
            for sig in signals:
                no_risk_prob *= max(0.0, 1.0 - min(0.99, sig.score))
            risk_score = round(min(1.0, 1.0 - no_risk_prob), 4)

            has_critical = any(s.severity == "CRITICAL" for s in signals)
            has_high = any(s.severity == "HIGH" for s in signals)
            if has_critical or risk_score >= 0.85:
                severity = "CRITICAL"
                action = "BLOCK_TOOL_CALL"
            elif has_high or risk_score >= 0.65:
                severity = "HIGH"
                action = (
                    "BLOCK_TOOL_CALL"
                    if invocation.tool_name in PRIVILEGED_WRITE_OR_EXEC_TOOLS
                    else "REQUIRE_HITL_APPROVAL"
                )
            elif risk_score >= 0.40:
                severity = "MEDIUM"
                action = "FLAG_AND_MONITOR"
            else:
                severity = "LOW"
                action = "FLAG_AND_MONITOR"

        assessment = AgentHijackAssessment(
            assessment_id=str(uuid.uuid4()),
            agent_id=invocation.agent_id,
            session_id=invocation.session_id,
            tool_name=invocation.tool_name,
            timestamp=ts,
            risk_score=risk_score,
            severity=severity,
            recommended_action=action,
            session_tainted=session.tainted,
            taint_sources=list(session.taint_sources),
            signals=signals,
        )

        self._assessment_counts[action] += 1
        if publish and signals and self._redis is not None:
            assessment.published = self._publish(assessment)

        return assessment

    def get_metrics(self) -> Dict[str, int]:
        return dict(self._assessment_counts)

    # ------------------------------------------------------------------
    # Lens 1 Implementation: Indirect Prompt Injection Scanner
    # ------------------------------------------------------------------

    def _scan_prompt_injection(
        self, texts: List[str], input_source: str
    ) -> List[HijackSignal]:
        signals: List[HijackSignal] = []
        matched_categories: Set[str] = set()
        matched_snippets: List[str] = []
        total_invisible = 0
        decoded_hits: List[Dict[str, str]] = []

        for raw_text in texts:
            if not raw_text:
                continue
            cleaned, inv_count = _strip_obfuscation_chars(raw_text)
            total_invisible += inv_count

            for cat, pattern in IPI_OVERRIDE_PATTERNS:
                m = pattern.search(cleaned)
                if m:
                    matched_categories.add(cat)
                    matched_snippets.append(m.group(0)[:120])

            # Decode base64 substrings and re-scan for hidden override directives
            for b64_blob, decoded in _decode_suspicious_base64_blobs(cleaned):
                for cat, pattern in IPI_OVERRIDE_PATTERNS:
                    m = pattern.search(decoded)
                    if m:
                        matched_categories.add(f"base64_obfuscated_{cat}")
                        decoded_hits.append(
                            {
                                "category": cat,
                                "encoded_prefix": b64_blob[:40],
                                "decoded_match": m.group(0)[:120],
                            }
                        )

        if matched_categories:
            is_untrusted = input_source in UNTRUSTED_INPUT_SOURCES
            score = min(0.96, 0.72 + 0.08 * len(matched_categories) + (0.06 if is_untrusted else 0.0))
            signals.append(
                HijackSignal(
                    signal_type="indirect_prompt_injection",
                    severity="CRITICAL" if (len(matched_categories) >= 2 or decoded_hits) else "HIGH",
                    score=round(score, 4),
                    taxonomy_tags=["OWASP-LLM01", "OWASP-ASI01", "T1059"],
                    description=(
                        f"Indirect prompt injection indicators ({', '.join(sorted(matched_categories))}) "
                        f"detected in '{input_source}' payload"
                    ),
                    evidence={
                        "input_source": input_source,
                        "matched_categories": sorted(matched_categories),
                        "matched_snippets": matched_snippets[:5],
                        "decoded_base64_hits": decoded_hits,
                    },
                )
            )

        if total_invisible >= 3:
            signals.append(
                HijackSignal(
                    signal_type="unicode_obfuscation_steganography",
                    severity="HIGH" if matched_categories else "MEDIUM",
                    score=0.68 if matched_categories else 0.52,
                    taxonomy_tags=["OWASP-LLM01", "T1027"],
                    description=(
                        f"Detected {total_invisible} hidden zero-width/BiDi Unicode characters "
                        f"in agent input/arguments (prompt obfuscation indicator)"
                    ),
                    evidence={
                        "invisible_char_count": total_invisible,
                        "input_source": input_source,
                    },
                )
            )

        return signals

    # ------------------------------------------------------------------
    # Lens 2 Implementation: Tool Sequence & Privilege Escalation Guard
    # ------------------------------------------------------------------

    def _analyze_tool_sequence(
        self,
        invocation: AgentToolInvocation,
        policy: AgentGuardPolicy,
        session: _SessionState,
    ) -> List[HijackSignal]:
        signals: List[HijackSignal] = []
        tool = invocation.tool_name
        tier = int(invocation.privilege_tier)

        # 2a. Explicit tool allowlist violation (when policy specifies allowed_tools)
        if policy.allowed_tools and tool not in policy.allowed_tools:
            signals.append(
                HijackSignal(
                    signal_type="unapproved_tool_invocation",
                    severity="HIGH",
                    score=0.80,
                    taxonomy_tags=["OWASP-LLM06", "OWASP-ASI02", "T1059"],
                    description=(
                        f"Agent '{invocation.agent_id}' invoked tool '{tool}' outside "
                        f"approved policy toolset"
                    ),
                    evidence={
                        "tool_name": tool,
                        "allowed_tools": sorted(policy.allowed_tools),
                    },
                )
            )

        # 2b. Privilege tier ceiling violation
        if tier > policy.max_privilege_tier:
            signals.append(
                HijackSignal(
                    signal_type="privilege_tier_escalation",
                    severity="CRITICAL" if tier >= TIER_PRIVILEGED_OT_ADMIN else "HIGH",
                    score=0.90 if tier >= TIER_PRIVILEGED_OT_ADMIN else 0.80,
                    taxonomy_tags=["OWASP-LLM06", "OWASP-ASI03", "T1068"],
                    description=(
                        f"Tool '{tool}' requires privilege tier {tier}, exceeding agent "
                        f"'{invocation.agent_id}' ceiling tier {policy.max_privilege_tier}"
                    ),
                    evidence={
                        "tool_name": tool,
                        "requested_tier": tier,
                        "max_allowed_tier": policy.max_privilege_tier,
                    },
                )
            )

        # 2c. Taint-to-Privileged-Sink propagation (untrusted vendor doc -> write/exec without HITL)
        is_sensitive_sink = (
            tool in PRIVILEGED_WRITE_OR_EXEC_TOOLS
            or tool in policy.hitl_required_tools
            or tier >= TIER_WRITE_BUSINESS
        )
        if session.tainted and is_sensitive_sink and not invocation.human_approved:
            signals.append(
                HijackSignal(
                    signal_type="tainted_session_privileged_sink",
                    severity="CRITICAL",
                    score=0.92,
                    taxonomy_tags=["OWASP-LLM01", "OWASP-LLM06", "OWASP-ASI02"],
                    description=(
                        f"Tainted session '{invocation.session_id}' (sources={session.taint_sources}) "
                        f"attempted privileged tool '{tool}' (tier={tier}) without human approval"
                    ),
                    evidence={
                        "tool_name": tool,
                        "privilege_tier": tier,
                        "taint_sources": list(session.taint_sources),
                        "human_approved": invocation.human_approved,
                        "prior_tools": [t for t, _, _ in list(session.tool_history)[-5:]],
                    },
                )
            )

        # 2d. Multi-step escalation chains (e.g., untrusted_read -> secret_read -> network/write)
        prior_tools = [t for t, _, _ in session.tool_history]
        prior_tiers = [pt for _, pt, _ in session.tool_history]

        if prior_tools:
            # Credential harvesting followed by egress/probing
            if (
                any(t in CREDENTIAL_READ_TOOLS for t in prior_tools)
                and (tool in NETWORK_EGRESS_OR_PROBE_TOOLS or tool in PRIVILEGED_WRITE_OR_EXEC_TOOLS)
            ):
                signals.append(
                    HijackSignal(
                        signal_type="credential_to_exfil_tool_chain",
                        severity="CRITICAL",
                        score=0.95,
                        taxonomy_tags=["OWASP-ASI02", "T1552", "T1041"],
                        description=(
                            f"Detected credential-to-egress escalation chain in session "
                            f"'{invocation.session_id}': {prior_tools[-3:]} -> {tool}"
                        ),
                        evidence={
                            "chain": prior_tools[-5:] + [tool],
                            "credential_tools_used": [t for t in prior_tools if t in CREDENTIAL_READ_TOOLS],
                        },
                    )
                )

            # Rapid jump from Tier 0 (untrusted ingestion) directly to Tier 2+ in consecutive calls
            last_tier = prior_tiers[-1]
            if last_tier == TIER_READ_UNTRUSTED and tier >= TIER_WRITE_BUSINESS and not invocation.human_approved:
                signals.append(
                    HijackSignal(
                        signal_type="abrupt_privilege_tier_jump",
                        severity="HIGH",
                        score=0.82,
                        taxonomy_tags=["OWASP-ASI03", "T1078"],
                        description=(
                            f"Abrupt privilege jump from tier {last_tier} ('{prior_tools[-1]}') "
                            f"to tier {tier} ('{tool}') within session '{invocation.session_id}'"
                        ),
                        evidence={
                            "previous_tool": prior_tools[-1],
                            "previous_tier": last_tier,
                            "current_tool": tool,
                            "current_tier": tier,
                        },
                    )
                )

        return signals

    # ------------------------------------------------------------------
    # Lens 3 Implementation: Unauthorized Internal API & SSRF Probing
    # ------------------------------------------------------------------

    def _analyze_internal_api_probing(
        self,
        invocation: AgentToolInvocation,
        policy: AgentGuardPolicy,
        session: _SessionState,
    ) -> List[HijackSignal]:
        signals: List[HijackSignal] = []

        candidate_strings: List[str] = []
        if invocation.target_url_or_endpoint:
            candidate_strings.append(invocation.target_url_or_endpoint)
        candidate_strings.extend(_flatten_strings(invocation.tool_args))

        extracted_urls: List[str] = []
        extracted_ips: List[Tuple[str, Optional[int]]] = []

        for text in candidate_strings:
            for url_match in _URL_RE.findall(text):
                extracted_urls.append(url_match)
            for ip_s, port_s in _IP_PORT_RE.findall(text):
                try:
                    ipaddress.ip_address(ip_s)
                    extracted_ips.append((ip_s, int(port_s) if port_s else None))
                except ValueError:
                    continue

        # Also inspect plain relative API paths like "/api/v1/containment/approve"
        if invocation.target_url_or_endpoint and invocation.target_url_or_endpoint.startswith("/"):
            extracted_urls.append(f"http://internal.local{invocation.target_url_or_endpoint}")

        forbidden_hits: List[Dict[str, Any]] = []
        sensitive_path_hits: List[str] = []
        dangerous_scheme_hits: List[str] = []
        sensitive_port_hits: List[Dict[str, Any]] = []

        for url in extracted_urls:
            parsed = urlparse(url)
            scheme = (parsed.scheme or "").lower()
            host = (parsed.hostname or "").lower()
            port = parsed.port
            path = parsed.path or ""

            if scheme in DANGEROUS_URI_SCHEMES:
                dangerous_scheme_hits.append(url)

            if host and host not in policy.allowed_internal_hosts:
                matched_cidr = _ip_in_cidrs(host, policy.forbidden_cidrs)
                if matched_cidr or host in policy.forbidden_hosts:
                    forbidden_hits.append(
                        {"target": host, "url": url, "matched_rule": matched_cidr or host}
                    )
                if _is_private_or_internal_ip(host) or host.endswith(".internal") or host.endswith(".local"):
                    session.probed_internal_targets.add(f"{host}:{port or 80}")

            if port is not None and port in SENSITIVE_INTERNAL_PORTS:
                sensitive_port_hits.append({"host": host, "port": port, "url": url})

            for pat in SENSITIVE_PATH_PATTERNS:
                if pat.search(path):
                    sensitive_path_hits.append(path)
                    break

        for ip_s, port_i in extracted_ips:
            if ip_s in policy.allowed_internal_hosts:
                continue
            matched_cidr = _ip_in_cidrs(ip_s, policy.forbidden_cidrs)
            if matched_cidr or ip_s in policy.forbidden_hosts:
                if not any(h["target"] == ip_s for h in forbidden_hits):
                    forbidden_hits.append(
                        {"target": ip_s, "port": port_i, "matched_rule": matched_cidr or ip_s}
                    )
            if _is_private_or_internal_ip(ip_s):
                session.probed_internal_targets.add(f"{ip_s}:{port_i or 0}")
            if port_i is not None and port_i in SENSITIVE_INTERNAL_PORTS:
                if not any(h["host"] == ip_s and h["port"] == port_i for h in sensitive_port_hits):
                    sensitive_port_hits.append({"host": ip_s, "port": port_i})

        if forbidden_hits or dangerous_scheme_hits:
            signals.append(
                HijackSignal(
                    signal_type="unauthorized_internal_ssrf_probe",
                    severity="CRITICAL",
                    score=0.95,
                    taxonomy_tags=["OWASP-LLM07", "OWASP-ASI02", "T1090", "T0846"],
                    description=(
                        f"Agent '{invocation.agent_id}' attempted unauthorized SSRF / restricted "
                        f"internal segment access via tool '{invocation.tool_name}'"
                    ),
                    evidence={
                        "tool_name": invocation.tool_name,
                        "forbidden_targets": forbidden_hits,
                        "dangerous_schemes": dangerous_scheme_hits,
                    },
                )
            )

        if sensitive_path_hits or sensitive_port_hits:
            signals.append(
                HijackSignal(
                    signal_type="sensitive_internal_endpoint_probing",
                    severity="HIGH",
                    score=0.85,
                    taxonomy_tags=["OWASP-ASI02", "T1046", "T1595"],
                    description=(
                        f"Agent '{invocation.agent_id}' probed sensitive internal endpoints/ports "
                        f"(paths={sensitive_path_hits}, ports={sensitive_port_hits})"
                    ),
                    evidence={
                        "sensitive_paths": sensitive_path_hits,
                        "sensitive_ports": sensitive_port_hits,
                    },
                )
            )

        if len(session.probed_internal_targets) >= policy.max_unique_internal_targets_per_session:
            signals.append(
                HijackSignal(
                    signal_type="agent_internal_network_recon_sweep",
                    severity="HIGH",
                    score=0.84,
                    taxonomy_tags=["OWASP-ASI02", "T1046", "T0846"],
                    description=(
                        f"Agent session '{invocation.session_id}' probed "
                        f"{len(session.probed_internal_targets)} distinct internal targets "
                        f"(threshold={policy.max_unique_internal_targets_per_session})"
                    ),
                    evidence={
                        "probed_targets": sorted(session.probed_internal_targets),
                        "threshold": policy.max_unique_internal_targets_per_session,
                    },
                )
            )

        return signals

    def _publish(self, assessment: AgentHijackAssessment) -> bool:
        try:
            self._redis.xadd(
                self._stream,
                {
                    "assessment_id": assessment.assessment_id,
                    "agent_id": assessment.agent_id,
                    "session_id": assessment.session_id,
                    "tool_name": assessment.tool_name,
                    "severity": assessment.severity,
                    "risk_score": str(assessment.risk_score),
                    "recommended_action": assessment.recommended_action,
                    "timestamp": assessment.timestamp,
                    "payload": json.dumps(assessment.to_dict()),
                },
            )
            return True
        except Exception as exc:
            logger.error("Failed publishing agent hijacking assessment to Redis: %s", exc)
            return False

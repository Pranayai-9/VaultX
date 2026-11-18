"""
novel_loopholes_engine.py — Novel OT/IIoT Network Loophole Detection Engine for VaultX Phase 3.

BECPL (Bharat Electronics Components Pvt. Ltd.), Pune — Manufacturing-Aware Hybrid NIDS.

Addresses three under-discussed network intrusion loopholes in electronics manufacturing:
1. **Modbus TCP Function Code Tunneling & Protocol Abuse** (``ModbusTunnelingDetector``):
   - User-defined function codes (0x41–0x48 / 65–72 and 0x64–0x6E / 100–110) used for
     arbitrary data encapsulation over port 502.
   - Diagnostic function code 0x08 subfunction abuse (Return Query Data 0x0000 high-entropy
     echo tunneling, Force Listen Only 0x0004, Restart Comms 0x0001).
   - Encapsulated Interface Transport (MEI FC 0x2B / 43) non-standard sub-types.
   - MBAP header anomalies (non-zero Protocol ID, declared length mismatch vs PDU,
     high-entropy opaque payloads).
2. **Sub-Threshold Sensor / Holding Register Drift** (``CUSUMDriftDetector``):
   - Two-sided Page's Cumulative Sum (CUSUM) sequential change-point detector on Modbus
     holding/input registers (e.g., SMT reflow oven thermal zones, pick-and-place offsets).
   - Catches "slow-burn" / boiling-frog register tampering where every individual reading
     remains strictly inside static alarm bounds yet cumulative shift degrades product
     quality or approaches unsafe physical envelopes.
3. **Passive Sensor Blind Spots & TCP Fragmentation Evasion** (``TCPFragmentationEvasionDetector``):
   - Overlapping TCP segments carrying conflicting payload bytes (Ptacek & Newsham /
     Novak & Sturges target-OS reassembly discrepancy evasion).
   - Micro-fragmentation / tiny TCP segment splitting designed to defeat signature engines.
   - Invalid TCP checksum decoy injection (exploiting ``checksum-validation: no`` on passive
     Suricata/Zeek sensors).
   - TTL manipulation / chaff packet insertion (short-TTL packets expiring before target PLC).
   - TCP Timestamp (RFC 7323 PAWS) non-monotonic or future-spike anomalies.
   - Asymmetric routing / half-duplex visibility blind spot detection.

Design Alignment
----------------
* Strict passive analysis — consumes parsed packet/flow/Modbus telemetry without ever
  injecting packets into VLAN 30 OT links.
* Emits structured ``LoopholeFinding`` records with MITRE ATT&CK / ICS tags and publishes
  to Redis stream ``detections:novel_loopholes`` when a Redis client is attached.
"""

from __future__ import annotations

import json
import logging
import math
import uuid
from collections import Counter, defaultdict, deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Deque, Dict, Iterable, List, Optional, Set, Tuple

import numpy as np

logger = logging.getLogger(__name__)

REDIS_STREAM_NOVEL_LOOPHOLES: str = "detections:novel_loopholes"

# Modbus Function Code Ranges (Modbus Application Protocol Specification V1.1b3)
STANDARD_MODBUS_READ_FCS: frozenset[int] = frozenset({1, 2, 3, 4})
STANDARD_MODBUS_WRITE_FCS: frozenset[int] = frozenset({5, 6, 15, 16, 22, 23})
USER_DEFINED_MODBUS_FC_RANGE_1: range = range(0x41, 0x49)  # 65..72 inclusive
USER_DEFINED_MODBUS_FC_RANGE_2: range = range(0x64, 0x6F)  # 100..110 inclusive
MODBUS_FC_DIAGNOSTICS: int = 0x08
MODBUS_FC_MEI_TRANSPORT: int = 0x2B  # 43

# Diagnostic (FC 0x08) subfunctions commonly abused for tunneling or disruption
DIAG_SUBFUNC_RETURN_QUERY_DATA: int = 0x0000
DIAG_HAZARDOUS_SUBFUNCTIONS: Dict[int, str] = {
    0x0001: "Restart Communications Option",
    0x0004: "Force Listen Only Mode",
    0x000A: "Clear Counters and Diagnostic Register",
    0x0014: "Clear Overrun Counter and Flag",
}
STANDARD_MEI_TYPES: frozenset[int] = frozenset({0x0D, 0x0E})

# Expected fixed PDU request lengths (excluding Unit ID) for common Modbus FCs
# Format: fc -> (min_pdu_len, max_pdu_len)
STANDARD_FC_PDU_BOUNDS: Dict[int, Tuple[int, int]] = {
    1: (5, 5),   # Read Coils request: FC(1) + addr(2) + qty(2)
    2: (5, 5),   # Read Discrete Inputs request
    3: (5, 5),   # Read Holding Registers request
    4: (5, 5),   # Read Input Registers request
    5: (5, 5),   # Write Single Coil request
    6: (5, 5),   # Write Single Register request
}


# ---------------------------------------------------------------------------
# Shared Utilities & Data Models
# ---------------------------------------------------------------------------


def shannon_entropy_bytes(data: bytes) -> float:
    """Compute Shannon entropy in bits per byte (range [0.0, 8.0])."""
    if not data:
        return 0.0
    counts = Counter(data)
    total = float(len(data))
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


def is_high_entropy_payload(
    data: bytes,
    abs_threshold: float = 5.5,
    normalized_threshold: float = 0.90,
    min_len: int = 16,
) -> bool:
    """
    Determine whether ``data`` exhibits encrypted/compressed high entropy.

    Accounts for finite-length entropy ceiling ``log2(min(len(data), 256))`` so
    short 16–64 byte encrypted Modbus PDUs are detected accurately.
    """
    if len(data) < min_len:
        return False
    ent = shannon_entropy_bytes(data)
    if ent >= abs_threshold:
        return True
    max_possible = math.log2(min(len(data), 256))
    return max_possible > 0 and (ent / max_possible) >= normalized_threshold


def _coerce_bytes(raw: Any) -> bytes:
    """Convert hex string, bytes, bytearray, or list[int] into raw bytes."""
    if raw is None:
        return b""
    if isinstance(raw, bytes):
        return raw
    if isinstance(raw, bytearray):
        return bytes(raw)
    if isinstance(raw, str):
        cleaned = raw.strip().replace(" ", "").replace(":", "")
        if not cleaned:
            return b""
        try:
            return bytes.fromhex(cleaned)
        except ValueError:
            return raw.encode("utf-8", errors="ignore")
    if isinstance(raw, Iterable):
        try:
            return bytes(int(x) & 0xFF for x in raw)
        except (TypeError, ValueError):
            return b""
    return b""


def _parse_iso_ts(raw_ts: Any) -> str:
    if isinstance(raw_ts, datetime):
        dt = raw_ts if raw_ts.tzinfo else raw_ts.replace(tzinfo=timezone.utc)
        return dt.isoformat()
    if isinstance(raw_ts, (int, float)):
        return datetime.fromtimestamp(float(raw_ts), tz=timezone.utc).isoformat()
    if isinstance(raw_ts, str) and raw_ts:
        return raw_ts
    return datetime.now(tz=timezone.utc).isoformat()


@dataclass
class LoopholeFinding:
    """Structured detection output from ``NovelLoopholesEngine``."""

    finding_id: str
    detector: str  # "modbus_tunneling" | "cusum_register_drift" | "tcp_fragmentation_evasion"
    loophole_type: str
    severity: str  # "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    confidence: float
    src_ip: str
    dst_ip: str
    timestamp: str
    mitre_techniques: List[str]
    description: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    published: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# 1. Modbus TCP Function Code Tunneling & Protocol Abuse Detector
# ---------------------------------------------------------------------------


class ModbusTunnelingDetector:
    """
    Detects covert data encapsulation and protocol abuse inside Modbus TCP frames.

    Targets:
    - User-defined function codes 0x41–0x48 (65–72) and 0x64–0x6E (100–110)
    - Diagnostic FC 0x08 subfunction abuse (echo data tunneling / hazardous subfuncs)
    - MEI Encapsulated Interface Transport FC 0x2B (43) with non-standard MEI types
    - MBAP Protocol ID != 0x0000 and declared length vs actual PDU length discrepancies
    - High-entropy opaque payloads carried inside Modbus frames
    """

    def __init__(
        self,
        approved_user_fcs: Optional[Set[Tuple[str, str, int]]] = None,
        payload_entropy_threshold: float = 5.5,
        diag_echo_max_bytes: int = 16,
        min_entropy_payload_len: int = 16,
        repeated_fc_window: int = 5,
    ) -> None:
        # Optional allowlist of (src_ip, dst_ip, fc) for legitimate vendor-specific extensions
        self._approved_user_fcs: Set[Tuple[str, str, int]] = set(approved_user_fcs or set())
        self.payload_entropy_threshold = float(payload_entropy_threshold)
        self.diag_echo_max_bytes = int(diag_echo_max_bytes)
        self.min_entropy_payload_len = int(min_entropy_payload_len)
        self.repeated_fc_window = int(repeated_fc_window)

        # Track suspicious FC counts per (src_ip, dst_ip) to escalate persistent tunneling
        self._suspicious_fc_counts: Dict[Tuple[str, str], int] = defaultdict(int)
        self._tunnel_bytes_accumulated: Dict[Tuple[str, str], int] = defaultdict(int)

    def allow_user_defined_fc(self, src_ip: str, dst_ip: str, function_code: int) -> None:
        """Explicitly whitelist a vendor-specific user-defined Modbus function code."""
        self._approved_user_fcs.add((src_ip, dst_ip, int(function_code)))

    def analyze_packet(self, packet: Dict[str, Any]) -> List[LoopholeFinding]:
        """
        Inspect a parsed Modbus TCP packet dictionary.

        Expected keys (flexible naming):
        - ``src_ip``, ``dst_ip``, ``timestamp``
        - ``function_code`` (int, 0–255)
        - ``subfunction_code`` (optional int, for FC 0x08 or MEI type for FC 0x2B)
        - ``protocol_id`` (optional int, MBAP Protocol Identifier; standard = 0)
        - ``unit_id`` (optional int)
        - ``mbap_length`` (optional int, MBAP Length field = Unit ID (1) + PDU length)
        - ``pdu_length`` (optional int, actual observed PDU byte length)
        - ``payload_bytes`` / ``payload_hex`` (optional raw PDU data bytes after FC)
        - ``direction`` (optional: ``"request"`` or ``"response"``, default ``"request"``)
        """
        src_ip = str(packet.get("src_ip") or packet.get("source_ip") or "")
        dst_ip = str(packet.get("dst_ip") or packet.get("destination_ip") or "")
        ts = _parse_iso_ts(packet.get("timestamp"))
        fc = int(packet.get("function_code", -1))
        subfunc = packet.get("subfunction_code")
        if subfunc is not None:
            subfunc = int(subfunc)
        protocol_id = int(packet.get("protocol_id", 0))
        unit_id = packet.get("unit_id")
        mbap_length = packet.get("mbap_length")
        direction = str(packet.get("direction", "request")).lower()

        raw_payload = _coerce_bytes(
            packet.get("payload_bytes")
            if packet.get("payload_bytes") is not None
            else packet.get("payload_hex")
        )
        pdu_length = packet.get("pdu_length")
        if pdu_length is None and raw_payload:
            pdu_length = 1 + len(raw_payload)

        payload_entropy = shannon_entropy_bytes(raw_payload)
        findings: List[LoopholeFinding] = []
        pair = (src_ip, dst_ip)

        # ------------------------------------------------------------------
        # 1. User-Defined Function Codes (0x41–0x48 and 0x64–0x6E)
        # ------------------------------------------------------------------
        in_user_range = (
            fc in USER_DEFINED_MODBUS_FC_RANGE_1 or fc in USER_DEFINED_MODBUS_FC_RANGE_2
        )
        if in_user_range and (src_ip, dst_ip, fc) not in self._approved_user_fcs:
            self._suspicious_fc_counts[pair] += 1
            self._tunnel_bytes_accumulated[pair] += len(raw_payload)
            persistent = self._suspicious_fc_counts[pair] >= self.repeated_fc_window
            high_ent = is_high_entropy_payload(
                raw_payload,
                abs_threshold=self.payload_entropy_threshold,
                min_len=self.min_entropy_payload_len,
            )
            severity = "CRITICAL" if (persistent or high_ent) else "HIGH"
            confidence = min(
                0.98,
                0.78
                + (0.10 if high_ent else 0.0)
                + (0.08 if persistent else 0.0),
            )
            findings.append(
                LoopholeFinding(
                    finding_id=str(uuid.uuid4()),
                    detector="modbus_tunneling",
                    loophole_type="modbus_user_defined_fc_tunneling",
                    severity=severity,
                    confidence=round(confidence, 4),
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    timestamp=ts,
                    mitre_techniques=["T0869", "T0836", "T1071"],
                    description=(
                        f"Unapproved user-defined Modbus function code 0x{fc:02X} ({fc}) "
                        f"from {src_ip} to {dst_ip} ({len(raw_payload)}B payload, "
                        f"entropy={payload_entropy:.2f} bits/B)"
                    ),
                    evidence={
                        "function_code": fc,
                        "function_code_hex": f"0x{fc:02X}",
                        "direction": direction,
                        "unit_id": unit_id,
                        "payload_len": len(raw_payload),
                        "payload_entropy": round(payload_entropy, 4),
                        "pair_suspicious_fc_count": self._suspicious_fc_counts[pair],
                        "accumulated_tunnel_bytes": self._tunnel_bytes_accumulated[pair],
                    },
                )
            )

        # ------------------------------------------------------------------
        # 2. Diagnostic FC 0x08 Subfunction Abuse & Echo Tunneling
        # ------------------------------------------------------------------
        if fc == MODBUS_FC_DIAGNOSTICS:
            if subfunc == DIAG_SUBFUNC_RETURN_QUERY_DATA:
                is_oversized = len(raw_payload) > self.diag_echo_max_bytes
                is_high_entropy = is_high_entropy_payload(
                    raw_payload,
                    abs_threshold=self.payload_entropy_threshold,
                    min_len=self.min_entropy_payload_len,
                )
                if is_oversized or is_high_entropy:
                    self._suspicious_fc_counts[pair] += 1
                    self._tunnel_bytes_accumulated[pair] += len(raw_payload)
                    findings.append(
                        LoopholeFinding(
                            finding_id=str(uuid.uuid4()),
                            detector="modbus_tunneling",
                            loophole_type="modbus_diagnostic_echo_tunneling",
                            severity="HIGH" if not is_high_entropy else "CRITICAL",
                            confidence=round(0.88 if is_high_entropy else 0.78, 4),
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            timestamp=ts,
                            mitre_techniques=["T0869", "T0885", "T1095"],
                            description=(
                                f"Modbus Diagnostic FC 0x08 Return Query Data (subfunc 0x0000) "
                                f"carries anomalous {len(raw_payload)}B payload "
                                f"(entropy={payload_entropy:.2f}) between {src_ip} and {dst_ip}"
                            ),
                            evidence={
                                "function_code": fc,
                                "subfunction_code": subfunc,
                                "payload_len": len(raw_payload),
                                "payload_entropy": round(payload_entropy, 4),
                                "diag_echo_max_bytes": self.diag_echo_max_bytes,
                                "direction": direction,
                            },
                        )
                    )
            elif subfunc in DIAG_HAZARDOUS_SUBFUNCTIONS:
                findings.append(
                    LoopholeFinding(
                        finding_id=str(uuid.uuid4()),
                        detector="modbus_tunneling",
                        loophole_type="modbus_diagnostic_hazardous_subfunction",
                        severity="CRITICAL",
                        confidence=0.92,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        timestamp=ts,
                        mitre_techniques=["T0814", "T0816", "T0855"],
                        description=(
                            f"Hazardous Modbus Diagnostic FC 0x08 subfunction 0x{subfunc:04X} "
                            f"({DIAG_HAZARDOUS_SUBFUNCTIONS[subfunc]}) from {src_ip} to {dst_ip}"
                        ),
                        evidence={
                            "function_code": fc,
                            "subfunction_code": subfunc,
                            "subfunction_name": DIAG_HAZARDOUS_SUBFUNCTIONS[subfunc],
                            "unit_id": unit_id,
                        },
                    )
                )

        # ------------------------------------------------------------------
        # 3. MEI Encapsulated Interface Transport (FC 0x2B / 43) Abuse
        # ------------------------------------------------------------------
        if fc == MODBUS_FC_MEI_TRANSPORT:
            non_standard_mei = subfunc is not None and subfunc not in STANDARD_MEI_TYPES
            high_ent_mei = is_high_entropy_payload(
                raw_payload,
                abs_threshold=self.payload_entropy_threshold,
                min_len=self.min_entropy_payload_len,
            )
            if non_standard_mei or high_ent_mei:
                findings.append(
                    LoopholeFinding(
                        finding_id=str(uuid.uuid4()),
                        detector="modbus_tunneling",
                        loophole_type="modbus_mei_encapsulation_abuse",
                        severity="HIGH",
                        confidence=0.84,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        timestamp=ts,
                        mitre_techniques=["T0869", "T0885"],
                        description=(
                            f"Modbus MEI Transport (FC 0x2B) with anomalous MEI type "
                            f"{subfunc} or high-entropy payload ({payload_entropy:.2f} bits/B)"
                        ),
                        evidence={
                            "function_code": fc,
                            "mei_type": subfunc,
                            "payload_len": len(raw_payload),
                            "payload_entropy": round(payload_entropy, 4),
                        },
                    )
                )

        # ------------------------------------------------------------------
        # 4. MBAP Protocol ID != 0 or Declared Length / PDU Size Discrepancy
        # ------------------------------------------------------------------
        if protocol_id != 0:
            findings.append(
                LoopholeFinding(
                    finding_id=str(uuid.uuid4()),
                    detector="modbus_tunneling",
                    loophole_type="modbus_mbap_protocol_id_anomaly",
                    severity="HIGH",
                    confidence=0.90,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    timestamp=ts,
                    mitre_techniques=["T0869", "T1001"],
                    description=(
                        f"Non-zero Modbus MBAP Protocol ID (0x{protocol_id:04X}) from "
                        f"{src_ip} to {dst_ip} indicates covert header signaling or tunneling"
                    ),
                    evidence={
                        "protocol_id": protocol_id,
                        "protocol_id_hex": f"0x{protocol_id:04X}",
                        "function_code": fc,
                    },
                )
            )

        if mbap_length is not None and pdu_length is not None:
            expected_mbap = int(pdu_length) + 1  # Unit ID (1B) + PDU
            if int(mbap_length) != expected_mbap:
                findings.append(
                    LoopholeFinding(
                        finding_id=str(uuid.uuid4()),
                        detector="modbus_tunneling",
                        loophole_type="modbus_mbap_length_mismatch",
                        severity="HIGH",
                        confidence=0.86,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        timestamp=ts,
                        mitre_techniques=["T0869", "T1001.001"],
                        description=(
                            f"Modbus MBAP length ({mbap_length}) mismatches observed "
                            f"UnitID+PDU length ({expected_mbap}) on FC 0x{fc:02X}"
                        ),
                        evidence={
                            "mbap_length": int(mbap_length),
                            "observed_pdu_length": int(pdu_length),
                            "expected_mbap_length": expected_mbap,
                            "slack_bytes": int(mbap_length) - expected_mbap,
                            "function_code": fc,
                        },
                    )
                )

        # Standard fixed-size request FC carrying unexpected extra payload bytes
        if (
            direction == "request"
            and fc in STANDARD_FC_PDU_BOUNDS
            and pdu_length is not None
        ):
            min_len, max_len = STANDARD_FC_PDU_BOUNDS[fc]
            if not (min_len <= int(pdu_length) <= max_len):
                findings.append(
                    LoopholeFinding(
                        finding_id=str(uuid.uuid4()),
                        detector="modbus_tunneling",
                        loophole_type="modbus_standard_fc_oversized_pdu",
                        severity="HIGH",
                        confidence=0.85,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        timestamp=ts,
                        mitre_techniques=["T0869", "T1001"],
                        description=(
                            f"Standard Modbus request FC 0x{fc:02X} has abnormal PDU length "
                            f"{pdu_length}B (expected {min_len}..{max_len}B)"
                        ),
                        evidence={
                            "function_code": fc,
                            "observed_pdu_length": int(pdu_length),
                            "expected_bounds": [min_len, max_len],
                            "payload_entropy": round(payload_entropy, 4),
                        },
                    )
                )

        return findings


# ---------------------------------------------------------------------------
# 2. Sub-Threshold Sensor / Holding Register Drift Detector (Page's CUSUM)
# ---------------------------------------------------------------------------


@dataclass
class RegisterBaseline:
    """Normal operating profile and CUSUM state for a single PLC holding register."""

    plc_ip: str
    register_addr: int
    register_name: str = ""
    mean: Optional[float] = None
    std: Optional[float] = None
    static_low: Optional[float] = None
    static_high: Optional[float] = None
    allowance_k: float = 0.5   # Reference slack in sigma units (0.5 detects >= 1-sigma shift)
    decision_h: float = 5.0    # Decision threshold in sigma units (ARL0 ~ 465 samples)
    warmup_samples: int = 20
    # Mutable CUSUM accumulators
    cusum_pos: float = 0.0
    cusum_neg: float = 0.0
    sample_count: int = 0
    warmup_buffer: List[float] = field(default_factory=list)
    recent_values: Deque[float] = field(default_factory=lambda: deque(maxlen=50))


class CUSUMDriftDetector:
    """
    Two-sided standardized Page's CUSUM detector for sub-threshold Modbus holding
    register manipulation ("slow-burn" / boiling-frog drift attacks).

    Example BECPL scenario:
    An attacker compromises an HMI/MES node and gradually nudges SMT Reflow Oven
    Zone-1 setpoint (register 40001, nominal 245.0°C ± 0.5°C, static alarm [235, 255])
    upward by +0.4°C per batch. Every sample remains well within [235, 255], evading
    static thresholds, while CUSUM accumulates the persistent positive residual and
    fires before thermal degradation ruins an automotive PCB production run.
    """

    def __init__(
        self,
        default_allowance_k: float = 0.5,
        default_decision_h: float = 5.0,
        default_warmup_samples: int = 20,
        min_std_floor: float = 1e-3,
    ) -> None:
        self.default_allowance_k = float(default_allowance_k)
        self.default_decision_h = float(default_decision_h)
        self.default_warmup_samples = int(default_warmup_samples)
        self.min_std_floor = float(min_std_floor)
        self._registers: Dict[Tuple[str, int], RegisterBaseline] = {}

    def register_baseline(
        self,
        plc_ip: str,
        register_addr: int,
        mean: float,
        std: float,
        static_low: Optional[float] = None,
        static_high: Optional[float] = None,
        register_name: str = "",
        allowance_k: Optional[float] = None,
        decision_h: Optional[float] = None,
    ) -> None:
        """Configure a known physical baseline for ``(plc_ip, register_addr)``."""
        key = (plc_ip, int(register_addr))
        self._registers[key] = RegisterBaseline(
            plc_ip=plc_ip,
            register_addr=int(register_addr),
            register_name=register_name or f"reg_{register_addr}",
            mean=float(mean),
            std=max(float(std), self.min_std_floor),
            static_low=static_low,
            static_high=static_high,
            allowance_k=self.default_allowance_k if allowance_k is None else float(allowance_k),
            decision_h=self.default_decision_h if decision_h is None else float(decision_h),
            warmup_samples=self.default_warmup_samples,
        )

    def reset_cusum(self, plc_ip: str, register_addr: int) -> None:
        """Reset cumulative sums after analyst triage or authorized recipe change."""
        state = self._registers.get((plc_ip, int(register_addr)))
        if state is not None:
            state.cusum_pos = 0.0
            state.cusum_neg = 0.0

    def get_register_state(self, plc_ip: str, register_addr: int) -> Optional[Dict[str, Any]]:
        """Return diagnostic CUSUM state for a monitored register."""
        state = self._registers.get((plc_ip, int(register_addr)))
        if state is None:
            return None
        return {
            "plc_ip": state.plc_ip,
            "register_addr": state.register_addr,
            "register_name": state.register_name,
            "mean": state.mean,
            "std": state.std,
            "cusum_pos": round(state.cusum_pos, 4),
            "cusum_neg": round(state.cusum_neg, 4),
            "decision_h": state.decision_h,
            "sample_count": state.sample_count,
            "ready": state.mean is not None,
        }

    def observe(
        self,
        plc_ip: str,
        register_addr: int,
        value: float,
        src_ip: str = "",
        timestamp: Any = None,
        static_low: Optional[float] = None,
        static_high: Optional[float] = None,
        register_name: str = "",
    ) -> Optional[LoopholeFinding]:
        """
        Ingest a single holding/input register observation and update CUSUM state.

        Returns a ``LoopholeFinding`` when either $S_t^+ > h$ or $S_t^- > h$.
        """
        key = (plc_ip, int(register_addr))
        val = float(value)
        ts = _parse_iso_ts(timestamp)

        state = self._registers.get(key)
        if state is None:
            state = RegisterBaseline(
                plc_ip=plc_ip,
                register_addr=int(register_addr),
                register_name=register_name or f"reg_{register_addr}",
                static_low=static_low,
                static_high=static_high,
                allowance_k=self.default_allowance_k,
                decision_h=self.default_decision_h,
                warmup_samples=self.default_warmup_samples,
            )
            self._registers[key] = state
        else:
            if static_low is not None and state.static_low is None:
                state.static_low = static_low
            if static_high is not None and state.static_high is None:
                state.static_high = static_high

        state.sample_count += 1
        state.recent_values.append(val)

        # Warmup phase if baseline not pre-registered
        if state.mean is None or state.std is None:
            state.warmup_buffer.append(val)
            if len(state.warmup_buffer) >= state.warmup_samples:
                arr = np.asarray(state.warmup_buffer, dtype=float)
                state.mean = float(np.mean(arr))
                state.std = max(float(np.std(arr, ddof=1)), self.min_std_floor)
            return None

        # Standardized two-sided Page's CUSUM update
        z = (val - state.mean) / state.std
        state.cusum_pos = max(0.0, state.cusum_pos + z - state.allowance_k)
        state.cusum_neg = max(0.0, state.cusum_neg - z - state.allowance_k)

        triggered_pos = state.cusum_pos > state.decision_h
        triggered_neg = state.cusum_neg > state.decision_h
        if not (triggered_pos or triggered_neg):
            return None

        drift_direction = "positive_drift" if triggered_pos else "negative_drift"
        cusum_score = state.cusum_pos if triggered_pos else state.cusum_neg

        # Determine if this drift stayed stealthily inside static alarm limits
        within_static_bounds = True
        if state.static_low is not None and val < state.static_low:
            within_static_bounds = False
        if state.static_high is not None and val > state.static_high:
            within_static_bounds = False
        has_static_limits = (state.static_low is not None) or (state.static_high is not None)
        sub_threshold_evasion = has_static_limits and within_static_bounds

        recent_arr = np.asarray(list(state.recent_values)[-10:], dtype=float)
        recent_mean = float(np.mean(recent_arr))
        cumulative_shift = recent_mean - state.mean
        confidence = min(0.99, 0.72 + 0.05 * (cusum_score - state.decision_h))
        severity = "CRITICAL" if sub_threshold_evasion else "HIGH"

        return LoopholeFinding(
            finding_id=str(uuid.uuid4()),
            detector="cusum_register_drift",
            loophole_type="sub_threshold_register_drift",
            severity=severity,
            confidence=round(confidence, 4),
            src_ip=src_ip or plc_ip,
            dst_ip=plc_ip,
            timestamp=ts,
            mitre_techniques=["T0836", "T0831", "T0856"],
            description=(
                f"CUSUM {drift_direction} on PLC {plc_ip} register {state.register_addr} "
                f"({state.register_name}): value={val:.3f}, baseline={state.mean:.3f}±{state.std:.3f}, "
                f"CUSUM={cusum_score:.2f} > h={state.decision_h:.2f}"
                + (" [STEALTH: within static alarm limits]" if sub_threshold_evasion else "")
            ),
            evidence={
                "plc_ip": plc_ip,
                "register_addr": state.register_addr,
                "register_name": state.register_name,
                "current_value": round(val, 4),
                "baseline_mean": round(state.mean, 4),
                "baseline_std": round(state.std, 4),
                "z_score": round(z, 4),
                "cusum_pos": round(state.cusum_pos, 4),
                "cusum_neg": round(state.cusum_neg, 4),
                "decision_h": state.decision_h,
                "allowance_k": state.allowance_k,
                "drift_direction": drift_direction,
                "recent_mean": round(recent_mean, 4),
                "cumulative_shift": round(cumulative_shift, 4),
                "static_bounds": [state.static_low, state.static_high],
                "sub_threshold_evasion": sub_threshold_evasion,
                "sample_count": state.sample_count,
            },
        )


# ---------------------------------------------------------------------------
# 3. Passive Sensor Blind Spot & TCP Fragmentation Evasion Detector
# ---------------------------------------------------------------------------


@dataclass
class _SegmentRecord:
    seq: int
    end_seq: int
    payload: bytes
    ttl: Optional[int]
    tcp_ts: Optional[int]
    direction: str


@dataclass
class _FlowReassemblyState:
    segments: Deque[_SegmentRecord] = field(default_factory=lambda: deque(maxlen=128))
    highest_seq_by_dir: Dict[str, int] = field(default_factory=dict)
    out_of_order_count: int = 0
    total_data_segments: int = 0
    micro_frag_count: int = 0
    ttl_history_by_dir: Dict[str, Deque[int]] = field(
        default_factory=lambda: defaultdict(lambda: deque(maxlen=32))
    )
    last_tcp_ts_by_dir: Dict[str, int] = field(default_factory=dict)
    dir_packet_counts: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    asymmetric_reported: bool = False


class TCPFragmentationEvasionDetector:
    """
    Detects passive NIDS reassembly evasion & sensor blind spots across TCP/IP streams.

    Detects:
    - Conflicting overlapping TCP segments (OS-dependent reassembly ambiguity)
    - Excessive micro-fragmentation / tiny TCP segments splitting protocol headers
    - Out-of-order segment bursts exceeding normal link jitter
    - Invalid TCP checksum decoy injection (exploits ``checksum-validation: no``)
    - TTL drop / chaff packet insertion (decoy packets expiring before target host)
    - TCP Timestamp (RFC 7323 PAWS) backward/extreme-future jumps
    - Asymmetric routing / half-duplex visibility blind spot on passive SPAN taps
    """

    def __init__(
        self,
        micro_frag_max_bytes: int = 24,
        micro_frag_burst_threshold: int = 4,
        ooo_ratio_threshold: float = 0.35,
        ooo_min_segments: int = 6,
        ttl_anomaly_delta: int = 5,
        low_ttl_chaff_threshold: int = 3,
        max_ts_forward_jump: int = 3_600_000,  # ~1 hour at 1kHz clock
        asymmetric_min_packets: int = 12,
    ) -> None:
        self.micro_frag_max_bytes = int(micro_frag_max_bytes)
        self.micro_frag_burst_threshold = int(micro_frag_burst_threshold)
        self.ooo_ratio_threshold = float(ooo_ratio_threshold)
        self.ooo_min_segments = int(ooo_min_segments)
        self.ttl_anomaly_delta = int(ttl_anomaly_delta)
        self.low_ttl_chaff_threshold = int(low_ttl_chaff_threshold)
        self.max_ts_forward_jump = int(max_ts_forward_jump)
        self.asymmetric_min_packets = int(asymmetric_min_packets)

        self._flows: Dict[str, _FlowReassemblyState] = defaultdict(_FlowReassemblyState)

    def _flow_key(self, seg: Dict[str, Any]) -> str:
        if seg.get("flow_id"):
            return str(seg["flow_id"])
        src_ip = str(seg.get("src_ip") or "")
        dst_ip = str(seg.get("dst_ip") or "")
        src_port = int(seg.get("src_port") or 0)
        dst_port = int(seg.get("dst_port") or 0)
        endpoints = sorted([(src_ip, src_port), (dst_ip, dst_port)])
        return f"{endpoints[0][0]}:{endpoints[0][1]}<->{endpoints[1][0]}:{endpoints[1][1]}"

    def analyze_segment(self, seg: Dict[str, Any]) -> List[LoopholeFinding]:
        """
        Inspect a TCP/IP segment metadata record.

        Expected keys:
        - ``flow_id`` (optional), ``src_ip``, ``dst_ip``, ``src_port``, ``dst_port``
        - ``direction`` (``"c2s"`` / ``"s2c"`` or ``"orig"`` / ``"resp"``)
        - ``seq`` (int TCP sequence number)
        - ``payload_bytes`` / ``payload_hex`` (optional bytes) and/or ``payload_len`` (int)
        - ``ttl`` (optional int IP TTL)
        - ``tcp_timestamp`` (optional int TSval)
        - ``checksum_valid`` (optional bool, default True)
        - ``ip_frag_offset`` (optional int, default 0), ``ip_mf_flag`` (optional bool)
        - ``tcp_flags`` (optional str, e.g. ``"PA"``, ``"A"``, ``"S"``)
        - ``timestamp`` (optional)
        """
        src_ip = str(seg.get("src_ip") or "")
        dst_ip = str(seg.get("dst_ip") or "")
        ts = _parse_iso_ts(seg.get("timestamp"))
        flow_id = self._flow_key(seg)
        direction = str(seg.get("direction") or f"{src_ip}->{dst_ip}")
        flags = str(seg.get("tcp_flags") or "").upper()

        payload = _coerce_bytes(
            seg.get("payload_bytes")
            if seg.get("payload_bytes") is not None
            else seg.get("payload_hex")
        )
        payload_len = int(seg.get("payload_len", len(payload)))
        seq = seg.get("seq")
        ttl = seg.get("ttl")
        tcp_ts = seg.get("tcp_timestamp")
        checksum_valid = seg.get("checksum_valid", True)
        ip_frag_offset = int(seg.get("ip_frag_offset", 0))
        ip_mf_flag = bool(seg.get("ip_mf_flag", False))

        state = self._flows[flow_id]
        state.dir_packet_counts[direction] += 1
        findings: List[LoopholeFinding] = []

        # ------------------------------------------------------------------
        # 1. Invalid TCP Checksum Decoy Packet Injection
        # ------------------------------------------------------------------
        if checksum_valid is False:
            findings.append(
                LoopholeFinding(
                    finding_id=str(uuid.uuid4()),
                    detector="tcp_fragmentation_evasion",
                    loophole_type="invalid_checksum_decoy_injection",
                    severity="HIGH",
                    confidence=0.93,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    timestamp=ts,
                    mitre_techniques=["T1562.001", "T1027", "T0820"],
                    description=(
                        f"Segment with invalid TCP checksum observed on flow {flow_id} "
                        f"(seq={seq}, len={payload_len}); potential passive NIDS chaff injection"
                    ),
                    evidence={
                        "flow_id": flow_id,
                        "seq": seq,
                        "payload_len": payload_len,
                        "direction": direction,
                    },
                )
            )

        # ------------------------------------------------------------------
        # 2. TTL Manipulation / Chaff Insertion Detection
        # ------------------------------------------------------------------
        if ttl is not None:
            ttl_val = int(ttl)
            ttl_hist = state.ttl_history_by_dir[direction]
            is_low_chaff = ttl_val <= self.low_ttl_chaff_threshold
            ttl_delta = 0
            baseline_ttl = None
            if ttl_hist:
                baseline_ttl = int(round(float(np.median(list(ttl_hist)))))
                ttl_delta = abs(ttl_val - baseline_ttl)
            if is_low_chaff or (baseline_ttl is not None and ttl_delta >= self.ttl_anomaly_delta):
                findings.append(
                    LoopholeFinding(
                        finding_id=str(uuid.uuid4()),
                        detector="tcp_fragmentation_evasion",
                        loophole_type="ttl_chaff_insertion_evasion",
                        severity="CRITICAL" if is_low_chaff else "HIGH",
                        confidence=0.92 if is_low_chaff else 0.84,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        timestamp=ts,
                        mitre_techniques=["T1562.001", "T1205"],
                        description=(
                            f"Anomalous IP TTL={ttl_val} (baseline={baseline_ttl}, "
                            f"delta={ttl_delta}) on flow {flow_id}; possible TTL-expiry NIDS decoy"
                        ),
                        evidence={
                            "flow_id": flow_id,
                            "observed_ttl": ttl_val,
                            "baseline_ttl": baseline_ttl,
                            "ttl_delta": ttl_delta,
                            "low_ttl_chaff": is_low_chaff,
                            "seq": seq,
                        },
                    )
                )
            # Only add normal-looking TTLs to median history so decoys don't poison baseline
            if not is_low_chaff:
                ttl_hist.append(ttl_val)

        # ------------------------------------------------------------------
        # 3. TCP Timestamp (RFC 7323 PAWS) Manipulation
        # ------------------------------------------------------------------
        if tcp_ts is not None:
            ts_val = int(tcp_ts)
            prev_ts = state.last_tcp_ts_by_dir.get(direction)
            if prev_ts is not None:
                delta_ts = ts_val - prev_ts
                # Detect backward timestamp (PAWS drop at receiver) or huge future spike
                if delta_ts < 0 or delta_ts > self.max_ts_forward_jump:
                    findings.append(
                        LoopholeFinding(
                            finding_id=str(uuid.uuid4()),
                            detector="tcp_fragmentation_evasion",
                            loophole_type="tcp_timestamp_paws_evasion",
                            severity="HIGH",
                            confidence=0.88,
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            timestamp=ts,
                            mitre_techniques=["T1562.001", "T1027"],
                            description=(
                                f"TCP Timestamp PAWS anomaly on flow {flow_id}: "
                                f"TSval jumped from {prev_ts} to {ts_val} (delta={delta_ts})"
                            ),
                            evidence={
                                "flow_id": flow_id,
                                "previous_tsval": prev_ts,
                                "current_tsval": ts_val,
                                "delta_tsval": delta_ts,
                                "anomaly_kind": "backward_paws_decoy" if delta_ts < 0 else "future_ts_spike",
                                "seq": seq,
                            },
                        )
                    )
                else:
                    state.last_tcp_ts_by_dir[direction] = ts_val
            else:
                state.last_tcp_ts_by_dir[direction] = ts_val

        # ------------------------------------------------------------------
        # 4. Overlapping TCP Segments with Conflicting Payload + OOO + Micro-Frag
        # ------------------------------------------------------------------
        if seq is not None and payload_len > 0:
            seq_i = int(seq)
            end_seq = seq_i + payload_len
            state.total_data_segments += 1

            # Check overlap against previously observed segments in the same direction
            if payload:
                for prev in state.segments:
                    if prev.direction != direction or not prev.payload:
                        continue
                    ov_start = max(seq_i, prev.seq)
                    ov_end = min(end_seq, prev.end_seq)
                    if ov_start < ov_end:
                        new_slice = payload[ov_start - seq_i : ov_end - seq_i]
                        old_slice = prev.payload[ov_start - prev.seq : ov_end - prev.seq]
                        if new_slice != old_slice:
                            findings.append(
                                LoopholeFinding(
                                    finding_id=str(uuid.uuid4()),
                                    detector="tcp_fragmentation_evasion",
                                    loophole_type="overlapping_tcp_segment_conflict",
                                    severity="CRITICAL",
                                    confidence=0.96,
                                    src_ip=src_ip,
                                    dst_ip=dst_ip,
                                    timestamp=ts,
                                    mitre_techniques=["T1562.001", "T1027"],
                                    description=(
                                        f"Conflicting overlapping TCP segments on flow {flow_id} "
                                        f"over sequence range [{ov_start}, {ov_end}): "
                                        f"OS reassembly ambiguity evasion detected"
                                    ),
                                    evidence={
                                        "flow_id": flow_id,
                                        "overlap_start": ov_start,
                                        "overlap_end": ov_end,
                                        "overlap_bytes": ov_end - ov_start,
                                        "previous_hex": old_slice.hex(),
                                        "current_hex": new_slice.hex(),
                                        "direction": direction,
                                    },
                                )
                            )
                            break

            # Out-of-order tracking
            highest = state.highest_seq_by_dir.get(direction)
            if highest is not None and seq_i < highest:
                state.out_of_order_count += 1
            if highest is None or end_seq > highest:
                state.highest_seq_by_dir[direction] = end_seq

            if state.total_data_segments >= self.ooo_min_segments:
                ooo_ratio = state.out_of_order_count / float(state.total_data_segments)
                if ooo_ratio >= self.ooo_ratio_threshold:
                    findings.append(
                        LoopholeFinding(
                            finding_id=str(uuid.uuid4()),
                            detector="tcp_fragmentation_evasion",
                            loophole_type="out_of_order_fragmentation_evasion",
                            severity="HIGH",
                            confidence=min(0.95, 0.70 + ooo_ratio * 0.4),
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            timestamp=ts,
                            mitre_techniques=["T1562.001"],
                            description=(
                                f"Sustained out-of-order TCP segment burst on flow {flow_id} "
                                f"({state.out_of_order_count}/{state.total_data_segments} = "
                                f"{ooo_ratio:.0%})"
                            ),
                            evidence={
                                "flow_id": flow_id,
                                "out_of_order_count": state.out_of_order_count,
                                "total_data_segments": state.total_data_segments,
                                "ooo_ratio": round(ooo_ratio, 4),
                            },
                        )
                    )

            # Micro-fragmentation / signature-splitting burst
            is_tiny_ip_frag = (ip_frag_offset > 0 or ip_mf_flag) and payload_len <= self.micro_frag_max_bytes
            is_tiny_tcp_seg = (
                payload_len <= self.micro_frag_max_bytes
                and "F" not in flags
                and "R" not in flags
            )
            if is_tiny_ip_frag or is_tiny_tcp_seg:
                state.micro_frag_count += 1
                if state.micro_frag_count == self.micro_frag_burst_threshold:
                    findings.append(
                        LoopholeFinding(
                            finding_id=str(uuid.uuid4()),
                            detector="tcp_fragmentation_evasion",
                            loophole_type="micro_fragmentation_signature_evasion",
                            severity="HIGH",
                            confidence=0.86,
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            timestamp=ts,
                            mitre_techniques=["T1562.001", "T1027"],
                            description=(
                                f"Micro-fragmentation burst on flow {flow_id}: "
                                f"{state.micro_frag_count} segments <= {self.micro_frag_max_bytes}B "
                                f"(signature-splitting evasion pattern)"
                            ),
                            evidence={
                                "flow_id": flow_id,
                                "micro_frag_count": state.micro_frag_count,
                                "max_bytes_threshold": self.micro_frag_max_bytes,
                                "ip_frag_offset": ip_frag_offset,
                                "ip_mf_flag": ip_mf_flag,
                            },
                        )
                    )

            state.segments.append(
                _SegmentRecord(
                    seq=seq_i,
                    end_seq=end_seq,
                    payload=payload,
                    ttl=int(ttl) if ttl is not None else None,
                    tcp_ts=int(tcp_ts) if tcp_ts is not None else None,
                    direction=direction,
                )
            )

        # ------------------------------------------------------------------
        # 5. Asymmetric Routing / Half-Duplex Passive Sensor Blind Spot
        # ------------------------------------------------------------------
        if (
            not state.asymmetric_reported
            and len(state.dir_packet_counts) == 1
            and state.dir_packet_counts[direction] >= self.asymmetric_min_packets
        ):
            state.asymmetric_reported = True
            findings.append(
                LoopholeFinding(
                    finding_id=str(uuid.uuid4()),
                    detector="tcp_fragmentation_evasion",
                    loophole_type="asymmetric_routing_sensor_blindspot",
                    severity="MEDIUM",
                    confidence=0.85,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    timestamp=ts,
                    mitre_techniques=["T1562.001"],
                    description=(
                        f"Half-duplex / asymmetric visibility on flow {flow_id}: observed "
                        f"{state.dir_packet_counts[direction]} packets in direction '{direction}' "
                        f"with zero reverse-path packets (SPAN/asymmetric routing blind spot)"
                    ),
                    evidence={
                        "flow_id": flow_id,
                        "observed_direction": direction,
                        "packet_count": state.dir_packet_counts[direction],
                        "reverse_packet_count": 0,
                    },
                )
            )

        return findings


# ---------------------------------------------------------------------------
# Unified Novel Loopholes Engine Facade
# ---------------------------------------------------------------------------


class NovelLoopholesEngine:
    """
    Unified VaultX Phase 3 engine orchestrating:
    - ``ModbusTunnelingDetector``
    - ``CUSUMDriftDetector``
    - ``TCPFragmentationEvasionDetector``

    Publishes findings to Redis stream ``detections:novel_loopholes`` when configured.
    """

    def __init__(
        self,
        redis_client: Any = None,
        modbus_detector: Optional[ModbusTunnelingDetector] = None,
        cusum_detector: Optional[CUSUMDriftDetector] = None,
        tcp_evasion_detector: Optional[TCPFragmentationEvasionDetector] = None,
        stream_name: str = REDIS_STREAM_NOVEL_LOOPHOLES,
    ) -> None:
        self._redis = redis_client
        self._stream = stream_name
        self.modbus_detector = modbus_detector or ModbusTunnelingDetector()
        self.cusum_detector = cusum_detector or CUSUMDriftDetector()
        self.tcp_evasion_detector = tcp_evasion_detector or TCPFragmentationEvasionDetector()
        self._finding_counts: Dict[str, int] = defaultdict(int)

    def analyze_modbus_packet(
        self, packet: Dict[str, Any], publish: bool = True
    ) -> List[LoopholeFinding]:
        findings = self.modbus_detector.analyze_packet(packet)
        return self._finalize(findings, publish=publish)

    def analyze_register_sample(
        self,
        plc_ip: str,
        register_addr: int,
        value: float,
        src_ip: str = "",
        timestamp: Any = None,
        static_low: Optional[float] = None,
        static_high: Optional[float] = None,
        register_name: str = "",
        publish: bool = True,
    ) -> Optional[LoopholeFinding]:
        finding = self.cusum_detector.observe(
            plc_ip=plc_ip,
            register_addr=register_addr,
            value=value,
            src_ip=src_ip,
            timestamp=timestamp,
            static_low=static_low,
            static_high=static_high,
            register_name=register_name,
        )
        if finding is None:
            return None
        return self._finalize([finding], publish=publish)[0]

    def analyze_tcp_segment(
        self, segment: Dict[str, Any], publish: bool = True
    ) -> List[LoopholeFinding]:
        findings = self.tcp_evasion_detector.analyze_segment(segment)
        return self._finalize(findings, publish=publish)

    def analyze_event(
        self, event: Dict[str, Any], publish: bool = True
    ) -> List[LoopholeFinding]:
        """
        Generic event dispatcher accepting ``event_type`` in:
        ``"modbus_packet"``, ``"register_sample"``, ``"tcp_segment"``.
        """
        etype = str(event.get("event_type", "")).lower()
        if etype == "modbus_packet":
            return self.analyze_modbus_packet(event, publish=publish)
        if etype == "register_sample":
            res = self.analyze_register_sample(
                plc_ip=str(event.get("plc_ip") or event.get("dst_ip") or ""),
                register_addr=int(event["register_addr"]),
                value=float(event["value"]),
                src_ip=str(event.get("src_ip") or ""),
                timestamp=event.get("timestamp"),
                static_low=event.get("static_low"),
                static_high=event.get("static_high"),
                register_name=str(event.get("register_name") or ""),
                publish=publish,
            )
            return [res] if res is not None else []
        if etype == "tcp_segment":
            return self.analyze_tcp_segment(event, publish=publish)
        logger.debug("NovelLoopholesEngine ignored unsupported event_type=%s", etype)
        return []

    def get_metrics(self) -> Dict[str, int]:
        """Return cumulative counts of detected loopholes by type."""
        return dict(self._finding_counts)

    def _finalize(
        self, findings: List[LoopholeFinding], publish: bool = True
    ) -> List[LoopholeFinding]:
        for finding in findings:
            self._finding_counts[finding.loophole_type] += 1
            if publish and self._redis is not None:
                finding.published = self._publish(finding)
        return findings

    def _publish(self, finding: LoopholeFinding) -> bool:
        try:
            self._redis.xadd(
                self._stream,
                {
                    "finding_id": finding.finding_id,
                    "detector": finding.detector,
                    "loophole_type": finding.loophole_type,
                    "severity": finding.severity,
                    "confidence": str(finding.confidence),
                    "src_ip": finding.src_ip,
                    "dst_ip": finding.dst_ip,
                    "timestamp": finding.timestamp,
                    "payload": json.dumps(finding.to_dict()),
                },
            )
            return True
        except Exception as exc:
            logger.error("Failed publishing novel loophole finding to Redis: %s", exc)
            return False

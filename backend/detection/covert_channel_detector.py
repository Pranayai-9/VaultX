"""
covert_channel_detector.py — Statistical Timing & Entropy Covert Channel Analyzer for VaultX Phase 3.

BECPL (Bharat Electronics Components Pvt. Ltd.), Pune — Manufacturing-Aware Hybrid NIDS.

Detects low-frequency, stealthy Command-and-Control (C2) and data exfiltration channels
operating over industrial protocols and DNS without opening suspicious HTTP/TLS ports:

1. **Modbus Polling Jitter Timing Channel Analyzer** (``ModbusPollingJitterAnalyzer``):
   - Industrial SCADA/HMI polling loops are highly deterministic (unimodal tight Gaussian
     jitter around nominal period $T_0$).
   - Covert timing channels modulate inter-packet delays into discrete bit symbols (e.g.,
     binary T_0 - δ vs T_0 + δ), producing bimodal/multimodal distributions
     measurable via **Sarle's Bimodality Coefficient** ($BC > 0.555$), **1D two-cluster
     Fisher separation** (Otsu split), and **quantized delay Shannon entropy**.
   - Also monitors **Modbus Transaction ID entropy/randomness** and **holding register
     LSB bit-stream steganography**.
2. **DNS Query Length & Label Entropy Analyzer** (``DNSCovertChannelAnalyzer``):
   - Tracks per-``(src_ip, base_domain)`` query series to catch low-and-slow DNS C2
     (Iodine, dnscat2, Cobalt Strike DNS TXT) that stays well below Suricata's
     ``request-flood: 500`` rate threshold.
   - Evaluates subdomain Shannon entropy, query length distribution entropy, mean subdomain
     length, unique-subdomain ratio, TXT/NULL record abuse, and TXT response entropy.
3. **Payload Padding & Slack-Space Steganography Analyzer** (``PayloadPaddingSteganographyAnalyzer``):
   - Inspects trailing Ethernet/Modbus/protocol padding bytes beyond declared PDU length
     for non-zero bytes, elevated Shannon entropy, and printable/base64 payloads.
   - Aggregates small (1–4 byte) non-zero slack snippets across consecutive frames on the
     same ``(src_ip, dst_ip)`` flow so ultra-slow steganographic exfiltration is caught.

Publishes findings to Redis stream ``detections:covert_channel`` when configured.
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

REDIS_STREAM_COVERT_CHANNEL: str = "detections:covert_channel"

COVERT_DNS_RECORD_TYPES: frozenset[str] = frozenset({"TXT", "NULL", "PRIVATE", "CNAME", "MX"})


# ---------------------------------------------------------------------------
# Statistical Helpers & Data Models
# ---------------------------------------------------------------------------


def shannon_entropy_string(text: str) -> float:
    """Compute Shannon entropy in bits per character."""
    if not text:
        return 0.0
    counts = Counter(text)
    total = float(len(text))
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def shannon_entropy_bytes(data: bytes) -> float:
    """Compute Shannon entropy in bits per byte (range [0.0, 8.0])."""
    if not data:
        return 0.0
    counts = Counter(data)
    total = float(len(data))
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def shannon_entropy_discrete(values: Iterable[Any]) -> float:
    """Compute Shannon entropy in bits over a discrete sequence of hashable bins."""
    seq = list(values)
    if not seq:
        return 0.0
    counts = Counter(seq)
    total = float(len(seq))
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def sarle_bimodality_coefficient(samples: np.ndarray) -> float:
    """
    Compute finite-sample Sarle's Bimodality Coefficient:
        BC = (skewness^2 + 1) / (excess_kurtosis + 3 * (n-1)^2 / ((n-2)*(n-3)))

    Values > 0.555 (the uniform distribution benchmark) indicate bimodality or
    multimodality characteristic of discrete-symbol covert timing channels.
    """
    n = len(samples)
    if n < 6:
        return 0.0
    mean = float(np.mean(samples))
    std = float(np.std(samples, ddof=0))
    if std < 1e-9:
        return 0.0
    z = (samples - mean) / std
    skew = float(np.mean(z ** 3))
    excess_kurt = float(np.mean(z ** 4)) - 3.0
    denom = excess_kurt + (3.0 * ((n - 1) ** 2)) / float((n - 2) * (n - 3))
    if denom <= 1e-9:
        return 0.0
    return float((skew ** 2 + 1.0) / denom)


def two_cluster_separation(samples: np.ndarray) -> Dict[str, float]:
    """
    Partition 1D inter-arrival samples at their midpoint / Otsu split and measure
    how tightly separated the two timing clusters are.

    Returns ``separation_ratio`` (|mu_hi - mu_lo| / pooled_within_std),
    ``balance`` (min_cluster_frac), ``delta_ms`` (|mu_hi - mu_lo|), and
    ``within_std``.
    """
    if len(samples) < 6:
        return {
            "separation_ratio": 0.0,
            "balance": 0.0,
            "delta": 0.0,
            "within_std": 0.0,
            "mu_low": 0.0,
            "mu_high": 0.0,
        }

    # Evaluate candidate thresholds across sorted unique midpoints (exact 1D Otsu)
    sorted_vals = np.sort(samples)
    best_between_var = -1.0
    best_threshold = float(np.median(sorted_vals))
    n = float(len(sorted_vals))

    for idx in range(2, len(sorted_vals) - 2):
        if sorted_vals[idx] == sorted_vals[idx - 1]:
            continue
        low = sorted_vals[:idx]
        high = sorted_vals[idx:]
        w0 = len(low) / n
        w1 = len(high) / n
        between_var = w0 * w1 * ((float(np.mean(high)) - float(np.mean(low))) ** 2)
        if between_var > best_between_var:
            best_between_var = between_var
            best_threshold = 0.5 * float(sorted_vals[idx - 1] + sorted_vals[idx])

    low_cluster = samples[samples <= best_threshold]
    high_cluster = samples[samples > best_threshold]
    if len(low_cluster) < 2 or len(high_cluster) < 2:
        return {
            "separation_ratio": 0.0,
            "balance": 0.0,
            "delta": 0.0,
            "within_std": 0.0,
            "mu_low": 0.0,
            "mu_high": 0.0,
        }

    mu_lo = float(np.mean(low_cluster))
    mu_hi = float(np.mean(high_cluster))
    std_lo = float(np.std(low_cluster, ddof=1))
    std_hi = float(np.std(high_cluster, ddof=1))
    pooled_std = math.sqrt(
        ((len(low_cluster) - 1) * (std_lo ** 2) + (len(high_cluster) - 1) * (std_hi ** 2))
        / float(len(low_cluster) + len(high_cluster) - 2)
    )
    delta = abs(mu_hi - mu_lo)
    sep_ratio = delta / max(pooled_std, 1e-6)
    balance = min(len(low_cluster), len(high_cluster)) / float(len(samples))
    return {
        "separation_ratio": round(sep_ratio, 4),
        "balance": round(balance, 4),
        "delta": round(delta, 6),
        "within_std": round(pooled_std, 6),
        "mu_low": round(mu_lo, 6),
        "mu_high": round(mu_hi, 6),
    }


def _coerce_bytes(raw: Any) -> bytes:
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


def _extract_base_domain(fqdn: str) -> Tuple[str, str]:
    """
    Split an FQDN into ``(subdomain_part, base_domain)``.
    Example: ``"a9f3c1e8.c2.evil.com"`` -> ``("a9f3c1e8.c2", "evil.com")``.
    """
    cleaned = fqdn.strip().rstrip(".").lower()
    parts = [p for p in cleaned.split(".") if p]
    if len(parts) <= 2:
        return "", cleaned
    # Handle common two-level public suffixes like .co.in, .co.uk, .com.au
    if len(parts) >= 3 and parts[-2] in {"co", "com", "org", "net", "gov", "ac"} and len(parts[-1]) == 2:
        base = ".".join(parts[-3:])
        sub = ".".join(parts[:-3])
        return sub, base
    base = ".".join(parts[-2:])
    sub = ".".join(parts[:-2])
    return sub, base


def _parse_ts_seconds(raw_ts: Any) -> float:
    if isinstance(raw_ts, (int, float)):
        return float(raw_ts)
    if isinstance(raw_ts, datetime):
        dt = raw_ts if raw_ts.tzinfo else raw_ts.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    if isinstance(raw_ts, str) and raw_ts:
        try:
            return datetime.fromisoformat(raw_ts.replace("Z", "+00:00")).timestamp()
        except ValueError:
            pass
    return datetime.now(tz=timezone.utc).timestamp()


def _iso_from_seconds(ts_sec: float) -> str:
    return datetime.fromtimestamp(ts_sec, tz=timezone.utc).isoformat()


@dataclass
class CovertChannelFinding:
    """Structured detection record from ``CovertChannelDetector``."""

    finding_id: str
    channel_type: str  # "modbus_polling_timing" | "dns_covert_c2" | "payload_padding_stego" | "register_lsb_stego"
    severity: str      # "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    confidence: float
    src_ip: str
    dst_ip: str
    timestamp: str
    mitre_techniques: List[str]
    indicators: List[str]
    description: str
    metrics: Dict[str, Any] = field(default_factory=dict)
    published: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# 1. Modbus Polling Jitter & Register LSB Timing/Storage Channel Analyzer
# ---------------------------------------------------------------------------


class ModbusPollingJitterAnalyzer:
    """
    Detects covert timing channels embedded in Modbus TCP polling jitter and
    covert storage channels in holding register LSB streams or Transaction IDs.
    """

    def __init__(
        self,
        window_size: int = 40,
        min_intervals: int = 16,
        bimodality_threshold: float = 0.58,
        cluster_separation_threshold: float = 3.5,
        min_cluster_balance: float = 0.20,
        min_jitter_delta_s: float = 0.015,
        lsb_window_size: int = 48,
        lsb_entropy_threshold: float = 0.92,
        lsb_transition_min: float = 0.35,
    ) -> None:
        self.window_size = int(window_size)
        self.min_intervals = int(min_intervals)
        self.bimodality_threshold = float(bimodality_threshold)
        self.cluster_separation_threshold = float(cluster_separation_threshold)
        self.min_cluster_balance = float(min_cluster_balance)
        self.min_jitter_delta_s = float(min_jitter_delta_s)
        self.lsb_window_size = int(lsb_window_size)
        self.lsb_entropy_threshold = float(lsb_entropy_threshold)
        self.lsb_transition_min = float(lsb_transition_min)

        # (src_ip, dst_ip, unit_id, fc) -> deque of timestamps (seconds)
        self._timestamps: Dict[Tuple[str, str, int, int], Deque[float]] = defaultdict(
            lambda: deque(maxlen=self.window_size + 1)
        )
        # (src_ip, dst_ip, unit_id, fc) -> deque of transaction IDs
        self._tx_ids: Dict[Tuple[str, str, int, int], Deque[int]] = defaultdict(
            lambda: deque(maxlen=self.window_size)
        )
        # (plc_ip, register_addr) -> deque of LSB bits (0 or 1)
        self._register_lsbs: Dict[Tuple[str, int], Deque[int]] = defaultdict(
            lambda: deque(maxlen=self.lsb_window_size)
        )
        # (plc_ip, register_addr) -> deque of raw integer register values
        self._register_vals: Dict[Tuple[str, int], Deque[int]] = defaultdict(
            lambda: deque(maxlen=self.lsb_window_size)
        )

    def observe_poll(
        self,
        src_ip: str,
        dst_ip: str,
        timestamp: Any,
        unit_id: int = 1,
        function_code: int = 3,
        transaction_id: Optional[int] = None,
    ) -> Optional[CovertChannelFinding]:
        """Record a Modbus poll event and test the rolling IAT series for covert timing."""
        ts_sec = _parse_ts_seconds(timestamp)
        key = (src_ip, dst_ip, int(unit_id), int(function_code))
        ts_buf = self._timestamps[key]
        ts_buf.append(ts_sec)

        tx_buf = self._tx_ids[key]
        if transaction_id is not None:
            tx_buf.append(int(transaction_id) & 0xFFFF)

        if len(ts_buf) < self.min_intervals + 1:
            return None

        ordered = np.asarray(list(ts_buf), dtype=float)
        intervals = np.diff(ordered)
        intervals = intervals[intervals > 0]
        if len(intervals) < self.min_intervals:
            return None

        bc = sarle_bimodality_coefficient(intervals)
        cluster = two_cluster_separation(intervals)

        # Quantized interval entropy (10ms bins)
        quant_bins = [int(round(iv * 100.0)) for iv in intervals]
        iat_entropy = shannon_entropy_discrete(quant_bins)
        mean_iv = float(np.mean(intervals))
        std_iv = float(np.std(intervals, ddof=1))

        indicators: List[str] = []
        if (
            bc >= self.bimodality_threshold
            and cluster["separation_ratio"] >= self.cluster_separation_threshold
            and cluster["balance"] >= self.min_cluster_balance
            and cluster["delta"] >= self.min_jitter_delta_s
        ):
            indicators.append("bimodal_polling_jitter_modulation")

        # Check Transaction ID non-sequential high-entropy covert signaling
        tx_non_seq_ratio = 0.0
        tx_byte_entropy = 0.0
        if len(tx_buf) >= self.min_intervals:
            tx_list = list(tx_buf)
            deltas = [(tx_list[i] - tx_list[i - 1]) & 0xFFFF for i in range(1, len(tx_list))]
            non_seq = sum(1 for d in deltas if d not in (0, 1))
            tx_non_seq_ratio = non_seq / float(len(deltas))
            raw_tx_bytes = b"".join(t.to_bytes(2, "big") for t in tx_list)
            tx_byte_entropy = shannon_entropy_bytes(raw_tx_bytes)
            if tx_non_seq_ratio >= 0.85 and tx_byte_entropy >= 4.8:
                indicators.append("high_entropy_transaction_id_channel")

        if not indicators:
            return None

        confidence = min(
            0.98,
            0.70
            + (0.15 if "bimodal_polling_jitter_modulation" in indicators else 0.0)
            + (0.10 if "high_entropy_transaction_id_channel" in indicators else 0.0)
            + min(0.08, max(0.0, (cluster["separation_ratio"] - 3.5) * 0.02)),
        )
        severity = "CRITICAL" if len(indicators) >= 2 else "HIGH"

        return CovertChannelFinding(
            finding_id=str(uuid.uuid4()),
            channel_type="modbus_polling_timing",
            severity=severity,
            confidence=round(confidence, 4),
            src_ip=src_ip,
            dst_ip=dst_ip,
            timestamp=_iso_from_seconds(ts_sec),
            mitre_techniques=["T0869", "T0885", "T1001.002"],
            indicators=indicators,
            description=(
                f"Covert timing/signaling channel detected on Modbus polling loop "
                f"{src_ip} -> {dst_ip} (FC={function_code}, unit={unit_id}): "
                f"BC={bc:.3f}, cluster_sep={cluster['separation_ratio']:.2f}, "
                f"delta={cluster['delta']*1000:.1f}ms"
            ),
            metrics={
                "unit_id": int(unit_id),
                "function_code": int(function_code),
                "sample_intervals": int(len(intervals)),
                "mean_interval_s": round(mean_iv, 4),
                "std_interval_s": round(std_iv, 4),
                "bimodality_coefficient": round(bc, 4),
                "cluster_separation": cluster,
                "quantized_iat_entropy": round(iat_entropy, 4),
                "tx_non_sequential_ratio": round(tx_non_seq_ratio, 4),
                "tx_byte_entropy": round(tx_byte_entropy, 4),
            },
        )

    def observe_register_lsb(
        self,
        plc_ip: str,
        register_addr: int,
        raw_int_value: int,
        src_ip: str = "",
        timestamp: Any = None,
    ) -> Optional[CovertChannelFinding]:
        """
        Detect covert data modulated into the Least Significant Bit (LSB) of a
        holding register while keeping higher-order bits virtually constant
        (so physical setpoint / telemetry looks unchanged).
        """
        key = (plc_ip, int(register_addr))
        ival = int(raw_int_value)
        lsbs = self._register_lsbs[key]
        vals = self._register_vals[key]
        lsbs.append(ival & 1)
        vals.append(ival)

        if len(lsbs) < self.lsb_window_size:
            return None

        bit_list = list(lsbs)
        val_list = list(vals)
        msb_list = [v >> 1 for v in val_list]
        msb_unique_ratio = len(set(msb_list)) / float(len(msb_list))

        lsb_entropy = shannon_entropy_discrete(bit_list)
        transitions = sum(1 for i in range(1, len(bit_list)) if bit_list[i] != bit_list[i - 1])
        transition_rate = transitions / float(len(bit_list) - 1)

        # Covert LSB steganography on a steady setpoint register:
        # Upper bits stay nearly static (msb_unique_ratio <= 0.15), while LSB flips
        # with near-maximal entropy (>= 0.92 bits) and high transition rate.
        if (
            msb_unique_ratio <= 0.15
            and lsb_entropy >= self.lsb_entropy_threshold
            and self.lsb_transition_min <= transition_rate <= 0.85
        ):
            ts_sec = _parse_ts_seconds(timestamp)
            return CovertChannelFinding(
                finding_id=str(uuid.uuid4()),
                channel_type="register_lsb_stego",
                severity="HIGH",
                confidence=round(min(0.95, 0.72 + (lsb_entropy - 0.9) * 2.0), 4),
                src_ip=src_ip or plc_ip,
                dst_ip=plc_ip,
                timestamp=_iso_from_seconds(ts_sec),
                mitre_techniques=["T0869", "T1001.002", "T1020"],
                indicators=["register_lsb_steganography"],
                description=(
                    f"LSB steganography detected on PLC {plc_ip} register {register_addr}: "
                    f"upper bits stable (unique_ratio={msb_unique_ratio:.2f}) while LSB "
                    f"entropy={lsb_entropy:.3f}, transition_rate={transition_rate:.2f}"
                ),
                metrics={
                    "register_addr": int(register_addr),
                    "window_size": len(bit_list),
                    "msb_unique_ratio": round(msb_unique_ratio, 4),
                    "lsb_entropy": round(lsb_entropy, 4),
                    "lsb_transition_rate": round(transition_rate, 4),
                    "ones_ratio": round(sum(bit_list) / float(len(bit_list)), 4),
                },
            )
        return None


# ---------------------------------------------------------------------------
# 2. DNS Query Length Entropy & TXT Covert C2 Analyzer
# ---------------------------------------------------------------------------


@dataclass
class _DNSWindowState:
    subdomains: Deque[str] = field(default_factory=lambda: deque(maxlen=60))
    query_lengths: Deque[int] = field(default_factory=lambda: deque(maxlen=60))
    record_types: Deque[str] = field(default_factory=lambda: deque(maxlen=60))
    label_entropies: Deque[float] = field(default_factory=lambda: deque(maxlen=60))
    txt_entropies: Deque[float] = field(default_factory=lambda: deque(maxlen=60))
    timestamps: Deque[float] = field(default_factory=lambda: deque(maxlen=60))


class DNSCovertChannelAnalyzer:
    """
    Detects low-frequency DNS tunneling and TXT-record C2 channels via
    label Shannon entropy, query length distribution entropy, unique FQDN ratio,
    and TXT/NULL payload analysis.
    """

    def __init__(
        self,
        min_queries: int = 8,
        subdomain_entropy_threshold: float = 3.7,
        mean_subdomain_len_threshold: float = 28.0,
        length_entropy_threshold: float = 2.0,
        unique_ratio_threshold: float = 0.80,
        covert_qtype_ratio_threshold: float = 0.40,
        txt_response_entropy_threshold: float = 4.2,
        min_signals: int = 2,
    ) -> None:
        self.min_queries = int(min_queries)
        self.subdomain_entropy_threshold = float(subdomain_entropy_threshold)
        self.mean_subdomain_len_threshold = float(mean_subdomain_len_threshold)
        self.length_entropy_threshold = float(length_entropy_threshold)
        self.unique_ratio_threshold = float(unique_ratio_threshold)
        self.covert_qtype_ratio_threshold = float(covert_qtype_ratio_threshold)
        self.txt_response_entropy_threshold = float(txt_response_entropy_threshold)
        self.min_signals = int(min_signals)

        self._windows: Dict[Tuple[str, str], _DNSWindowState] = defaultdict(_DNSWindowState)

    def analyze_query(self, record: Dict[str, Any]) -> Optional[CovertChannelFinding]:
        """
        Analyze a DNS query/response telemetry record.

        Expected keys:
        - ``src_ip``, ``dst_ip`` (optional DNS server IP), ``timestamp``
        - ``query_name`` (FQDN)
        - ``query_type`` (e.g. ``"A"``, ``"AAAA"``, ``"TXT"``, ``"NULL"``, ``"CNAME"``)
        - ``response_txt`` (optional string/list of TXT response payload)
        """
        src_ip = str(record.get("src_ip") or record.get("source_ip") or "")
        dst_ip = str(record.get("dst_ip") or record.get("destination_ip") or "")
        qname = str(record.get("query_name") or record.get("qname") or "").strip().lower()
        qtype = str(record.get("query_type") or record.get("qtype") or "A").upper()
        ts_sec = _parse_ts_seconds(record.get("timestamp"))

        if not qname:
            return None

        subdomain, base_domain = _extract_base_domain(qname)
        state = self._windows[(src_ip, base_domain)]

        sub_clean = subdomain.replace(".", "")
        sub_entropy = shannon_entropy_string(sub_clean) if sub_clean else 0.0

        state.subdomains.append(subdomain)
        state.query_lengths.append(len(qname))
        state.record_types.append(qtype)
        state.label_entropies.append(sub_entropy)
        state.timestamps.append(ts_sec)

        raw_txt = record.get("response_txt")
        if raw_txt:
            txt_str = " ".join(raw_txt) if isinstance(raw_txt, list) else str(raw_txt)
            state.txt_entropies.append(shannon_entropy_string(txt_str))

        n = len(state.subdomains)
        if n < self.min_queries:
            return None

        mean_sub_entropy = float(np.mean(list(state.label_entropies)))
        mean_sub_len = float(np.mean([len(s) for s in state.subdomains]))
        # Bin query lengths into 2-char buckets for distribution entropy
        len_entropy = shannon_entropy_discrete([l // 2 for l in state.query_lengths])
        non_empty_subs = [s for s in state.subdomains if s]
        unique_ratio = (
            len(set(non_empty_subs)) / float(len(non_empty_subs))
            if non_empty_subs
            else 0.0
        )
        covert_qtype_ratio = sum(
            1 for qt in state.record_types if qt in COVERT_DNS_RECORD_TYPES
        ) / float(n)
        mean_txt_entropy = (
            float(np.mean(list(state.txt_entropies))) if state.txt_entropies else 0.0
        )

        indicators: List[str] = []
        if mean_sub_entropy >= self.subdomain_entropy_threshold and mean_sub_len >= 12.0:
            indicators.append("high_subdomain_shannon_entropy")
        if mean_sub_len >= self.mean_subdomain_len_threshold:
            indicators.append("excessive_subdomain_length")
        if len_entropy >= self.length_entropy_threshold and unique_ratio >= self.unique_ratio_threshold:
            indicators.append("high_query_length_entropy_and_uniqueness")
        if covert_qtype_ratio >= self.covert_qtype_ratio_threshold:
            indicators.append("elevated_txt_null_record_ratio")
        if state.txt_entropies and mean_txt_entropy >= self.txt_response_entropy_threshold:
            indicators.append("high_entropy_dns_txt_response")

        if len(indicators) < self.min_signals:
            return None

        # Check periodic low-frequency beaconing bonus
        beacon_cv = None
        if len(state.timestamps) >= self.min_queries:
            ivs = np.diff(np.sort(np.asarray(list(state.timestamps), dtype=float)))
            ivs = ivs[ivs > 0]
            if len(ivs) >= 5 and float(np.mean(ivs)) > 0:
                beacon_cv = float(np.std(ivs) / np.mean(ivs))
                if beacon_cv < 0.15:
                    indicators.append("periodic_dns_beacon_cadence")

        severity = "CRITICAL" if len(indicators) >= 3 else "HIGH"
        confidence = min(0.98, 0.65 + 0.08 * len(indicators))

        return CovertChannelFinding(
            finding_id=str(uuid.uuid4()),
            channel_type="dns_covert_c2",
            severity=severity,
            confidence=round(confidence, 4),
            src_ip=src_ip,
            dst_ip=dst_ip,
            timestamp=_iso_from_seconds(ts_sec),
            mitre_techniques=["T1071.004", "T1048.003", "T0869"],
            indicators=indicators,
            description=(
                f"DNS covert C2/tunneling suspected from {src_ip} to base domain "
                f"'{base_domain}' ({len(indicators)} signals: {', '.join(indicators)})"
            ),
            metrics={
                "base_domain": base_domain,
                "queries_evaluated": n,
                "mean_subdomain_entropy": round(mean_sub_entropy, 4),
                "mean_subdomain_len": round(mean_sub_len, 2),
                "query_length_entropy": round(len_entropy, 4),
                "unique_subdomain_ratio": round(unique_ratio, 4),
                "covert_qtype_ratio": round(covert_qtype_ratio, 4),
                "mean_txt_response_entropy": round(mean_txt_entropy, 4),
                "beacon_cv": round(beacon_cv, 4) if beacon_cv is not None else None,
            },
        )


# ---------------------------------------------------------------------------
# 3. Payload Padding & Slack-Space Steganography Analyzer
# ---------------------------------------------------------------------------


class PayloadPaddingSteganographyAnalyzer:
    """
    Detects data hidden inside protocol/frame padding or trailing slack bytes
    (e.g., non-zero Ethernet trailer padding, Modbus TCP bytes past declared
    MBAP length, or cumulative cross-packet tiny slack-space leakage).
    """

    def __init__(
        self,
        single_frame_min_nonzero: int = 4,
        entropy_threshold: float = 3.8,
        cumulative_buffer_limit: int = 256,
        cumulative_trigger_bytes: int = 16,
    ) -> None:
        self.single_frame_min_nonzero = int(single_frame_min_nonzero)
        self.entropy_threshold = float(entropy_threshold)
        self.cumulative_buffer_limit = int(cumulative_buffer_limit)
        self.cumulative_trigger_bytes = int(cumulative_trigger_bytes)

        # (src_ip, dst_ip, protocol) -> accumulated non-zero padding bytes across frames
        self._slack_buffers: Dict[Tuple[str, str, str], bytearray] = defaultdict(bytearray)
        self._slack_packet_counts: Dict[Tuple[str, str, str], int] = defaultdict(int)

    def analyze_frame(self, frame: Dict[str, Any]) -> Optional[CovertChannelFinding]:
        """
        Inspect a frame/packet for padding steganography.

        Accepts either explicit ``padding_bytes`` / ``padding_hex`` OR
        ``actual_payload`` (bytes/hex) + ``declared_length`` (int), from which
        trailing slack bytes ``actual_payload[declared_length:]`` are extracted.
        """
        src_ip = str(frame.get("src_ip") or frame.get("source_ip") or "")
        dst_ip = str(frame.get("dst_ip") or frame.get("destination_ip") or "")
        protocol = str(frame.get("protocol") or "MODBUS").upper()
        ts_sec = _parse_ts_seconds(frame.get("timestamp"))

        padding = _coerce_bytes(
            frame.get("padding_bytes")
            if frame.get("padding_bytes") is not None
            else frame.get("padding_hex")
        )
        if not padding and frame.get("actual_payload") is not None and frame.get("declared_length") is not None:
            actual = _coerce_bytes(frame.get("actual_payload"))
            declared = int(frame["declared_length"])
            if len(actual) > declared >= 0:
                padding = actual[declared:]

        if not padding:
            return None

        nonzero_bytes = bytes(b for b in padding if b != 0)
        if not nonzero_bytes:
            return None

        nonzero_ratio = len(nonzero_bytes) / float(len(padding))
        frame_entropy = shannon_entropy_bytes(padding)
        printable_ratio = sum(1 for b in nonzero_bytes if 32 <= b <= 126) / float(len(nonzero_bytes))

        # Accumulate cross-packet slack buffer per (src, dst, proto)
        key = (src_ip, dst_ip, protocol)
        buf = self._slack_buffers[key]
        buf.extend(nonzero_bytes)
        if len(buf) > self.cumulative_buffer_limit:
            del buf[: len(buf) - self.cumulative_buffer_limit]
        self._slack_packet_counts[key] += 1

        indicators: List[str] = []
        if len(nonzero_bytes) >= self.single_frame_min_nonzero:
            indicators.append("nonzero_protocol_padding")
        if len(padding) >= 8 and frame_entropy >= self.entropy_threshold:
            indicators.append("high_entropy_padding_payload")
        if len(nonzero_bytes) >= 6 and printable_ratio >= 0.85:
            indicators.append("printable_ascii_in_padding")

        cum_entropy = shannon_entropy_bytes(bytes(buf))
        if (
            len(buf) >= self.cumulative_trigger_bytes
            and self._slack_packet_counts[key] >= 3
        ):
            indicators.append("cumulative_cross_packet_slack_leakage")

        if not indicators:
            return None

        severity = "HIGH" if (
            "high_entropy_padding_payload" in indicators
            or "cumulative_cross_packet_slack_leakage" in indicators
            or "printable_ascii_in_padding" in indicators
        ) else "MEDIUM"
        confidence = min(0.96, 0.68 + 0.08 * len(indicators))

        return CovertChannelFinding(
            finding_id=str(uuid.uuid4()),
            channel_type="payload_padding_stego",
            severity=severity,
            confidence=round(confidence, 4),
            src_ip=src_ip,
            dst_ip=dst_ip,
            timestamp=_iso_from_seconds(ts_sec),
            mitre_techniques=["T1001.002", "T0869", "T1020"],
            indicators=indicators,
            description=(
                f"Non-zero padding steganography in {protocol} traffic {src_ip} -> {dst_ip}: "
                f"{len(nonzero_bytes)}/{len(padding)}B non-zero (entropy={frame_entropy:.2f}, "
                f"cumulative={len(buf)}B across {self._slack_packet_counts[key]} frames)"
            ),
            metrics={
                "protocol": protocol,
                "padding_len": len(padding),
                "nonzero_len": len(nonzero_bytes),
                "nonzero_ratio": round(nonzero_ratio, 4),
                "frame_padding_entropy": round(frame_entropy, 4),
                "printable_ascii_ratio": round(printable_ratio, 4),
                "cumulative_nonzero_bytes": len(buf),
                "cumulative_entropy": round(cum_entropy, 4),
                "slack_frames_seen": self._slack_packet_counts[key],
            },
        )


# ---------------------------------------------------------------------------
# Unified Covert Channel Detector Facade
# ---------------------------------------------------------------------------


class CovertChannelDetector:
    """
    Unified VaultX Phase 3 covert channel detection suite combining:
    - ``ModbusPollingJitterAnalyzer``
    - ``DNSCovertChannelAnalyzer``
    - ``PayloadPaddingSteganographyAnalyzer``

    Publishes findings to Redis stream ``detections:covert_channel`` when configured.
    """

    def __init__(
        self,
        redis_client: Any = None,
        modbus_jitter_analyzer: Optional[ModbusPollingJitterAnalyzer] = None,
        dns_analyzer: Optional[DNSCovertChannelAnalyzer] = None,
        padding_analyzer: Optional[PayloadPaddingSteganographyAnalyzer] = None,
        stream_name: str = REDIS_STREAM_COVERT_CHANNEL,
    ) -> None:
        self._redis = redis_client
        self._stream = stream_name
        self.modbus_jitter = modbus_jitter_analyzer or ModbusPollingJitterAnalyzer()
        self.dns_analyzer = dns_analyzer or DNSCovertChannelAnalyzer()
        self.padding_analyzer = padding_analyzer or PayloadPaddingSteganographyAnalyzer()
        self._counts: Dict[str, int] = defaultdict(int)

    def analyze_modbus_timing(
        self,
        src_ip: str,
        dst_ip: str,
        timestamp: Any,
        unit_id: int = 1,
        function_code: int = 3,
        transaction_id: Optional[int] = None,
        publish: bool = True,
    ) -> Optional[CovertChannelFinding]:
        finding = self.modbus_jitter.observe_poll(
            src_ip=src_ip,
            dst_ip=dst_ip,
            timestamp=timestamp,
            unit_id=unit_id,
            function_code=function_code,
            transaction_id=transaction_id,
        )
        return self._finalize(finding, publish=publish)

    def analyze_register_lsb(
        self,
        plc_ip: str,
        register_addr: int,
        raw_int_value: int,
        src_ip: str = "",
        timestamp: Any = None,
        publish: bool = True,
    ) -> Optional[CovertChannelFinding]:
        finding = self.modbus_jitter.observe_register_lsb(
            plc_ip=plc_ip,
            register_addr=register_addr,
            raw_int_value=raw_int_value,
            src_ip=src_ip,
            timestamp=timestamp,
        )
        return self._finalize(finding, publish=publish)

    def analyze_dns_query(
        self, record: Dict[str, Any], publish: bool = True
    ) -> Optional[CovertChannelFinding]:
        finding = self.dns_analyzer.analyze_query(record)
        return self._finalize(finding, publish=publish)

    def analyze_payload_padding(
        self, frame: Dict[str, Any], publish: bool = True
    ) -> Optional[CovertChannelFinding]:
        finding = self.padding_analyzer.analyze_frame(frame)
        return self._finalize(finding, publish=publish)

    def analyze_event(
        self, event: Dict[str, Any], publish: bool = True
    ) -> Optional[CovertChannelFinding]:
        """Dispatch events by ``event_type``: ``modbus_poll``, ``register_lsb``, ``dns_query``, ``frame_padding``."""
        etype = str(event.get("event_type", "")).lower()
        if etype == "modbus_poll":
            return self.analyze_modbus_timing(
                src_ip=str(event.get("src_ip") or ""),
                dst_ip=str(event.get("dst_ip") or ""),
                timestamp=event.get("timestamp"),
                unit_id=int(event.get("unit_id", 1)),
                function_code=int(event.get("function_code", 3)),
                transaction_id=event.get("transaction_id"),
                publish=publish,
            )
        if etype == "register_lsb":
            return self.analyze_register_lsb(
                plc_ip=str(event.get("plc_ip") or event.get("dst_ip") or ""),
                register_addr=int(event["register_addr"]),
                raw_int_value=int(event["raw_int_value"]),
                src_ip=str(event.get("src_ip") or ""),
                timestamp=event.get("timestamp"),
                publish=publish,
            )
        if etype == "dns_query":
            return self.analyze_dns_query(event, publish=publish)
        if etype == "frame_padding":
            return self.analyze_payload_padding(event, publish=publish)
        return None

    def get_metrics(self) -> Dict[str, int]:
        return dict(self._counts)

    def _finalize(
        self, finding: Optional[CovertChannelFinding], publish: bool = True
    ) -> Optional[CovertChannelFinding]:
        if finding is None:
            return None
        self._counts[finding.channel_type] += 1
        if publish and self._redis is not None:
            finding.published = self._publish(finding)
        return finding

    def _publish(self, finding: CovertChannelFinding) -> bool:
        try:
            self._redis.xadd(
                self._stream,
                {
                    "finding_id": finding.finding_id,
                    "channel_type": finding.channel_type,
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
            logger.error("Failed publishing covert channel finding to Redis: %s", exc)
            return False

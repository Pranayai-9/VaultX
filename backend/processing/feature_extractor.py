"""
VaultX NIDS - ML Feature Extractor
Bharat Electronics Components Pvt. Ltd. (BECPL), Pune

Accepts completed FlowRecord objects from FlowAggregator and extracts:
  1. CIC-IDS2017-compatible flow features
  2. BECPL manufacturing & VLAN-aware contextual features
  3. Always-available encrypted-traffic timing/volume features
  4. Optional TLS metadata features when encryption telemetry is present
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

from backend.ingestion.models import FlowRecord

# IANA protocol numbers
PROTOCOL_NUMBERS: Dict[str, int] = {
    "ICMP": 1,
    "IGMP": 2,
    "TCP": 6,
    "UDP": 17,
    "GRE": 47,
    "ESP": 50,
    "ICMPV6": 58,
    "SCTP": 132,
    # Application / industrial protocols carried over TCP/UDP
    "HTTP": 6,
    "HTTPS": 6,
    "TLS": 6,
    "SSH": 6,
    "RDP": 6,
    "SMB": 6,
    "MODBUS": 6,
    "S7COMM": 6,
    "OPCUA": 6,
    "DNS": 17,
    "SNMP": 17,
    "NTP": 17,
}

CRITICALITY_SCORES: Dict[str, float] = {
    "critical": 4.0,
    "high": 3.0,
    "medium": 2.0,
    "low": 1.0,
}

TLS_VERSION_NUMBERS: Dict[str, float] = {
    "sslv2": 0.2,
    "sslv3": 0.3,
    "tlsv1": 1.0,
    "tlsv1.0": 1.0,
    "tls 1.0": 1.0,
    "tlsv10": 1.0,
    "tlsv1.1": 1.1,
    "tls 1.1": 1.1,
    "tlsv11": 1.1,
    "tlsv1.2": 1.2,
    "tls 1.2": 1.2,
    "tlsv12": 1.2,
    "tlsv1.3": 1.3,
    "tls 1.3": 1.3,
    "tlsv13": 1.3,
}

# Ordered numeric feature schema for ML model input vectors
NUMERIC_FEATURE_NAMES: List[str] = [
    # CIC-IDS2017 core features (15)
    "duration",
    "protocol_num",
    "fwd_packets",
    "bwd_packets",
    "fwd_bytes",
    "bwd_bytes",
    "flow_bytes_per_sec",
    "flow_packets_per_sec",
    "fwd_iat_mean",
    "bwd_iat_mean",
    "psh_flag_count",
    "ack_flag_count",
    "down_up_ratio",
    "pkt_len_mean",
    "pkt_len_std",
    # BECPL manufacturing-aware features (8)
    "source_vlan",
    "dest_vlan",
    "is_cross_vlan",
    "source_criticality_score",
    "dest_criticality_score",
    "is_vendor_connection",
    "is_ot_destination",
    "is_external_dest",
    # Always-available encrypted-traffic flow features (7)
    "flow_duration_sec",
    "bytes_up",
    "bytes_down",
    "ratio_up_down",
    "num_packets",
    "inter_packet_interval_mean",
    "inter_packet_interval_std",
    # TLS numeric features (3)
    "tls_version_num",
    "has_sni",
    "cert_issuer_known",
]


class FeatureExtractor:
    """
    Extracts ML-ready feature dictionaries and numeric vectors from FlowRecord objects.
    """

    def extract(self, flow: FlowRecord) -> Dict[str, Any]:
        """
        Extract full feature dictionary from a completed FlowRecord.

        Includes:
        - CIC-IDS2017-compatible flow features
        - BECPL-specific VLAN, criticality, OT, vendor, and external context features
        - Always-available encrypted traffic statistical features
        - TLS metadata features (populated when TLS metadata is available)
        """
        duration_sec = max(0.0, float(flow.duration_ms) / 1000.0)
        protocol_num = self._protocol_to_num(flow.protocol)

        fwd_bytes = max(0, int(flow.fwd_bytes))
        bwd_bytes = max(0, int(flow.bwd_bytes))
        fwd_packets = max(0, int(flow.fwd_packets))
        bwd_packets = max(0, int(flow.bwd_packets))
        num_packets = fwd_packets + bwd_packets

        ratio_up_down = (
            round(fwd_bytes / bwd_bytes, 6)
            if bwd_bytes > 0
            else (float(fwd_bytes) if fwd_bytes > 0 else 0.0)
        )
        down_up_ratio = (
            round(bwd_bytes / fwd_bytes, 6)
            if fwd_bytes > 0
            else 0.0
        )

        features: Dict[str, Any] = {
            # --- CIC-IDS2017 compatible features ---
            "duration": round(duration_sec, 6),
            "protocol_num": protocol_num,
            "fwd_packets": fwd_packets,
            "bwd_packets": bwd_packets,
            "fwd_bytes": fwd_bytes,
            "bwd_bytes": bwd_bytes,
            "flow_bytes_per_sec": max(0.0, float(flow.flow_bytes_per_sec)),
            "flow_packets_per_sec": max(0.0, float(flow.flow_packets_per_sec)),
            "fwd_iat_mean": max(0.0, float(flow.fwd_iat_mean)),
            "bwd_iat_mean": max(0.0, float(flow.bwd_iat_mean)),
            "psh_flag_count": max(0, int(flow.psh_flag_count)),
            "ack_flag_count": max(0, int(flow.ack_flag_count)),
            "down_up_ratio": down_up_ratio,
            "pkt_len_mean": max(0.0, float(flow.pkt_len_mean)),
            "pkt_len_std": max(0.0, float(flow.pkt_len_std)),

            # --- BECPL-specific features ---
            "source_vlan": int(flow.source_vlan) if flow.source_vlan is not None else 0,
            "dest_vlan": int(flow.dest_vlan) if flow.dest_vlan is not None else 0,
            "is_cross_vlan": 1 if flow.is_cross_vlan else 0,
            "source_criticality_score": self._criticality_score(flow.source_criticality),
            "dest_criticality_score": self._criticality_score(flow.dest_criticality),
            "is_vendor_connection": 1 if flow.is_vendor_connection else 0,
            "is_ot_destination": 1 if flow.is_ot_destination else 0,
            "is_external_dest": 1 if flow.is_external_dest else 0,

            # --- Encrypted traffic features (always available) ---
            "flow_duration_sec": round(duration_sec, 6),
            "bytes_up": fwd_bytes,
            "bytes_down": bwd_bytes,
            "ratio_up_down": ratio_up_down,
            "num_packets": num_packets,
            "inter_packet_interval_mean": max(0.0, float(flow.inter_packet_interval_mean)),
            "inter_packet_interval_std": max(0.0, float(flow.inter_packet_interval_std)),
        }

        # --- Encrypted traffic features (TLS metadata when available) ---
        has_tls = any([
            flow.tls_version,
            flow.sni,
            flow.ja3_hash,
            flow.ja3s_hash,
            flow.cert_issuer_known is not None,
        ])
        if has_tls:
            features.update({
                "tls_version_num": self._tls_version_to_num(flow.tls_version),
                "has_sni": 1 if flow.sni else 0,
                "cert_issuer_known": 1 if flow.cert_issuer_known else 0,
                "ja3_hash": flow.ja3_hash,
                "ja3s_hash": flow.ja3s_hash,
            })

        return features

    def extract_vector(self, flow: FlowRecord) -> Tuple[List[str], List[float]]:
        """
        Return an ordered numeric feature vector matching ``NUMERIC_FEATURE_NAMES``
        ready for scikit-learn / XGBoost / PyTorch model inference.
        """
        feat_dict = self.extract(flow)
        vector = [float(feat_dict.get(name, 0.0) or 0.0) for name in NUMERIC_FEATURE_NAMES]
        return list(NUMERIC_FEATURE_NAMES), vector

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _protocol_to_num(protocol: str) -> int:
        if not protocol:
            return 0
        key = str(protocol).strip().upper()
        if key.isdigit():
            return int(key)
        return PROTOCOL_NUMBERS.get(key, 0)

    @staticmethod
    def _criticality_score(criticality: str | None) -> float:
        if not criticality:
            return 0.0
        return CRITICALITY_SCORES.get(str(criticality).strip().lower(), 0.0)

    @staticmethod
    def _tls_version_to_num(tls_version: str | None) -> float:
        if not tls_version:
            return 0.0
        key = str(tls_version).strip().lower()
        return TLS_VERSION_NUMBERS.get(key, 0.0)

"""
VaultX Phase 2 - Threat Intelligence Package
BECPL (Bharat Electronics Components Pvt. Ltd.), Pune

Exports:
- ThreatIntelFeedManager, ThreatIndicator
- VulnerabilityEngine, SoftwareItem, VulnerabilityFinding
- ExploitationCorrelator, ExploitationStage, ExploitationFinding
- SupplyChainMonitor, VendorProfile, VendorAnomalyIndicator
"""

from .threat_intel_feeds import ThreatIndicator, ThreatIntelFeedManager
from .vulnerability_engine import (
    SoftwareItem,
    VulnerabilityEngine,
    VulnerabilityFinding,
)
from .exploitation_correlator import (
    ExploitationCorrelator,
    ExploitationFinding,
    ExploitationStage,
)
from .supply_chain_monitor import (
    SupplyChainMonitor,
    VendorAnomalyIndicator,
    VendorProfile,
)

__all__ = [
    "ThreatIndicator",
    "ThreatIntelFeedManager",
    "SoftwareItem",
    "VulnerabilityFinding",
    "VulnerabilityEngine",
    "ExploitationStage",
    "ExploitationFinding",
    "ExploitationCorrelator",
    "VendorProfile",
    "VendorAnomalyIndicator",
    "SupplyChainMonitor",
]

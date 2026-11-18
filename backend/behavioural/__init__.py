"""
VaultX Behavioural Intelligence Package (Phase 2).

Provides asset/identity baselining, multi-signal deviation detection with
false-positive suppression, and Living-off-the-Land (LOTL) endpoint+network
correlation for BECPL's manufacturing-aware hybrid NIDS.
"""

from backend.behavioural.baseline_engine import (
    AssetBaseline,
    BaselineEngine,
    IdentityBaseline,
    MaintenanceWindow,
)
from backend.behavioural.deviation_detector import (
    DeviationDetector,
    DeviationResult,
    DeviationSignal,
)
from backend.behavioural.lotl_detector import (
    LotlDetector,
    LotlIndicator,
    LotlPatternMatch,
)

__all__ = [
    "AssetBaseline",
    "BaselineEngine",
    "IdentityBaseline",
    "MaintenanceWindow",
    "DeviationDetector",
    "DeviationResult",
    "DeviationSignal",
    "LotlDetector",
    "LotlIndicator",
    "LotlPatternMatch",
]

"""
containment_config.py — Configuration and safety invariants for VaultX Phase 2
Containment & Response Engine.

BECPL (Bharat Electronics Components Pvt. Ltd.), Pune — Manufacturing-Aware Hybrid NIDS.

Safety Invariants
-----------------
1. ``DEFAULT_MODE`` is hardcoded to ``HUMAN_APPROVAL_REQUIRED`` (MODE 3).
2. ``OT_ALWAYS_HUMAN_APPROVAL`` is permanently ``True`` and CANNOT be disabled
   programmatically. Any containment action targeting VLAN 30 (Manufacturing OT)
   or an asset carrying ``ot_safety_flag=True`` ALWAYS requires human approval
   (minimum MODE 3), even if MODE 4 (PRE_APPROVED_AUTOMATION) is active for IT.
3. Critical OT containment enforces the two-person rule
   (``SECURITY_MANAGER`` + a distinct second ``APPROVER``).
"""

from __future__ import annotations

import hashlib
import hmac
import os
from enum import Enum, IntEnum
from typing import Any, Final


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class SafetyInvariantViolationError(RuntimeError):
    """Raised when code attempts to violate an immutable containment safety invariant."""


# ---------------------------------------------------------------------------
# Core Enums
# ---------------------------------------------------------------------------


class ContainmentMode(IntEnum):
    """Four containment operating modes supported by VaultX."""

    DISABLED = 1
    MONITOR_ONLY = 2
    HUMAN_APPROVAL_REQUIRED = 3
    PRE_APPROVED_AUTOMATION = 4

    @classmethod
    def from_name(cls, value: str | int | ContainmentMode) -> ContainmentMode:
        if isinstance(value, cls):
            return value
        if isinstance(value, int):
            return cls(value)
        normalised = value.strip().upper()
        # Support "MODE_3" / "MODE 3" aliases
        if normalised.startswith("MODE"):
            digits = "".join(ch for ch in normalised if ch.isdigit())
            if digits:
                return cls(int(digits))
        try:
            return cls[normalised]
        except KeyError as exc:
            raise ValueError(f"Unknown containment mode: {value!r}") from exc


class ActionCategory(str, Enum):
    """Five supported VaultX containment action categories."""

    ENDPOINT_QUARANTINE = "ENDPOINT_QUARANTINE"
    IDENTITY_CONTAINMENT = "IDENTITY_CONTAINMENT"
    NETWORK_CONTAINMENT = "NETWORK_CONTAINMENT"
    THIRD_PARTY_CONTAINMENT = "THIRD_PARTY_CONTAINMENT"
    OT_BOUNDARY_RESTRICTION = "OT_BOUNDARY_RESTRICTION"


class ActionStatus(str, Enum):
    """Lifecycle states of a containment action in ``response_actions``."""

    RECOMMENDED = "recommended"
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    EXPIRED = "expired"


class Role(str, Enum):
    """RBAC roles for the VaultX Containment & Approval Engine."""

    ANALYST = "ANALYST"                    # Read-only
    OPERATOR = "OPERATOR"                  # Can propose containment actions
    APPROVER = "APPROVER"                  # Can approve tier-1 non-critical actions
    SECURITY_MANAGER = "SECURITY_MANAGER"  # Can approve any action & promote ML models
    ADMIN = "ADMIN"                        # Can change system configuration


class ApprovalMethod(str, Enum):
    """Recorded approval method in ``response_actions.approval_method``."""

    MFA_TOKEN = "mfa_token"
    MANAGER_APPROVAL = "manager_approval"
    BREAK_GLASS = "break_glass"
    AUTO_POLICY = "auto_policy"
    SELF_SERVICE = "self_service"


# ---------------------------------------------------------------------------
# BECPL Network Topology Constants (7 VLANs)
# ---------------------------------------------------------------------------

OT_VLAN_ID: Final[int] = 30
SECURITY_VLAN_ID: Final[int] = 70
QUARANTINE_VLAN_ID: Final[int] = 999

VLAN_MAP: Final[dict[int, dict[str, str]]] = {
    10: {"name": "Corporate IT", "cidr": "10.10.10.0/24"},
    20: {"name": "Engineering", "cidr": "10.10.20.0/24"},
    30: {"name": "OT", "cidr": "10.10.30.0/24"},
    40: {"name": "Warehouse", "cidr": "10.10.40.0/24"},
    50: {"name": "DMZ", "cidr": "10.10.50.0/24"},
    60: {"name": "Cloud", "cidr": "10.10.60.0/24"},
    70: {"name": "Security", "cidr": "10.10.70.0/24"},
}

VLAN_NAMES: Final[dict[int, str]] = {
    vlan_id: meta["name"] for vlan_id, meta in VLAN_MAP.items()
}

# Industrial device types that automatically trigger the OT safety override
OT_DEVICE_TYPES: Final[frozenset[str]] = frozenset(
    {"plc", "hmi", "scada", "rtu", "dcs", "cnc", "smt_machine", "industrial_controller"}
)

# ---------------------------------------------------------------------------
# Containment Configuration Constants
# ---------------------------------------------------------------------------

# Hardcoded default containment mode: MODE 3 (HUMAN_APPROVAL_REQUIRED).
# May only be changed at runtime by an authenticated ADMIN.
DEFAULT_MODE: Final[str] = "HUMAN_APPROVAL_REQUIRED"
DEFAULT_MODE_ENUM: Final[ContainmentMode] = ContainmentMode.HUMAN_APPROVAL_REQUIRED

# IMMUTABLE SAFETY INVARIANT: OT assets ALWAYS require human approval.
OT_ALWAYS_HUMAN_APPROVAL: Final[bool] = True

# Approved actions not executed within this window automatically expire.
APPROVAL_EXPIRY_HOURS: Final[int] = int(
    os.environ.get("VAULTX_APPROVAL_EXPIRY_HOURS", "4")
)

# SHA-256 hex digest of emergency break-glass admin password (from env).
# Leave empty in env if break-glass is not provisioned; break-glass rejects
# all attempts when unset.
BREAK_GLASS_HASH: str = os.environ.get("BREAK_GLASS_HASH", "")

# Two-person rule for CRITICAL OT asset containment (SECURITY_MANAGER + APPROVER).
TWO_PERSON_RULE_OT_ENABLED: Final[bool] = True

# Adapter execution timeout in seconds; exceeding marks action 'failed' + alert.
EXECUTION_TIMEOUT_SECONDS: Final[int] = int(
    os.environ.get("VAULTX_EXECUTION_TIMEOUT_SECONDS", "30")
)

# Window during which completed containment actions can be rolled back automatically.
ROLLBACK_WINDOW_HOURS: Final[int] = int(
    os.environ.get("VAULTX_ROLLBACK_WINDOW_HOURS", "24")
)

# ---------------------------------------------------------------------------
# Redis Stream & Database Constants
# ---------------------------------------------------------------------------

REDIS_STREAM_CONTAINMENT_EXECUTED: Final[str] = "containment:executed"
REDIS_STREAM_CONTAINMENT_ALERTS: Final[str] = "containment:alerts"
REDIS_STREAM_CORRELATION_UPDATES: Final[str] = "correlation:incident_updates"

DB_SCHEMA: Final[str] = "becpl_nids"

# ---------------------------------------------------------------------------
# Model Improvement Pipeline Constants
# ---------------------------------------------------------------------------

MODEL_PIPELINE_MAX_MISSING_RATIO: Final[float] = float(
    os.environ.get("VAULTX_PIPELINE_MAX_MISSING_RATIO", "0.20")
)
MINIO_BUCKET: Final[str] = os.environ.get("VAULTX_MINIO_BUCKET", "vaultx-datasets")
MINIO_TRAINING_DATASET_PREFIX: Final[str] = "datasets/training"

# ---------------------------------------------------------------------------
# Narrowly Pre-Scoped, Pre-Tested, Pre-Approved Action Templates (MODE 4 only)
# ---------------------------------------------------------------------------
# Even in MODE 4 (PRE_APPROVED_AUTOMATION), ONLY actions matching one of these
# narrowly scoped templates AND targeting non-OT, non-critical assets may be
# auto-approved. OT assets are ALWAYS blocked by the OT safety override.

PRE_APPROVED_ACTION_TEMPLATES: Final[dict[str, dict[str, Any]]] = {
    "TPL-BLOCK-KNOWN-C2-IT": {
        "name": "Block Known External C2 IP from Corporate/Warehouse Workstation",
        "action_category": ActionCategory.NETWORK_CONTAINMENT.value,
        "allowed_vlans": [10, 40],
        "allowed_criticalities": ["low", "medium"],
        "max_duration_hours": 4,
        "pre_tested": True,
        "pre_approved_by": "CISO",
    },
    "TPL-QUARANTINE-LOW-CORP-WS": {
        "name": "Quarantine Low-Criticality Corporate Workstation",
        "action_category": ActionCategory.ENDPOINT_QUARANTINE.value,
        "allowed_vlans": [10],
        "allowed_criticalities": ["low"],
        "max_duration_hours": 4,
        "pre_tested": True,
        "pre_approved_by": "CISO",
    },
    "TPL-REVOKE-COMPROMISED-SVC-SESSION": {
        "name": "Revoke Non-Critical Session Token on Brute-Force Lockout",
        "action_category": ActionCategory.IDENTITY_CONTAINMENT.value,
        "allowed_vlans": [10, 40],
        "allowed_criticalities": ["low", "medium"],
        "max_duration_hours": 2,
        "pre_tested": True,
        "pre_approved_by": "CISO",
    },
}


# ---------------------------------------------------------------------------
# Guarded Configuration Container
# ---------------------------------------------------------------------------


class ContainmentConfig:
    """
    Runtime containment configuration wrapper that enforces immutable safety
    invariants (specifically ``ot_always_human_approval == True``).
    """

    def __init__(
        self,
        default_mode: str | ContainmentMode = DEFAULT_MODE,
        approval_expiry_hours: int = APPROVAL_EXPIRY_HOURS,
        break_glass_hash: str | None = None,
        two_person_rule_ot: bool = TWO_PERSON_RULE_OT_ENABLED,
        execution_timeout_seconds: int = EXECUTION_TIMEOUT_SECONDS,
        rollback_window_hours: int = ROLLBACK_WINDOW_HOURS,
    ) -> None:
        self._mode: ContainmentMode = ContainmentMode.from_name(default_mode)
        self._ot_always_human_approval: bool = True
        self.approval_expiry_hours: int = approval_expiry_hours
        self.break_glass_hash: str = (
            break_glass_hash
            if break_glass_hash is not None
            else os.environ.get("BREAK_GLASS_HASH", BREAK_GLASS_HASH)
        )
        self.two_person_rule_ot: bool = two_person_rule_ot
        self.execution_timeout_seconds: int = execution_timeout_seconds
        self.rollback_window_hours: int = rollback_window_hours

    @property
    def default_mode(self) -> ContainmentMode:
        return self._mode

    @property
    def ot_always_human_approval(self) -> bool:
        """Always True; cannot be modified programmatically."""
        return True

    @ot_always_human_approval.setter
    def ot_always_human_approval(self, value: bool) -> None:
        if value is not True:
            raise SafetyInvariantViolationError(
                "OT_ALWAYS_HUMAN_APPROVAL is a hard safety invariant and "
                "cannot be changed programmatically."
            )

    def __setattr__(self, name: str, value: Any) -> None:
        if name in ("_ot_always_human_approval", "OT_ALWAYS_HUMAN_APPROVAL") and value is not True:
            raise SafetyInvariantViolationError(
                "OT_ALWAYS_HUMAN_APPROVAL is a hard safety invariant and "
                "cannot be disabled programmatically."
            )
        super().__setattr__(name, value)

    def verify_break_glass_code(self, plaintext_code: str) -> bool:
        """
        Verify an emergency break-glass code against ``BREAK_GLASS_HASH`` using
        constant-time SHA-256 digest comparison.
        """
        expected_hash = (self.break_glass_hash or os.environ.get("BREAK_GLASS_HASH", "")).strip().lower()
        if not expected_hash or not plaintext_code:
            return False
        candidate_hash = hashlib.sha256(plaintext_code.encode("utf-8")).hexdigest().lower()
        return hmac.compare_digest(candidate_hash, expected_hash)

    def to_dict(self) -> dict[str, Any]:
        return {
            "default_mode": self._mode.name,
            "default_mode_number": int(self._mode),
            "ot_always_human_approval": self.ot_always_human_approval,
            "approval_expiry_hours": self.approval_expiry_hours,
            "break_glass_configured": bool(
                self.break_glass_hash or os.environ.get("BREAK_GLASS_HASH", "")
            ),
            "two_person_rule_ot": self.two_person_rule_ot,
            "execution_timeout_seconds": self.execution_timeout_seconds,
            "rollback_window_hours": self.rollback_window_hours,
        }

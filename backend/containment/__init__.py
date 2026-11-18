"""
VaultX Phase 2 — Containment & Response Engine Package.

Exports the policy engine, human-in-the-loop approval engine, simulated
enforcement adapters, action executor, simulated firewall state manager,
configuration constants, and the continuous model improvement pipeline.
"""

from backend.containment.action_executor import (
    ActionExecutionTimeoutError,
    ContainmentActionExecutor,
    RollbackWindowExceededError,
)
from backend.containment.approval_engine import (
    ActionExpiredError,
    ActionNotFoundError,
    ApprovalEngine,
    ApprovalResult,
    AuthenticationError,
    AuthorizationError,
    IdentityRecord,
    InvalidBreakGlassError,
    InvalidStateTransitionError,
    REVERSE_ACTION_MAP,
    ReverseActionSpec,
    get_reverse_action,
)
from backend.containment.containment_config import (
    APPROVAL_EXPIRY_HOURS,
    ActionCategory,
    ActionStatus,
    ApprovalMethod,
    BREAK_GLASS_HASH,
    ContainmentConfig,
    ContainmentMode,
    DEFAULT_MODE,
    EXECUTION_TIMEOUT_SECONDS,
    OT_ALWAYS_HUMAN_APPROVAL,
    OT_VLAN_ID,
    ROLLBACK_WINDOW_HOURS,
    Role,
    SafetyInvariantViolationError,
    TWO_PERSON_RULE_OT_ENABLED,
)
from backend.containment.enforcement_adapters import (
    ContainmentAction,
    EndpointQuarantineAdapter,
    EnforcementAdapter,
    ExecutionResult,
    FirewallAdapter,
    IdentityAdapter,
    OTBoundaryAdapter,
    QuarantineRecord,
    RollbackResult,
    VPNAdapter,
    build_default_adapters,
)
from backend.containment.policy_engine import (
    ActionProposal,
    AffectedAsset,
    ContainmentPolicyEngine,
    DisabledModeError,
    IsolationPolicy,
    PolicyLookupError,
    ProposalValidationError,
    UnauthorizedModeChangeError,
)
from backend.containment.simulated_firewall import (
    FirewallAuditEntry,
    FirewallOperationResult,
    FirewallRule,
    SimulatedFirewallManager,
)

_MODEL_PIPELINE_EXPORTS = {
    "DataQualityReport",
    "DatasetVersionManifest",
    "LabelVerificationReport",
    "ModelEvaluationReport",
    "ModelImprovementPipeline",
}


def __getattr__(name: str):
    """Lazy-load model_pipeline exports so ``python -m backend.containment.model_pipeline`` runs without runpy warnings."""
    if name in _MODEL_PIPELINE_EXPORTS:
        from backend.containment import model_pipeline

        return getattr(model_pipeline, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

__all__ = [
    # Config & Enums
    "APPROVAL_EXPIRY_HOURS",
    "ActionCategory",
    "ActionStatus",
    "ApprovalMethod",
    "BREAK_GLASS_HASH",
    "ContainmentConfig",
    "ContainmentMode",
    "DEFAULT_MODE",
    "EXECUTION_TIMEOUT_SECONDS",
    "OT_ALWAYS_HUMAN_APPROVAL",
    "OT_VLAN_ID",
    "ROLLBACK_WINDOW_HOURS",
    "Role",
    "SafetyInvariantViolationError",
    "TWO_PERSON_RULE_OT_ENABLED",
    # Policy Engine
    "ActionProposal",
    "AffectedAsset",
    "ContainmentPolicyEngine",
    "DisabledModeError",
    "IsolationPolicy",
    "PolicyLookupError",
    "ProposalValidationError",
    "UnauthorizedModeChangeError",
    # Approval Engine
    "ActionExpiredError",
    "ActionNotFoundError",
    "ApprovalEngine",
    "ApprovalResult",
    "AuthenticationError",
    "AuthorizationError",
    "IdentityRecord",
    "InvalidBreakGlassError",
    "InvalidStateTransitionError",
    "REVERSE_ACTION_MAP",
    "ReverseActionSpec",
    "get_reverse_action",
    # Simulated Firewall & Enforcement Adapters
    "ContainmentAction",
    "EndpointQuarantineAdapter",
    "EnforcementAdapter",
    "ExecutionResult",
    "FirewallAdapter",
    "FirewallAuditEntry",
    "FirewallOperationResult",
    "FirewallRule",
    "IdentityAdapter",
    "OTBoundaryAdapter",
    "QuarantineRecord",
    "RollbackResult",
    "SimulatedFirewallManager",
    "VPNAdapter",
    "build_default_adapters",
    # Action Executor
    "ActionExecutionTimeoutError",
    "ContainmentActionExecutor",
    "RollbackWindowExceededError",
    # Model Pipeline
    "DataQualityReport",
    "DatasetVersionManifest",
    "LabelVerificationReport",
    "ModelEvaluationReport",
    "ModelImprovementPipeline",
]

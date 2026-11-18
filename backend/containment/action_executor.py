"""
action_executor.py — Containment Action Executor for VaultX Phase 2.

Executes human-approved (or MODE 4 pre-approved template) containment actions
through the appropriate ``EnforcementAdapter``, enforces execution timeouts,
updates PostgreSQL ``response_actions`` and ``audit_log``, publishes events to
Redis stream ``containment:executed``, notifies the correlation engine to
update incident status, and supports full rollback within the rollback window.

Execution Workflow (9 Steps)
----------------------------
1. Load action from ``response_actions`` (must have ``status == 'approved'``).
2. Verify action has not expired (4-hour approval expiry window).
3. Select the appropriate ``EnforcementAdapter`` for the action category.
4. Execute the action via the adapter with a strict timeout
   (``EXECUTION_TIMEOUT_SECONDS = 30``). On timeout, mark ``failed`` and raise alert.
5. Record execution result (success/failure, timestamp, adapter response).
6. Update ``response_actions`` (``status = 'completed'`` or ``'failed'``).
7. Write a full audit record to ``audit_log``.
8. Publish execution event to Redis stream ``containment:executed``.
9. Notify correlation engine to update incident status (e.g. ``contained``).
"""

from __future__ import annotations

import concurrent.futures
import json
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from backend.containment.approval_engine import (
    ActionExpiredError,
    ActionNotFoundError,
    ApprovalEngine,
    InvalidStateTransitionError,
)
from backend.containment.containment_config import (
    ActionCategory,
    ActionStatus,
    ContainmentConfig,
    DB_SCHEMA,
    REDIS_STREAM_CONTAINMENT_ALERTS,
    REDIS_STREAM_CONTAINMENT_EXECUTED,
    REDIS_STREAM_CORRELATION_UPDATES,
)
from backend.containment.enforcement_adapters import (
    ContainmentAction,
    EnforcementAdapter,
    ExecutionResult,
    RollbackResult,
    build_default_adapters,
)
from backend.containment.policy_engine import ActionProposal, ContainmentPolicyEngine

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class ActionExecutionTimeoutError(TimeoutError):
    """Raised when an enforcement adapter fails to respond within timeout."""


class RollbackWindowExceededError(RuntimeError):
    """Raised when a rollback is requested past the configured rollback window."""


# ---------------------------------------------------------------------------
# Action Executor
# ---------------------------------------------------------------------------


class ContainmentActionExecutor:
    """
    Orchestrates safe execution and rollback of approved containment actions.

    Parameters
    ----------
    policy_engine : ContainmentPolicyEngine
        Stores and resolves ``ActionProposal`` records.
    approval_engine : ApprovalEngine
        Handles expiry verification and writes tamper-evident audit records.
    adapters : dict[ActionCategory, EnforcementAdapter] | None
        Mapping of action categories to enforcement adapters. Defaults to
        ``build_default_adapters(db_conn=db_conn)``.
    db_conn : optional DB-API 2.0 connection
        PostgreSQL connection for updating ``response_actions`` & ``incidents``.
    redis_client : optional Redis client
        Publishes to ``containment:executed``, ``containment:alerts``, and
        ``correlation:incident_updates``.
    correlation_notifier : callable | None
        Optional callback ``(incident_id, new_status, details) -> None`` to
        notify the correlation engine in-process.
    alert_callback : callable | None
        Optional callback invoked when an execution timeout or failure alert fires.
    config : ContainmentConfig | None
        Execution timeout (default 30s) and rollback window (default 24h).
    """

    def __init__(
        self,
        policy_engine: ContainmentPolicyEngine,
        approval_engine: ApprovalEngine,
        adapters: dict[ActionCategory, EnforcementAdapter] | None = None,
        db_conn: Any | None = None,
        redis_client: Any | None = None,
        correlation_notifier: Callable[[uuid.UUID, str, dict[str, Any]], None] | None = None,
        alert_callback: Callable[[dict[str, Any]], None] | None = None,
        config: ContainmentConfig | None = None,
    ) -> None:
        self._policy_engine = policy_engine
        self._approval_engine = approval_engine
        self._db_conn = db_conn
        self._redis = redis_client
        self._correlation_notifier = correlation_notifier
        self._alert_callback = alert_callback
        self._config = config or policy_engine.config
        self._adapters: dict[ActionCategory, EnforcementAdapter] = (
            adapters if adapters is not None else build_default_adapters(db_conn=db_conn)
        )
        self._published_events: list[dict[str, Any]] = []
        self._alerts: list[dict[str, Any]] = []
        self._correlation_notifications: list[dict[str, Any]] = []

    # ------------------------------------------------------------------
    # Inspection Helpers
    # ------------------------------------------------------------------

    def get_published_events(self) -> list[dict[str, Any]]:
        return list(self._published_events)

    def get_alerts(self) -> list[dict[str, Any]]:
        return list(self._alerts)

    def get_correlation_notifications(self) -> list[dict[str, Any]]:
        return list(self._correlation_notifications)

    def get_adapter(self, category: ActionCategory) -> EnforcementAdapter:
        adapter = self._adapters.get(category)
        if adapter is None:
            raise LookupError(f"No enforcement adapter registered for category {category.value}.")
        return adapter

    # ------------------------------------------------------------------
    # Step 1-9 Execution Workflow
    # ------------------------------------------------------------------

    def execute_action(
        self,
        action_id: uuid.UUID | str,
        executed_by: str = "vaultx-action-executor",
        now: datetime | None = None,
        timeout_seconds: float | None = None,
    ) -> ExecutionResult:
        """
        Execute an approved containment action following the 9-step workflow.
        """
        target_id = action_id if isinstance(action_id, uuid.UUID) else uuid.UUID(str(action_id))
        current_time = now or datetime.now(timezone.utc)
        timeout = (
            timeout_seconds
            if timeout_seconds is not None
            else float(self._config.execution_timeout_seconds)
        )

        # Step 1: Load action (from memory / response_actions) & verify status == 'approved'
        proposal = self._policy_engine.get_proposal(target_id)
        if proposal is None:
            raise ActionNotFoundError(f"Containment action {target_id} not found.")

        if proposal.execution_status != ActionStatus.APPROVED.value:
            raise InvalidStateTransitionError(
                f"Cannot execute action {target_id} in status {proposal.execution_status!r}. "
                f"Only 'approved' actions may be executed."
            )

        # Step 2: Verify action has not expired (4-hour approval expiry window)
        if self._approval_engine.expire_if_needed(proposal, now=current_time):
            raise ActionExpiredError(
                f"Containment action {target_id} expired after "
                f"{self._config.approval_expiry_hours} hours and cannot be executed."
            )

        # Step 3: Load appropriate enforcement adapter
        adapter = self.get_adapter(proposal.action_category)

        # Transition status -> executing
        proposal.execution_status = ActionStatus.EXECUTING.value
        proposal.executed_at = current_time
        self._persist_execution_state(proposal, execution_detail={"stage": "executing"})

        action_payload = ContainmentAction(
            action_id=proposal.action_id,
            incident_id=proposal.incident_id,
            action_category=proposal.action_category,
            target_asset_id=proposal.affected_asset.asset_id,
            target_identity_id=proposal.target_identity_id,
            target_principal=proposal.proposed_action.get("parameters", {}).get("principal_name"),
            target_ip=proposal.target_ip or proposal.affected_asset.ip_address,
            parameters=dict(proposal.proposed_action.get("parameters", {})),
            initiated_by=proposal.initiated_by,
            approved_by=proposal.approver_identity,
            expires_at=proposal.expires_at,
        )

        # Step 4: Execute action via adapter with timeout enforcement
        result: ExecutionResult
        timed_out = False
        pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        future = pool.submit(adapter.execute, action_payload)
        try:
            result = future.result(timeout=timeout)
        except concurrent.futures.TimeoutError:
            timed_out = True
            future.cancel()
            result = ExecutionResult(
                action_id=proposal.action_id,
                adapter_name=adapter.adapter_name,
                success=False,
                status=ActionStatus.FAILED,
                message=(
                    f"Adapter {adapter.adapter_name} timed out after {timeout}s "
                    f"while executing action {proposal.action_id}."
                ),
                error="execution_timeout",
            )
            self._raise_execution_alert(
                proposal=proposal,
                alert_type="CONTAINMENT_EXECUTION_TIMEOUT",
                message=result.message,
            )
        except Exception as exc:
            result = ExecutionResult(
                action_id=proposal.action_id,
                adapter_name=adapter.adapter_name,
                success=False,
                status=ActionStatus.FAILED,
                message=f"Adapter {adapter.adapter_name} raised error: {exc}",
                error=str(exc),
            )
            self._raise_execution_alert(
                proposal=proposal,
                alert_type="CONTAINMENT_EXECUTION_ERROR",
                message=result.message,
            )
        finally:
            pool.shutdown(wait=False, cancel_futures=True)

        # Step 5 & 6: Record execution result & update response_actions table
        completed_time = datetime.now(timezone.utc)
        proposal.execution_status = (
            ActionStatus.COMPLETED.value if result.success else ActionStatus.FAILED.value
        )
        proposal.completed_at = completed_time
        self._persist_execution_state(proposal, execution_detail=result.to_dict())

        # Step 7: Write full audit record
        self._approval_engine.write_audit_log(
            actor=executed_by,
            actor_type="automation" if executed_by == "vaultx-action-executor" else "human_operator",
            action="CONTAINMENT_ACTION_EXECUTED" if result.success else "CONTAINMENT_ACTION_FAILED",
            target_table="response_actions",
            target_id=str(proposal.action_id),
            old_value={"status": ActionStatus.APPROVED.value},
            new_value={
                "status": proposal.execution_status,
                "adapter": adapter.adapter_name,
                "result": result.to_dict(),
                "timed_out": timed_out,
            },
            outcome="success" if result.success else "failure",
            failure_reason=result.error,
        )

        # Step 8: Publish to Redis stream 'containment:executed'
        stream_event = {
            "event_type": "containment_executed" if result.success else "containment_failed",
            "action_id": str(proposal.action_id),
            "incident_id": str(proposal.incident_id),
            "action_category": proposal.action_category.value,
            "target_asset_id": proposal.affected_asset.asset_id,
            "target_vlan": proposal.affected_asset.vlan_id,
            "adapter": adapter.adapter_name,
            "status": proposal.execution_status,
            "success": result.success,
            "approved_by": proposal.approver_identity,
            "break_glass_used": proposal.break_glass_used,
            "executed_at": completed_time.isoformat(),
            "details": result.details,
        }
        self._publish_containment_event(stream_event)

        # Step 9: Notify correlation engine to update incident status
        if result.success:
            self._notify_correlation_engine(
                incident_id=proposal.incident_id,
                new_status="contained",
                details={
                    "action_id": str(proposal.action_id),
                    "action_category": proposal.action_category.value,
                    "target_asset_id": proposal.affected_asset.asset_id,
                    "contained_at": completed_time.isoformat(),
                },
            )

        if timed_out:
            raise ActionExecutionTimeoutError(result.message)

        return result

    # ------------------------------------------------------------------
    # Rollback Executor
    # ------------------------------------------------------------------

    def rollback_action(
        self,
        action_id: uuid.UUID | str,
        actor_identity: str,
        reason: str = "operator_requested_rollback",
        now: datetime | None = None,
    ) -> RollbackResult:
        """
        Reverse a previously executed containment action using its adapter and
        update ``response_actions``, ``audit_log``, Redis, and correlation engine.
        """
        target_id = action_id if isinstance(action_id, uuid.UUID) else uuid.UUID(str(action_id))
        proposal = self._policy_engine.get_proposal(target_id)
        if proposal is None:
            raise ActionNotFoundError(f"Containment action {target_id} not found.")

        if proposal.execution_status != ActionStatus.COMPLETED.value:
            raise InvalidStateTransitionError(
                f"Cannot roll back action {target_id} in status {proposal.execution_status!r}. "
                f"Only 'completed' actions may be rolled back."
            )

        current_time = now or datetime.now(timezone.utc)
        if proposal.completed_at is not None:
            rollback_deadline = proposal.completed_at + timedelta(
                hours=self._config.rollback_window_hours
            )
            if current_time > rollback_deadline:
                raise RollbackWindowExceededError(
                    f"Action {target_id} exceeded the {self._config.rollback_window_hours}-hour "
                    f"automatic rollback window."
                )

        adapter = self.get_adapter(proposal.action_category)
        rb_result = adapter.rollback(target_id)

        if rb_result.success:
            proposal.execution_status = ActionStatus.ROLLED_BACK.value
            proposal.rollback_at = rb_result.rolled_back_at
            self._persist_rollback_state(
                proposal=proposal,
                rollback_by=actor_identity,
                rollback_reason=reason,
                detail=rb_result.to_dict(),
            )

        self._approval_engine.write_audit_log(
            actor=actor_identity,
            actor_type="human_operator",
            action="CONTAINMENT_ACTION_ROLLED_BACK" if rb_result.success else "CONTAINMENT_ROLLBACK_FAILED",
            target_table="response_actions",
            target_id=str(target_id),
            old_value={"status": ActionStatus.COMPLETED.value},
            new_value={
                "status": proposal.execution_status,
                "rollback_by": actor_identity,
                "rollback_reason": reason,
                "adapter_result": rb_result.to_dict(),
            },
            outcome="success" if rb_result.success else "failure",
            failure_reason=rb_result.error,
        )

        self._publish_containment_event(
            {
                "event_type": "containment_rolled_back" if rb_result.success else "containment_rollback_failed",
                "action_id": str(target_id),
                "incident_id": str(proposal.incident_id),
                "action_category": proposal.action_category.value,
                "target_asset_id": proposal.affected_asset.asset_id,
                "rollback_by": actor_identity,
                "rollback_reason": reason,
                "rolled_back_at": rb_result.rolled_back_at.isoformat(),
                "success": rb_result.success,
            }
        )

        if rb_result.success:
            self._notify_correlation_engine(
                incident_id=proposal.incident_id,
                new_status="investigating",
                details={
                    "action_id": str(target_id),
                    "event": "containment_rolled_back",
                    "rollback_by": actor_identity,
                    "rollback_reason": reason,
                },
            )

        return rb_result

    # ------------------------------------------------------------------
    # Redis, Alerting, Correlation, & PostgreSQL Helpers
    # ------------------------------------------------------------------

    def _publish_containment_event(self, payload: dict[str, Any]) -> None:
        self._published_events.append(payload)
        if self._redis is None:
            return
        try:
            self._redis.xadd(
                REDIS_STREAM_CONTAINMENT_EXECUTED,
                {"payload": json.dumps(payload, default=str)},
            )
        except Exception as exc:
            logger.warning(
                "Failed to publish to Redis stream '%s': %s",
                REDIS_STREAM_CONTAINMENT_EXECUTED,
                exc,
            )

    def _raise_execution_alert(
        self,
        proposal: ActionProposal,
        alert_type: str,
        message: str,
    ) -> None:
        alert = {
            "alert_type": alert_type,
            "severity": "critical",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action_id": str(proposal.action_id),
            "incident_id": str(proposal.incident_id),
            "target_asset_id": proposal.affected_asset.asset_id,
            "action_category": proposal.action_category.value,
            "message": message,
        }
        self._alerts.append(alert)
        logger.error("CONTAINMENT ALERT [%s]: %s", alert_type, message)
        if self._redis is not None:
            try:
                self._redis.xadd(
                    REDIS_STREAM_CONTAINMENT_ALERTS,
                    {"payload": json.dumps(alert, default=str)},
                )
            except Exception as exc:
                logger.warning("Failed to publish containment alert to Redis: %s", exc)
        if self._alert_callback is not None:
            try:
                self._alert_callback(alert)
            except Exception as exc:
                logger.warning("Execution alert callback failed: %s", exc)

    def _notify_correlation_engine(
        self,
        incident_id: uuid.UUID,
        new_status: str,
        details: dict[str, Any],
    ) -> None:
        notification = {
            "incident_id": str(incident_id),
            "new_status": new_status,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "details": details,
        }
        self._correlation_notifications.append(notification)

        if self._redis is not None:
            try:
                self._redis.xadd(
                    REDIS_STREAM_CORRELATION_UPDATES,
                    {"payload": json.dumps(notification, default=str)},
                )
            except Exception as exc:
                logger.warning("Failed to publish correlation update to Redis: %s", exc)

        if self._correlation_notifier is not None:
            try:
                self._correlation_notifier(incident_id, new_status, details)
            except Exception as exc:
                logger.warning("Correlation notifier callback failed: %s", exc)

        if self._db_conn is not None:
            sql = f"""
                UPDATE {DB_SCHEMA}.incidents
                   SET status = %s,
                       contained_at = CASE WHEN %s = 'contained' THEN NOW() ELSE contained_at END
                 WHERE incident_id = %s
            """
            try:
                with self._db_conn.cursor() as cur:
                    cur.execute(sql, (new_status, new_status, str(incident_id)))
                self._db_conn.commit()
            except Exception as exc:
                logger.warning("Failed to update incident %s status in PostgreSQL: %s", incident_id, exc)
                try:
                    self._db_conn.rollback()
                except Exception:
                    pass

    def _persist_execution_state(
        self,
        proposal: ActionProposal,
        execution_detail: dict[str, Any],
    ) -> None:
        if self._db_conn is None:
            return
        sql = f"""
            UPDATE {DB_SCHEMA}.response_actions
               SET status = %s,
                   executed_at = %s,
                   completed_at = %s,
                   execution_detail = %s::jsonb,
                   action_proposal = %s::jsonb
             WHERE action_id = %s
        """
        try:
            with self._db_conn.cursor() as cur:
                cur.execute(
                    sql,
                    (
                        proposal.execution_status,
                        proposal.executed_at,
                        proposal.completed_at,
                        json.dumps(execution_detail, default=str),
                        json.dumps(proposal.to_dict(), default=str),
                        str(proposal.action_id),
                    ),
                )
            self._db_conn.commit()
        except Exception as exc:
            logger.warning("Failed to update execution state for %s: %s", proposal.action_id, exc)
            try:
                self._db_conn.rollback()
            except Exception:
                pass

    def _persist_rollback_state(
        self,
        proposal: ActionProposal,
        rollback_by: str,
        rollback_reason: str,
        detail: dict[str, Any],
    ) -> None:
        if self._db_conn is None:
            return
        sql = f"""
            UPDATE {DB_SCHEMA}.response_actions
               SET status = %s,
                   rollback_at = %s,
                   rollback_by = %s,
                   rollback_reason = %s,
                   execution_detail = %s::jsonb,
                   action_proposal = %s::jsonb
             WHERE action_id = %s
        """
        try:
            with self._db_conn.cursor() as cur:
                cur.execute(
                    sql,
                    (
                        proposal.execution_status,
                        proposal.rollback_at,
                        rollback_by,
                        rollback_reason,
                        json.dumps(detail, default=str),
                        json.dumps(proposal.to_dict(), default=str),
                        str(proposal.action_id),
                    ),
                )
            self._db_conn.commit()
        except Exception as exc:
            logger.warning("Failed to update rollback state for %s: %s", proposal.action_id, exc)
            try:
                self._db_conn.rollback()
            except Exception:
                pass

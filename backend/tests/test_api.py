"""
backend/tests/test_api.py — Unit & Integration Test Suite for VaultX Backend API
VaultX Hybrid NIDS for BECPL (Bharat Electronics Components Pvt. Ltd.), Pune
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import pytest
from fastapi import HTTPException

from backend.api.dependencies import UserProfile, UserRole, mock_store, require_roles
from backend.api.routers import (
    behavioural,
    containment,
    detection,
    health,
    identity,
    incidents,
    ingestion,
    models,
    risk,
    threat_intel,
)
from backend.api.schemas import (
    ActionStatus,
    ActionType,
    ApproveActionRequest,
    ExecuteActionRequest,
    IncidentCreate,
    IncidentStatus,
    IncidentUpdateStatus,
    InferenceRequest,
    JA3CheckRequest,
    MaintenanceWindowCreate,
    PromoteModelRequest,
    ProposeActionRequest,
    RetrainModelRequest,
    RollbackActionRequest,
    SeverityLevel,
)


def run_coro(coro):
    """Executes a coroutine deterministically without requiring event loop sockets."""
    try:
        coro.send(None)
    except StopIteration as e:
        return e.value


# Standard test identities across BECPL roles
USER_ANALYST = UserProfile(username="analyst_pooja", role=UserRole.ANALYST, department="SOC Operations")
USER_OPERATOR = UserProfile(username="operator_vikram", role=UserRole.OPERATOR, department="SOC Operations")
USER_APPROVER = UserProfile(username="approver_anita", role=UserRole.APPROVER, department="Plant Operations")
USER_MANAGER = UserProfile(username="sec_mgr_rajesh", role=UserRole.SECURITY_MANAGER, department="Cybersecurity")
USER_ADMIN = UserProfile(username="admin", role=UserRole.ADMIN, department="IT Security")


# ---------------------------------------------------------------------------
# 1. Health & Sensor Telemetry Tests
# ---------------------------------------------------------------------------

def test_system_health():
    res = run_coro(health.get_system_health(mock_store, mock_store, USER_ANALYST))
    assert res.status == "healthy"
    assert res.sensors_online == 7
    assert res.database.connected is True
    assert res.redis.connected is True
    assert res.pipeline.active_backpressure is False
    assert "BECPL" in res.system_version


def test_sensor_health_list():
    sensors = run_coro(health.get_sensor_health_list(USER_ANALYST))
    assert len(sensors) >= 7
    vlan_ids = [s.vlan_id for s in sensors]
    assert 10 in vlan_ids  # Corporate IT
    assert 30 in vlan_ids  # Manufacturing OT
    assert 50 in vlan_ids  # DMZ
    ot_sensor = next(s for s in sensors if s.vlan_id == 30)
    assert ot_sensor.zone_name == "Manufacturing OT"
    assert ot_sensor.status == "online"


def test_pipeline_queue_depths():
    queues = run_coro(health.get_pipeline_queue_depths(USER_OPERATOR))
    assert len(queues) >= 6
    names = [q.stream_name for q in queues]
    assert "events:raw" in names
    assert "flows:completed" in names
    assert "detections:ml" in names


def test_prometheus_metrics():
    res = run_coro(health.get_prometheus_metrics())
    content = res.body.decode("utf-8")
    assert "vaultx_uptime_seconds" in content
    assert "vaultx_events_ingested_total" in content
    assert "vaultx_sensors_online" in content
    assert 'stream="events:raw"' in content


# ---------------------------------------------------------------------------
# 2. Incidents & Blast Radius Tests
# ---------------------------------------------------------------------------

def test_list_and_filter_incidents():
    # List all
    all_inc = run_coro(incidents.list_incidents(None, None, None, 50, 0, USER_ANALYST))
    assert len(all_inc) >= 3

    # Filter by severity
    crit_inc = run_coro(incidents.list_incidents(SeverityLevel.CRITICAL, None, None, 50, 0, USER_ANALYST))
    assert len(crit_inc) >= 1
    assert all(i.severity == SeverityLevel.CRITICAL for i in crit_inc)

    # Filter by zone
    ot_inc = run_coro(incidents.list_incidents(None, None, "Manufacturing OT", 50, 0, USER_ANALYST))
    assert len(ot_inc) >= 1


def test_get_incident_detail():
    inc = run_coro(incidents.get_incident("INC-2026-001", USER_ANALYST))
    assert inc.incident_reference == "INC-2026-001"
    assert "Vendor" in inc.title
    assert len(inc.timeline) >= 2


def test_incident_blast_radius():
    graph = run_coro(incidents.get_incident_blast_radius("INC-2026-006", USER_ANALYST))
    assert graph.ot_boundary_threatened is True
    assert "OT-PLC-001" in graph.critical_assets_exposed
    assert len(graph.nodes) >= 4
    assert len(graph.edges) >= 3


def test_incident_ai_investigation():
    investigation = run_coro(incidents.get_incident_investigation("INC-2026-006", USER_ANALYST))
    assert "Modbus" in investigation.narrative
    assert investigation.confidence_score >= 0.90
    assert "SAFETY WARNING" in investigation.ot_safety_evaluation


def test_create_and_update_incident():
    create_payload = IncidentCreate(
        title="Test Synthetic Modbus Infiltration",
        description="Operator synthetic verification incident",
        severity=SeverityLevel.HIGH,
        attack_scenario="OT Anomaly",
        affected_assets=["ENG-WS-001", "OT-PLC-001"],
        affected_zones=["Engineering & Firmware", "Manufacturing OT"],
    )
    created = run_coro(incidents.create_incident(create_payload, USER_OPERATOR))
    assert created.incident_id in mock_store.incidents

    # Update status to investigating
    update_payload = IncidentUpdateStatus(
        status=IncidentStatus.INVESTIGATING,
        notes="SOC lead investigating telemetry stream",
    )
    updated = run_coro(incidents.update_incident_status(created.incident_id, update_payload, USER_OPERATOR))
    assert updated.status == IncidentStatus.INVESTIGATING


# ---------------------------------------------------------------------------
# 3. Containment & OT Safety Workflow Tests
# ---------------------------------------------------------------------------

def test_containment_modes():
    modes = run_coro(containment.get_containment_modes(USER_ANALYST))
    assert modes.active_mode == "MODE_3_HUMAN_APPROVAL_REQUIRED"
    assert modes.ot_safety_interlock_active is True
    assert modes.two_person_rule_for_ot is True


def test_it_containment_lifecycle():
    # 1. Propose IP block
    propose_req = ProposeActionRequest(
        incident_id="INC-2026-001",
        action_type=ActionType.BLOCK_IP,
        target_ip="198.51.100.99",
        justification="Suspicious external scanning activity",
    )
    action = run_coro(containment.propose_containment_action(propose_req, USER_OPERATOR))
    action_id = action.action_id
    assert action.status == ActionStatus.PENDING
    assert action.is_ot_asset is False

    # 2. Invalid MFA code rejected
    bad_mfa_req = ApproveActionRequest(mfa_code="bad")
    with pytest.raises(HTTPException) as exc_mfa:
        run_coro(containment.approve_containment_action(action_id, bad_mfa_req, USER_APPROVER))
    assert exc_mfa.value.status_code == 400

    # 3. Approve with valid MFA code
    approve_req = ApproveActionRequest(mfa_code="654321", approval_notes="Approved by plant lead")
    approved = run_coro(containment.approve_containment_action(action_id, approve_req, USER_APPROVER))
    assert approved.status == ActionStatus.APPROVED

    # 4. Execute action
    exec_req = ExecuteActionRequest(force_immediate=False)
    executed = run_coro(containment.execute_containment_action(action_id, exec_req, USER_OPERATOR))
    assert executed.status == ActionStatus.COMPLETED

    # 5. Verify simulated firewall rules
    rules = run_coro(containment.list_firewall_rules(USER_ANALYST))
    assert any(r.source_ip == "198.51.100.99" and r.action == "DROP" for r in rules)

    # 6. Rollback action
    rollback_req = RollbackActionRequest(rollback_reason="Target host cleared of malware")
    rolled_back = run_coro(containment.rollback_containment_action(action_id, rollback_req, USER_MANAGER))
    assert rolled_back.status == ActionStatus.ROLLED_BACK


def test_ot_safety_two_person_rule():
    # Propose isolation of an OT PLC
    propose_req = ProposeActionRequest(
        incident_id="INC-2026-006",
        action_type=ActionType.ISOLATE,
        target_asset_id="OT-PLC-001",
        target_ip="10.10.30.10",
        justification="Emergency SMT line isolation proposal",
    )
    action = run_coro(containment.propose_containment_action(propose_req, USER_OPERATOR))
    action_id = action.action_id
    assert action.is_ot_asset is True

    # 1. Non-manager role blocked from OT approval
    app_req = ApproveActionRequest(mfa_code="112233", second_approver_username="plant_head")
    with pytest.raises(HTTPException) as exc_role:
        run_coro(containment.approve_containment_action(action_id, app_req, USER_APPROVER))
    assert exc_role.value.status_code == 403
    assert "OT Containment Safety Violation" in exc_role.value.detail

    # 2. Manager missing second approver blocked under Two-Person Rule
    app_no_2nd = ApproveActionRequest(mfa_code="112233", second_approver_username=None)
    with pytest.raises(HTTPException) as exc_2p:
        run_coro(containment.approve_containment_action(action_id, app_no_2nd, USER_MANAGER))
    assert exc_2p.value.status_code == 422
    assert "Two-Person Rule Violation" in exc_2p.value.detail

    # 3. Manager WITH designated second approver succeeds
    app_valid = ApproveActionRequest(
        mfa_code="112233",
        second_approver_username="anita_plant_head",
        approval_notes="Plant Operations Head concurred. Secondary assembly line enabled."
    )
    ot_approved = run_coro(containment.approve_containment_action(action_id, app_valid, USER_MANAGER))
    assert ot_approved.status == ActionStatus.APPROVED
    assert ot_approved.second_approver == "anita_plant_head"


# ---------------------------------------------------------------------------
# 4. Risk Assessment Tests
# ---------------------------------------------------------------------------

def test_zone_risk_scores():
    zones = run_coro(risk.get_zone_risk_scores(USER_ANALYST))
    assert len(zones) == 6
    names = [z.zone_name for z in zones]
    assert "Corporate IT" in names
    assert "Manufacturing OT" in names
    assert "DMZ & Vendor Access" in names


def test_asset_criticality_matrix():
    matrix = run_coro(risk.get_asset_criticality_matrix(USER_ANALYST))
    plc = next(a for a in matrix if a.asset_id == "OT-PLC-001")
    assert plc.criticality == "critical"
    assert "SMT" in plc.business_impact


def test_ot_safety_status():
    status = run_coro(risk.get_ot_safety_status(USER_ANALYST))
    assert status.interlocks_engaged is True
    assert status.production_line_safety_clearance is True
    assert status.safety_override_requires_2_approvers is True


# ---------------------------------------------------------------------------
# 5. Model Registry & Offline Retraining Tests
# ---------------------------------------------------------------------------

def test_list_models():
    m_list = run_coro(models.list_models(USER_ANALYST))
    assert len(m_list) >= 2
    ids = [m.model_id for m in m_list]
    assert "model-rf-001" in ids
    assert "model-if-001" in ids


def test_model_evaluation_report():
    report = run_coro(models.get_model_evaluation_report("model-rf-001", USER_ANALYST))
    assert report.macro_f1 >= 0.95
    assert report.false_positive_rate <= 0.02
    assert "BENIGN" in report.per_class_metrics
    assert "OT_ANOMALY" in report.per_class_metrics
    assert len(report.top_shap_features) >= 3


def test_promote_model_governance():
    req = PromoteModelRequest(manager_approval_notes="Approved for production after holdout verification")
    promoted = run_coro(models.promote_model_to_production("model-rf-001", req, USER_MANAGER))
    assert promoted.is_active is True


def test_trigger_offline_training():
    req = RetrainModelRequest(dataset_name="becpl_synthetic_traffic_50k.csv", epochs_or_estimators=200)
    res = run_coro(models.trigger_offline_training(req, USER_OPERATOR))
    assert res.status == "queued"
    assert "train-job-" in res.job_id


# ---------------------------------------------------------------------------
# 6. Threat Intel & Identity Tests
# ---------------------------------------------------------------------------

def test_threat_intel_vulnerabilities():
    vulns = run_coro(threat_intel.list_vulnerabilities(None, None, None, False, USER_ANALYST))
    cves = [v.cve_id for v in vulns]
    assert "CVE-2020-0796" in cves
    assert "CVE-2016-10009" in cves

    kev = run_coro(threat_intel.get_cisa_kev_catalog(None, USER_ANALYST))
    assert len(kev) >= 2


def test_ja3_fingerprint_check():
    req = JA3CheckRequest(ja3_hash="6734f37431670b3ab4292b8f60f29984")
    res = run_coro(threat_intel.check_ja3_fingerprint(req, USER_ANALYST))
    assert res.matched_threat is True
    assert "Cobalt Strike" in (res.threat_name or "")


def test_identity_registry_7_way():
    registry = run_coro(identity.list_identities(None, None, USER_ANALYST))
    types = {r.principal_type for r in registry}
    expected = {
        "HUMAN_USER", "SERVICE_ACCOUNT", "AUTOMATION_WORKLOAD",
        "AI_AGENT", "INDUSTRIAL_DEVICE", "THIRD_PARTY_IDENTITY", "UNKNOWN_IDENTITY"
    }
    assert expected.issubset(types)


def test_vendor_compliance():
    vendors = run_coro(identity.get_vendor_compliance(USER_ANALYST))
    schneider = next(v for v in vendors if v.vendor_id == "VEND-SCHNEIDER")
    assert schneider.overall_compliance_status == "policy_violation"
    assert schneider.max_session_hours_allowed == 4


# ---------------------------------------------------------------------------
# 7. Ingestion, Detection & Behavioural Tests
# ---------------------------------------------------------------------------

def test_ingestion_status_and_lag():
    status = run_coro(ingestion.get_ingestion_status(USER_ANALYST))
    assert status.is_running is True
    assert "events:raw" in status.active_streams

    lag = run_coro(ingestion.get_stream_lag(USER_ANALYST))
    assert len(lag) >= 2


def test_detection_inference():
    req = InferenceRequest(
        flow_features={"protocol": "Modbus TCP", "flow_bytes_per_sec": 1400.0},
        destination_ip="10.10.30.10",
        source_ip="10.10.20.31",
    )
    res = run_coro(detection.run_on_demand_inference(req, USER_ANALYST))
    assert res.predicted_label == "OT_ANOMALY"
    assert res.is_attack is True
    assert res.confidence_score >= 0.90


def test_behavioural_baseline_and_deviation():
    baseline = run_coro(behavioural.get_asset_baseline("OT-PLC-001", USER_ANALYST))
    assert baseline.asset_id == "OT-PLC-001"
    assert 502 in baseline.normal_ports

    # Test deviation
    from backend.api.schemas import DeviationQueryRequest
    dev_req = DeviationQueryRequest(
        asset_id="CORP-WS-001",
        destination_ip="10.10.30.10",
        destination_port=502,
        protocol="TCP",
        bytes_transferred=80000,
        hour_of_day=2,  # 2 AM
    )
    dev_res = run_coro(behavioural.query_deviation(dev_req, USER_ANALYST))
    assert dev_res.is_anomalous is True
    assert dev_res.combined_deviation_score >= 0.70
    assert any("cross_vlan" in s for s in dev_res.signals_triggered)

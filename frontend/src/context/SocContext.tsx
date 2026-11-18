import React, { createContext, useContext, useEffect, useState } from 'react';
import type {
  CommandCentreOverview,
  ContainmentAction,
  ContainmentMode,
  FirewallRule,
  IncidentRecord,
  SystemAnalysisEntry,
  UserProfile,
  VlanZoneDetail,
} from '../types';
import { vaultxApi } from '../services/api';
import {
  INITIAL_ANALYSIS_TICKER,
  INITIAL_CONTAINMENT_ACTIONS,
  INITIAL_FIREWALL_RULES,
  INITIAL_INCIDENTS,
  INITIAL_OVERVIEW,
  USER_PERSONAS,
  VLAN_ZONES,
} from '../services/mockData';
import { telemetryStream } from '../services/websocket';

interface SocContextValue {
  currentUser: UserProfile;
  setCurrentUser: (user: UserProfile) => void;
  backendOnline: boolean;
  backendVersion: string;
  overview: CommandCentreOverview;
  liveEps: number;
  liveP95LatencyMs: number;
  analysisTicker: SystemAnalysisEntry[];
  addAnalysisEntry: (entry: SystemAnalysisEntry) => void;
  zones: VlanZoneDetail[];
  toggleZoneIsolation: (vlanId: number) => void;
  incidents: IncidentRecord[];
  addIncident: (incident: IncidentRecord) => void;
  updateIncidentStatus: (incidentId: string, status: IncidentRecord['status']) => void;
  containmentMode: ContainmentMode;
  setContainmentMode: (mode: ContainmentMode) => void;
  containmentActions: ContainmentAction[];
  approveAction: (
    actionId: string,
    mfaCode: string,
    secondApprover?: string,
    breakGlass?: boolean,
    breakGlassReason?: string,
  ) => Promise<void>;
  rollbackAction: (actionId: string, reason: string) => Promise<void>;
  firewallRules: FirewallRule[];
  rollbackFirewallRule: (ruleId: string) => void;
}

const SocContext = createContext<SocContextValue | null>(null);

export const SocProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [currentUser, setCurrentUserState] = useState<UserProfile>(USER_PERSONAS[0]);
  const [backendOnline, setBackendOnline] = useState(false);
  const [backendVersion, setBackendVersion] = useState('VaultX Digital Twin v3.0');
  const [overview, setOverview] = useState<CommandCentreOverview>(INITIAL_OVERVIEW);
  const [liveEps, setLiveEps] = useState(4280);
  const [liveP95LatencyMs, setLiveP95LatencyMs] = useState(4.2);
  const [analysisTicker, setAnalysisTicker] = useState<SystemAnalysisEntry[]>(
    INITIAL_ANALYSIS_TICKER,
  );
  const [zones, setZones] = useState<VlanZoneDetail[]>(VLAN_ZONES);
  const [incidents, setIncidents] = useState<IncidentRecord[]>(INITIAL_INCIDENTS);
  const [containmentMode, setContainmentMode] = useState<ContainmentMode>(
    'MODE_3_HUMAN_APPROVAL_REQUIRED',
  );
  const [containmentActions, setContainmentActions] = useState<ContainmentAction[]>(
    INITIAL_CONTAINMENT_ACTIONS,
  );
  const [firewallRules, setFirewallRules] = useState<FirewallRule[]>(INITIAL_FIREWALL_RULES);

  const setCurrentUser = (user: UserProfile) => {
    setCurrentUserState(user);
    if (user.api_key) {
      vaultxApi.setApiKey(user.api_key);
    }
  };

  useEffect(() => {
    let active = true;
    vaultxApi.checkHealth().then((res) => {
      if (!active) return;
      setBackendOnline(res.online);
      setBackendVersion(res.version);
    });
    vaultxApi.getIncidents().then((list) => {
      if (!active) return;
      setIncidents(list);
    });

    const unsub = telemetryStream.subscribe((pulse) => {
      setLiveEps(pulse.eps);
      setLiveP95LatencyMs(pulse.p95LatencyMs);
      setOverview((prev) => ({
        ...prev,
        activeFlows: pulse.activeFlows,
        throughputGbps: pulse.throughputGbps,
        encryptedTrafficPct: pulse.encryptedPct,
      }));
    });

    return () => {
      active = false;
      unsub();
    };
  }, []);

  const addAnalysisEntry = (entry: SystemAnalysisEntry) => {
    setAnalysisTicker((prev) => [entry, ...prev].slice(0, 12));
  };

  const toggleZoneIsolation = (vlanId: number) => {
    setZones((prev) =>
      prev.map((z) =>
        z.vlan_id === vlanId ? { ...z, isolation_enabled: !z.isolation_enabled } : z,
      ),
    );
  };

  const addIncident = (incident: IncidentRecord) => {
    setIncidents((prev) => [incident, ...prev]);
    setOverview((prev) => ({
      ...prev,
      activeIncidents: prev.activeIncidents + 1,
      networkStatus: incident.severity === 'critical' ? 'UNDER_ATTACK' : 'ELEVATED',
      threatSummary: {
        ...prev.threatSummary,
        critical:
          incident.severity === 'critical'
            ? prev.threatSummary.critical + 1
            : prev.threatSummary.critical,
        high:
          incident.severity === 'high'
            ? prev.threatSummary.high + 1
            : prev.threatSummary.high,
        medium:
          incident.severity === 'medium'
            ? prev.threatSummary.medium + 1
            : prev.threatSummary.medium,
        unresolved: prev.threatSummary.unresolved + 1,
      },
    }));
  };

  const updateIncidentStatus = (incidentId: string, status: IncidentRecord['status']) => {
    setIncidents((prev) =>
      prev.map((inc) => (inc.incident_id === incidentId ? { ...inc, status } : inc)),
    );
  };

  const approveAction = async (
    actionId: string,
    mfaCode: string,
    secondApprover?: string,
    breakGlass?: boolean,
    breakGlassReason?: string,
  ) => {
    await vaultxApi.approveContainmentAction(actionId, {
      mfa_code: mfaCode,
      second_approver_username: secondApprover,
      break_glass: breakGlass,
      break_glass_reason: breakGlassReason,
    });
    const nowStr = new Date().toTimeString().slice(0, 8) + ' IST';
    const targetAction = containmentActions.find((a) => a.action_id === actionId);
    setContainmentActions((prev) =>
      prev.map((act) =>
        act.action_id === actionId
          ? {
              ...act,
              status: 'completed',
              approved_by: currentUser.username,
              second_approver: secondApprover || undefined,
              approval_method: breakGlass ? 'EMERGENCY_BREAK_GLASS' : 'MFA_TOTP_VERIFIED',
              executed_at: `2026-11-18 ${nowStr}`,
            }
          : act,
      ),
    );
    if (targetAction) {
      setFirewallRules((prev) => [
        {
          rule_id: `FW-DYN-${Math.floor(210 + Math.random() * 780)}`,
          source_ip: targetAction.target_ip,
          destination_ip: 'ANY',
          protocol: 'ANY',
          port: 'ANY',
          action: targetAction.action_type === 'quarantine' ? 'QUARANTINE' : 'DROP',
          zone: targetAction.target_zone,
          active: true,
          incident_id: targetAction.incident_reference,
          created_by: currentUser.username,
          created_at: `2026-11-18 ${nowStr}`,
          expires_at: '2026-11-19 12:00:00 IST',
        },
        ...prev,
      ]);
      addAnalysisEntry({
        id: `ANL-${Date.now()}`,
        timestamp: nowStr,
        zone: targetAction.target_zone,
        severity: 'informational',
        summary: `Containment ${targetAction.action_id} (${targetAction.action_type.toUpperCase()}) executed on ${targetAction.target_asset_id} by ${currentUser.full_name}${secondApprover ? ` + ${secondApprover} (Two-Person OT Rule)` : ''}.`,
        evidenceRef: targetAction.incident_reference,
        confidence: 1.0,
      });
    }
  };

  const rollbackAction = async (actionId: string, reason: string) => {
    await vaultxApi.rollbackContainmentAction(actionId, reason);
    const nowStr = new Date().toTimeString().slice(0, 8) + ' IST';
    setContainmentActions((prev) =>
      prev.map((act) =>
        act.action_id === actionId
          ? {
              ...act,
              status: 'rolled_back',
              rollback_at: `2026-11-18 ${nowStr}`,
              rollback_reason: reason,
            }
          : act,
      ),
    );
  };

  const rollbackFirewallRule = (ruleId: string) => {
    setFirewallRules((prev) =>
      prev.map((r) => (r.rule_id === ruleId ? { ...r, active: false } : r)),
    );
  };

  return (
    <SocContext.Provider
      value={{
        currentUser,
        setCurrentUser,
        backendOnline,
        backendVersion,
        overview,
        liveEps,
        liveP95LatencyMs,
        analysisTicker,
        addAnalysisEntry,
        zones,
        toggleZoneIsolation,
        incidents,
        addIncident,
        updateIncidentStatus,
        containmentMode,
        setContainmentMode,
        containmentActions,
        approveAction,
        rollbackAction,
        firewallRules,
        rollbackFirewallRule,
      }}
    >
      {children}
    </SocContext.Provider>
  );
};

export function useSoc(): SocContextValue {
  const ctx = useContext(SocContext);
  if (!ctx) throw new Error('useSoc must be used within SocProvider');
  return ctx;
}

import React, { useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Activity,
  ArrowRight,
  Bot,
  Brain,
  CheckCircle2,
  Cpu,
  ExternalLink,
  Layers,
  Play,
  Radio,
  Shield,
  Sparkles,
  Zap,
} from 'lucide-react';
import { VALIDATION_SCENARIOS } from '../services/mockData';
import type { IncidentRecord, ValidationScenario } from '../types';
import { useSoc } from '../context/SocContext';
import { StatusBadge } from '../components/StatusBadge';

type AgentId =
  | 'sensors'
  | 'normalizer'
  | 'detection'
  | 'correlation'
  | 'containment'
  | 'coordinator';

const SWARM_NODES: {
  id: AgentId;
  label: string;
  role: string;
  icon: React.ComponentType<{ className?: string }>;
}[] = [
  { id: 'sensors', label: 'Passive Sensors', role: '6x Zeek + Suricata Taps', icon: Radio },
  { id: 'normalizer', label: 'Ingestion Normalizer', role: 'Redis Streams + Enricher', icon: Layers },
  { id: 'detection', label: 'Detection Engines', role: 'RF v1 + IForest + Rules', icon: Brain },
  { id: 'correlation', label: 'Correlation Engine', role: 'Attack Graph & Blast Radius', icon: Cpu },
  { id: 'containment', label: 'Containment Adapter', role: 'MFA + OT Safety Interlock', icon: Shield },
  { id: 'coordinator', label: 'SOC Coordinator', role: 'AI Brief & Incident Dispatch', icon: Bot },
];

interface StreamLogItem {
  id: string;
  time: string;
  agent: AgentId;
  action: string;
  detail: string;
  latencyMs: number;
}

export const AgentDemoView: React.FC = () => {
  const navigate = useNavigate();
  const { addIncident, addAnalysisEntry } = useSoc();
  const [runningScenario, setRunningScenario] = useState<ValidationScenario | null>(null);
  const [activeAgent, setActiveAgent] = useState<AgentId | null>(null);
  const [completedAgents, setCompletedAgents] = useState<AgentId[]>([]);
  const [streamLogs, setStreamLogs] = useState<StreamLogItem[]>([]);
  const [generatedIncidentRef, setGeneratedIncidentRef] = useState<string | null>(null);
  const timersRef = useRef<number[]>([]);

  const clearTimers = () => {
    timersRef.current.forEach((t) => window.clearTimeout(t));
    timersRef.current = [];
  };

  const triggerScenario = (scn: ValidationScenario) => {
    clearTimers();
    setRunningScenario(scn);
    setActiveAgent(null);
    setCompletedAgents([]);
    setStreamLogs([]);
    setGeneratedIncidentRef(null);

    scn.agent_steps.forEach((step, idx) => {
      const delay = idx * 650;
      const timerId = window.setTimeout(() => {
        setActiveAgent(step.agent);
        setStreamLogs((prev) => [
          {
            id: `${scn.scenario_id}-${idx}`,
            time: new Date().toTimeString().slice(0, 8),
            agent: step.agent,
            action: step.action,
            detail: step.detail,
            latencyMs: step.latency_ms,
          },
          ...prev,
        ]);

        if (idx > 0) {
          setCompletedAgents((prev) => [...prev, scn.agent_steps[idx - 1].agent]);
        }

        // Final step: emit live incident + Command Centre analysis entry
        if (idx === scn.agent_steps.length - 1) {
          const finishTimer = window.setTimeout(() => {
            setCompletedAgents((prev) => [...prev, step.agent]);
            setActiveAgent(null);

            const refNum = Math.floor(100 + Math.random() * 899);
            const incRef = `INC-2026-${refNum}`;
            const nowStr = new Date().toTimeString().slice(0, 8) + ' IST';

            const newIncident: IncidentRecord = {
              incident_id: `inc-sim-${Date.now()}`,
              incident_reference: incRef,
              title: `[LIVE DEMO] ${scn.scenario_id}: ${scn.name}`,
              description: scn.description,
              severity: scn.severity,
              status: 'open',
              attack_scenario: `${scn.scenario_id}: ${scn.name}`,
              mitre_tactic: scn.category,
              mitre_technique: scn.mitre.join(' / '),
              affected_assets: [scn.source_asset, scn.target_asset],
              affected_zones: [scn.target_zone],
              detected_at: `2026-11-18 ${nowStr}`,
              assigned_to: 'Autonomous Swarm Coordinator',
              ot_safety_flag: scn.ot_safety_lock,
              timeline: scn.agent_steps.map((s) => ({
                timestamp: nowStr,
                actor: s.agent.toUpperCase(),
                action: s.action,
                notes: s.detail,
                stage: s.agent,
              })),
              blast_radius: {
                root_cause_asset: scn.source_asset,
                total_nodes_at_risk: 2,
                ot_boundary_threatened: scn.ot_safety_lock,
                nodes: [
                  {
                    id: scn.source_asset,
                    label: scn.source_asset,
                    type: 'workstation',
                    vlan_id: 20,
                    zone_name: scn.target_zone,
                    criticality: 'high',
                    hop_level: 0,
                    compromised: true,
                    risk_score: 94,
                  },
                  {
                    id: scn.target_asset,
                    label: scn.target_asset,
                    type: scn.ot_safety_lock ? 'plc' : 'server',
                    vlan_id: scn.ot_safety_lock ? 30 : 10,
                    zone_name: scn.target_zone,
                    criticality: 'critical',
                    hop_level: 1,
                    compromised: false,
                    risk_score: 88,
                  },
                ],
                edges: [
                  {
                    source: scn.source_asset,
                    target: scn.target_asset,
                    protocol: scn.ot_safety_lock ? 'Modbus/TCP' : 'TLS/TCP',
                    port: scn.ot_safety_lock ? 502 : 443,
                    suspicious: true,
                    bytes_label: `${scn.expected_eps} EPS burst`,
                  },
                ],
              },
              evidence_logs: [
                {
                  id: `EV-SIM-${refNum}`,
                  timestamp: nowStr,
                  sensor: 'SENS-SWARM-DEMO',
                  protocol: scn.ot_safety_lock ? 'MODBUS' : 'TCP',
                  src: scn.source_asset,
                  dst: scn.target_asset,
                  signature: `VAULTX_${scn.scenario_id}_CONFIRMED`,
                  severity: scn.severity,
                  raw: scn.agent_steps.map((s) => `${s.agent}:${s.action}`).join(' | '),
                },
              ],
              investigation_summary: {
                incident_id: `inc-sim-${Date.now()}`,
                narrative: `Autonomous VaultX multi-agent swarm detected and correlated ${scn.scenario_id} (${scn.name}) end-to-end in under 15ms pipeline latency.`,
                attack_vector: scn.description,
                mitre_tactics: [scn.category],
                mitre_techniques: scn.mitre,
                confidence_score: 0.988,
                root_cause_hypothesis: `Simulated Phase 3 validation trigger from ${scn.source_asset} targeting ${scn.target_asset}.`,
                recommended_containment_actions: [
                  scn.ot_safety_lock
                    ? 'OT Safety Interlock Engaged — Require Two-Person MFA Approval before isolating VLAN 30.'
                    : 'Review automated firewall drop proposal in Isolation & Active Defence.',
                ],
                potential_business_impact: `Validated resilience against ${scn.category} threat vector at ${scn.expected_eps} EPS.`,
                ot_safety_evaluation: scn.ot_safety_lock
                  ? 'OT INTERLOCK ACTIVE: Zero autonomous PLC disconnection.'
                  : 'NO OT IMPACT: Non-shopfloor segment.',
                generated_at: `2026-11-18 ${nowStr}`,
              },
            };

            addIncident(newIncident);
            addAnalysisEntry({
              id: `ANL-SIM-${Date.now()}`,
              timestamp: nowStr,
              zone: scn.target_zone,
              severity: scn.severity,
              summary: `[SWARM DEMO ${scn.scenario_id}] ${scn.name} detected & correlated across 6 autonomous agents -> Generated ${incRef}.`,
              evidenceRef: incRef,
              confidence: 0.988,
            });
            setGeneratedIncidentRef(incRef);
          }, 500);
          timersRef.current.push(finishTimer);
        }
      }, delay);
      timersRef.current.push(timerId);
    });
  };

  return (
    <div className="space-y-6">
      {/* Autonomous Agent Swarm Visual Operational Workflow Diagram */}
      <div className="soc-card rounded-xl p-5 space-y-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
              <Bot className="h-4 w-4 text-cyan-400" />
              Autonomous Multi-Agent SOC Operational Swarm Topology
            </h2>
            <p className="text-xs font-mono text-slate-400">
              Trigger any of the 10 Phase 3 validation scenarios below to watch live packet &amp; decision propagation across all 6 agents
            </p>
          </div>
          {runningScenario ? (
            <StatusBadge
              variant={activeAgent ? 'cyan' : 'healthy'}
              label={
                activeAgent
                  ? `EXECUTING ${runningScenario.scenario_id}`
                  : `COMPLETED ${runningScenario.scenario_id}`
              }
              pulse={Boolean(activeAgent)}
            />
          ) : (
            <StatusBadge variant="cyan" label="SWARM STANDBY • READY" />
          )}
        </div>

        {/* 6-Agent Animated Pipeline Diagram */}
        <div className="flex flex-col lg:flex-row items-stretch lg:items-center justify-between gap-2 overflow-x-auto pb-2">
          {SWARM_NODES.map((node, idx) => {
            const Icon = node.icon;
            const isActive = activeAgent === node.id;
            const isDone = completedAgents.includes(node.id);

            return (
              <React.Fragment key={node.id}>
                <div
                  className={`relative flex-1 min-w-[162px] rounded-xl border p-3.5 transition-all duration-300 ${
                    isActive
                      ? 'border-cyan-400 bg-cyan-500/20 shadow-lg shadow-cyan-500/25 scale-[1.03]'
                      : isDone
                        ? 'border-emerald-500/60 bg-emerald-500/12'
                        : 'border-slate-800 bg-slate-900/70'
                  }`}
                >
                  {isActive && (
                    <span className="absolute -right-1 -top-1 flex h-3.5 w-3.5">
                      <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-cyan-400 opacity-75" />
                      <span className="relative inline-flex h-3.5 w-3.5 rounded-full bg-cyan-400" />
                    </span>
                  )}
                  <div className="flex items-center justify-between">
                    <div
                      className={`flex h-9 w-9 items-center justify-center rounded-lg border ${
                        isActive
                          ? 'border-cyan-400 bg-cyan-500/25 text-cyan-200'
                          : isDone
                            ? 'border-emerald-500/50 bg-emerald-500/20 text-emerald-300'
                            : 'border-slate-700 bg-slate-950 text-slate-400'
                      }`}
                    >
                      <Icon className="h-4 w-4" />
                    </div>
                    {isDone ? (
                      <CheckCircle2 className="h-4 w-4 text-emerald-400" />
                    ) : isActive ? (
                      <Zap className="h-4 w-4 text-cyan-300 animate-pulse" />
                    ) : (
                      <span className="font-mono text-[10px] text-slate-500">0{idx + 1}</span>
                    )}
                  </div>
                  <p className="mt-2.5 text-xs font-bold text-slate-100">{node.label}</p>
                  <p className="text-[10px] font-mono text-slate-400">{node.role}</p>
                </div>

                {idx < SWARM_NODES.length - 1 && (
                  <div className="hidden lg:flex items-center justify-center px-0.5">
                    <ArrowRight
                      className={`h-4 w-4 transition-colors ${
                        isDone
                          ? 'text-emerald-400'
                          : isActive
                            ? 'text-cyan-400 animate-pulse'
                            : 'text-slate-700'
                      }`}
                    />
                  </div>
                )}
              </React.Fragment>
            );
          })}
        </div>

        {/* Live Incident Generated Banner */}
        {generatedIncidentRef && runningScenario && (
          <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-emerald-500/50 bg-emerald-950/25 px-4 py-3">
            <div className="flex items-center gap-2.5 text-xs">
              <Sparkles className="h-4 w-4 text-emerald-400 shrink-0" />
              <span className="font-mono text-emerald-200">
                <strong>LIVE INCIDENT GENERATED: {generatedIncidentRef}</strong> —{' '}
                {runningScenario.scenario_id} ({runningScenario.name}) injected into Incident Queue &amp; Command Centre Ticker.
              </span>
            </div>
            <button
              type="button"
              onClick={() => navigate('/incidents')}
              className="inline-flex items-center gap-1.5 rounded-lg border border-emerald-500/50 bg-emerald-500/20 px-3 py-1.5 text-xs font-mono font-bold text-emerald-200 hover:bg-emerald-500/30 cursor-pointer"
            >
              Inspect in Incidents <ExternalLink className="h-3.5 w-3.5" />
            </button>
          </div>
        )}
      </div>

      {/* Interactive 10-Scenario Player + Live Agent Event Stream */}
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-12">
        {/* Left: 10 Phase 3 Validation Attack Scenarios */}
        <div className="soc-card rounded-xl p-5 xl:col-span-7 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
                <Play className="h-4 w-4 text-emerald-400" />
                Interactive Phase 3 Validation Scenario Player (10 Scenarios)
              </h2>
              <p className="text-xs font-mono text-slate-400">
                Click any scenario button to stream simulated attack packets through the multi-agent SOC
              </p>
            </div>
          </div>

          <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
            {VALIDATION_SCENARIOS.map((scn) => {
              const isCurrent = runningScenario?.scenario_id === scn.scenario_id;
              return (
                <div
                  key={scn.scenario_id}
                  className={`rounded-xl border p-3.5 flex flex-col justify-between space-y-2.5 transition-all ${
                    isCurrent
                      ? 'border-cyan-400/70 bg-cyan-500/10'
                      : 'border-slate-800 bg-slate-900/60 hover:border-slate-700'
                  }`}
                >
                  <div>
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-mono text-xs font-bold text-cyan-300">
                        {scn.scenario_id}
                      </span>
                      <div className="flex items-center gap-1.5">
                        {scn.ot_safety_lock && (
                          <StatusBadge variant="critical" label="OT LOCK" />
                        )}
                        <StatusBadge variant={scn.severity} label={scn.severity} />
                      </div>
                    </div>
                    <h3 className="mt-1 text-xs font-bold text-slate-100">{scn.name}</h3>
                    <p className="mt-1 text-[11px] text-slate-400 leading-snug">
                      {scn.description}
                    </p>
                  </div>

                  <div className="flex items-center justify-between gap-2 border-t border-slate-800 pt-2.5">
                    <span className="text-[10px] font-mono text-slate-400">
                      {scn.source_asset} -&gt; {scn.target_asset}
                    </span>
                    <button
                      type="button"
                      onClick={() => triggerScenario(scn)}
                      className="inline-flex items-center gap-1 rounded-lg border border-cyan-500/50 bg-cyan-500/15 px-2.5 py-1 text-[11px] font-mono font-bold text-cyan-200 hover:bg-cyan-500/25 cursor-pointer shrink-0"
                    >
                      <Play className="h-3 w-3" /> Trigger {scn.scenario_id}
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Right: Live Animated Packet & Agent Decision Telemetry Console */}
        <div className="soc-card rounded-xl p-5 xl:col-span-5 flex flex-col space-y-3">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
              <Activity className="h-4 w-4 text-cyan-400" />
              Live Swarm Telemetry &amp; Decision Stream
            </h2>
            <span className="font-mono text-[10px] text-slate-400">
              {streamLogs.length} STEPS RECORDED
            </span>
          </div>

          <div className="flex-1 space-y-2.5 max-h-[640px] overflow-y-auto pr-1">
            {streamLogs.length === 0 ? (
              <div className="rounded-xl border border-dashed border-slate-800 bg-slate-950/50 p-8 text-center space-y-3">
                <Bot className="mx-auto h-8 w-8 text-cyan-400/60" />
                <p className="text-xs font-mono text-slate-400">
                  Select a validation scenario (e.g. <strong className="text-cyan-300">SCN-001</strong>,{' '}
                  <strong className="text-rose-300">SCN-006</strong>, or{' '}
                  <strong className="text-emerald-300">SCN-010</strong>) to stream real-time agent decisions.
                </p>
                <div className="flex flex-wrap justify-center gap-2 pt-2">
                  <button
                    type="button"
                    onClick={() => triggerScenario(VALIDATION_SCENARIOS[0])}
                    className="rounded-lg border border-cyan-500/50 bg-cyan-500/15 px-3 py-1.5 text-xs font-mono font-semibold text-cyan-200 hover:bg-cyan-500/25 cursor-pointer"
                  >
                    Run SCN-001 Vendor Compromise
                  </button>
                  <button
                    type="button"
                    onClick={() => triggerScenario(VALIDATION_SCENARIOS[5])}
                    className="rounded-lg border border-rose-500/50 bg-rose-500/15 px-3 py-1.5 text-xs font-mono font-semibold text-rose-200 hover:bg-rose-500/25 cursor-pointer"
                  >
                    Run SCN-006 Modbus Override
                  </button>
                </div>
              </div>
            ) : (
              streamLogs.map((log) => (
                <div
                  key={log.id}
                  className="animate-ticker rounded-xl border border-slate-800 bg-slate-950/80 p-3 font-mono text-xs space-y-1"
                >
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <StatusBadge variant="cyan" label={log.agent} />
                      <span className="font-bold text-slate-100">{log.action}</span>
                    </div>
                    <span className="text-[10px] text-emerald-400 telemetry-num">
                      +{log.latencyMs}ms • {log.time}
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-300 leading-relaxed">{log.detail}</p>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

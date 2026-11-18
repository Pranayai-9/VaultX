import React, { useState } from 'react';
import {
  AlertOctagon,
  Brain,
  CheckCircle2,
  Clock,
  FileTerminal,
  Flame,
  Network,
  ShieldAlert,
} from 'lucide-react';
import { useSoc } from '../context/SocContext';
import type { IncidentRecord } from '../types';
import { StatusBadge } from '../components/StatusBadge';

export const IncidentsView: React.FC = () => {
  const { incidents, updateIncidentStatus } = useSoc();
  const [selectedId, setSelectedId] = useState<string>(incidents[0]?.incident_id || '');
  const [activeTab, setActiveTab] = useState<'ai' | 'blast' | 'timeline' | 'evidence'>('ai');

  const selected: IncidentRecord =
    incidents.find((i) => i.incident_id === selectedId) || incidents[0];

  const hopGroups: { hop: 0 | 1 | 2; title: string; badge: string }[] = [
    { hop: 0, title: 'Directly Affected (Hop 0)', badge: 'border-rose-500/60 bg-rose-500/15 text-rose-300' },
    { hop: 1, title: '1-Hop Adjacent Assets', badge: 'border-amber-500/50 bg-amber-500/15 text-amber-300' },
    { hop: 2, title: '2-Hop Downstream Exposure', badge: 'border-cyan-500/40 bg-cyan-500/10 text-cyan-300' },
  ];

  return (
    <div className="grid grid-cols-1 gap-6 xl:grid-cols-12">
      {/* Left: Incident Queue (INC-2026-001 through INC-2026-007+) */}
      <div className="soc-card rounded-xl p-4 xl:col-span-4 space-y-3 h-fit">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
            <Flame className="h-4 w-4 text-rose-400" />
            Incident Queue ({incidents.length})
          </h2>
          <span className="text-[10px] font-mono text-slate-400">SORTED BY PRIORITY</span>
        </div>

        <div className="space-y-2 max-h-[74vh] overflow-y-auto pr-1">
          {incidents.map((inc) => {
            const isSelected = inc.incident_id === selected.incident_id;
            return (
              <button
                key={inc.incident_id}
                type="button"
                onClick={() => setSelectedId(inc.incident_id)}
                className={`w-full rounded-xl border p-3 text-left transition-all cursor-pointer ${
                  isSelected
                    ? 'border-cyan-400/70 bg-cyan-500/10'
                    : 'border-slate-800 bg-slate-900/60 hover:border-slate-700'
                }`}
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono text-xs font-bold text-cyan-300">
                    {inc.incident_reference}
                  </span>
                  <div className="flex items-center gap-1.5">
                    <StatusBadge
                      variant={inc.severity}
                      label={inc.severity}
                      pulse={inc.severity === 'critical' && inc.status !== 'resolved'}
                    />
                  </div>
                </div>
                <p className="mt-1.5 text-xs font-semibold text-slate-100 leading-snug">
                  {inc.title}
                </p>
                <div className="mt-2 flex flex-wrap items-center justify-between gap-1 text-[10px] font-mono text-slate-400">
                  <span>{inc.affected_zones.join(' • ')}</span>
                  <StatusBadge
                    variant={
                      inc.status === 'resolved'
                        ? 'healthy'
                        : inc.status === 'contained'
                          ? 'cyan'
                          : 'warning'
                    }
                    label={inc.status}
                  />
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* Right: Deep Forensic Investigation Workspace */}
      <div className="soc-card rounded-xl p-5 xl:col-span-8 space-y-5">
        {/* Header Bar */}
        <div className="flex flex-wrap items-start justify-between gap-4 border-b border-slate-800 pb-4">
          <div className="space-y-1.5">
            <div className="flex flex-wrap items-center gap-2">
              <span className="rounded bg-cyan-500/15 px-2 py-0.5 font-mono text-xs font-bold text-cyan-300 border border-cyan-500/30">
                {selected.incident_reference}
              </span>
              <StatusBadge variant={selected.severity} label={selected.severity} pulse />
              <StatusBadge
                variant={selected.status === 'resolved' ? 'healthy' : 'warning'}
                label={selected.status}
              />
              {selected.ot_safety_flag && (
                <StatusBadge variant="critical" label="OT SAFETY INTERLOCK" />
              )}
            </div>
            <h2 className="text-lg font-bold text-slate-100">{selected.title}</h2>
            <p className="text-xs text-slate-400">{selected.description}</p>
            <p className="text-[11px] font-mono text-slate-400">
              Scenario: <span className="text-cyan-300">{selected.attack_scenario}</span> • MITRE:{' '}
              <span className="text-amber-300">{selected.mitre_technique}</span> • Owner:{' '}
              <span className="text-slate-200">{selected.assigned_to}</span>
            </p>
          </div>

          <div className="flex items-center gap-2">
            <select
              aria-label="Update incident status"
              value={selected.status}
              onChange={(e) =>
                updateIncidentStatus(
                  selected.incident_id,
                  e.target.value as IncidentRecord['status'],
                )
              }
              className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs font-mono text-slate-200 focus:border-cyan-500 focus:outline-none"
            >
              <option value="open">Status: OPEN</option>
              <option value="investigating">Status: INVESTIGATING</option>
              <option value="contained">Status: CONTAINED</option>
              <option value="resolved">Status: RESOLVED</option>
              <option value="false_positive">Status: FALSE POSITIVE</option>
            </select>
          </div>
        </div>

        {/* Investigation Sub-Navigation Tabs */}
        <div className="flex flex-wrap gap-2 border-b border-slate-800 pb-3">
          {[
            { id: 'ai', label: '9-Field AI Investigation Brief', icon: Brain },
            { id: 'blast', label: 'Interactive Blast-Radius Graph', icon: Network },
            { id: 'timeline', label: 'Attack Timeline', icon: Clock },
            { id: 'evidence', label: `Evidence Logs (${selected.evidence_logs.length})`, icon: FileTerminal },
          ].map((tab) => {
            const Icon = tab.icon;
            return (
              <button
                key={tab.id}
                type="button"
                onClick={() => setActiveTab(tab.id as typeof activeTab)}
                className={`inline-flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-mono font-semibold transition-colors cursor-pointer ${
                  activeTab === tab.id
                    ? 'border-cyan-500/60 bg-cyan-500/15 text-cyan-200'
                    : 'border-slate-800 bg-slate-900/60 text-slate-400 hover:text-slate-200'
                }`}
              >
                <Icon className="h-3.5 w-3.5" />
                {tab.label}
              </button>
            );
          })}
        </div>

        {/* TAB 1: 9-Field AI-Assisted Investigation Summary */}
        {activeTab === 'ai' && (
          <div className="space-y-4">
            <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
              <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-3.5 md:col-span-2">
                <p className="text-[10px] font-mono uppercase text-cyan-400">
                  1. Executive Narrative
                </p>
                <p className="mt-1 text-xs text-slate-200 leading-relaxed">
                  {selected.investigation_summary.narrative}
                </p>
              </div>

              <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-3.5">
                <p className="text-[10px] font-mono uppercase text-cyan-400">
                  2. Attack Vector
                </p>
                <p className="mt-1 text-xs text-slate-200">
                  {selected.investigation_summary.attack_vector}
                </p>
              </div>

              <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-3.5">
                <p className="text-[10px] font-mono uppercase text-cyan-400">
                  3. Confidence Score & Generation Time
                </p>
                <p className="mt-1 text-sm font-mono font-bold text-emerald-300 telemetry-num">
                  {(selected.investigation_summary.confidence_score * 100).toFixed(1)}% Confidence{' '}
                  <span className="text-[11px] font-normal text-slate-400">
                    ({selected.investigation_summary.generated_at})
                  </span>
                </p>
              </div>

              <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-3.5">
                <p className="text-[10px] font-mono uppercase text-cyan-400">
                  4. MITRE ATT&amp;CK Tactics
                </p>
                <div className="mt-1.5 flex flex-wrap gap-1.5">
                  {selected.investigation_summary.mitre_tactics.map((t) => (
                    <StatusBadge key={t} variant="purple" label={t} />
                  ))}
                </div>
              </div>

              <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-3.5">
                <p className="text-[10px] font-mono uppercase text-cyan-400">
                  5. MITRE ATT&amp;CK Techniques
                </p>
                <div className="mt-1.5 flex flex-wrap gap-1.5">
                  {selected.investigation_summary.mitre_techniques.map((t) => (
                    <StatusBadge key={t} variant="warning" label={t} />
                  ))}
                </div>
              </div>

              <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-3.5 md:col-span-2">
                <p className="text-[10px] font-mono uppercase text-cyan-400">
                  6. Root Cause Hypothesis
                </p>
                <p className="mt-1 text-xs text-slate-200">
                  {selected.investigation_summary.root_cause_hypothesis}
                </p>
              </div>

              <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-3.5 md:col-span-2">
                <p className="text-[10px] font-mono uppercase text-cyan-400">
                  7. Recommended Containment Actions
                </p>
                <ul className="mt-1.5 space-y-1.5 text-xs text-slate-200">
                  {selected.investigation_summary.recommended_containment_actions.map((a) => (
                    <li key={a} className="flex items-start gap-2">
                      <CheckCircle2 className="h-3.5 w-3.5 shrink-0 text-emerald-400 mt-0.5" />
                      <span>{a}</span>
                    </li>
                  ))}
                </ul>
              </div>

              <div className="rounded-xl border border-amber-500/35 bg-amber-950/15 p-3.5">
                <p className="text-[10px] font-mono uppercase text-amber-300">
                  8. Potential Business Impact
                </p>
                <p className="mt-1 text-xs text-amber-100/90">
                  {selected.investigation_summary.potential_business_impact}
                </p>
              </div>

              <div className="rounded-xl border border-rose-500/40 bg-rose-950/20 p-3.5">
                <p className="text-[10px] font-mono uppercase text-rose-300 flex items-center gap-1">
                  <ShieldAlert className="h-3.5 w-3.5" />
                  9. OT Safety Evaluation
                </p>
                <p className="mt-1 text-xs text-rose-100/90">
                  {selected.investigation_summary.ot_safety_evaluation}
                </p>
              </div>
            </div>
          </div>
        )}

        {/* TAB 2: Interactive Blast-Radius Graph (Hop 0, Hop 1, Hop 2) */}
        {activeTab === 'blast' && (
          <div className="space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-slate-800 bg-slate-950/70 px-4 py-2.5 text-xs font-mono">
              <span>
                Root Cause Asset:{' '}
                <strong className="text-rose-300">{selected.blast_radius.root_cause_asset}</strong>
              </span>
              <span>
                Nodes at Risk:{' '}
                <strong className="text-amber-300">{selected.blast_radius.total_nodes_at_risk}</strong>
              </span>
              <span>
                OT Boundary Threatened:{' '}
                <strong
                  className={
                    selected.blast_radius.ot_boundary_threatened
                      ? 'text-rose-400'
                      : 'text-emerald-400'
                  }
                >
                  {selected.blast_radius.ot_boundary_threatened ? 'YES — INTERLOCK ACTIVE' : 'NO'}
                </strong>
              </span>
            </div>

            {/* 3-Column Hop Topology */}
            <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
              {hopGroups.map((group) => {
                const hopNodes = selected.blast_radius.nodes.filter(
                  (n) => n.hop_level === group.hop,
                );
                return (
                  <div
                    key={group.hop}
                    className="rounded-xl border border-slate-800 bg-slate-950/60 p-3.5 space-y-3"
                  >
                    <div className={`rounded-lg border px-2.5 py-1 text-[11px] font-mono font-bold ${group.badge}`}>
                      {group.title}
                    </div>
                    {hopNodes.length === 0 ? (
                      <p className="text-xs font-mono text-slate-500 py-4 text-center">
                        No assets at this hop distance.
                      </p>
                    ) : (
                      hopNodes.map((n) => (
                        <div
                          key={n.id}
                          className={`rounded-lg border p-3 space-y-1 ${
                            n.compromised
                              ? 'border-rose-500/60 bg-rose-500/10'
                              : 'border-slate-800 bg-slate-900/80'
                          }`}
                        >
                          <div className="flex items-center justify-between">
                            <span className="font-mono text-xs font-bold text-slate-100">
                              {n.label}
                            </span>
                            <StatusBadge
                              variant={n.compromised ? 'critical' : 'warning'}
                              label={n.compromised ? 'COMPROMISED' : `RISK ${n.risk_score}`}
                            />
                          </div>
                          <p className="text-[11px] font-mono text-slate-400">
                            VLAN {n.vlan_id} • {n.zone_name} • {n.type.toUpperCase()}
                          </p>
                        </div>
                      ))
                    )}
                  </div>
                );
              })}
            </div>

            {/* Observed Lateral Edges */}
            <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-3.5">
              <p className="text-[10px] font-mono uppercase text-slate-400 mb-2">
                Observed Blast-Radius Communication Paths
              </p>
              <div className="space-y-1.5 font-mono text-xs">
                {selected.blast_radius.edges.map((e, i) => (
                  <div
                    key={`${e.source}-${e.target}-${i}`}
                    className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-slate-800 bg-slate-950/70 px-3 py-2"
                  >
                    <span className="text-slate-200">
                      <strong className="text-cyan-300">{e.source}</strong> ---[{e.protocol}
                      {e.port ? `:${e.port}` : ''}]---&gt;{' '}
                      <strong className="text-slate-100">{e.target}</strong>
                    </span>
                    <div className="flex items-center gap-2">
                      <span className="text-[11px] text-slate-400">{e.bytes_label}</span>
                      <StatusBadge
                        variant={e.suspicious ? 'critical' : 'healthy'}
                        label={e.suspicious ? 'MALICIOUS PATH' : 'BASELINE'}
                      />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* TAB 3: Attack Timeline */}
        {activeTab === 'timeline' && (
          <div className="relative pl-6 space-y-4 before:absolute before:left-2.5 before:top-2 before:bottom-2 before:w-px before:bg-slate-800">
            {selected.timeline.map((step, idx) => (
              <div key={idx} className="relative rounded-xl border border-slate-800 bg-slate-900/70 p-3.5">
                <span className="absolute -left-[22px] top-4 h-3 w-3 rounded-full border-2 border-[#0f172a] bg-cyan-400" />
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs font-bold text-cyan-300">
                      {step.timestamp}
                    </span>
                    {step.stage && <StatusBadge variant="cyan" label={step.stage} />}
                  </div>
                  <span className="font-mono text-[11px] text-slate-400">Actor: {step.actor}</span>
                </div>
                <p className="mt-1.5 text-xs font-semibold text-slate-100">{step.action}</p>
                {step.notes && <p className="mt-1 text-xs text-slate-400">{step.notes}</p>}
              </div>
            ))}
          </div>
        )}

        {/* TAB 4: Supporting Evidence Logs */}
        {activeTab === 'evidence' && (
          <div className="space-y-2.5">
            {selected.evidence_logs.map((ev) => (
              <div
                key={ev.id}
                className="rounded-xl border border-slate-800 bg-slate-950/80 p-3.5 font-mono text-xs space-y-1.5"
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <AlertOctagon className="h-3.5 w-3.5 text-rose-400" />
                    <span className="font-bold text-rose-300">{ev.signature}</span>
                    <StatusBadge variant={ev.severity} label={ev.protocol} />
                  </div>
                  <span className="text-[11px] text-slate-400">
                    {ev.sensor} • {ev.timestamp}
                  </span>
                </div>
                <p className="text-cyan-300 text-[11px]">
                  {ev.src} -&gt; {ev.dst}
                </p>
                <pre className="overflow-x-auto rounded bg-slate-900/90 p-2 text-[11px] text-emerald-300 border border-slate-800">
                  {ev.raw}
                </pre>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

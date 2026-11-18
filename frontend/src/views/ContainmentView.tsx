import React, { useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  KeyRound,
  Lock,
  RotateCcw,
  Shield,
  ShieldAlert,
  ShieldOff,
  Users,
} from 'lucide-react';
import { useSoc } from '../context/SocContext';
import type { ContainmentAction, ContainmentMode } from '../types';
import { Modal } from '../components/Modal';
import { StatusBadge } from '../components/StatusBadge';

const CONTAINMENT_MODES: {
  id: ContainmentMode;
  num: string;
  title: string;
  desc: string;
  accent: string;
}[] = [
  {
    id: 'MODE_1_DISABLED',
    num: 'MODE 1',
    title: 'Disabled',
    desc: 'All active containment adapters disengaged. Passive visibility & alerting only.',
    accent: 'border-slate-700',
  },
  {
    id: 'MODE_2_MONITOR_ONLY',
    num: 'MODE 2',
    title: 'Monitor Only (Dry Run)',
    desc: 'Generates containment proposals and impact simulations without pushing firewall rules.',
    accent: 'border-sky-500/50',
  },
  {
    id: 'MODE_3_HUMAN_APPROVAL_REQUIRED',
    num: 'MODE 3',
    title: 'Human Approval Required',
    desc: 'Recommended BECPL default. Requires MFA verification + 2-Person Rule on OT VLAN 30.',
    accent: 'border-cyan-500/60',
  },
  {
    id: 'MODE_4_PREAPPROVED_AUTOMATION',
    num: 'MODE 4',
    title: 'Pre-Approved Automation',
    desc: 'Auto-isolates high-confidence IT/DMZ threats; OT VLAN 30 interlock remains strictly manual.',
    accent: 'border-amber-500/60',
  },
];

export const ContainmentView: React.FC = () => {
  const {
    containmentMode,
    setContainmentMode,
    zones,
    toggleZoneIsolation,
    containmentActions,
    approveAction,
    rollbackAction,
    firewallRules,
    rollbackFirewallRule,
    currentUser,
  } = useSoc();

  const [selectedAction, setSelectedAction] = useState<ContainmentAction | null>(null);
  const [mfaCode, setMfaCode] = useState('');
  const [secondApprover, setSecondApprover] = useState('approver_anita');
  const [breakGlass, setBreakGlass] = useState(false);
  const [breakGlassReason, setBreakGlassReason] = useState('');
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const openApprovalModal = (action: ContainmentAction) => {
    setSelectedAction(action);
    setMfaCode('');
    setBreakGlass(false);
    setBreakGlassReason('');
    setErrorMsg(null);
  };

  const handleConfirmApproval = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedAction) return;

    // Validate MFA code (accepts 1xxxxx 6-digit TOTP) unless break-glass override with justification
    if (!breakGlass) {
      if (!/^1\d{5}$/.test(mfaCode.trim())) {
        setErrorMsg('Invalid TOTP MFA code. Enter a 6-digit code starting with 1 (e.g. 148290).');
        return;
      }
      if (selectedAction.is_ot_asset && !secondApprover.trim()) {
        setErrorMsg('OT Two-Person Rule requires a secondary Plant Operations approver.');
        return;
      }
    } else if (breakGlassReason.trim().length < 10) {
      setErrorMsg('Emergency Break-Glass Override requires a detailed justification (>= 10 chars).');
      return;
    }

    setSubmitting(true);
    await approveAction(
      selectedAction.action_id,
      breakGlass ? 'BREAK-GLASS' : mfaCode.trim(),
      selectedAction.is_ot_asset ? secondApprover : undefined,
      breakGlass,
      breakGlass ? breakGlassReason.trim() : undefined,
    );
    setSubmitting(false);
    setSelectedAction(null);
  };

  return (
    <div className="space-y-6">
      {/* Containment Modes 1-4 Toggle */}
      <div className="soc-card rounded-xl p-5 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
              <Shield className="h-4 w-4 text-cyan-400" />
              Active Defence Containment Mode (Modes 1–4)
            </h2>
            <p className="text-xs font-mono text-slate-400">
              Global enforcement posture governing FortiGate, 802.1X NAC, and IAM containment adapters
            </p>
          </div>
          <StatusBadge variant="warning" label="OT INTERLOCK HARD-LOCKED" />
        </div>

        <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-4">
          {CONTAINMENT_MODES.map((m) => {
            const active = containmentMode === m.id;
            return (
              <button
                key={m.id}
                type="button"
                onClick={() => setContainmentMode(m.id)}
                className={`rounded-xl border p-4 text-left transition-all cursor-pointer ${
                  active
                    ? 'border-cyan-400 bg-cyan-500/12 ring-1 ring-cyan-400/50'
                    : `${m.accent} bg-slate-900/60 hover:bg-slate-900`
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="font-mono text-[11px] font-bold text-cyan-300">{m.num}</span>
                  {active && <StatusBadge variant="healthy" label="ACTIVE" />}
                </div>
                <p className="mt-1.5 text-sm font-bold text-slate-100">{m.title}</p>
                <p className="mt-1 text-xs text-slate-400 leading-relaxed">{m.desc}</p>
              </button>
            );
          })}
        </div>
      </div>

      {/* Section-by-Section Enable/Disable Controls */}
      <div className="soc-card rounded-xl p-5 space-y-4">
        <div>
          <h2 className="text-sm font-semibold text-slate-100">
            Zone-by-Zone Containment Enforcement Switches
          </h2>
          <p className="text-xs font-mono text-slate-400">
            Granular isolation arming across Corporate IT, Engineering, OT, Warehouse, DMZ & Cloud
          </p>
        </div>

        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {zones
            .filter((z) => z.vlan_id !== 70)
            .map((z) => {
              const isOt = z.vlan_id === 30;
              return (
                <div
                  key={z.vlan_id}
                  className="flex items-center justify-between rounded-xl border border-slate-800 bg-slate-900/70 p-3.5"
                >
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-[10px] text-slate-400">VLAN {z.vlan_id}</span>
                      {isOt && <StatusBadge variant="critical" label="2-PERSON RULE" />}
                    </div>
                    <p className="mt-0.5 text-xs font-bold text-slate-100">{z.name}</p>
                    <p className="text-[10px] font-mono text-slate-400">{z.subnet}</p>
                  </div>
                  <button
                    type="button"
                    onClick={() => toggleZoneIsolation(z.vlan_id)}
                    className={`relative inline-flex h-6 w-12 shrink-0 items-center rounded-full border transition-colors cursor-pointer ${
                      z.isolation_enabled
                        ? 'border-emerald-500/60 bg-emerald-500/25'
                        : 'border-slate-700 bg-slate-800'
                    }`}
                    aria-label={`Toggle isolation for ${z.name}`}
                  >
                    <span
                      className={`inline-block h-4 w-4 transform rounded-full transition-transform ${
                        z.isolation_enabled
                          ? 'translate-x-6 bg-emerald-400'
                          : 'translate-x-1 bg-slate-500'
                      }`}
                    />
                  </button>
                </div>
              );
            })}
        </div>
      </div>

      {/* Pending & Recent Containment Actions (Human-in-the-Loop Queue) */}
      <div className="soc-card rounded-xl p-5 space-y-4">
        <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
          <Lock className="h-4 w-4 text-amber-400" />
          Human-in-the-Loop Containment Approval Queue
        </h2>

        <div className="space-y-3">
          {containmentActions.map((act) => (
            <div
              key={act.action_id}
              className={`rounded-xl border p-4 flex flex-col lg:flex-row lg:items-center justify-between gap-4 ${
                act.status === 'pending' && act.is_ot_asset
                  ? 'border-rose-500/50 bg-rose-950/15'
                  : act.status === 'pending'
                    ? 'border-amber-500/40 bg-amber-950/10'
                    : 'border-slate-800 bg-slate-900/60'
              }`}
            >
              <div className="space-y-1.5">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-xs font-bold text-cyan-300">{act.action_id}</span>
                  <span className="font-mono text-xs text-slate-300">({act.incident_reference})</span>
                  <StatusBadge
                    variant={
                      act.status === 'completed'
                        ? 'healthy'
                        : act.status === 'rolled_back'
                          ? 'offline'
                          : 'warning'
                    }
                    label={act.status}
                  />
                  {act.is_ot_asset && (
                    <StatusBadge variant="critical" label="OT TWO-PERSON RULE" pulse />
                  )}
                </div>
                <p className="text-sm font-semibold text-slate-100">
                  {act.action_type.toUpperCase()} -&gt; {act.target_asset_id} ({act.target_ip})
                </p>
                <p className="text-xs text-slate-300">{act.reason}</p>
                <p className="text-[11px] font-mono text-slate-400">
                  Impact: {act.operational_impact}
                </p>
                {act.approved_by && (
                  <p className="text-[11px] font-mono text-emerald-300">
                    Approved by {act.approved_by}
                    {act.second_approver ? ` + ${act.second_approver}` : ''} via {act.approval_method}
                  </p>
                )}
              </div>

              <div className="flex items-center gap-2 shrink-0">
                {act.status === 'pending' && (
                  <button
                    type="button"
                    onClick={() => openApprovalModal(act)}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-cyan-500/60 bg-cyan-500/15 px-3.5 py-2 text-xs font-mono font-bold text-cyan-200 hover:bg-cyan-500/25 transition-colors cursor-pointer"
                  >
                    <KeyRound className="h-3.5 w-3.5" />
                    Review &amp; MFA Approve
                  </button>
                )}
                {act.status === 'completed' && (
                  <button
                    type="button"
                    onClick={() => rollbackAction(act.action_id, 'Manual SOC operator rollback')}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-amber-500/50 bg-amber-500/15 px-3 py-1.5 text-xs font-mono font-semibold text-amber-200 hover:bg-amber-500/25 transition-colors cursor-pointer"
                  >
                    <RotateCcw className="h-3.5 w-3.5" />
                    1-Click Rollback
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Active Containment Firewall Rules Table */}
      <div className="soc-card rounded-xl p-5 space-y-3">
        <h2 className="text-sm font-semibold text-slate-100">
          Active Containment &amp; Dynamic Firewall Rules
        </h2>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="border-b border-slate-800 text-[10px] uppercase text-slate-400">
              <tr>
                <th className="py-2 pr-3">Rule ID</th>
                <th className="py-2 pr-3">Source -&gt; Dest</th>
                <th className="py-2 pr-3">Proto / Port</th>
                <th className="py-2 pr-3">Action</th>
                <th className="py-2 pr-3">Incident / Author</th>
                <th className="py-2 pr-3">Status</th>
                <th className="py-2">Rollback</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {firewallRules.map((rule) => (
                <tr key={rule.rule_id}>
                  <td className="py-2.5 pr-3 font-bold text-cyan-300">{rule.rule_id}</td>
                  <td className="py-2.5 pr-3 text-slate-200">
                    {rule.source_ip} -&gt; {rule.destination_ip}
                  </td>
                  <td className="py-2.5 pr-3 text-slate-300">
                    {rule.protocol} / {rule.port}
                  </td>
                  <td className="py-2.5 pr-3">
                    <StatusBadge variant="critical" label={rule.action} />
                  </td>
                  <td className="py-2.5 pr-3 text-slate-400">
                    {rule.incident_id} • {rule.created_by}
                  </td>
                  <td className="py-2.5 pr-3">
                    <StatusBadge
                      variant={rule.active ? 'healthy' : 'offline'}
                      label={rule.active ? 'ENFORCED' : 'ROLLED BACK'}
                    />
                  </td>
                  <td className="py-2.5">
                    {rule.active ? (
                      <button
                        type="button"
                        onClick={() => rollbackFirewallRule(rule.rule_id)}
                        className="inline-flex items-center gap-1 rounded border border-rose-500/40 bg-rose-500/10 px-2 py-1 text-[11px] text-rose-200 hover:bg-rose-500/20 cursor-pointer"
                      >
                        <RotateCcw className="h-3 w-3" /> Rollback
                      </button>
                    ) : (
                      <span className="text-slate-500">Reverted</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Human-in-the-Loop Approval Modal */}
      <Modal
        open={Boolean(selectedAction)}
        onClose={() => setSelectedAction(null)}
        title="Human-in-the-Loop Containment Approval"
        subtitle={
          selectedAction
            ? `${selectedAction.action_id} • ${selectedAction.incident_reference} • Operator: ${currentUser.full_name}`
            : ''
        }
      >
        {selectedAction && (
          <form onSubmit={handleConfirmApproval} className="space-y-4">
            {/* Summary Grid */}
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 text-xs font-mono">
              <div className="rounded-lg border border-slate-800 bg-slate-900/80 p-3">
                <p className="text-[10px] text-slate-400">INCIDENT ID</p>
                <p className="mt-0.5 font-bold text-cyan-300">{selectedAction.incident_reference}</p>
              </div>
              <div className="rounded-lg border border-slate-800 bg-slate-900/80 p-3">
                <p className="text-[10px] text-slate-400">TARGET ASSET</p>
                <p className="mt-0.5 font-bold text-slate-100">
                  {selectedAction.target_asset_id} ({selectedAction.target_ip})
                </p>
              </div>
              <div className="rounded-lg border border-slate-800 bg-slate-900/80 p-3">
                <p className="text-[10px] text-slate-400">REQUIRED RBAC ROLE</p>
                <p className="mt-0.5 font-bold text-amber-300">{selectedAction.required_role}</p>
              </div>
              <div className="rounded-lg border border-slate-800 bg-slate-900/80 p-3">
                <p className="text-[10px] text-slate-400">TARGET ZONE</p>
                <p className="mt-0.5 font-bold text-slate-100">{selectedAction.target_zone}</p>
              </div>
            </div>

            <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3 space-y-1 text-xs">
              <p className="font-mono text-[10px] uppercase text-slate-400">Containment Reason</p>
              <p className="text-slate-200">{selectedAction.reason}</p>
              <p className="pt-2 font-mono text-[10px] uppercase text-amber-300">
                Operational Impact Assessment
              </p>
              <p className="text-amber-100/90">{selectedAction.operational_impact}</p>
            </div>

            {/* OT Two-Person Rule Banner */}
            {selectedAction.is_ot_asset && (
              <div className="rounded-xl border border-rose-500/50 bg-rose-950/25 p-3.5 space-y-2.5">
                <div className="flex items-center gap-2 text-xs font-mono font-bold text-rose-300">
                  <Users className="h-4 w-4" />
                  TWO-PERSON RULE ENFORCED (MANUFACTURING OT VLAN 30)
                </div>
                <p className="text-xs text-rose-200/85">
                  Physical shopfloor safety requires secondary counter-signature from Plant Operations before pushing any VLAN 30 containment rule.
                </p>
                <div>
                  <label className="block text-[11px] font-mono text-slate-300 mb-1">
                    Secondary Approver (Plant Operations)
                  </label>
                  <select
                    value={secondApprover}
                    onChange={(e) => setSecondApprover(e.target.value)}
                    className="w-full rounded-lg border border-rose-500/40 bg-slate-950 px-3 py-2 text-xs font-mono text-slate-100"
                  >
                    <option value="approver_anita">Anita Deshmukh (Plant Ops Head — approver_anita)</option>
                    <option value="ot_lead_desai">Suresh Desai (SMT Shift Engineer — ot_lead_desai)</option>
                  </select>
                </div>
              </div>
            )}

            {/* MFA TOTP Input */}
            {!breakGlass && (
              <div>
                <label className="block text-xs font-mono text-slate-300 mb-1.5">
                  6-Digit MFA Verification Code{' '}
                  <span className="text-cyan-400">(Accepts 1xxxxx, e.g. 148290)</span>
                </label>
                <input
                  type="text"
                  maxLength={6}
                  value={mfaCode}
                  onChange={(e) => setMfaCode(e.target.value)}
                  placeholder="148290"
                  className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3.5 py-2.5 text-sm font-mono tracking-[0.35em] text-cyan-300 focus:border-cyan-400 focus:outline-none"
                />
              </div>
            )}

            {/* Emergency Break-Glass Override */}
            <div className="rounded-lg border border-amber-500/35 bg-amber-950/15 p-3 space-y-2">
              <label className="flex items-center gap-2 text-xs font-mono text-amber-300 cursor-pointer">
                <input
                  type="checkbox"
                  checked={breakGlass}
                  onChange={(e) => setBreakGlass(e.target.checked)}
                  className="rounded border-amber-500"
                />
                <ShieldOff className="h-3.5 w-3.5" />
                Emergency Break-Glass Override (Triggers Immediate CERT-In / CISO Audit Alert)
              </label>
              {breakGlass && (
                <textarea
                  rows={2}
                  value={breakGlassReason}
                  onChange={(e) => setBreakGlassReason(e.target.value)}
                  placeholder="Document emergency justification for break-glass bypass..."
                  className="w-full rounded-lg border border-amber-500/40 bg-slate-950 p-2 text-xs font-mono text-slate-200 focus:outline-none"
                />
              )}
            </div>

            {errorMsg && (
              <div className="flex items-center gap-2 rounded-lg border border-rose-500/50 bg-rose-500/15 px-3 py-2 text-xs text-rose-200">
                <AlertTriangle className="h-4 w-4 shrink-0 text-rose-400" />
                {errorMsg}
              </div>
            )}

            <div className="flex items-center justify-end gap-3 pt-2">
              <button
                type="button"
                onClick={() => setSelectedAction(null)}
                className="rounded-lg border border-slate-700 bg-slate-900 px-4 py-2 text-xs font-mono text-slate-300 hover:bg-slate-800 cursor-pointer"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={submitting}
                className="inline-flex items-center gap-2 rounded-lg border border-emerald-500/60 bg-emerald-500/20 px-4 py-2 text-xs font-mono font-bold text-emerald-200 hover:bg-emerald-500/30 cursor-pointer"
              >
                {breakGlass ? (
                  <>
                    <ShieldAlert className="h-4 w-4 text-amber-300" /> Execute Break-Glass
                  </>
                ) : (
                  <>
                    <CheckCircle2 className="h-4 w-4" /> Authorize &amp; Execute Containment
                  </>
                )}
              </button>
            </div>
          </form>
        )}
      </Modal>
    </div>
  );
};

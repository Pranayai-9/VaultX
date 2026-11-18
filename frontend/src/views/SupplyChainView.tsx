import React, { useEffect, useState } from 'react';
import {
  AlertTriangle,
  ArrowRight,
  Clock,
  GitBranch,
  KeyRound,
  Link2,
  Server,
  ShieldAlert,
  ShieldCheck,
  Terminal,
} from 'lucide-react';
import { VENDOR_INVENTORY, VENDOR_SESSIONS } from '../services/mockData';
import type { VendorSession } from '../types';
import { StatusBadge } from '../components/StatusBadge';

const TRUST_CHAIN = [
  { id: 'vpn', label: 'Vendor VPN', sub: 'DMZ-VPN-GW01', zone: 'VLAN 50', status: 'elevated', icon: KeyRound, detail: 'FortiGate SSL-VPN enforcing TOTP MFA + 4h hard session limit. Current anomaly: NL ASN 45102.' },
  { id: 'bastion', label: 'DMZ Bastion', sub: 'DMZ-BASTION01', zone: 'VLAN 50', status: 'elevated', icon: Terminal, detail: 'PAM jump host with full SSH/RDP session recording. Active pivot observed by techmaintain_ext_eng.' },
  { id: 'engws', label: 'Eng Workstation', sub: 'ENG-WS-002 / 005', zone: 'VLAN 20', status: 'warning', icon: Server, detail: 'Firmware & PLC programming endpoints. Authorized for CodeBridge CI and TIA Portal.' },
  { id: 'git', label: 'Gitea & OTA', sub: 'ENG-GITEA-01', zone: 'VLAN 20', status: 'warning', icon: GitBranch, detail: 'Source control + signed OTA staging. Flagged unsigned artifact feeder_cal_unsigned.hex.' },
  { id: 'mes', label: 'OT MES Bridge', sub: 'OT-MES01', zone: 'VLAN 30', status: 'critical', icon: ShieldAlert, detail: 'Shopfloor MES server bridging VLAN 30 PLCs. Protected by OT Two-Person Safety Interlock.' },
] as const;

export const SupplyChainView: React.FC = () => {
  const [sessions, setSessions] = useState<VendorSession[]>(VENDOR_SESSIONS);
  const [selectedChainNode, setSelectedChainNode] = useState<string>('bastion');
  const [revokedIds, setRevokedIds] = useState<string[]>([]);

  // Live 1-second ticking countdown for 4-hour vendor session timers
  useEffect(() => {
    const timer = window.setInterval(() => {
      setSessions((prev) =>
        prev.map((s) => ({
          ...s,
          remaining_seconds: Math.max(0, s.remaining_seconds - 1),
        })),
      );
    }, 1000);
    return () => window.clearInterval(timer);
  }, []);

  const formatCountdown = (sec: number) => {
    const h = Math.floor(sec / 3600);
    const m = Math.floor((sec % 3600) / 60);
    const s = sec % 60;
    return `${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
  };

  const activeChainInfo =
    TRUST_CHAIN.find((n) => n.id === selectedChainNode) || TRUST_CHAIN[1];

  return (
    <div className="space-y-6">
      {/* Interactive Trust Relationship Graph */}
      <div className="soc-card rounded-xl p-5 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
              <Link2 className="h-4 w-4 text-cyan-400" />
              Interactive Third-Party Trust Relationship Graph
            </h2>
            <p className="text-xs font-mono text-slate-400">
              Vendor VPN -&gt; DMZ Bastion -&gt; Eng Workstation -&gt; Git -&gt; MES (Click any hop to inspect trust boundary)
            </p>
          </div>
          <StatusBadge variant="warning" label="2 ACTIVE ANOMALIES ON CHAIN" pulse />
        </div>

        <div className="flex flex-col lg:flex-row items-stretch lg:items-center justify-between gap-2 overflow-x-auto pb-2">
          {TRUST_CHAIN.map((node, idx) => {
            const Icon = node.icon;
            const isSelected = selectedChainNode === node.id;
            return (
              <React.Fragment key={node.id}>
                <button
                  type="button"
                  onClick={() => setSelectedChainNode(node.id)}
                  className={`flex-1 min-w-[165px] rounded-xl border p-3.5 text-left transition-all cursor-pointer ${
                    isSelected
                      ? 'border-cyan-400 bg-cyan-500/12 ring-1 ring-cyan-400/50'
                      : 'border-slate-800 bg-slate-900/70 hover:border-slate-600'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-slate-950 border border-slate-700">
                      <Icon className="h-4 w-4 text-cyan-300" />
                    </div>
                    <StatusBadge
                      variant={node.status}
                      label={node.zone}
                    />
                  </div>
                  <p className="mt-2.5 text-xs font-bold text-slate-100">{node.label}</p>
                  <p className="text-[11px] font-mono text-slate-400">{node.sub}</p>
                </button>
                {idx < TRUST_CHAIN.length - 1 && (
                  <div className="hidden lg:flex items-center justify-center px-1 text-cyan-500/70">
                    <ArrowRight className="h-4 w-4 animate-pulse" />
                  </div>
                )}
              </React.Fragment>
            );
          })}
        </div>

        <div className="rounded-lg border border-cyan-500/30 bg-cyan-950/20 px-4 py-3 text-xs">
          <span className="font-mono font-bold text-cyan-300">
            [{activeChainInfo.label} • {activeChainInfo.sub}]
          </span>{' '}
          <span className="text-slate-200">{activeChainInfo.detail}</span>
        </div>
      </div>

      {/* Vendor Session Monitor with Live 4-Hour Countdown Timers */}
      <div className="soc-card rounded-xl p-5 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
              <Clock className="h-4 w-4 text-amber-400" />
              Active Vendor Sessions — 4-Hour Hard Session Countdown Monitor
            </h2>
            <p className="text-xs font-mono text-slate-400">
              BECPL Vendor Access Policy mandates MFA + maximum 4h continuous remote tunnel duration
            </p>
          </div>
          <span className="text-xs font-mono text-slate-400">
            Active Tunnels: {sessions.length - revokedIds.length} / {sessions.length}
          </span>
        </div>

        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          {sessions.map((sess) => {
            const isRevoked = revokedIds.includes(sess.session_id);
            const pctLeft = Math.round((sess.remaining_seconds / sess.max_seconds) * 100);
            const isLowTime = sess.remaining_seconds < 1800;

            return (
              <div
                key={sess.session_id}
                className={`rounded-xl border p-4 space-y-3 ${
                  isRevoked
                    ? 'border-slate-800 bg-slate-950/60 opacity-60'
                    : sess.is_anomalous
                      ? 'border-rose-500/50 bg-rose-950/15'
                      : 'border-slate-800 bg-slate-900/60'
                }`}
              >
                <div className="flex items-start justify-between gap-2">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs font-bold text-cyan-300">
                        {sess.session_id}
                      </span>
                      <StatusBadge
                        variant={isRevoked ? 'offline' : sess.is_anomalous ? 'critical' : 'healthy'}
                        label={isRevoked ? 'REVOKED' : sess.is_anomalous ? 'ANOMALOUS' : 'COMPLIANT'}
                        pulse={!isRevoked && sess.is_anomalous}
                      />
                    </div>
                    <h3 className="mt-1 text-sm font-semibold text-slate-100">
                      {sess.vendor_name}
                    </h3>
                    <p className="text-xs font-mono text-slate-400">
                      Principal: <span className="text-slate-200">{sess.principal_name}</span> •{' '}
                      {sess.source_ip} ({sess.source_geo})
                    </p>
                  </div>

                  {/* Live 4-Hour Countdown Clock */}
                  <div className="text-right shrink-0">
                    <p className="text-[10px] font-mono uppercase text-slate-400">TIME LEFT (4H MAX)</p>
                    <p
                      className={`text-lg font-bold telemetry-num ${
                        isRevoked
                          ? 'text-slate-500'
                          : isLowTime
                            ? 'text-rose-400'
                            : 'text-emerald-300'
                      }`}
                    >
                      {isRevoked ? '00:00:00' : formatCountdown(sess.remaining_seconds)}
                    </p>
                  </div>
                </div>

                {/* Progress Bar */}
                <div className="h-1.5 w-full overflow-hidden rounded-full bg-slate-800">
                  <div
                    className={`h-full transition-all ${
                      isRevoked
                        ? 'bg-slate-600'
                        : isLowTime
                          ? 'bg-rose-500'
                          : sess.is_anomalous
                            ? 'bg-amber-400'
                            : 'bg-emerald-400'
                    }`}
                    style={{ width: isRevoked ? '0%' : `${pctLeft}%` }}
                  />
                </div>

                <div className="flex flex-wrap items-center justify-between gap-2 text-[11px] font-mono text-slate-400">
                  <span>Path: {sess.entry_node} -&gt; {sess.target_resource}</span>
                  <span className="text-emerald-400 flex items-center gap-1">
                    <ShieldCheck className="h-3.5 w-3.5" /> MFA Verified
                  </span>
                </div>

                {sess.anomaly_reasons.length > 0 && !isRevoked && (
                  <div className="rounded-lg border border-rose-500/30 bg-rose-500/10 p-2.5 space-y-1">
                    {sess.anomaly_reasons.map((r) => (
                      <p key={r} className="text-[11px] text-rose-200 flex items-center gap-1.5">
                        <AlertTriangle className="h-3.5 w-3.5 shrink-0 text-rose-400" />
                        {r}
                      </p>
                    ))}
                  </div>
                )}

                {!isRevoked && (
                  <div className="flex justify-end">
                    <button
                      type="button"
                      onClick={() => setRevokedIds((prev) => [...prev, sess.session_id])}
                      className="rounded-lg border border-rose-500/50 bg-rose-500/15 px-3 py-1 text-xs font-mono font-semibold text-rose-200 hover:bg-rose-500/25 transition-colors cursor-pointer"
                    >
                      Terminate VPN Session
                    </button>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* Third-Party Trust Inventory Table */}
      <div className="soc-card rounded-xl p-5 space-y-3">
        <h2 className="text-sm font-semibold text-slate-100">
          Third-Party Vendor Trust Inventory (Siemens • CodeBridge • NetSolve • DTDC • AWS)
        </h2>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-slate-800 text-[10px] font-mono uppercase text-slate-400">
              <tr>
                <th className="py-2.5 pr-3">Vendor & Scope</th>
                <th className="py-2.5 pr-3">Trust Tier</th>
                <th className="py-2.5 pr-3">Authorized Zones</th>
                <th className="py-2.5 pr-3">MFA Compliance</th>
                <th className="py-2.5 pr-3">Risk Score</th>
                <th className="py-2.5">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {VENDOR_INVENTORY.map((v) => (
                <tr key={v.vendor_id} className="hover:bg-slate-800/30">
                  <td className="py-3 pr-3">
                    <p className="font-semibold text-slate-100">{v.vendor_name}</p>
                    <p className="text-[11px] text-slate-400">{v.service_scope}</p>
                  </td>
                  <td className="py-3 pr-3 font-mono text-cyan-300">{v.trust_tier}</td>
                  <td className="py-3 pr-3 font-mono text-[11px] text-slate-300">
                    {v.allowed_zones.join(', ')}
                  </td>
                  <td className="py-3 pr-3 font-mono telemetry-num text-emerald-300">
                    {v.mfa_compliance_pct.toFixed(1)}%
                  </td>
                  <td className="py-3 pr-3 font-mono font-bold telemetry-num">
                    <span
                      className={
                        v.risk_score >= 70
                          ? 'text-rose-400'
                          : v.risk_score >= 40
                            ? 'text-amber-300'
                            : 'text-emerald-300'
                      }
                    >
                      {v.risk_score}/100
                    </span>
                  </td>
                  <td className="py-3">
                    <StatusBadge
                      variant={
                        v.compliance_status === 'policy_violation'
                          ? 'critical'
                          : v.compliance_status === 'review_required'
                            ? 'warning'
                            : 'healthy'
                      }
                      label={v.compliance_status.replace('_', ' ')}
                    />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

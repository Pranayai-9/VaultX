import React, { useState } from 'react';
import {
  CalendarClock,
  CheckCircle2,
  Database,
  Plus,
  Settings,
  Shield,
  Users,
} from 'lucide-react';
import {
  MAINTENANCE_WINDOWS,
  RETENTION_RULES,
  USER_PERSONAS,
} from '../services/mockData';
import type { MaintenanceWindow } from '../types';
import { StatusBadge } from '../components/StatusBadge';

const RBAC_MATRIX = [
  { role: 'ANALYST', tier: 'Tier 1', viewDash: true, triageInc: true, proposeAct: true, approveIt: false, approveOt: false, adminPolicy: false },
  { role: 'OPERATOR', tier: 'Tier 2', viewDash: true, triageInc: true, proposeAct: true, approveIt: true, approveOt: false, adminPolicy: false },
  { role: 'APPROVER', tier: 'Tier 3', viewDash: true, triageInc: true, proposeAct: true, approveIt: true, approveOt: true, adminPolicy: false },
  { role: 'SECURITY_MANAGER', tier: 'Tier 4', viewDash: true, triageInc: true, proposeAct: true, approveIt: true, approveOt: true, adminPolicy: true },
  { role: 'ADMIN', tier: 'Tier 5', viewDash: true, triageInc: true, proposeAct: true, approveIt: true, approveOt: true, adminPolicy: true },
];

export const AdminPoliciesView: React.FC = () => {
  const [windows, setWindows] = useState<MaintenanceWindow[]>(MAINTENANCE_WINDOWS);
  const [newTitle, setNewTitle] = useState('');
  const [newZone, setNewZone] = useState('Manufacturing OT');
  const [maxIsolationHours, setMaxIsolationHours] = useState(24);
  const [vendorSessionMaxHours, setVendorSessionMaxHours] = useState(4);
  const [otTwoPersonEnforced, setOtTwoPersonEnforced] = useState(true);
  const [savedMsg, setSavedMsg] = useState<string | null>(null);

  const handleAddWindow = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTitle.trim()) return;
    const created: MaintenanceWindow = {
      window_id: `MW-2026-${Math.floor(20 + Math.random() * 79)}`,
      title: newTitle.trim(),
      start_time: '2026-11-20 01:00 IST',
      end_time: '2026-11-20 03:00 IST',
      target_zones: [newZone],
      target_assets: ['ALL_ZONE_ASSETS'],
      approver: 'Rajesh Kumar (Security Manager)',
      suppress_alerts: true,
      status: 'scheduled',
    };
    setWindows((prev) => [created, ...prev]);
    setNewTitle('');
  };

  const handleSavePolicy = () => {
    setSavedMsg(
      `Isolation policy updated: Max isolation TTL=${maxIsolationHours}h, Vendor VPN limit=${vendorSessionMaxHours}h, OT Two-Person Rule=${otTwoPersonEnforced ? 'LOCKED' : 'OFF'}.`,
    );
  };

  return (
    <div className="space-y-6">
      {/* 5-Tier RBAC Matrix & Active Staff Directory */}
      <div className="soc-card rounded-xl p-5 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
              <Users className="h-4 w-4 text-cyan-400" />
              5-Tier Role-Based Access Control (RBAC) Governance
            </h2>
            <p className="text-xs font-mono text-slate-400">
              Strict separation of duties across BECPL SOC Analysts, Operators, Plant Approvers &amp; Security Managers
            </p>
          </div>
          <StatusBadge variant="healthy" label="5 RBAC TIERS ENFORCED" />
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="border-b border-slate-800 text-[10px] uppercase text-slate-400">
              <tr>
                <th className="py-2 pr-3">Tier / Role</th>
                <th className="py-2 pr-3">Assigned BECPL User</th>
                <th className="py-2 pr-3 text-center">View Telemetry</th>
                <th className="py-2 pr-3 text-center">Propose Action</th>
                <th className="py-2 pr-3 text-center">Approve IT</th>
                <th className="py-2 pr-3 text-center">Approve OT (2-Person)</th>
                <th className="py-2 text-center">Policy &amp; Model Gate</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {RBAC_MATRIX.map((row) => {
                const persona = USER_PERSONAS.find((p) => p.role === row.role);
                const cell = (v: boolean) =>
                  v ? (
                    <span className="text-emerald-400 font-bold">ALLOW</span>
                  ) : (
                    <span className="text-slate-600">DENY</span>
                  );
                return (
                  <tr key={row.role}>
                    <td className="py-2.5 pr-3">
                      <span className="text-cyan-300 font-bold">{row.role}</span>
                      <span className="ml-2 text-[10px] text-slate-500">{row.tier}</span>
                    </td>
                    <td className="py-2.5 pr-3 text-slate-200">
                      {persona ? `${persona.full_name} (${persona.username})` : '-'}
                    </td>
                    <td className="py-2.5 pr-3 text-center">{cell(row.viewDash)}</td>
                    <td className="py-2.5 pr-3 text-center">{cell(row.proposeAct)}</td>
                    <td className="py-2.5 pr-3 text-center">{cell(row.approveIt)}</td>
                    <td className="py-2.5 pr-3 text-center">{cell(row.approveOt)}</td>
                    <td className="py-2.5 text-center">{cell(row.adminPolicy)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Isolation Policy Editor + Scheduled Maintenance Windows */}
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-12">
        {/* Isolation Policy Editor */}
        <div className="soc-card rounded-xl p-5 xl:col-span-5 space-y-4">
          <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
            <Shield className="h-4 w-4 text-amber-400" />
            Isolation &amp; Safety Policy Editor
          </h2>

          <div className="space-y-3 text-xs font-mono">
            <div>
              <label className="block text-slate-400 mb-1">
                Max Automatic Isolation TTL (Hours)
              </label>
              <input
                type="number"
                min={1}
                max={72}
                value={maxIsolationHours}
                onChange={(e) => setMaxIsolationHours(Number(e.target.value))}
                className="w-full rounded-lg border border-slate-800 bg-slate-950 px-3 py-2 text-cyan-300"
              />
            </div>

            <div>
              <label className="block text-slate-400 mb-1">
                Vendor Remote VPN Hard Cutoff (Hours)
              </label>
              <input
                type="number"
                min={1}
                max={12}
                value={vendorSessionMaxHours}
                onChange={(e) => setVendorSessionMaxHours(Number(e.target.value))}
                className="w-full rounded-lg border border-slate-800 bg-slate-950 px-3 py-2 text-cyan-300"
              />
            </div>

            <label className="flex items-center justify-between rounded-lg border border-rose-500/40 bg-rose-950/15 p-3 cursor-pointer">
              <div>
                <p className="font-bold text-rose-300">Mandatory OT Two-Person Rule</p>
                <p className="text-[10px] text-rose-200/80">
                  Require secondary Plant Ops approval for VLAN 30 actions
                </p>
              </div>
              <input
                type="checkbox"
                checked={otTwoPersonEnforced}
                onChange={(e) => setOtTwoPersonEnforced(e.target.checked)}
                className="h-4 w-4"
              />
            </label>

            <button
              type="button"
              onClick={handleSavePolicy}
              className="w-full inline-flex items-center justify-center gap-2 rounded-lg border border-cyan-500/60 bg-cyan-500/15 px-4 py-2 font-bold text-cyan-200 hover:bg-cyan-500/25 cursor-pointer"
            >
              <Settings className="h-3.5 w-3.5" /> Save Global Policy Parameters
            </button>

            {savedMsg && (
              <div className="flex items-center gap-2 rounded-lg border border-emerald-500/40 bg-emerald-500/10 p-2.5 text-[11px] text-emerald-200">
                <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-400" />
                {savedMsg}
              </div>
            )}
          </div>
        </div>

        {/* Scheduled Maintenance Windows */}
        <div className="soc-card rounded-xl p-5 xl:col-span-7 space-y-4">
          <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
            <CalendarClock className="h-4 w-4 text-cyan-400" />
            Scheduled Maintenance Windows (Behavioural Alert Suppression)
          </h2>

          <form onSubmit={handleAddWindow} className="flex flex-wrap gap-2">
            <input
              type="text"
              value={newTitle}
              onChange={(e) => setNewTitle(e.target.value)}
              placeholder="New maintenance window title (e.g. PLC Firmware Audit)..."
              className="flex-1 min-w-[200px] rounded-lg border border-slate-800 bg-slate-950 px-3 py-1.5 text-xs font-mono text-slate-200 focus:border-cyan-500 focus:outline-none"
            />
            <select
              value={newZone}
              onChange={(e) => setNewZone(e.target.value)}
              className="rounded-lg border border-slate-800 bg-slate-950 px-2.5 py-1.5 text-xs font-mono text-slate-300"
            >
              <option>Manufacturing OT</option>
              <option>Engineering &amp; Firmware</option>
              <option>Corporate IT</option>
              <option>DMZ &amp; Vendor Access</option>
            </select>
            <button
              type="submit"
              className="inline-flex items-center gap-1 rounded-lg border border-emerald-500/50 bg-emerald-500/15 px-3 py-1.5 text-xs font-mono font-semibold text-emerald-200 hover:bg-emerald-500/25 cursor-pointer"
            >
              <Plus className="h-3.5 w-3.5" /> Schedule
            </button>
          </form>

          <div className="space-y-2.5">
            {windows.map((mw) => (
              <div
                key={mw.window_id}
                className="rounded-xl border border-slate-800 bg-slate-900/60 p-3 text-xs font-mono space-y-1"
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="font-bold text-slate-100">
                    {mw.window_id} • {mw.title}
                  </span>
                  <StatusBadge
                    variant={mw.status === 'scheduled' ? 'cyan' : 'healthy'}
                    label={mw.status}
                  />
                </div>
                <p className="text-[11px] text-cyan-300">
                  {mw.start_time} -&gt; {mw.end_time}
                </p>
                <p className="text-[11px] text-slate-400">
                  Zones: {mw.target_zones.join(', ')} • Approver: {mw.approver}
                </p>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Data Retention & Compliance Rules */}
      <div className="soc-card rounded-xl p-5 space-y-3">
        <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
          <Database className="h-4 w-4 text-indigo-400" />
          Data Retention &amp; CERT-In / ISO 9001 Compliance Policies
        </h2>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="border-b border-slate-800 text-[10px] uppercase text-slate-400">
              <tr>
                <th className="py-2 pr-3">Data Class</th>
                <th className="py-2 pr-3">Hot (NVMe)</th>
                <th className="py-2 pr-3">Warm (S3)</th>
                <th className="py-2 pr-3">Cold Archive</th>
                <th className="py-2 pr-3">Encryption</th>
                <th className="py-2">Compliance</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {RETENTION_RULES.map((r) => (
                <tr key={r.id}>
                  <td className="py-2.5 pr-3 text-slate-100 font-sans font-medium">
                    {r.data_class}
                  </td>
                  <td className="py-2.5 pr-3 text-cyan-300">{r.hot_days}d</td>
                  <td className="py-2.5 pr-3 text-slate-300">{r.warm_days}d</td>
                  <td className="py-2.5 pr-3 text-slate-300">{r.cold_archive_days}d</td>
                  <td className="py-2.5 pr-3 text-emerald-300">{r.encryption}</td>
                  <td className="py-2.5">
                    <StatusBadge variant="purple" label={r.compliance_tag} />
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

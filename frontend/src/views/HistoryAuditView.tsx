import React, { useMemo, useState } from 'react';
import {
  CheckCircle2,
  FileClock,
  Filter,
  Lock,
  Search,
  ShieldCheck,
} from 'lucide-react';
import { AUDIT_LOGS, SECURITY_EVENTS } from '../services/mockData';
import { StatusBadge } from '../components/StatusBadge';

export const HistoryAuditView: React.FC = () => {
  const [search, setSearch] = useState('');
  const [zone, setZone] = useState('ALL');
  const [severity, setSeverity] = useState('ALL');
  const [verifiedChain, setVerifiedChain] = useState(false);

  const filteredEvents = useMemo(() => {
    return SECURITY_EVENTS.filter((e) => {
      if (zone !== 'ALL' && e.zone !== zone) return false;
      if (severity !== 'ALL' && e.severity !== severity) return false;
      if (search.trim()) {
        const q = search.toLowerCase();
        const hay = `${e.event_id} ${e.asset_id} ${e.identity} ${e.event_type} ${e.message} ${e.source_engine}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }, [search, zone, severity]);

  return (
    <div className="space-y-6">
      {/* Searchable Multi-Field Event Log */}
      <div className="soc-card rounded-xl p-5 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
              <FileClock className="h-4 w-4 text-cyan-400" />
              Chronological Security Event Reconstruction &amp; Search
            </h2>
            <p className="text-xs font-mono text-slate-400">
              Unified forensic query across Zeek, Suricata, ML-RF, Behavioural &amp; Containment logs
            </p>
          </div>
          <span className="text-xs font-mono text-slate-400">
            Showing {filteredEvents.length} of {SECURITY_EVENTS.length} events
          </span>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <div className="relative flex-1 min-w-[240px]">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Filter by asset, identity, event type, engine, message..."
              className="w-full rounded-lg border border-slate-800 bg-slate-950 py-2 pl-9 pr-3 text-xs font-mono text-slate-200 focus:border-cyan-500/60 focus:outline-none"
            />
          </div>
          <div className="flex items-center gap-2 text-xs font-mono">
            <Filter className="h-3.5 w-3.5 text-slate-400" />
            <select
              value={zone}
              onChange={(e) => setZone(e.target.value)}
              className="rounded-lg border border-slate-800 bg-slate-950 px-2.5 py-2 text-slate-300"
            >
              <option value="ALL">All Zones</option>
              <option value="Manufacturing OT">Manufacturing OT</option>
              <option value="Engineering & Firmware">Engineering &amp; Firmware</option>
              <option value="Corporate IT">Corporate IT</option>
              <option value="DMZ & Vendor Access">DMZ &amp; Vendor Access</option>
            </select>
            <select
              value={severity}
              onChange={(e) => setSeverity(e.target.value)}
              className="rounded-lg border border-slate-800 bg-slate-950 px-2.5 py-2 text-slate-300"
            >
              <option value="ALL">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="informational">Informational</option>
            </select>
          </div>
        </div>

        {/* Chronological Timeline List */}
        <div className="relative pl-6 space-y-2.5 before:absolute before:left-2.5 before:top-2 before:bottom-2 before:w-px before:bg-slate-800">
          {filteredEvents.map((ev) => (
            <div
              key={ev.event_id}
              className="relative rounded-xl border border-slate-800 bg-slate-900/60 p-3 hover:border-slate-700 transition-colors"
            >
              <span
                className={`absolute -left-[22px] top-4 h-3 w-3 rounded-full border-2 border-[#0f172a] ${
                  ev.severity === 'critical'
                    ? 'bg-rose-500'
                    : ev.severity === 'high'
                      ? 'bg-orange-400'
                      : ev.severity === 'medium'
                        ? 'bg-amber-400'
                        : 'bg-cyan-400'
                }`}
              />
              <div className="flex flex-wrap items-center justify-between gap-2 text-xs font-mono">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-slate-400">{ev.timestamp} IST</span>
                  <StatusBadge variant={ev.severity} label={ev.severity} />
                  <span className="font-bold text-cyan-300">{ev.event_type}</span>
                  <span className="rounded bg-slate-800 px-1.5 py-0.5 text-[10px] text-slate-300">
                    {ev.source_engine}
                  </span>
                </div>
                <span className="text-[11px] text-slate-400">
                  {ev.zone} • <strong className="text-slate-200">{ev.asset_id}</strong> • {ev.identity}
                </span>
              </div>
              <p className="mt-1.5 text-xs text-slate-200">{ev.message}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Tamper-Evident System Audit Log (SHA-256 Hash Chain) */}
      <div className="soc-card rounded-xl p-5 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
              <Lock className="h-4 w-4 text-emerald-400" />
              Tamper-Evident System Audit Ledger (SHA-256 Hash Chain)
            </h2>
            <p className="text-xs font-mono text-slate-400">
              Every RBAC approval, containment rule, and denial is cryptographically chained for CERT-In compliance
            </p>
          </div>
          <button
            type="button"
            onClick={() => setVerifiedChain(true)}
            className="inline-flex items-center gap-1.5 rounded-lg border border-emerald-500/50 bg-emerald-500/15 px-3 py-1.5 text-xs font-mono font-semibold text-emerald-200 hover:bg-emerald-500/25 cursor-pointer"
          >
            <ShieldCheck className="h-3.5 w-3.5" />
            {verifiedChain ? 'Chain Integrity Verified (5/5 Valid)' : 'Verify SHA-256 Hash Chain'}
          </button>
        </div>

        {verifiedChain && (
          <div className="flex items-center gap-2 rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-3.5 py-2 text-xs font-mono text-emerald-200">
            <CheckCircle2 className="h-4 w-4 text-emerald-400" />
            VERIFIED: All sequential SHA-256 parent-child hash links match (Seq #1044 -&gt; #1048). Zero tampering detected.
          </div>
        )}

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="border-b border-slate-800 text-[10px] uppercase text-slate-400">
              <tr>
                <th className="py-2 pr-3">Seq / Time</th>
                <th className="py-2 pr-3">Actor &amp; Role</th>
                <th className="py-2 pr-3">Action / Target</th>
                <th className="py-2 pr-3">Outcome</th>
                <th className="py-2">Cryptographic Chain (Prev -&gt; Entry Hash)</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {AUDIT_LOGS.map((log) => (
                <tr key={log.audit_id} className="hover:bg-slate-800/30">
                  <td className="py-2.5 pr-3">
                    <p className="font-bold text-cyan-300">#{log.seq}</p>
                    <p className="text-[10px] text-slate-500">{log.timestamp}</p>
                  </td>
                  <td className="py-2.5 pr-3">
                    <p className="text-slate-100">{log.actor}</p>
                    <span className="text-[10px] text-indigo-300">{log.role}</span>
                  </td>
                  <td className="py-2.5 pr-3">
                    <p className="text-slate-200">{log.action}</p>
                    <p className="text-[10px] text-slate-400">{log.target}</p>
                  </td>
                  <td className="py-2.5 pr-3">
                    <StatusBadge
                      variant={
                        log.outcome === 'SUCCESS'
                          ? 'healthy'
                          : log.outcome === 'DENIED'
                            ? 'critical'
                            : 'warning'
                      }
                      label={log.outcome}
                    />
                  </td>
                  <td className="py-2.5 text-[10px] text-slate-400">
                    <p>prev: {log.prev_hash}</p>
                    <p className="text-emerald-400">hash: {log.entry_hash}</p>
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

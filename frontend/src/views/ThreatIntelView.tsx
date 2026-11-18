import React, { useState } from 'react';
import {
  AlertTriangle,
  ArrowRight,
  Fingerprint,
  Globe,
  Search,
  ShieldAlert,
} from 'lucide-react';
import {
  EXPLOITATION_LADDER,
  IP_BLOCKLIST,
  JA3_FINGERPRINTS,
  KEV_CATALOG,
} from '../services/mockData';
import type { ExploitationStage } from '../types';
import { StatusBadge } from '../components/StatusBadge';

const LADDER_STAGES: { id: ExploitationStage; label: string; color: string }[] = [
  { id: 'EXPOSED', label: '1. EXPOSED', color: 'border-sky-500/40 bg-sky-500/10 text-sky-300' },
  { id: 'ATTACK_ATTEMPT', label: '2. ATTACK ATTEMPT', color: 'border-amber-500/40 bg-amber-500/10 text-amber-300' },
  { id: 'POTENTIAL_EXPLOITATION', label: '3. POTENTIAL EXPLOITATION', color: 'border-orange-500/50 bg-orange-500/15 text-orange-300' },
  { id: 'CONFIRMED_COMPROMISE', label: '4. CONFIRMED COMPROMISE', color: 'border-rose-500/60 bg-rose-500/15 text-rose-300' },
];

export const ThreatIntelView: React.FC = () => {
  const [kevQuery, setKevQuery] = useState('');
  const [ja3Input, setJa3Input] = useState('e7d705a3286e19ea42f587b344ee6865');
  const [ja3Result, setJa3Result] = useState<string | null>(null);

  const filteredKev = KEV_CATALOG.filter((k) => {
    if (!kevQuery.trim()) return true;
    const q = kevQuery.toLowerCase();
    return `${k.cve_id} ${k.vendor_project} ${k.product} ${k.vulnerability_name}`.toLowerCase().includes(q);
  });

  const handleJa3Lookup = () => {
    const found = JA3_FINGERPRINTS.find(
      (f) => f.ja3_hash.toLowerCase() === ja3Input.trim().toLowerCase(),
    );
    if (found) {
      setJa3Result(
        `MATCHED THREAT: ${found.threat_name} (${found.malware_family}) • Confidence ${(found.confidence * 100).toFixed(0)}% • Status: ${found.status.toUpperCase()}`,
      );
    } else {
      setJa3Result('CLEAN: No known malware family match in VaultX JA3 intelligence feed.');
    }
  };

  return (
    <div className="space-y-6">
      {/* Exploitation Ladder Visualizer */}
      <div className="soc-card rounded-xl p-5 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
              <ShieldAlert className="h-4 w-4 text-rose-400" />
              Live Exploitation Ladder Visualizer
            </h2>
            <p className="text-xs font-mono text-slate-400">
              Correlates passive vulnerability inventory with real-time Zeek/Suricata exploit telemetry
            </p>
          </div>
          <div className="flex items-center gap-1.5 text-[10px] font-mono text-slate-400">
            <span>EXPOSED</span>
            <ArrowRight className="h-3 w-3" />
            <span>ATTACK ATTEMPT</span>
            <ArrowRight className="h-3 w-3" />
            <span>POTENTIAL EXPLOIT</span>
            <ArrowRight className="h-3 w-3" />
            <span className="text-rose-300 font-bold">CONFIRMED COMPROMISE</span>
          </div>
        </div>

        <div className="grid grid-cols-1 gap-4 lg:grid-cols-4">
          {LADDER_STAGES.map((stage) => {
            const items = EXPLOITATION_LADDER.filter((i) => i.stage === stage.id);
            return (
              <div
                key={stage.id}
                className="rounded-xl border border-slate-800 bg-slate-950/60 p-3.5 flex flex-col gap-3"
              >
                <div className={`rounded-lg border px-2.5 py-1.5 text-[11px] font-mono font-bold ${stage.color}`}>
                  {stage.label} ({items.length})
                </div>
                {items.map((item) => (
                  <div
                    key={item.id}
                    className="rounded-lg border border-slate-800 bg-slate-900/80 p-3 space-y-1.5"
                  >
                    <div className="flex items-center justify-between text-xs font-mono">
                      <span className="font-bold text-slate-100">{item.asset_id}</span>
                      <span className="text-cyan-400">{item.cve_id}</span>
                    </div>
                    <p className="text-[11px] text-slate-300 leading-snug">{item.evidence}</p>
                    <div className="flex items-center justify-between pt-1 text-[10px] font-mono text-slate-500">
                      <span>{item.zone}</span>
                      <span>{item.incident_ref || item.updated_at}</span>
                    </div>
                  </div>
                ))}
              </div>
            );
          })}
        </div>
      </div>

      {/* CISA KEV Catalog Integration */}
      <div className="soc-card rounded-xl p-5 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-amber-400" />
              CISA KEV Catalog & BECPL Asset Correlation
            </h2>
            <p className="text-xs font-mono text-slate-400">
              Known Exploited Vulnerabilities actively mapped against BECPL Pune host inventory
            </p>
          </div>
          <div className="relative w-full sm:w-72">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-500" />
            <input
              type="text"
              value={kevQuery}
              onChange={(e) => setKevQuery(e.target.value)}
              placeholder="Search CVE, vendor, product..."
              className="w-full rounded-lg border border-slate-800 bg-slate-950 py-1.5 pl-8 pr-3 text-xs font-mono text-slate-200 focus:border-cyan-500/60 focus:outline-none"
            />
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-slate-800 text-[10px] font-mono uppercase text-slate-400">
              <tr>
                <th className="py-2 pr-3">CVE ID</th>
                <th className="py-2 pr-3">Vendor / Product</th>
                <th className="py-2 pr-3">BECPL Exposure</th>
                <th className="py-2 pr-3">Ransomware Use</th>
                <th className="py-2">Required Action & Due Date</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {filteredKev.map((kev) => (
                <tr key={kev.cve_id} className="hover:bg-slate-800/30">
                  <td className="py-3 pr-3 font-mono font-bold text-rose-300">{kev.cve_id}</td>
                  <td className="py-3 pr-3">
                    <p className="font-semibold text-slate-100">{kev.vendor_project} — {kev.product}</p>
                    <p className="text-[11px] text-slate-400">{kev.short_description}</p>
                  </td>
                  <td className="py-3 pr-3 font-mono">
                    {kev.affected_becpl_assets.map((a) => (
                      <span
                        key={a}
                        className="mr-1 inline-block rounded border border-rose-500/40 bg-rose-500/10 px-1.5 py-0.5 text-[10px] text-rose-300"
                      >
                        {a}
                      </span>
                    ))}
                  </td>
                  <td className="py-3 pr-3">
                    <StatusBadge
                      variant={kev.known_ransomware_campaign_use === 'Known' ? 'critical' : 'warning'}
                      label={kev.known_ransomware_campaign_use}
                    />
                  </td>
                  <td className="py-3 text-xs text-slate-300">
                    <p>{kev.required_action}</p>
                    <p className="mt-0.5 font-mono text-[10px] text-amber-300">Due: {kev.due_date}</p>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Bottom Row: IP Blocklist Feed + JA3 Malware Fingerprints */}
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        {/* IP Blocklist */}
        <div className="soc-card rounded-xl p-5 space-y-3">
          <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
            <Globe className="h-4 w-4 text-cyan-400" />
            Active Threat IP Blocklist Feed
          </h2>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="border-b border-slate-800 text-[10px] uppercase text-slate-400">
                <tr>
                  <th className="py-2 pr-2">IP / ASN</th>
                  <th className="py-2 pr-2">Category</th>
                  <th className="py-2 pr-2">Feed</th>
                  <th className="py-2">Hits (24h)</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70">
                {IP_BLOCKLIST.map((b) => (
                  <tr key={b.ip_address}>
                    <td className="py-2.5 pr-2">
                      <p className="text-rose-300 font-semibold">{b.ip_address}</p>
                      <p className="text-[10px] text-slate-500">{b.asn} • {b.country}</p>
                    </td>
                    <td className="py-2.5 pr-2">
                      <StatusBadge variant="high" label={b.category} />
                    </td>
                    <td className="py-2.5 pr-2 text-slate-300 text-[11px]">{b.source_feed}</td>
                    <td className="py-2.5 text-amber-300 font-bold telemetry-num">{b.hits_24h}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* JA3 Malware Fingerprint Matcher */}
        <div className="soc-card rounded-xl p-5 space-y-4">
          <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
            <Fingerprint className="h-4 w-4 text-indigo-400" />
            JA3 / JA3S Encrypted TLS Malware Fingerprints
          </h2>

          {/* Interactive JA3 Tester */}
          <div className="rounded-lg border border-slate-800 bg-slate-950/70 p-3 space-y-2">
            <label className="text-[10px] font-mono uppercase text-slate-400">
              Instant JA3 Hash Threat Verification
            </label>
            <div className="flex gap-2">
              <input
                type="text"
                value={ja3Input}
                onChange={(e) => setJa3Input(e.target.value)}
                className="flex-1 rounded-lg border border-slate-800 bg-slate-900 px-3 py-1.5 text-xs font-mono text-cyan-300 focus:border-cyan-500/60 focus:outline-none"
              />
              <button
                type="button"
                onClick={handleJa3Lookup}
                className="rounded-lg border border-cyan-500/50 bg-cyan-500/15 px-3 py-1.5 text-xs font-mono font-semibold text-cyan-200 hover:bg-cyan-500/25"
              >
                Check JA3
              </button>
            </div>
            {ja3Result && (
              <p
                className={`text-[11px] font-mono ${
                  ja3Result.startsWith('MATCHED') ? 'text-rose-300' : 'text-emerald-300'
                }`}
              >
                {ja3Result}
              </p>
            )}
          </div>

          <div className="space-y-2">
            {JA3_FINGERPRINTS.map((fp) => (
              <div
                key={fp.ja3_hash}
                className="flex items-center justify-between rounded-lg border border-slate-800 bg-slate-900/60 px-3 py-2 text-xs font-mono"
              >
                <div className="min-w-0">
                  <p className="text-slate-100 font-semibold">{fp.threat_name}</p>
                  <p className="text-[10px] text-cyan-400 truncate">{fp.ja3_hash}</p>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <span className="text-[11px] text-slate-400">{fp.matched_flows} flows</span>
                  <StatusBadge
                    variant={fp.status === 'alerting' ? 'critical' : fp.status === 'blocked' ? 'purple' : 'cyan'}
                    label={fp.status}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

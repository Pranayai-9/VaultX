import React, { useState } from 'react';
import { Bug, CheckCircle2, Flame, ShieldAlert, Wrench } from 'lucide-react';
import { VULNERABILITIES } from '../services/mockData';
import { StatusBadge } from '../components/StatusBadge';

export const VulnerabilitiesView: React.FC = () => {
  const [severityFilter, setSeverityFilter] = useState<'ALL' | 'critical' | 'high'>('ALL');
  const [patchedCves, setPatchedCves] = useState<string[]>([]);

  const testTargets = VULNERABILITIES.filter((v) => v.is_test_target);
  const filteredVulns = VULNERABILITIES.filter((v) =>
    severityFilter === 'ALL' ? true : v.severity === severityFilter,
  );

  return (
    <div className="space-y-6">
      {/* Intentionally Vulnerable Phase 3 Test Assets Highlight Cards */}
      <div>
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
          <div>
            <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
              <Flame className="h-4 w-4 text-rose-400" />
              Intentionally Vulnerable Phase 3 Validation Assets (4 Core Targets)
            </h2>
            <p className="text-xs font-mono text-slate-400">
              SMBGhost (CVE-2020-0796) • OpenSSH 7.4 • Flask 1.0 Debug Console • Nginx 1.14
            </p>
          </div>
          <StatusBadge variant="critical" label="4 CRITICAL TARGETS MONITORED" pulse />
        </div>

        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
          {testTargets.map((vuln) => {
            const primaryAsset = vuln.affected_assets[0];
            const isMitigated = patchedCves.includes(vuln.cve_id);
            return (
              <div
                key={vuln.cve_id}
                className={`soc-card rounded-xl p-4 flex flex-col justify-between space-y-3 border ${
                  isMitigated ? 'border-emerald-500/40' : 'border-rose-500/40'
                }`}
              >
                <div className="space-y-2">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono text-xs font-bold text-rose-300">
                      {vuln.cve_id}
                    </span>
                    <span className="rounded bg-rose-500/20 px-2 py-0.5 text-xs font-mono font-bold text-rose-200 telemetry-num">
                      CVSS {vuln.cvss_score.toFixed(1)}
                    </span>
                  </div>
                  <h3 className="text-sm font-bold text-slate-100 leading-snug">{vuln.title}</h3>
                  <p className="text-[11px] font-mono text-cyan-300">
                    {primaryAsset.asset_id} ({primaryAsset.ip}) • {primaryAsset.zone}
                  </p>
                  <p className="text-xs text-slate-400 leading-relaxed">{vuln.description}</p>
                </div>

                <div className="space-y-2 border-t border-slate-800 pt-3">
                  <div className="flex items-center justify-between text-[11px] font-mono">
                    <span className="text-slate-400">Composite Risk Score</span>
                    <span className="font-bold text-amber-300 telemetry-num">
                      {primaryAsset.priority_risk_score}/100
                    </span>
                  </div>
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex gap-1.5">
                      {vuln.in_cisa_kev && <StatusBadge variant="critical" label="KEV" />}
                      {vuln.exploit_available && <StatusBadge variant="high" label="EXPLOIT" />}
                    </div>
                    <button
                      type="button"
                      onClick={() =>
                        setPatchedCves((prev) =>
                          prev.includes(vuln.cve_id) ? prev : [...prev, vuln.cve_id],
                        )
                      }
                      className={`rounded-lg border px-2.5 py-1 text-[11px] font-mono font-semibold transition-colors cursor-pointer ${
                        isMitigated
                          ? 'border-emerald-500/40 bg-emerald-500/15 text-emerald-300'
                          : 'border-cyan-500/50 bg-cyan-500/15 text-cyan-200 hover:bg-cyan-500/25'
                      }`}
                    >
                      {isMitigated ? (
                        <span className="inline-flex items-center gap-1">
                          <CheckCircle2 className="h-3 w-3" /> Patch Queued
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1">
                          <Wrench className="h-3 w-3" /> Queue Patch
                        </span>
                      )}
                    </button>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Prioritised Risk Matrix (CVSS × Criticality × Exposure) */}
      <div className="soc-card rounded-xl p-5 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
              <Bug className="h-4 w-4 text-amber-400" />
              Asset Software Inventory & Prioritised Risk Matrix (CVSS × Criticality × Exposure)
            </h2>
            <p className="text-xs font-mono text-slate-400">
              Weighted vulnerability prioritization balancing exploitability against OT/business criticality
            </p>
          </div>
          <div className="flex items-center gap-2">
            {(['ALL', 'critical', 'high'] as const).map((lvl) => (
              <button
                key={lvl}
                type="button"
                onClick={() => setSeverityFilter(lvl)}
                className={`rounded-lg border px-3 py-1 text-xs font-mono uppercase cursor-pointer ${
                  severityFilter === lvl
                    ? 'border-cyan-500/60 bg-cyan-500/15 text-cyan-200'
                    : 'border-slate-800 bg-slate-900 text-slate-400 hover:text-slate-200'
                }`}
              >
                {lvl}
              </button>
            ))}
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-slate-800 text-[10px] font-mono uppercase text-slate-400">
              <tr>
                <th className="py-2.5 pr-3">CVE & Software</th>
                <th className="py-2.5 pr-3">Asset / Zone</th>
                <th className="py-2.5 pr-3">CVSS</th>
                <th className="py-2.5 pr-3">Criticality</th>
                <th className="py-2.5 pr-3">Exposure</th>
                <th className="py-2.5 pr-3">Risk Formula Score</th>
                <th className="py-2.5">Mitigation Guidance</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {filteredVulns.flatMap((v) =>
                v.affected_assets.map((asset) => (
                  <tr key={`${v.cve_id}-${asset.asset_id}`} className="hover:bg-slate-800/30">
                    <td className="py-3 pr-3">
                      <p className="font-mono font-bold text-rose-300">{v.cve_id}</p>
                      <p className="text-slate-200">{v.software}</p>
                      <p className="text-[10px] font-mono text-slate-400">{v.version}</p>
                    </td>
                    <td className="py-3 pr-3 font-mono">
                      <p className="text-cyan-300 font-semibold">{asset.asset_id}</p>
                      <p className="text-[10px] text-slate-400">
                        {asset.ip} • {asset.zone}
                      </p>
                    </td>
                    <td className="py-3 pr-3 font-mono font-bold telemetry-num text-rose-300">
                      {v.cvss_score.toFixed(1)}
                    </td>
                    <td className="py-3 pr-3">
                      <StatusBadge
                        variant={asset.criticality === 'critical' ? 'critical' : 'high'}
                        label={asset.criticality}
                      />
                    </td>
                    <td className="py-3 pr-3 font-mono text-[11px] text-amber-300">
                      {asset.exposure.replace('_', ' ')}
                    </td>
                    <td className="py-3 pr-3">
                      <div className="flex items-center gap-2">
                        <div className="h-2 w-20 overflow-hidden rounded-full bg-slate-800">
                          <div
                            className={`h-full ${
                              asset.priority_risk_score >= 90
                                ? 'bg-rose-500'
                                : asset.priority_risk_score >= 75
                                  ? 'bg-orange-400'
                                  : 'bg-amber-400'
                            }`}
                            style={{ width: `${asset.priority_risk_score}%` }}
                          />
                        </div>
                        <span className="font-mono font-bold text-slate-100 telemetry-num">
                          {asset.priority_risk_score}
                        </span>
                      </div>
                    </td>
                    <td className="py-3 text-[11px] text-slate-300 max-w-xs">
                      <div className="flex items-start gap-1.5">
                        <ShieldAlert className="h-3.5 w-3.5 shrink-0 text-cyan-400 mt-0.5" />
                        <span>{v.recommended_mitigation}</span>
                      </div>
                    </td>
                  </tr>
                )),
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

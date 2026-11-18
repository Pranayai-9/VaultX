import React, { useMemo, useState } from 'react';
import { Activity, Filter, Lock, Search, Unlock } from 'lucide-react';
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { NETWORK_FLOWS, THROUGHPUT_TIMESERIES } from '../services/mockData';
import type { PrincipalType } from '../types';
import { StatusBadge } from '../components/StatusBadge';

const SEGMENT_TABS: { id: 'ALL' | PrincipalType; label: string }[] = [
  { id: 'ALL', label: 'All Flows' },
  { id: 'HUMAN_USER', label: 'Human Users' },
  { id: 'SERVICE_ACCOUNT', label: 'Service Accounts' },
  { id: 'AUTOMATION_WORKLOAD', label: 'Automated Workloads' },
  { id: 'AI_AGENT', label: 'AI Agents' },
  { id: 'INDUSTRIAL_DEVICE', label: 'Industrial Modbus' },
  { id: 'THIRD_PARTY_IDENTITY', label: 'Third-Party Vendors' },
];

export const NetworkMonitoringView: React.FC = () => {
  const [segment, setSegment] = useState<'ALL' | PrincipalType>('ALL');
  const [zoneFilter, setZoneFilter] = useState('ALL');
  const [protocolFilter, setProtocolFilter] = useState('ALL');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [search, setSearch] = useState('');

  const filteredFlows = useMemo(() => {
    return NETWORK_FLOWS.filter((f) => {
      if (segment !== 'ALL' && f.identity_type !== segment) return false;
      if (zoneFilter !== 'ALL' && f.source_zone !== zoneFilter && f.dest_zone !== zoneFilter) {
        return false;
      }
      if (protocolFilter !== 'ALL' && f.protocol !== protocolFilter) return false;
      if (statusFilter !== 'ALL' && f.detection_status !== statusFilter) return false;
      if (search.trim()) {
        const q = search.toLowerCase();
        const hay = `${f.flow_id} ${f.source_asset} ${f.dest_asset} ${f.source_ip} ${f.dest_ip} ${f.identity} ${f.rule_match || ''}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }, [segment, zoneFilter, protocolFilter, statusFilter, search]);

  const formatBytes = (b: number) => {
    if (b >= 1_000_000_000) return `${(b / 1_000_000_000).toFixed(2)} GB`;
    if (b >= 1_000_000) return `${(b / 1_000_000).toFixed(1)} MB`;
    if (b >= 1_000) return `${(b / 1_000).toFixed(1)} KB`;
    return `${b} B`;
  };

  return (
    <div className="space-y-6">
      {/* Top Charts Row: PPS/FPS Throughput + Direction Breakdown */}
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-12">
        <div className="soc-card rounded-xl p-5 xl:col-span-7">
          <div className="flex items-center justify-between mb-3">
            <div>
              <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
                <Activity className="h-4 w-4 text-cyan-400" />
                Live PPS / FPS Throughput & Encryption Trend
              </h2>
              <p className="text-xs font-mono text-slate-400">
                Real-time passive Zeek connection telemetry (78.4% Encrypted TLS/SSH)
              </p>
            </div>
            <StatusBadge variant="cyan" label="ZERO PACKET DROP" />
          </div>
          <div className="h-52">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={THROUGHPUT_TIMESERIES}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="time" stroke="#64748b" fontSize={11} />
                <YAxis stroke="#64748b" fontSize={11} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0f172a',
                    borderColor: '#334155',
                    borderRadius: 8,
                    fontSize: 12,
                  }}
                />
                <Legend wrapperStyle={{ fontSize: 11 }} />
                <Area
                  type="monotone"
                  dataKey="pps"
                  name="Packets/sec (PPS)"
                  stroke="#06b6d4"
                  fill="#06b6d4"
                  fillOpacity={0.18}
                  strokeWidth={2}
                />
                <Area
                  type="monotone"
                  dataKey="fps"
                  name="Flows/sec (FPS)"
                  stroke="#10b981"
                  fill="#10b981"
                  fillOpacity={0.22}
                  strokeWidth={2}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="soc-card rounded-xl p-5 xl:col-span-5">
          <div className="mb-3">
            <h2 className="text-sm font-semibold text-slate-100">
              Traffic Direction Breakdown (Inbound / Outbound / Lateral)
            </h2>
            <p className="text-xs font-mono text-slate-400">
              Percentage split across VLAN boundaries & external gateways
            </p>
          </div>
          <div className="h-52">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={THROUGHPUT_TIMESERIES}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="time" stroke="#64748b" fontSize={11} />
                <YAxis stroke="#64748b" fontSize={11} unit="%" />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0f172a',
                    borderColor: '#334155',
                    borderRadius: 8,
                    fontSize: 12,
                  }}
                />
                <Legend wrapperStyle={{ fontSize: 11 }} />
                <Bar dataKey="lateral" stackId="a" name="Lateral (East-West)" fill="#06b6d4" />
                <Bar dataKey="inbound" stackId="a" name="Inbound" fill="#10b981" />
                <Bar dataKey="outbound" stackId="a" name="Outbound" fill="#f59e0b" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Segmented Identity Views Tabs */}
      <div className="flex flex-wrap items-center gap-2">
        {SEGMENT_TABS.map((tab) => (
          <button
            key={tab.id}
            type="button"
            onClick={() => setSegment(tab.id)}
            className={`rounded-lg border px-3 py-1.5 text-xs font-mono font-semibold transition-colors cursor-pointer ${
              segment === tab.id
                ? 'border-cyan-500/60 bg-cyan-500/15 text-cyan-200'
                : 'border-slate-800 bg-slate-900/70 text-slate-400 hover:border-slate-700 hover:text-slate-200'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Filter Bar + Active Flows Table */}
      <div className="soc-card rounded-xl p-5 space-y-4">
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative flex-1 min-w-[220px]">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search asset, IP, identity, JA3 or rule match..."
              className="w-full rounded-lg border border-slate-800 bg-slate-950/80 py-2 pl-9 pr-3 text-xs font-mono text-slate-200 placeholder-slate-500 focus:border-cyan-500/60 focus:outline-none"
            />
          </div>

          <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
            <Filter className="h-3.5 w-3.5 text-slate-400" />
            <select
              value={zoneFilter}
              onChange={(e) => setZoneFilter(e.target.value)}
              className="rounded-lg border border-slate-800 bg-slate-950 px-2.5 py-2 text-slate-300"
            >
              <option value="ALL">All Zones</option>
              <option value="Corporate IT">Corporate IT</option>
              <option value="Engineering & Firmware">Engineering & Firmware</option>
              <option value="Manufacturing OT">Manufacturing OT</option>
              <option value="Warehouse & Logistics">Warehouse & Logistics</option>
              <option value="DMZ & Vendor Access">DMZ & Vendor Access</option>
              <option value="Cloud & External">Cloud & External</option>
            </select>

            <select
              value={protocolFilter}
              onChange={(e) => setProtocolFilter(e.target.value)}
              className="rounded-lg border border-slate-800 bg-slate-950 px-2.5 py-2 text-slate-300"
            >
              <option value="ALL">All Protocols</option>
              <option value="Modbus/TCP">Modbus/TCP</option>
              <option value="TLSv1.3">TLSv1.3</option>
              <option value="HTTPS">HTTPS</option>
              <option value="SSH">SSH</option>
              <option value="SMB">SMB</option>
              <option value="Kerberos">Kerberos</option>
            </select>

            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="rounded-lg border border-slate-800 bg-slate-950 px-2.5 py-2 text-slate-300"
            >
              <option value="ALL">All Detection States</option>
              <option value="malicious">Malicious</option>
              <option value="suspicious">Suspicious</option>
              <option value="blocked">Blocked</option>
              <option value="clean">Clean</option>
            </select>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-slate-800 text-[10px] font-mono uppercase tracking-wider text-slate-400">
              <tr>
                <th className="py-2.5 pr-3">Flow / Time</th>
                <th className="py-2.5 pr-3">Source -&gt; Destination</th>
                <th className="py-2.5 pr-3">Identity & Class</th>
                <th className="py-2.5 pr-3">Proto / Dir</th>
                <th className="py-2.5 pr-3">Encryption</th>
                <th className="py-2.5 pr-3">Volume (Tx/Rx)</th>
                <th className="py-2.5">Detection</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70 font-mono">
              {filteredFlows.map((flow) => (
                <tr key={flow.flow_id} className="hover:bg-slate-800/35 transition-colors">
                  <td className="py-2.5 pr-3">
                    <p className="font-semibold text-cyan-300">{flow.flow_id}</p>
                    <p className="text-[10px] text-slate-500">{flow.timestamp} IST</p>
                  </td>
                  <td className="py-2.5 pr-3">
                    <p className="text-slate-100">
                      {flow.source_asset}{' '}
                      <span className="text-slate-500">({flow.source_ip})</span>
                    </p>
                    <p className="text-[11px] text-slate-400">
                      -&gt; {flow.dest_asset}{' '}
                      <span className="text-slate-500">
                        ({flow.dest_ip}:{flow.port})
                      </span>
                    </p>
                  </td>
                  <td className="py-2.5 pr-3">
                    <p className="text-slate-200">{flow.identity}</p>
                    <span className="inline-block mt-0.5 rounded bg-slate-800 px-1.5 py-0.5 text-[9px] text-slate-300">
                      {flow.identity_type}
                    </span>
                  </td>
                  <td className="py-2.5 pr-3">
                    <span className="text-slate-200">{flow.protocol}</span>
                    <p className="text-[10px] text-slate-400">{flow.direction}</p>
                  </td>
                  <td className="py-2.5 pr-3">
                    {flow.encrypted ? (
                      <span className="inline-flex items-center gap-1 text-emerald-300">
                        <Lock className="h-3 w-3" /> {flow.tls_version || 'Encrypted'}
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 text-amber-300">
                        <Unlock className="h-3 w-3" /> Cleartext
                      </span>
                    )}
                    {flow.ja3_hash && (
                      <p className="text-[9px] text-rose-300 truncate max-w-[115px]">
                        JA3:{flow.ja3_hash.slice(0, 12)}...
                      </p>
                    )}
                  </td>
                  <td className="py-2.5 pr-3 telemetry-num text-slate-300">
                    <p>↑ {formatBytes(flow.bytes_sent)}</p>
                    <p className="text-[10px] text-slate-500">↓ {formatBytes(flow.bytes_recv)}</p>
                  </td>
                  <td className="py-2.5">
                    <StatusBadge
                      variant={
                        flow.detection_status === 'malicious'
                          ? 'critical'
                          : flow.detection_status === 'suspicious'
                            ? 'warning'
                            : flow.detection_status === 'blocked'
                              ? 'purple'
                              : 'healthy'
                      }
                      label={flow.detection_status}
                    />
                    {flow.rule_match && (
                      <p className="mt-1 text-[10px] text-slate-400">{flow.rule_match}</p>
                    )}
                  </td>
                </tr>
              ))}
              {filteredFlows.length === 0 && (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-slate-500">
                    No active network flows match the selected filters.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

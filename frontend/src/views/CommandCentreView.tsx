import React from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Activity,
  AlertOctagon,
  ArrowRight,
  Bug,
  Cpu,
  Globe,
  Lock,
  Radio,
  ShieldCheck,
  Sparkles,
  Wifi,
} from 'lucide-react';
import {
  Area,
  AreaChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { useSoc } from '../context/SocContext';
import { MetricCard } from '../components/MetricCard';
import { StatusBadge } from '../components/StatusBadge';
import { THROUGHPUT_TIMESERIES } from '../services/mockData';

const ORIGIN_COLORS = ['#06b6d4', '#10b981', '#818cf8', '#f59e0b'];

export const CommandCentreView: React.FC = () => {
  const navigate = useNavigate();
  const { overview, analysisTicker, zones, incidents } = useSoc();

  const originData = [
    { name: 'Human Users', value: overview.trafficByOrigin.human },
    { name: 'Automated Workloads', value: overview.trafficByOrigin.automated },
    { name: 'AI Agents', value: overview.trafficByOrigin.aiAgent },
    { name: 'Industrial OT', value: overview.trafficByOrigin.industrial },
  ];

  const zoneStatusColor = (status: string) => {
    switch (status) {
      case 'critical':
        return 'border-rose-500/50 bg-rose-500/10 text-rose-300';
      case 'elevated':
        return 'border-orange-500/50 bg-orange-500/10 text-orange-300';
      case 'warning':
        return 'border-amber-500/50 bg-amber-500/10 text-amber-300';
      case 'offline':
        return 'border-slate-600 bg-slate-800/70 text-slate-400';
      default:
        return 'border-emerald-500/40 bg-emerald-500/10 text-emerald-300';
    }
  };

  return (
    <div className="space-y-6">
      {/* Top 6-KPI Organisation-Wide Security Status */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6">
        <MetricCard
          title="Security Health Score"
          value={`${overview.healthScore}%`}
          subtitle="BECPL Pune • 7 VLANs"
          accent="emerald"
          badge="SLA OK"
          icon={<ShieldCheck className="h-5 w-5" />}
        />
        <MetricCard
          title="Active Incidents"
          value={overview.activeIncidents}
          subtitle={`${overview.threatSummary.critical} Critical • ${overview.threatSummary.high} High`}
          accent="rose"
          badge="TRIAGE"
          icon={<AlertOctagon className="h-5 w-5" />}
          onClick={() => navigate('/incidents')}
        />
        <MetricCard
          title="Critical CVEs (KEV)"
          value={overview.criticalCves}
          subtitle="SMBGhost, SSH 7.4, Flask"
          accent="amber"
          badge="EXPOSED"
          icon={<Bug className="h-5 w-5" />}
          onClick={() => navigate('/vulnerabilities')}
        />
        <MetricCard
          title="Passive Sensor Grid"
          value={`${overview.sensorsActive}/${overview.sensorsTotal}`}
          subtitle="Zeek + Suricata Online"
          accent="cyan"
          badge="100%"
          icon={<Radio className="h-5 w-5" />}
          onClick={() => navigate('/health')}
        />
        <MetricCard
          title="Ingestion Stream Lag"
          value={`${overview.ingestionLagMs} ms`}
          subtitle="Redis Streams Backpressure: 0"
          accent="emerald"
          badge="ZERO LAG"
          icon={<Activity className="h-5 w-5" />}
          onClick={() => navigate('/health')}
        />
        <MetricCard
          title="Network Throughput"
          value={`${overview.throughputGbps} Gbps`}
          subtitle={`${overview.activeFlows.toLocaleString()} active flows`}
          accent="indigo"
          badge="LIVE"
          icon={<Wifi className="h-5 w-5" />}
          onClick={() => navigate('/network')}
        />
      </div>

      {/* Middle Row: Real-Time Activity Gauges & Threat Summary */}
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-12">
        {/* Left: Real-Time Network Activity & Gauges */}
        <div className="soc-card rounded-xl p-5 xl:col-span-7 space-y-5">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
                <Activity className="h-4 w-4 text-cyan-400" />
                Real-Time Network Activity & Telemetry Gauges
              </h2>
              <p className="text-xs font-mono text-slate-400">
                Passive SPAN telemetry across Corporate, Engineering, OT, Warehouse, DMZ & Cloud
              </p>
            </div>
            <StatusBadge variant="cyan" label="STREAMING LIVE" pulse />
          </div>

          {/* 3 Telemetry Ratio Gauges */}
          <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
            {/* Encrypted Traffic % */}
            <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3.5">
              <div className="flex items-center justify-between text-xs font-mono text-slate-400">
                <span className="flex items-center gap-1.5">
                  <Lock className="h-3.5 w-3.5 text-emerald-400" />
                  ENCRYPTED TLS/SSH
                </span>
                <span className="text-emerald-300 font-bold telemetry-num">
                  {overview.encryptedTrafficPct}%
                </span>
              </div>
              <div className="mt-2.5 h-2.5 w-full overflow-hidden rounded-full bg-slate-800">
                <div
                  className="h-full rounded-full bg-gradient-to-r from-cyan-500 to-emerald-400 transition-all duration-500"
                  style={{ width: `${overview.encryptedTrafficPct}%` }}
                />
              </div>
              <p className="mt-2 text-[11px] font-mono text-slate-400">
                21.6% Cleartext (Modbus/TCP + Internal DNS)
              </p>
            </div>

            {/* Internal vs External Ratio */}
            <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3.5">
              <div className="flex items-center justify-between text-xs font-mono text-slate-400">
                <span className="flex items-center gap-1.5">
                  <Globe className="h-3.5 w-3.5 text-cyan-400" />
                  INTERNAL / EXTERNAL
                </span>
                <span className="text-cyan-300 font-bold telemetry-num">
                  {overview.internalTrafficPct}% / {overview.externalTrafficPct}%
                </span>
              </div>
              <div className="mt-2.5 flex h-2.5 w-full overflow-hidden rounded-full bg-slate-800">
                <div
                  className="h-full bg-cyan-500"
                  style={{ width: `${overview.internalTrafficPct}%` }}
                />
                <div
                  className="h-full bg-amber-400"
                  style={{ width: `${overview.externalTrafficPct}%` }}
                />
              </div>
              <p className="mt-2 text-[11px] font-mono text-slate-400">
                East-West Lateral Dominant (Normal Mfg Profile)
              </p>
            </div>

            {/* Active Flows & Throughput */}
            <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3.5">
              <div className="flex items-center justify-between text-xs font-mono text-slate-400">
                <span className="flex items-center gap-1.5">
                  <Cpu className="h-3.5 w-3.5 text-indigo-400" />
                  FLOW VELOCITY
                </span>
                <span className="text-indigo-300 font-bold telemetry-num">
                  {overview.activeFlows.toLocaleString()}
                </span>
              </div>
              <div className="mt-2.5 h-2.5 w-full overflow-hidden rounded-full bg-slate-800">
                <div
                  className="h-full rounded-full bg-gradient-to-r from-indigo-500 to-cyan-400"
                  style={{ width: '68%' }}
                />
              </div>
              <p className="mt-2 text-[11px] font-mono text-slate-400">
                Peak Capacity: 25,000 flows/sec • Headroom 32%
              </p>
            </div>
          </div>

          {/* Live Throughput Area Chart */}
          <div className="h-52 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={THROUGHPUT_TIMESERIES}>
                <defs>
                  <linearGradient id="ppsGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.35} />
                    <stop offset="95%" stopColor="#06b6d4" stopOpacity={0.02} />
                  </linearGradient>
                  <linearGradient id="fpsGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#10b981" stopOpacity={0.35} />
                    <stop offset="95%" stopColor="#10b981" stopOpacity={0.02} />
                  </linearGradient>
                </defs>
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
                <Area
                  type="monotone"
                  dataKey="pps"
                  name="Packets/sec"
                  stroke="#06b6d4"
                  fill="url(#ppsGrad)"
                  strokeWidth={2}
                />
                <Area
                  type="monotone"
                  dataKey="fps"
                  name="Flows/sec"
                  stroke="#10b981"
                  fill="url(#fpsGrad)"
                  strokeWidth={2}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Right: Identity Traffic Split + Threat Summary Cards */}
        <div className="space-y-6 xl:col-span-5">
          {/* Human vs Automated vs AI Agent vs Industrial Traffic */}
          <div className="soc-card rounded-xl p-5">
            <h2 className="text-sm font-semibold text-slate-100">
              Principal Identity Traffic Breakdown
            </h2>
            <p className="text-xs font-mono text-slate-400">
              7-Way Identity Attribution (Human • Automated • AI Agent • OT PLC)
            </p>
            <div className="mt-3 grid grid-cols-1 items-center gap-4 sm:grid-cols-2">
              <div className="h-44">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={originData}
                      dataKey="value"
                      nameKey="name"
                      cx="50%"
                      cy="50%"
                      innerRadius={44}
                      outerRadius={68}
                      paddingAngle={3}
                    >
                      {originData.map((entry, idx) => (
                        <Cell
                          key={entry.name}
                          fill={ORIGIN_COLORS[idx % ORIGIN_COLORS.length]}
                        />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#0f172a',
                        borderColor: '#334155',
                        borderRadius: 8,
                        fontSize: 12,
                      }}
                    />
                  </PieChart>
                </ResponsiveContainer>
              </div>
              <div className="space-y-2.5">
                {originData.map((item, idx) => (
                  <div
                    key={item.name}
                    className="flex items-center justify-between rounded-lg border border-slate-800/80 bg-slate-900/50 px-3 py-1.5 text-xs"
                  >
                    <div className="flex items-center gap-2">
                      <span
                        className="h-2.5 w-2.5 rounded-sm"
                        style={{ backgroundColor: ORIGIN_COLORS[idx] }}
                      />
                      <span className="text-slate-300">{item.name}</span>
                    </div>
                    <span className="font-mono font-semibold text-slate-100 telemetry-num">
                      {item.value}%
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Threat Summary Matrix */}
          <div className="soc-card rounded-xl p-5">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-semibold text-slate-100">
                Threat Summary & Resolution Posture
              </h2>
              <button
                type="button"
                onClick={() => navigate('/incidents')}
                className="text-xs font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
              >
                Queue <ArrowRight className="h-3.5 w-3.5" />
              </button>
            </div>
            <div className="mt-3 grid grid-cols-4 gap-2.5">
              <div className="rounded-lg border border-rose-500/35 bg-rose-500/10 p-2.5 text-center">
                <p className="text-[10px] font-mono uppercase text-rose-300">Critical</p>
                <p className="mt-1 text-xl font-bold text-rose-300 telemetry-num">
                  {overview.threatSummary.critical}
                </p>
              </div>
              <div className="rounded-lg border border-orange-500/35 bg-orange-500/10 p-2.5 text-center">
                <p className="text-[10px] font-mono uppercase text-orange-300">High</p>
                <p className="mt-1 text-xl font-bold text-orange-300 telemetry-num">
                  {overview.threatSummary.high}
                </p>
              </div>
              <div className="rounded-lg border border-amber-500/35 bg-amber-500/10 p-2.5 text-center">
                <p className="text-[10px] font-mono uppercase text-amber-300">Medium</p>
                <p className="mt-1 text-xl font-bold text-amber-300 telemetry-num">
                  {overview.threatSummary.medium}
                </p>
              </div>
              <div className="rounded-lg border border-sky-500/35 bg-sky-500/10 p-2.5 text-center">
                <p className="text-[10px] font-mono uppercase text-sky-300">Low</p>
                <p className="mt-1 text-xl font-bold text-sky-300 telemetry-num">
                  {overview.threatSummary.low}
                </p>
              </div>
            </div>
            <div className="mt-3 grid grid-cols-2 gap-3">
              <div className="flex items-center justify-between rounded-lg border border-slate-800 bg-slate-900/70 px-3 py-2 text-xs font-mono">
                <span className="text-slate-400">UNRESOLVED</span>
                <span className="text-rose-300 font-bold telemetry-num">
                  {incidents.filter((i) => i.status === 'open' || i.status === 'investigating').length}
                </span>
              </div>
              <div className="flex items-center justify-between rounded-lg border border-slate-800 bg-slate-900/70 px-3 py-2 text-xs font-mono">
                <span className="text-slate-400">CONTAINED / RESOLVED</span>
                <span className="text-emerald-300 font-bold telemetry-num">
                  {incidents.filter((i) => i.status === 'contained' || i.status === 'resolved').length}
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Bottom Row: Evidence-Grounded System Analysis Ticker + 7-VLAN Quick Posture */}
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-12">
        {/* Evidence-Grounded System Analysis Ticker */}
        <div className="soc-card rounded-xl p-5 xl:col-span-8">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div className="flex items-center gap-2">
              <Sparkles className="h-4 w-4 text-cyan-400" />
              <h2 className="text-sm font-semibold text-slate-100">
                Evidence-Grounded System Analysis Ticker
              </h2>
            </div>
            <span className="text-[11px] font-mono text-slate-400">
              AUTO-CORRELATED • ZERO HALLUCINATION CITATIONS
            </span>
          </div>
          <div className="mt-3 space-y-2.5 max-h-[300px] overflow-y-auto pr-1">
            {analysisTicker.map((item) => (
              <div
                key={item.id}
                className="animate-ticker rounded-lg border border-slate-800/90 bg-slate-900/60 p-3 hover:border-slate-700 transition-colors"
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <StatusBadge variant={item.severity} label={item.severity} />
                    <span className="text-xs font-mono font-semibold text-cyan-300">
                      {item.zone}
                    </span>
                  </div>
                  <div className="flex items-center gap-2 text-[11px] font-mono text-slate-400">
                    <span className="rounded bg-slate-800 px-1.5 py-0.5 text-slate-300">
                      {item.evidenceRef}
                    </span>
                    <span className="text-emerald-400">
                      conf {(item.confidence * 100).toFixed(1)}%
                    </span>
                    <span>{item.timestamp}</span>
                  </div>
                </div>
                <p className="mt-2 text-xs text-slate-200 leading-relaxed">{item.summary}</p>
              </div>
            ))}
          </div>
        </div>

        {/* 7-VLAN Posture Strip */}
        <div className="soc-card rounded-xl p-5 xl:col-span-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <h2 className="text-sm font-semibold text-slate-100">7-VLAN Segment Status</h2>
            <button
              type="button"
              onClick={() => navigate('/infrastructure')}
              className="text-xs font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
            >
              Topology <ArrowRight className="h-3.5 w-3.5" />
            </button>
          </div>
          <div className="mt-3 space-y-2">
            {zones.map((z) => (
              <button
                key={z.vlan_id}
                type="button"
                onClick={() => navigate('/infrastructure')}
                className="w-full flex items-center justify-between rounded-lg border border-slate-800 bg-slate-900/60 px-3 py-2 text-left hover:border-cyan-500/40 transition-colors"
              >
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-[11px] font-mono font-bold text-slate-400">
                      VLAN {z.vlan_id}
                    </span>
                    <span className="truncate text-xs font-semibold text-slate-100">
                      {z.name}
                    </span>
                  </div>
                  <p className="text-[10px] font-mono text-slate-400">
                    {z.subnet} • {z.asset_count} assets
                  </p>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <span className="text-xs font-mono text-slate-300 telemetry-num">
                    Risk {z.risk_score}
                  </span>
                  <span
                    className={`rounded border px-1.5 py-0.5 text-[10px] font-mono uppercase ${zoneStatusColor(z.status)}`}
                  >
                    {z.status}
                  </span>
                </div>
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

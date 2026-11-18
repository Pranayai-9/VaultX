import React, { useEffect, useState } from 'react';
import {
  Activity,
  Cpu,
  Database,
  HeartPulse,
  Layers,
  Radio,
  Terminal,
} from 'lucide-react';
import { vaultxApi } from '../services/api';
import {
  PASSIVE_SENSORS,
  PROMETHEUS_SAMPLE_METRICS,
  REDIS_QUEUES,
} from '../services/mockData';
import type { QueueDepthMetric, SensorHealth } from '../types';
import { useSoc } from '../context/SocContext';
import { MetricCard } from '../components/MetricCard';
import { StatusBadge } from '../components/StatusBadge';

export const SystemHealthView: React.FC = () => {
  const { liveEps, liveP95LatencyMs, backendOnline } = useSoc();
  const [sensors, setSensors] = useState<SensorHealth[]>(PASSIVE_SENSORS);
  const [queues, setQueues] = useState<QueueDepthMetric[]>(REDIS_QUEUES);
  const [prometheusText, setPrometheusText] = useState(PROMETHEUS_SAMPLE_METRICS);

  useEffect(() => {
    let mounted = true;
    vaultxApi.getSensors().then((s) => mounted && setSensors(s));
    vaultxApi.getPipelineQueues().then((q) => mounted && setQueues(q));
    vaultxApi.getPrometheusMetrics().then((m) => mounted && setPrometheusText(m));
    return () => {
      mounted = false;
    };
  }, []);

  return (
    <div className="space-y-6">
      {/* Top 4 Infrastructure KPI Cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <MetricCard
          title="Passive Sensor Grid"
          value={`${sensors.filter((s) => s.status === 'online').length} / ${sensors.length}`}
          subtitle="VLANs 10–70 • 0.005% Avg Drop"
          accent="emerald"
          badge="HEALTHY"
          icon={<Radio className="h-5 w-5" />}
        />
        <MetricCard
          title="P95 Processing Latency"
          value={`${liveP95LatencyMs} ms`}
          subtitle="Ingestion -> ML RF -> Correlator"
          accent="cyan"
          badge="SLA <10ms"
          icon={<Activity className="h-5 w-5" />}
        />
        <MetricCard
          title="PostgreSQL Pool"
          value="6 / 20"
          subtitle="PostgreSQL 15.4 • RTT 1.4 ms"
          accent="indigo"
          badge={backendOnline ? 'LIVE' : 'TWIN'}
          icon={<Database className="h-5 w-5" />}
        />
        <MetricCard
          title="Redis Streams Throughput"
          value={`${liveEps.toLocaleString()} EPS`}
          subtitle="6 Active Streams • 12.4 MB RAM"
          accent="emerald"
          badge="0 LAG"
          icon={<Layers className="h-5 w-5" />}
        />
      </div>

      {/* Distributed Passive Sensor Grid (All 6 Sensors across VLANs 10-70) */}
      <div className="soc-card rounded-xl p-5 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
              <HeartPulse className="h-4 w-4 text-emerald-400" />
              Distributed Passive Sensor Grid (6 Sensors • VLANs 10–70)
            </h2>
            <p className="text-xs font-mono text-slate-400">
              Non-intrusive SPAN / optical tap collectors running Zeek 6.0 &amp; Suricata 7.0
            </p>
          </div>
          <StatusBadge variant="healthy" label="ALL TAPS SYNCHRONIZED" pulse />
        </div>

        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
          {sensors.map((s) => (
            <div
              key={s.sensor_id}
              className="rounded-xl border border-slate-800 bg-slate-900/70 p-4 space-y-3"
            >
              <div className="flex items-start justify-between gap-2">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs font-bold text-cyan-300">
                      {s.sensor_id}
                    </span>
                    <span className="rounded bg-slate-800 px-1.5 py-0.5 text-[10px] font-mono text-slate-300">
                      VLAN {s.vlan_id}
                    </span>
                  </div>
                  <p className="mt-0.5 text-xs font-semibold text-slate-100">{s.zone_name}</p>
                  <p className="text-[10px] font-mono text-slate-500">
                    {s.hostname} • Heartbeat: {s.last_heartbeat}
                  </p>
                </div>
                <StatusBadge
                  variant={s.status === 'online' ? 'healthy' : 'critical'}
                  label={s.status}
                  pulse={s.status === 'online'}
                />
              </div>

              {/* CPU & Memory Utilization Bars */}
              <div className="space-y-2 text-[11px] font-mono">
                <div>
                  <div className="flex justify-between text-slate-400">
                    <span>CPU Load</span>
                    <span className="text-slate-200 telemetry-num">{s.cpu_pct}%</span>
                  </div>
                  <div className="mt-1 h-1.5 rounded-full bg-slate-800 overflow-hidden">
                    <div className="h-full bg-cyan-400" style={{ width: `${s.cpu_pct}%` }} />
                  </div>
                </div>
                <div>
                  <div className="flex justify-between text-slate-400">
                    <span>Memory</span>
                    <span className="text-slate-200 telemetry-num">{s.memory_pct}%</span>
                  </div>
                  <div className="mt-1 h-1.5 rounded-full bg-slate-800 overflow-hidden">
                    <div className="h-full bg-indigo-400" style={{ width: `${s.memory_pct}%` }} />
                  </div>
                </div>
              </div>

              <div className="flex flex-wrap items-center justify-between gap-2 border-t border-slate-800 pt-2.5 text-[11px] font-mono">
                <span className="text-emerald-300">
                  {s.events_per_sec.toLocaleString()} EPS
                </span>
                <span className="text-slate-300">
                  Drop: <strong className="text-emerald-400">{s.drop_rate_pct.toFixed(2)}%</strong>
                </span>
                <div className="flex gap-1.5">
                  <span className="rounded bg-emerald-500/15 px-1.5 py-0.5 text-[9px] text-emerald-300 border border-emerald-500/30">
                    ZEEK: {s.zeek_status}
                  </span>
                  <span className="rounded bg-emerald-500/15 px-1.5 py-0.5 text-[9px] text-emerald-300 border border-emerald-500/30">
                    SURICATA: {s.suricata_status}
                  </span>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Bottom Row: Redis Queue Depths + Prometheus Metrics Exposition */}
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-12">
        <div className="soc-card rounded-xl p-5 xl:col-span-6 space-y-3">
          <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
            <Cpu className="h-4 w-4 text-cyan-400" />
            Redis Streams Ingestion Queue Depth
          </h2>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="border-b border-slate-800 text-[10px] uppercase text-slate-400">
                <tr>
                  <th className="py-2 pr-3">Stream Name</th>
                  <th className="py-2 pr-3">Queue Len</th>
                  <th className="py-2 pr-3">Consumers</th>
                  <th className="py-2 pr-3">Unack</th>
                  <th className="py-2">Lag (ms)</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70">
                {queues.map((q) => (
                  <tr key={q.stream_name}>
                    <td className="py-2.5 pr-3 text-cyan-300">{q.stream_name}</td>
                    <td className="py-2.5 pr-3 text-slate-200 telemetry-num">{q.queue_length}</td>
                    <td className="py-2.5 pr-3 text-slate-400 telemetry-num">{q.consumer_groups}</td>
                    <td className="py-2.5 pr-3 text-amber-300 telemetry-num">{q.unacknowledged}</td>
                    <td className="py-2.5 text-emerald-300 font-bold telemetry-num">
                      {q.lag_ms.toFixed(1)} ms
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        <div className="soc-card rounded-xl p-5 xl:col-span-6 space-y-3">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
              <Terminal className="h-4 w-4 text-emerald-400" />
              Prometheus Telemetry Endpoint (/metrics)
            </h2>
            <StatusBadge variant="cyan" label="OPENMETRICS 1.0" />
          </div>
          <pre className="max-h-72 overflow-auto rounded-lg border border-slate-800 bg-slate-950 p-3.5 text-[11px] font-mono text-emerald-300 leading-relaxed">
            {prometheusText}
          </pre>
        </div>
      </div>
    </div>
  );
};

import React, { useState } from 'react';
import {
  Building2,
  Cloud,
  Cpu,
  Factory,
  GitBranch,
  Globe,
  Lock,
  Radio,
  Server,
  Shield,
  Truck,
  Wrench,
} from 'lucide-react';
import { clsx } from 'clsx';
import { useSoc } from '../context/SocContext';
import type { VlanZoneDetail, ZoneHealthStatus } from '../types';
import { StatusBadge } from '../components/StatusBadge';

const STATUS_RING: Record<ZoneHealthStatus, { border: string; bg: string; dot: string; label: string }> = {
  healthy: { border: 'border-emerald-500/60', bg: 'bg-emerald-500/10', dot: 'bg-emerald-400', label: 'GREEN • HEALTHY' },
  warning: { border: 'border-amber-400/60', bg: 'bg-amber-400/10', dot: 'bg-amber-400', label: 'YELLOW • WARNING' },
  elevated: { border: 'border-orange-500/60', bg: 'bg-orange-500/10', dot: 'bg-orange-500', label: 'ORANGE • ELEVATED' },
  critical: { border: 'border-rose-500/70', bg: 'bg-rose-500/15', dot: 'bg-rose-500', label: 'RED • CRITICAL' },
  offline: { border: 'border-slate-600', bg: 'bg-slate-800/80', dot: 'bg-slate-500', label: 'GREY • OFFLINE' },
};

const VLAN_ICON: Record<number, React.ComponentType<{ className?: string }>> = {
  10: Building2,
  20: Wrench,
  30: Factory,
  40: Truck,
  50: Globe,
  60: Cloud,
  70: Shield,
};

export const InfrastructureMapView: React.FC = () => {
  const { zones } = useSoc();
  const [selectedVlanId, setSelectedVlanId] = useState<number>(30);

  const selectedZone: VlanZoneDetail =
    zones.find((z) => z.vlan_id === selectedVlanId) || zones[2];

  const getZone = (id: number) => zones.find((z) => z.vlan_id === id)!;

  const renderZoneNode = (vlanId: number) => {
    const z = getZone(vlanId);
    const Icon = VLAN_ICON[vlanId] || Server;
    const style = STATUS_RING[z.status];
    const isSelected = selectedVlanId === vlanId;

    return (
      <button
        key={vlanId}
        type="button"
        onClick={() => setSelectedVlanId(vlanId)}
        className={clsx(
          'relative flex flex-col justify-between rounded-xl border p-3.5 text-left transition-all cursor-pointer',
          style.border,
          style.bg,
          isSelected
            ? 'ring-2 ring-cyan-400 shadow-lg shadow-cyan-950/60 scale-[1.01]'
            : 'hover:border-cyan-400/70',
        )}
      >
        <div className="flex items-start justify-between gap-2">
          <div className="flex items-center gap-2">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-slate-950/80 border border-slate-700/80">
              <Icon className="h-4 w-4 text-cyan-300" />
            </div>
            <div>
              <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-slate-300">
                VLAN {z.vlan_id}
              </span>
              <h3 className="text-xs font-bold text-slate-100 leading-tight">{z.name}</h3>
            </div>
          </div>
          <span className="relative flex h-2.5 w-2.5 shrink-0 mt-1">
            {z.status === 'critical' && (
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-rose-400 opacity-75" />
            )}
            <span className={clsx('relative inline-flex h-2.5 w-2.5 rounded-full', style.dot)} />
          </span>
        </div>

        <div className="mt-3 flex items-center justify-between text-[11px] font-mono text-slate-300">
          <span>{z.subnet}</span>
          <span className="telemetry-num font-bold">Risk {z.risk_score}</span>
        </div>

        <div className="mt-2 flex items-center justify-between border-t border-slate-800/70 pt-2 text-[10px] font-mono text-slate-400">
          <span>{z.asset_count} Assets</span>
          <span className="text-cyan-300">{z.throughput_mbps} Mbps</span>
          {z.active_incidents > 0 ? (
            <span className="text-rose-300 font-bold">{z.active_incidents} INC</span>
          ) : (
            <span className="text-emerald-400">CLEAN</span>
          )}
        </div>
      </button>
    );
  };

  return (
    <div className="grid grid-cols-1 gap-6 xl:grid-cols-12">
      {/* Left: 7-VLAN Interactive Visual Topology */}
      <div className="soc-card rounded-xl p-5 xl:col-span-7 flex flex-col justify-between space-y-5">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <h2 className="text-sm font-semibold text-slate-100">
              BECPL Pune — 7-VLAN Segmented Industrial Network Topology
            </h2>
            <p className="text-xs font-mono text-slate-400">
              Click any VLAN segment to inspect dedicated PLC, Git/OTA, Bastion & Firewall telemetry
            </p>
          </div>
          {/* Legend */}
          <div className="flex flex-wrap items-center gap-2 text-[10px] font-mono">
            <span className="flex items-center gap-1 text-emerald-300">
              <span className="h-2 w-2 rounded-full bg-emerald-400" /> Healthy
            </span>
            <span className="flex items-center gap-1 text-amber-300">
              <span className="h-2 w-2 rounded-full bg-amber-400" /> Warning
            </span>
            <span className="flex items-center gap-1 text-orange-300">
              <span className="h-2 w-2 rounded-full bg-orange-500" /> Elevated
            </span>
            <span className="flex items-center gap-1 text-rose-300">
              <span className="h-2 w-2 rounded-full bg-rose-500" /> Critical
            </span>
            <span className="flex items-center gap-1 text-slate-400">
              <span className="h-2 w-2 rounded-full bg-slate-500" /> Offline
            </span>
          </div>
        </div>

        {/* Central Security Management Overlay Banner (VLAN 70) */}
        <div className="relative rounded-xl border border-cyan-500/40 bg-gradient-to-r from-cyan-950/40 via-slate-900/90 to-emerald-950/40 p-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-cyan-500/40 bg-cyan-500/15">
                <Radio className="h-5 w-5 text-cyan-300 animate-pulse" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-xs font-bold text-cyan-200">
                    CENTRAL SECURITY MANAGEMENT OVERLAY (VLAN 70)
                  </span>
                  <StatusBadge variant="healthy" label="6/6 PASSIVE TAPS" />
                </div>
                <p className="text-[11px] font-mono text-slate-400">
                  Out-of-Band SPAN Mirror Bus • Zeek + Suricata + Redis Streams + RF v1 • Zero Inline OT Latency
                </p>
              </div>
            </div>
            <button
              type="button"
              onClick={() => setSelectedVlanId(70)}
              className="rounded-lg border border-cyan-500/50 bg-cyan-500/15 px-3 py-1.5 text-xs font-mono font-semibold text-cyan-200 hover:bg-cyan-500/25 transition-colors"
            >
              Inspect VLAN 70
            </button>
          </div>
        </div>

        {/* Perimeter Tier: DMZ (50) & Cloud (60) */}
        <div>
          <p className="mb-2 text-[10px] font-mono uppercase tracking-widest text-slate-500">
            TIER 1 — PERIMETER, VENDOR ACCESS & CLOUD INTEGRATIONS
          </p>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            {renderZoneNode(50)}
            {renderZoneNode(60)}
          </div>
        </div>

        {/* Visual FortiGate L3 Firewall Boundary Divider */}
        <div className="relative flex items-center justify-center py-1">
          <div className="absolute inset-x-0 top-1/2 h-px bg-gradient-to-r from-transparent via-amber-500/60 to-transparent" />
          <span className="relative flex items-center gap-2 rounded-full border border-amber-500/40 bg-[#0d1424] px-3.5 py-1 text-[10px] font-mono font-bold text-amber-300">
            <Lock className="h-3 w-3" />
            FORTIGATE L3 INTER-VLAN FIREWALL • IT-TO-OT STRICT DENY (FW-001)
          </span>
        </div>

        {/* Enterprise Tier: Corporate IT (10), Engineering (20), Warehouse (40) */}
        <div>
          <p className="mb-2 text-[10px] font-mono uppercase tracking-widest text-slate-500">
            TIER 2 — ENTERPRISE IT, R&D FIRMWARE & WAREHOUSE OPERATIONS
          </p>
          <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
            {renderZoneNode(10)}
            {renderZoneNode(20)}
            {renderZoneNode(40)}
          </div>
        </div>

        {/* OT Safety Boundary Divider */}
        <div className="relative flex items-center justify-center py-1">
          <div className="absolute inset-x-0 top-1/2 h-px bg-gradient-to-r from-transparent via-rose-500/70 to-transparent" />
          <span className="relative flex items-center gap-2 rounded-full border border-rose-500/50 bg-[#0d1424] px-3.5 py-1 text-[10px] font-mono font-bold text-rose-300">
            <Cpu className="h-3 w-3" />
            IEC 62443 OT DMZ CONDUIT • PASSIVE MONITORING ONLY • TWO-PERSON SAFETY INTERLOCK
          </span>
        </div>

        {/* Industrial Tier: Manufacturing OT (30) */}
        <div>
          <p className="mb-2 text-[10px] font-mono uppercase tracking-widest text-slate-500">
            TIER 3 — MANUFACTURING SHOPFLOOR OT (SMT LINES A & B)
          </p>
          <div className="grid grid-cols-1">{renderZoneNode(30)}</div>
        </div>
      </div>

      {/* Right: Click-to-Inspect Side Panel */}
      <div className="soc-card rounded-xl p-5 xl:col-span-5 space-y-5 h-fit">
        <div className="flex items-start justify-between gap-3 border-b border-slate-800 pb-4">
          <div>
            <div className="flex items-center gap-2">
              <span className="rounded bg-cyan-500/15 px-2 py-0.5 text-xs font-mono font-bold text-cyan-300 border border-cyan-500/30">
                VLAN {selectedZone.vlan_id}
              </span>
              <StatusBadge
                variant={selectedZone.status}
                label={STATUS_RING[selectedZone.status].label}
                pulse={selectedZone.status === 'critical'}
              />
            </div>
            <h2 className="mt-2 text-lg font-bold text-slate-100">{selectedZone.name}</h2>
            <p className="mt-1 text-xs text-slate-400 leading-relaxed">
              {selectedZone.description}
            </p>
          </div>
        </div>

        {/* Network Metadata Strip */}
        <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-4 text-xs font-mono">
          <div className="rounded-lg border border-slate-800 bg-slate-900/70 p-2.5">
            <p className="text-[10px] text-slate-500">SUBNET</p>
            <p className="mt-0.5 text-slate-200">{selectedZone.subnet}</p>
          </div>
          <div className="rounded-lg border border-slate-800 bg-slate-900/70 p-2.5">
            <p className="text-[10px] text-slate-500">GATEWAY</p>
            <p className="mt-0.5 text-slate-200">{selectedZone.gateway}</p>
          </div>
          <div className="rounded-lg border border-slate-800 bg-slate-900/70 p-2.5">
            <p className="text-[10px] text-slate-500">TAP SENSOR</p>
            <p className="mt-0.5 text-cyan-300 truncate">{selectedZone.sensor_id}</p>
          </div>
          <div className="rounded-lg border border-slate-800 bg-slate-900/70 p-2.5">
            <p className="text-[10px] text-slate-500">CROSS-VLAN DROPS</p>
            <p className="mt-0.5 text-amber-300 font-bold telemetry-num">
              {selectedZone.blockedCrossVlanCount}
            </p>
          </div>
        </div>

        {/* Dedicated Zone Telemetry Grid */}
        <div>
          <h3 className="text-xs font-mono font-semibold uppercase tracking-wider text-slate-400 mb-2.5">
            Live Zone Telemetry
          </h3>
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
            {selectedZone.telemetry.map((t) => (
              <div
                key={t.label}
                className="rounded-lg border border-slate-800 bg-slate-900/60 px-3 py-2"
              >
                <p className="text-[10px] font-mono text-slate-400">{t.label}</p>
                <p
                  className={clsx(
                    'mt-0.5 text-xs font-mono font-semibold',
                    t.status === 'crit' && 'text-rose-300',
                    t.status === 'warn' && 'text-amber-300',
                    t.status === 'ok' && 'text-emerald-300',
                    (!t.status || t.status === 'info') && 'text-cyan-300',
                  )}
                >
                  {t.value}
                </p>
              </div>
            ))}
          </div>
        </div>

        {/* OT Specific: Modbus Registers 40001-40005 */}
        {selectedZone.modbusRegisters && (
          <div className="rounded-xl border border-rose-500/35 bg-rose-950/15 p-3.5">
            <div className="flex items-center justify-between mb-2">
              <h3 className="text-xs font-mono font-bold uppercase text-rose-300 flex items-center gap-1.5">
                <Factory className="h-3.5 w-3.5" />
                PLC S7-1200 Holding Registers (40001–40005)
              </h3>
              <StatusBadge variant="critical" label="FC06 TAMPERED" pulse />
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-[11px] font-mono">
                <thead className="text-slate-400 border-b border-slate-800">
                  <tr>
                    <th className="py-1.5 pr-2">Reg</th>
                    <th className="py-1.5 pr-2">Parameter</th>
                    <th className="py-1.5 pr-2">Live</th>
                    <th className="py-1.5 pr-2">Baseline</th>
                    <th className="py-1.5">State</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {selectedZone.modbusRegisters.map((reg) => (
                    <tr key={reg.address}>
                      <td className="py-1.5 pr-2 text-cyan-300">{reg.address}</td>
                      <td className="py-1.5 pr-2 text-slate-200">{reg.name}</td>
                      <td
                        className={clsx(
                          'py-1.5 pr-2 font-bold telemetry-num',
                          reg.status === 'tampered'
                            ? 'text-rose-400'
                            : reg.status === 'warning'
                              ? 'text-amber-300'
                              : 'text-emerald-300',
                        )}
                      >
                        {reg.value} {reg.unit}
                      </td>
                      <td className="py-1.5 pr-2 text-slate-400">{reg.baseline}</td>
                      <td className="py-1.5">
                        <StatusBadge
                          variant={
                            reg.status === 'tampered'
                              ? 'critical'
                              : reg.status === 'warning'
                                ? 'warning'
                                : 'healthy'
                          }
                          label={reg.status}
                        />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Engineering Specific: Gitea / OTA Firmware Hash Integrity */}
        {selectedZone.firmwareIntegrity && (
          <div className="rounded-xl border border-indigo-500/35 bg-indigo-950/15 p-3.5">
            <h3 className="text-xs font-mono font-bold uppercase text-indigo-300 flex items-center gap-1.5 mb-2.5">
              <GitBranch className="h-3.5 w-3.5" />
              Gitea Repository & OTA Firmware Hash Integrity
            </h3>
            <div className="space-y-2">
              {selectedZone.firmwareIntegrity.map((fw) => (
                <div
                  key={fw.artifact}
                  className="rounded-lg border border-slate-800 bg-slate-900/70 p-2.5 text-[11px] font-mono"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-slate-100 font-semibold">{fw.artifact}</span>
                    <StatusBadge
                      variant={fw.verified ? 'healthy' : 'critical'}
                      label={fw.verified ? 'SHA-256 VALID' : 'UNSIGNED'}
                    />
                  </div>
                  <p className="mt-1 text-slate-400">
                    {fw.repo} ({fw.branch}) • {fw.lastPush}
                  </p>
                  <p className="mt-0.5 text-[10px] text-cyan-400/90 truncate">
                    sha256: {fw.sha256}
                  </p>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Assets Table inside Selected VLAN */}
        <div>
          <h3 className="text-xs font-mono font-semibold uppercase tracking-wider text-slate-400 mb-2">
            Monitored Hosts ({selectedZone.assets.length} Key Assets)
          </h3>
          <div className="space-y-1.5 max-h-56 overflow-y-auto pr-1">
            {selectedZone.assets.map((a) => (
              <div
                key={a.asset_id}
                className="flex items-center justify-between rounded-lg border border-slate-800/90 bg-slate-900/60 px-3 py-2 text-xs"
              >
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="font-mono font-bold text-slate-100">{a.asset_id}</span>
                    <span className="font-mono text-[11px] text-cyan-400">{a.ip_address}</span>
                  </div>
                  <p className="truncate text-[11px] text-slate-400">{a.os_or_firmware}</p>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  {a.active_alerts > 0 && (
                    <span className="rounded bg-rose-500/20 px-1.5 py-0.5 text-[10px] font-mono font-bold text-rose-300">
                      {a.active_alerts} ALERTS
                    </span>
                  )}
                  <StatusBadge variant={a.status} label={a.status} />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

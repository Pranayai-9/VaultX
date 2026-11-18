import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  Activity,
  Bot,
  Brain,
  Bug,
  ChevronLeft,
  ChevronRight,
  Cpu,
  FileClock,
  Flame,
  HeartPulse,
  Link2,
  Network,
  Radar,
  Settings,
  Shield,
  ShieldAlert,
} from 'lucide-react';
import { clsx } from 'clsx';
import { useSoc } from '../context/SocContext';

interface NavGroup {
  label: string;
  items: {
    to: string;
    label: string;
    icon: React.ComponentType<{ className?: string }>;
    badge?: 'incidents' | 'pending' | 'demo';
  }[];
}

const NAV_GROUPS: NavGroup[] = [
  {
    label: 'SOC Operations',
    items: [
      { to: '/', label: 'Command Centre', icon: Radar },
      { to: '/infrastructure', label: 'Infrastructure Map', icon: Network },
      { to: '/network', label: 'Network Monitoring', icon: Activity },
      { to: '/incidents', label: 'Incident Investigation', icon: Flame, badge: 'incidents' },
    ],
  },
  {
    label: 'Threat & Exposure',
    items: [
      { to: '/threat-intel', label: 'Threat Intelligence', icon: ShieldAlert },
      { to: '/supply-chain', label: 'Third-Party Trust', icon: Link2 },
      { to: '/vulnerabilities', label: 'Vulnerabilities', icon: Bug },
    ],
  },
  {
    label: 'Defence & Audit',
    items: [
      { to: '/containment', label: 'Isolation & Defence', icon: Shield, badge: 'pending' },
      { to: '/history', label: 'History & Audit', icon: FileClock },
      { to: '/admin', label: 'Admin & Policies', icon: Settings },
    ],
  },
  {
    label: 'AI & Platform',
    items: [
      { to: '/models', label: 'Model Intelligence', icon: Brain },
      { to: '/health', label: 'System Health', icon: HeartPulse },
      { to: '/agent-demo', label: 'Multi-Agent Demo', icon: Bot, badge: 'demo' },
    ],
  },
];

interface SidebarProps {
  collapsed: boolean;
  onToggle: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ collapsed, onToggle }) => {
  const { incidents, containmentActions } = useSoc();
  const openIncidentCount = incidents.filter(
    (i) => i.status === 'open' || i.status === 'investigating',
  ).length;
  const pendingApprovalCount = containmentActions.filter((a) => a.status === 'pending').length;

  return (
    <aside
      className={clsx(
        'flex h-screen shrink-0 flex-col border-r border-slate-800/90 bg-[#0b1120] transition-all duration-200',
        collapsed ? 'w-[72px]' : 'w-[258px]',
      )}
    >
      {/* Brand Header */}
      <div className="flex h-16 items-center justify-between border-b border-slate-800/90 px-4">
        <div className="flex items-center gap-2.5 overflow-hidden">
          <div className="relative flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-gradient-to-br from-cyan-500/20 to-emerald-500/20 border border-cyan-500/40 shadow-inner">
            <Cpu className="h-5 w-5 text-cyan-400" />
            <span className="absolute -right-0.5 -top-0.5 h-2.5 w-2.5 rounded-full bg-emerald-400 ring-2 ring-[#0b1120]" />
          </div>
          {!collapsed && (
            <div className="min-w-0">
              <div className="flex items-center gap-1.5">
                <span className="text-sm font-bold tracking-wide text-slate-100">VAULTX</span>
                <span className="rounded bg-cyan-500/15 px-1.5 py-0.5 text-[9px] font-mono font-semibold text-cyan-300 border border-cyan-500/30">
                  PHASE 3
                </span>
              </div>
              <p className="truncate text-[10px] font-mono text-slate-400">
                BECPL PUNE • HYBRID NIDS
              </p>
            </div>
          )}
        </div>
        <button
          type="button"
          onClick={onToggle}
          className="rounded-md p-1 text-slate-400 hover:bg-slate-800 hover:text-slate-200 transition-colors"
          title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        >
          {collapsed ? <ChevronRight className="h-4 w-4" /> : <ChevronLeft className="h-4 w-4" />}
        </button>
      </div>

      {/* Navigation Groups */}
      <nav className="flex-1 overflow-y-auto px-2.5 py-3 space-y-4">
        {NAV_GROUPS.map((group) => (
          <div key={group.label}>
            {!collapsed && (
              <p className="mb-1.5 px-2.5 text-[10px] font-mono font-semibold uppercase tracking-widest text-slate-500">
                {group.label}
              </p>
            )}
            <div className="space-y-0.5">
              {group.items.map((item) => {
                const Icon = item.icon;
                return (
                  <NavLink
                    key={item.to}
                    to={item.to}
                    end={item.to === '/'}
                    title={collapsed ? item.label : undefined}
                    className={({ isActive }) =>
                      clsx(
                        'group flex items-center justify-between rounded-lg px-2.5 py-2 text-[13px] font-medium transition-all',
                        isActive
                          ? 'bg-cyan-500/12 text-cyan-200 border border-cyan-500/30 shadow-sm shadow-cyan-950/40'
                          : 'text-slate-400 border border-transparent hover:bg-slate-800/60 hover:text-slate-100',
                      )
                    }
                  >
                    {({ isActive }) => (
                      <>
                        <div className="flex items-center gap-2.5 min-w-0">
                          <Icon
                            className={clsx(
                              'h-4 w-4 shrink-0',
                              isActive
                                ? 'text-cyan-400'
                                : 'text-slate-400 group-hover:text-slate-200',
                            )}
                          />
                          {!collapsed && <span className="truncate">{item.label}</span>}
                        </div>
                        {!collapsed && item.badge === 'incidents' && openIncidentCount > 0 && (
                          <span className="rounded-full bg-rose-500/20 px-1.5 py-0.5 text-[10px] font-mono font-bold text-rose-300 border border-rose-500/40">
                            {openIncidentCount}
                          </span>
                        )}
                        {!collapsed && item.badge === 'pending' && pendingApprovalCount > 0 && (
                          <span className="rounded-full bg-amber-500/20 px-1.5 py-0.5 text-[10px] font-mono font-bold text-amber-300 border border-amber-500/40">
                            {pendingApprovalCount}
                          </span>
                        )}
                        {!collapsed && item.badge === 'demo' && (
                          <span className="rounded bg-emerald-500/15 px-1.5 py-0.5 text-[9px] font-mono font-bold text-emerald-300 border border-emerald-500/30">
                            LIVE
                          </span>
                        )}
                      </>
                    )}
                  </NavLink>
                );
              })}
            </div>
          </div>
        ))}
      </nav>

      {/* Bottom OT Safety Status Pill */}
      {!collapsed && (
        <div className="border-t border-slate-800/90 p-3">
          <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-2">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-amber-300">
                OT SAFETY INTERLOCK
              </span>
              <span className="h-2 w-2 rounded-full bg-amber-400 animate-pulse" />
            </div>
            <p className="mt-1 text-[11px] text-amber-200/80 leading-snug">
              2-Person MFA Rule active on VLAN 30 PLCs. Zero autonomous OT cutoffs.
            </p>
          </div>
        </div>
      )}
    </aside>
  );
};

import React from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import {
  Activity,
  AlertTriangle,
  Bot,
  Radio,
  ShieldCheck,
  UserCheck,
} from 'lucide-react';
import { useSoc } from '../context/SocContext';
import { USER_PERSONAS } from '../services/mockData';
import { StatusBadge } from './StatusBadge';

const ROUTE_TITLES: Record<string, { title: string; subtitle: string }> = {
  '/': { title: 'SOC Command Centre', subtitle: 'BECPL Pune — Organisation-Wide Industrial Security Posture' },
  '/infrastructure': { title: '7-VLAN Infrastructure Map', subtitle: 'Interactive IT / Engineering / OT / DMZ / Cloud / SecMgmt Topology' },
  '/network': { title: 'Network Monitoring & Flow Telemetry', subtitle: 'Real-Time Passive Zeek & Suricata Deep Flow Inspection' },
  '/threat-intel': { title: 'Threat Intelligence & KEV Correlation', subtitle: 'CISA KEV, IP Blocklists, JA3 Fingerprints & Exploitation Ladder' },
  '/supply-chain': { title: 'Third-Party Vendor Trust & Supply Chain', subtitle: 'Vendor Access Graph, 4-Hour Session Timers & Compliance Telemetry' },
  '/vulnerabilities': { title: 'Vulnerability Management & Risk Matrix', subtitle: 'CVSS × Criticality × Exposure Correlation & Phase 3 Target Assets' },
  '/incidents': { title: 'Incident Investigation & Forensics', subtitle: 'Attack Timelines, 2-Hop Blast Radius & 9-Field AI Triage Briefs' },
  '/containment': { title: 'Isolation & Active Defence', subtitle: 'Modes 1–4 Control, Human-in-the-Loop MFA & OT Two-Person Interlock' },
  '/history': { title: 'Security History & Tamper-Evident Audit', subtitle: 'Multi-Field Event Search & SHA-256 Hash-Chained Audit Ledger' },
  '/models': { title: 'Model Intelligence & Continuous Learning', subtitle: 'Random Forest v1 (F1=1.0), SHAP Explainability & Promotion Gate' },
  '/health': { title: 'System Health & Sensor Grid', subtitle: '6 Distributed Passive Taps, Redis Streams & Prometheus Metrics' },
  '/admin': { title: 'Administration & Security Policies', subtitle: '5-Tier RBAC, Isolation Policy Editor, Retention & Maintenance Windows' },
  '/agent-demo': { title: 'Multi-Agent Workflow Operational Demo', subtitle: 'Autonomous Swarm Topology & Interactive 10-Scenario Validation Player' },
};

export const Header: React.FC = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const {
    currentUser,
    setCurrentUser,
    backendOnline,
    overview,
    liveEps,
    liveP95LatencyMs,
  } = useSoc();

  const meta = ROUTE_TITLES[location.pathname] || ROUTE_TITLES['/'];

  return (
    <header className="sticky top-0 z-30 flex h-16 shrink-0 items-center justify-between gap-4 border-b border-slate-800/90 bg-[#0b1120]/95 px-6 backdrop-blur">
      {/* Left: Route Heading */}
      <div className="min-w-0">
        <div className="flex items-center gap-2.5">
          <h1 className="truncate text-base font-bold tracking-tight text-slate-100">
            {meta.title}
          </h1>
          <StatusBadge
            variant={
              overview.networkStatus === 'UNDER_ATTACK'
                ? 'critical'
                : overview.networkStatus === 'ELEVATED'
                  ? 'warning'
                  : 'healthy'
            }
            label={overview.networkStatus.replace('_', ' ')}
            pulse
          />
        </div>
        <p className="truncate text-[11px] font-mono text-slate-400">{meta.subtitle}</p>
      </div>

      {/* Right: Live Telemetry Readouts + API Mode + Persona Switcher */}
      <div className="flex items-center gap-3 shrink-0">
        <div className="hidden xl:flex items-center gap-3 rounded-lg border border-slate-800 bg-slate-900/70 px-3 py-1.5 text-xs font-mono">
          <div className="flex items-center gap-1.5 text-cyan-300">
            <Activity className="h-3.5 w-3.5" />
            <span className="telemetry-num font-semibold">{liveEps.toLocaleString()} EPS</span>
          </div>
          <span className="text-slate-700">|</span>
          <div className="flex items-center gap-1.5 text-emerald-300">
            <ShieldCheck className="h-3.5 w-3.5" />
            <span className="telemetry-num">P95 {liveP95LatencyMs}ms</span>
          </div>
          <span className="text-slate-700">|</span>
          <div className="flex items-center gap-1.5 text-slate-300">
            <Radio
              className={`h-3.5 w-3.5 ${backendOnline ? 'text-emerald-400' : 'text-cyan-400'}`}
            />
            <span className="text-[11px]">
              {backendOnline ? 'REST API LIVE' : 'DIGITAL TWIN'}
            </span>
          </div>
        </div>

        {/* Quick Trigger Demo Shortcut */}
        {location.pathname !== '/agent-demo' && (
          <button
            type="button"
            onClick={() => navigate('/agent-demo')}
            className="hidden md:inline-flex items-center gap-1.5 rounded-lg border border-cyan-500/40 bg-cyan-500/10 px-2.5 py-1.5 text-xs font-mono font-semibold text-cyan-300 hover:bg-cyan-500/20 transition-colors"
          >
            <Bot className="h-3.5 w-3.5" />
            <span>SWARM DEMO</span>
          </button>
        )}

        {/* Active Incidents Alert Button */}
        <button
          type="button"
          onClick={() => navigate('/incidents')}
          className="inline-flex items-center gap-1.5 rounded-lg border border-rose-500/40 bg-rose-500/10 px-2.5 py-1.5 text-xs font-mono font-semibold text-rose-300 hover:bg-rose-500/20 transition-colors"
        >
          <AlertTriangle className="h-3.5 w-3.5" />
          <span className="telemetry-num">{overview.activeIncidents} ACTIVE</span>
        </button>

        {/* RBAC Persona Switcher */}
        <div className="flex items-center gap-2 rounded-lg border border-slate-800 bg-slate-900/90 px-2.5 py-1">
          <UserCheck className="h-3.5 w-3.5 text-emerald-400 shrink-0" />
          <select
            aria-label="Switch RBAC Persona"
            value={currentUser.username}
            onChange={(e) => {
              const found = USER_PERSONAS.find((p) => p.username === e.target.value);
              if (found) setCurrentUser(found);
            }}
            className="bg-transparent text-xs font-mono text-slate-200 focus:outline-none cursor-pointer"
          >
            {USER_PERSONAS.map((p) => (
              <option key={p.username} value={p.username} className="bg-slate-900 text-slate-200">
                {p.full_name} ({p.role})
              </option>
            ))}
          </select>
        </div>
      </div>
    </header>
  );
};

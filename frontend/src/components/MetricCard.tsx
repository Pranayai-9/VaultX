import React from 'react';
import { clsx } from 'clsx';

interface MetricCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon: React.ReactNode;
  accent?: 'emerald' | 'cyan' | 'amber' | 'rose' | 'indigo';
  badge?: string;
  onClick?: () => void;
}

const ACCENT_MAP = {
  emerald: {
    bar: 'bg-emerald-500',
    iconBg: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
    value: 'text-emerald-300',
  },
  cyan: {
    bar: 'bg-cyan-500',
    iconBg: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30',
    value: 'text-cyan-300',
  },
  amber: {
    bar: 'bg-amber-500',
    iconBg: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
    value: 'text-amber-300',
  },
  rose: {
    bar: 'bg-rose-500',
    iconBg: 'bg-rose-500/10 text-rose-400 border-rose-500/30',
    value: 'text-rose-300',
  },
  indigo: {
    bar: 'bg-indigo-500',
    iconBg: 'bg-indigo-500/10 text-indigo-400 border-indigo-500/30',
    value: 'text-indigo-300',
  },
};

export const MetricCard: React.FC<MetricCardProps> = ({
  title,
  value,
  subtitle,
  icon,
  accent = 'cyan',
  badge,
  onClick,
}) => {
  const styles = ACCENT_MAP[accent];
  return (
    <div
      onClick={onClick}
      className={clsx(
        'soc-card relative overflow-hidden rounded-xl p-4',
        onClick && 'soc-card-hover cursor-pointer',
      )}
    >
      <div className={clsx('absolute left-0 top-0 h-full w-1', styles.bar)} />
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="text-[11px] font-mono uppercase tracking-wider text-slate-400 truncate">
            {title}
          </p>
          <div className="mt-1.5 flex items-baseline gap-2">
            <span className={clsx('text-2xl font-bold telemetry-num', styles.value)}>
              {value}
            </span>
            {badge && (
              <span className="rounded bg-slate-800/90 px-1.5 py-0.5 text-[10px] font-mono text-slate-300 border border-slate-700">
                {badge}
              </span>
            )}
          </div>
          {subtitle && (
            <p className="mt-1 text-xs text-slate-400 truncate">{subtitle}</p>
          )}
        </div>
        <div
          className={clsx(
            'flex h-10 w-10 shrink-0 items-center justify-center rounded-lg border',
            styles.iconBg,
          )}
        >
          {icon}
        </div>
      </div>
    </div>
  );
};

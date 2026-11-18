import React from 'react';
import { clsx } from 'clsx';

export type BadgeVariant =
  | 'critical'
  | 'high'
  | 'medium'
  | 'low'
  | 'informational'
  | 'healthy'
  | 'warning'
  | 'elevated'
  | 'offline'
  | 'cyan'
  | 'purple'
  | 'neutral';

const VARIANT_STYLES: Record<BadgeVariant, string> = {
  critical: 'bg-rose-500/15 text-rose-300 border-rose-500/40',
  high: 'bg-orange-500/15 text-orange-300 border-orange-500/40',
  elevated: 'bg-orange-500/15 text-orange-300 border-orange-500/40',
  medium: 'bg-amber-500/15 text-amber-300 border-amber-500/40',
  warning: 'bg-amber-500/15 text-amber-300 border-amber-500/40',
  low: 'bg-sky-500/15 text-sky-300 border-sky-500/40',
  informational: 'bg-cyan-500/15 text-cyan-300 border-cyan-500/40',
  cyan: 'bg-cyan-500/15 text-cyan-300 border-cyan-500/40',
  healthy: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/40',
  purple: 'bg-indigo-500/15 text-indigo-300 border-indigo-500/40',
  offline: 'bg-slate-700/40 text-slate-400 border-slate-600/50',
  neutral: 'bg-slate-800/80 text-slate-300 border-slate-700',
};

const DOT_STYLES: Record<BadgeVariant, string> = {
  critical: 'bg-rose-500',
  high: 'bg-orange-500',
  elevated: 'bg-orange-500',
  medium: 'bg-amber-400',
  warning: 'bg-amber-400',
  low: 'bg-sky-400',
  informational: 'bg-cyan-400',
  cyan: 'bg-cyan-400',
  healthy: 'bg-emerald-400',
  purple: 'bg-indigo-400',
  offline: 'bg-slate-500',
  neutral: 'bg-slate-400',
};

interface StatusBadgeProps {
  variant?: BadgeVariant;
  label: string;
  pulse?: boolean;
  className?: string;
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({
  variant = 'neutral',
  label,
  pulse = false,
  className,
}) => {
  return (
    <span
      className={clsx(
        'inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-[11px] font-mono font-semibold uppercase tracking-wider',
        VARIANT_STYLES[variant],
        className,
      )}
    >
      {pulse && (
        <span className="relative flex h-2 w-2">
          <span
            className={clsx(
              'absolute inline-flex h-full w-full rounded-full opacity-75 animate-ping',
              DOT_STYLES[variant],
            )}
          />
          <span
            className={clsx('relative inline-flex h-2 w-2 rounded-full', DOT_STYLES[variant])}
          />
        </span>
      )}
      {label}
    </span>
  );
};

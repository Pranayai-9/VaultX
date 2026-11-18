import React, { useEffect } from 'react';
import { X } from 'lucide-react';

interface ModalProps {
  open: boolean;
  onClose: () => void;
  title: string;
  subtitle?: string;
  maxWidthClass?: string;
  children: React.ReactNode;
}

export const Modal: React.FC<ModalProps> = ({
  open,
  onClose,
  title,
  subtitle,
  maxWidthClass = 'max-w-2xl',
  children,
}) => {
  useEffect(() => {
    if (!open) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div
        className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm"
        onClick={onClose}
      />
      <div
        className={`relative z-10 w-full ${maxWidthClass} max-h-[90vh] overflow-y-auto rounded-xl border border-slate-700/80 bg-[#0d1424] shadow-2xl shadow-black/80`}
      >
        <div className="sticky top-0 z-10 flex items-start justify-between border-b border-slate-800 bg-[#0d1424]/95 px-5 py-4 backdrop-blur">
          <div>
            <h3 className="text-base font-semibold text-slate-100">{title}</h3>
            {subtitle && (
              <p className="mt-0.5 text-xs font-mono text-slate-400">{subtitle}</p>
            )}
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg p-1.5 text-slate-400 hover:bg-slate-800 hover:text-slate-100 transition-colors"
            aria-label="Close modal"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="p-5">{children}</div>
      </div>
    </div>
  );
};

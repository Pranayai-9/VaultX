import React, { useState } from 'react';
import {
  ArrowRight,
  Brain,
  CheckCircle2,
  Cpu,
  Play,
  RefreshCw,
  ShieldCheck,
  Sparkles,
} from 'lucide-react';
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { ML_MODELS, SHAP_IMPORTANCE } from '../services/mockData';
import type { ModelMetadata } from '../types';
import { vaultxApi } from '../services/api';
import { StatusBadge } from '../components/StatusBadge';

const PIPELINE_STAGES = [
  { id: 1, title: 'Events', sub: 'Zeek / Suricata' },
  { id: 2, title: 'Preprocessing', sub: 'Log1p + Scaler' },
  { id: 3, title: 'Feature Store', sub: '24 Flow Signals' },
  { id: 4, title: 'Verified Labels', sub: 'SOC Analyst QA' },
  { id: 5, title: 'Training', sub: 'Offline Sandbox' },
  { id: 6, title: 'Evaluation', sub: 'F1 / FPR Gates' },
  { id: 7, title: 'Approval', sub: 'SecMgr Signoff' },
  { id: 8, title: 'Deployment', sub: 'Atomic Swap' },
];

export const ModelsView: React.FC = () => {
  const [models, setModels] = useState<ModelMetadata[]>(ML_MODELS);
  const [approvalNotes, setApprovalNotes] = useState(
    'Verified Macro F1=0.9996 & FPR=0.0002 on BECPL holdout benchmark; approved for production.',
  );
  const [promotionBanner, setPromotionBanner] = useState<string | null>(null);
  const [trainingJob, setTrainingJob] = useState<string | null>(null);

  const deployedModels = models.filter((m) => m.status === 'deployed');
  const candidateModel = models.find((m) => m.status === 'candidate');

  const handlePromoteCandidate = async () => {
    if (!candidateModel) return;
    await vaultxApi.promoteModel(candidateModel.model_id, approvalNotes);
    setModels((prev) =>
      prev.map((m) => {
        if (m.model_id === candidateModel.model_id) {
          return { ...m, status: 'deployed', role: 'Classifier' };
        }
        if (m.model_id === 'rf-classifier-v1') {
          return { ...m, status: 'archived' };
        }
        return m;
      }),
    );
    setPromotionBanner(
      `PROMOTED: ${candidateModel.model_name} (${candidateModel.model_version}) is now active in production scoring.`,
    );
  };

  const handleTriggerRetrain = async () => {
    const res = await vaultxApi.triggerRetrain('becpl_synthetic_traffic_50k.csv');
    setTrainingJob(
      `Offline retraining job ${res.jobId} queued in isolated ML sandbox (zero production impact).`,
    );
  };

  return (
    <div className="space-y-6">
      {/* Deployed Model Cards */}
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
        {deployedModels.map((m) => (
          <div key={m.model_id} className="soc-card rounded-xl p-4 flex flex-col justify-between space-y-3">
            <div>
              <div className="flex items-center justify-between gap-2">
                <StatusBadge variant="healthy" label="DEPLOYED" />
                <span className="font-mono text-[11px] text-cyan-300">{m.model_version}</span>
              </div>
              <h3 className="mt-2 text-sm font-bold text-slate-100">{m.model_name}</h3>
              <p className="text-[11px] font-mono text-slate-400">{m.model_type}</p>
            </div>

            <div className="grid grid-cols-2 gap-2 text-xs font-mono border-t border-slate-800 pt-3">
              <div>
                <p className="text-[10px] text-slate-500">MACRO F1</p>
                <p className="text-emerald-300 font-bold telemetry-num">
                  {m.macro_f1.toFixed(4)}
                </p>
              </div>
              <div>
                <p className="text-[10px] text-slate-500">FPR</p>
                <p className="text-cyan-300 font-bold telemetry-num">
                  {(m.false_positive_rate * 100).toFixed(2)}%
                </p>
              </div>
              <div>
                <p className="text-[10px] text-slate-500">LATENCY</p>
                <p className="text-slate-200 telemetry-num">{m.inference_latency_ms} ms</p>
              </div>
              <div>
                <p className="text-[10px] text-slate-500">DRIFT</p>
                <p className="text-emerald-400 telemetry-num">{m.drift_score.toFixed(2)}</p>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Continuous Learning Pipeline Visualizer */}
      <div className="soc-card rounded-xl p-5 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
              <Cpu className="h-4 w-4 text-cyan-400" />
              Continuous Offline Learning Pipeline (Human-Governed MLOps)
            </h2>
            <p className="text-xs font-mono text-slate-400">
              Events -&gt; Preprocessing -&gt; Feature Store -&gt; Verified Labels -&gt; Training -&gt; Evaluation -&gt; Approval -&gt; Deployment
            </p>
          </div>
          <button
            type="button"
            onClick={handleTriggerRetrain}
            className="inline-flex items-center gap-1.5 rounded-lg border border-cyan-500/50 bg-cyan-500/15 px-3 py-1.5 text-xs font-mono font-semibold text-cyan-200 hover:bg-cyan-500/25 cursor-pointer"
          >
            <RefreshCw className="h-3.5 w-3.5" />
            Trigger Offline Retrain
          </button>
        </div>

        {trainingJob && (
          <div className="rounded-lg border border-cyan-500/40 bg-cyan-500/10 px-3.5 py-2 text-xs font-mono text-cyan-200">
            {trainingJob}
          </div>
        )}

        <div className="flex flex-wrap lg:flex-nowrap items-center justify-between gap-2 overflow-x-auto pb-1">
          {PIPELINE_STAGES.map((stage, idx) => (
            <React.Fragment key={stage.id}>
              <div
                className={`min-w-[118px] flex-1 rounded-xl border p-3 text-center ${
                  stage.id === 7
                    ? 'border-amber-500/60 bg-amber-500/10'
                    : 'border-slate-800 bg-slate-900/70'
                }`}
              >
                <span className="font-mono text-[10px] text-cyan-400">STAGE 0{stage.id}</span>
                <p className="mt-1 text-xs font-bold text-slate-100">{stage.title}</p>
                <p className="text-[10px] font-mono text-slate-400">{stage.sub}</p>
              </div>
              {idx < PIPELINE_STAGES.length - 1 && (
                <ArrowRight className="hidden lg:block h-3.5 w-3.5 shrink-0 text-slate-600" />
              )}
            </React.Fragment>
          ))}
        </div>
      </div>

      {/* Bottom Row: SHAP Feature Importance Bar Chart + Candidate Promotion Gate */}
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-12">
        {/* SHAP Feature Importance Horizontal Bar Chart */}
        <div className="soc-card rounded-xl p-5 xl:col-span-7 space-y-3">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
                <Sparkles className="h-4 w-4 text-indigo-400" />
                SHAP TreeExplainer — Global Feature Importance
              </h2>
              <p className="text-xs font-mono text-slate-400">
                Mean |SHAP value| driving Random Forest v1 industrial threat classification
              </p>
            </div>
            <StatusBadge variant="purple" label="EXPLAINABLE AI" />
          </div>

          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={SHAP_IMPORTANCE} layout="vertical" margin={{ left: 32, right: 16 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" horizontal={false} />
                <XAxis type="number" stroke="#64748b" fontSize={11} domain={[0, 0.35]} />
                <YAxis
                  type="category"
                  dataKey="feature"
                  stroke="#94a3b8"
                  fontSize={11}
                  width={150}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0f172a',
                    borderColor: '#334155',
                    borderRadius: 8,
                    fontSize: 12,
                  }}
                />
                <Bar dataKey="importance" name="Mean |SHAP|" radius={[0, 6, 6, 0]}>
                  {SHAP_IMPORTANCE.map((entry, idx) => (
                    <Cell
                      key={entry.feature}
                      fill={idx < 2 ? '#f43f5e' : idx < 4 ? '#06b6d4' : '#818cf8'}
                    />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Candidate Model Promotion Approval Gate */}
        <div className="soc-card rounded-xl p-5 xl:col-span-5 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
              <Brain className="h-4 w-4 text-amber-400" />
              Candidate Model Promotion Gate
            </h2>
            <StatusBadge
              variant={candidateModel ? 'warning' : 'healthy'}
              label={candidateModel ? 'AWAITING SIGNOFF' : 'ALL PROMOTED'}
            />
          </div>

          {promotionBanner && (
            <div className="flex items-center gap-2 rounded-lg border border-emerald-500/40 bg-emerald-500/10 p-3 text-xs font-mono text-emerald-200">
              <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-400" />
              {promotionBanner}
            </div>
          )}

          {candidateModel ? (
            <div className="space-y-4">
              <div className="rounded-xl border border-amber-500/40 bg-amber-950/15 p-4 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-sm font-bold text-slate-100">
                    {candidateModel.model_name}
                  </span>
                  <span className="font-mono text-xs text-amber-300">
                    {candidateModel.model_version}
                  </span>
                </div>
                <p className="text-xs font-mono text-slate-400">
                  Dataset: {candidateModel.training_dataset}
                </p>
                <div className="grid grid-cols-3 gap-2 pt-2 text-xs font-mono">
                  <div className="rounded bg-slate-950/70 p-2">
                    <p className="text-[10px] text-slate-500">MACRO F1</p>
                    <p className="text-emerald-300 font-bold telemetry-num">
                      {candidateModel.macro_f1.toFixed(4)}
                    </p>
                  </div>
                  <div className="rounded bg-slate-950/70 p-2">
                    <p className="text-[10px] text-slate-500">FPR</p>
                    <p className="text-cyan-300 font-bold telemetry-num">
                      {(candidateModel.false_positive_rate * 100).toFixed(2)}%
                    </p>
                  </div>
                  <div className="rounded bg-slate-950/70 p-2">
                    <p className="text-[10px] text-slate-500">LATENCY</p>
                    <p className="text-emerald-300 font-bold telemetry-num">
                      {candidateModel.inference_latency_ms} ms
                    </p>
                  </div>
                </div>
              </div>

              <div>
                <label className="block text-[11px] font-mono text-slate-400 mb-1">
                  Security Manager Evaluation Notes
                </label>
                <textarea
                  rows={2}
                  value={approvalNotes}
                  onChange={(e) => setApprovalNotes(e.target.value)}
                  className="w-full rounded-lg border border-slate-800 bg-slate-950 p-2.5 text-xs font-mono text-slate-200 focus:border-cyan-500 focus:outline-none"
                />
              </div>

              <button
                type="button"
                onClick={handlePromoteCandidate}
                className="w-full inline-flex items-center justify-center gap-2 rounded-lg border border-emerald-500/60 bg-emerald-500/20 px-4 py-2.5 text-xs font-mono font-bold text-emerald-200 hover:bg-emerald-500/30 transition-colors cursor-pointer"
              >
                <ShieldCheck className="h-4 w-4" />
                Approve &amp; Promote Candidate to Production
              </button>
            </div>
          ) : (
            <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-6 text-center space-y-2">
              <Play className="mx-auto h-6 w-6 text-emerald-400" />
              <p className="text-xs font-mono text-slate-300">
                Production classifier is up to date. Trigger an offline retrain to stage a new candidate model.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

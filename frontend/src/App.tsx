import React, { Suspense, lazy, useState } from 'react';
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import { SocProvider } from './context/SocContext';
import { Sidebar } from './components/Sidebar';
import { Header } from './components/Header';
import { CommandCentreView } from './views/CommandCentreView';

const InfrastructureMapView = lazy(() =>
  import('./views/InfrastructureMapView').then((m) => ({ default: m.InfrastructureMapView })),
);
const NetworkMonitoringView = lazy(() =>
  import('./views/NetworkMonitoringView').then((m) => ({ default: m.NetworkMonitoringView })),
);
const ThreatIntelView = lazy(() =>
  import('./views/ThreatIntelView').then((m) => ({ default: m.ThreatIntelView })),
);
const SupplyChainView = lazy(() =>
  import('./views/SupplyChainView').then((m) => ({ default: m.SupplyChainView })),
);
const VulnerabilitiesView = lazy(() =>
  import('./views/VulnerabilitiesView').then((m) => ({ default: m.VulnerabilitiesView })),
);
const IncidentsView = lazy(() =>
  import('./views/IncidentsView').then((m) => ({ default: m.IncidentsView })),
);
const ContainmentView = lazy(() =>
  import('./views/ContainmentView').then((m) => ({ default: m.ContainmentView })),
);
const HistoryAuditView = lazy(() =>
  import('./views/HistoryAuditView').then((m) => ({ default: m.HistoryAuditView })),
);
const ModelsView = lazy(() =>
  import('./views/ModelsView').then((m) => ({ default: m.ModelsView })),
);
const SystemHealthView = lazy(() =>
  import('./views/SystemHealthView').then((m) => ({ default: m.SystemHealthView })),
);
const AdminPoliciesView = lazy(() =>
  import('./views/AdminPoliciesView').then((m) => ({ default: m.AdminPoliciesView })),
);
const AgentDemoView = lazy(() =>
  import('./views/AgentDemoView').then((m) => ({ default: m.AgentDemoView })),
);

const ViewFallback: React.FC = () => (
  <div className="flex h-64 items-center justify-center font-mono text-xs text-cyan-400">
    Loading VaultX SOC telemetry view...
  </div>
);

export const App: React.FC = () => {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);

  return (
    <SocProvider>
      <BrowserRouter>
        <div className="flex h-screen w-screen overflow-hidden bg-[#090d16] text-slate-100">
          <Sidebar
            collapsed={sidebarCollapsed}
            onToggle={() => setSidebarCollapsed((c) => !c)}
          />
          <div className="flex min-w-0 flex-1 flex-col overflow-hidden">
            <Header />
            <main className="soc-grid-bg flex-1 overflow-y-auto px-6 py-5">
              <div className="mx-auto max-w-[1680px]">
                <Suspense fallback={<ViewFallback />}>
                  <Routes>
                    <Route path="/" element={<CommandCentreView />} />
                    <Route path="/infrastructure" element={<InfrastructureMapView />} />
                    <Route path="/network" element={<NetworkMonitoringView />} />
                    <Route path="/threat-intel" element={<ThreatIntelView />} />
                    <Route path="/supply-chain" element={<SupplyChainView />} />
                    <Route path="/vulnerabilities" element={<VulnerabilitiesView />} />
                    <Route path="/incidents" element={<IncidentsView />} />
                    <Route path="/containment" element={<ContainmentView />} />
                    <Route path="/history" element={<HistoryAuditView />} />
                    <Route path="/models" element={<ModelsView />} />
                    <Route path="/health" element={<SystemHealthView />} />
                    <Route path="/admin" element={<AdminPoliciesView />} />
                    <Route path="/agent-demo" element={<AgentDemoView />} />
                    <Route path="*" element={<Navigate to="/" replace />} />
                  </Routes>
                </Suspense>
              </div>
            </main>
          </div>
        </div>
      </BrowserRouter>
    </SocProvider>
  );
};

export default App;

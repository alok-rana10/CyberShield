import React, { useState, useEffect, useCallback } from 'react';
import { Navbar } from '../components/Navbar';
import { StatusCard } from '../components/StatusCard';
import { DashboardOverview } from '../features/dashboard/DashboardOverview';
import { NavigationPlaceholder } from '../components/NavigationPlaceholder';
import { LoginPage } from '../features/auth/LoginPage';
import { RegisterPage } from '../features/auth/RegisterPage';
import { ProtectedRoute } from '../features/auth/ProtectedRoute';
import { FindingsPage } from '../features/findings/FindingsPage';
import { WebSecurityHeadersPage } from '../features/headers/WebSecurityHeadersPage';
import { FileIntegrityMonitorPage } from '../features/fim/FileIntegrityMonitorPage';
import { LogAnalyzerPage } from '../features/logs/LogAnalyzerPage';
import { AuthProvider } from '../features/auth/AuthContext';
import { useAuth } from '../features/auth/useAuth';
import { getHealthStatus, API_BASE_URL } from '../services/api';
import { HealthCheckState } from '../types';
import { UserCheck, KeyRound } from 'lucide-react';

const AppContent: React.FC = () => {
  const { user, isAuthenticated } = useAuth();
  const [activeView, setActiveView] = useState<
    'dashboard' | 'findings' | 'headers' | 'fim' | 'logs' | 'login' | 'register'
  >('dashboard');
  const [selectedFindingId, setSelectedFindingId] = useState<string | undefined>(undefined);
  const [health, setHealth] = useState<HealthCheckState>({
    state: 'checking',
    apiUrl: API_BASE_URL,
  });
  const [isRefreshing, setIsRefreshing] = useState<boolean>(false);

  const checkHealth = useCallback(async () => {
    setIsRefreshing(true);
    const { data, latencyMs, error } = await getHealthStatus();

    if (data && data.status === 'ok') {
      setHealth({
        state: 'online',
        app: data.app,
        apiUrl: API_BASE_URL,
        lastChecked: new Date().toLocaleTimeString(),
        latencyMs,
      });
    } else {
      setHealth({
        state: 'offline',
        apiUrl: API_BASE_URL,
        lastChecked: new Date().toLocaleTimeString(),
        latencyMs,
        errorMessage: error || 'Connection refused',
      });
    }
    setIsRefreshing(false);
  }, []);

  useEffect(() => {
    checkHealth();
  }, [checkHealth]);

  return (
    <div className="min-h-screen bg-slate-950 cyber-grid flex flex-col selection:bg-cyan-500 selection:text-white">
      {/* Top Navigation */}
      <Navbar
        connectionState={health.state}
        activeView={activeView}
        onNavigate={(view) => setActiveView(view)}
      />

      {/* Main Content Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
        {activeView === 'login' && (
          <LoginPage
            onSuccess={() => setActiveView('dashboard')}
            onNavigateToRegister={() => setActiveView('register')}
          />
        )}

        {activeView === 'register' && (
          <RegisterPage
            onSuccess={() => setActiveView('login')}
            onNavigateToLogin={() => setActiveView('login')}
          />
        )}

        {activeView === 'dashboard' && (
          <ProtectedRoute onNavigateToLogin={() => setActiveView('login')}>
            {/* Project Header Banner */}
            <section className="space-y-3">
              <div className="flex items-center space-x-2">
                <span className="h-2 w-2 rounded-full bg-cyan-400"></span>
                <span className="text-xs font-mono uppercase tracking-widest text-cyan-400">
                  Defensive Cyber Engineering Platform
                </span>
              </div>
              <h1 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
                CyberShield Command Center
              </h1>
              <p className="text-sm sm:text-base text-slate-400 max-w-3xl leading-relaxed">
                A modular defensive cybersecurity monitoring and assessment platform built for
                authorized environments. Provides structured vulnerability diagnostics, file
                integrity baselines, log anomaly detection, and compliance reporting.
              </p>
            </section>

            {/* Authenticated Operator Profile Banner */}
            {isAuthenticated && user && (
              <section className="p-4 rounded-xl bg-gradient-to-r from-slate-900 to-cyan-950/40 border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-4 shadow-lg">
                <div className="flex items-center space-x-3">
                  <div className="p-2.5 rounded-lg bg-cyan-950 border border-cyan-800/80 text-cyan-400">
                    <UserCheck className="w-5 h-5" />
                  </div>
                  <div>
                    <div className="flex items-center space-x-2">
                      <span className="text-sm font-semibold text-white">
                        Authenticated as {user.full_name || user.email}
                      </span>
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 uppercase font-bold">
                        {user.role}
                      </span>
                    </div>
                    <p className="text-xs text-slate-400 font-mono mt-0.5">
                      User ID: {user.id} • Account Status: Active
                    </p>
                  </div>
                </div>

                <div className="flex items-center space-x-2 text-xs font-mono text-slate-400 bg-slate-950/60 px-3 py-1.5 rounded-lg border border-slate-800/80 self-start sm:self-auto">
                  <KeyRound className="w-3.5 h-3.5 text-cyan-400" />
                  <span>RBAC Access: {user.role.toUpperCase()} Granted</span>
                </div>
              </section>
            )}

            {/* Live Backend Connection Card */}
            <section>
              <StatusCard status={health} onRefresh={checkHealth} isRefreshing={isRefreshing} />
            </section>

            {/* Real Security Posture Metrics & Recent Findings */}
            <section>
              <DashboardOverview
                onNavigateToFindings={(findingId) => {
                  setSelectedFindingId(findingId);
                  setActiveView('findings');
                }}
              />
            </section>

            {/* Planned Modules Roadmap */}
            <section>
              <NavigationPlaceholder
                onNavigateToHeaders={() => setActiveView('headers')}
                onNavigateToFindings={() => setActiveView('findings')}
                onNavigateToFim={() => setActiveView('fim')}
                onNavigateToLogs={() => setActiveView('logs')}
              />
            </section>
          </ProtectedRoute>
        )}

        {activeView === 'findings' && (
          <ProtectedRoute onNavigateToLogin={() => setActiveView('login')}>
            <FindingsPage initialFindingId={selectedFindingId} />
          </ProtectedRoute>
        )}

        {activeView === 'headers' && (
          <ProtectedRoute onNavigateToLogin={() => setActiveView('login')}>
            <WebSecurityHeadersPage onNavigateToFindings={() => setActiveView('findings')} />
          </ProtectedRoute>
        )}

        {activeView === 'fim' && (
          <ProtectedRoute onNavigateToLogin={() => setActiveView('login')}>
            <FileIntegrityMonitorPage onNavigateToFindings={() => setActiveView('findings')} />
          </ProtectedRoute>
        )}

        {activeView === 'logs' && (
          <ProtectedRoute onNavigateToLogin={() => setActiveView('login')}>
            <LogAnalyzerPage onNavigateToFindings={() => setActiveView('findings')} />
          </ProtectedRoute>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-900 bg-slate-950/80 py-6 text-center text-xs text-slate-500">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-2">
          <span>CyberShield © 2026 — Defensive Security & Assessment Platform</span>
          <span className="font-mono text-slate-600">
            Built with FastAPI, React, TypeScript, and Tailwind CSS
          </span>
        </div>
      </footer>
    </div>
  );
};

export const App: React.FC = () => {
  return (
    <AuthProvider>
      <AppContent />
    </AuthProvider>
  );
};

export default App;

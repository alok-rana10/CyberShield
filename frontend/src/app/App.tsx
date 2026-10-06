import React, { useState, useEffect, useCallback } from 'react';
import { Navbar } from '../components/Navbar';
import { StatusCard } from '../components/StatusCard';
import { DashboardPlaceholder } from '../components/DashboardPlaceholder';
import { NavigationPlaceholder } from '../components/NavigationPlaceholder';
import { getHealthStatus, API_BASE_URL } from '../services/api';
import { HealthCheckState } from '../types';

export const App: React.FC = () => {
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
      <Navbar connectionState={health.state} />

      {/* Main Content Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
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
            A modular defensive cybersecurity monitoring and assessment platform built for authorized environments.
            Provides structured vulnerability diagnostics, file integrity baselines, log anomaly detection, and
            compliance reporting.
          </p>
        </section>

        {/* Live Backend Connection Card */}
        <section>
          <StatusCard
            status={health}
            onRefresh={checkHealth}
            isRefreshing={isRefreshing}
          />
        </section>

        {/* Core Principles & Dashboard Placeholder */}
        <section>
          <DashboardPlaceholder />
        </section>

        {/* Planned Modules Roadmap */}
        <section>
          <NavigationPlaceholder />
        </section>
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-900 bg-slate-950/80 py-6 text-center text-xs text-slate-500">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-2">
          <span>CyberShield © 2026 — Defensive Security & Assessment Platform</span>
          <span className="font-mono text-slate-600">Built with FastAPI, React, TypeScript, and Tailwind CSS</span>
        </div>
      </footer>
    </div>
  );
};

export default App;

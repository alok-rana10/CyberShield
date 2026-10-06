import React from 'react';
import { Activity, RefreshCw, CheckCircle2, XCircle, AlertCircle, Server } from 'lucide-react';
import { HealthCheckState } from '../types';

interface StatusCardProps {
  status: HealthCheckState;
  onRefresh: () => void;
  isRefreshing: boolean;
}

export const StatusCard: React.FC<StatusCardProps> = ({ status, onRefresh, isRefreshing }) => {
  const isOnline = status.state === 'online';
  const isOffline = status.state === 'offline';

  return (
    <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-6 shadow-xl backdrop-blur">
      <div className="flex items-center justify-between pb-4 border-b border-slate-800/80">
        <div className="flex items-center space-x-3">
          <div className="p-2.5 rounded-lg bg-slate-800 text-cyan-400">
            <Server className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-base font-semibold text-white">Core System Connectivity</h2>
            <p className="text-xs text-slate-400">Direct ASGI service probe via REST /api/v1/health</p>
          </div>
        </div>

        <button
          onClick={onRefresh}
          disabled={isRefreshing}
          className="inline-flex items-center space-x-1.5 px-3 py-1.5 text-xs font-medium rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700/60 transition disabled:opacity-50"
          title="Re-run health check probe"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin text-cyan-400' : ''}`} />
          <span>{isRefreshing ? 'Checking...' : 'Refresh'}</span>
        </button>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mt-5">
        {/* Metric 1: Operational Status */}
        <div className="p-4 rounded-lg bg-slate-950/70 border border-slate-800/80">
          <span className="text-xs text-slate-400 block mb-1">Service Status</span>
          <div className="flex items-center space-x-2">
            {isOnline && <CheckCircle2 className="w-5 h-5 text-emerald-400" />}
            {isOffline && <XCircle className="w-5 h-5 text-rose-400" />}
            {status.state === 'checking' && <AlertCircle className="w-5 h-5 text-amber-400 animate-pulse" />}
            <span
              className={`text-sm font-semibold ${
                isOnline ? 'text-emerald-400' : isOffline ? 'text-rose-400' : 'text-amber-400'
              }`}
            >
              {isOnline ? 'Backend Online' : isOffline ? 'Backend Offline' : 'Verifying...'}
            </span>
          </div>
        </div>

        {/* Metric 2: Application Name */}
        <div className="p-4 rounded-lg bg-slate-950/70 border border-slate-800/80">
          <span className="text-xs text-slate-400 block mb-1">Target Application</span>
          <div className="flex items-center space-x-2">
            <span className="text-sm font-semibold font-mono text-cyan-300">
              {status.app || (isOffline ? 'Unavailable' : 'Loading...')}
            </span>
          </div>
        </div>

        {/* Metric 3: Endpoint URL */}
        <div className="p-4 rounded-lg bg-slate-950/70 border border-slate-800/80">
          <span className="text-xs text-slate-400 block mb-1">Configured Base URL</span>
          <div className="text-xs font-mono text-slate-300 truncate" title={status.apiUrl}>
            {status.apiUrl}
          </div>
        </div>

        {/* Metric 4: Latency */}
        <div className="p-4 rounded-lg bg-slate-950/70 border border-slate-800/80">
          <span className="text-xs text-slate-400 block mb-1">Round-trip Latency</span>
          <div className="flex items-center space-x-1.5">
            <Activity className="w-4 h-4 text-cyan-400" />
            <span className="text-sm font-mono font-medium text-slate-200">
              {status.latencyMs !== undefined ? `${status.latencyMs} ms` : '—'}
            </span>
          </div>
        </div>
      </div>

      {/* Offline Error Diagnostic Banner */}
      {isOffline && status.errorMessage && (
        <div className="mt-4 p-3 rounded-lg bg-rose-950/30 border border-rose-800/50 text-rose-300 text-xs flex items-start space-x-2">
          <AlertCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
          <div>
            <span className="font-semibold">Connection failed:</span> {status.errorMessage}. Verify that the FastAPI backend is running with Uvicorn.
          </div>
        </div>
      )}
    </div>
  );
};

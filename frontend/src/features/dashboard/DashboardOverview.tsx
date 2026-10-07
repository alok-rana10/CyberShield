import React, { useEffect, useState, useCallback } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  CheckCircle2,
  Clock,
  ArrowRight,
  RefreshCw,
  Layers,
  Terminal,
  Activity,
  Compass,
} from 'lucide-react';
import { DashboardSummary, SecurityFinding } from '../../types';
import { getDashboardSummaryApi } from '../../services/api';
import { useAuth } from '../auth/useAuth';

interface DashboardOverviewProps {
  onNavigateToFindings: (selectedFindingId?: string) => void;
}

export const DashboardOverview: React.FC<DashboardOverviewProps> = ({ onNavigateToFindings }) => {
  const { token } = useAuth();
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const fetchSummary = useCallback(async () => {
    if (!token) return;
    setIsLoading(true);
    setError(null);
    try {
      const data = await getDashboardSummaryApi(token);
      setSummary(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to retrieve security metrics');
    } finally {
      setIsLoading(false);
    }
  }, [token]);

  useEffect(() => {
    fetchSummary();
  }, [fetchSummary]);

  const getSeverityBadgeClass = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical':
        return 'bg-rose-950/80 text-rose-300 border-rose-800/80 shadow-[0_0_8px_rgba(244,63,94,0.3)]';
      case 'high':
        return 'bg-orange-950/80 text-orange-300 border-orange-800/80';
      case 'medium':
        return 'bg-amber-950/80 text-amber-300 border-amber-800/80';
      case 'low':
        return 'bg-cyan-950/80 text-cyan-300 border-cyan-800/80';
      case 'informational':
      default:
        return 'bg-slate-800 text-slate-300 border-slate-700';
    }
  };

  const getStatusBadgeClass = (status: string) => {
    switch (status.toLowerCase()) {
      case 'open':
        return 'bg-amber-950/60 text-amber-300 border-amber-800/60';
      case 'resolved':
        return 'bg-emerald-950/60 text-emerald-300 border-emerald-800/60';
      case 'accepted':
        return 'bg-indigo-950/60 text-indigo-300 border-indigo-800/60';
      default:
        return 'bg-slate-800 text-slate-300 border-slate-700';
    }
  };

  const getScoreRating = (score: number) => {
    if (score >= 90)
      return {
        label: 'Optimal Posture',
        color: 'text-emerald-400',
        bg: 'bg-emerald-950/40 border-emerald-800/50',
      };
    if (score >= 70)
      return {
        label: 'Satisfactory Hardening',
        color: 'text-cyan-400',
        bg: 'bg-cyan-950/40 border-cyan-800/50',
      };
    if (score >= 50)
      return {
        label: 'Moderate Exposure',
        color: 'text-amber-400',
        bg: 'bg-amber-950/40 border-amber-800/50',
      };
    return {
      label: 'High Remediation Priority',
      color: 'text-rose-400',
      bg: 'bg-rose-950/40 border-rose-800/50',
    };
  };

  return (
    <div className="space-y-6">
      {/* Top Header & Posture Index Bar */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-6 shadow-xl backdrop-blur">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-5 border-b border-slate-800/80">
          <div>
            <h2 className="text-lg font-bold text-white flex items-center space-x-2">
              <Activity className="w-5 h-5 text-cyan-400" />
              <span>Security Posture & Telemetry</span>
            </h2>
            <p className="text-xs text-slate-400 mt-1">
              Aggregated defensive metrics calculated from verified authorized diagnostic
              assessments
            </p>
          </div>

          <div className="flex items-center space-x-3">
            {summary && (
              <div
                className={`px-3 py-1.5 rounded-lg border flex items-center space-x-2 text-xs font-mono ${getScoreRating(summary.posture_score).bg}`}
              >
                <span className="text-slate-400">Posture Score:</span>
                <span
                  className={`text-sm font-bold ${getScoreRating(summary.posture_score).color}`}
                >
                  {summary.posture_score}/100
                </span>
                <span className="text-[10px] text-slate-400">
                  ({getScoreRating(summary.posture_score).label})
                </span>
              </div>
            )}

            <button
              onClick={fetchSummary}
              disabled={isLoading}
              className="inline-flex items-center space-x-1.5 px-3 py-1.5 text-xs font-medium rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700/60 transition disabled:opacity-50"
            >
              <RefreshCw
                className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin text-cyan-400' : ''}`}
              />
              <span>{isLoading ? 'Syncing...' : 'Refresh'}</span>
            </button>
          </div>
        </div>

        {error && (
          <div className="mt-4 p-3 rounded-lg bg-rose-950/40 border border-rose-800/60 text-rose-300 text-xs flex items-center justify-between">
            <span>{error}</span>
            <button onClick={fetchSummary} className="underline text-xs hover:text-white">
              Retry
            </button>
          </div>
        )}

        {/* Real Metrics Cards Grid */}
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 mt-6">
          {/* Card: Total */}
          <div className="p-3.5 rounded-lg bg-slate-950/70 border border-slate-800/80 flex flex-col justify-between">
            <span className="text-[11px] font-mono text-slate-400">Total Findings</span>
            <span className="text-2xl font-bold font-mono text-white mt-1">
              {isLoading ? '—' : (summary?.total_findings ?? 0)}
            </span>
            <span className="text-[10px] text-slate-500 mt-1">Recorded in registry</span>
          </div>

          {/* Card: Critical */}
          <div className="p-3.5 rounded-lg bg-rose-950/20 border border-rose-900/40 flex flex-col justify-between">
            <span className="text-[11px] font-mono text-rose-400 flex items-center justify-between">
              Critical
              <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
            </span>
            <span className="text-2xl font-bold font-mono text-rose-300 mt-1">
              {isLoading ? '—' : (summary?.severity_counts.critical ?? 0)}
            </span>
            <span className="text-[10px] text-rose-400/70 mt-1">Immediate action</span>
          </div>

          {/* Card: High */}
          <div className="p-3.5 rounded-lg bg-orange-950/20 border border-orange-900/40 flex flex-col justify-between">
            <span className="text-[11px] font-mono text-orange-400 flex items-center justify-between">
              High
              <AlertTriangle className="w-3.5 h-3.5 text-orange-400" />
            </span>
            <span className="text-2xl font-bold font-mono text-orange-300 mt-1">
              {isLoading ? '—' : (summary?.severity_counts.high ?? 0)}
            </span>
            <span className="text-[10px] text-orange-400/70 mt-1">Elevated risk</span>
          </div>

          {/* Card: Medium */}
          <div className="p-3.5 rounded-lg bg-amber-950/20 border border-amber-900/40 flex flex-col justify-between">
            <span className="text-[11px] font-mono text-amber-400 flex items-center justify-between">
              Medium
              <Clock className="w-3.5 h-3.5 text-amber-400" />
            </span>
            <span className="text-2xl font-bold font-mono text-amber-300 mt-1">
              {isLoading ? '—' : (summary?.severity_counts.medium ?? 0)}
            </span>
            <span className="text-[10px] text-amber-400/70 mt-1">Hardening gap</span>
          </div>

          {/* Card: Open */}
          <div className="p-3.5 rounded-lg bg-slate-950/70 border border-slate-800/80 flex flex-col justify-between">
            <span className="text-[11px] font-mono text-amber-400 flex items-center justify-between">
              Open Status
              <span className="w-2 h-2 rounded-full bg-amber-400"></span>
            </span>
            <span className="text-2xl font-bold font-mono text-amber-300 mt-1">
              {isLoading ? '—' : (summary?.status_counts.open ?? 0)}
            </span>
            <span className="text-[10px] text-slate-500 mt-1">Awaiting fix</span>
          </div>

          {/* Card: Resolved */}
          <div className="p-3.5 rounded-lg bg-emerald-950/20 border border-emerald-900/40 flex flex-col justify-between">
            <span className="text-[11px] font-mono text-emerald-400 flex items-center justify-between">
              Resolved
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
            </span>
            <span className="text-2xl font-bold font-mono text-emerald-300 mt-1">
              {isLoading ? '—' : (summary?.status_counts.resolved ?? 0)}
            </span>
            <span className="text-[10px] text-emerald-400/70 mt-1">Verified mitigated</span>
          </div>
        </div>

        {/* Distribution Bars */}
        {summary && summary.total_findings > 0 && (
          <div className="mt-6 pt-5 border-t border-slate-800/80 space-y-3">
            <div className="flex items-center justify-between text-xs font-mono text-slate-400">
              <span>Severity Distribution</span>
              <span>{summary.total_findings} total analyzed</span>
            </div>
            <div className="h-2.5 w-full bg-slate-950 rounded-full overflow-hidden flex border border-slate-800">
              {summary.severity_counts.critical > 0 && (
                <div
                  style={{
                    width: `${(summary.severity_counts.critical / summary.total_findings) * 100}%`,
                  }}
                  className="bg-rose-500"
                  title={`Critical: ${summary.severity_counts.critical}`}
                />
              )}
              {summary.severity_counts.high > 0 && (
                <div
                  style={{
                    width: `${(summary.severity_counts.high / summary.total_findings) * 100}%`,
                  }}
                  className="bg-orange-500"
                  title={`High: ${summary.severity_counts.high}`}
                />
              )}
              {summary.severity_counts.medium > 0 && (
                <div
                  style={{
                    width: `${(summary.severity_counts.medium / summary.total_findings) * 100}%`,
                  }}
                  className="bg-amber-400"
                  title={`Medium: ${summary.severity_counts.medium}`}
                />
              )}
              {summary.severity_counts.low > 0 && (
                <div
                  style={{
                    width: `${(summary.severity_counts.low / summary.total_findings) * 100}%`,
                  }}
                  className="bg-cyan-400"
                  title={`Low: ${summary.severity_counts.low}`}
                />
              )}
              {summary.severity_counts.informational > 0 && (
                <div
                  style={{
                    width: `${(summary.severity_counts.informational / summary.total_findings) * 100}%`,
                  }}
                  className="bg-slate-500"
                  title={`Informational: ${summary.severity_counts.informational}`}
                />
              )}
            </div>
            <div className="flex flex-wrap gap-4 text-[11px] font-mono text-slate-400 pt-1">
              <span className="flex items-center space-x-1.5">
                <span className="w-2 h-2 rounded-full bg-rose-500"></span>
                <span>Critical ({summary.severity_counts.critical})</span>
              </span>
              <span className="flex items-center space-x-1.5">
                <span className="w-2 h-2 rounded-full bg-orange-500"></span>
                <span>High ({summary.severity_counts.high})</span>
              </span>
              <span className="flex items-center space-x-1.5">
                <span className="w-2 h-2 rounded-full bg-amber-400"></span>
                <span>Medium ({summary.severity_counts.medium})</span>
              </span>
              <span className="flex items-center space-x-1.5">
                <span className="w-2 h-2 rounded-full bg-cyan-400"></span>
                <span>Low ({summary.severity_counts.low})</span>
              </span>
              <span className="flex items-center space-x-1.5">
                <span className="w-2 h-2 rounded-full bg-slate-500"></span>
                <span>Info ({summary.severity_counts.informational})</span>
              </span>
            </div>
          </div>
        )}
      </div>

      {/* Recent Findings Section */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-6 shadow-xl backdrop-blur">
        <div className="flex items-center justify-between pb-4 border-b border-slate-800/80 mb-4">
          <div>
            <h3 className="text-base font-semibold text-white flex items-center space-x-2">
              <Layers className="w-4 h-4 text-cyan-400" />
              <span>Recent Security Findings</span>
            </h3>
            <p className="text-xs text-slate-400">
              Most recently identified vulnerabilities and gaps
            </p>
          </div>
          <button
            onClick={() => onNavigateToFindings()}
            className="inline-flex items-center space-x-1.5 text-xs font-medium text-cyan-400 hover:text-cyan-300 transition"
          >
            <span>View All Registry</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>

        {isLoading ? (
          <div className="py-8 text-center text-xs font-mono text-slate-400 animate-pulse">
            Loading recent security records from backend...
          </div>
        ) : !summary || summary.recent_findings.length === 0 ? (
          <div className="py-8 text-center space-y-2">
            <ShieldCheck className="w-8 h-8 text-emerald-400 mx-auto" />
            <p className="text-sm font-semibold text-slate-200">
              No Security Findings Recorded Yet
            </p>
            <p className="text-xs text-slate-400 max-w-sm mx-auto">
              Your security registry is currently clean. Automated scans and diagnostic modules will
              populate this dashboard.
            </p>
            <button
              onClick={() => onNavigateToFindings()}
              className="mt-3 px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-xs font-medium text-white transition"
            >
              Open Findings Registry
            </button>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950/60 text-slate-400 font-mono border-b border-slate-800">
                <tr>
                  <th className="py-2.5 px-3">Severity</th>
                  <th className="py-2.5 px-3">Status</th>
                  <th className="py-2.5 px-3">Title</th>
                  <th className="py-2.5 px-3">Affected Asset</th>
                  <th className="py-2.5 px-3">Module</th>
                  <th className="py-2.5 px-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-sans">
                {summary.recent_findings.map((finding: SecurityFinding) => (
                  <tr key={finding.id} className="hover:bg-slate-800/40 transition">
                    <td className="py-2.5 px-3">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-mono uppercase font-bold border ${getSeverityBadgeClass(finding.severity)}`}
                      >
                        {finding.severity}
                      </span>
                    </td>
                    <td className="py-2.5 px-3">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-mono uppercase border ${getStatusBadgeClass(finding.status)}`}
                      >
                        {finding.status}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 font-medium text-slate-200">
                      <div className="max-w-md truncate" title={finding.title}>
                        {finding.title}
                      </div>
                      {finding.cwe_id && (
                        <span className="text-[10px] font-mono text-slate-500">
                          {finding.cwe_id}
                        </span>
                      )}
                    </td>
                    <td className="py-2.5 px-3 font-mono text-slate-400 text-[11px] truncate max-w-xs">
                      {finding.affected_resource || '—'}
                    </td>
                    <td className="py-2.5 px-3 font-mono text-slate-400 text-[11px]">
                      {finding.source_module}
                    </td>
                    <td className="py-2.5 px-3 text-right">
                      <button
                        onClick={() => onNavigateToFindings(finding.id)}
                        className="text-xs text-cyan-400 hover:text-cyan-300 font-medium inline-flex items-center space-x-1"
                      >
                        <span>Details</span>
                        <ArrowRight className="w-3 h-3" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Defensive Security Notice */}
      <div className="p-4 rounded-lg bg-cyan-950/20 border border-cyan-800/40 flex items-start space-x-3 text-xs text-slate-300">
        <ShieldAlert className="w-5 h-5 text-cyan-400 shrink-0 mt-0.5" />
        <p className="leading-relaxed">
          <strong className="text-cyan-300">Defensive Security Notice:</strong> CyberShield is
          designed strictly for monitoring, testing, and securing systems, networks, files, and
          domains you own or have explicit, documented authorization to assess. All diagnostic
          findings are logged in an immutable audit trail.
        </p>
      </div>

      {/* Operational Principles Overview */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="p-4 rounded-lg bg-slate-950/70 border border-slate-800 flex flex-col justify-between">
          <div>
            <div className="w-8 h-8 rounded-lg bg-cyan-950/80 border border-cyan-800/50 text-cyan-400 flex items-center justify-center mb-2.5">
              <ShieldCheck className="w-4 h-4" />
            </div>
            <h4 className="text-xs font-semibold text-white">Explicit Authorization Scope</h4>
            <p className="text-[11px] text-slate-400 mt-1 leading-relaxed">
              Every operation strictly requires operator confirmation. Scanners prohibit probing
              boundaries outside target scope.
            </p>
          </div>
          <div className="mt-3 pt-2 border-t border-slate-900 text-[10px] font-mono text-cyan-400">
            Rule: Zero Offensive Capability
          </div>
        </div>

        <div className="p-4 rounded-lg bg-slate-950/70 border border-slate-800 flex flex-col justify-between">
          <div>
            <div className="w-8 h-8 rounded-lg bg-indigo-950/80 border border-indigo-800/50 text-indigo-400 flex items-center justify-center mb-2.5">
              <Terminal className="w-4 h-4" />
            </div>
            <h4 className="text-xs font-semibold text-white">Non-Destructive Mechanics</h4>
            <p className="text-[11px] text-slate-400 mt-1 leading-relaxed">
              Diagnostic probes use safe timeouts and passive header inspection. No exploits or
              intrusive testing tools are permitted.
            </p>
          </div>
          <div className="mt-3 pt-2 border-t border-slate-900 text-[10px] font-mono text-indigo-400">
            Rule: Safe Socket Connect Only
          </div>
        </div>

        <div className="p-4 rounded-lg bg-slate-950/70 border border-slate-800 flex flex-col justify-between">
          <div>
            <div className="w-8 h-8 rounded-lg bg-amber-950/80 border border-amber-800/50 text-amber-400 flex items-center justify-center mb-2.5">
              <Compass className="w-4 h-4" />
            </div>
            <h4 className="text-xs font-semibold text-white">Immutable Non-Repudiation</h4>
            <p className="text-[11px] text-slate-400 mt-1 leading-relaxed">
              All findings creation, status changes, and administrative deletions generate
              structured compliance audit trails.
            </p>
          </div>
          <div className="mt-3 pt-2 border-t border-slate-900 text-[10px] font-mono text-amber-400">
            Rule: Full RBAC & Audit Trails
          </div>
        </div>
      </div>
    </div>
  );
};

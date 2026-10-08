import React, { useState, useEffect, useCallback } from 'react';
import {
  ScrollText,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  CheckCircle2,
  Lock,
  ArrowRight,
  FolderTree,
  FileCode,
  Search,
  RefreshCw,
  Loader2,
  Terminal,
  Eye,
  X,
  User,
  Globe,
} from 'lucide-react';
import {
  LogAnalysisResponse,
  LogEventItem,
  LogStatusSummary,
} from '../../types';
import {
  analyzeLogsApi,
  getLogEventsApi,
  getLogRootsApi,
  getLogSummaryApi,
} from '../../services/api';
import { useAuth } from '../auth/useAuth';

interface LogAnalyzerPageProps {
  onNavigateToFindings?: () => void;
}

export const LogAnalyzerPage: React.FC<LogAnalyzerPageProps> = ({
  onNavigateToFindings,
}) => {
  const { user, token } = useAuth();
  const isOperator = user?.role === 'admin' || user?.role === 'analyst';

  // Input & Allowed Roots State
  const [targetPath, setTargetPath] = useState<string>('./logs/auth.log');
  const [allowedRoots, setAllowedRoots] = useState<string[]>([]);
  const [isAnalyzing, setIsAnalyzing] = useState<boolean>(false);
  const [actionError, setActionError] = useState<string | null>(null);

  // Analysis Result Notification State
  const [lastAnalysisResult, setLastAnalysisResult] = useState<LogAnalysisResponse | null>(null);

  // Status Summary Metrics State
  const [statusSummary, setStatusSummary] = useState<LogStatusSummary | null>(null);
  const [isLoadingSummary, setIsLoadingSummary] = useState<boolean>(false);

  // Events Table State
  const [events, setEvents] = useState<LogEventItem[]>([]);
  const [totalEvents, setTotalEvents] = useState<number>(0);
  const [currentPage, setCurrentPage] = useState<number>(1);
  const [totalPages, setTotalPages] = useState<number>(1);
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [categoryFilter, setCategoryFilter] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [isLoadingEvents, setIsLoadingEvents] = useState<boolean>(false);

  // Event Details Modal
  const [selectedEvent, setSelectedEvent] = useState<LogEventItem | null>(null);

  // Fetch configured allowed roots
  const fetchRoots = useCallback(async () => {
    if (!token) return;
    try {
      const data = await getLogRootsApi(token);
      setAllowedRoots(data.allowed_roots);
      if (data.allowed_roots.length > 0 && !targetPath) {
        setTargetPath(`${data.allowed_roots[0]}/auth.log`);
      }
    } catch {
      // Background roots fetch failure
    }
  }, [token, targetPath]);

  // Fetch status summary metrics
  const fetchStatusSummary = useCallback(async () => {
    if (!token) return;
    setIsLoadingSummary(true);
    try {
      const data = await getLogSummaryApi(token);
      setStatusSummary(data);
      if (data.allowed_roots && data.allowed_roots.length > 0) {
        setAllowedRoots(data.allowed_roots);
      }
    } catch {
      // Background summary fetch error
    } finally {
      setIsLoadingSummary(false);
    }
  }, [token]);

  // Fetch paginated events
  const fetchEvents = useCallback(
    async (page = 1) => {
      if (!token) return;
      setIsLoadingEvents(true);
      try {
        const data = await getLogEventsApi(token, {
          page,
          size: 15,
          severity: severityFilter,
          category: categoryFilter,
          search: searchQuery,
        });
        setEvents(data.items);
        setTotalEvents(data.total);
        setCurrentPage(data.page);
        setTotalPages(data.pages);
      } catch {
        // Events fetch error
      } finally {
        setIsLoadingEvents(false);
      }
    },
    [token, severityFilter, categoryFilter, searchQuery],
  );

  useEffect(() => {
    fetchRoots();
    fetchStatusSummary();
  }, [fetchRoots, fetchStatusSummary]);

  useEffect(() => {
    fetchEvents(1);
  }, [fetchEvents]);

  // Handle Form Submission
  const handleAnalyze = async () => {
    if (!token || !isOperator || !targetPath.trim()) return;
    setIsAnalyzing(true);
    setActionError(null);
    setLastAnalysisResult(null);

    try {
      const response = await analyzeLogsApi(token, { path: targetPath.trim() });
      setLastAnalysisResult(response);
      fetchStatusSummary();
      fetchEvents(1);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Log analysis failed';
      setActionError(msg);
    } finally {
      setIsAnalyzing(false);
    }
  };

  const getSeverityBadge = (severity: string) => {
    const sev = severity.toUpperCase();
    switch (sev) {
      case 'CRITICAL':
      case 'HIGH':
        return (
          <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-[11px] font-mono font-bold bg-rose-950/80 text-rose-400 border border-rose-800/80">
            <AlertTriangle className="w-3 h-3" />
            <span>{sev}</span>
          </span>
        );
      case 'MEDIUM':
        return (
          <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-[11px] font-mono font-bold bg-amber-950/80 text-amber-400 border border-amber-800/80">
            <ShieldAlert className="w-3 h-3" />
            <span>{sev}</span>
          </span>
        );
      case 'LOW':
        return (
          <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-[11px] font-mono font-medium bg-cyan-950/80 text-cyan-400 border border-cyan-800/80">
            <span>{sev}</span>
          </span>
        );
      case 'INFO':
      default:
        return (
          <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-[11px] font-mono text-slate-400 bg-slate-900 border border-slate-800">
            <span>{sev}</span>
          </span>
        );
    }
  };

  const getCategoryBadge = (category: string) => {
    switch (category) {
      case 'authentication_failure':
        return (
          <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-rose-950/50 text-rose-300 border border-rose-800/50">
            auth_fail
          </span>
        );
      case 'authentication_success':
        return (
          <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-emerald-950/50 text-emerald-300 border border-emerald-800/50">
            auth_success
          </span>
        );
      case 'access_denied':
        return (
          <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-amber-950/50 text-amber-300 border border-amber-800/50">
            access_denied
          </span>
        );
      case 'suspicious_request':
        return (
          <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-purple-950/50 text-purple-300 border border-purple-800/50">
            web_probe
          </span>
        );
      case 'system_error':
        return (
          <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-slate-800 text-slate-300 border border-slate-700">
            system_error
          </span>
        );
      default:
        return (
          <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-slate-800 text-slate-400">
            {category}
          </span>
        );
    }
  };

  return (
    <div className="space-y-8">
      {/* Header Banner */}
      <div className="p-6 rounded-xl bg-slate-900/80 border border-slate-800 backdrop-blur shadow-xl relative overflow-hidden">
        <div className="absolute top-0 right-0 w-96 h-96 bg-cyan-500/5 rounded-full blur-3xl pointer-events-none" />
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center space-x-2">
              <span className="p-2 rounded-lg bg-cyan-950 border border-cyan-500/30 text-cyan-400 shadow-sm shadow-cyan-500/20">
                <ScrollText className="w-5 h-5" />
              </span>
              <span className="text-xs font-mono uppercase tracking-widest text-cyan-400 font-semibold">
                Defensive Log Analysis • Phase 7
              </span>
            </div>
            <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight pt-1">
              Defensive Log Analyzer
            </h1>
            <p className="text-sm text-slate-400 max-w-3xl leading-relaxed">
              Automated ingestion, parsing, and correlation of security events from authorized log
              files (syslog, auth.log, Apache/Nginx web access, and application logs) with direct
              Findings Engine integration.
            </p>
          </div>

          <div className="flex flex-col items-start md:items-end space-y-2">
            <div className="flex items-center space-x-2 text-xs font-mono px-3 py-1.5 rounded-lg bg-slate-950/60 border border-slate-800 text-slate-300">
              <FolderTree className="w-3.5 h-3.5 text-cyan-400" />
              <span>
                Authorized Roots:{' '}
                {allowedRoots.length > 0 ? allowedRoots.join(', ') : './logs, ./data/logs'}
              </span>
            </div>
            <div className="flex items-center space-x-1.5 text-xs font-mono text-emerald-400">
              <ShieldCheck className="w-3.5 h-3.5" />
              <span>Bounded Streaming Ingestion Active</span>
            </div>
          </div>
        </div>
      </div>

      {/* Control Panel: Target Path, Allowed Roots Chips, and Action Triggers */}
      <div className="p-6 rounded-xl bg-slate-900/60 border border-slate-800 shadow-xl space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-base font-semibold text-white flex items-center space-x-2">
            <FileCode className="w-4 h-4 text-cyan-400" />
            <span>Target Log File</span>
          </h2>
          {!isOperator && (
            <div className="flex items-center space-x-1.5 text-xs text-amber-400 font-mono bg-amber-950/40 px-3 py-1 rounded border border-amber-800/60">
              <Lock className="w-3.5 h-3.5" />
              <span>Viewer Role (Read-Only)</span>
            </div>
          )}
        </div>

        <div className="space-y-3">
          <div className="flex flex-col sm:flex-row gap-3">
            <div className="relative flex-1">
              <input
                type="text"
                value={targetPath}
                onChange={(e) => setTargetPath(e.target.value)}
                placeholder="Enter authorized log path, e.g. ./logs/auth.log or ./logs/access.log"
                className="w-full px-4 py-2.5 rounded-lg bg-slate-950/80 border border-slate-700/80 text-white placeholder-slate-500 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-cyan-500 focus:border-cyan-500"
              />
            </div>

            <button
              type="button"
              onClick={handleAnalyze}
              disabled={!isOperator || isAnalyzing || !targetPath.trim()}
              title={
                !isOperator
                  ? 'Analyst or Admin permissions required'
                  : 'Ingest and analyze target log file'
              }
              className="px-5 py-2.5 rounded-lg font-medium text-sm flex items-center space-x-2 bg-cyan-600 hover:bg-cyan-500 text-white shadow-md shadow-cyan-900/30 transition disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {isAnalyzing ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span>Analyzing Logs...</span>
                </>
              ) : (
                <>
                  <Terminal className="w-4 h-4" />
                  <span>Analyze Log File</span>
                </>
              )}
            </button>
          </div>

          {/* Quick-select chips */}
          <div className="flex flex-wrap items-center gap-2 pt-1 text-xs text-slate-400">
            <span className="font-mono">Quick select:</span>
            {allowedRoots.map((root) => (
              <React.Fragment key={root}>
                <button
                  type="button"
                  onClick={() => setTargetPath(`${root}/auth.log`)}
                  className="px-2.5 py-1 rounded bg-slate-800/80 hover:bg-slate-700 hover:text-cyan-400 font-mono text-slate-300 border border-slate-700/60 transition"
                >
                  {root}/auth.log
                </button>
                <button
                  type="button"
                  onClick={() => setTargetPath(`${root}/access.log`)}
                  className="px-2.5 py-1 rounded bg-slate-800/80 hover:bg-slate-700 hover:text-cyan-400 font-mono text-slate-300 border border-slate-700/60 transition"
                >
                  {root}/access.log
                </button>
              </React.Fragment>
            ))}
          </div>
        </div>

        {/* Action Error Banner */}
        {actionError && (
          <div className="p-4 rounded-lg bg-rose-950/60 border border-rose-800/80 text-rose-300 flex items-start space-x-3 text-sm">
            <AlertTriangle className="w-5 h-5 flex-shrink-0 text-rose-400 mt-0.5" />
            <div>
              <p className="font-semibold">Log Analysis Rejected</p>
              <p className="font-mono text-xs mt-1 text-rose-200">{actionError}</p>
            </div>
          </div>
        )}

        {/* Analysis Result Banner */}
        {lastAnalysisResult && (
          <div className="p-4 rounded-lg bg-slate-950 border border-slate-700 text-slate-200 space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                <span className="font-semibold text-white text-sm">
                  Analysis Completed for{' '}
                  <span className="font-mono text-cyan-400">{lastAnalysisResult.file_name}</span>
                </span>
              </div>
              <button
                onClick={() => setLastAnalysisResult(null)}
                className="text-xs text-slate-400 hover:text-slate-200 font-mono underline"
              >
                Dismiss
              </button>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-center text-xs">
              <div className="p-2 rounded bg-slate-900 border border-slate-800">
                <span className="text-slate-400 block">Lines Scanned</span>
                <span className="font-mono font-bold text-sm text-white">{lastAnalysisResult.lines_read}</span>
              </div>
              <div className="p-2 rounded bg-cyan-950/40 border border-cyan-800/50">
                <span className="text-cyan-400 block">Events Normalized</span>
                <span className="font-mono font-bold text-sm text-cyan-300">
                  {lastAnalysisResult.events_parsed_count}
                </span>
              </div>
              <div className="p-2 rounded bg-amber-950/40 border border-amber-800/50">
                <span className="text-amber-400 block">Findings Generated</span>
                <span className="font-mono font-bold text-sm text-amber-300">
                  {lastAnalysisResult.created_findings_count}
                </span>
              </div>
              <div className="p-2 rounded bg-emerald-950/40 border border-emerald-800/50">
                <span className="text-emerald-400 block">Log Format</span>
                <span className="font-mono font-bold text-sm text-emerald-300">Supported</span>
              </div>
            </div>

            {lastAnalysisResult.created_findings_count > 0 && (
              <div className="flex items-center justify-between pt-2 border-t border-slate-800 text-xs">
                <span className="text-amber-300 flex items-center space-x-1.5 font-medium">
                  <AlertTriangle className="w-4 h-4 text-amber-400" />
                  <span>
                    Correlated {lastAnalysisResult.created_findings_count} security finding(s) into Findings Registry.
                  </span>
                </span>
                {onNavigateToFindings && (
                  <button
                    onClick={onNavigateToFindings}
                    className="inline-flex items-center space-x-1 text-cyan-400 hover:text-cyan-300 font-semibold underline"
                  >
                    <span>View in Findings Registry</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                )}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Aggregate Metric KPI Cards */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 shadow-lg">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-1">
            <span>Total Events</span>
            <ScrollText className="w-4 h-4 text-cyan-400" />
          </div>
          <p className="text-2xl font-bold font-mono text-white">
            {isLoadingSummary ? '...' : statusSummary?.total_events ?? 0}
          </p>
          <span className="text-[11px] text-slate-500 font-mono">Normalized catalog</span>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/60 border border-rose-900/30 shadow-lg">
          <div className="flex items-center justify-between text-rose-400 text-xs mb-1">
            <span>High & Critical</span>
            <AlertTriangle className="w-4 h-4" />
          </div>
          <p className="text-2xl font-bold font-mono text-rose-300">
            {isLoadingSummary
              ? '...'
              : (statusSummary?.severity_counts?.HIGH ?? 0) +
                (statusSummary?.severity_counts?.CRITICAL ?? 0)}
          </p>
          <span className="text-[11px] text-slate-500 font-mono">High priority events</span>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/60 border border-amber-900/30 shadow-lg">
          <div className="flex items-center justify-between text-amber-400 text-xs mb-1">
            <span>Auth Failures</span>
            <User className="w-4 h-4" />
          </div>
          <p className="text-2xl font-bold font-mono text-amber-300">
            {isLoadingSummary ? '...' : statusSummary?.category_counts?.authentication_failure ?? 0}
          </p>
          <span className="text-[11px] text-slate-500 font-mono">Credential rejections</span>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/60 border border-sky-900/30 shadow-lg">
          <div className="flex items-center justify-between text-sky-400 text-xs mb-1">
            <span>Access Denied</span>
            <Lock className="w-4 h-4" />
          </div>
          <p className="text-2xl font-bold font-mono text-sky-300">
            {isLoadingSummary ? '...' : statusSummary?.category_counts?.access_denied ?? 0}
          </p>
          <span className="text-[11px] text-slate-500 font-mono">Permission violations</span>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/60 border border-purple-900/30 shadow-lg">
          <div className="flex items-center justify-between text-purple-400 text-xs mb-1">
            <span>Web Probing</span>
            <Globe className="w-4 h-4" />
          </div>
          <p className="text-2xl font-bold font-mono text-purple-300">
            {isLoadingSummary ? '...' : statusSummary?.category_counts?.suspicious_request ?? 0}
          </p>
          <span className="text-[11px] text-slate-500 font-mono">Path reconnaissance</span>
        </div>
      </div>

      {/* Normalized Events Table */}
      <div className="p-6 rounded-xl bg-slate-900/60 border border-slate-800 shadow-xl space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800">
          <div>
            <h2 className="text-lg font-semibold text-white">Ingested Security Events</h2>
            <p className="text-xs text-slate-400">
              Normalized log events with deterministic defensive categorization
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            {/* Search Input */}
            <div className="relative">
              <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                placeholder="Search event summary or IP..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-9 pr-3 py-1.5 text-xs rounded-lg bg-slate-950 border border-slate-700 text-slate-200 placeholder-slate-500 font-mono focus:outline-none focus:ring-1 focus:ring-cyan-500"
              />
            </div>

            {/* Severity Filter */}
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="px-3 py-1.5 text-xs rounded-lg bg-slate-950 border border-slate-700 text-slate-200 font-mono focus:outline-none focus:ring-1 focus:ring-cyan-500"
            >
              <option value="all">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="info">Info</option>
            </select>

            {/* Category Filter */}
            <select
              value={categoryFilter}
              onChange={(e) => setCategoryFilter(e.target.value)}
              className="px-3 py-1.5 text-xs rounded-lg bg-slate-950 border border-slate-700 text-slate-200 font-mono focus:outline-none focus:ring-1 focus:ring-cyan-500"
            >
              <option value="all">All Categories</option>
              <option value="authentication_failure">Auth Failure</option>
              <option value="authentication_success">Auth Success</option>
              <option value="access_denied">Access Denied</option>
              <option value="suspicious_request">Web Probe</option>
              <option value="system_error">System Error</option>
            </select>

            {/* Refresh */}
            <button
              onClick={() => {
                fetchStatusSummary();
                fetchEvents(currentPage);
              }}
              className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition"
              title="Refresh Events"
            >
              <RefreshCw className={`w-4 h-4 ${isLoadingEvents ? 'animate-spin' : ''}`} />
            </button>
          </div>
        </div>

        {/* Table / Empty State */}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/60 text-slate-400 font-mono uppercase tracking-wider border-b border-slate-800">
              <tr>
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">Category</th>
                <th className="py-3 px-4">Timestamp</th>
                <th className="py-3 px-4">Source IP / User</th>
                <th className="py-3 px-4">Summary & Event Details</th>
                <th className="py-3 px-4 text-right">Inspect</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {isLoadingEvents ? (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-slate-500 font-mono">
                    <Loader2 className="w-5 h-5 animate-spin mx-auto mb-2 text-cyan-400" />
                    Loading events...
                  </td>
                </tr>
              ) : events.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-slate-500 font-mono">
                    No log events found matching criteria.
                  </td>
                </tr>
              ) : (
                events.map((ev) => (
                  <tr key={ev.id} className="hover:bg-slate-800/30 transition">
                    <td className="py-3 px-4 whitespace-nowrap">{getSeverityBadge(ev.severity)}</td>
                    <td className="py-3 px-4 whitespace-nowrap">{getCategoryBadge(ev.event_category)}</td>
                    <td className="py-3 px-4 whitespace-nowrap font-mono text-slate-400 text-[11px]">
                      {ev.event_timestamp
                        ? new Date(ev.event_timestamp).toLocaleString()
                        : new Date(ev.created_at).toLocaleString()}
                    </td>
                    <td className="py-3 px-4 whitespace-nowrap font-mono text-slate-300">
                      <div>{ev.source_ip || '—'}</div>
                      {ev.username && (
                        <div className="text-[11px] text-cyan-400">user: {ev.username}</div>
                      )}
                    </td>
                    <td className="py-3 px-4">
                      <div className="font-semibold text-white">{ev.message_summary || ev.raw_message.substring(0, 80)}</div>
                      <div className="text-[11px] font-mono text-slate-500 truncate max-w-xs sm:max-w-md">
                        {ev.source_file || ev.source_type}
                      </div>
                    </td>
                    <td className="py-3 px-4 text-right whitespace-nowrap">
                      <button
                        onClick={() => setSelectedEvent(ev)}
                        className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-400 hover:text-cyan-300 transition"
                        title="View Full Event Details"
                      >
                        <Eye className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Controls */}
        <div className="flex items-center justify-between pt-4 border-t border-slate-800 text-xs font-mono text-slate-400">
          <div>
            Showing {events.length} of {totalEvents} total events
          </div>
          <div className="flex items-center space-x-2">
            <button
              onClick={() => fetchEvents(currentPage - 1)}
              disabled={currentPage <= 1 || isLoadingEvents}
              className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-50 disabled:cursor-not-allowed text-slate-300"
            >
              Previous
            </button>
            <span>
              Page {currentPage} of {totalPages}
            </span>
            <button
              onClick={() => fetchEvents(currentPage + 1)}
              disabled={currentPage >= totalPages || isLoadingEvents}
              className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-50 disabled:cursor-not-allowed text-slate-300"
            >
              Next
            </button>
          </div>
        </div>
      </div>

      {/* Event Details Inspection Modal */}
      {selectedEvent && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-in fade-in">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-2xl w-full p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center space-x-2">
                <ScrollText className="w-5 h-5 text-cyan-400" />
                <h3 className="font-semibold text-white text-base">Normalized Log Event Details</h3>
              </div>
              <button
                onClick={() => setSelectedEvent(null)}
                className="p-1 rounded text-slate-400 hover:text-white hover:bg-slate-800 transition"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div className="grid grid-cols-2 gap-3 p-3 rounded-lg bg-slate-950/60 border border-slate-800 font-mono">
                <div>
                  <span className="text-slate-500 block">Event ID:</span>
                  <span className="text-slate-200">{selectedEvent.id}</span>
                </div>
                <div>
                  <span className="text-slate-500 block">Severity / Category:</span>
                  <span className="text-cyan-400">{selectedEvent.severity} • {selectedEvent.event_category}</span>
                </div>
                <div>
                  <span className="text-slate-500 block">Source IP:</span>
                  <span className="text-slate-200">{selectedEvent.source_ip || 'None'}</span>
                </div>
                <div>
                  <span className="text-slate-500 block">Username:</span>
                  <span className="text-slate-200">{selectedEvent.username || 'None'}</span>
                </div>
                <div>
                  <span className="text-slate-500 block">Source File:</span>
                  <span className="text-slate-200 truncate block">{selectedEvent.source_file || 'None'}</span>
                </div>
                <div>
                  <span className="text-slate-500 block">Timestamp:</span>
                  <span className="text-slate-200">
                    {selectedEvent.event_timestamp
                      ? new Date(selectedEvent.event_timestamp).toISOString()
                      : new Date(selectedEvent.created_at).toISOString()}
                  </span>
                </div>
              </div>

              <div>
                <span className="text-slate-400 font-semibold block mb-1">Message Summary:</span>
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-slate-200 font-sans">
                  {selectedEvent.message_summary || 'No summary available.'}
                </div>
              </div>

              <div>
                <span className="text-slate-400 font-semibold block mb-1">Raw Log Snippet:</span>
                <pre className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-cyan-300 font-mono text-[11px] overflow-x-auto whitespace-pre-wrap">
                  {selectedEvent.raw_message}
                </pre>
              </div>

              {selectedEvent.parsed_event && Object.keys(selectedEvent.parsed_event).length > 0 && (
                <div>
                  <span className="text-slate-400 font-semibold block mb-1">Parsed JSON Metadata:</span>
                  <pre className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-emerald-400 font-mono text-[11px] overflow-x-auto">
                    {JSON.stringify(selectedEvent.parsed_event, null, 2)}
                  </pre>
                </div>
              )}
            </div>

            <div className="pt-3 border-t border-slate-800 flex justify-end">
              <button
                onClick={() => setSelectedEvent(null)}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-white text-xs font-medium transition"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

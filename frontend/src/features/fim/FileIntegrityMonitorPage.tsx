import React, { useState, useEffect, useCallback } from 'react';
import {
  FileCheck2,
  ShieldCheck,
  AlertTriangle,
  CheckCircle2,
  PlusCircle,
  Trash2,
  Loader2,
  RefreshCw,
  Lock,
  ArrowRight,
  FolderTree,
  FileCode,
  Search,
  Copy,
  Check,
} from 'lucide-react';
import {
  FIMBaselineResponse,
  FIMCheckResponse,
  FIMRecord,
  FIMRecordStatus,
  FIMStatusSummary,
} from '../../types';
import {
  createFimBaselineApi,
  checkFimIntegrityApi,
  getFimStatusApi,
  getFimRecordsApi,
  getFimRootsApi,
} from '../../services/api';
import { useAuth } from '../auth/useAuth';

interface FileIntegrityMonitorPageProps {
  onNavigateToFindings?: () => void;
}

export const FileIntegrityMonitorPage: React.FC<FileIntegrityMonitorPageProps> = ({
  onNavigateToFindings,
}) => {
  const { user, token } = useAuth();
  const isOperator = user?.role === 'admin' || user?.role === 'analyst';

  // Input & Allowed Roots State
  const [targetPath, setTargetPath] = useState<string>('./monitored');
  const [allowedRoots, setAllowedRoots] = useState<string[]>([]);
  const [isCreatingBaseline, setIsCreatingBaseline] = useState<boolean>(false);
  const [isCheckingIntegrity, setIsCheckingIntegrity] = useState<boolean>(false);
  const [actionError, setActionError] = useState<string | null>(null);

  // Operation Results State
  const [lastBaselineResult, setLastBaselineResult] = useState<FIMBaselineResponse | null>(null);
  const [lastCheckResult, setLastCheckResult] = useState<FIMCheckResponse | null>(null);

  // Status Summary State
  const [statusSummary, setStatusSummary] = useState<FIMStatusSummary | null>(null);
  const [isLoadingSummary, setIsLoadingSummary] = useState<boolean>(false);

  // Records Table State
  const [records, setRecords] = useState<FIMRecord[]>([]);
  const [totalRecords, setTotalRecords] = useState<number>(0);
  const [currentPage, setCurrentPage] = useState<number>(1);
  const [totalPages, setTotalPages] = useState<number>(1);
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [searchPath, setSearchPath] = useState<string>('');
  const [isLoadingRecords, setIsLoadingRecords] = useState<boolean>(false);

  // Copied hash tooltip state
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  const formatFileSize = (bytes: number): string => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(text);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  // Fetch configured allowed roots
  const fetchRoots = useCallback(async () => {
    if (!token) return;
    try {
      const data = await getFimRootsApi(token);
      setAllowedRoots(data.allowed_roots);
      if (data.allowed_roots.length > 0 && !targetPath) {
        setTargetPath(data.allowed_roots[0]);
      }
    } catch {
      // Non-critical background fetch failure
    }
  }, [token, targetPath]);

  // Fetch aggregated status summary
  const fetchStatusSummary = useCallback(async () => {
    if (!token) return;
    setIsLoadingSummary(true);
    try {
      const data = await getFimStatusApi(token);
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

  // Fetch paginated records list
  const fetchRecords = useCallback(
    async (page = 1) => {
      if (!token) return;
      setIsLoadingRecords(true);
      try {
        const data = await getFimRecordsApi(token, {
          page,
          size: 15,
          status: statusFilter,
          path: searchPath,
        });
        setRecords(data.items);
        setTotalRecords(data.total);
        setCurrentPage(data.page);
        setTotalPages(data.pages);
      } catch {
        // Records fetch error
      } finally {
        setIsLoadingRecords(false);
      }
    },
    [token, statusFilter, searchPath],
  );

  useEffect(() => {
    fetchRoots();
    fetchStatusSummary();
  }, [fetchRoots, fetchStatusSummary]);

  useEffect(() => {
    fetchRecords(1);
  }, [fetchRecords]);

  // Handle Baseline Creation
  const handleCreateBaseline = async () => {
    if (!token || !isOperator || !targetPath.trim()) return;
    setIsCreatingBaseline(true);
    setActionError(null);
    setLastCheckResult(null);

    try {
      const response = await createFimBaselineApi(token, { path: targetPath.trim() });
      setLastBaselineResult(response);
      fetchStatusSummary();
      fetchRecords(1);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Baseline creation failed';
      setActionError(msg);
    } finally {
      setIsCreatingBaseline(false);
    }
  };

  // Handle Integrity Check
  const handleCheckIntegrity = async () => {
    if (!token || !isOperator || !targetPath.trim()) return;
    setIsCheckingIntegrity(true);
    setActionError(null);
    setLastBaselineResult(null);

    try {
      const response = await checkFimIntegrityApi(token, { path: targetPath.trim() });
      setLastCheckResult(response);
      fetchStatusSummary();
      fetchRecords(1);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Integrity check failed';
      setActionError(msg);
    } finally {
      setIsCheckingIntegrity(false);
    }
  };

  const getStatusBadge = (status: FIMRecordStatus | string) => {
    switch (status) {
      case 'unchanged':
        return (
          <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-950/80 text-emerald-400 border border-emerald-800/80">
            <CheckCircle2 className="w-3.5 h-3.5" />
            <span>Unchanged</span>
          </span>
        );
      case 'baseline':
        return (
          <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-cyan-950/80 text-cyan-400 border border-cyan-800/80">
            <ShieldCheck className="w-3.5 h-3.5" />
            <span>Baseline</span>
          </span>
        );
      case 'modified':
        return (
          <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-amber-950/80 text-amber-400 border border-amber-800/80 animate-pulse">
            <AlertTriangle className="w-3.5 h-3.5" />
            <span>Modified</span>
          </span>
        );
      case 'added':
        return (
          <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-sky-950/80 text-sky-400 border border-sky-800/80">
            <PlusCircle className="w-3.5 h-3.5" />
            <span>Added</span>
          </span>
        );
      case 'deleted':
        return (
          <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-rose-950/80 text-rose-400 border border-rose-800/80">
            <Trash2 className="w-3.5 h-3.5" />
            <span>Deleted</span>
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-mono bg-slate-800 text-slate-300">
            {status}
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
                <FileCheck2 className="w-5 h-5" />
              </span>
              <span className="text-xs font-mono uppercase tracking-widest text-cyan-400 font-semibold">
                Defensive Host Security • Phase 6
              </span>
            </div>
            <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight pt-1">
              File Integrity Monitor (FIM)
            </h1>
            <p className="text-sm text-slate-400 max-w-3xl leading-relaxed">
              Cryptographic SHA-256 file baseline monitoring and tampering detection. Audits file
              modifications, additions, and deletions against authorized roots, with automatic
              Findings Engine integration.
            </p>
          </div>

          <div className="flex flex-col items-start md:items-end space-y-2">
            <div className="flex items-center space-x-2 text-xs font-mono px-3 py-1.5 rounded-lg bg-slate-950/60 border border-slate-800 text-slate-300">
              <FolderTree className="w-3.5 h-3.5 text-cyan-400" />
              <span>
                Authorized Roots:{' '}
                {allowedRoots.length > 0 ? allowedRoots.join(', ') : './monitored, ./data'}
              </span>
            </div>
            <div className="flex items-center space-x-1.5 text-xs font-mono text-emerald-400">
              <ShieldCheck className="w-3.5 h-3.5" />
              <span>SHA-256 Streaming Verification Active</span>
            </div>
          </div>
        </div>
      </div>

      {/* Control Panel: Target Path, Allowed Roots Chips, and Action Triggers */}
      <div className="p-6 rounded-xl bg-slate-900/60 border border-slate-800 shadow-xl space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-base font-semibold text-white flex items-center space-x-2">
            <FileCode className="w-4 h-4 text-cyan-400" />
            <span>Target Monitoring Path</span>
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
                placeholder="Enter authorized path, e.g. ./monitored or ./monitored/config.yaml"
                className="w-full px-4 py-2.5 rounded-lg bg-slate-950/80 border border-slate-700/80 text-white placeholder-slate-500 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-cyan-500 focus:border-cyan-500"
              />
            </div>

            <div className="flex items-center space-x-2">
              <button
                type="button"
                onClick={handleCreateBaseline}
                disabled={!isOperator || isCreatingBaseline || isCheckingIntegrity || !targetPath.trim()}
                title={
                  !isOperator
                    ? 'Analyst or Admin permissions required'
                    : 'Establish or update cryptographic baseline for target path'
                }
                className="px-4 py-2.5 rounded-lg font-medium text-sm flex items-center space-x-2 bg-cyan-600 hover:bg-cyan-500 text-white shadow-md shadow-cyan-900/30 transition disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {isCreatingBaseline ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    <span>Baselining...</span>
                  </>
                ) : (
                  <>
                    <ShieldCheck className="w-4 h-4" />
                    <span>Establish Baseline</span>
                  </>
                )}
              </button>

              <button
                type="button"
                onClick={handleCheckIntegrity}
                disabled={!isOperator || isCheckingIntegrity || isCreatingBaseline || !targetPath.trim()}
                title={
                  !isOperator
                    ? 'Analyst or Admin permissions required'
                    : 'Execute integrity comparison against current baseline'
                }
                className="px-4 py-2.5 rounded-lg font-medium text-sm flex items-center space-x-2 bg-emerald-600 hover:bg-emerald-500 text-white shadow-md shadow-emerald-900/30 transition disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {isCheckingIntegrity ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    <span>Checking...</span>
                  </>
                ) : (
                  <>
                    <RefreshCw className="w-4 h-4" />
                    <span>Run Integrity Check</span>
                  </>
                )}
              </button>
            </div>
          </div>

          {/* Quick-select chips */}
          <div className="flex flex-wrap items-center gap-2 pt-1 text-xs text-slate-400">
            <span className="font-mono">Quick select:</span>
            {allowedRoots.map((root) => (
              <button
                key={root}
                type="button"
                onClick={() => setTargetPath(root)}
                className="px-2.5 py-1 rounded bg-slate-800/80 hover:bg-slate-700 hover:text-cyan-400 font-mono text-slate-300 border border-slate-700/60 transition"
              >
                {root}
              </button>
            ))}
          </div>
        </div>

        {/* Action Error Message */}
        {actionError && (
          <div className="p-4 rounded-lg bg-rose-950/60 border border-rose-800/80 text-rose-300 flex items-start space-x-3 text-sm">
            <AlertTriangle className="w-5 h-5 flex-shrink-0 text-rose-400 mt-0.5" />
            <div>
              <p className="font-semibold">Security Action Rejected</p>
              <p className="font-mono text-xs mt-1 text-rose-200">{actionError}</p>
            </div>
          </div>
        )}

        {/* Baseline Success Notification */}
        {lastBaselineResult && (
          <div className="p-4 rounded-lg bg-cyan-950/60 border border-cyan-800/80 text-cyan-200 flex items-start justify-between gap-4 text-sm">
            <div className="flex items-start space-x-3">
              <CheckCircle2 className="w-5 h-5 flex-shrink-0 text-cyan-400 mt-0.5" />
              <div>
                <p className="font-semibold text-white">Cryptographic Baseline Created</p>
                <p className="text-xs text-cyan-300 mt-1">
                  Baselined <span className="font-mono font-bold">{lastBaselineResult.files_baselined_count}</span> files under{' '}
                  <span className="font-mono font-bold">{lastBaselineResult.path}</span> ({formatFileSize(lastBaselineResult.total_size_bytes)} total size).
                </p>
              </div>
            </div>
            <button
              onClick={() => setLastBaselineResult(null)}
              className="text-xs text-cyan-400 hover:text-cyan-200 font-mono underline"
            >
              Dismiss
            </button>
          </div>
        )}

        {/* Integrity Check Result Notification */}
        {lastCheckResult && (
          <div className="p-4 rounded-lg bg-slate-950 border border-slate-700 text-slate-200 space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <ShieldCheck className="w-5 h-5 text-emerald-400" />
                <span className="font-semibold text-white text-sm">
                  Integrity Verification Result for{' '}
                  <span className="font-mono text-cyan-400">{lastCheckResult.path}</span>
                </span>
              </div>
              <span className="text-xs font-mono text-slate-400">
                {new Date(lastCheckResult.checked_at).toLocaleTimeString()}
              </span>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-5 gap-2 text-center text-xs">
              <div className="p-2 rounded bg-slate-900 border border-slate-800">
                <span className="text-slate-400 block">Total Files</span>
                <span className="font-mono font-bold text-sm text-white">{lastCheckResult.total_files}</span>
              </div>
              <div className="p-2 rounded bg-emerald-950/40 border border-emerald-800/50">
                <span className="text-emerald-400 block">Unchanged</span>
                <span className="font-mono font-bold text-sm text-emerald-300">{lastCheckResult.unchanged_count}</span>
              </div>
              <div className="p-2 rounded bg-amber-950/40 border border-amber-800/50">
                <span className="text-amber-400 block">Modified</span>
                <span className="font-mono font-bold text-sm text-amber-300">{lastCheckResult.modified_count}</span>
              </div>
              <div className="p-2 rounded bg-sky-950/40 border border-sky-800/50">
                <span className="text-sky-400 block">Added</span>
                <span className="font-mono font-bold text-sm text-sky-300">{lastCheckResult.added_count}</span>
              </div>
              <div className="p-2 rounded bg-rose-950/40 border border-rose-800/50">
                <span className="text-rose-400 block">Deleted</span>
                <span className="font-mono font-bold text-sm text-rose-300">{lastCheckResult.deleted_count}</span>
              </div>
            </div>

            {lastCheckResult.created_findings_count > 0 && (
              <div className="flex items-center justify-between pt-2 border-t border-slate-800 text-xs">
                <span className="text-amber-300 flex items-center space-x-1.5 font-medium">
                  <AlertTriangle className="w-4 h-4 text-amber-400" />
                  <span>
                    Generated {lastCheckResult.created_findings_count} security finding(s) in Findings Registry.
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
            <span>Monitored Files</span>
            <FileCode className="w-4 h-4 text-cyan-400" />
          </div>
          <p className="text-2xl font-bold font-mono text-white">
            {isLoadingSummary ? '...' : statusSummary?.total_monitored_files ?? 0}
          </p>
          <span className="text-[11px] text-slate-500 font-mono">Baseline catalog</span>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/60 border border-emerald-900/30 shadow-lg">
          <div className="flex items-center justify-between text-emerald-400 text-xs mb-1">
            <span>Unchanged</span>
            <CheckCircle2 className="w-4 h-4" />
          </div>
          <p className="text-2xl font-bold font-mono text-emerald-300">
            {isLoadingSummary ? '...' : (statusSummary?.status_counts?.unchanged ?? 0) + (statusSummary?.status_counts?.baseline ?? 0)}
          </p>
          <span className="text-[11px] text-slate-500 font-mono">Verified authentic</span>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/60 border border-amber-900/30 shadow-lg">
          <div className="flex items-center justify-between text-amber-400 text-xs mb-1">
            <span>Modified</span>
            <AlertTriangle className="w-4 h-4" />
          </div>
          <p className="text-2xl font-bold font-mono text-amber-300">
            {isLoadingSummary ? '...' : statusSummary?.status_counts?.modified ?? 0}
          </p>
          <span className="text-[11px] text-slate-500 font-mono">Cryptographic mismatch</span>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/60 border border-sky-900/30 shadow-lg">
          <div className="flex items-center justify-between text-sky-400 text-xs mb-1">
            <span>Added</span>
            <PlusCircle className="w-4 h-4" />
          </div>
          <p className="text-2xl font-bold font-mono text-sky-300">
            {isLoadingSummary ? '...' : statusSummary?.status_counts?.added ?? 0}
          </p>
          <span className="text-[11px] text-slate-500 font-mono">New unbaselined files</span>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/60 border border-rose-900/30 shadow-lg">
          <div className="flex items-center justify-between text-rose-400 text-xs mb-1">
            <span>Deleted</span>
            <Trash2 className="w-4 h-4" />
          </div>
          <p className="text-2xl font-bold font-mono text-rose-300">
            {isLoadingSummary ? '...' : statusSummary?.status_counts?.deleted ?? 0}
          </p>
          <span className="text-[11px] text-slate-500 font-mono">Missing from disk</span>
        </div>
      </div>

      {/* Monitored Records Table */}
      <div className="p-6 rounded-xl bg-slate-900/60 border border-slate-800 shadow-xl space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800">
          <div>
            <h2 className="text-lg font-semibold text-white">Monitored File Records</h2>
            <p className="text-xs text-slate-400">
              Active integrity catalog with cryptographic hash comparison
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            {/* Search Input */}
            <div className="relative">
              <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                placeholder="Search file path..."
                value={searchPath}
                onChange={(e) => setSearchPath(e.target.value)}
                className="pl-9 pr-3 py-1.5 text-xs rounded-lg bg-slate-950 border border-slate-700 text-slate-200 placeholder-slate-500 font-mono focus:outline-none focus:ring-1 focus:ring-cyan-500"
              />
            </div>

            {/* Status Filter */}
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="px-3 py-1.5 text-xs rounded-lg bg-slate-950 border border-slate-700 text-slate-200 font-mono focus:outline-none focus:ring-1 focus:ring-cyan-500"
            >
              <option value="all">All States</option>
              <option value="baseline">Baseline</option>
              <option value="unchanged">Unchanged</option>
              <option value="modified">Modified</option>
              <option value="added">Added</option>
              <option value="deleted">Deleted</option>
            </select>

            {/* Refresh */}
            <button
              onClick={() => {
                fetchStatusSummary();
                fetchRecords(currentPage);
              }}
              className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition"
              title="Refresh Records"
            >
              <RefreshCw className={`w-4 h-4 ${isLoadingRecords ? 'animate-spin' : ''}`} />
            </button>
          </div>
        </div>

        {/* Table / Empty State */}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/60 text-slate-400 font-mono uppercase tracking-wider border-b border-slate-800">
              <tr>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4">File Name & Path</th>
                <th className="py-3 px-4">Size</th>
                <th className="py-3 px-4">Baseline SHA-256</th>
                <th className="py-3 px-4">Current SHA-256</th>
                <th className="py-3 px-4">Last Verified</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {isLoadingRecords ? (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-slate-500 font-mono">
                    <Loader2 className="w-5 h-5 animate-spin mx-auto mb-2 text-cyan-400" />
                    Loading monitored files...
                  </td>
                </tr>
              ) : records.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-slate-500 font-mono">
                    No monitored files found matching criteria.
                  </td>
                </tr>
              ) : (
                records.map((rec) => (
                  <tr key={rec.id} className="hover:bg-slate-800/30 transition">
                    <td className="py-3 px-4 whitespace-nowrap">{getStatusBadge(rec.status)}</td>
                    <td className="py-3 px-4">
                      <div className="font-semibold text-white">{rec.file_name}</div>
                      <div className="text-[11px] font-mono text-slate-400 truncate max-w-xs sm:max-w-md" title={rec.monitored_path}>
                        {rec.monitored_path}
                      </div>
                    </td>
                    <td className="py-3 px-4 whitespace-nowrap font-mono text-slate-400">
                      {formatFileSize(rec.file_size_bytes)}
                    </td>
                    <td className="py-3 px-4 whitespace-nowrap font-mono">
                      <div className="flex items-center space-x-1.5">
                        <span title={rec.baseline_hash} className="text-slate-300">
                          {rec.baseline_hash ? `${rec.baseline_hash.substring(0, 12)}...` : 'N/A'}
                        </span>
                        {rec.baseline_hash && (
                          <button
                            onClick={() => copyToClipboard(rec.baseline_hash)}
                            className="text-slate-500 hover:text-cyan-400"
                            title="Copy full SHA-256"
                          >
                            {copiedHash === rec.baseline_hash ? (
                              <Check className="w-3.5 h-3.5 text-emerald-400" />
                            ) : (
                              <Copy className="w-3.5 h-3.5" />
                            )}
                          </button>
                        )}
                      </div>
                    </td>
                    <td className="py-3 px-4 whitespace-nowrap font-mono">
                      {rec.current_hash ? (
                        <div className="flex items-center space-x-1.5">
                          <span
                            title={rec.current_hash}
                            className={
                              rec.status === 'modified'
                                ? 'text-amber-400 font-bold'
                                : 'text-slate-300'
                            }
                          >
                            {`${rec.current_hash.substring(0, 12)}...`}
                          </span>
                          <button
                            onClick={() => copyToClipboard(rec.current_hash || '')}
                            className="text-slate-500 hover:text-cyan-400"
                            title="Copy current SHA-256"
                          >
                            {copiedHash === rec.current_hash ? (
                              <Check className="w-3.5 h-3.5 text-emerald-400" />
                            ) : (
                              <Copy className="w-3.5 h-3.5" />
                            )}
                          </button>
                        </div>
                      ) : (
                        <span className="text-slate-500 italic">Deleted / Absent</span>
                      )}
                    </td>
                    <td className="py-3 px-4 whitespace-nowrap font-mono text-slate-400 text-[11px]">
                      {rec.last_verified_at
                        ? new Date(rec.last_verified_at).toLocaleString()
                        : new Date(rec.created_at).toLocaleString()}
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
            Showing {records.length} of {totalRecords} total records
          </div>
          <div className="flex items-center space-x-2">
            <button
              onClick={() => fetchRecords(currentPage - 1)}
              disabled={currentPage <= 1 || isLoadingRecords}
              className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-50 disabled:cursor-not-allowed text-slate-300"
            >
              Previous
            </button>
            <span>
              Page {currentPage} of {totalPages}
            </span>
            <button
              onClick={() => fetchRecords(currentPage + 1)}
              disabled={currentPage >= totalPages || isLoadingRecords}
              className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-50 disabled:cursor-not-allowed text-slate-300"
            >
              Next
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

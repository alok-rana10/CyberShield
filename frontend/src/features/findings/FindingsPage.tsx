import React, { useState, useEffect, useCallback } from 'react';
import {
  Search,
  Filter,
  X,
  Plus,
  Trash2,
  RefreshCw,
  Loader2,
  FileText,
  ChevronLeft,
  ChevronRight,
  ShieldCheck,
  AlertCircle,
} from 'lucide-react';
import {
  SecurityFinding,
  FindingSeverity,
  FindingStatus,
  FindingCreatePayload,
} from '../../types';
import {
  getFindingsApi,
  createFindingApi,
  updateFindingStatusApi,
  deleteFindingApi,
} from '../../services/api';
import { useAuth } from '../auth/useAuth';

interface FindingsPageProps {
  initialFindingId?: string;
}

export const FindingsPage: React.FC<FindingsPageProps> = ({ initialFindingId }) => {
  const { user, token } = useAuth();
  const isOperator = user?.role === 'admin' || user?.role === 'analyst';
  const isAdmin = user?.role === 'admin';

  // Filters and pagination state
  const [findings, setFindings] = useState<SecurityFinding[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [page, setPage] = useState<number>(1);
  const [pageSize] = useState<number>(15);
  const [pages, setPages] = useState<number>(1);
  const [search, setSearch] = useState<string>('');
  const [severityFilter, setSeverityFilter] = useState<string>('');
  const [statusFilter, setStatusFilter] = useState<string>('');
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Selected finding for details modal
  const [selectedFinding, setSelectedFinding] = useState<SecurityFinding | null>(null);

  // Status transition state
  const [isUpdatingStatus, setIsUpdatingStatus] = useState<boolean>(false);
  const [statusNotes, setStatusNotes] = useState<string>('');
  const [statusActionError, setStatusActionError] = useState<string | null>(null);

  // Create finding modal state
  const [isCreateOpen, setIsCreateOpen] = useState<boolean>(false);
  const [isSubmittingCreate, setIsSubmittingCreate] = useState<boolean>(false);
  const [createError, setCreateError] = useState<string | null>(null);
  const [createForm, setCreateForm] = useState<FindingCreatePayload>({
    title: '',
    description: '',
    severity: 'medium',
    category: 'web_security',
    source_module: 'manual',
    affected_resource: '',
    remediation: '',
    evidence: '',
    cwe_id: '',
    status: 'open',
  });

  const fetchFindings = useCallback(async () => {
    if (!token) return;
    setIsLoading(true);
    setError(null);
    try {
      const response = await getFindingsApi(token, {
        page,
        size: pageSize,
        search: search.trim() || undefined,
        severity: severityFilter || undefined,
        status: statusFilter || undefined,
      });
      setFindings(response.items);
      setTotal(response.total);
      setPages(response.pages);

      // If initialFindingId was passed, open it
      if (initialFindingId && !selectedFinding) {
        const match = response.items.find((f) => f.id === initialFindingId);
        if (match) setSelectedFinding(match);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load security findings.');
    } finally {
      setIsLoading(false);
    }
  }, [token, page, pageSize, search, severityFilter, statusFilter, initialFindingId, selectedFinding]);

  useEffect(() => {
    fetchFindings();
  }, [fetchFindings]);

  const handleStatusChange = async (newStatus: FindingStatus) => {
    if (!token || !selectedFinding || !isOperator) return;
    setIsUpdatingStatus(true);
    setStatusActionError(null);
    try {
      const updated = await updateFindingStatusApi(token, selectedFinding.id, {
        status: newStatus,
        resolution_notes: statusNotes.trim() || undefined,
      });
      setSelectedFinding(updated);
      setStatusNotes('');
      // Update item in local list
      setFindings((prev) => prev.map((f) => (f.id === updated.id ? updated : f)));
    } catch (err) {
      setStatusActionError(err instanceof Error ? err.message : 'Failed to update finding status');
    } finally {
      setIsUpdatingStatus(false);
    }
  };

  const handleDelete = async (findingId: string) => {
    if (!token || !isAdmin) return;
    if (!window.confirm('Are you sure you want to permanently delete this finding? This action is audited.')) {
      return;
    }
    try {
      await deleteFindingApi(token, findingId);
      setSelectedFinding(null);
      fetchFindings();
    } catch (err) {
      alert(err instanceof Error ? err.message : 'Failed to delete finding');
    }
  };

  const handleCreateSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!token || !isOperator) return;
    setIsSubmittingCreate(true);
    setCreateError(null);
    try {
      await createFindingApi(token, createForm);
      setIsCreateOpen(false);
      setCreateForm({
        title: '',
        description: '',
        severity: 'medium',
        category: 'web_security',
        source_module: 'manual',
        affected_resource: '',
        remediation: '',
        evidence: '',
        cwe_id: '',
        status: 'open',
      });
      fetchFindings();
    } catch (err) {
      setCreateError(err instanceof Error ? err.message : 'Failed to create finding.');
    } finally {
      setIsSubmittingCreate(false);
    }
  };

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

  return (
    <div className="space-y-6">
      {/* Top Banner and Actions */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-6 shadow-xl backdrop-blur">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-800/80">
          <div>
            <div className="flex items-center space-x-2">
              <span className="h-2 w-2 rounded-full bg-cyan-400"></span>
              <span className="text-xs font-mono uppercase tracking-widest text-cyan-400">
                Defensive Telemetry & Vulnerability Registry
              </span>
            </div>
            <h1 className="text-xl sm:text-2xl font-bold text-white tracking-tight mt-1">
              Security Findings Registry
            </h1>
            <p className="text-xs text-slate-400 mt-1">
              Standardized vulnerabilities, misconfigurations, and integrity alerts classified by CWE and severity
            </p>
          </div>

          <div className="flex items-center space-x-3">
            {isOperator && (
              <button
                onClick={() => setIsCreateOpen(true)}
                className="inline-flex items-center space-x-1.5 px-3.5 py-2 text-xs font-semibold rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white shadow-sm shadow-cyan-600/30 transition"
              >
                <Plus className="w-3.5 h-3.5" />
                <span>Record Finding</span>
              </button>
            )}

            <button
              onClick={fetchFindings}
              disabled={isLoading}
              className="inline-flex items-center space-x-1.5 px-3 py-2 text-xs font-medium rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700/60 transition disabled:opacity-50"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin text-cyan-400' : ''}`} />
              <span>{isLoading ? 'Loading...' : 'Refresh'}</span>
            </button>
          </div>
        </div>

        {/* Filter Controls Bar */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 mt-4">
          {/* Search Box */}
          <div className="relative">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5 pointer-events-none" />
            <input
              type="text"
              placeholder="Search by title, asset, or CWE..."
              value={search}
              onChange={(e) => {
                setSearch(e.target.value);
                setPage(1);
              }}
              className="w-full pl-9 pr-3 py-2 bg-slate-950/80 border border-slate-800 rounded-lg text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500"
            />
          </div>

          {/* Severity Filter */}
          <div className="flex items-center space-x-2">
            <Filter className="w-3.5 h-3.5 text-slate-400 shrink-0" />
            <select
              value={severityFilter}
              onChange={(e) => {
                setSeverityFilter(e.target.value);
                setPage(1);
              }}
              className="w-full py-2 px-3 bg-slate-950/80 border border-slate-800 rounded-lg text-xs text-slate-300 focus:outline-none focus:border-cyan-500 font-mono"
            >
              <option value="">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="informational">Informational</option>
            </select>
          </div>

          {/* Status Filter */}
          <div className="flex items-center space-x-2">
            <select
              value={statusFilter}
              onChange={(e) => {
                setStatusFilter(e.target.value);
                setPage(1);
              }}
              className="w-full py-2 px-3 bg-slate-950/80 border border-slate-800 rounded-lg text-xs text-slate-300 focus:outline-none focus:border-cyan-500 font-mono"
            >
              <option value="">All Statuses</option>
              <option value="open">Open</option>
              <option value="resolved">Resolved</option>
              <option value="accepted">Accepted Risk</option>
            </select>
          </div>

          {/* Quick Clear / Counter */}
          <div className="flex items-center justify-between px-3 py-2 bg-slate-950/40 rounded-lg border border-slate-800/80 text-xs font-mono text-slate-400">
            <span>Results: {total}</span>
            {(search || severityFilter || statusFilter) && (
              <button
                onClick={() => {
                  setSearch('');
                  setSeverityFilter('');
                  setStatusFilter('');
                  setPage(1);
                }}
                className="text-cyan-400 hover:text-cyan-300 text-[11px] underline"
              >
                Reset Filters
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Error Banner */}
      {error && (
        <div className="p-4 rounded-xl bg-rose-950/40 border border-rose-800/80 text-rose-300 text-xs flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <AlertCircle className="w-4 h-4 text-rose-400" />
            <span>{error}</span>
          </div>
          <button onClick={fetchFindings} className="underline hover:text-white">Retry</button>
        </div>
      )}

      {/* Findings Table Card */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl shadow-xl backdrop-blur overflow-hidden">
        {isLoading ? (
          <div className="py-16 text-center space-y-3">
            <Loader2 className="w-8 h-8 text-cyan-400 animate-spin mx-auto" />
            <p className="text-xs font-mono text-slate-400">Loading security findings from database...</p>
          </div>
        ) : findings.length === 0 ? (
          <div className="py-16 text-center space-y-3">
            <ShieldCheck className="w-10 h-10 text-emerald-400 mx-auto" />
            <h3 className="text-base font-semibold text-white">No Security Findings Found</h3>
            <p className="text-xs text-slate-400 max-w-sm mx-auto">
              {search || severityFilter || statusFilter
                ? 'No findings match the configured filter criteria.'
                : 'No security findings have been recorded in the platform database yet.'}
            </p>
            {isOperator && (
              <button
                onClick={() => setIsCreateOpen(true)}
                className="mt-2 inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-xs font-medium text-white transition"
              >
                <Plus className="w-3.5 h-3.5" />
                <span>Create New Finding</span>
              </button>
            )}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950/80 text-slate-400 font-mono border-b border-slate-800">
                <tr>
                  <th className="py-3 px-4">Severity</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">Title & Classification</th>
                  <th className="py-3 px-4">Category</th>
                  <th className="py-3 px-4">Affected Resource</th>
                  <th className="py-3 px-4">Module</th>
                  <th className="py-3 px-4">Created Date</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {findings.map((item) => (
                  <tr
                    key={item.id}
                    onClick={() => setSelectedFinding(item)}
                    className="hover:bg-slate-800/50 cursor-pointer transition"
                  >
                    <td className="py-3 px-4">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono uppercase font-bold border ${getSeverityBadgeClass(item.severity)}`}>
                        {item.severity}
                      </span>
                    </td>
                    <td className="py-3 px-4">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono uppercase border ${getStatusBadgeClass(item.status)}`}>
                        {item.status}
                      </span>
                    </td>
                    <td className="py-3 px-4">
                      <div className="font-semibold text-slate-200 max-w-md truncate" title={item.title}>
                        {item.title}
                      </div>
                      {item.cwe_id && (
                        <span className="text-[10px] font-mono text-cyan-400/80">{item.cwe_id}</span>
                      )}
                    </td>
                    <td className="py-3 px-4 font-mono text-slate-400 text-[11px]">
                      {item.category}
                    </td>
                    <td className="py-3 px-4 font-mono text-slate-300 text-[11px] max-w-xs truncate" title={item.affected_resource || ''}>
                      {item.affected_resource || '—'}
                    </td>
                    <td className="py-3 px-4 font-mono text-slate-400 text-[11px]">
                      {item.source_module}
                    </td>
                    <td className="py-3 px-4 font-mono text-slate-400 text-[11px]">
                      {new Date(item.created_at).toLocaleDateString()}
                    </td>
                    <td className="py-3 px-4 text-right" onClick={(e) => e.stopPropagation()}>
                      <button
                        onClick={() => setSelectedFinding(item)}
                        className="text-xs text-cyan-400 hover:text-cyan-300 font-medium px-2 py-1 rounded hover:bg-slate-800 transition"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination Controls */}
        {pages > 1 && (
          <div className="p-4 border-t border-slate-800 flex items-center justify-between text-xs font-mono text-slate-400">
            <span>
              Page {page} of {pages} ({total} total findings)
            </span>
            <div className="flex items-center space-x-2">
              <button
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page <= 1}
                className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 disabled:opacity-40 disabled:hover:bg-slate-800 text-slate-200 transition"
              >
                <ChevronLeft className="w-4 h-4" />
              </button>
              <button
                onClick={() => setPage((p) => Math.min(pages, p + 1))}
                disabled={page >= pages}
                className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 disabled:opacity-40 disabled:hover:bg-slate-800 text-slate-200 transition"
              >
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Finding Details Modal */}
      {selectedFinding && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-in fade-in">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-3xl w-full max-h-[90vh] overflow-y-auto shadow-2xl flex flex-col">
            {/* Modal Header */}
            <div className="p-5 border-b border-slate-800 flex items-start justify-between sticky top-0 bg-slate-900/95 backdrop-blur z-10">
              <div className="space-y-1">
                <div className="flex items-center space-x-2">
                  <span className={`px-2 py-0.5 rounded text-[10px] font-mono uppercase font-bold border ${getSeverityBadgeClass(selectedFinding.severity)}`}>
                    {selectedFinding.severity}
                  </span>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-mono uppercase border ${getStatusBadgeClass(selectedFinding.status)}`}>
                    {selectedFinding.status}
                  </span>
                  {selectedFinding.cwe_id && (
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-cyan-400 border border-slate-700">
                      {selectedFinding.cwe_id}
                    </span>
                  )}
                </div>
                <h2 className="text-lg font-bold text-white pt-1">{selectedFinding.title}</h2>
              </div>
              <button
                onClick={() => {
                  setSelectedFinding(null);
                  setStatusActionError(null);
                }}
                className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Modal Content */}
            <div className="p-6 space-y-6 flex-1 text-xs">
              {/* Status Action Error */}
              {statusActionError && (
                <div className="p-3 rounded-lg bg-rose-950/40 border border-rose-800/80 text-rose-300">
                  {statusActionError}
                </div>
              )}

              {/* Core Metadata Grid */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <div className="p-3 rounded-lg bg-slate-950/70 border border-slate-800">
                  <span className="text-[10px] font-mono text-slate-400 block mb-0.5">Category</span>
                  <span className="font-semibold text-slate-200">{selectedFinding.category}</span>
                </div>
                <div className="p-3 rounded-lg bg-slate-950/70 border border-slate-800">
                  <span className="text-[10px] font-mono text-slate-400 block mb-0.5">Source Module</span>
                  <span className="font-semibold text-slate-200">{selectedFinding.source_module}</span>
                </div>
                <div className="p-3 rounded-lg bg-slate-950/70 border border-slate-800">
                  <span className="text-[10px] font-mono text-slate-400 block mb-0.5">Created Date</span>
                  <span className="font-mono text-slate-200">
                    {new Date(selectedFinding.created_at).toLocaleDateString()}
                  </span>
                </div>
                <div className="p-3 rounded-lg bg-slate-950/70 border border-slate-800">
                  <span className="text-[10px] font-mono text-slate-400 block mb-0.5">Resolved Date</span>
                  <span className="font-mono text-slate-200">
                    {selectedFinding.resolved_at
                      ? new Date(selectedFinding.resolved_at).toLocaleDateString()
                      : 'Not resolved'}
                  </span>
                </div>
              </div>

              {/* Affected Asset */}
              {selectedFinding.affected_resource && (
                <div>
                  <h4 className="font-mono text-slate-400 mb-1.5">Affected Asset / Target Resource</h4>
                  <div className="p-2.5 rounded-lg bg-slate-950/80 border border-slate-800 font-mono text-cyan-300 text-xs">
                    {selectedFinding.affected_resource}
                  </div>
                </div>
              )}

              {/* Vulnerability Description */}
              <div>
                <h4 className="font-mono text-slate-400 mb-1.5">Technical Description</h4>
                <div className="p-3.5 rounded-lg bg-slate-950/60 border border-slate-800 text-slate-300 leading-relaxed whitespace-pre-wrap">
                  {selectedFinding.description}
                </div>
              </div>

              {/* Actionable Remediation Guidance */}
              <div>
                <h4 className="font-mono text-cyan-400 mb-1.5 flex items-center space-x-1.5">
                  <ShieldCheck className="w-4 h-4 text-cyan-400" />
                  <span>Actionable Defensive Remediation</span>
                </h4>
                <div className="p-3.5 rounded-lg bg-cyan-950/20 border border-cyan-800/40 text-cyan-200 leading-relaxed whitespace-pre-wrap">
                  {selectedFinding.remediation}
                </div>
              </div>

              {/* Evidence Container */}
              {selectedFinding.evidence && (
                <div>
                  <h4 className="font-mono text-slate-400 mb-1.5 flex items-center space-x-1.5">
                    <FileText className="w-3.5 h-3.5 text-slate-400" />
                    <span>Diagnostic Evidence / Header Snippet</span>
                  </h4>
                  <pre className="p-3 rounded-lg bg-slate-950 border border-slate-800 font-mono text-[11px] text-slate-300 overflow-x-auto whitespace-pre-wrap">
                    {selectedFinding.evidence}
                  </pre>
                </div>
              )}

              {/* Lifecycle Status Management (RBAC Gated) */}
              <div className="pt-4 border-t border-slate-800 space-y-3">
                <div className="flex items-center justify-between">
                  <h4 className="font-mono text-slate-400">Lifecycle State Transition</h4>
                  {!isOperator && (
                    <span className="text-[11px] font-mono text-slate-500">
                      Viewer role: Read-only access
                    </span>
                  )}
                </div>

                {isOperator ? (
                  <div className="space-y-3 p-3.5 rounded-lg bg-slate-950/60 border border-slate-800">
                    <div className="flex flex-wrap gap-2">
                      <button
                        onClick={() => handleStatusChange('open')}
                        disabled={selectedFinding.status === 'open' || isUpdatingStatus}
                        className="px-3 py-1.5 rounded-lg border border-amber-800/60 bg-amber-950/40 hover:bg-amber-900/60 text-amber-300 transition disabled:opacity-30 disabled:pointer-events-none"
                      >
                        Re-open Finding
                      </button>
                      <button
                        onClick={() => handleStatusChange('resolved')}
                        disabled={selectedFinding.status === 'resolved' || isUpdatingStatus}
                        className="px-3 py-1.5 rounded-lg border border-emerald-800/60 bg-emerald-950/40 hover:bg-emerald-900/60 text-emerald-300 transition disabled:opacity-30 disabled:pointer-events-none"
                      >
                        Mark as Resolved
                      </button>
                      <button
                        onClick={() => handleStatusChange('accepted')}
                        disabled={selectedFinding.status === 'accepted' || isUpdatingStatus}
                        className="px-3 py-1.5 rounded-lg border border-indigo-800/60 bg-indigo-950/40 hover:bg-indigo-900/60 text-indigo-300 transition disabled:opacity-30 disabled:pointer-events-none"
                      >
                        Accept Risk
                      </button>
                    </div>

                    <input
                      type="text"
                      placeholder="Optional audit resolution notes (e.g., patched in revision v1.2)..."
                      value={statusNotes}
                      onChange={(e) => setStatusNotes(e.target.value)}
                      className="w-full px-3 py-1.5 bg-slate-900 border border-slate-800 rounded-lg text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500"
                    />
                  </div>
                ) : null}
              </div>
            </div>

            {/* Modal Footer */}
            <div className="p-4 border-t border-slate-800 bg-slate-950/60 flex items-center justify-between text-xs font-mono text-slate-400">
              <span>ID: {selectedFinding.id}</span>
              <div className="flex items-center space-x-2">
                {isAdmin && (
                  <button
                    onClick={() => handleDelete(selectedFinding.id)}
                    className="inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-rose-950/60 hover:bg-rose-900/80 text-rose-300 border border-rose-800/80 transition"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                    <span>Delete Finding (Admin)</span>
                  </button>
                )}
                <button
                  onClick={() => setSelectedFinding(null)}
                  className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 transition"
                >
                  Close
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Record New Finding Modal */}
      {isCreateOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-in fade-in">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-2xl w-full max-h-[90vh] overflow-y-auto shadow-2xl flex flex-col">
            <div className="p-5 border-b border-slate-800 flex items-center justify-between sticky top-0 bg-slate-900 z-10">
              <div>
                <h3 className="text-base font-bold text-white">Record Security Finding</h3>
                <p className="text-xs text-slate-400">Defensive gap or misconfiguration entry</p>
              </div>
              <button
                onClick={() => setIsCreateOpen(false)}
                className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={handleCreateSubmit} className="p-6 space-y-4 flex-1 text-xs">
              {createError && (
                <div className="p-3 rounded-lg bg-rose-950/40 border border-rose-800/80 text-rose-300">
                  {createError}
                </div>
              )}

              <div>
                <label className="block text-slate-300 font-medium mb-1">Title *</label>
                <input
                  type="text"
                  required
                  placeholder="e.g., Insecure Cookie Missing SameSite Attribute"
                  value={createForm.title}
                  onChange={(e) => setCreateForm({ ...createForm, title: e.target.value })}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-white focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-300 font-medium mb-1">Severity *</label>
                  <select
                    value={createForm.severity}
                    onChange={(e) => setCreateForm({ ...createForm, severity: e.target.value as FindingSeverity })}
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-white focus:outline-none focus:border-cyan-500 font-mono"
                  >
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                    <option value="informational">Informational</option>
                  </select>
                </div>

                <div>
                  <label className="block text-slate-300 font-medium mb-1">Category</label>
                  <select
                    value={createForm.category}
                    onChange={(e) => setCreateForm({ ...createForm, category: e.target.value })}
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-white focus:outline-none focus:border-cyan-500 font-mono"
                  >
                    <option value="web_security">Web Security</option>
                    <option value="network">Network Security</option>
                    <option value="iam">Identity & Access</option>
                    <option value="integrity">File Integrity</option>
                    <option value="logging">Logging & Auditing</option>
                    <option value="configuration">Configuration</option>
                    <option value="general">General</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-300 font-medium mb-1">Affected Resource</label>
                  <input
                    type="text"
                    placeholder="e.g., https://app.example.com or 10.0.0.1:443"
                    value={createForm.affected_resource}
                    onChange={(e) => setCreateForm({ ...createForm, affected_resource: e.target.value })}
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-white focus:outline-none focus:border-cyan-500 font-mono"
                  />
                </div>

                <div>
                  <label className="block text-slate-300 font-medium mb-1">CWE Identifier</label>
                  <input
                    type="text"
                    placeholder="e.g., CWE-1021 or CWE-693"
                    value={createForm.cwe_id}
                    onChange={(e) => setCreateForm({ ...createForm, cwe_id: e.target.value })}
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-white focus:outline-none focus:border-cyan-500 font-mono"
                  />
                </div>
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">Technical Description *</label>
                <textarea
                  required
                  rows={3}
                  placeholder="Detailed explanation of the vulnerability or hardening defect..."
                  value={createForm.description}
                  onChange={(e) => setCreateForm({ ...createForm, description: e.target.value })}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-white focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">Remediation Guidance *</label>
                <textarea
                  required
                  rows={2}
                  placeholder="Explicit defensive actions required to mitigate this gap..."
                  value={createForm.remediation}
                  onChange={(e) => setCreateForm({ ...createForm, remediation: e.target.value })}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-white focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">Evidence / Log Snippet (Optional)</label>
                <textarea
                  rows={2}
                  placeholder="Paste headers or diagnostic socket responses here..."
                  value={createForm.evidence}
                  onChange={(e) => setCreateForm({ ...createForm, evidence: e.target.value })}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-white font-mono text-[11px] focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="pt-4 border-t border-slate-800 flex items-center justify-end space-x-2">
                <button
                  type="button"
                  onClick={() => setIsCreateOpen(false)}
                  className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSubmittingCreate}
                  className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-medium transition disabled:opacity-50 flex items-center space-x-1.5"
                >
                  {isSubmittingCreate ? <Loader2 className="w-4 h-4 animate-spin" /> : null}
                  <span>Save Finding</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

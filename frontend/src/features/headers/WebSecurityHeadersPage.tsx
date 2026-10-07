import React, { useState, useEffect, useCallback } from 'react';
import {
  Globe,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Loader2,
  RefreshCw,
  History,
  Lock,
  ArrowRight,
  Info,
} from 'lucide-react';
import { HeaderAnalysisRequest, HeaderAnalysisResponse, WebSecurityHistoryItem } from '../../types';
import { analyzeHeadersApi, getHeaderHistoryApi } from '../../services/api';
import { useAuth } from '../auth/useAuth';

interface WebSecurityHeadersPageProps {
  onNavigateToFindings?: () => void;
}

export const WebSecurityHeadersPage: React.FC<WebSecurityHeadersPageProps> = ({
  onNavigateToFindings,
}) => {
  const { user, token } = useAuth();
  const isOperator = user?.role === 'admin' || user?.role === 'analyst';

  // Analysis Form State
  const [targetUrl, setTargetUrl] = useState<string>('');
  const [authConfirmed, setAuthConfirmed] = useState<boolean>(false);
  const [isAnalyzing, setIsAnalyzing] = useState<boolean>(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Results State
  const [currentResult, setCurrentResult] = useState<HeaderAnalysisResponse | null>(null);

  // History State
  const [history, setHistory] = useState<WebSecurityHistoryItem[]>([]);
  const [isLoadingHistory, setIsLoadingHistory] = useState<boolean>(false);

  // Fetch assessment history
  const fetchHistory = useCallback(async () => {
    if (!token) return;
    setIsLoadingHistory(true);
    try {
      const data = await getHeaderHistoryApi(token);
      setHistory(data);
    } catch {
      // Non-critical background history fetch failure
    } finally {
      setIsLoadingHistory(false);
    }
  }, [token]);

  useEffect(() => {
    fetchHistory();
  }, [fetchHistory]);

  // Handle Form Submission
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!token || !isOperator || !authConfirmed || !targetUrl.trim()) return;

    setIsAnalyzing(true);
    setErrorMessage(null);

    try {
      const payload: HeaderAnalysisRequest = {
        url: targetUrl.trim(),
        authorization_confirmed: authConfirmed,
      };
      const response = await analyzeHeadersApi(token, payload);
      setCurrentResult(response);
      fetchHistory();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Analysis request failed';
      setErrorMessage(msg);
    } finally {
      setIsAnalyzing(false);
    }
  };

  const getGradeBadge = (grade: string) => {
    switch (grade) {
      case 'A+':
      case 'A':
        return {
          bg: 'bg-emerald-950/80 text-emerald-400 border-emerald-500/50 shadow-[0_0_12px_rgba(52,211,153,0.3)]',
          text: 'Security Grade ' + grade,
        };
      case 'B':
        return {
          bg: 'bg-cyan-950/80 text-cyan-400 border-cyan-500/50 shadow-[0_0_12px_rgba(6,182,212,0.3)]',
          text: 'Security Grade B',
        };
      case 'C':
        return {
          bg: 'bg-amber-950/80 text-amber-400 border-amber-500/50 shadow-[0_0_12px_rgba(245,158,11,0.3)]',
          text: 'Security Grade C',
        };
      case 'D':
      case 'F':
      default:
        return {
          bg: 'bg-rose-950/80 text-rose-400 border-rose-500/50 shadow-[0_0_12px_rgba(244,63,94,0.3)]',
          text: 'Security Grade ' + grade,
        };
    }
  };

  const getStatusBadge = (status: 'present' | 'missing' | 'weak') => {
    switch (status) {
      case 'present':
        return (
          <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-950/80 text-emerald-400 border border-emerald-800/80">
            <CheckCircle2 className="w-3.5 h-3.5" />
            <span>Present</span>
          </span>
        );
      case 'weak':
        return (
          <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-amber-950/80 text-amber-400 border border-amber-800/80">
            <AlertTriangle className="w-3.5 h-3.5" />
            <span>Weak Configuration</span>
          </span>
        );
      case 'missing':
        return (
          <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-rose-950/80 text-rose-400 border border-rose-800/80">
            <XCircle className="w-3.5 h-3.5" />
            <span>Missing Header</span>
          </span>
        );
    }
  };

  return (
    <div className="space-y-8 animate-fadeIn">
      {/* Header and Context Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-6">
        <div>
          <div className="flex items-center space-x-2">
            <div className="p-2 rounded-lg bg-cyan-950 border border-cyan-800/80 text-cyan-400">
              <Globe className="w-5 h-5" />
            </div>
            <h1 className="text-2xl font-bold text-white tracking-tight">
              Web Security Header Analyzer
            </h1>
            <span className="text-xs font-mono uppercase px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
              Phase 5
            </span>
          </div>
          <p className="text-sm text-slate-400 mt-1 max-w-3xl">
            Defensive HTTP security header posture assessment for authorized web endpoints.
            Evaluates Content-Security-Policy, HSTS, X-Content-Type-Options, X-Frame-Options,
            Referrer-Policy, and Permissions-Policy with hardened SSRF protection and findings
            engine integration.
          </p>
        </div>

        {onNavigateToFindings && (
          <button
            onClick={onNavigateToFindings}
            className="self-start md:self-auto inline-flex items-center space-x-2 px-3 py-2 rounded-lg border border-slate-800 bg-slate-900/80 hover:bg-slate-800 text-xs font-medium text-slate-300 hover:text-white transition"
          >
            <ShieldAlert className="w-4 h-4 text-cyan-400" />
            <span>Go to Findings Registry</span>
          </button>
        )}
      </div>

      {/* Analyzer Input Card */}
      <div className="p-6 rounded-xl bg-slate-900/60 border border-slate-800 shadow-xl space-y-5">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <Lock className="w-4 h-4 text-cyan-400" />
            <h2 className="text-base font-semibold text-white">Target Endpoint Configuration</h2>
          </div>
          <span className="text-xs text-slate-500 font-mono">Non-Intrusive HTTP GET Only</span>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label htmlFor="target-url" className="block text-xs font-medium text-slate-300 mb-1.5">
              Target URL
            </label>
            <div className="relative">
              <input
                id="target-url"
                type="text"
                placeholder="https://example.com"
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                disabled={isAnalyzing || !isOperator}
                className="w-full bg-slate-950/80 border border-slate-700 rounded-lg px-4 py-2.5 text-sm text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500 focus:border-cyan-500 disabled:opacity-50 disabled:cursor-not-allowed font-mono"
              />
            </div>
            <p className="text-[11px] text-slate-400 mt-1">
              Supports standard HTTP and HTTPS web addresses on ports 80 and 443. All internal IP
              ranges, loopback, and metadata services are blocked.
            </p>
          </div>

          {/* Mandatory Authorization Acknowledgement Checkbox */}
          <div className="p-3.5 rounded-lg bg-slate-950/60 border border-slate-800/80 space-y-2">
            <label className="flex items-start space-x-3 cursor-pointer">
              <input
                type="checkbox"
                checked={authConfirmed}
                onChange={(e) => setAuthConfirmed(e.target.checked)}
                disabled={isAnalyzing || !isOperator}
                className="mt-1 rounded bg-slate-900 border-slate-700 text-cyan-500 focus:ring-cyan-400 focus:ring-offset-slate-950 h-4 w-4 disabled:opacity-50"
              />
              <span className="text-xs text-slate-300 leading-relaxed select-none">
                <strong className="text-cyan-400 font-semibold">
                  Mandatory Authorization Acknowledgement:
                </strong>{' '}
                I confirm that I own or have explicit, documented authorization to assess this web
                target. I understand this platform strictly performs non-intrusive defensive header
                evaluations.
              </span>
            </label>
          </div>

          {/* RBAC Notice for Viewers */}
          {!isOperator && (
            <div className="p-3 rounded-lg bg-amber-950/30 border border-amber-900/50 flex items-center space-x-2 text-xs text-amber-300">
              <Info className="w-4 h-4 flex-shrink-0 text-amber-400" />
              <span>
                <strong>Viewer Role (Read-Only):</strong> You can review past assessment results
                below, but initiating new header scans requires an Analyst or Admin account.
              </span>
            </div>
          )}

          {/* Error Banner */}
          {errorMessage && (
            <div className="p-3.5 rounded-lg bg-rose-950/50 border border-rose-800 flex items-start space-x-3 text-xs text-rose-300 animate-fadeIn">
              <AlertTriangle className="w-4 h-4 flex-shrink-0 mt-0.5 text-rose-400" />
              <div className="space-y-1">
                <span className="font-semibold block">Analysis Request Failed</span>
                <span className="text-rose-200">{errorMessage}</span>
              </div>
            </div>
          )}

          <div className="flex items-center justify-between pt-2">
            <span className="text-xs text-slate-500 font-mono">Rate Limit: 15 analyses / min</span>

            <button
              type="submit"
              disabled={isAnalyzing || !isOperator || !authConfirmed || !targetUrl.trim()}
              className="inline-flex items-center space-x-2 px-5 py-2.5 rounded-lg font-medium text-xs bg-cyan-600 hover:bg-cyan-500 text-white shadow-lg shadow-cyan-600/30 transition disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {isAnalyzing ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span>Inspecting Target...</span>
                </>
              ) : (
                <>
                  <ShieldCheck className="w-4 h-4" />
                  <span>Analyze Security Headers</span>
                </>
              )}
            </button>
          </div>
        </form>
      </div>

      {/* Analysis Results View */}
      {currentResult && (
        <div className="space-y-6 animate-fadeIn">
          {/* Result Score Banner */}
          <div className="p-6 rounded-xl bg-gradient-to-r from-slate-900 via-slate-900/90 to-cyan-950/40 border border-slate-800 shadow-xl space-y-6">
            <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-4 border-b border-slate-800/80">
              <div className="space-y-1">
                <div className="flex items-center space-x-3">
                  <h2 className="text-lg font-bold text-white">Assessment Overview</h2>
                  <span
                    className={`px-3 py-1 rounded-full text-xs font-bold border ${
                      getGradeBadge(currentResult.grade).bg
                    }`}
                  >
                    {getGradeBadge(currentResult.grade).text}
                  </span>
                </div>
                <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-slate-400 font-mono">
                  <span>Target: {currentResult.target_url}</span>
                  {currentResult.final_url !== currentResult.target_url && (
                    <span className="text-cyan-400">Final: {currentResult.final_url}</span>
                  )}
                  <span>Status: HTTP {currentResult.status_code}</span>
                  <span>Timestamp: {new Date(currentResult.analyzed_at).toLocaleTimeString()}</span>
                </div>
              </div>

              {currentResult.created_findings_count > 0 && onNavigateToFindings && (
                <button
                  onClick={onNavigateToFindings}
                  className="inline-flex items-center space-x-2 px-4 py-2 rounded-lg bg-cyan-950/80 hover:bg-cyan-900 border border-cyan-700/80 text-cyan-300 text-xs font-medium transition shadow-md"
                >
                  <ShieldAlert className="w-4 h-4 text-cyan-400" />
                  <span>View {currentResult.created_findings_count} Generated Finding(s)</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </button>
              )}
            </div>

            {/* Score & Counter Grid */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
              <div className="p-4 rounded-lg bg-slate-950/60 border border-slate-800/80">
                <span className="text-xs text-slate-400 block mb-1">Security Score</span>
                <div className="flex items-baseline space-x-1">
                  <span className="text-2xl font-extrabold text-white">{currentResult.score}</span>
                  <span className="text-xs text-slate-500 font-mono">/ 100</span>
                </div>
              </div>

              <div className="p-4 rounded-lg bg-slate-950/60 border border-slate-800/80">
                <span className="text-xs text-slate-400 block mb-1">Headers Present</span>
                <div className="flex items-center space-x-2">
                  <span className="text-2xl font-extrabold text-emerald-400">
                    {currentResult.headers_present_count}
                  </span>
                  <span className="text-xs text-slate-500 font-mono">
                    / {currentResult.headers_evaluated_count}
                  </span>
                </div>
              </div>

              <div className="p-4 rounded-lg bg-slate-950/60 border border-slate-800/80">
                <span className="text-xs text-slate-400 block mb-1">Missing / Weak</span>
                <div className="flex items-center space-x-2">
                  <span className="text-2xl font-extrabold text-rose-400">
                    {currentResult.headers_missing_count}
                  </span>
                  <span className="text-xs text-slate-500 font-mono">unhardened</span>
                </div>
              </div>

              <div className="p-4 rounded-lg bg-slate-950/60 border border-slate-800/80">
                <span className="text-xs text-slate-400 block mb-1">Findings Logged</span>
                <div className="flex items-center space-x-2">
                  <span className="text-2xl font-extrabold text-cyan-400">
                    {currentResult.created_findings_count}
                  </span>
                  <span className="text-xs text-slate-500 font-mono">in registry</span>
                </div>
              </div>
            </div>
          </div>

          {/* Detailed Header Cards */}
          <div className="space-y-4">
            <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-400">
              Evaluated Security Headers ({currentResult.details.length})
            </h3>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {currentResult.details.map((header) => (
                <div
                  key={header.name}
                  className={`p-5 rounded-xl border transition-all ${
                    header.status === 'present'
                      ? 'bg-slate-900/60 border-slate-800 hover:border-slate-700'
                      : header.status === 'weak'
                        ? 'bg-slate-900/80 border-amber-900/60 shadow-sm shadow-amber-950'
                        : 'bg-slate-900/80 border-rose-900/50 shadow-sm shadow-rose-950'
                  }`}
                >
                  <div className="flex items-start justify-between gap-3 mb-2.5">
                    <div>
                      <h4 className="text-sm font-bold text-white font-mono">{header.name}</h4>
                      <p className="text-xs text-slate-400 mt-0.5 leading-relaxed">
                        {header.description}
                      </p>
                    </div>
                    {getStatusBadge(header.status)}
                  </div>

                  {/* Header Value if present */}
                  {header.value ? (
                    <div className="mt-3 p-2.5 rounded bg-slate-950 border border-slate-800 font-mono text-xs text-cyan-300 break-all select-all">
                      <span className="text-slate-500 select-none text-[10px] block mb-0.5">
                        Observed Header Value:
                      </span>
                      {header.value}
                    </div>
                  ) : (
                    <div className="mt-3 p-2 rounded bg-slate-950/60 border border-slate-800/60 text-xs text-slate-500 font-mono italic">
                      Header not sent by target web server
                    </div>
                  )}

                  {/* Remediation Note */}
                  <div className="mt-3 pt-3 border-t border-slate-800/80 text-xs flex items-start space-x-2">
                    <span className="text-slate-400 font-medium flex-shrink-0">Remediation:</span>
                    <span className="text-slate-300 font-mono text-[11px] leading-relaxed">
                      {header.recommendation}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Assessment History Table */}
      <div className="p-6 rounded-xl bg-slate-900/60 border border-slate-800 shadow-xl space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <History className="w-4 h-4 text-cyan-400" />
            <h2 className="text-base font-semibold text-white">Recent Header Assessments</h2>
          </div>

          <button
            onClick={fetchHistory}
            disabled={isLoadingHistory}
            className="p-1.5 rounded-lg border border-slate-800 hover:bg-slate-800 text-slate-400 hover:text-white transition"
            title="Refresh History"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoadingHistory ? 'animate-spin' : ''}`} />
          </button>
        </div>

        {history.length === 0 ? (
          <div className="p-8 text-center text-xs text-slate-500 font-mono border border-dashed border-slate-800 rounded-lg">
            No previous web security header assessments recorded.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs text-slate-300">
              <thead className="bg-slate-950/60 text-slate-400 font-mono border-b border-slate-800">
                <tr>
                  <th className="py-2.5 px-3">Target Endpoint</th>
                  <th className="py-2.5 px-3">HTTP Status</th>
                  <th className="py-2.5 px-3">Grade</th>
                  <th className="py-2.5 px-3">Score</th>
                  <th className="py-2.5 px-3">Headers (Pres / Miss)</th>
                  <th className="py-2.5 px-3">Findings</th>
                  <th className="py-2.5 px-3">Timestamp</th>
                  <th className="py-2.5 px-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono">
                {history.map((item) => (
                  <tr key={item.id} className="hover:bg-slate-800/40 transition">
                    <td className="py-2.5 px-3 text-white font-medium truncate max-w-xs">
                      {item.target_url}
                    </td>
                    <td className="py-2.5 px-3 text-slate-400">{item.status_code}</td>
                    <td className="py-2.5 px-3">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                          getGradeBadge(item.grade).bg
                        }`}
                      >
                        {item.grade}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-slate-200">{item.score} / 100</td>
                    <td className="py-2.5 px-3 text-slate-400">
                      <span className="text-emerald-400">{item.headers_present_count}</span>
                      {' / '}
                      <span className="text-rose-400">{item.headers_missing_count}</span>
                    </td>
                    <td className="py-2.5 px-3 text-cyan-400">{item.created_findings_count}</td>
                    <td className="py-2.5 px-3 text-slate-500 text-[11px]">
                      {new Date(item.analyzed_at).toLocaleString()}
                    </td>
                    <td className="py-2.5 px-3 text-right">
                      <button
                        onClick={() => {
                          setTargetUrl(item.target_url);
                          window.scrollTo({ top: 0, behavior: 'smooth' });
                        }}
                        className="text-cyan-400 hover:text-cyan-300 text-[11px] hover:underline"
                      >
                        Load Target
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};

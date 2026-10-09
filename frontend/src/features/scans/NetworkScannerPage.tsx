import React, { useState, useEffect, useCallback } from 'react';
import {
  Network,
  ShieldCheck,
  AlertTriangle,
  Search,
  CheckCircle2,
  XCircle,
  HelpCircle,
  Loader2,
  ExternalLink,
  Info,
  Server,
  Layers,
  Activity,
  Radio,
} from 'lucide-react';
import { useAuth } from '../auth/useAuth';
import {
  runNetworkScanApi,
  getNetworkScansApi,
  getNetworkScanSummaryApi,
  getNetworkScanScopeApi,
} from '../../services/api';
import {
  ScanResponse,
  ScanSummaryResponse,
  ScanScopeResponse,
} from '../../types';

interface NetworkScannerPageProps {
  onNavigateToFindings?: () => void;
}

export const NetworkScannerPage: React.FC<NetworkScannerPageProps> = ({
  onNavigateToFindings,
}) => {
  const { token, user } = useAuth();

  // Scope & Config
  const [scope, setScope] = useState<ScanScopeResponse | null>(null);
  const [summary, setSummary] = useState<ScanSummaryResponse | null>(null);

  // Form Inputs
  const [target, setTarget] = useState<string>('127.0.0.1');
  const [preset, setPreset] = useState<string>('common');
  const [customPortsInput, setCustomPortsInput] = useState<string>('80, 443, 8000, 8080');
  const [authorizationConfirmed, setAuthorizationConfirmed] = useState<boolean>(false);

  // Scan State
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [scanError, setScanError] = useState<string | null>(null);
  const [currentScan, setCurrentScan] = useState<ScanResponse | null>(null);

  // History State
  const [history, setHistory] = useState<ScanResponse[]>([]);
  const [historyPage, setHistoryPage] = useState<number>(1);
  const [historyTotal, setHistoryTotal] = useState<number>(0);
  const [historyPages, setHistoryPages] = useState<number>(1);
  const [isLoadingHistory, setIsLoadingHistory] = useState<boolean>(false);

  // Detail Modal
  const [selectedScan, setSelectedScan] = useState<ScanResponse | null>(null);

  const isViewer = user?.role === 'viewer';

  // Load Scope & Summary
  const loadScopeAndSummary = useCallback(async () => {
    if (!token) return;
    try {
      const [scopeData, sumData] = await Promise.all([
        getNetworkScanScopeApi(token),
        getNetworkScanSummaryApi(token),
      ]);
      setScope(scopeData);
      setSummary(sumData);
    } catch {
      // Non-critical background failure
    }
  }, [token]);

  // Load History
  const loadHistory = useCallback(
    async (page = 1) => {
      if (!token) return;
      setIsLoadingHistory(true);
      try {
        const res = await getNetworkScansApi(token, page, 10);
        setHistory(res.items);
        setHistoryTotal(res.total);
        setHistoryPages(res.pages);
        setHistoryPage(page);
      } catch {
        // Silently handle history load error
      } finally {
        setIsLoadingHistory(false);
      }
    },
    [token],
  );

  useEffect(() => {
    loadScopeAndSummary();
    loadHistory(1);
  }, [loadScopeAndSummary, loadHistory]);

  // Parse custom ports string into number array
  const parseCustomPorts = (input: string): number[] => {
    const rawParts = input.split(/[,;\s]+/);
    const ports: number[] = [];
    for (const part of rawParts) {
      const trimmed = part.trim();
      if (!trimmed) continue;
      if (trimmed.includes('-')) {
        const [startStr, endStr] = trimmed.split('-');
        const start = parseInt(startStr, 10);
        const end = parseInt(endStr, 10);
        if (!isNaN(start) && !isNaN(end) && start <= end) {
          for (let p = start; p <= Math.min(end, start + 100); p++) {
            if (p >= 1 && p <= 65535) ports.push(p);
          }
        }
      } else {
        const p = parseInt(trimmed, 10);
        if (!isNaN(p) && p >= 1 && p <= 65535) {
          ports.push(p);
        }
      }
    }
    return Array.from(new Set(ports)).sort((a, b) => a - b);
  };

  // Handle Scan Submit
  const handleExecuteScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!token) return;

    setScanError(null);
    setCurrentScan(null);

    if (!authorizationConfirmed) {
      setScanError('You must confirm explicit authorization before initiating a scan.');
      return;
    }

    let portsToSend: number[] | undefined = undefined;
    if (preset === 'custom') {
      const parsed = parseCustomPorts(customPortsInput);
      if (parsed.length === 0) {
        setScanError('Custom port selection is empty or invalid. Enter valid ports (1-65535).');
        return;
      }
      if (scope && parsed.length > scope.max_ports_per_scan) {
        setScanError(
          `Port count (${parsed.length}) exceeds server limit of ${scope.max_ports_per_scan} ports.`,
        );
        return;
      }
      portsToSend = parsed;
    }

    setIsScanning(true);
    try {
      const response = await runNetworkScanApi(token, {
        target: target.trim(),
        port_preset: preset !== 'custom' ? preset : undefined,
        ports: portsToSend,
        authorization_confirmed: true,
      });
      setCurrentScan(response);
      loadScopeAndSummary();
      loadHistory(1);
    } catch (err: unknown) {
      if (err instanceof Error) {
        setScanError(err.message);
      } else {
        setScanError('Network scan failed due to an unexpected error.');
      }
    } finally {
      setIsScanning(false);
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status.toLowerCase()) {
      case 'open':
        return (
          <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-xs font-mono font-bold bg-emerald-950/80 text-emerald-400 border border-emerald-800/80 shadow-[0_0_8px_rgba(52,211,153,0.3)]">
            <CheckCircle2 className="w-3 h-3" />
            <span>OPEN</span>
          </span>
        );
      case 'closed':
        return (
          <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-xs font-mono bg-slate-800 text-slate-300 border border-slate-700">
            <XCircle className="w-3 h-3" />
            <span>CLOSED</span>
          </span>
        );
      case 'filtered_or_unreachable':
      default:
        return (
          <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-xs font-mono bg-amber-950/70 text-amber-400 border border-amber-800/80">
            <HelpCircle className="w-3 h-3" />
            <span>FILTERED / TIMEOUT</span>
          </span>
        );
    }
  };

  const getServiceSecurityTag = (port: number, status: string) => {
    if (status.toLowerCase() !== 'open') return null;
    if (port === 23) {
      return (
        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-950/80 text-rose-300 border border-rose-800/80">
          Insecure Cleartext (Finding Logged)
        </span>
      );
    }
    if (port === 21) {
      return (
        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-950/80 text-amber-300 border border-amber-800/80">
          Unencrypted FTP (Finding Logged)
        </span>
      );
    }
    if (port === 445 || port === 6379 || port === 27017) {
      return (
        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-950/80 text-rose-300 border border-rose-800/80">
          Exposed Interface (Finding Logged)
        </span>
      );
    }
    if (port === 3389 || port === 5900) {
      return (
        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-950/80 text-amber-300 border border-amber-800/80">
          Remote Desktop (Finding Logged)
        </span>
      );
    }
    return (
      <span className="text-[10px] font-mono text-slate-400">
        Normal Service
      </span>
    );
  };

  return (
    <div className="space-y-8">
      {/* Page Header */}
      <section className="space-y-2">
        <div className="flex items-center space-x-2">
          <div className="p-1.5 rounded bg-cyan-950 border border-cyan-800 text-cyan-400">
            <Network className="w-5 h-5" />
          </div>
          <span className="text-xs font-mono uppercase tracking-widest text-cyan-400">
            Phase 8 Defensive Engine
          </span>
        </div>
        <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
          Authorized Network Scanner
        </h1>
        <p className="text-sm text-slate-400 max-w-3xl leading-relaxed">
          Perform non-destructive, standard TCP connect assessments against explicitly authorized
          infrastructure. Detects open services, isolates cleartext exposure vectors, and
          automatically aggregates hardening findings into the Security Findings Registry.
        </p>
      </section>

      {/* Scope Policy & Defense Limitations Banner */}
      <section className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-800/80">
          <div className="flex items-center space-x-2">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            <span className="text-xs font-semibold text-white">
              Authorized Scope Policy Active
            </span>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950/80 text-emerald-400 border border-emerald-800/80">
              STRICT DEFENSIVE MODE
            </span>
          </div>
          <div className="text-[11px] font-mono text-slate-400 flex items-center space-x-3">
            <span>Rate Limit: {scope?.rate_limit_per_minute ?? 10}/min</span>
            <span>Max Ports: {scope?.max_ports_per_scan ?? 100}</span>
            <span>Socket Timeout: {scope?.connect_timeout_seconds ?? 1.5}s</span>
          </div>
        </div>

        <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 text-xs text-slate-400">
          <div className="space-y-1">
            <span className="text-slate-300 font-medium">Permitted Targets Policy:</span>
            <div className="flex flex-wrap gap-1.5 mt-1">
              {scope?.allowed_targets.map((tgt) => (
                <button
                  key={tgt}
                  type="button"
                  onClick={() => setTarget(tgt)}
                  className="px-2 py-0.5 rounded text-[11px] font-mono bg-cyan-950/60 text-cyan-300 border border-cyan-800/60 hover:bg-cyan-900/60 transition"
                  title="Click to populate target field"
                >
                  {tgt}
                </button>
              )) ?? (
                <span className="text-slate-500 font-mono">127.0.0.1, localhost, ::1</span>
              )}
            </div>
          </div>

          <div className="flex items-start space-x-2 bg-slate-950/60 p-2.5 rounded-lg border border-slate-800/80 max-w-md">
            <Info className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
            <p className="text-[11px] leading-relaxed text-slate-400">
              Only standard TCP connect handshakes are performed. SYN scanning, stealth evasion,
              exploit payloads, and scanning third-party targets are strictly prohibited.
            </p>
          </div>
        </div>
      </section>

      {/* KPI Summary Cards */}
      <section className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium">Total Scans</span>
            <Activity className="w-4 h-4 text-cyan-400" />
          </div>
          <p className="text-2xl font-bold text-white font-mono">
            {summary?.total_scans ?? 0}
          </p>
          <span className="text-[10px] text-slate-500">Historical jobs recorded</span>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium">Ports Probed</span>
            <Layers className="w-4 h-4 text-cyan-400" />
          </div>
          <p className="text-2xl font-bold text-white font-mono">
            {summary?.total_ports_checked ?? 0}
          </p>
          <span className="text-[10px] text-slate-500">Individual socket checks</span>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium">Open Services</span>
            <Radio className="w-4 h-4 text-emerald-400" />
          </div>
          <p className="text-2xl font-bold text-emerald-400 font-mono">
            {summary?.total_open_ports ?? 0}
          </p>
          <span className="text-[10px] text-slate-500">Active TCP listeners</span>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium">Finding Integrations</span>
            <Server className="w-4 h-4 text-rose-400" />
          </div>
          <p className="text-2xl font-bold text-rose-400 font-mono">
            {currentScan?.created_findings_count ?? 0}
          </p>
          <span className="text-[10px] text-slate-500">Insecure protocol exposures</span>
        </div>
      </section>

      {/* Scan Execution Form */}
      <section className="p-6 rounded-xl bg-slate-900/70 border border-slate-800 shadow-xl space-y-6">
        <div>
          <h2 className="text-base font-semibold text-white">Execute Authorized Network Scan</h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Probe TCP listening ports to verify perimeter exposure and network service hygiene.
          </p>
        </div>

        {isViewer && (
          <div className="p-3 rounded-lg bg-amber-950/40 border border-amber-800/80 flex items-center space-x-2 text-xs text-amber-300">
            <AlertTriangle className="w-4 h-4 shrink-0 text-amber-400" />
            <span>
              Your current account role is <strong>VIEWER</strong>. Viewing historical scan data is
              permitted, but initiating scans requires <strong>ANALYST</strong> or{' '}
              <strong>ADMIN</strong> privileges.
            </span>
          </div>
        )}

        <form onSubmit={handleExecuteScan} className="space-y-5">
          {/* Target Host Input */}
          <div className="space-y-1.5">
            <label htmlFor="target-input" className="block text-xs font-medium text-slate-300">
              Target IP Address or Hostname <span className="text-rose-400">*</span>
            </label>
            <div className="relative">
              <input
                id="target-input"
                type="text"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                disabled={isViewer || isScanning}
                placeholder="e.g. 127.0.0.1 or localhost"
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-cyan-500 transition disabled:opacity-50"
              />
            </div>
            <p className="text-[11px] text-slate-500">
              Must match the server-enforced authorized target policy. Do not include schemes (http://)
              or port notation.
            </p>
          </div>

          {/* Port Presets */}
          <div className="space-y-2">
            <label className="block text-xs font-medium text-slate-300">
              Port Selection Profile
            </label>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
              {[
                { id: 'common', name: 'Common Services', desc: 'Top 20 standard ports' },
                { id: 'web', name: 'Web Services', desc: 'HTTP, HTTPS, 8080, etc.' },
                { id: 'database', name: 'Databases', desc: 'MySQL, Postgres, Redis, etc.' },
                { id: 'custom', name: 'Custom Selection', desc: 'Specify exact port list' },
              ].map((p) => (
                <button
                  key={p.id}
                  type="button"
                  disabled={isViewer || isScanning}
                  onClick={() => setPreset(p.id)}
                  className={`p-3 rounded-lg border text-left transition ${
                    preset === p.id
                      ? 'bg-cyan-950/80 border-cyan-500 text-white shadow-sm'
                      : 'bg-slate-950 border-slate-800 text-slate-400 hover:border-slate-700'
                  } disabled:opacity-50`}
                >
                  <p className="text-xs font-semibold text-slate-200">{p.name}</p>
                  <p className="text-[10px] text-slate-400 mt-0.5">{p.desc}</p>
                </button>
              ))}
            </div>

            {preset === 'custom' && (
              <div className="mt-2 space-y-1">
                <input
                  type="text"
                  value={customPortsInput}
                  onChange={(e) => setCustomPortsInput(e.target.value)}
                  disabled={isViewer || isScanning}
                  placeholder="e.g. 21, 22, 80, 443, 8000-8010"
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-white font-mono focus:outline-none focus:border-cyan-500 transition disabled:opacity-50"
                />
                <span className="text-[10px] text-slate-500">
                  Comma-separated ports or short ranges (max {scope?.max_ports_per_scan ?? 100} ports).
                </span>
              </div>
            )}
          </div>

          {/* Explicit Authorization Checkbox */}
          <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 space-y-2">
            <label className="flex items-start space-x-3 cursor-pointer">
              <input
                type="checkbox"
                checked={authorizationConfirmed}
                onChange={(e) => setAuthorizationConfirmed(e.target.checked)}
                disabled={isViewer || isScanning}
                className="mt-0.5 rounded border-slate-700 text-cyan-600 focus:ring-cyan-500 bg-slate-900 disabled:opacity-50 cursor-pointer"
              />
              <span className="text-xs text-slate-300 leading-relaxed select-none">
                <strong className="text-white">Explicit Authorization Confirmation:</strong> I confirm
                that I own this asset or have documented written permission to perform a defensive
                network port scan against this target.
              </span>
            </label>
          </div>

          {/* Error Message */}
          {scanError && (
            <div className="p-3 rounded-lg bg-rose-950/70 border border-rose-800/80 text-rose-300 text-xs flex items-center space-x-2">
              <AlertTriangle className="w-4 h-4 shrink-0 text-rose-400" />
              <span>{scanError}</span>
            </div>
          )}

          {/* Submit Action */}
          <div className="flex items-center justify-end space-x-3 pt-2">
            <button
              type="submit"
              disabled={isViewer || isScanning || !authorizationConfirmed}
              className="inline-flex items-center space-x-2 px-5 py-2.5 rounded-lg text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white shadow-lg shadow-cyan-950 transition disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {isScanning ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin text-white" />
                  <span>Scanning TCP Ports...</span>
                </>
              ) : (
                <>
                  <Search className="w-4 h-4" />
                  <span>Start Network Scan</span>
                </>
              )}
            </button>
          </div>
        </form>
      </section>

      {/* Active Scan Results */}
      {currentScan && (
        <section className="p-6 rounded-xl bg-slate-900/80 border border-cyan-800/60 shadow-xl space-y-5">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-800">
            <div>
              <div className="flex items-center space-x-2">
                <span className="text-sm font-bold text-white">Scan Results for</span>
                <span className="text-sm font-mono font-bold text-cyan-400">
                  {currentScan.target_host}
                </span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950/80 text-emerald-400 border border-emerald-800/80">
                  {currentScan.status}
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                Probed {currentScan.total_ports_scanned} ports in{' '}
                <span className="font-mono text-slate-200">
                  {currentScan.scan_duration_ms ?? 0} ms
                </span>
              </p>
            </div>

            <div className="flex items-center space-x-2">
              {currentScan.created_findings_count > 0 && (
                <button
                  onClick={onNavigateToFindings}
                  className="inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-rose-950/80 text-rose-300 border border-rose-800 hover:bg-rose-900/80 transition"
                >
                  <AlertTriangle className="w-3.5 h-3.5 text-rose-400" />
                  <span>{currentScan.created_findings_count} Findings Generated →</span>
                </button>
              )}
            </div>
          </div>

          {/* Port Results Table */}
          <div className="overflow-x-auto rounded-lg border border-slate-800">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950 text-slate-400 uppercase font-mono text-[10px] border-b border-slate-800">
                <tr>
                  <th className="py-2.5 px-3">Port</th>
                  <th className="py-2.5 px-3">Service</th>
                  <th className="py-2.5 px-3">Probe Status</th>
                  <th className="py-2.5 px-3">Security Assessment</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono">
                {currentScan.port_details.map((item) => (
                  <tr
                    key={item.port}
                    className={`hover:bg-slate-800/30 transition ${
                      item.status === 'open' ? 'bg-cyan-950/10' : ''
                    }`}
                  >
                    <td className="py-2.5 px-3 font-bold text-white">{item.port}</td>
                    <td className="py-2.5 px-3 text-slate-300">
                      {item.service || <span className="text-slate-600">Unknown</span>}
                    </td>
                    <td className="py-2.5 px-3">{getStatusBadge(item.status)}</td>
                    <td className="py-2.5 px-3">
                      {getServiceSecurityTag(item.port, item.status)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {/* Historical Scans Registry */}
      <section className="p-6 rounded-xl bg-slate-900/60 border border-slate-800 space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-sm font-semibold text-white">Historical Scan Registry</h3>
            <p className="text-xs text-slate-400">
              Audit log of verified network discovery assessments
            </p>
          </div>
          <span className="text-xs font-mono text-slate-400">
            Total Records: {historyTotal}
          </span>
        </div>

        {isLoadingHistory ? (
          <div className="py-8 text-center text-xs text-slate-500 flex items-center justify-center space-x-2">
            <Loader2 className="w-4 h-4 animate-spin text-cyan-400" />
            <span>Loading scan history...</span>
          </div>
        ) : history.length === 0 ? (
          <div className="py-8 text-center text-xs text-slate-500">
            No historical network scans recorded yet. Initiate an authorized scan above.
          </div>
        ) : (
          <div className="overflow-x-auto rounded-lg border border-slate-800">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950 text-slate-400 uppercase font-mono text-[10px] border-b border-slate-800">
                <tr>
                  <th className="py-2.5 px-3">Target Host</th>
                  <th className="py-2.5 px-3">Scan Type</th>
                  <th className="py-2.5 px-3">Ports Checked</th>
                  <th className="py-2.5 px-3">Open Ports</th>
                  <th className="py-2.5 px-3">Duration</th>
                  <th className="py-2.5 px-3">Timestamp</th>
                  <th className="py-2.5 px-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono">
                {history.map((record) => (
                  <tr key={record.id} className="hover:bg-slate-800/30 transition">
                    <td className="py-2.5 px-3 font-bold text-white">{record.target_host}</td>
                    <td className="py-2.5 px-3 text-slate-300">{record.scan_type}</td>
                    <td className="py-2.5 px-3 text-slate-300">{record.total_ports_scanned}</td>
                    <td className="py-2.5 px-3">
                      <span
                        className={`font-bold ${
                          record.open_ports_count > 0 ? 'text-emerald-400' : 'text-slate-500'
                        }`}
                      >
                        {record.open_ports_count}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-slate-400">
                      {record.scan_duration_ms ? `${record.scan_duration_ms} ms` : '—'}
                    </td>
                    <td className="py-2.5 px-3 text-slate-500 text-[11px]">
                      {new Date(record.created_at).toLocaleString()}
                    </td>
                    <td className="py-2.5 px-3 text-right">
                      <button
                        onClick={() => setSelectedScan(record)}
                        className="inline-flex items-center space-x-1 text-cyan-400 hover:text-cyan-300 text-xs font-semibold"
                      >
                        <span>Details</span>
                        <ExternalLink className="w-3 h-3" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination */}
        {historyPages > 1 && (
          <div className="flex items-center justify-between pt-2">
            <span className="text-xs text-slate-500 font-mono">
              Page {historyPage} of {historyPages}
            </span>
            <div className="flex space-x-2">
              <button
                disabled={historyPage <= 1}
                onClick={() => loadHistory(historyPage - 1)}
                className="px-2.5 py-1 text-xs rounded bg-slate-800 text-slate-300 hover:bg-slate-700 disabled:opacity-50"
              >
                Previous
              </button>
              <button
                disabled={historyPage >= historyPages}
                onClick={() => loadHistory(historyPage + 1)}
                className="px-2.5 py-1 text-xs rounded bg-slate-800 text-slate-300 hover:bg-slate-700 disabled:opacity-50"
              >
                Next
              </button>
            </div>
          </div>
        )}
      </section>

      {/* Detail Modal */}
      {selectedScan && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
          <div className="bg-slate-900 border border-slate-700 rounded-xl max-w-2xl w-full p-6 shadow-2xl space-y-4 max-h-[85vh] overflow-y-auto">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center space-x-2">
                <Network className="w-5 h-5 text-cyan-400" />
                <h3 className="text-base font-bold text-white">
                  Scan Breakdown: {selectedScan.target_host}
                </h3>
              </div>
              <button
                onClick={() => setSelectedScan(null)}
                className="p-1 rounded text-slate-400 hover:text-white hover:bg-slate-800"
              >
                ✕
              </button>
            </div>

            <div className="grid grid-cols-2 gap-3 text-xs font-mono bg-slate-950 p-3 rounded-lg border border-slate-800">
              <div>
                <span className="text-slate-500">Scan ID:</span>{' '}
                <span className="text-slate-300">{selectedScan.id}</span>
              </div>
              <div>
                <span className="text-slate-500">Scan Type:</span>{' '}
                <span className="text-slate-300">{selectedScan.scan_type}</span>
              </div>
              <div>
                <span className="text-slate-500">Duration:</span>{' '}
                <span className="text-slate-300">{selectedScan.scan_duration_ms ?? 0} ms</span>
              </div>
              <div>
                <span className="text-slate-500">Executed At:</span>{' '}
                <span className="text-slate-300">
                  {new Date(selectedScan.created_at).toLocaleString()}
                </span>
              </div>
            </div>

            <div className="overflow-x-auto rounded-lg border border-slate-800">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-950 text-slate-400 uppercase font-mono text-[10px] border-b border-slate-800">
                  <tr>
                    <th className="py-2 px-3">Port</th>
                    <th className="py-2 px-3">Service</th>
                    <th className="py-2 px-3">Status</th>
                    <th className="py-2 px-3">Assessment</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-mono">
                  {selectedScan.port_details.map((p) => (
                    <tr key={p.port} className="hover:bg-slate-800/30">
                      <td className="py-2 px-3 font-bold text-white">{p.port}</td>
                      <td className="py-2 px-3 text-slate-300">{p.service || 'Unknown'}</td>
                      <td className="py-2 px-3">{getStatusBadge(p.status)}</td>
                      <td className="py-2 px-3">{getServiceSecurityTag(p.port, p.status)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="flex justify-end pt-2">
              <button
                onClick={() => setSelectedScan(null)}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-white text-xs font-medium"
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

import React from 'react';
import {
  Network,
  Globe,
  KeyRound,
  FileCheck2,
  ScrollText,
  FileBarChart2,
  ShieldAlert,
  ClipboardList,
} from 'lucide-react';

interface ModuleItem {
  name: string;
  phase: string;
  description: string;
  icon: React.ReactNode;
}

const PLANNED_MODULES: ModuleItem[] = [
  {
    name: 'Authorized Network Scanner',
    phase: 'Phase 8',
    description: 'Non-destructive TCP service and port discovery on authorized targets',
    icon: <Network className="w-5 h-5" />,
  },
  {
    name: 'Web Security Header Analyzer',
    phase: 'Phase 5',
    description: 'Evaluation of CSP, HSTS, X-Frame-Options, and cookie security flags',
    icon: <Globe className="w-5 h-5" />,
  },
  {
    name: 'Password Security Analyzer',
    phase: 'Phase 9',
    description: 'Client-side entropy calculator and defensive strength auditor',
    icon: <KeyRound className="w-5 h-5" />,
  },
  {
    name: 'File Integrity Monitor',
    phase: 'Phase 6',
    description: 'SHA-256 cryptographic baseline change detection and tampering alerts',
    icon: <FileCheck2 className="w-5 h-5" />,
  },
  {
    name: 'Defensive Log Analyzer',
    phase: 'Phase 7',
    description: 'Syslog, Auth, and Web access regex pattern and anomaly parser',
    icon: <ScrollText className="w-5 h-5" />,
  },
  {
    name: 'Security Findings Aggregator',
    phase: 'Phase 4',
    description: 'Centralized posture registry classified by CWE and OWASP identifiers',
    icon: <ShieldAlert className="w-5 h-5" />,
  },
  {
    name: 'Executive Report Generator',
    phase: 'Phase 9',
    description: 'Compiles technical assessments into PDF and JSON executive summaries',
    icon: <FileBarChart2 className="w-5 h-5" />,
  },
  {
    name: 'Audit Trail & Compliance',
    phase: 'Phase 3',
    description: 'Immutable records of all platform operations and operator actions',
    icon: <ClipboardList className="w-5 h-5" />,
  },
];

interface NavigationPlaceholderProps {
  onNavigateToHeaders?: () => void;
  onNavigateToFindings?: () => void;
  onNavigateToFim?: () => void;
  onNavigateToLogs?: () => void;
}

export const NavigationPlaceholder: React.FC<NavigationPlaceholderProps> = ({
  onNavigateToHeaders,
  onNavigateToFindings,
  onNavigateToFim,
  onNavigateToLogs,
}) => {
  return (
    <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-6 shadow-xl backdrop-blur">
      <div className="flex items-center justify-between pb-4 border-b border-slate-800/80 mb-5">
        <div>
          <h2 className="text-base font-semibold text-white">Platform Modules Roadmap</h2>
          <p className="text-xs text-slate-400">
            Defensive modules scheduled for systematic implementation in upcoming phases
          </p>
        </div>
        <span className="text-xs font-mono text-cyan-400 px-2.5 py-1 rounded bg-cyan-950/60 border border-cyan-800/60">
          8 Core Modules
        </span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {PLANNED_MODULES.map((mod) => {
          const isHeaders = mod.name === 'Web Security Header Analyzer';
          const isFindings = mod.name === 'Security Findings Aggregator';
          const isFim = mod.name === 'File Integrity Monitor';
          const isLogs = mod.name === 'Defensive Log Analyzer';
          const isAuth = mod.name === 'Audit Trail & Compliance';
          const isOperational = isHeaders || isFindings || isFim || isLogs;

          return (
            <div
              key={mod.name}
              className={`p-4 rounded-lg border transition flex flex-col justify-between ${
                isOperational
                  ? 'bg-slate-900/80 border-cyan-800/60 shadow-sm shadow-cyan-950'
                  : 'bg-slate-950/50 border-slate-800/80 hover:border-slate-700'
              }`}
            >
              <div>
                <div className="flex items-center justify-between mb-2">
                  <div
                    className={`p-2 rounded-lg border ${
                      isOperational
                        ? 'bg-cyan-950 text-cyan-400 border-cyan-700/80'
                        : 'bg-slate-900 text-cyan-400 border-slate-800'
                    }`}
                  >
                    {mod.icon}
                  </div>
                  <span
                    className={`text-[11px] font-mono font-medium px-2 py-0.5 rounded ${
                      isOperational
                        ? 'bg-emerald-950/80 text-emerald-400 border border-emerald-800/80'
                        : isAuth
                          ? 'bg-cyan-950/80 text-cyan-300 border border-cyan-800/80'
                          : 'bg-slate-800 text-slate-300'
                    }`}
                  >
                    {isOperational ? 'Operational' : isAuth ? 'Integrated' : mod.phase}
                  </span>
                </div>
                <h3 className="text-sm font-semibold text-slate-200 mt-2">{mod.name}</h3>
                <p className="text-xs text-slate-400 mt-1 leading-relaxed">{mod.description}</p>
              </div>

              <div className="mt-4 pt-3 border-t border-slate-800/60 text-[11px] font-mono flex items-center justify-between">
                {isHeaders ? (
                  <button
                    onClick={onNavigateToHeaders}
                    className="text-cyan-400 hover:text-cyan-300 font-semibold hover:underline flex items-center space-x-1"
                  >
                    <span>Launch Analyzer →</span>
                  </button>
                ) : isFindings ? (
                  <button
                    onClick={onNavigateToFindings}
                    className="text-cyan-400 hover:text-cyan-300 font-semibold hover:underline flex items-center space-x-1"
                  >
                    <span>Open Registry →</span>
                  </button>
                ) : isFim ? (
                  <button
                    onClick={onNavigateToFim}
                    className="text-cyan-400 hover:text-cyan-300 font-semibold hover:underline flex items-center space-x-1"
                  >
                    <span>Launch Monitor →</span>
                  </button>
                ) : isLogs ? (
                  <button
                    onClick={onNavigateToLogs}
                    className="text-cyan-400 hover:text-cyan-300 font-semibold hover:underline flex items-center space-x-1"
                  >
                    <span>Launch Analyzer →</span>
                  </button>
                ) : isAuth ? (
                  <span className="text-slate-400">Security Layer Active</span>
                ) : (
                  <span className="text-slate-500">Scheduled: {mod.phase}</span>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

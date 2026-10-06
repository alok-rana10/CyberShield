import React from 'react';
import { ShieldAlert, ShieldCheck, Terminal, Compass } from 'lucide-react';

export const DashboardPlaceholder: React.FC = () => {
  return (
    <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-6 shadow-xl backdrop-blur">
      <div className="flex items-center justify-between pb-4 border-b border-slate-800/80 mb-5">
        <div>
          <h2 className="text-base font-semibold text-white">Defensive Operations Overview</h2>
          <p className="text-xs text-slate-400">Architectural principles and security posture baseline</p>
        </div>
        <div className="flex items-center space-x-1.5 text-xs text-emerald-400 bg-emerald-950/40 border border-emerald-800/50 px-2.5 py-1 rounded">
          <ShieldCheck className="w-3.5 h-3.5" />
          <span>Foundation Ready</span>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Card 1: Strict Scope & Authorization */}
        <div className="p-5 rounded-lg bg-slate-950/70 border border-slate-800 flex flex-col justify-between">
          <div>
            <div className="w-9 h-9 rounded-lg bg-cyan-950/80 border border-cyan-800/50 text-cyan-400 flex items-center justify-center mb-3">
              <ShieldCheck className="w-5 h-5" />
            </div>
            <h3 className="text-sm font-semibold text-white">Explicit Authorization Scope</h3>
            <p className="text-xs text-slate-400 mt-2 leading-relaxed">
              CyberShield enforces strict authorization checks. All diagnostic scans are gated by consent confirmation,
              with SSRF defenses preventing unauthorized probing of private network boundaries.
            </p>
          </div>
          <div className="mt-4 pt-3 border-t border-slate-900 text-[11px] font-mono text-cyan-400">
            Rule: Zero Offensive Capability
          </div>
        </div>

        {/* Card 2: Non-Destructive Mechanics */}
        <div className="p-5 rounded-lg bg-slate-950/70 border border-slate-800 flex flex-col justify-between">
          <div>
            <div className="w-9 h-9 rounded-lg bg-indigo-950/80 border border-indigo-800/50 text-indigo-400 flex items-center justify-center mb-3">
              <Terminal className="w-5 h-5" />
            </div>
            <h3 className="text-sm font-semibold text-white">Non-Destructive Probing</h3>
            <p className="text-xs text-slate-400 mt-2 leading-relaxed">
              Pure Python socket handshakes with timeout guards and passive header inspectors replace volatile
              external binaries. No exploit kits, credential stuffing, or invasive payloads are permitted.
            </p>
          </div>
          <div className="mt-4 pt-3 border-t border-slate-900 text-[11px] font-mono text-indigo-400">
            Rule: Safe Socket Connect Only
          </div>
        </div>

        {/* Card 3: Continuous Integrity & Auditing */}
        <div className="p-5 rounded-lg bg-slate-950/70 border border-slate-800 flex flex-col justify-between">
          <div>
            <div className="w-9 h-9 rounded-lg bg-amber-950/80 border border-amber-800/50 text-amber-400 flex items-center justify-center mb-3">
              <Compass className="w-5 h-5" />
            </div>
            <h3 className="text-sm font-semibold text-white">Immutable Non-Repudiation</h3>
            <p className="text-xs text-slate-400 mt-2 leading-relaxed">
              Every operation across the API triggers structured audit telemetry recording operator identity,
              source IP, and target scope to maintain rigorous compliance trails.
            </p>
          </div>
          <div className="mt-4 pt-3 border-t border-slate-900 text-[11px] font-mono text-amber-400">
            Rule: Audit Logging Middleware
          </div>
        </div>
      </div>

      {/* Security Disclaimer Banner */}
      <div className="mt-6 p-4 rounded-lg bg-cyan-950/20 border border-cyan-800/40 flex items-start space-x-3 text-xs text-slate-300">
        <ShieldAlert className="w-5 h-5 text-cyan-400 shrink-0 mt-0.5" />
        <p className="leading-relaxed">
          <strong className="text-cyan-300">Defensive Security Notice:</strong> CyberShield is designed strictly for
          monitoring, testing, and securing systems, networks, files, and domains you own or have explicit, documented
          authorization to assess. Unauthorized scanning of third-party networks is strictly prohibited.
        </p>
      </div>
    </div>
  );
};

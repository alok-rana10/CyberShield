import React from 'react';
import { Shield, Lock } from 'lucide-react';
import { ConnectionState } from '../types';

interface NavbarProps {
  connectionState: ConnectionState;
}

export const Navbar: React.FC<NavbarProps> = ({ connectionState }) => {
  return (
    <header className="border-b border-slate-800 bg-slate-900/80 backdrop-blur sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
        {/* Brand / Logo */}
        <div className="flex items-center space-x-3">
          <div className="p-2 bg-cyan-950/80 border border-cyan-500/30 rounded-lg text-cyan-400 shadow-sm shadow-cyan-500/20">
            <Shield className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className="text-xl font-bold tracking-tight text-white">CyberShield</span>
              <span className="text-[10px] font-semibold uppercase tracking-wider px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                Phase 1 Foundation
              </span>
            </div>
            <p className="text-xs text-slate-400 hidden sm:block">Defensive Security Monitoring Platform</p>
          </div>
        </div>

        {/* Status Indicator & Badge */}
        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-2 text-xs font-mono px-3 py-1.5 rounded-full border border-slate-800 bg-slate-950/60">
            <span
              className={`w-2 h-2 rounded-full ${
                connectionState === 'online'
                  ? 'bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.8)]'
                  : connectionState === 'offline'
                  ? 'bg-rose-500 shadow-[0_0_8px_rgba(244,63,94,0.8)]'
                  : 'bg-amber-400 animate-pulse'
              }`}
            />
            <span className="text-slate-300">
              {connectionState === 'online'
                ? 'Backend Online'
                : connectionState === 'offline'
                ? 'Backend Offline'
                : 'Connecting...'}
            </span>
          </div>

          <div className="hidden md:flex items-center space-x-1 text-xs text-slate-400 border-l border-slate-800 pl-4">
            <Lock className="w-3.5 h-3.5 text-cyan-400" />
            <span>Authorized Scope Only</span>
          </div>
        </div>
      </div>
    </header>
  );
};

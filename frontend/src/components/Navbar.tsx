import React from 'react';
import {
  Shield,
  Lock,
  LogOut,
  User as UserIcon,
  LogIn,
  UserPlus,
  Activity,
  Layers,
  Globe,
  FileCheck2,
  ScrollText,
} from 'lucide-react';
import { ConnectionState } from '../types';
import { useAuth } from '../features/auth/useAuth';

interface NavbarProps {
  connectionState: ConnectionState;
  activeView: 'dashboard' | 'findings' | 'headers' | 'fim' | 'logs' | 'login' | 'register';
  onNavigate: (view: 'dashboard' | 'findings' | 'headers' | 'fim' | 'logs' | 'login' | 'register') => void;
}

export const Navbar: React.FC<NavbarProps> = ({ connectionState, activeView, onNavigate }) => {
  const { user, isAuthenticated, logout } = useAuth();

  const getRoleBadgeColor = (role?: string) => {
    switch (role) {
      case 'admin':
        return 'bg-rose-950/80 text-rose-300 border-rose-800/80 shadow-[0_0_8px_rgba(244,63,94,0.3)]';
      case 'analyst':
        return 'bg-cyan-950/80 text-cyan-300 border-cyan-800/80 shadow-[0_0_8px_rgba(6,182,212,0.3)]';
      case 'viewer':
      default:
        return 'bg-slate-800 text-slate-300 border-slate-700';
    }
  };

  return (
    <header className="border-b border-slate-800 bg-slate-900/80 backdrop-blur sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
        {/* Brand / Logo */}
        <div className="flex items-center space-x-6">
          <button
            onClick={() => onNavigate('dashboard')}
            className="flex items-center space-x-3 text-left focus:outline-none"
          >
            <div className="p-2 bg-cyan-950/80 border border-cyan-500/30 rounded-lg text-cyan-400 shadow-sm shadow-cyan-500/20">
              <Shield className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="text-xl font-bold tracking-tight text-white">CyberShield</span>
                <span className="text-[10px] font-semibold uppercase tracking-wider px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                  Phase 7 Engine
                </span>
              </div>
              <p className="text-xs text-slate-400 hidden sm:block">
                Defensive Security Monitoring Platform
              </p>
            </div>
          </button>

          {/* Navigation Links (when authenticated) */}
          {isAuthenticated && (
            <nav className="hidden md:flex items-center space-x-1 pl-4 border-l border-slate-800">
              <button
                onClick={() => onNavigate('dashboard')}
                className={`inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition ${
                  activeView === 'dashboard'
                    ? 'bg-slate-800 text-cyan-400 border border-slate-700'
                    : 'text-slate-300 hover:text-white hover:bg-slate-800/60'
                }`}
              >
                <Activity className="w-3.5 h-3.5" />
                <span>Dashboard</span>
              </button>

              <button
                onClick={() => onNavigate('findings')}
                className={`inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition ${
                  activeView === 'findings'
                    ? 'bg-slate-800 text-cyan-400 border border-slate-700'
                    : 'text-slate-300 hover:text-white hover:bg-slate-800/60'
                }`}
              >
                <Layers className="w-3.5 h-3.5" />
                <span>Findings Registry</span>
              </button>

              <button
                onClick={() => onNavigate('headers')}
                className={`inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition ${
                  activeView === 'headers'
                    ? 'bg-slate-800 text-cyan-400 border border-slate-700'
                    : 'text-slate-300 hover:text-white hover:bg-slate-800/60'
                }`}
              >
                <Globe className="w-3.5 h-3.5" />
                <span>Security Headers</span>
              </button>

              <button
                onClick={() => onNavigate('fim')}
                className={`inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition ${
                  activeView === 'fim'
                    ? 'bg-slate-800 text-cyan-400 border border-slate-700'
                    : 'text-slate-300 hover:text-white hover:bg-slate-800/60'
                }`}
              >
                <FileCheck2 className="w-3.5 h-3.5" />
                <span>File Integrity</span>
              </button>

              <button
                onClick={() => onNavigate('logs')}
                className={`inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition ${
                  activeView === 'logs'
                    ? 'bg-slate-800 text-cyan-400 border border-slate-700'
                    : 'text-slate-300 hover:text-white hover:bg-slate-800/60'
                }`}
              >
                <ScrollText className="w-3.5 h-3.5" />
                <span>Log Analyzer</span>
              </button>
            </nav>
          )}
        </div>

        {/* Right Action Bar */}
        <div className="flex items-center space-x-4">
          {/* Health Status Indicator */}
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
            <span className="text-slate-300 hidden sm:inline">
              {connectionState === 'online'
                ? 'Backend Online'
                : connectionState === 'offline'
                  ? 'Backend Offline'
                  : 'Connecting...'}
            </span>
          </div>

          {/* User Session / Auth Controls */}
          {isAuthenticated && user ? (
            <div className="flex items-center space-x-3 border-l border-slate-800 pl-4">
              <div className="flex items-center space-x-2 text-left">
                <div className="p-1.5 rounded-full bg-slate-800 text-slate-300">
                  <UserIcon className="w-3.5 h-3.5" />
                </div>
                <div className="hidden md:block">
                  <p className="text-xs font-medium text-white leading-tight">
                    {user.full_name || user.email}
                  </p>
                  <p className="text-[10px] text-slate-400 font-mono leading-tight">{user.email}</p>
                </div>
                {/* Role Badge */}
                <span
                  className={`text-[10px] font-mono font-semibold uppercase px-2 py-0.5 rounded border ${getRoleBadgeColor(
                    user.role,
                  )}`}
                >
                  {user.role}
                </span>
              </div>

              <button
                onClick={logout}
                title="Sign out of current session"
                className="p-1.5 rounded-lg text-slate-400 hover:text-rose-400 hover:bg-slate-800/80 transition flex items-center space-x-1"
              >
                <LogOut className="w-4 h-4" />
                <span className="text-xs hidden lg:inline">Sign Out</span>
              </button>
            </div>
          ) : (
            <div className="flex items-center space-x-2 border-l border-slate-800 pl-4">
              <button
                onClick={() => onNavigate('login')}
                className={`inline-flex items-center space-x-1 px-3 py-1.5 text-xs font-medium rounded-lg transition ${
                  activeView === 'login'
                    ? 'bg-cyan-600 text-white shadow-sm'
                    : 'bg-slate-800 hover:bg-slate-700 text-slate-200'
                }`}
              >
                <LogIn className="w-3.5 h-3.5" />
                <span>Sign In</span>
              </button>

              <button
                onClick={() => onNavigate('register')}
                className={`inline-flex items-center space-x-1 px-3 py-1.5 text-xs font-medium rounded-lg transition ${
                  activeView === 'register'
                    ? 'bg-cyan-600 text-white shadow-sm'
                    : 'bg-slate-800 hover:bg-slate-700 text-slate-200'
                }`}
              >
                <UserPlus className="w-3.5 h-3.5" />
                <span>Register</span>
              </button>
            </div>
          )}

          <div className="hidden xl:flex items-center space-x-1 text-xs text-slate-400 border-l border-slate-800 pl-4">
            <Lock className="w-3.5 h-3.5 text-cyan-400" />
            <span>Authorized Scope Only</span>
          </div>
        </div>
      </div>
    </header>
  );
};

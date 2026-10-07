import React from 'react';
import { useAuth } from './useAuth';
import { ShieldAlert, Lock, Loader2 } from 'lucide-react';

interface ProtectedRouteProps {
  children: React.ReactNode;
  onNavigateToLogin: () => void;
}

export const ProtectedRoute: React.FC<ProtectedRouteProps> = ({ children, onNavigateToLogin }) => {
  const { isAuthenticated, isLoading } = useAuth();

  if (isLoading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[50vh] space-y-4">
        <Loader2 className="w-8 h-8 text-cyan-400 animate-spin" />
        <p className="text-sm font-mono text-slate-400">Verifying session credentials...</p>
      </div>
    );
  }

  if (!isAuthenticated) {
    return (
      <div className="max-w-md mx-auto my-12 p-8 rounded-xl bg-slate-900/80 border border-slate-800 text-center shadow-2xl backdrop-blur">
        <div className="w-12 h-12 mx-auto rounded-full bg-rose-950/60 border border-rose-800/50 text-rose-400 flex items-center justify-center mb-4">
          <ShieldAlert className="w-6 h-6" />
        </div>
        <h2 className="text-xl font-bold text-white mb-2">Access Restricted</h2>
        <p className="text-sm text-slate-400 mb-6 leading-relaxed">
          The requested security dashboard and assessment modules require valid operator
          credentials. Please sign in to authenticate.
        </p>
        <button
          onClick={onNavigateToLogin}
          className="w-full inline-flex items-center justify-center space-x-2 py-2.5 px-4 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-medium text-sm transition shadow-lg shadow-cyan-600/20"
        >
          <Lock className="w-4 h-4" />
          <span>Authenticate Operator</span>
        </button>
      </div>
    );
  }

  return <>{children}</>;
};

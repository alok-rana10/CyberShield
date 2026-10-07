/**
 * CyberShield Frontend Type Definitions
 */

export interface HealthResponse {
  status: string;
  app: string;
}

export type ConnectionState = 'checking' | 'online' | 'offline';

export interface HealthCheckState {
  state: ConnectionState;
  app?: string;
  apiUrl: string;
  lastChecked?: string;
  latencyMs?: number;
  errorMessage?: string;
}

export type UserRole = 'admin' | 'analyst' | 'viewer';

export interface User {
  id: string;
  email: string;
  full_name: string | null;
  role: UserRole;
  is_active: boolean;
  created_at: string;
  last_login_at: string | null;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  user: User;
}

export interface LoginCredentials {
  email: string;
  password: string;
}

export interface RegisterCredentials {
  email: string;
  password: string;
  full_name?: string;
  role: 'analyst' | 'viewer';
}

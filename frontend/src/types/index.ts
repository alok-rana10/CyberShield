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

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

export type FindingSeverity = 'critical' | 'high' | 'medium' | 'low' | 'informational';
export type FindingStatus = 'open' | 'resolved' | 'accepted';

export interface SecurityFinding {
  id: string;
  user_id: string;
  source_module: string;
  title: string;
  description: string;
  severity: FindingSeverity;
  category: string;
  affected_resource?: string | null;
  remediation: string;
  evidence?: string | null;
  cwe_id?: string | null;
  status: FindingStatus;
  created_at: string;
  updated_at: string;
  resolved_at?: string | null;
}

export interface FindingListResponse {
  items: SecurityFinding[];
  total: number;
  page: number;
  size: number;
  pages: number;
}

export interface FindingFilterParams {
  page?: number;
  size?: number;
  severity?: string;
  status?: string;
  category?: string;
  source_module?: string;
  search?: string;
}

export interface FindingCreatePayload {
  title: string;
  description: string;
  severity: FindingSeverity;
  category?: string;
  source_module?: string;
  affected_resource?: string;
  remediation: string;
  evidence?: string;
  cwe_id?: string;
  status?: FindingStatus;
}

export interface FindingUpdatePayload {
  title?: string;
  description?: string;
  severity?: FindingSeverity;
  category?: string;
  affected_resource?: string;
  remediation?: string;
  evidence?: string;
  cwe_id?: string;
}

export interface FindingStatusUpdatePayload {
  status: FindingStatus;
  resolution_notes?: string;
}

export interface DashboardSummary {
  total_findings: number;
  severity_counts: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    informational: number;
  };
  status_counts: {
    open: number;
    resolved: number;
    accepted: number;
  };
  recent_findings: SecurityFinding[];
  by_category: Record<string, number>;
  by_source: Record<string, number>;
  posture_score: number;
}


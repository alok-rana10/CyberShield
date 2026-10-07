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

export interface HeaderAnalysisRequest {
  url: string;
  authorization_confirmed: boolean;
}

export interface HeaderEvaluationDetail {
  name: string;
  status: 'present' | 'missing' | 'weak';
  value: string | null;
  severity: string;
  description: string;
  recommendation: string;
}

export interface HeaderAnalysisResponse {
  id: string;
  target_url: string;
  final_url: string;
  status_code: number;
  analyzed_at: string;
  score: number;
  grade: string;
  headers_evaluated_count: number;
  headers_present_count: number;
  headers_missing_count: number;
  created_findings_count: number;
  details: HeaderEvaluationDetail[];
  created_finding_ids: string[];
}

export interface WebSecurityHistoryItem {
  id: string;
  target_url: string;
  status_code: number;
  grade: string;
  score: number;
  headers_evaluated_count: number;
  headers_present_count: number;
  headers_missing_count: number;
  created_findings_count: number;
  analyzed_at: string;
}

export type FIMRecordStatus = 'baseline' | 'unchanged' | 'modified' | 'added' | 'deleted';

export interface FIMBaselineRequest {
  path: string;
}

export interface FIMCheckRequest {
  path: string;
}

export interface FIMRecord {
  id: string;
  user_id: string;
  monitored_path: string;
  file_name: string;
  baseline_hash: string;
  current_hash?: string | null;
  file_size_bytes: number;
  status: FIMRecordStatus;
  file_modified_at?: string | null;
  last_verified_at?: string | null;
  created_at: string;
  updated_at: string;
}

export interface FIMBaselineResponse {
  path: string;
  files_baselined_count: number;
  total_size_bytes: number;
  created_at: string;
  records: FIMRecord[];
}

export interface FIMCheckResponse {
  path: string;
  checked_at: string;
  total_files: number;
  unchanged_count: number;
  modified_count: number;
  added_count: number;
  deleted_count: number;
  created_findings_count: number;
  created_finding_ids: string[];
  records: FIMRecord[];
}

export interface FIMStatusSummary {
  total_monitored_files: number;
  status_counts: Record<string, number>;
  allowed_roots: string[];
  last_check_at?: string | null;
}

export interface FIMRecordListResponse {
  items: FIMRecord[];
  total: number;
  page: number;
  size: number;
  pages: number;
}

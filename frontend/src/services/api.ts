import {
  DashboardSummary,
  FindingCreatePayload,
  FindingFilterParams,
  FindingListResponse,
  FindingStatusUpdatePayload,
  FindingUpdatePayload,
  HealthResponse,
  LoginCredentials,
  RegisterCredentials,
  SecurityFinding,
  TokenResponse,
  User,
  HeaderAnalysisRequest,
  HeaderAnalysisResponse,
  WebSecurityHistoryItem,
  FIMBaselineRequest,
  FIMBaselineResponse,
  FIMCheckRequest,
  FIMCheckResponse,
  FIMRecordListResponse,
  FIMStatusSummary,
  LogAnalysisRequest,
  LogAnalysisResponse,
  LogEventItem,
  LogEventListResponse,
  LogStatusSummary,
  ScanCreateRequest,
  ScanListResponse,
  ScanResponse,
  ScanScopeResponse,
  ScanSummaryResponse,
} from '../types';

const rawApiBase = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';
export const API_BASE_URL = rawApiBase.replace(/\/+$/, '');

/**
 * Helper to parse error details from API responses
 */
async function parseErrorDetail(response: Response): Promise<string> {
  // If session has expired or token is invalid on an authenticated request, broadcast unauthorized event
  if (
    response.status === 401 &&
    typeof window !== 'undefined' &&
    !(response.url || '').includes('/auth/login')
  ) {
    window.dispatchEvent(new CustomEvent('cybershield:unauthorized'));
  }

  try {
    const errorData = await response.json();
    if (typeof errorData.detail === 'string') {
      return errorData.detail;
    }
    if (Array.isArray(errorData.detail)) {
      return errorData.detail
        .map((err: { msg?: string }) => err.msg || 'Validation error')
        .join('; ');
    }
    return response.statusText || 'Request failed';
  } catch {
    return response.statusText || 'Request failed';
  }
}

/**
 * Fetch operational health status from backend /api/v1/health
 */
export async function getHealthStatus(): Promise<{
  data: HealthResponse | null;
  latencyMs: number;
  error?: string;
}> {
  const startTime = performance.now();
  try {
    const response = await fetch(`${API_BASE_URL}/api/v1/health`, {
      method: 'GET',
      headers: {
        Accept: 'application/json',
      },
    });

    const latencyMs = Math.round(performance.now() - startTime);

    if (!response.ok) {
      return {
        data: null,
        latencyMs,
        error: `HTTP ${response.status}: ${response.statusText}`,
      };
    }

    const data: HealthResponse = await response.json();
    return { data, latencyMs };
  } catch (err: unknown) {
    const latencyMs = Math.round(performance.now() - startTime);
    const message = err instanceof Error ? err.message : 'Network unreachable';
    return {
      data: null,
      latencyMs,
      error: message,
    };
  }
}

/**
 * Authenticate with email and password via POST /api/v1/auth/login
 */
export async function loginApi(credentials: LoginCredentials): Promise<TokenResponse> {
  const response = await fetch(`${API_BASE_URL}/api/v1/auth/login`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
    },
    body: JSON.stringify(credentials),
  });

  if (!response.ok) {
    const detail = await parseErrorDetail(response);
    throw new Error(detail);
  }

  return response.json();
}

/**
 * Register a new user via POST /api/v1/auth/register
 */
export async function registerApi(credentials: RegisterCredentials): Promise<User> {
  const response = await fetch(`${API_BASE_URL}/api/v1/auth/register`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
    },
    body: JSON.stringify(credentials),
  });

  if (!response.ok) {
    const detail = await parseErrorDetail(response);
    throw new Error(detail);
  }

  return response.json();
}

/**
 * Fetch the authenticated user's profile via GET /api/v1/auth/me
 */
export async function getMeApi(token: string): Promise<User> {
  const response = await fetch(`${API_BASE_URL}/api/v1/auth/me`, {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/json',
    },
  });

  if (!response.ok) {
    const detail = await parseErrorDetail(response);
    throw new Error(detail);
  }

  return response.json();
}

/**
 * Fetch aggregated dashboard metrics via GET /api/v1/dashboard/summary
 */
export async function getDashboardSummaryApi(token: string): Promise<DashboardSummary> {
  const response = await fetch(`${API_BASE_URL}/api/v1/dashboard/summary`, {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/json',
    },
  });

  if (!response.ok) {
    const detail = await parseErrorDetail(response);
    throw new Error(detail);
  }

  return response.json();
}

/**
 * List paginated findings with filter parameters via GET /api/v1/findings
 */
export async function getFindingsApi(
  token: string,
  params: FindingFilterParams = {},
): Promise<FindingListResponse> {
  const searchParams = new URLSearchParams();
  if (params.page) searchParams.set('page', params.page.toString());
  if (params.size) searchParams.set('size', params.size.toString());
  if (params.severity) searchParams.set('severity', params.severity);
  if (params.status) searchParams.set('status', params.status);
  if (params.category) searchParams.set('category', params.category);
  if (params.source_module) searchParams.set('source_module', params.source_module);
  if (params.search) searchParams.set('search', params.search);

  const url = `${API_BASE_URL}/api/v1/findings${
    searchParams.toString() ? `?${searchParams.toString()}` : ''
  }`;

  const response = await fetch(url, {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/json',
    },
  });

  if (!response.ok) {
    const detail = await parseErrorDetail(response);
    throw new Error(detail);
  }

  return response.json();
}

/**
 * Fetch a single finding by ID via GET /api/v1/findings/{id}
 */
export async function getFindingByIdApi(token: string, id: string): Promise<SecurityFinding> {
  const response = await fetch(`${API_BASE_URL}/api/v1/findings/${id}`, {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/json',
    },
  });

  if (!response.ok) {
    const detail = await parseErrorDetail(response);
    throw new Error(detail);
  }

  return response.json();
}

/**
 * Create a new security finding via POST /api/v1/findings
 */
export async function createFindingApi(
  token: string,
  payload: FindingCreatePayload,
): Promise<SecurityFinding> {
  const response = await fetch(`${API_BASE_URL}/api/v1/findings`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
      Accept: 'application/json',
    },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    const detail = await parseErrorDetail(response);
    throw new Error(detail);
  }

  return response.json();
}

/**
 * Transition finding status via PATCH /api/v1/findings/{id}/status
 */
export async function updateFindingStatusApi(
  token: string,
  id: string,
  payload: FindingStatusUpdatePayload,
): Promise<SecurityFinding> {
  const response = await fetch(`${API_BASE_URL}/api/v1/findings/${id}/status`, {
    method: 'PATCH',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
      Accept: 'application/json',
    },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    const detail = await parseErrorDetail(response);
    throw new Error(detail);
  }

  return response.json();
}

/**
 * Update editable finding fields via PATCH /api/v1/findings/{id}
 */
export async function updateFindingApi(
  token: string,
  id: string,
  payload: FindingUpdatePayload,
): Promise<SecurityFinding> {
  const response = await fetch(`${API_BASE_URL}/api/v1/findings/${id}`, {
    method: 'PATCH',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
      Accept: 'application/json',
    },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    const detail = await parseErrorDetail(response);
    throw new Error(detail);
  }

  return response.json();
}

/**
 * Delete a finding permanently via DELETE /api/v1/findings/{id}
 */
export async function deleteFindingApi(token: string, id: string): Promise<void> {
  const response = await fetch(`${API_BASE_URL}/api/v1/findings/${id}`, {
    method: 'DELETE',
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/json',
    },
  });

  if (!response.ok) {
    const detail = await parseErrorDetail(response);
    throw new Error(detail);
  }
}

/**
 * Execute defensive web security header analysis via POST /api/v1/headers/analyze
 */
export async function analyzeHeadersApi(
  token: string,
  payload: HeaderAnalysisRequest,
): Promise<HeaderAnalysisResponse> {
  const response = await fetch(`${API_BASE_URL}/api/v1/headers/analyze`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
      Accept: 'application/json',
    },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    const detail = await parseErrorDetail(response);
    throw new Error(detail);
  }

  return response.json();
}

/**
 * Retrieve recent web security header assessments via GET /api/v1/headers/history
 */
export async function getHeaderHistoryApi(token: string): Promise<WebSecurityHistoryItem[]> {
  const response = await fetch(`${API_BASE_URL}/api/v1/headers/history`, {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/json',
    },
  });

  if (!response.ok) {
    const detail = await parseErrorDetail(response);
    throw new Error(detail);
  }

  return response.json();
}

/**
 * Create or update cryptographic baseline via POST /api/v1/fim/baselines
 */
export async function createFimBaselineApi(
  token: string,
  payload: FIMBaselineRequest,
): Promise<FIMBaselineResponse> {
  const response = await fetch(`${API_BASE_URL}/api/v1/fim/baselines`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
      Accept: 'application/json',
    },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    const detail = await parseErrorDetail(response);
    throw new Error(detail);
  }

  return response.json();
}

/**
 * Execute integrity check against baseline via POST /api/v1/fim/check
 */
export async function checkFimIntegrityApi(
  token: string,
  payload: FIMCheckRequest,
): Promise<FIMCheckResponse> {
  const response = await fetch(`${API_BASE_URL}/api/v1/fim/check`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
      Accept: 'application/json',
    },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    const detail = await parseErrorDetail(response);
    throw new Error(detail);
  }

  return response.json();
}

/**
 * Retrieve FIM status summary via GET /api/v1/fim/status
 */
export async function getFimStatusApi(token: string): Promise<FIMStatusSummary> {
  const response = await fetch(`${API_BASE_URL}/api/v1/fim/status`, {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/json',
    },
  });

  if (!response.ok) {
    const detail = await parseErrorDetail(response);
    throw new Error(detail);
  }

  return response.json();
}

/**
 * Retrieve paginated monitored file records via GET /api/v1/fim/records
 */
export async function getFimRecordsApi(
  token: string,
  params: { status?: string; path?: string; page?: number; size?: number } = {},
): Promise<FIMRecordListResponse> {
  const query = new URLSearchParams();
  if (params.status && params.status !== 'all') {
    query.set('status', params.status);
  }
  if (params.path && params.path.trim()) {
    query.set('path', params.path.trim());
  }
  if (params.page) {
    query.set('page', params.page.toString());
  }
  if (params.size) {
    query.set('size', params.size.toString());
  }

  const queryString = query.toString() ? `?${query.toString()}` : '';
  const response = await fetch(`${API_BASE_URL}/api/v1/fim/records${queryString}`, {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/json',
    },
  });

  if (!response.ok) {
    const detail = await parseErrorDetail(response);
    throw new Error(detail);
  }

  return response.json();
}

/**
 * Retrieve authorized monitoring roots via GET /api/v1/fim/roots
 */
export async function getFimRootsApi(token: string): Promise<{ allowed_roots: string[] }> {
  const response = await fetch(`${API_BASE_URL}/api/v1/fim/roots`, {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/json',
    },
  });

  if (!response.ok) {
    const detail = await parseErrorDetail(response);
    throw new Error(detail);
  }

  return response.json();
}

/**
 * Execute defensive log analysis via POST /api/v1/logs/analyze
 */
export async function analyzeLogsApi(
  token: string,
  payload: LogAnalysisRequest,
): Promise<LogAnalysisResponse> {
  const response = await fetch(`${API_BASE_URL}/api/v1/logs/analyze`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
      Accept: 'application/json',
    },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    const detail = await parseErrorDetail(response);
    throw new Error(detail);
  }

  return response.json();
}

/**
 * Fetch paginated normalized log events via GET /api/v1/logs/events
 */
export async function getLogEventsApi(
  token: string,
  params: {
    severity?: string;
    category?: string;
    source_type?: string;
    source_file?: string;
    search?: string;
    page?: number;
    size?: number;
  } = {},
): Promise<LogEventListResponse> {
  const query = new URLSearchParams();
  if (params.severity && params.severity !== 'all') {
    query.set('severity', params.severity);
  }
  if (params.category && params.category !== 'all') {
    query.set('category', params.category);
  }
  if (params.source_type && params.source_type !== 'all') {
    query.set('source_type', params.source_type);
  }
  if (params.source_file && params.source_file.trim()) {
    query.set('source_file', params.source_file.trim());
  }
  if (params.search && params.search.trim()) {
    query.set('search', params.search.trim());
  }
  if (params.page) {
    query.set('page', params.page.toString());
  }
  if (params.size) {
    query.set('size', params.size.toString());
  }

  const queryString = query.toString() ? `?${query.toString()}` : '';
  const response = await fetch(`${API_BASE_URL}/api/v1/logs/events${queryString}`, {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/json',
    },
  });

  if (!response.ok) {
    const detail = await parseErrorDetail(response);
    throw new Error(detail);
  }

  return response.json();
}

/**
 * Fetch a single log event by ID via GET /api/v1/logs/events/{id}
 */
export async function getLogEventByIdApi(token: string, id: string): Promise<LogEventItem> {
  const response = await fetch(`${API_BASE_URL}/api/v1/logs/events/${id}`, {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/json',
    },
  });

  if (!response.ok) {
    const detail = await parseErrorDetail(response);
    throw new Error(detail);
  }

  return response.json();
}

/**
 * Retrieve log summary metrics via GET /api/v1/logs/summary
 */
export async function getLogSummaryApi(token: string): Promise<LogStatusSummary> {
  const response = await fetch(`${API_BASE_URL}/api/v1/logs/summary`, {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/json',
    },
  });

  if (!response.ok) {
    const detail = await parseErrorDetail(response);
    throw new Error(detail);
  }

  return response.json();
}

/**
 * Retrieve configured authorized log roots via GET /api/v1/logs/roots
 */
export async function getLogRootsApi(token: string): Promise<{ allowed_roots: string[] }> {
  const response = await fetch(`${API_BASE_URL}/api/v1/logs/roots`, {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/json',
    },
  });

  if (!response.ok) {
    const detail = await parseErrorDetail(response);
    throw new Error(detail);
  }

  return response.json();
}

/**
 * Execute an authorized TCP network scan via POST /api/v1/scans
 */
export async function runNetworkScanApi(
  token: string,
  payload: ScanCreateRequest,
): Promise<ScanResponse> {
  const response = await fetch(`${API_BASE_URL}/api/v1/scans`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
      Accept: 'application/json',
    },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    const detail = await parseErrorDetail(response);
    throw new Error(detail);
  }

  return response.json();
}

/**
 * List paginated historical network scans via GET /api/v1/scans
 */
export async function getNetworkScansApi(
  token: string,
  page = 1,
  size = 20,
): Promise<ScanListResponse> {
  const params = new URLSearchParams({
    page: page.toString(),
    size: size.toString(),
  });

  const response = await fetch(`${API_BASE_URL}/api/v1/scans?${params.toString()}`, {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/json',
    },
  });

  if (!response.ok) {
    const detail = await parseErrorDetail(response);
    throw new Error(detail);
  }

  return response.json();
}

/**
 * Fetch a single scan by ID via GET /api/v1/scans/{id}
 */
export async function getNetworkScanByIdApi(token: string, id: string): Promise<ScanResponse> {
  const response = await fetch(`${API_BASE_URL}/api/v1/scans/${id}`, {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/json',
    },
  });

  if (!response.ok) {
    const detail = await parseErrorDetail(response);
    throw new Error(detail);
  }

  return response.json();
}

/**
 * Retrieve aggregated scan metrics via GET /api/v1/scans/summary
 */
export async function getNetworkScanSummaryApi(token: string): Promise<ScanSummaryResponse> {
  const response = await fetch(`${API_BASE_URL}/api/v1/scans/summary`, {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/json',
    },
  });

  if (!response.ok) {
    const detail = await parseErrorDetail(response);
    throw new Error(detail);
  }

  return response.json();
}

/**
 * Retrieve configured authorized scan scope via GET /api/v1/scans/scope
 */
export async function getNetworkScanScopeApi(token: string): Promise<ScanScopeResponse> {
  const response = await fetch(`${API_BASE_URL}/api/v1/scans/scope`, {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/json',
    },
  });

  if (!response.ok) {
    const detail = await parseErrorDetail(response);
    throw new Error(detail);
  }

  return response.json();
}


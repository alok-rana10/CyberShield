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
} from '../types';

const rawApiBase = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';
export const API_BASE_URL = rawApiBase.replace(/\/+$/, '');

/**
 * Helper to parse error details from API responses
 */
async function parseErrorDetail(response: Response): Promise<string> {
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

import {
  HealthResponse,
  LoginCredentials,
  RegisterCredentials,
  TokenResponse,
  User,
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
      return errorData.detail.map((err: { msg?: string }) => err.msg || 'Validation error').join('; ');
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

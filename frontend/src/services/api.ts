import { HealthResponse } from '../types';

const rawApiBase = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';
export const API_BASE_URL = rawApiBase.replace(/\/+$/, '');

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
        'Accept': 'application/json',
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

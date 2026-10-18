/**
 * API client for communicating with the WebVulnScanner FastAPI backend.
 * Provides typed, cancellation-safe methods with normalized error handling.
 */

import type {
  ApiErrorPayload,
  CheckMetadata,
  ScanCreateRequest,
  ScanResponse,
  ValidationErrorItem,
} from '../types/api';

/**
 * Standardized client error representing HTTP, network, or validation failures.
 */
export class ApiError extends Error {
  public readonly status: number;
  public readonly detail?: string;
  public readonly validationErrors?: ValidationErrorItem[];
  public readonly isNetworkError: boolean;
  public readonly isCancelled: boolean;

  constructor(params: {
    message: string;
    status: number;
    detail?: string;
    validationErrors?: ValidationErrorItem[];
    isNetworkError?: boolean;
    isCancelled?: boolean;
  }) {
    super(params.message);
    this.name = 'ApiError';
    this.status = params.status;
    this.detail = params.detail;
    this.validationErrors = params.validationErrors;
    this.isNetworkError = params.isNetworkError ?? false;
    this.isCancelled = params.isCancelled ?? false;
  }
}

/**
 * Resolve the API base URL from parameter or Vite environment variable.
 */
export function resolveApiBaseUrl(customBaseUrl?: string): string {
  if (customBaseUrl !== undefined) {
    return customBaseUrl.trim().replace(/\/+$/, '');
  }
  const envUrl = (import.meta.env?.VITE_API_BASE_URL as string | undefined)?.trim();
  return envUrl ? envUrl.replace(/\/+$/, '') : '';
}

/**
 * Options for API requests, supporting abort cancellation.
 */
export interface RequestOptions {
  signal?: AbortSignal;
}

/**
 * Configuration options for initializing the ApiClient.
 */
export interface ApiClientConfig {
  baseUrl?: string;
  fetchFn?: typeof fetch;
}

/**
 * Reusable HTTP client for WebVulnScanner backend endpoints.
 */
export class ApiClient {
  private readonly baseUrl: string;
  private readonly fetchImpl: typeof fetch;

  constructor(config?: ApiClientConfig) {
    this.baseUrl = resolveApiBaseUrl(config?.baseUrl);
    this.fetchImpl = config?.fetchFn ?? fetch.bind(globalThis);
  }

  /**
   * Internal helper to execute HTTP requests with robust error parsing and cancellation handling.
   */
  private async request<T>(
    endpoint: string,
    init: RequestInit,
    options?: RequestOptions,
  ): Promise<T> {
    const url = `${this.baseUrl}${endpoint}`;
    let response: Response;

    try {
      response = await this.fetchImpl(url, {
        ...init,
        signal: options?.signal,
      });
    } catch (err: unknown) {
      if (err instanceof DOMException && err.name === 'AbortError') {
        throw new ApiError({
          message: 'Request was cancelled.',
          status: 0,
          isCancelled: true,
        });
      }
      throw new ApiError({
        message: 'Network error: Unable to connect to backend server. Verify the service is running.',
        status: 0,
        isNetworkError: true,
      });
    }

    let responseData: unknown;
    const contentType = response.headers.get('content-type') || '';
    if (contentType.includes('application/json')) {
      try {
        responseData = await response.json();
      } catch {
        throw new ApiError({
          message: `Malformed JSON response from server (HTTP ${response.status}).`,
          status: response.status,
        });
      }
    } else {
      const text = await response.text();
      responseData = text ? { detail: text } : {};
    }

    if (!response.ok) {
      this.handleErrorResponse(response.status, responseData);
    }

    return responseData as T;
  }

  /**
   * Parse error payloads and throw normalized ApiError instances.
   */
  private handleErrorResponse(status: number, data: unknown): never {
    const errorPayload = (typeof data === 'object' && data !== null ? data : {}) as ApiErrorPayload;
    const rawDetail = errorPayload.detail;

    if (Array.isArray(rawDetail)) {
      const validationErrors = rawDetail;
      const first = validationErrors[0];
      const field = first?.loc?.filter((seg) => seg !== 'body').join('.');
      const msg = first ? `${field ? `${field}: ` : ''}${first.msg}` : 'Validation error';

      throw new ApiError({
        message: msg,
        status,
        detail: JSON.stringify(validationErrors),
        validationErrors,
      });
    }

    const detailString = typeof rawDetail === 'string' ? rawDetail : undefined;

    if (status === 400) {
      throw new ApiError({
        message: detailString || 'Invalid request parameters.',
        status,
        detail: detailString,
      });
    }

    if (status === 422) {
      throw new ApiError({
        message: detailString || 'Target address or request parameters violate security policy.',
        status,
        detail: detailString,
      });
    }

    if (status === 504) {
      throw new ApiError({
        message: detailString || 'Scan execution timed out against target host.',
        status,
        detail: detailString,
      });
    }

    if (status === 500) {
      throw new ApiError({
        message: 'An internal error occurred during scan execution.',
        status,
        detail: detailString,
      });
    }

    if (status >= 500) {
      throw new ApiError({
        message: detailString || `Server error (HTTP ${status}).`,
        status,
        detail: detailString,
      });
    }

    throw new ApiError({
      message: detailString || `Request failed with HTTP ${status}.`,
      status,
      detail: detailString,
    });
  }

  /**
   * Fetch registered security checks from GET /api/v1/checks.
   */
  public async getChecks(options?: RequestOptions): Promise<CheckMetadata[]> {
    return this.request<CheckMetadata[]>('/api/v1/checks', {
      method: 'GET',
      headers: {
        Accept: 'application/json',
      },
    }, options);
  }

  /**
   * Submit a target URL for scanning via POST /api/v1/scans.
   */
  public async submitScan(
    payload: ScanCreateRequest,
    options?: RequestOptions,
  ): Promise<ScanResponse> {
    return this.request<ScanResponse>('/api/v1/scans', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify(payload),
    }, options);
  }

  /**
   * Verify backend service readiness via GET /api/v1/health.
   */
  public async checkHealth(
    options?: RequestOptions,
  ): Promise<{ status: string; app: string; version: string }> {
    return this.request<{ status: string; app: string; version: string }>(
      '/api/v1/health',
      {
        method: 'GET',
        headers: {
          Accept: 'application/json',
        },
      },
      options,
    );
  }
}

/**
 * Default singleton instance configured with the active environment's API base URL.
 */
export const apiClient = new ApiClient();

/**
 * Type definitions for WebVulnScanner API integration.
 * Derived strictly from backend Pydantic schemas and models.
 */

/**
 * Vulnerability severity levels produced by scanner checks.
 */
export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

/**
 * Terminal and transitional lifecycle status of a vulnerability scan.
 */
export type ScanStatus =
  | 'pending'
  | 'running'
  | 'completed'
  | 'partial'
  | 'failed'
  | 'cancelled';

/**
 * Metadata describing an available security check registered in the default registry.
 */
export interface CheckMetadata {
  check_id: string;
  name: string;
  description: string;
  severity: Severity;
}

/**
 * Validated vulnerability finding observed during a scan session.
 */
export interface Finding {
  check_id: string;
  title: string;
  severity: Severity;
  url: string;
  evidence: string;
  recommendation: string;
  timestamp: string;
  extra_data?: Record<string, unknown>;
}

/**
 * Payload sent to POST /api/v1/scans to initiate a scan session.
 */
export interface ScanCreateRequest {
  target_url: string;
  check_ids?: string[] | null;
  max_requests?: number;
  timeout_seconds?: number;
  max_concurrency?: number;
}

/**
 * Structured scan result returned by POST /api/v1/scans.
 */
export interface ScanResponse {
  target_url: string;
  status: ScanStatus;
  findings: Finding[];
  executed_checks: string[];
  check_errors: Record<string, string>;
  total_requests: number;
  start_time: string | null;
  end_time: string | null;
  duration_seconds: number;
}

/**
 * Individual field validation error returned by FastAPI / Pydantic.
 */
export interface ValidationErrorItem {
  loc: (string | number)[];
  msg: string;
  type: string;
}

/**
 * Raw error payload returned by FastAPI on 4xx/5xx responses.
 */
export interface ApiErrorPayload {
  detail?: string | ValidationErrorItem[];
}

import React from 'react';
import type { ScanResponse, ScanStatus } from '../types/api';

interface ScanSummaryProps {
  scanResult: ScanResponse | null;
  totalChecksAvailable: number;
}

export const ScanSummary: React.FC<ScanSummaryProps> = ({
  scanResult,
  totalChecksAvailable,
}) => {
  if (!scanResult) {
    return (
      <section
        className="scan-summary-empty card"
        data-testid="scan-summary-empty"
        aria-label="Scan Summary"
      >
        <div className="empty-state-content">
          <svg
            className="empty-icon"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
            aria-hidden="true"
          >
            <circle cx="12" cy="12" r="10" />
            <line x1="12" y1="8" x2="12" y2="12" />
            <line x1="12" y1="16" x2="12.01" y2="16" />
          </svg>
          <h3 className="empty-title">Ready for Security Assessment</h3>
          <p className="empty-description">
            Submit an authorized target URL above to evaluate security headers, HTTPS posture, cookie attributes, and CORS policies.
          </p>
        </div>
      </section>
    );
  }

  const formatStatus = (status: ScanStatus): { label: string; className: string } => {
    switch (status) {
      case 'completed':
        return { label: 'Completed', className: 'status-completed' };
      case 'partial':
        return { label: 'Partial Success', className: 'status-partial' };
      case 'failed':
        return { label: 'Scan Failed', className: 'status-failed' };
      case 'running':
        return { label: 'Running', className: 'status-running' };
      case 'cancelled':
        return { label: 'Cancelled', className: 'status-cancelled' };
      default:
        return { label: status, className: 'status-pending' };
    }
  };

  const statusInfo = formatStatus(scanResult.status);
  const findingsCount = scanResult.findings.length;
  const checksCount = scanResult.executed_checks.length;

  return (
    <section className="scan-summary" data-testid="scan-summary" aria-label="Scan Metrics Summary">
      <div className="summary-meta-bar">
        <div className="target-indicator">
          <span className="target-label">Target:</span>
          <code className="target-value" data-testid="summary-target-url" title={scanResult.target_url}>
            {scanResult.target_url}
          </code>
        </div>
        <div className={`scan-status-pill ${statusInfo.className}`} data-testid="summary-scan-status">
          <span className="status-dot" aria-hidden="true" />
          <span>{statusInfo.label}</span>
        </div>
      </div>

      <div className="metrics-grid">
        <div className="metric-card card" data-testid="metric-findings">
          <div className="metric-header">
            <span className="metric-title">Findings Identified</span>
            <svg
              className="metric-icon"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
              aria-hidden="true"
            >
              <polygon points="12 2 2 22 22 22 12 2" />
              <line x1="12" y1="9" x2="12" y2="13" />
              <line x1="12" y1="17" x2="12.01" y2="17" />
            </svg>
          </div>
          <div className="metric-value" data-testid="metric-findings-count">
            {findingsCount}
          </div>
          <span className="metric-subtext">
            {findingsCount === 0
              ? 'Defensive controls verified'
              : `${findingsCount} issue${findingsCount === 1 ? '' : 's'} to review`}
          </span>
        </div>

        <div className="metric-card card" data-testid="metric-requests">
          <div className="metric-header">
            <span className="metric-title">Total Requests</span>
            <svg
              className="metric-icon"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
              aria-hidden="true"
            >
              <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
            </svg>
          </div>
          <div className="metric-value" data-testid="metric-requests-count">
            {scanResult.total_requests}
          </div>
          <span className="metric-subtext">Passive HTTP probes</span>
        </div>

        <div className="metric-card card" data-testid="metric-duration">
          <div className="metric-header">
            <span className="metric-title">Duration</span>
            <svg
              className="metric-icon"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
              aria-hidden="true"
            >
              <circle cx="12" cy="12" r="10" />
              <polyline points="12 6 12 12 16 14" />
            </svg>
          </div>
          <div className="metric-value" data-testid="metric-duration-value">
            {scanResult.duration_seconds.toFixed(2)}s
          </div>
          <span className="metric-subtext">Total assessment time</span>
        </div>

        <div className="metric-card card" data-testid="metric-checks">
          <div className="metric-header">
            <span className="metric-title">Checks Executed</span>
            <svg
              className="metric-icon"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
              aria-hidden="true"
            >
              <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
              <polyline points="22 4 12 14.01 9 11.01" />
            </svg>
          </div>
          <div className="metric-value" data-testid="metric-checks-executed">
            {checksCount}
            <span className="metric-denominator"> / {totalChecksAvailable || checksCount}</span>
          </div>
          <span className="metric-subtext">Registered security modules</span>
        </div>
      </div>
    </section>
  );
};

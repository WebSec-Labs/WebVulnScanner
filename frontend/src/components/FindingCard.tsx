import React, { useState } from 'react';
import type { Finding } from '../types/api';
import { SeverityBadge } from './SeverityBadge';

interface FindingCardProps {
  finding: Finding;
  index: number;
}

export const FindingCard: React.FC<FindingCardProps> = ({ finding, index }) => {
  const [isExpanded, setIsExpanded] = useState(false);

  const formatTimestamp = (ts: string): string => {
    try {
      const date = new Date(ts);
      if (isNaN(date.getTime())) {
        return ts;
      }
      return date.toUTCString();
    } catch {
      return ts;
    }
  };

  const hasExtraData =
    finding.extra_data && Object.keys(finding.extra_data).length > 0;

  return (
    <article
      className={`finding-card card ${isExpanded ? 'expanded' : ''}`}
      data-testid={`finding-card-${index}`}
      aria-labelledby={`finding-title-${index}`}
    >
      <div className="finding-header">
        <div className="finding-title-section">
          <SeverityBadge severity={finding.severity} />
          <h4 id={`finding-title-${index}`} className="finding-title" data-testid="finding-title">
            {finding.title}
          </h4>
        </div>

        <button
          type="button"
          className="btn-toggle-details"
          onClick={() => setIsExpanded((prev) => !prev)}
          aria-expanded={isExpanded}
          aria-controls={`finding-details-${index}`}
          data-testid={`toggle-details-btn-${index}`}
        >
          <span>{isExpanded ? 'Hide Details' : 'View Details'}</span>
          <svg
            className={`chevron-icon ${isExpanded ? 'rotated' : ''}`}
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
            aria-hidden="true"
          >
            <polyline points="6 9 12 15 18 9" />
          </svg>
        </button>
      </div>

      <div className="finding-meta-row">
        <div className="meta-item">
          <span className="meta-label">Module:</span>
          <code className="meta-code" data-testid="finding-check-id">{finding.check_id}</code>
        </div>
        <div className="meta-item url-item">
          <span className="meta-label">URL:</span>
          <span className="meta-url" data-testid="finding-url" title={finding.url}>
            {finding.url}
          </span>
        </div>
      </div>

      {isExpanded && (
        <div
          id={`finding-details-${index}`}
          className="finding-details-drawer"
          data-testid={`finding-details-${index}`}
        >
          <div className="detail-block">
            <span className="detail-heading">Evidence Observed</span>
            <div className="evidence-box" data-testid="finding-evidence">
              {finding.evidence}
            </div>
          </div>

          <div className="detail-block">
            <span className="detail-heading">Remediation Guidance</span>
            <p className="recommendation-text" data-testid="finding-recommendation">
              {finding.recommendation}
            </p>
          </div>

          {hasExtraData && (
            <div className="detail-block">
              <span className="detail-heading">Structured Context</span>
              <pre className="extra-data-box" data-testid="finding-extra-data">
                {JSON.stringify(finding.extra_data, null, 2)}
              </pre>
            </div>
          )}

          <div className="detail-footer">
            <span className="timestamp-label">Detected:</span>
            <time dateTime={finding.timestamp} className="timestamp-value">
              {formatTimestamp(finding.timestamp)}
            </time>
          </div>
        </div>
      )}
    </article>
  );
};

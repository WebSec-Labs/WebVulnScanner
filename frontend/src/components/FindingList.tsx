import React, { useState } from 'react';
import type { Finding, Severity } from '../types/api';
import { FindingCard } from './FindingCard';

interface FindingListProps {
  findings: Finding[];
  checkErrors?: Record<string, string>;
  isScanCompleted: boolean;
}

type SeverityFilter = 'all' | Severity;

export const FindingList: React.FC<FindingListProps> = ({
  findings,
  checkErrors = {},
  isScanCompleted,
}) => {
  const [activeFilter, setActiveFilter] = useState<SeverityFilter>('all');

  if (!isScanCompleted) {
    return null;
  }

  const checkErrorEntries = Object.entries(checkErrors);

  // Filter calculations
  const filteredFindings =
    activeFilter === 'all'
      ? findings
      : findings.filter((f) => f.severity.toLowerCase() === activeFilter);

  const getCountBySeverity = (sev: SeverityFilter): number => {
    if (sev === 'all') return findings.length;
    return findings.filter((f) => f.severity.toLowerCase() === sev).length;
  };

  const highCount = getCountBySeverity('high');
  const mediumCount = getCountBySeverity('medium');
  const lowCount = getCountBySeverity('low');
  const infoCount = getCountBySeverity('info');

  return (
    <section
      className="findings-section"
      data-testid="findings-section"
      aria-labelledby="findings-section-title"
    >
      <div className="findings-header-row">
        <div>
          <h3 id="findings-section-title" className="section-title">
            Security Findings ({findings.length})
          </h3>
          <p className="section-subtitle">
            Passive security observations prioritized by severity.
          </p>
        </div>

        {findings.length > 0 && (
          <div className="severity-filter-group" role="group" aria-label="Filter findings by severity">
            <button
              type="button"
              className={`filter-btn ${activeFilter === 'all' ? 'active' : ''}`}
              onClick={() => setActiveFilter('all')}
              data-testid="filter-all"
            >
              All ({findings.length})
            </button>
            {highCount > 0 && (
              <button
                type="button"
                className={`filter-btn filter-high ${activeFilter === 'high' ? 'active' : ''}`}
                onClick={() => setActiveFilter('high')}
                data-testid="filter-high"
              >
                High ({highCount})
              </button>
            )}
            {mediumCount > 0 && (
              <button
                type="button"
                className={`filter-btn filter-medium ${activeFilter === 'medium' ? 'active' : ''}`}
                onClick={() => setActiveFilter('medium')}
                data-testid="filter-medium"
              >
                Medium ({mediumCount})
              </button>
            )}
            {lowCount > 0 && (
              <button
                type="button"
                className={`filter-btn filter-low ${activeFilter === 'low' ? 'active' : ''}`}
                onClick={() => setActiveFilter('low')}
                data-testid="filter-low"
              >
                Low ({lowCount})
              </button>
            )}
            {infoCount > 0 && (
              <button
                type="button"
                className={`filter-btn filter-info ${activeFilter === 'info' ? 'active' : ''}`}
                onClick={() => setActiveFilter('info')}
                data-testid="filter-info"
              >
                Info ({infoCount})
              </button>
            )}
          </div>
        )}
      </div>

      {/* Partial Check Errors Banner */}
      {checkErrorEntries.length > 0 && (
        <div className="partial-errors-alert" data-testid="partial-errors-alert" role="alert">
          <div className="alert-header">
            <svg
              className="alert-icon"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
              aria-hidden="true"
            >
              <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
              <line x1="12" y1="9" x2="12" y2="13" />
              <line x1="12" y1="17" x2="12.01" y2="17" />
            </svg>
            <strong>Partial Scan Execution Notice</strong>
          </div>
          <p className="alert-message">
            The following check modules encountered errors during execution:
          </p>
          <ul className="error-list">
            {checkErrorEntries.map(([checkId, errorMsg]) => (
              <li key={checkId} data-testid={`check-error-${checkId}`}>
                <code>{checkId}</code>: {errorMsg}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Findings List or Empty State */}
      {findings.length === 0 ? (
        <div className="findings-empty card" data-testid="findings-empty">
          <svg
            className="empty-icon success"
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
          <h4 className="empty-title">No Security Misconfigurations Detected</h4>
          <p className="empty-description">
            The target host responded with all evaluated defensive security controls in place. No passive header, HTTPS, cookie, or CORS weaknesses were observed.
          </p>
        </div>
      ) : filteredFindings.length === 0 ? (
        <div className="findings-empty card" data-testid="filtered-findings-empty">
          <p className="empty-description">
            No findings match the selected severity filter (<strong>{activeFilter.toUpperCase()}</strong>).
          </p>
          <button
            type="button"
            className="btn btn-secondary btn-sm"
            onClick={() => setActiveFilter('all')}
          >
            Reset Filter
          </button>
        </div>
      ) : (
        <div className="findings-cards-list" data-testid="findings-cards-list">
          {filteredFindings.map((finding, idx) => (
            <FindingCard key={`${finding.check_id}-${idx}`} finding={finding} index={idx} />
          ))}
        </div>
      )}
    </section>
  );
};

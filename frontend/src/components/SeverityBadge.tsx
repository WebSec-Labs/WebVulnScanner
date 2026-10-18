import React from 'react';
import type { Severity } from '../types/api';

interface SeverityBadgeProps {
  severity: Severity;
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({ severity }) => {
  const normalized = severity.toLowerCase() as Severity;

  return (
    <span
      className={`severity-badge severity-${normalized}`}
      data-testid={`severity-badge-${normalized}`}
    >
      <span className="severity-dot" aria-hidden="true" />
      <span className="severity-label">{normalized.toUpperCase()}</span>
    </span>
  );
};

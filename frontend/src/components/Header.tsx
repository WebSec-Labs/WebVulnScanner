import React from 'react';

export type ApiHealthStatus = 'checking' | 'connected' | 'offline';

interface HeaderProps {
  healthStatus: ApiHealthStatus;
  onRefreshHealth: () => void;
}

export const Header: React.FC<HeaderProps> = ({ healthStatus, onRefreshHealth }) => {
  return (
    <header className="main-header" data-testid="main-header">
      <div className="header-titles">
        <h1 className="header-title">Security Overview</h1>
        <p className="header-subtitle">
          Identify common web security misconfigurations with passive security checks.
        </p>
      </div>

      <div className="header-actions">
        <div
          className={`api-status-badge status-${healthStatus}`}
          data-testid="api-status-badge"
          aria-live="polite"
        >
          <span className="api-status-dot" aria-hidden="true" />
          <span className="api-status-text">
            {healthStatus === 'checking' && 'Checking API...'}
            {healthStatus === 'connected' && 'API Connected'}
            {healthStatus === 'offline' && 'API Offline'}
          </span>
          <button
            type="button"
            className="api-refresh-btn"
            onClick={onRefreshHealth}
            title="Recheck API connectivity"
            aria-label="Recheck API connectivity"
            data-testid="recheck-health-button"
          >
            ↻
          </button>
        </div>
      </div>
    </header>
  );
};

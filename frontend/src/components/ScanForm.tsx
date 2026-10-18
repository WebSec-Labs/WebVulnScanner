import React, { useState, useEffect, useRef } from 'react';
import type { CheckMetadata } from '../types/api';

interface ScanFormProps {
  checks: CheckMetadata[];
  isLoadingChecks: boolean;
  checksError?: string | null;
  onRetryChecks: () => void;
  isScanning: boolean;
  onSubmitScan: (params: { targetUrl: string; checkIds: string[] | null }) => void;
}

export const ScanForm: React.FC<ScanFormProps> = ({
  checks,
  isLoadingChecks,
  checksError,
  onRetryChecks,
  isScanning,
  onSubmitScan,
}) => {
  const [targetUrl, setTargetUrl] = useState('');
  const [selectedCheckIds, setSelectedCheckIds] = useState<string[]>([]);
  const [touched, setTouched] = useState(false);
  const [urlError, setUrlError] = useState<string | null>(null);

  const initializedRef = useRef(false);

  // Initialize selected checks once checks are loaded
  useEffect(() => {
    if (checks.length > 0 && !initializedRef.current) {
      setSelectedCheckIds(checks.map((c) => c.check_id));
      initializedRef.current = true;
    }
  }, [checks]);

  // Client-side URL validation
  const validateUrl = (url: string): string | null => {
    const trimmed = url.trim();
    if (!trimmed) {
      return 'Target URL is required.';
    }
    if (!/^https?:\/\//i.test(trimmed)) {
      return 'Target URL must begin with http:// or https://';
    }
    try {
      const parsed = new URL(trimmed);
      if (!parsed.hostname) {
        return 'Target URL must include a valid hostname.';
      }
    } catch {
      return 'Invalid URL format.';
    }
    return null;
  };

  const handleUrlChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const val = e.target.value;
    setTargetUrl(val);
    if (touched) {
      setUrlError(validateUrl(val));
    }
  };

  const handleUrlBlur = () => {
    setTouched(true);
    setUrlError(validateUrl(targetUrl));
  };

  const handleToggleCheck = (checkId: string) => {
    setSelectedCheckIds((prev) =>
      prev.includes(checkId) ? prev.filter((id) => id !== checkId) : [...prev, checkId]
    );
  };

  const handleSelectAll = () => {
    setSelectedCheckIds(checks.map((c) => c.check_id));
  };

  const handleClearAll = () => {
    setSelectedCheckIds([]);
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setTouched(true);
    const err = validateUrl(targetUrl);
    if (err) {
      setUrlError(err);
      return;
    }
    if (selectedCheckIds.length === 0) {
      return;
    }

    // If all checks are selected, pass null to trigger default full scan semantics on backend
    const checkIdsPayload =
      selectedCheckIds.length === checks.length ? null : selectedCheckIds;

    onSubmitScan({
      targetUrl: targetUrl.trim(),
      checkIds: checkIdsPayload,
    });
  };

  const isFormValid = !validateUrl(targetUrl) && selectedCheckIds.length > 0;

  return (
    <section className="scan-panel card" data-testid="scan-form-card" aria-labelledby="scan-panel-title">
      <div className="card-header">
        <h2 id="scan-panel-title" className="card-title">Start a Scan</h2>
        <p className="card-subtitle">
          Enter a target URL and choose the checks to perform.
        </p>
      </div>

      <form onSubmit={handleSubmit} noValidate className="scan-form">
        <div className="form-group">
          <label htmlFor="target-url-input" className="form-label">
            Target URL
          </label>
          <div className="input-with-button">
            <input
              id="target-url-input"
              type="url"
              className={`text-input ${touched && urlError ? 'input-error' : ''}`}
              placeholder="https://example.com"
              value={targetUrl}
              onChange={handleUrlChange}
              onBlur={handleUrlBlur}
              disabled={isScanning}
              aria-describedby={touched && urlError ? 'target-url-error' : 'target-url-hint'}
              aria-invalid={touched && urlError ? 'true' : 'false'}
              data-testid="target-url-input"
            />
            <button
              type="submit"
              className="btn btn-primary btn-run-scan"
              disabled={isScanning || !isFormValid}
              data-testid="run-scan-button"
            >
              {isScanning ? (
                <>
                  <span className="spinner" aria-hidden="true" />
                  <span>Scanning...</span>
                </>
              ) : (
                <>
                  <svg
                    className="btn-icon"
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="2"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    aria-hidden="true"
                  >
                    <polygon points="5 3 19 12 5 21 5 3" />
                  </svg>
                  <span>Run Scan</span>
                </>
              )}
            </button>
          </div>
          {touched && urlError ? (
            <p id="target-url-error" className="field-error" role="alert" data-testid="url-validation-error">
              {urlError}
            </p>
          ) : (
            <p id="target-url-hint" className="field-hint">
              Target must be a publicly accessible HTTP or HTTPS host. SSRF protection is strictly enforced.
            </p>
          )}
        </div>

        <div className="form-group checks-section">
          <div className="checks-header">
            <span className="form-label">Passive Security Checks</span>
            <div className="checks-actions">
              <button
                type="button"
                className="btn-text"
                onClick={handleSelectAll}
                disabled={isScanning || isLoadingChecks || checks.length === 0}
                data-testid="select-all-checks"
              >
                Select All
              </button>
              <span className="divider" aria-hidden="true">|</span>
              <button
                type="button"
                className="btn-text"
                onClick={handleClearAll}
                disabled={isScanning || isLoadingChecks || checks.length === 0}
                data-testid="clear-all-checks"
              >
                Clear
              </button>
            </div>
          </div>

          {isLoadingChecks && (
            <div className="checks-loading" data-testid="checks-loading">
              <span className="spinner" aria-hidden="true" />
              <span>Loading available checks from registry...</span>
            </div>
          )}

          {checksError && (
            <div className="checks-error" data-testid="checks-error">
              <span>Failed to load checks: {checksError}</span>
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={onRetryChecks}
                data-testid="retry-checks-button"
              >
                Retry
              </button>
            </div>
          )}

          {!isLoadingChecks && !checksError && (
            <div className="checks-grid" data-testid="checks-selector-grid">
              {checks.map((check) => {
                const isChecked = selectedCheckIds.includes(check.check_id);
                return (
                  <label
                    key={check.check_id}
                    className={`check-card ${isChecked ? 'selected' : ''}`}
                    htmlFor={`check-${check.check_id}`}
                    data-testid={`check-item-${check.check_id}`}
                  >
                    <input
                      id={`check-${check.check_id}`}
                      type="checkbox"
                      className="check-checkbox"
                      checked={isChecked}
                      onChange={() => handleToggleCheck(check.check_id)}
                      disabled={isScanning}
                      data-testid={`checkbox-${check.check_id}`}
                    />
                    <div className="check-details">
                      <div className="check-title-row">
                        <span className="check-name">{check.name}</span>
                        <span className={`check-severity-badge severity-${check.severity.toLowerCase()}`}>
                          {check.severity}
                        </span>
                      </div>
                      <p className="check-description">{check.description}</p>
                    </div>
                  </label>
                );
              })}
            </div>
          )}

          {selectedCheckIds.length === 0 && !isLoadingChecks && (
            <p className="field-warning" role="alert" data-testid="no-checks-warning">
              Please select at least one check to execute, or click Select All.
            </p>
          )}
        </div>

        <div className="form-footer-notice">
          <svg
            className="notice-icon"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
            aria-hidden="true"
          >
            <circle cx="12" cy="12" r="10" />
            <line x1="12" y1="16" x2="12" y2="12" />
            <line x1="12" y1="8" x2="12.01" y2="8" />
          </svg>
          <span>
            Authorized testing only. Evaluates passive response configuration without sending active attack payloads.
          </span>
        </div>
      </form>
    </section>
  );
};

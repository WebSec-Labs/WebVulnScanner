import { useState, useEffect, useCallback, useRef } from 'react';
import type { CheckMetadata, ScanResponse } from './types/api';
import { apiClient } from './services/api';
import { Header, type ApiHealthStatus } from './components/Header';
import { Sidebar, type NavItem } from './components/Sidebar';
import { ScanForm } from './components/ScanForm';
import { ScanSummary } from './components/ScanSummary';
import { FindingList } from './components/FindingList';
import './App.css';

export function App() {
  const [activeNav, setActiveNav] = useState<NavItem>('overview');
  const [isMobileSidebarOpen, setIsMobileSidebarOpen] = useState(false);

  // API connectivity state
  const [healthStatus, setHealthStatus] = useState<ApiHealthStatus>('checking');

  // Registry checks state
  const [checks, setChecks] = useState<CheckMetadata[]>([]);
  const [isLoadingChecks, setIsLoadingChecks] = useState(true);
  const [checksError, setChecksError] = useState<string | null>(null);

  // Scan execution state
  const [isScanning, setIsScanning] = useState(false);
  const [scanResult, setScanResult] = useState<ScanResponse | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);

  const scanFormRef = useRef<HTMLDivElement>(null);

  // 1. Health check verification
  const checkApiHealth = useCallback(async () => {
    try {
      await apiClient.checkHealth();
      setHealthStatus('connected');
    } catch {
      setHealthStatus('offline');
    }
  }, []);

  const handleRefreshHealth = useCallback(async () => {
    setHealthStatus('checking');
    await checkApiHealth();
  }, [checkApiHealth]);

  // 2. Fetch registered checks from backend
  const fetchChecks = useCallback(async () => {
    try {
      const data = await apiClient.getChecks();
      setChecks(data);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Unable to connect to registry';
      setChecksError(msg);
    } finally {
      setIsLoadingChecks(false);
    }
  }, []);

  const handleRetryChecks = useCallback(async () => {
    setIsLoadingChecks(true);
    setChecksError(null);
    await fetchChecks();
  }, [fetchChecks]);

  useEffect(() => {
    let ignore = false;

    apiClient
      .checkHealth()
      .then(() => {
        if (!ignore) setHealthStatus('connected');
      })
      .catch(() => {
        if (!ignore) setHealthStatus('offline');
      });

    apiClient
      .getChecks()
      .then((data) => {
        if (!ignore) {
          setChecks(data);
          setIsLoadingChecks(false);
        }
      })
      .catch((err: unknown) => {
        if (!ignore) {
          const msg = err instanceof Error ? err.message : 'Unable to connect to registry';
          setChecksError(msg);
          setIsLoadingChecks(false);
        }
      });

    return () => {
      ignore = true;
    };
  }, []);

  // 3. Submit scan handler
  const handleSubmitScan = async ({
    targetUrl,
    checkIds,
  }: {
    targetUrl: string;
    checkIds: string[] | null;
  }) => {
    setIsScanning(true);
    setScanError(null);

    try {
      const response = await apiClient.submitScan({
        target_url: targetUrl,
        check_ids: checkIds,
      });
      setScanResult(response);
    } catch (err: unknown) {
      const msg =
        err instanceof Error
          ? err.message
          : 'An unexpected error occurred during scan execution.';
      setScanError(msg);
    } finally {
      setIsScanning(false);
    }
  };

  const handleSelectNav = (nav: NavItem) => {
    setActiveNav(nav);
    setIsMobileSidebarOpen(false);
    if (nav === 'new-scan') {
      scanFormRef.current?.scrollIntoView({ behavior: 'smooth' });
    }
  };

  return (
    <div className="dashboard-layout" data-testid="dashboard-layout">
      {/* Top Mobile Bar */}
      <div className="mobile-header">
        <button
          type="button"
          className="mobile-menu-toggle"
          onClick={() => setIsMobileSidebarOpen((prev) => !prev)}
          aria-label="Toggle navigation menu"
          data-testid="mobile-menu-toggle"
        >
          <svg
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
            aria-hidden="true"
          >
            <line x1="3" y1="12" x2="21" y2="12" />
            <line x1="3" y1="6" x2="21" y2="6" />
            <line x1="3" y1="18" x2="21" y2="18" />
          </svg>
        </button>
        <span className="mobile-brand-title">WebVulnScanner</span>
      </div>

      {/* Sidebar Navigation */}
      <Sidebar
        activeNav={activeNav}
        onSelectNav={handleSelectNav}
        isOpen={isMobileSidebarOpen}
        onToggleMobile={() => setIsMobileSidebarOpen(false)}
      />

      {/* Main Workspace */}
      <main className="main-content" data-testid="main-content">
        <div className="workspace-container">
          <Header healthStatus={healthStatus} onRefreshHealth={handleRefreshHealth} />

          {/* Error Banner */}
          {scanError && (
            <div
              className="scan-error-banner card"
              data-testid="scan-error-banner"
              role="alert"
            >
              <div className="error-icon-wrapper" aria-hidden="true">
                <svg
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                >
                  <circle cx="12" cy="12" r="10" />
                  <line x1="12" y1="8" x2="12" y2="12" />
                  <line x1="12" y1="16" x2="12.01" y2="16" />
                </svg>
              </div>
              <div className="error-content">
                <h4 className="error-title">Scan Execution Notice</h4>
                <p className="error-message" data-testid="scan-error-message">{scanError}</p>
              </div>
              <button
                type="button"
                className="error-dismiss-btn"
                onClick={() => setScanError(null)}
                aria-label="Dismiss error notification"
                data-testid="dismiss-error-button"
              >
                ✕
              </button>
            </div>
          )}

          {/* Start a Scan Form */}
          <div ref={scanFormRef}>
            <ScanForm
              checks={checks}
              isLoadingChecks={isLoadingChecks}
              checksError={checksError}
              onRetryChecks={handleRetryChecks}
              isScanning={isScanning}
              onSubmitScan={handleSubmitScan}
            />
          </div>

          {/* Scan Execution Summary */}
          <ScanSummary
            scanResult={scanResult}
            totalChecksAvailable={checks.length}
          />

          {/* Scan Findings List */}
          <FindingList
            findings={scanResult?.findings ?? []}
            checkErrors={scanResult?.check_errors}
            isScanCompleted={scanResult !== null}
          />
        </div>
      </main>
    </div>
  );
}

export default App;

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import App from './App';
import { apiClient } from './services/api';
import type { CheckMetadata, ScanResponse } from './types/api';

const mockChecks: CheckMetadata[] = [
  {
    check_id: 'security_headers',
    name: 'Security Headers',
    description: 'Evaluates HTTP defensive headers',
    severity: 'low',
  },
  {
    check_id: 'cookie_security',
    name: 'Cookie Security',
    description: 'Evaluates cookie flags and attributes',
    severity: 'medium',
  },
  {
    check_id: 'https_configuration',
    name: 'HTTPS Configuration',
    description: 'Evaluates TLS and transport posture',
    severity: 'high',
  },
  {
    check_id: 'cors_security',
    name: 'CORS Security',
    description: 'Evaluates cross-origin resource sharing policies',
    severity: 'medium',
  },
];

const mockScanResponse: ScanResponse = {
  target_url: 'https://example.com/',
  status: 'completed',
  findings: [
    {
      check_id: 'security_headers',
      title: 'Missing Content-Security-Policy',
      severity: 'medium',
      url: 'https://example.com/',
      evidence: 'Header Content-Security-Policy is absent',
      recommendation: 'Configure a restrictive CSP policy',
      timestamp: '2026-10-17T20:00:00Z',
    },
    {
      check_id: 'https_configuration',
      title: 'Missing Strict-Transport-Security Header',
      severity: 'high',
      url: 'https://example.com/',
      evidence: 'Header Strict-Transport-Security is not returned',
      recommendation: 'Enforce HSTS with max-age >= 31536000',
      timestamp: '2026-10-17T20:00:00Z',
      extra_data: { header_missing: true },
    },
  ],
  executed_checks: [
    'security_headers',
    'cookie_security',
    'https_configuration',
    'cors_security',
  ],
  check_errors: {},
  total_requests: 1,
  start_time: '2026-10-17T20:00:00Z',
  end_time: '2026-10-17T20:00:01Z',
  duration_seconds: 1.25,
};

const mockComprehensiveFindingsResponse: ScanResponse = {
  ...mockScanResponse,
  findings: [
    {
      check_id: 'https_configuration',
      title: 'Missing Strict-Transport-Security Header',
      severity: 'high',
      url: 'https://example.com/',
      evidence: 'Header Strict-Transport-Security is not returned',
      recommendation: 'Enforce HSTS with max-age >= 31536000',
      timestamp: '2026-10-17T20:00:00Z',
    },
    {
      check_id: 'security_headers',
      title: 'Missing Content-Security-Policy',
      severity: 'medium',
      url: 'https://example.com/',
      evidence: 'Header Content-Security-Policy is absent',
      recommendation: 'Configure a restrictive CSP policy',
      timestamp: '2026-10-17T20:00:00Z',
    },
    {
      check_id: 'cookie_security',
      title: 'Cookie Missing SameSite Attribute',
      severity: 'low',
      url: 'https://example.com/',
      evidence: 'Set-Cookie: session=123; Secure; HttpOnly',
      recommendation: 'Specify SameSite=Lax or Strict',
      timestamp: '2026-10-17T20:00:00Z',
    },
    {
      check_id: 'cors_security',
      title: 'Informational CORS Configuration',
      severity: 'info',
      url: 'https://example.com/',
      evidence: 'Access-Control-Allow-Origin: * on static asset',
      recommendation: 'Verify intended exposure of static assets',
      timestamp: '2026-10-17T20:00:00Z',
    },
  ],
};

describe('WebVulnScanner UI Integration', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.spyOn(apiClient, 'checkHealth').mockResolvedValue({
      status: 'ok',
      app: 'WebVulnScanner',
      version: '0.1.0',
    });
    vi.spyOn(apiClient, 'getChecks').mockResolvedValue(mockChecks);
  });

  it('1. renders initial application layout, branding, and pre-scan state', async () => {
    render(<App />);

    expect(screen.getAllByText('WebVulnScanner')[0]).toBeInTheDocument();
    expect(screen.getByRole('heading', { level: 1, name: /Security Overview/i })).toBeInTheDocument();
    expect(screen.getByText('Authorized testing only')).toBeInTheDocument();
    expect(screen.getByTestId('scan-summary-empty')).toBeInTheDocument();
    expect(screen.getByText(/Ready for Security Assessment/i)).toBeInTheDocument();

    await waitFor(() => {
      expect(screen.getByTestId('api-status-badge')).toBeInTheDocument();
      expect(screen.getByText('API Connected')).toBeInTheDocument();
    });
  });

  it('2. successfully loads check metadata and populates check selector', async () => {
    render(<App />);

    await waitFor(() => {
      expect(screen.getByText('Security Headers')).toBeInTheDocument();
      expect(screen.getByText('Cookie Security')).toBeInTheDocument();
      expect(screen.getByText('HTTPS Configuration')).toBeInTheDocument();
      expect(screen.getByText('CORS Security')).toBeInTheDocument();
    });

    await waitFor(() => {
      const checkboxes = screen.getAllByRole('checkbox');
      expect(checkboxes.length).toBe(4);
      checkboxes.forEach((cb) => expect(cb).toBeChecked());
    });
  });

  it('3. handles failure to load check metadata with retry capability', async () => {
    vi.spyOn(apiClient, 'getChecks')
      .mockRejectedValueOnce(new Error('Network error: Unable to connect'))
      .mockResolvedValueOnce(mockChecks);

    render(<App />);

    await waitFor(() => {
      expect(screen.getByTestId('checks-error')).toBeInTheDocument();
      expect(screen.getByText(/Failed to load checks/i)).toBeInTheDocument();
    });

    const retryBtn = screen.getByTestId('retry-checks-button');
    fireEvent.click(retryBtn);

    await waitFor(() => {
      expect(screen.getByText('Security Headers')).toBeInTheDocument();
    });
  });

  it('4. performs client-side target URL validation', async () => {
    render(<App />);

    await waitFor(() => expect(screen.getByText('Security Headers')).toBeInTheDocument());

    const input = screen.getByTestId('target-url-input');
    const submitBtn = screen.getByTestId('run-scan-button');

    // Button disabled initially
    expect(submitBtn).toBeDisabled();

    // Invalid scheme
    fireEvent.change(input, { target: { value: 'ftp://example.com' } });
    fireEvent.blur(input);

    expect(screen.getByTestId('url-validation-error')).toHaveTextContent(
      'Target URL must begin with http:// or https://'
    );
    expect(submitBtn).toBeDisabled();

    // Valid URL
    fireEvent.change(input, { target: { value: 'https://example.com' } });
    expect(screen.queryByTestId('url-validation-error')).not.toBeInTheDocument();
    expect(submitBtn).toBeEnabled();
  });

  it('5. successfully submits scan and renders metrics summary', async () => {
    const submitSpy = vi.spyOn(apiClient, 'submitScan').mockResolvedValue(mockScanResponse);

    render(<App />);
    await waitFor(() => expect(screen.getByText('Security Headers')).toBeInTheDocument());

    const input = screen.getByTestId('target-url-input');
    fireEvent.change(input, { target: { value: 'https://example.com' } });

    const submitBtn = screen.getByTestId('run-scan-button');
    fireEvent.click(submitBtn);

    await waitFor(() => {
      expect(submitSpy).toHaveBeenCalledWith({
        target_url: 'https://example.com',
        check_ids: null, // Full scan semantics
      });
      expect(screen.getByTestId('scan-summary')).toBeInTheDocument();
    });

    // 6. Display of scan metrics
    expect(screen.getByTestId('metric-findings-count')).toHaveTextContent('2');
    expect(screen.getByTestId('metric-requests-count')).toHaveTextContent('1');
    expect(screen.getByTestId('metric-duration-value')).toHaveTextContent('1.25s');
    expect(screen.getByTestId('metric-checks-executed')).toHaveTextContent('4 / 4');
  });

  it('7. displays findings and allows expanding details', async () => {
    vi.spyOn(apiClient, 'submitScan').mockResolvedValue(mockScanResponse);

    render(<App />);
    await waitFor(() => expect(screen.getByText('Security Headers')).toBeInTheDocument());

    fireEvent.change(screen.getByTestId('target-url-input'), {
      target: { value: 'https://example.com' },
    });
    fireEvent.click(screen.getByTestId('run-scan-button'));

    await waitFor(() => {
      expect(screen.getByText('Missing Content-Security-Policy')).toBeInTheDocument();
      expect(screen.getByText('Missing Strict-Transport-Security Header')).toBeInTheDocument();
    });

    // Expand details
    const toggleBtn = screen.getByTestId('toggle-details-btn-0');
    expect(toggleBtn).toHaveAttribute('aria-expanded', 'false');
    fireEvent.click(toggleBtn);
    expect(toggleBtn).toHaveAttribute('aria-expanded', 'true');

    expect(screen.getByTestId('finding-evidence')).toHaveTextContent(
      'Header Content-Security-Policy is absent'
    );
    expect(screen.getByTestId('finding-recommendation')).toHaveTextContent(
      'Configure a restrictive CSP policy'
    );
  });

  it('8. filters findings by severity level', async () => {
    vi.spyOn(apiClient, 'submitScan').mockResolvedValue(mockScanResponse);

    render(<App />);
    await waitFor(() => expect(screen.getByText('Security Headers')).toBeInTheDocument());

    fireEvent.change(screen.getByTestId('target-url-input'), {
      target: { value: 'https://example.com' },
    });
    fireEvent.click(screen.getByTestId('run-scan-button'));

    await waitFor(() => {
      expect(screen.getByText('Missing Content-Security-Policy')).toBeInTheDocument();
    });

    // Click High filter
    const highFilterBtn = screen.getByTestId('filter-high');
    fireEvent.click(highFilterBtn);

    // Only High finding should remain visible
    expect(screen.getByText('Missing Strict-Transport-Security Header')).toBeInTheDocument();
    expect(screen.queryByText('Missing Content-Security-Policy')).not.toBeInTheDocument();

    // Click Medium filter
    const medFilterBtn = screen.getByTestId('filter-medium');
    fireEvent.click(medFilterBtn);

    expect(screen.getByText('Missing Content-Security-Policy')).toBeInTheDocument();
    expect(screen.queryByText('Missing Strict-Transport-Security Header')).not.toBeInTheDocument();
  });

  it('9. displays empty-findings state when scan identifies zero weaknesses', async () => {
    const zeroFindingsResponse: ScanResponse = {
      ...mockScanResponse,
      findings: [],
    };
    vi.spyOn(apiClient, 'submitScan').mockResolvedValue(zeroFindingsResponse);

    render(<App />);
    await waitFor(() => expect(screen.getByText('Security Headers')).toBeInTheDocument());

    fireEvent.change(screen.getByTestId('target-url-input'), {
      target: { value: 'https://secure-target.com' },
    });
    fireEvent.click(screen.getByTestId('run-scan-button'));

    await waitFor(() => {
      expect(screen.getByTestId('findings-empty')).toBeInTheDocument();
      expect(screen.getByText(/No Security Misconfigurations Detected/i)).toBeInTheDocument();
    });
  });

  it('10. displays partial check errors alert when scan encounters module errors', async () => {
    const partialResponse: ScanResponse = {
      ...mockScanResponse,
      status: 'partial',
      check_errors: {
        https_configuration: 'TLS handshake timeout during check execution',
      },
    };
    vi.spyOn(apiClient, 'submitScan').mockResolvedValue(partialResponse);

    render(<App />);
    await waitFor(() => expect(screen.getByText('Security Headers')).toBeInTheDocument());

    fireEvent.change(screen.getByTestId('target-url-input'), {
      target: { value: 'https://example.com' },
    });
    fireEvent.click(screen.getByTestId('run-scan-button'));

    await waitFor(() => {
      expect(screen.getByTestId('partial-errors-alert')).toBeInTheDocument();
      expect(screen.getByTestId('check-error-https_configuration')).toHaveTextContent(
        'TLS handshake timeout during check execution'
      );
    });
  });

  it('11. displays user-safe error banner when scan API fails', async () => {
    vi.spyOn(apiClient, 'submitScan').mockRejectedValue(
      new Error('Target destination is prohibited by SSRF security policy')
    );

    render(<App />);
    await waitFor(() => expect(screen.getByText('Security Headers')).toBeInTheDocument());

    fireEvent.change(screen.getByTestId('target-url-input'), {
      target: { value: 'http://127.0.0.1' },
    });
    fireEvent.click(screen.getByTestId('run-scan-button'));

    await waitFor(() => {
      expect(screen.getByTestId('scan-error-banner')).toBeInTheDocument();
      expect(screen.getByTestId('scan-error-message')).toHaveTextContent(
        'Target destination is prohibited by SSRF security policy'
      );
    });

    // Dismiss error
    fireEvent.click(screen.getByTestId('dismiss-error-button'));
    expect(screen.queryByTestId('scan-error-banner')).not.toBeInTheDocument();
  });

  it('12. prevents duplicate submissions and displays loading state during scan', async () => {
    let resolveScan!: (value: ScanResponse) => void;
    const pendingScan = new Promise<ScanResponse>((res) => {
      resolveScan = res;
    });

    vi.spyOn(apiClient, 'submitScan').mockReturnValue(pendingScan);

    render(<App />);
    await waitFor(() => expect(screen.getByText('Security Headers')).toBeInTheDocument());

    fireEvent.change(screen.getByTestId('target-url-input'), {
      target: { value: 'https://example.com' },
    });

    const submitBtn = screen.getByTestId('run-scan-button');
    fireEvent.click(submitBtn);

    // Button should enter disabled loading state
    expect(submitBtn).toBeDisabled();
    expect(screen.getByText('Scanning...')).toBeInTheDocument();

    // Resolve scan
    resolveScan(mockScanResponse);

    await waitFor(() => {
      expect(screen.getByText('Run Scan')).toBeInTheDocument();
      expect(submitBtn).toBeEnabled();
    });
  });

  it('13. safely renders untrusted content without executing scripts', async () => {
    const xssPayloadResponse: ScanResponse = {
      ...mockScanResponse,
      findings: [
        {
          check_id: 'security_headers',
          title: '<img src=x onerror=alert(1)> Untrusted Title',
          severity: 'high',
          url: 'https://example.com/?q=<script>alert("xss")</script>',
          evidence: '<script>alert(document.cookie)</script>',
          recommendation: 'Sanitize <b>input</b>',
          timestamp: '2026-10-17T20:00:00Z',
        },
      ],
    };

    vi.spyOn(apiClient, 'submitScan').mockResolvedValue(xssPayloadResponse);

    render(<App />);
    await waitFor(() => expect(screen.getByText('Security Headers')).toBeInTheDocument());

    fireEvent.change(screen.getByTestId('target-url-input'), {
      target: { value: 'https://example.com' },
    });
    fireEvent.click(screen.getByTestId('run-scan-button'));

    await waitFor(() => {
      // Content rendered as pure text node, not HTML DOM elements
      const titleEl = screen.getByTestId('finding-title');
      expect(titleEl.textContent).toContain('<img src=x onerror=alert(1)> Untrusted Title');
      expect(document.querySelector('img[src="x"]')).toBeNull();
    });
  });

  it('14. supports select all and clear checks selector controls', async () => {
    render(<App />);
    await waitFor(() => expect(screen.getByText('Security Headers')).toBeInTheDocument());

    const clearBtn = screen.getByTestId('clear-all-checks');
    const selectAllBtn = screen.getByTestId('select-all-checks');
    const submitBtn = screen.getByTestId('run-scan-button');

    fireEvent.change(screen.getByTestId('target-url-input'), {
      target: { value: 'https://example.com' },
    });

    // Clear checks
    fireEvent.click(clearBtn);
    expect(screen.getByTestId('no-checks-warning')).toBeInTheDocument();
    expect(submitBtn).toBeDisabled();

    // Select All checks
    fireEvent.click(selectAllBtn);
    expect(screen.queryByTestId('no-checks-warning')).not.toBeInTheDocument();
    expect(submitBtn).toBeEnabled();
  });

  it('15. verifies health check indicator reflects connectivity status', async () => {
    vi.spyOn(apiClient, 'checkHealth').mockResolvedValue({
      status: 'ok',
      app: 'WebVulnScanner',
      version: '0.1.0',
    });

    render(<App />);

    await waitFor(() => {
      expect(screen.getByTestId('api-status-badge')).toHaveTextContent('API Connected');
    });

    // When health check fails
    vi.spyOn(apiClient, 'checkHealth').mockRejectedValue(new Error('Connection refused'));

    const recheckBtn = screen.getByTestId('recheck-health-button');
    fireEvent.click(recheckBtn);

    await waitFor(() => {
      expect(screen.getByTestId('api-status-badge')).toHaveTextContent('API Offline');
    });
  });

  it('16. deselecting one check submits only the remaining selected check IDs', async () => {
    const submitSpy = vi.spyOn(apiClient, 'submitScan').mockResolvedValue(mockScanResponse);

    render(<App />);
    await waitFor(() => expect(screen.getByText('Security Headers')).toBeInTheDocument());

    const input = screen.getByTestId('target-url-input');
    fireEvent.change(input, { target: { value: 'https://example.com' } });

    // Deselect cors_security
    const corsCheckbox = screen.getByTestId('checkbox-cors_security');
    fireEvent.click(corsCheckbox);
    expect(corsCheckbox).not.toBeChecked();

    const submitBtn = screen.getByTestId('run-scan-button');
    fireEvent.click(submitBtn);

    await waitFor(() => {
      expect(submitSpy).toHaveBeenCalledWith({
        target_url: 'https://example.com',
        check_ids: ['security_headers', 'cookie_security', 'https_configuration'],
      });
    });
  });

  it('17. opens and closes mobile navigation menu using accessible controls', async () => {
    render(<App />);
    await waitFor(() => expect(screen.getByText('Security Headers')).toBeInTheDocument());

    const sidebar = screen.getByTestId('app-sidebar');
    expect(sidebar).not.toHaveClass('open');

    // Open mobile menu
    const menuToggle = screen.getByRole('button', { name: /toggle navigation menu/i });
    fireEvent.click(menuToggle);
    expect(sidebar).toHaveClass('open');

    // Clicking backdrop closes menu
    const backdrop = document.querySelector('.sidebar-backdrop');
    expect(backdrop).toBeInTheDocument();
    fireEvent.click(backdrop!);
    expect(sidebar).not.toHaveClass('open');

    // Re-open and click nav item to close
    fireEvent.click(menuToggle);
    expect(sidebar).toHaveClass('open');

    const navOverview = screen.getByTestId('nav-overview');
    fireEvent.click(navOverview);
    expect(sidebar).not.toHaveClass('open');
  });

  it('18. filters findings by low and info severity levels', async () => {
    vi.spyOn(apiClient, 'submitScan').mockResolvedValue(mockComprehensiveFindingsResponse);

    render(<App />);
    await waitFor(() => expect(screen.getByText('Security Headers')).toBeInTheDocument());

    fireEvent.change(screen.getByTestId('target-url-input'), {
      target: { value: 'https://example.com' },
    });
    fireEvent.click(screen.getByTestId('run-scan-button'));

    await waitFor(() => {
      expect(screen.getByText('Cookie Missing SameSite Attribute')).toBeInTheDocument();
      expect(screen.getByText('Informational CORS Configuration')).toBeInTheDocument();
    });

    // Low filter
    const lowFilterBtn = screen.getByTestId('filter-low');
    fireEvent.click(lowFilterBtn);
    expect(screen.getByText('Cookie Missing SameSite Attribute')).toBeInTheDocument();
    expect(screen.queryByText('Missing Strict-Transport-Security Header')).not.toBeInTheDocument();
    expect(screen.queryByText('Missing Content-Security-Policy')).not.toBeInTheDocument();
    expect(screen.queryByText('Informational CORS Configuration')).not.toBeInTheDocument();

    // Info filter
    const infoFilterBtn = screen.getByTestId('filter-info');
    fireEvent.click(infoFilterBtn);
    expect(screen.getByText('Informational CORS Configuration')).toBeInTheDocument();
    expect(screen.queryByText('Missing Strict-Transport-Security Header')).not.toBeInTheDocument();
    expect(screen.queryByText('Missing Content-Security-Policy')).not.toBeInTheDocument();
    expect(screen.queryByText('Cookie Missing SameSite Attribute')).not.toBeInTheDocument();
  });
});

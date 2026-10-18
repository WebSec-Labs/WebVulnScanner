import { describe, it, expect, vi } from 'vitest';
import { ApiClient, ApiError, resolveApiBaseUrl } from './api';
import type { CheckMetadata, ScanResponse } from '../types/api';

describe('ApiClient', () => {
  const mockChecks: CheckMetadata[] = [
    {
      check_id: 'cookie_security',
      name: 'Cookie Security Check',
      description: 'Evaluates cookie security attributes',
      severity: 'medium',
    },
    {
      check_id: 'security_headers',
      name: 'Security Headers Check',
      description: 'Evaluates HTTP defensive headers',
      severity: 'low',
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
        evidence: 'No CSP header present',
        recommendation: 'Configure a restrictive CSP',
        timestamp: '2026-10-17T20:00:00Z',
      },
    ],
    executed_checks: ['cookie_security', 'security_headers'],
    check_errors: {},
    total_requests: 1,
    start_time: '2026-10-17T20:00:00Z',
    end_time: '2026-10-17T20:00:01Z',
    duration_seconds: 1.0,
  };

  describe('resolveApiBaseUrl', () => {
    it('strips trailing slashes from custom base URL', () => {
      expect(resolveApiBaseUrl('http://localhost:8000/')).toBe('http://localhost:8000');
      expect(resolveApiBaseUrl('http://localhost:8000///')).toBe('http://localhost:8000');
    });

    it('returns empty string when given empty or whitespace base URL', () => {
      expect(resolveApiBaseUrl('')).toBe('');
      expect(resolveApiBaseUrl('   ')).toBe('');
    });
  });

  describe('getChecks', () => {
    it('successfully fetches available checks with expected headers', async () => {
      const mockFetch = vi.fn().mockResolvedValue(
        new Response(JSON.stringify(mockChecks), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        })
      );

      const client = new ApiClient({ baseUrl: 'http://test-api', fetchFn: mockFetch });
      const result = await client.getChecks();

      expect(result).toEqual(mockChecks);
      expect(mockFetch).toHaveBeenCalledWith(
        'http://test-api/api/v1/checks',
        expect.objectContaining({
          method: 'GET',
          headers: { Accept: 'application/json' },
        })
      );
    });

    it('throws ApiError on HTTP 500 server error', async () => {
      const mockFetch = vi.fn().mockImplementation(() =>
        Promise.resolve(
          new Response(JSON.stringify({ detail: 'Internal error' }), {
            status: 500,
            headers: { 'Content-Type': 'application/json' },
          })
        )
      );

      const client = new ApiClient({ baseUrl: 'http://test-api', fetchFn: mockFetch });
      await expect(client.getChecks()).rejects.toThrow(ApiError);

      try {
        await client.getChecks();
      } catch (err) {
        expect(err).toBeInstanceOf(ApiError);
        const apiErr = err as ApiError;
        expect(apiErr.status).toBe(500);
        expect(apiErr.message).toBe('An internal error occurred during scan execution.');
      }
    });
  });

  describe('submitScan', () => {
    it('submits a scan request and returns serialized ScanResponse', async () => {
      const mockFetch = vi.fn().mockResolvedValue(
        new Response(JSON.stringify(mockScanResponse), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        })
      );

      const client = new ApiClient({ baseUrl: 'http://test-api', fetchFn: mockFetch });
      const result = await client.submitScan({
        target_url: 'https://example.com',
        check_ids: ['security_headers'],
      });

      expect(result).toEqual(mockScanResponse);
      expect(mockFetch).toHaveBeenCalledWith(
        'http://test-api/api/v1/scans',
        expect.objectContaining({
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Accept: 'application/json',
          },
          body: JSON.stringify({
            target_url: 'https://example.com',
            check_ids: ['security_headers'],
          }),
        })
      );
    });

    it('handles HTTP 400 bad request error', async () => {
      const mockFetch = vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ detail: 'Invalid target URL: Scheme ftp is not supported' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' },
        })
      );

      const client = new ApiClient({ baseUrl: 'http://test-api', fetchFn: mockFetch });

      await expect(
        client.submitScan({ target_url: 'ftp://example.com' })
      ).rejects.toMatchObject({
        status: 400,
        message: 'Invalid target URL: Scheme ftp is not supported',
      });
    });

    it('handles HTTP 422 SSRF prohibited destination error', async () => {
      const mockFetch = vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({ detail: 'Target destination is prohibited by SSRF security policy' }),
          {
            status: 422,
            headers: { 'Content-Type': 'application/json' },
          }
        )
      );

      const client = new ApiClient({ baseUrl: 'http://test-api', fetchFn: mockFetch });

      await expect(
        client.submitScan({ target_url: 'http://127.0.0.1' })
      ).rejects.toMatchObject({
        status: 422,
        message: 'Target destination is prohibited by SSRF security policy',
      });
    });

    it('handles HTTP 422 Pydantic validation error lists', async () => {
      const validationPayload = {
        detail: [
          {
            loc: ['body', 'target_url'],
            msg: 'String should have at most 2048 characters',
            type: 'string_too_long',
          },
        ],
      };

      const mockFetch = vi.fn().mockResolvedValue(
        new Response(JSON.stringify(validationPayload), {
          status: 422,
          headers: { 'Content-Type': 'application/json' },
        })
      );

      const client = new ApiClient({ baseUrl: 'http://test-api', fetchFn: mockFetch });

      try {
        await client.submitScan({ target_url: 'https://example.com' });
        expect.unreachable('Should have thrown ApiError');
      } catch (err) {
        expect(err).toBeInstanceOf(ApiError);
        const apiErr = err as ApiError;
        expect(apiErr.status).toBe(422);
        expect(apiErr.message).toBe('target_url: String should have at most 2048 characters');
        expect(apiErr.validationErrors).toBeDefined();
        expect(apiErr.validationErrors?.length).toBe(1);
      }
    });

    it('handles HTTP 504 gateway timeout error', async () => {
      const mockFetch = vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ detail: 'Scan execution timed out against target host' }), {
          status: 504,
          headers: { 'Content-Type': 'application/json' },
        })
      );

      const client = new ApiClient({ baseUrl: 'http://test-api', fetchFn: mockFetch });

      await expect(
        client.submitScan({ target_url: 'https://example.com' })
      ).rejects.toMatchObject({
        status: 504,
        message: 'Scan execution timed out against target host',
      });
    });
  });

  describe('checkHealth', () => {
    it('successfully queries the health endpoint', async () => {
      const mockHealth = { status: 'ok', app: 'WebVulnScanner', version: '0.1.0' };
      const mockFetch = vi.fn().mockResolvedValue(
        new Response(JSON.stringify(mockHealth), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        })
      );

      const client = new ApiClient({ baseUrl: 'http://test-api', fetchFn: mockFetch });
      const result = await client.checkHealth();

      expect(result).toEqual(mockHealth);
      expect(mockFetch).toHaveBeenCalledWith(
        'http://test-api/api/v1/health',
        expect.objectContaining({
          method: 'GET',
        })
      );
    });
  });

  describe('Error and Edge-Case Handling', () => {
    it('handles network failure (TypeError: Failed to fetch)', async () => {
      const mockFetch = vi.fn().mockRejectedValue(new TypeError('Failed to fetch'));

      const client = new ApiClient({ baseUrl: 'http://test-api', fetchFn: mockFetch });

      try {
        await client.getChecks();
        expect.unreachable('Should have thrown ApiError');
      } catch (err) {
        expect(err).toBeInstanceOf(ApiError);
        const apiErr = err as ApiError;
        expect(apiErr.status).toBe(0);
        expect(apiErr.isNetworkError).toBe(true);
        expect(apiErr.message).toContain('Network error');
      }
    });

    it('handles request cancellation via AbortSignal', async () => {
      const abortError = new DOMException('The user aborted a request.', 'AbortError');
      const mockFetch = vi.fn().mockRejectedValue(abortError);

      const client = new ApiClient({ baseUrl: 'http://test-api', fetchFn: mockFetch });
      const controller = new AbortController();

      try {
        await client.getChecks({ signal: controller.signal });
        expect.unreachable('Should have thrown ApiError');
      } catch (err) {
        expect(err).toBeInstanceOf(ApiError);
        const apiErr = err as ApiError;
        expect(apiErr.status).toBe(0);
        expect(apiErr.isCancelled).toBe(true);
        expect(apiErr.message).toBe('Request was cancelled.');
      }
    });

    it('handles malformed non-JSON response when content-type is application/json', async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        status: 200,
        ok: true,
        headers: new Headers({ 'Content-Type': 'application/json' }),
        json: () => Promise.reject(new SyntaxError('Unexpected token < in JSON at position 0')),
        text: () => Promise.resolve('<html>Error</html>'),
      });

      const client = new ApiClient({ baseUrl: 'http://test-api', fetchFn: mockFetch });

      await expect(client.getChecks()).rejects.toMatchObject({
        status: 200,
        message: expect.stringContaining('Malformed JSON response from server'),
      });
    });

    it('handles non-JSON error responses gracefully', async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        status: 502,
        ok: false,
        headers: new Headers({ 'Content-Type': 'text/plain' }),
        text: () => Promise.resolve('Bad Gateway'),
      });

      const client = new ApiClient({ baseUrl: 'http://test-api', fetchFn: mockFetch });

      await expect(client.getChecks()).rejects.toMatchObject({
        status: 502,
        message: 'Bad Gateway',
      });
    });
  });
});

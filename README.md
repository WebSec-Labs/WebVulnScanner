# WebVulnScanner

> A collaborative web application vulnerability assessment platform developed by **WebSec-Labs**.

---

## ⚠️ Authorized Use & Legal Disclaimer

**WebVulnScanner is designed and provided strictly for educational purposes and for assessing applications that the operator owns or has explicit, documented authorization to test.**

* Unauthorized scanning of third-party networks or web applications may violate computer crime laws (such as the Computer Fraud and Abuse Act in the United States and similar legal frameworks worldwide).
* The authors and maintainers accept no liability for misuse of this software.
* Scanning modules are subject to strict target-scope enforcement, request budgets, SSRF protections, safe redirect handling, and timeouts.
* **Active checks require explicit opt-in** (`active_checks_enabled: true`). Target authorization is **never** inferred from URLs or responses; users are strictly responsible for obtaining permission before running active checks.

---

## Current Development Status

> [!NOTE]
> **Phase 5: Crawler & Controlled Active Checks (Complete)**
> The core scanning architecture, bounded crawler, passive analysis checks, and controlled active-check framework are implemented and tested locally.
>
> * **Implemented**:
>   * Pre-flight SSRF protection, connection-time DNS IP pinning, and private/metadata IP blocking.
>   * Same-origin scope enforcement and per-hop redirect re-validation.
>   * Four passive security checks: `security_headers`, `cookie_security`, `cors_security`, and `https_configuration`.
>   * Bounded same-origin crawler (`BoundedCrawler`) with HTML link extraction and URL normalization.
>   * Multi-page scanner engine with per-page response reuse and concurrency bounding.
>   * Controlled active-check framework with sequential execution and shared request budget accounting.
>   * Two non-destructive active checks: `http_trace_method` (RFC 7231 reflection) and `http_options_method` (RFC 9110 method discovery).
>   * REST API (`POST /api/v1/scans`, `GET /api/v1/checks`) and interactive React dashboard.
> * **Planned for Future Phases**:
>   * Persistent database storage (PostgreSQL/SQLite) and scan history.
>   * User authentication and role-based access control (RBAC).
>   * Asynchronous background scan task queues (e.g. Celery / Redis).
>   * Additional active vulnerability evaluation modules.

---

## Technology Stack

### Backend
* **Language & Runtime**: Python 3.12+
* **Web Framework**: FastAPI
* **Data Validation & Settings**: Pydantic v2 & Pydantic-Settings
* **HTTP Client & Transport**: HTTPX (with connection-level IP pinning via HTTPCore)
* **ASGI Server**: Uvicorn
* **Testing**: pytest, pytest-asyncio, and HTTPX
* **Code Quality & Formatting**: Ruff

### Frontend
* **UI Framework**: React 19
* **Language**: TypeScript
* **Bundler & Dev Server**: Vite
* **Testing**: Vitest, React Testing Library, and jsdom
* **Linting & Types**: ESLint with TypeScript ESLint, `tsc`

### CI / CD & Repository
* **Version Control**: Git / GitHub
* **CI Workflows**: GitHub Actions (separate Backend and Frontend workflows)
* **License**: MIT License

---

## Project Structure

```text
WebVulnScanner/
├── .github/
│   └── workflows/
│       ├── backend-ci.yml       # Backend lint, format check, and pytest suite
│       └── frontend-ci.yml      # Frontend lint, typecheck, vitest, and build
├── backend/
│   ├── app/
│   │   ├── api/                 # Versioned API routes (/api/v1/scans, /api/v1/checks)
│   │   ├── core/                # Application configuration & logging
│   │   ├── scanner/             # Core scanning engine & security guardrails
│   │   │   ├── checks/          # Passive and controlled active checks
│   │   │   ├── crawler/         # Bounded same-origin crawler & link extractor
│   │   │   ├── check.py         # BaseCheck interface & ScanContext
│   │   │   ├── client.py        # SSRF-safe, DNS-pinned ScannerHttpClient
│   │   │   ├── engine.py        # ScannerEngine orchestrator
│   │   │   ├── models.py        # Finding, Severity, ScanConfig, ScanResult
│   │   │   ├── registry.py      # Deterministic check registries
│   │   │   └── scope.py         # TargetScope & SameOriginScopePolicy
│   │   ├── schemas/             # Pydantic API request & response schemas
│   │   └── main.py              # FastAPI application entrypoint
│   ├── tests/                   # Backend pytest test suite (264 tests)
│   ├── requirements.txt         # Backend Python dependencies
│   ├── pytest.ini               # Pytest configuration
│   └── .env.example             # Environment configuration template
├── frontend/
│   ├── src/                     # React application source code & test suites
│   │   ├── components/          # Dashboard & scan control components
│   │   ├── services/            # Typed API client & api.test.ts
│   │   ├── types/               # TypeScript interfaces
│   │   └── App.test.tsx         # UI integration test suite (31 tests)
│   ├── package.json             # Node package manifest and scripts
│   ├── package-lock.json        # Deterministic dependency lockfile
│   ├── vite.config.ts           # Vite configuration
│   └── .env.example             # Frontend environment template
├── docs/
│   └── architecture.md          # Architectural specification and threat model
├── CONTRIBUTING.md              # Contribution guidelines & branching model
├── LICENSE                      # MIT License
└── README.md                    # Project documentation
```

---

## Scanner Capabilities & API Parameters

### Registered Security Checks

#### Passive Checks (Default)
Passive checks analyze already-retrieved HTTP responses without issuing additional network probes:
* `security_headers`: Inspects defensive headers (CSP, HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy).
* `cookie_security`: Evaluates cookie security attributes (`Secure`, `HttpOnly`, `SameSite`, prefixing) while **completely discarding cookie values** to protect secrets.
* `cors_security`: Audits CORS configuration against arbitrary and null origins.
* `https_configuration`: Validates HTTPS usage, secure schemes, and unencrypted transmission risks.

#### Active Checks (Explicit Opt-In Required)
Active checks issue targeted, non-destructive diagnostic probes through the shared safe HTTP client:
* `http_trace_method`: Sends a single `TRACE` request with a diagnostic probe header to verify RFC 7231 reflection without claims of exploitable XST. (`Severity.LOW`)
* `http_options_method`: Sends a single `OPTIONS` request to discover advertised methods via the `Allow` header without assuming exploitability. (`Severity.INFO`)

### Scan Request Configuration (`POST /api/v1/scans`)

| Parameter | Type | Default | Bounds | Description |
|---|---|:---:|:---:|---|
| `target_url` | string | *required* | 1–2048 chars | Target URL to scan (http/https only) |
| `check_ids` | list[string] | `null` | max 50 items | Optional subset of check IDs. Defaults to all passive checks |
| `max_requests` | integer | `50` | 1–100 | Hard session limit on total HTTP requests (crawls, redirects, checks) |
| `timeout_seconds` | float | `10.0` | 1.0–30.0s | Maximum timeout per HTTP request |
| `max_concurrency` | integer | `5` | 1–10 | Maximum concurrent check tasks |
| `crawl_enabled` | boolean | `false` | true/false | Whether to discover and scan same-origin pages |
| `max_depth` | integer | `2` | 0–5 | Maximum crawl depth (0 scans target URL only) |
| `max_pages` | integer | `10` | 1–50 | Maximum same-origin pages to crawl and scan |
| `active_checks_enabled` | boolean | `false` | true/false | **Explicit authorization opt-in** to run active checks |

---

## Quickstart & Local Setup

### 1. Prerequisites
* Python 3.12 or newer
* Node.js 22 or newer (with `npm`)

### 2. Backend Setup
```bash
# Navigate to backend
cd backend

# Create and activate virtual environment
python -m venv .venv

# Windows (PowerShell):
.venv\Scripts\Activate.ps1
# Windows (cmd):
.venv\Scripts\activate.bat
# macOS / Linux:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run backend development server
uvicorn app.main:app --reload --port 8000
```
Interactive API documentation is available at [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs) and health status at [http://127.0.0.1:8000/health](http://127.0.0.1:8000/health).

### 3. Frontend Setup
```bash
# Navigate to frontend
cd frontend

# Install dependencies deterministically
npm ci

# Run frontend development server
npm run dev
```
The dashboard will be accessible at [http://localhost:5173](http://localhost:5173).

---

## Running Quality Checks

### Backend Checks
```bash
cd backend
pytest -v                  # Run unit & integration tests (264 tests)
ruff check .              # Lint codebase
ruff format --check .     # Verify code formatting
```

### Frontend Checks
```bash
cd frontend
npm test -- --run         # Run Vitest test suites (31 tests)
npm run lint              # Run ESLint
npx tsc -b                # Verify TypeScript type compilation
npm run build             # Build production bundle
```

---

## Contributing

Please review [CONTRIBUTING.md](file:///c:/Users/nethu/OneDrive/Desktop/WebVulnScanner/CONTRIBUTING.md) for branch naming conventions, testing expectations, and pull request procedures.

---

## License

This project is licensed under the MIT License - see the [`LICENSE`](file:///c:/Users/nethu/OneDrive/Desktop/WebVulnScanner/LICENSE) file for details.

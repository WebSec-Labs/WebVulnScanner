# WebVulnScanner

> A collaborative web application vulnerability scanner platform developed by **WebSec-Labs**.

---

## ⚠️ Authorized Use & Legal Disclaimer

**WebVulnScanner is designed and provided strictly for educational purposes and for assessing applications that the operator owns or has explicit, documented authorization to test.**

* Unauthorized scanning of third-party networks or web applications may violate computer crime laws (such as the CFAA in the United States and similar legal frameworks worldwide).
* The authors and maintainers accept no liability for misuse of this software.
* Scanning modules are subject to strict scope enforcement, rate limits, safe redirect handling, and request timeouts.

---

## Current Development Status

> [!NOTE]
> **Phase 1: Project Foundation (In Progress)**
> Currently, only the core architectural foundation, monorepo skeleton, health endpoint, basic landing page, quality linters, and CI pipelines are established.
> **No database, authentication system, crawler, or active scanning checks are implemented at this stage.**

---

## Technology Stack

### Backend
* **Language & Runtime**: Python 3.12+
* **Web Framework**: FastAPI
* **Data Validation & Settings**: Pydantic v2 & Pydantic-Settings
* **ASGI Server**: Uvicorn
* **Testing**: pytest, pytest-asyncio, and HTTPX
* **Code Quality & Formatting**: Ruff

### Frontend
* **UI Framework**: React 19
* **Language**: TypeScript
* **Bundler & Dev Server**: Vite
* **Testing**: Vitest, React Testing Library, and jsdom
* **Linting**: ESLint with TypeScript ESLint

### CI / CD & Repository
* **Version Control**: Git / GitHub
* **CI/CD Workflows**: GitHub Actions (separate Backend and Frontend workflows)
* **License**: MIT License

---

## Project Structure

```text
WebVulnScanner/
├── .github/
│   └── workflows/
│       ├── backend-ci.yml       # Backend linting & pytest execution
│       └── frontend-ci.yml      # Frontend lint, typecheck, vitest, and build
├── backend/
│   ├── app/
│   │   ├── api/                 # API routers and endpoints
│   │   ├── core/                # Settings and configuration
│   │   └── main.py              # FastAPI application entrypoint
│   ├── tests/                   # Pytest test suite
│   ├── requirements.txt         # Python dependencies
│   ├── pytest.ini               # Pytest configuration
│   └── .env.example             # Safe environment configuration template
├── frontend/
│   ├── src/                     # React application source code
│   ├── tests/                   # Vitest component test suite
│   ├── package.json             # Node package manifest and scripts
│   ├── vite.config.ts           # Vite configuration
│   └── .env.example             # Safe frontend environment template
├── docs/
│   └── architecture.md          # Architectural specification and threat model
├── CONTRIBUTING.md              # Contribution guidelines & branching model
├── LICENSE                      # MIT License
└── README.md                    # Project documentation
```

---

## Quickstart & Local Setup

### 1. Prerequisites
* Python 3.12 or newer
* Node.js 20 or newer (with `npm`)

### 2. Backend Setup
```bash
# Navigate to backend
cd backend

# Create and activate virtual environment
python -m venv .venv

# Windows:
.venv\Scripts\activate
# macOS / Linux:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run backend development server
uvicorn app.main:app --reload --port 8000
```
API Documentation will be available at [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs) and the health check at [http://127.0.0.1:8000/health](http://127.0.0.1:8000/health).

### 3. Frontend Setup
```bash
# Navigate to frontend
cd frontend

# Install dependencies
npm install

# Run frontend development server
npm run dev
```
The application will be accessible at [http://localhost:5173](http://localhost:5173).

---

## Running Quality Checks

### Backend Checks
```bash
cd backend
pytest -v                  # Run tests
ruff check .              # Lint codebase
ruff format --check .     # Verify code formatting
```

### Frontend Checks
```bash
cd frontend
npm test                  # Run unit & component tests
npm run lint              # Run ESLint
npx tsc -b                # Verify TypeScript types
npm run build             # Validate production bundle
```

---

## Contributing

Please review [CONTRIBUTING.md](file:///c:/Users/nethu/OneDrive/Desktop/WebVulnScanner/CONTRIBUTING.md) for branch naming conventions, testing expectations, and pull request procedures.

---

## License

This project is licensed under the MIT License - see the [`LICENSE`](file:///c:/Users/nethu/OneDrive/Desktop/WebVulnScanner/LICENSE) file for details.

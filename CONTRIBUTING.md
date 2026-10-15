# Contributing to WebVulnScanner

Thank you for your interest in contributing to **WebVulnScanner**! We welcome bug reports, feature proposals, documentation improvements, and pull requests.

## Code of Conduct & Ethical Guidelines

WebVulnScanner is developed solely for authorized security evaluations and educational purposes. Contributors must adhere to responsible disclosure principles and ethical security practices. Under no circumstances should automated scanning or attack capabilities targeting unauthorized third-party systems be introduced.

---

## Getting Started

### 1. Branching Strategy
* Always branch off of the `main` branch.
* Use descriptive branch names:
  * `feature/issue-description` for new functionality
  * `bugfix/issue-description` for bug fixes
  * `docs/topic-name` for documentation updates
  * `test/test-description` for testing improvements

### 2. Local Development

#### Backend (Python / FastAPI)
1. Navigate to the backend directory:
   ```bash
   cd backend
   ```
2. Create and activate a Python virtual environment:
   ```bash
   python -m venv .venv
   # On Windows:
   .venv\Scripts\activate
   # On Linux / macOS:
   source .venv/bin/activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Run tests and linting:
   ```bash
   pytest
   ruff check .
   ruff format --check .
   ```

#### Frontend (React / TypeScript / Vite)
1. Navigate to the frontend directory:
   ```bash
   cd frontend
   ```
2. Install dependencies:
   ```bash
   npm install
   ```
3. Run tests, linting, and build validation:
   ```bash
   npm test
   npm run lint
   npm run build
   ```

---

## Secrets and Sensitive Information

> [!WARNING]
> **Never commit secrets, API keys, credentials, or `.env` files.**
> Use `.env.example` templates with generic placeholder values. Pull requests containing sensitive credentials or tokens will be rejected immediately.

---

## Submitting Pull Requests

1. **Ensure all checks pass locally** before opening a PR:
   * Backend test suite: `pytest`
   * Backend linter: `ruff check .`
   * Frontend test suite: `npm test`
   * Frontend linter & type check: `npm run lint` and `tsc --noEmit`
2. **Write clear commit messages** explaining the rationale of the change.
3. **Open a Pull Request** against `main`:
   * Provide a concise summary of changes and reference any related issue numbers.
   * Verify that GitHub Actions CI workflows pass.
4. **Code Review**: At least one maintainer review is required before merging.

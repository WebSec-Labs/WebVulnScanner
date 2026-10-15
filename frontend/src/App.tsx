import { useState } from 'react'
import './App.css'

export function App() {
  const [activeTab, setActiveTab] = useState<'overview' | 'security' | 'architecture'>('overview')

  return (
    <div className="app-container">
      <header className="header">
        <div className="brand">
          <span className="brand-logo" role="img" aria-label="shield">🛡️</span>
          <div>
            <h1 className="brand-title">WebVulnScanner</h1>
            <p className="brand-subtitle">Web Application Vulnerability Assessment Platform</p>
          </div>
        </div>
        <div className="status-badge" data-testid="status-badge">
          <span className="status-dot"></span>
          <span>Phase 1: Foundation Ready</span>
        </div>
      </header>

      <nav className="nav-tabs" aria-label="Platform navigation">
        <button
          className={`tab-button ${activeTab === 'overview' ? 'active' : ''}`}
          onClick={() => setActiveTab('overview')}
          data-testid="tab-overview"
        >
          Overview
        </button>
        <button
          className={`tab-button ${activeTab === 'security' ? 'active' : ''}`}
          onClick={() => setActiveTab('security')}
          data-testid="tab-security"
        >
          Authorized Use Policy
        </button>
        <button
          className={`tab-button ${activeTab === 'architecture' ? 'active' : ''}`}
          onClick={() => setActiveTab('architecture')}
          data-testid="tab-architecture"
        >
          System Architecture
        </button>
      </nav>

      <main className="content-container">
        {activeTab === 'overview' && (
          <section className="tab-pane" data-testid="overview-pane">
            <div className="hero-banner">
              <h2>Defensive Security &amp; Assessment Engine</h2>
              <p>
                WebVulnScanner is a collaborative, modular security assessment platform built for web applications.
                Designed with strict safety boundaries, scope validation, and rate controls.
              </p>
            </div>

            <div className="grid-cards">
              <div className="card">
                <div className="card-icon">⚡</div>
                <h3>FastAPI Backend</h3>
                <p>
                  High-performance Python backend with Pydantic validation, structured logging, and health monitoring endpoints.
                </p>
                <div className="card-meta">
                  <code>/api/v1/health</code>
                </div>
              </div>

              <div className="card">
                <div className="card-icon">⚛️</div>
                <h3>React + TypeScript Frontend</h3>
                <p>
                  Built with Vite, modern TypeScript, Vitest testing, and component-driven architecture for clear finding reports.
                </p>
                <div className="card-meta">
                  <code>Vite + Vitest</code>
                </div>
              </div>

              <div className="card">
                <div className="card-icon">🔒</div>
                <h3>Strict Scope Enforcement</h3>
                <p>
                  Centralized scope validation prevents unauthorized target requests, private IP traversal (SSRF), and resource exhaustion.
                </p>
                <div className="card-meta">
                  <code>Planned for Phase 2</code>
                </div>
              </div>
            </div>
          </section>
        )}

        {activeTab === 'security' && (
          <section className="tab-pane" data-testid="security-pane">
            <div className="alert-box">
              <h3>⚠️ Legal &amp; Ethical Notice</h3>
              <p>
                This software is intended strictly for systems that the operator owns or has explicit, written permission to evaluate.
                Unauthorized vulnerability scanning or testing is strictly prohibited and may violate relevant computer crime laws.
              </p>
            </div>
            <div className="rules-list">
              <h4>Safety Guardrails in Core Design</h4>
              <ul>
                <li>Mandatory explicit target hostname and domain validation</li>
                <li>Hard prohibition of scanning localhost, private subnets (RFC 1918), or cloud metadata services</li>
                <li>Enforced request concurrency throttling, timeouts, and redirect caps</li>
              </ul>
            </div>
          </section>
        )}

        {activeTab === 'architecture' && (
          <section className="tab-pane" data-testid="architecture-pane">
            <div className="arch-card">
              <h3>Project Monorepo Layout</h3>
              <ul className="arch-list">
                <li><code>backend/</code>: FastAPI REST API, Pydantic schemas, and Pytest test suite</li>
                <li><code>frontend/</code>: React UI, Vite build pipeline, and Vitest test suite</li>
                <li><code>docs/</code>: Technical specifications, architecture docs, and threat models</li>
                <li><code>.github/workflows/</code>: Automated multi-stage GitHub Actions CI</li>
              </ul>
            </div>
          </section>
        )}
      </main>

      <footer className="footer">
        <p>WebVulnScanner • WebSec-Labs • Released under MIT License</p>
      </footer>
    </div>
  )
}

export default App

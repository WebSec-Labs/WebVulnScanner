import { describe, it, expect } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import App from './App'

describe('WebVulnScanner Landing Page', () => {
  it('renders the main brand heading and foundation status badge', () => {
    render(<App />)

    const titleElement = screen.getByRole('heading', { level: 1, name: /WebVulnScanner/i })
    expect(titleElement).toBeInTheDocument()

    const badge = screen.getByTestId('status-badge')
    expect(badge).toHaveTextContent(/Phase 1: Foundation Ready/i)
  })

  it('renders overview pane with architectural cards by default', () => {
    render(<App />)

    expect(screen.getByTestId('overview-pane')).toBeInTheDocument()
    expect(screen.getByRole('heading', { level: 3, name: /FastAPI Backend/i })).toBeInTheDocument()
    expect(screen.getByRole('heading', { level: 3, name: /React \+ TypeScript Frontend/i })).toBeInTheDocument()
    expect(screen.getByRole('heading', { level: 3, name: /Strict Scope Enforcement/i })).toBeInTheDocument()
  })

  it('switches to authorized use policy tab when clicked', () => {
    render(<App />)

    const policyTabButton = screen.getByTestId('tab-security')
    fireEvent.click(policyTabButton)

    expect(screen.getByTestId('security-pane')).toBeInTheDocument()
    expect(screen.getByText(/Legal & Ethical Notice/i)).toBeInTheDocument()
    expect(screen.getByText(/systems that the operator owns or has explicit, written permission/i)).toBeInTheDocument()
  })

  it('switches to system architecture tab when clicked', () => {
    render(<App />)

    const archTabButton = screen.getByTestId('tab-architecture')
    fireEvent.click(archTabButton)

    expect(screen.getByTestId('architecture-pane')).toBeInTheDocument()
    expect(screen.getByRole('heading', { level: 3, name: /Project Monorepo Layout/i })).toBeInTheDocument()
  })
})

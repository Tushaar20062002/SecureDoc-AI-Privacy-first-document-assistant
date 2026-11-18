import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('../services/api', async () => {
  const actual = await vi.importActual('../services/api')
  return {
    ...actual,
    documentsApi: { history: vi.fn(), chat: vi.fn() },
  }
})

import ChatPanel from '../components/ChatPanel'
import PermissionsForm from '../components/PermissionsForm'
import { validateFile } from '../pages/DashboardPage'
import { passwordProblems } from '../pages/RegisterPage'
import { documentsApi } from '../services/api'

const policy = {
  policy_version: '1.0',
  configurable_fields: [
    { key: 'name', label: 'Name', default: true },
    { key: 'phone', label: 'Phone number', default: false },
  ],
  fixed_restrictions: ['Aadhaar numbers', 'PAN'],
  consents: { external_ai_text: 'text consent', external_ai_images: 'image consent', privacy_policy: 'ack' },
  groq_configured: true,
}

describe('ChatPanel', () => {
  beforeEach(() => vi.clearAllMocks())

  it('loads history and sends a message', async () => {
    documentsApi.history.mockResolvedValue({ messages: [{ id: 1, role: 'assistant', content: 'Earlier answer' }] })
    documentsApi.chat.mockResolvedValue({
      user_message: { id: 2, role: 'user', content: 'What is my PAN?' },
      assistant_message: { id: 3, role: 'assistant', content: 'I’m sorry, but I cannot access…', kind: 'restricted' },
    })
    render(<ChatPanel documentId="doc1" />)
    expect(await screen.findByText('Earlier answer')).toBeInTheDocument()
    await userEvent.type(screen.getByLabelText('Your question'), 'What is my PAN?')
    await userEvent.click(screen.getByRole('button', { name: 'Send' }))
    expect(await screen.findByText(/cannot access/)).toBeInTheDocument()
    expect(screen.getByText('Protected information')).toBeInTheDocument()
    expect(documentsApi.chat).toHaveBeenCalledWith('doc1', 'What is my PAN?')
  })

  it('shows an error state and restores the input on failure', async () => {
    documentsApi.history.mockResolvedValue({ messages: [] })
    documentsApi.chat.mockRejectedValue({ response: { status: 500, data: { detail: 'Server failed' } } })
    render(<ChatPanel documentId="doc1" />)
    await userEvent.type(await screen.findByLabelText('Your question'), 'hello')
    await userEvent.click(screen.getByRole('button', { name: 'Send' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Server failed')
    expect(screen.getByLabelText('Your question')).toHaveValue('hello')
  })

  it('clears context when the document changes', async () => {
    documentsApi.history.mockImplementation((id) =>
      Promise.resolve({ messages: [{ id, role: 'assistant', content: `history of ${id}` }] }))
    const { rerender } = render(<ChatPanel key="a" documentId="a" />)
    expect(await screen.findByText('history of a')).toBeInTheDocument()
    rerender(<ChatPanel key="b" documentId="b" />)
    expect(await screen.findByText('history of b')).toBeInTheDocument()
    await waitFor(() => expect(screen.queryByText('history of a')).not.toBeInTheDocument())
  })
})

describe('PermissionsForm', () => {
  it('toggles fields and shows fixed restrictions as non-editable', async () => {
    const onChange = vi.fn()
    const value = { allowed_fields: { name: true, phone: false }, external_ai_text: false, external_ai_images: false, save_history: true }
    render(<MemoryRouter><PermissionsForm policy={policy} value={value} onChange={onChange} /></MemoryRouter>)
    expect(screen.getByText('Aadhaar numbers')).toBeInTheDocument()
    expect(screen.queryByRole('checkbox', { name: /Aadhaar/ })).not.toBeInTheDocument()
    expect(screen.getByLabelText(/ORIGINAL scanned page images/)).not.toBeChecked()
    await userEvent.click(screen.getByLabelText('Phone number'))
    expect(onChange).toHaveBeenCalledWith(expect.objectContaining({ allowed_fields: { name: true, phone: true } }))
  })
})

describe('client-side validation', () => {
  it('validates uploads', () => {
    expect(validateFile(null)).toMatch(/choose/)
    expect(validateFile({ name: 'a.txt', type: 'text/plain', size: 10 })).toMatch(/Only PDF/)
    expect(validateFile({ name: 'a.pdf', type: 'application/pdf', size: 11 * 1024 * 1024 })).toMatch(/10 MB/)
    expect(validateFile({ name: 'a.pdf', type: 'application/pdf', size: 1000 })).toBe('')
    // images are accepted (read by the consented vision AI on the server)
    expect(validateFile({ name: 'id.jpeg', type: 'image/jpeg', size: 1000 })).toBe('')
    expect(validateFile({ name: 'scan.png', type: 'image/png', size: 1000 })).toBe('')
    expect(validateFile({ name: 'card.webp', type: 'image/webp', size: 1000 })).toBe('')
    expect(validateFile({ name: 'a.gif', type: 'image/gif', size: 1000 })).toMatch(/Only PDF/)
  })
  it('checks password strength', () => {
    expect(passwordProblems('short')).toHaveLength(2)
    expect(passwordProblems('Str0ng!Passw0rd')).toHaveLength(0)
  })
})

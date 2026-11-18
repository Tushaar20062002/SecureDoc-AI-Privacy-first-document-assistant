import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import { errorMessage } from '../services/api'
import { Alert, Button, Spinner, inputClass } from '../components/ui'
import Icon from '../components/icons'
import { Logo } from '../components/Layout'

const TRUST_POINTS = [
  ['shield', 'Sensitive IDs masked on our server', 'Aadhaar, PAN, bank and card numbers never reach the AI provider.'],
  ['lock', 'Encrypted at rest', 'Stored details are protected with AES-256-GCM encryption.'],
  ['eye', 'You control what is shown', 'Choose which personal fields the assistant may display.'],
]

export function AuthShell({ title, subtitle, children }) {
  return (
    <div className="flex min-h-screen">
      <div className="hidden w-[44%] flex-col justify-between bg-gradient-to-br from-indigo-700 via-indigo-600 to-indigo-800 p-12 text-white lg:flex">
        <div className="flex items-center gap-2.5">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-white/15"><Icon name="shield" /></div>
          <span className="text-lg font-semibold">SecureDoc AI</span>
        </div>
        <div>
          <h2 className="text-3xl font-semibold leading-tight">Understand your documents.<br />Keep your identity private.</h2>
          <ul className="mt-8 space-y-5">
            {TRUST_POINTS.map(([icon, t, d]) => (
              <li key={t} className="flex gap-3">
                <div className="mt-0.5 rounded-lg bg-white/15 p-2"><Icon name={icon} className="h-4 w-4" /></div>
                <div><p className="text-sm font-medium">{t}</p><p className="text-sm text-indigo-100">{d}</p></div>
              </li>
            ))}
          </ul>
        </div>
        <p className="text-xs text-indigo-200">Processing follows the privacy preferences you set. Consent does not by itself imply legal compliance.</p>
      </div>
      <div className="flex flex-1 items-center justify-center px-4 py-12 sm:px-8">
        <div className="w-full max-w-sm">
          <div className="mb-8 lg:hidden"><Logo /></div>
          <h1 className="text-2xl font-semibold tracking-tight text-slate-900">{title}</h1>
          {subtitle && <p className="mt-1 text-sm text-slate-500">{subtitle}</p>}
          <div className="mt-8">{children}</div>
        </div>
      </div>
    </div>
  )
}

export function PasswordInput({ id, value, onChange, autoComplete }) {
  const [show, setShow] = useState(false)
  return (
    <div className="relative">
      <input id={id} type={show ? 'text' : 'password'} autoComplete={autoComplete} required
        className={`${inputClass} pr-10`} value={value} onChange={onChange} />
      <button type="button" onClick={() => setShow((s) => !s)}
        className="absolute inset-y-0 right-0 flex items-center px-3 text-slate-400 hover:text-slate-600"
        aria-label={show ? 'Hide password' : 'Show password'}>
        <Icon name={show ? 'eyeOff' : 'eye'} className="h-4 w-4" />
      </button>
    </div>
  )
}

export default function LoginPage() {
  const { login } = useAuth()
  const navigate = useNavigate()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  const submit = async (e) => {
    e.preventDefault()
    setError('')
    setBusy(true)
    try {
      const u = await login(email, password)
      navigate(u.onboarding_complete ? '/' : '/onboarding')
    } catch (err) {
      setError(errorMessage(err, 'Login failed.'))
    } finally {
      setBusy(false)
    }
  }

  return (
    <AuthShell title="Welcome back" subtitle="Sign in to access your documents.">
      <form onSubmit={submit} className="space-y-5">
        {error && <Alert>{error}</Alert>}
        <div>
          <label htmlFor="email" className="mb-1.5 block text-sm font-medium text-slate-700">Email address</label>
          <input id="email" type="email" autoComplete="email" required className={inputClass}
            value={email} onChange={(e) => setEmail(e.target.value)} />
        </div>
        <div>
          <label htmlFor="password" className="mb-1.5 block text-sm font-medium text-slate-700">Password</label>
          <PasswordInput id="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} />
        </div>
        <Button type="submit" className="w-full py-2.5" disabled={busy}>
          {busy && <Spinner />}{busy ? 'Signing in…' : 'Sign in'}
        </Button>
      </form>
      <p className="mt-6 text-center text-sm text-slate-500">
        New to SecureDoc AI? <Link to="/register" className="font-semibold text-indigo-600 hover:text-indigo-500">Create an account</Link>
      </p>
    </AuthShell>
  )
}

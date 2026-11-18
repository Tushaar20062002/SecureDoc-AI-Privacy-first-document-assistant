import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import { errorMessage } from '../services/api'
import { Alert, Button, Spinner, inputClass } from '../components/ui'
import { AuthShell, PasswordInput } from './LoginPage'

function PasswordStrength({ password }) {
  const rules = [
    ['10+ characters', password.length >= 10],
    ['Lowercase', /[a-z]/.test(password)],
    ['Uppercase', /[A-Z]/.test(password)],
    ['Number', /\d/.test(password)],
    ['Symbol', /[^A-Za-z0-9]/.test(password)],
  ]
  return (
    <ul className="mt-2 flex flex-wrap gap-x-3 gap-y-1 text-xs" aria-label="Password requirements">
      {rules.map(([label, ok]) => (
        <li key={label} className={ok ? 'text-emerald-600' : 'text-slate-400'}>{ok ? '✓' : '○'} {label}</li>
      ))}
      <li className="w-full text-slate-400">Needs 10+ characters and 3 of: lowercase, uppercase, number, symbol.</li>
    </ul>
  )
}

export function passwordProblems(pw) {
  const problems = []
  if (pw.length < 10) problems.push('at least 10 characters')
  const classes = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((r) => r.test(pw)).length
  if (classes < 3) problems.push('3 of: lowercase, uppercase, digit, symbol')
  return problems
}

export default function RegisterPage() {
  const { register } = useAuth()
  const navigate = useNavigate()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  const submit = async (e) => {
    e.preventDefault()
    setError('')
    const problems = passwordProblems(password)
    if (problems.length) return setError(`Password needs ${problems.join(' and ')}.`)
    if (password !== confirm) return setError('Passwords do not match.')
    setBusy(true)
    try {
      await register(email, password)
      navigate('/onboarding')
    } catch (err) {
      setError(errorMessage(err, 'Registration failed.'))
    } finally {
      setBusy(false)
    }
  }

  return (
    <AuthShell title="Create your account" subtitle="You'll set your privacy preferences next.">
      <form onSubmit={submit} className="space-y-5">
        {error && <Alert>{error}</Alert>}
        <div>
          <label htmlFor="email" className="mb-1.5 block text-sm font-medium text-slate-700">Email address</label>
          <input id="email" type="email" autoComplete="email" required className={inputClass}
            value={email} onChange={(e) => setEmail(e.target.value)} />
        </div>
        <div>
          <label htmlFor="password" className="mb-1.5 block text-sm font-medium text-slate-700">Password</label>
          <PasswordInput id="password" autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} />
          <PasswordStrength password={password} />
        </div>
        <div>
          <label htmlFor="confirm" className="mb-1.5 block text-sm font-medium text-slate-700">Confirm password</label>
          <PasswordInput id="confirm" autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} />
        </div>
        <Button type="submit" className="w-full py-2.5" disabled={busy}>
          {busy && <Spinner />}{busy ? 'Creating account…' : 'Create account'}
        </Button>
      </form>
      <p className="mt-6 text-center text-sm text-slate-500">
        Already have an account? <Link to="/login" className="font-semibold text-indigo-600 hover:text-indigo-500">Sign in</Link>
      </p>
    </AuthShell>
  )
}

import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import usePolicy from '../hooks/usePolicy'
import { errorMessage, privacyApi } from '../services/api'
import PermissionsForm, { initialPreferences } from '../components/PermissionsForm'
import { Alert, Button, Card, Spinner, Toggle } from '../components/ui'
import { Logo } from '../components/Layout'

export default function OnboardingPage() {
  const { policy, prefs, error: loadError } = usePolicy()
  const { refresh } = useAuth()
  const navigate = useNavigate()
  const [value, setValue] = useState(null)
  const [ack, setAck] = useState(false)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    if (policy && prefs) setValue(initialPreferences(policy, prefs))
  }, [policy, prefs])

  const submit = async () => {
    setError('')
    if (!ack) return setError('Please acknowledge the privacy notice to continue.')
    setBusy(true)
    try {
      await privacyApi.save({ ...value, accept_policy: true, policy_version: policy.policy_version })
      await refresh()
      navigate('/')
    } catch (e) {
      setError(errorMessage(e))
    } finally {
      setBusy(false)
    }
  }

  if (loadError) return <div className="p-8"><Alert>{loadError}</Alert></div>
  if (!policy || !value) return <div className="p-8 text-slate-500">Loading privacy options…</div>

  return (
    <div className="min-h-screen">
      <header className="border-b border-slate-200 bg-white">
        <div className="mx-auto flex max-w-3xl items-center justify-between px-4 py-4 sm:px-6"><Logo />
          <span className="text-xs font-medium text-slate-500">Step 2 of 2 · Privacy setup</span>
        </div>
      </header>
      <div className="mx-auto max-w-3xl space-y-6 px-4 py-8 sm:px-6">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-slate-900">Set your privacy preferences</h1>
          <p className="mt-1 text-sm text-slate-500">
            Choose how SecureDoc AI may process and show your information. You can change these at any time in
            Privacy &amp; Permissions. Policy version {policy.policy_version}.
          </p>
        </div>
        <PermissionsForm policy={policy} value={value} onChange={setValue} />
        <Card title="Privacy notice">
          <p className="mb-2 text-sm leading-relaxed text-slate-700">{policy.notice}</p>
          <Toggle id="ack" label={policy.consents.privacy_policy} checked={ack} onChange={setAck} />
        </Card>
        {error && <Alert>{error}</Alert>}
        <div className="flex justify-end">
          <Button onClick={submit} disabled={busy} className="px-6 py-2.5">
            {busy && <Spinner />}{busy ? 'Saving…' : 'Save and continue'}
          </Button>
        </div>
      </div>
    </div>
  )
}

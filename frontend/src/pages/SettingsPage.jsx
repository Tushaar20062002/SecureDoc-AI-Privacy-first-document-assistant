import { useEffect, useState } from 'react'
import usePolicy from '../hooks/usePolicy'
import { errorMessage, privacyApi } from '../services/api'
import PermissionsForm, { initialPreferences } from '../components/PermissionsForm'
import { Alert, Badge, Button, Card, ConfirmDialog, PageHeader, Skeleton, Spinner } from '../components/ui'

const prettyConsent = (t) =>
  t.replace('display_field:', 'Show field: ').replace(/_/g, ' ').replace(/^\w/, (c) => c.toUpperCase())

export default function SettingsPage() {
  const { policy, prefs, setPrefs, error: loadError } = usePolicy()
  const [value, setValue] = useState(null)
  const [msg, setMsg] = useState(null)
  const [busy, setBusy] = useState(false)
  const [consents, setConsents] = useState([])
  const [dialog, setDialog] = useState(null) // 'revoke' | 'deleteAll'

  useEffect(() => {
    if (policy && prefs) setValue(initialPreferences(policy, prefs))
  }, [policy, prefs])
  useEffect(() => { privacyApi.consents().then(setConsents).catch(() => {}) }, [prefs])

  const revoking = value && prefs
    ? Object.keys(value.allowed_fields).filter((k) => prefs.allowed_fields[k] && !value.allowed_fields[k])
    : []
  const dirty = value && prefs && JSON.stringify(value) !== JSON.stringify(initialPreferences(policy, prefs))

  const doSave = async () => {
    setDialog(null)
    setBusy(true)
    setMsg(null)
    try {
      const updated = await privacyApi.save({ ...value, accept_policy: true, policy_version: policy.policy_version })
      setPrefs(updated)
      setMsg({ kind: 'success', text: 'Preferences saved. Changes apply to all future processing and answers.' })
    } catch (e) {
      setMsg({ kind: 'error', text: errorMessage(e) })
    } finally {
      setBusy(false)
    }
  }

  const deleteAll = async () => {
    setDialog(null)
    try {
      const r = await privacyApi.deleteAllDocuments()
      setMsg({ kind: 'success', text: `${r.deleted} document(s) deleted.` })
    } catch (e) {
      setMsg({ kind: 'error', text: errorMessage(e) })
    }
  }

  if (loadError) return <Alert>{loadError}</Alert>
  if (!policy || !value) {
    return <div className="max-w-3xl space-y-4"><Skeleton className="h-8 w-64" /><Skeleton className="h-48" /><Skeleton className="h-48" /></div>
  }

  return (
    <div className="max-w-3xl pb-24">
      <PageHeader
        title="Privacy & Permissions"
        description={
          <span className="flex flex-wrap items-center gap-2">
            Policy version <Badge tone="indigo">v{prefs.policy_version}</Badge>
            {prefs.updated_at && <span className="text-slate-400">· last updated {new Date(prefs.updated_at).toLocaleString()}</span>}
          </span>
        }
      />

      <div className="space-y-6">
        <PermissionsForm policy={policy} value={value} onChange={setValue} />
        {prefs.save_history && !value.save_history && (
          <Alert kind="warning">
            With history off, newly uploaded documents (person details, masked PDF and chat) exist only while you are
            signed in and are deleted at logout or session expiry. Documents already saved are kept until you delete them.
          </Alert>
        )}
        {msg && <Alert kind={msg.kind}>{msg.text}</Alert>}

        <Card title="Danger zone" subtitle="Permanently remove everything stored for your account's documents.">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <p className="text-sm text-slate-600">Deletes all documents, masked outputs, stored person details and chat histories.</p>
            <Button variant="danger" icon="trash" onClick={() => setDialog('deleteAll')}>Delete all documents</Button>
          </div>
        </Card>

        <Card title="Consent history" subtitle="A versioned record of every consent you have given or withdrawn." padded={false}>
          {consents.length === 0 ? <p className="p-5 text-sm text-slate-500">No records.</p> : (
            <div className="max-h-72 overflow-auto">
              <table className="min-w-full text-left text-xs">
                <thead className="sticky top-0 bg-slate-50 font-medium uppercase tracking-wide text-slate-500">
                  <tr><th className="px-5 py-2.5">Consent</th><th className="px-3 py-2.5">Status</th><th className="px-3 py-2.5">Version</th><th className="px-3 py-2.5">Recorded</th><th className="px-5 py-2.5">Withdrawn</th></tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {consents.map((c, i) => (
                    <tr key={i}>
                      <td className="px-5 py-2 text-slate-700">{prettyConsent(c.consent_type)}</td>
                      <td className="px-3 py-2"><Badge tone={c.granted ? 'green' : 'slate'}>{c.granted ? 'Granted' : 'Declined'}</Badge></td>
                      <td className="px-3 py-2 text-slate-500">v{c.policy_version}</td>
                      <td className="whitespace-nowrap px-3 py-2 text-slate-500">{new Date(c.accepted_at).toLocaleString()}</td>
                      <td className="whitespace-nowrap px-5 py-2 text-slate-500">{c.revoked_at ? new Date(c.revoked_at).toLocaleString() : '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      </div>

      {dirty && (
        <div className="fixed inset-x-0 bottom-0 z-40 border-t border-slate-200 bg-white/95 backdrop-blur md:left-64">
          <div className="mx-auto max-w-7xl px-4 py-3 sm:px-6 lg:px-8">
          <div className="flex max-w-3xl items-center justify-between gap-3">
            <p className="text-sm text-slate-600">You have unsaved changes.</p>
            <div className="flex gap-2">
              <Button variant="secondary" onClick={() => setValue(initialPreferences(policy, prefs))}>Discard</Button>
              <Button onClick={() => (revoking.length ? setDialog('revoke') : doSave())} disabled={busy}>
                {busy && <Spinner />}Save preferences
              </Button>
            </div>
          </div>
          </div>
        </div>
      )}

      <ConfirmDialog open={dialog === 'revoke'} title="Withdraw field permissions?"
        message={`Turning off ${revoking.join(', ')} permanently deletes the retained original values for those fields from all your documents.`}
        confirmLabel="Save and delete" onConfirm={doSave} onCancel={() => setDialog(null)} />
      <ConfirmDialog open={dialog === 'deleteAll'} title="Delete all documents?"
        message="All documents, masked outputs, stored person details and chat histories will be permanently deleted. This cannot be undone."
        confirmLabel="Delete everything" onConfirm={deleteAll} onCancel={() => setDialog(null)} />
    </div>
  )
}

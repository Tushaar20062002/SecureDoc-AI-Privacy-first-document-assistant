import Icon from './icons'
import { Card, Toggle } from './ui'

/** Shared by onboarding and Settings → Privacy & Permissions. The backend enforces
 *  every rule; this form only collects the user's choices. */
export default function PermissionsForm({ policy, value, onChange }) {
  const set = (patch) => onChange({ ...value, ...patch })
  const setField = (key, v) => set({ allowed_fields: { ...value.allowed_fields, [key]: v } })

  return (
    <div className="space-y-6">
      <Card title="Always protected" subtitle="Masked, never stored in original form, never sent to AI and never revealed. Cannot be changed.">
        <ul className="grid gap-2 sm:grid-cols-2">
          {policy.fixed_restrictions.map((r) => (
            <li key={r} className="flex items-start gap-2 text-sm text-slate-700">
              <span className="mt-0.5 rounded-md bg-red-50 p-1 text-red-600"><Icon name="lock" className="h-3.5 w-3.5" /></span>
              {r}
            </li>
          ))}
        </ul>
        {policy.not_masked?.length > 0 && (
          <div className="mt-4 rounded-lg bg-slate-50 px-3 py-2.5 text-xs text-slate-600">
            <span className="font-medium text-slate-700">Not treated as sensitive (shown and processed as-is): </span>
            {policy.not_masked.join(', ')}.
          </div>
        )}
      </Card>

      <Card
        title="Fields the assistant may show you"
        subtitle="When enabled, the original value is stored encrypted (AES-256-GCM) and shown only to you after a server-side permission check. It is never sent to the external AI. Turning a field off permanently deletes its retained originals."
      >
        <div className="grid gap-x-8 divide-y divide-slate-100 sm:grid-cols-2 sm:divide-y-0">
          {policy.configurable_fields.map((f) => (
            <Toggle
              key={f.key}
              id={`field-${f.key}`}
              label={f.label}
              checked={value.allowed_fields[f.key]}
              onChange={(v) => setField(f.key, v)}
            />
          ))}
        </div>
      </Card>

      <Card title="AI processing & history" subtitle="Separate, optional consents. You can change them at any time.">
        <div className="divide-y divide-slate-100">
        <Toggle
          id="consent-text"
          label="Send document text to Groq (sensitive identifiers masked first)"
          description={policy.consents.external_ai_text}
          checked={value.external_ai_text}
          onChange={(v) => set({ external_ai_text: v })}
        />
        {!policy.groq_configured && (
          <p className="pb-3 text-xs text-amber-700">Groq is not configured on this server; local processing is used.</p>
        )}
        <div className="py-1">
          <div className="rounded-lg border border-amber-200 bg-amber-50/60 px-3">
            <Toggle
              id="consent-images"
              label="Send ORIGINAL scanned page images to the external vision AI"
              description={policy.consents.external_ai_images}
              checked={value.external_ai_images}
              onChange={(v) => set({ external_ai_images: v })}
            />
            <p className="flex items-center gap-1.5 pb-3 text-xs font-medium text-amber-800">
              <Icon name="alert" className="h-3.5 w-3.5" />
              Off by default. Without it, scanned pages are reported as unsupported and are never sent anywhere.
            </p>
          </div>
        </div>
        <Toggle
          id="consent-history"
          label="Save masked documents and chat history"
          description="If off, documents and chats are kept only until you log out or your session expires, then deleted."
          checked={value.save_history}
          onChange={(v) => set({ save_history: v })}
        />
        </div>
      </Card>
    </div>
  )
}

export function initialPreferences(policy, prefs) {
  const defaults = Object.fromEntries(policy.configurable_fields.map((f) => [f.key, f.default]))
  return {
    allowed_fields: { ...defaults, ...(prefs?.allowed_fields || {}) },
    external_ai_text: prefs?.external_ai_text ?? false,
    external_ai_images: prefs?.external_ai_images ?? false,
    save_history: prefs?.save_history ?? true,
  }
}

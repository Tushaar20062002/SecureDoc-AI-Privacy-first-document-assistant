import { useEffect, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { documentsApi, errorMessage } from '../services/api'
import ChatPanel from '../components/ChatPanel'
import Icon from '../components/icons'
import { Alert, Badge, Button, Card, ConfirmDialog, EmptyState, PageHeader, Skeleton, StatusBadge } from '../components/ui'
import { prettyType } from './DashboardPage'

const CATEGORY_LABELS = {
  AADHAAR: 'Aadhaar', PAN: 'PAN', PASSPORT: 'Passport', BANK_ACCOUNT: 'Bank account', IFSC: 'IFSC',
  CREDIT_CARD: 'Card', CVV: 'CVV', PASSWORD: 'Password', PIN: 'PIN', OTP: 'OTP', IP_ADDRESS: 'IP address',
  OTHER_ID: 'Other ID', PHONE: 'Phone', EMAIL: 'Email', PERSON: 'Name', ADDRESS: 'Address', DOB: 'Date of birth',
  APP_REF: 'Reference',
}

function PrivacySummary({ summary, entities }) {
  const rows = Object.entries(summary || {})
  const total = rows.reduce((n, [, c]) => n + c, 0)
  const review = (entities || []).filter((e) => e.needs_review).length
  return (
    <Card title="Privacy summary" subtitle="Values masked on the server before storage, AI processing and output.">
      {rows.length === 0 ? (
        <p className="text-sm text-slate-500">No sensitive identifiers were detected.</p>
      ) : (
        <>
          <div className="mb-3 flex items-center gap-2 text-sm text-slate-700">
            <span className="rounded-lg bg-emerald-50 p-1.5 text-emerald-600"><Icon name="shield" className="h-4 w-4" /></span>
            <span><b>{total}</b> sensitive value{total === 1 ? '' : 's'} masked</span>
          </div>
          <div className="flex flex-wrap gap-1.5">
            {rows.map(([cat, n]) => <Badge key={cat} tone="indigo">{CATEGORY_LABELS[cat] || cat} · {n}</Badge>)}
          </div>
        </>
      )}
      {review > 0 && <p className="mt-3 text-xs text-amber-700">{review} low-confidence detection(s) — please review the outputs.</p>}
    </Card>
  )
}

const ACRONYMS = new Set(['pan', 'ifsc', 'cvv', 'otp', 'pin', 'dob', 'id', 'upi', 'uan', 'gstin', 'ip', 'emi', 'ctc'])

/** "father_s_name" -> "Father's name", "pan_number" -> "PAN number" */
function prettyField(key) {
  const words = key.replace(/_s_/g, "'s_").split('_').filter(Boolean)
  return words
    .map((w, i) => (ACRONYMS.has(w) ? w.toUpperCase() : i === 0 ? w.charAt(0).toUpperCase() + w.slice(1) : w))
    .join(' ')
}

function FieldsTable({ fields }) {
  if (!fields?.length) {
    return <EmptyState icon="doc" title="No person details" description="No person details could be extracted from this document." />
  }
  return (
    <div className="max-h-[28rem] overflow-auto">
      <table className="min-w-full text-left text-sm">
        <thead className="sticky top-0 bg-slate-50 text-xs font-medium uppercase tracking-wide text-slate-500">
          <tr><th scope="col" className="px-5 py-2.5">Field</th><th scope="col" className="px-3 py-2.5">Value</th><th scope="col" className="px-5 py-2.5 text-right">Page</th></tr>
        </thead>
        <tbody className="divide-y divide-slate-100">
          {fields.map((f, i) => (
            <tr key={i} className="align-top">
              <td className="whitespace-nowrap px-5 py-2.5 font-medium text-slate-700">{prettyField(f.field)}</td>
              <td className="px-3 py-2.5">
                {f.masked ? (
                  <span className="inline-flex items-center gap-1.5 font-mono text-xs text-indigo-700">
                    <Icon name="lock" className="h-3.5 w-3.5" />{f.value}
                  </span>
                ) : <span className="text-slate-900">{f.value}</span>}
              </td>
              <td className="px-5 py-2.5 text-right text-xs text-slate-500">{f.page ?? '—'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export default function DocumentPage() {
  const { id } = useParams()
  const navigate = useNavigate()
  const [doc, setDoc] = useState(null)
  const [error, setError] = useState('')
  const [tab, setTab] = useState('table')
  const [confirm, setConfirm] = useState(false)

  useEffect(() => {
    setDoc(null)
    setError('')
    documentsApi.get(id).then(setDoc).catch((e) => setError(errorMessage(e, 'Document not found.')))
  }, [id])

  const back = (
    <Link to="/" className="mb-2 inline-flex items-center gap-1 text-xs font-medium text-slate-500 hover:text-slate-900">
      <Icon name="arrowLeft" className="h-3.5 w-3.5" /> All documents
    </Link>
  )

  if (error) {
    return (
      <div>
        <PageHeader title="Document" back={back} />
        <Card><EmptyState icon="alert" title="Document unavailable" description={error}
          action={<Link to="/"><Button variant="secondary">Back to documents</Button></Link>} /></Card>
      </div>
    )
  }
  if (!doc) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-8 w-72" /><Skeleton className="h-4 w-96" />
        <div className="grid gap-6 xl:grid-cols-2"><Skeleton className="h-80" /><Skeleton className="h-80" /></div>
      </div>
    )
  }
  const md = doc.masked_data || {}
  // Every review reason has a matching, more detailed warning; older documents may only have reasons.
  const notes = [...new Set(md.warnings?.length ? md.warnings : md.review_reasons || [])]

  const remove = async () => {
    setConfirm(false)
    await documentsApi.remove(doc.id)
    navigate('/')
  }

  return (
    <div>
      <PageHeader
        back={back}
        title={doc.document_name}
        description={
          <span className="flex flex-wrap items-center gap-2">
            <StatusBadge status={doc.processing_status} />
            <span>{prettyType(doc.document_type)}</span><span aria-hidden>·</span>
            <span>{doc.page_count} page{doc.page_count === 1 ? '' : 's'}</span><span aria-hidden>·</span>
            <span>{md.extraction_method === 'groq' ? 'AI extraction' : 'Local extraction'}</span>
            {!doc.retained && <Badge>Kept for this session only</Badge>}
          </span>
        }
        actions={
          <>
            {doc.has_pdf ? (
              <a href={documentsApi.pdfUrl(doc.id)}><Button icon="download">Masked PDF</Button></a>
            ) : (
              <Button variant="secondary" disabled title={doc.output_mode === 'json_only' ? 'JSON-only mode' : 'Masked PDF unavailable'}>
                {doc.output_mode === 'json_only' ? 'JSON-only mode' : 'PDF unavailable'}
              </Button>
            )}
            <a href={documentsApi.jsonUrl(doc.id)}><Button variant="secondary" icon="download">JSON</Button></a>
            <Button variant="ghost" icon="trash" onClick={() => setConfirm(true)} aria-label="Delete document">Delete</Button>
          </>
        }
      />

      {notes.length > 0 && (
        <div className="mb-6">
          <Alert kind="warning">
            <p className="font-medium">Please review</p>
            <ul className="ml-4 mt-1 list-disc space-y-0.5">{notes.map((w, i) => <li key={i}>{w}</li>)}</ul>
          </Alert>
        </div>
      )}
      {md.notices?.length > 0 && (
        <div className="mb-6">
          <Alert kind="info">
            <ul className="space-y-0.5">{md.notices.map((w, i) => <li key={i}>{w}</li>)}</ul>
          </Alert>
        </div>
      )}

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        <div className="min-w-0 space-y-6">
          <PrivacySummary summary={md.entity_summary} entities={md.entities} />
          <Card
            title="Person details"
            subtitle="Extracted details. Locked values are masked sensitive identifiers."
            padded={false}
            actions={
              <div className="inline-flex rounded-lg bg-slate-100 p-0.5 text-xs font-medium" role="tablist">
                {[['table', 'Table'], ['json', 'JSON']].map(([k, label]) => (
                  <button key={k} role="tab" aria-selected={tab === k} onClick={() => setTab(k)}
                    className={`rounded-md px-3 py-1 ${tab === k ? 'bg-white text-slate-900 shadow-sm' : 'text-slate-500 hover:text-slate-900'}`}>
                    {label}
                  </button>
                ))}
              </div>
            }
          >
            {tab === 'json' ? (
              <pre className="max-h-[28rem] overflow-auto rounded-b-xl bg-slate-900 p-4 text-xs leading-relaxed text-slate-100">
                {JSON.stringify(doc.person_json, null, 2)}
              </pre>
            ) : (
              <FieldsTable fields={doc.person_details} />
            )}
          </Card>
          {md.detection_notice && <p className="text-xs text-slate-400">{md.detection_notice}</p>}
        </div>
        <div className="min-w-0"><ChatPanel key={doc.id} documentId={doc.id} /></div>
      </div>

      <ConfirmDialog open={confirm} title="Delete document?"
        message="This permanently deletes the masked outputs, stored person details and the chat history for this document."
        confirmLabel="Delete" onConfirm={remove} onCancel={() => setConfirm(false)} />
    </div>
  )
}

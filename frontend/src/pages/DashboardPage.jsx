import { useCallback, useEffect, useRef, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { documentsApi, errorMessage } from '../services/api'
import Icon from '../components/icons'
import { Alert, Badge, Button, Card, ConfirmDialog, EmptyState, PageHeader, Skeleton, Spinner, StatusBadge } from '../components/ui'

const MAX_BYTES = 10 * 1024 * 1024
const MAX_FILES = 10
const CONCURRENCY = 2 // AI processing is rate-limited by the provider; 2 at a time keeps the queue moving
const ACCEPT = 'application/pdf,.pdf,image/png,.png,image/jpeg,.jpg,.jpeg,image/webp,.webp'
const IMAGE_RE = /\.(png|jpe?g|webp)$/i

export function validateFile(file) {
  if (!file) return 'Please choose a file.'
  const name = file.name.toLowerCase()
  const ok = file.type === 'application/pdf' || name.endsWith('.pdf') || /^image\/(png|jpe?g|webp)$/.test(file.type) || IMAGE_RE.test(name)
  if (!ok) return 'Only PDF, PNG, JPEG and WebP files are accepted.'
  if (file.size > MAX_BYTES) return 'File exceeds the 10 MB limit.'
  if (file.size === 0) return 'The file is empty.'
  return ''
}

export const prettyType = (t) => (t || 'other').replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase())
const fmtSize = (n) => (n > 1024 * 1024 ? `${(n / 1024 / 1024).toFixed(1)} MB` : `${Math.max(1, Math.round(n / 1024))} KB`)
const isImage = (f) => /^image\//.test(f.type) || IMAGE_RE.test(f.name)

let nextKey = 1

function QueueRow({ item, onRemove, onRetry }) {
  const { file, status, progress, error, doc } = item
  const tone = {
    queued: 'text-slate-500', uploading: 'text-indigo-600', processing: 'text-indigo-600',
    done: 'text-emerald-700', error: 'text-red-700', invalid: 'text-red-700',
  }[status]
  const label = {
    queued: 'Waiting', uploading: `Uploading ${progress}%`, processing: 'Masking securely…',
    done: doc?.processing_status === 'needs_review' ? 'Done · needs review' : 'Done',
    error: 'Failed', invalid: 'Not accepted',
  }[status]
  return (
    <li className="flex items-start gap-3 py-2.5">
      <div className={`mt-0.5 rounded-md p-1.5 ${status === 'done' ? 'bg-emerald-50 text-emerald-600' : status === 'error' || status === 'invalid' ? 'bg-red-50 text-red-600' : 'bg-slate-100 text-slate-500'}`}>
        <Icon name={status === 'done' ? 'check' : status === 'error' || status === 'invalid' ? 'alert' : isImage(file) ? 'eye' : 'doc'} className="h-4 w-4" />
      </div>
      <div className="min-w-0 flex-1">
        <div className="flex items-center justify-between gap-2">
          {doc ? (
            <Link to={`/documents/${doc.id}`} className="truncate text-sm font-medium text-slate-900 hover:text-indigo-600">{file.name}</Link>
          ) : <p className="truncate text-sm font-medium text-slate-900" title={file.name}>{file.name}</p>}
          <span className={`flex shrink-0 items-center gap-1.5 text-xs font-medium ${tone}`}>
            {(status === 'uploading' || status === 'processing') && <Spinner />}{label}
          </span>
        </div>
        <p className="text-xs text-slate-500">
          {fmtSize(file.size)}{isImage(file) && ' · image (read by vision AI)'}
        </p>
        {(status === 'uploading' || status === 'processing') && (
          <div className="mt-1.5 h-1 overflow-hidden rounded-full bg-slate-100">
            <div className={`h-full rounded-full bg-indigo-500 transition-all ${status === 'processing' ? 'w-full animate-pulse' : ''}`}
              style={status === 'uploading' ? { width: `${progress}%` } : undefined} />
          </div>
        )}
        {error && <p className="mt-1 text-xs text-red-700">{error}</p>}
        {status === 'done' && doc && (
          <div className="mt-1 flex gap-3 text-xs font-medium">
            <Link to={`/documents/${doc.id}`} className="text-indigo-600 hover:text-indigo-500">Open</Link>
            {doc.has_pdf && <a href={documentsApi.pdfUrl(doc.id)} className="text-indigo-600 hover:text-indigo-500">Masked PDF</a>}
            <a href={documentsApi.jsonUrl(doc.id)} className="text-indigo-600 hover:text-indigo-500">JSON</a>
          </div>
        )}
      </div>
      {status === 'error' && /privacy/i.test(error || '') && (
        <Link to="/settings" className="whitespace-nowrap text-xs font-medium text-indigo-600 hover:text-indigo-500">Open settings</Link>
      )}
      {status === 'error' && (!item.code || item.code >= 429) && (
        <button type="button" onClick={() => onRetry(item.key)} className="text-xs font-medium text-indigo-600 hover:text-indigo-500">Retry</button>
      )}
      {(status === 'queued' || status === 'invalid' || status === 'error') && (
        <button type="button" onClick={() => onRemove(item.key)} aria-label={`Remove ${file.name}`}
          className="rounded p-1 text-slate-400 hover:bg-slate-100 hover:text-slate-700"><Icon name="x" className="h-3.5 w-3.5" /></button>
      )}
    </li>
  )
}

function UploadPanel({ onUploaded }) {
  const [items, setItems] = useState([])
  const [mode, setMode] = useState('pdf_and_json')
  const [running, setRunning] = useState(false)
  const [drag, setDrag] = useState(false)
  const [notice, setNotice] = useState('')
  const inputRef = useRef(null)
  const itemsRef = useRef(items)
  itemsRef.current = items

  const update = (key, patch) => setItems((xs) => xs.map((x) => (x.key === key ? { ...x, ...patch } : x)))

  const add = (fileList) => {
    const files = Array.from(fileList || [])
    if (!files.length) return
    setNotice('')
    setItems((xs) => {
      const room = MAX_FILES - xs.filter((x) => x.status !== 'done').length
      if (files.length > room) setNotice(`You can queue up to ${MAX_FILES} files at a time.`)
      const fresh = files.slice(0, Math.max(0, room)).map((file) => {
        const problem = validateFile(file)
        return { key: nextKey++, file, status: problem ? 'invalid' : 'queued', progress: 0, error: problem, doc: null }
      })
      return [...xs.filter((x) => x.status !== 'done'), ...fresh]
    })
    if (inputRef.current) inputRef.current.value = ''
  }

  const uploadOne = async (item) => {
    update(item.key, { status: 'uploading', progress: 0, error: '' })
    try {
      const doc = await documentsApi.upload(item.file, mode, (p) =>
        update(item.key, p >= 100 ? { status: 'processing', progress: 100 } : { progress: p }))
      update(item.key, { status: 'done', doc })
      return doc
    } catch (err) {
      update(item.key, { status: 'error', error: errorMessage(err, 'Upload failed.'), code: err?.response?.status })
      return null
    }
  }

  const start = async (keys) => {
    setRunning(true)
    const pending = itemsRef.current.filter((x) => keys.includes(x.key))
    const done = []
    let i = 0
    const worker = async () => {
      while (i < pending.length) {
        const item = pending[i++]
        const doc = await uploadOne(item)
        if (doc) done.push(doc)
      }
    }
    await Promise.all(Array.from({ length: Math.min(CONCURRENCY, pending.length) }, worker))
    setRunning(false)
    onUploaded(done, pending.length)
  }

  const submit = (e) => {
    e.preventDefault()
    const keys = items.filter((x) => x.status === 'queued').map((x) => x.key)
    if (keys.length) start(keys)
  }

  const queued = items.filter((x) => x.status === 'queued').length
  const finished = items.filter((x) => x.status === 'done' && x.doc)
  const hasImages = items.some((x) => x.status !== 'invalid' && isImage(x.file))

  return (
    <Card title="Upload documents" subtitle="PDF, PNG, JPEG or WebP · up to 10 files of 10 MB. Sensitive identifiers are masked on the server before any AI processing.">
      <form onSubmit={submit} className="space-y-4">
        <label
          onDragOver={(e) => { e.preventDefault(); setDrag(true) }}
          onDragLeave={() => setDrag(false)}
          onDrop={(e) => { e.preventDefault(); setDrag(false); add(e.dataTransfer.files) }}
          className={`flex cursor-pointer flex-col items-center justify-center rounded-xl border-2 border-dashed px-6 py-7 text-center transition-colors ${
            drag ? 'border-indigo-500 bg-indigo-50' : 'border-slate-300 hover:border-indigo-400 hover:bg-slate-50'}`}
        >
          <div className="mb-2 rounded-full bg-indigo-50 p-2.5 text-indigo-600"><Icon name="upload" /></div>
          <p className="text-sm text-slate-600"><span className="font-semibold text-indigo-600">Click to choose</span> or drag and drop files</p>
          <p className="mt-0.5 text-xs text-slate-400">You can select several files at once</p>
          <input ref={inputRef} type="file" multiple accept={ACCEPT} aria-label="Document files" className="sr-only"
            onChange={(e) => add(e.target.files)} />
        </label>

        {items.length > 0 && (
          <ul className="divide-y divide-slate-100 rounded-lg border border-slate-200 px-3" aria-label="Upload queue">
            {items.map((item) => (
              <QueueRow key={item.key} item={item}
                onRemove={(k) => setItems((xs) => xs.filter((x) => x.key !== k))}
                onRetry={(k) => { update(k, { status: 'queued', error: '' }); setTimeout(() => start([k]), 0) }} />
            ))}
          </ul>
        )}
        {notice && <Alert kind="warning">{notice}</Alert>}
        {hasImages && (
          <p className="flex gap-2 rounded-lg bg-amber-50 px-3 py-2 text-xs text-amber-800">
            <Icon name="info" className="h-4 w-4 shrink-0" />
            Images are read by the external vision AI, so they need “external image processing” turned on in Privacy &amp; Permissions.
            Sensitive regions are then masked inside the image and re-checked.
          </p>
        )}

        <fieldset>
          <legend className="mb-2 text-xs font-medium text-slate-500">Output</legend>
          <div className="grid gap-2 sm:grid-cols-2">
            {[
              ['pdf_and_json', 'Masked PDF + JSON', 'Redacted copy of each document and person details'],
              ['json_only', 'JSON only', 'Person details only, no PDF is generated'],
            ].map(([value, label, desc]) => (
              <label key={value} className={`flex cursor-pointer gap-3 rounded-lg border p-3 text-sm ${mode === value ? 'border-indigo-600 bg-indigo-50/50 ring-1 ring-indigo-600' : 'border-slate-200 hover:bg-slate-50'}`}>
                <input type="radio" name="mode" value={value} checked={mode === value} onChange={() => setMode(value)} disabled={running} className="mt-0.5 accent-indigo-600" />
                <span><span className="block font-medium text-slate-900">{label}</span><span className="block text-xs text-slate-500">{desc}</span></span>
              </label>
            ))}
          </div>
        </fieldset>

        <div className="flex flex-wrap items-center justify-end gap-3">
          {finished.length > 1 && !running && (
            <a href={documentsApi.zipUrl(finished.map((x) => x.doc.id))}>
              <Button type="button" variant="secondary" icon="download">Download all ({finished.length}) as ZIP</Button>
            </a>
          )}
          <Button type="submit" disabled={running || !queued} icon={running ? undefined : 'shield'}>
            {running && <Spinner />}
            {running ? 'Processing…' : queued > 1 ? `Upload & process ${queued} files` : 'Upload & process'}
          </Button>
        </div>
      </form>
    </Card>
  )
}

function Stat({ label, value, icon, tone }) {
  return (
    <div className="flex items-center gap-4 rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
      <div className={`rounded-lg p-2.5 ${tone}`}><Icon name={icon} /></div>
      <div>
        <p className="text-xs font-medium text-slate-500">{label}</p>
        <p className="text-xl font-semibold text-slate-900">{value}</p>
      </div>
    </div>
  )
}

export default function DashboardPage() {
  const [docs, setDocs] = useState(null)
  const [error, setError] = useState('')
  const [toDelete, setToDelete] = useState(null)
  const navigate = useNavigate()

  const load = useCallback(() => {
    setError('')
    documentsApi.list().then(setDocs).catch((e) => { setDocs([]); setError(errorMessage(e, 'Could not load documents.')) })
  }, [])
  useEffect(load, [load])

  const remove = async () => {
    const id = toDelete.id
    setToDelete(null)
    try {
      await documentsApi.remove(id)
      load()
    } catch (e) {
      setError(errorMessage(e))
    }
  }

  const total = docs?.length ?? 0
  const review = docs?.filter((d) => d.processing_status === 'needs_review').length ?? 0
  const withPdf = docs?.filter((d) => d.has_pdf).length ?? 0

  return (
    <div>
      <PageHeader title="Documents" description="Upload PDFs or images, review masked results and chat with your documents." />

      <div className="mb-6 grid gap-4 sm:grid-cols-3">
        <Stat label="Documents" value={docs ? total : '—'} icon="doc" tone="bg-indigo-50 text-indigo-600" />
        <Stat label="Needs review" value={docs ? review : '—'} icon="alert" tone="bg-amber-50 text-amber-600" />
        <Stat label="Masked PDFs ready" value={docs ? withPdf : '—'} icon="shield" tone="bg-emerald-50 text-emerald-600" />
      </div>

      <div className="grid gap-6 xl:grid-cols-5">
        <div className="xl:col-span-2"><UploadPanel onUploaded={(done, total) => (total === 1 && done.length === 1 ? navigate(`/documents/${done[0].id}`) : load())} /></div>

        <div className="xl:col-span-3">
          <Card title="Document history" subtitle="Only your documents are listed. Open one to view details, download outputs or chat." padded={false}>
            {error && <div className="p-4"><Alert>{error} <button className="ml-1 font-medium underline" onClick={load}>Retry</button></Alert></div>}
            {!docs ? (
              <div className="space-y-3 p-5">{[0, 1, 2].map((i) => <Skeleton key={i} className="h-10 w-full" />)}</div>
            ) : docs.length === 0 && !error ? (
              <EmptyState icon="doc" title="No documents yet"
                description="Upload your first PDF. Sensitive identifiers are masked before anything is stored or sent to AI." />
            ) : (
              <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-slate-200 text-left text-sm">
                  <thead className="bg-slate-50 text-xs font-medium uppercase tracking-wide text-slate-500">
                    <tr>
                      <th scope="col" className="px-5 py-3">Document</th>
                      <th scope="col" className="px-3 py-3">Status</th>
                      <th scope="col" className="px-3 py-3">Outputs</th>
                      <th scope="col" className="px-5 py-3"><span className="sr-only">Actions</span></th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 bg-white">
                    {docs.map((d) => (
                      <tr key={d.id} className="hover:bg-slate-50">
                        <td className="max-w-xs px-5 py-3">
                          <Link to={`/documents/${d.id}`} className="block truncate font-medium text-slate-900 hover:text-indigo-600">{d.document_name}</Link>
                          <span className="text-xs text-slate-500">
                            {prettyType(d.document_type)} · {d.page_count} page{d.page_count === 1 ? '' : 's'} ·{' '}
                            <time dateTime={d.created_at}>{new Date(d.created_at).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' })}</time>
                          </span>
                          {!d.retained && <Badge tone="slate">Session only</Badge>}
                        </td>
                        <td className="px-3 py-3"><StatusBadge status={d.processing_status} /></td>
                        <td className="space-x-1 whitespace-nowrap px-3 py-3">
                          {d.has_pdf && <Badge tone="indigo">PDF</Badge>}
                          {d.has_json && <Badge tone="indigo">JSON</Badge>}
                        </td>
                        <td className="px-5 py-3 text-right">
                          <button onClick={() => setToDelete(d)} className="rounded-lg p-1.5 text-slate-400 hover:bg-red-50 hover:text-red-600"
                            aria-label={`Delete ${d.document_name}`} title="Delete">
                            <Icon name="trash" className="h-4 w-4" />
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Card>
        </div>
      </div>

      <ConfirmDialog
        open={!!toDelete}
        title="Delete document?"
        message={`“${toDelete?.document_name}” will be permanently deleted with its masked outputs, stored details and chat history.`}
        confirmLabel="Delete"
        onConfirm={remove}
        onCancel={() => setToDelete(null)}
      />
    </div>
  )
}

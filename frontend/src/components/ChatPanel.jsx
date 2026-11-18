import { useEffect, useRef, useState } from 'react'
import { documentsApi, errorMessage } from '../services/api'
import Icon from './icons'
import { Alert, Button, Spinner } from './ui'

const SUGGESTIONS = ['What is my name?', 'What qualification is mentioned?', 'Who is the employer?', 'What is my Aadhaar number?']

const KIND_NOTE = {
  restricted: ['Protected information', 'text-red-600'],
  permission_disabled: ['Hidden by your privacy settings', 'text-amber-700'],
  out_of_scope: ['Outside this document', 'text-slate-500'],
}

/** Chat bound to ONE document. Mount with key={documentId} so switching documents
 *  fully resets the conversation context. */
export default function ChatPanel({ documentId }) {
  const [messages, setMessages] = useState([])
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const [historyLoading, setHistoryLoading] = useState(true)
  const [error, setError] = useState('')
  const bottomRef = useRef(null)

  useEffect(() => {
    let alive = true
    setMessages([])
    setHistoryLoading(true)
    documentsApi
      .history(documentId)
      .then((h) => alive && setMessages(h.messages))
      .catch((e) => alive && setError(errorMessage(e, 'Could not load chat history.')))
      .finally(() => alive && setHistoryLoading(false))
    return () => { alive = false }
  }, [documentId])

  useEffect(() => {
    bottomRef.current?.scrollIntoView?.({ block: 'nearest' })
  }, [messages, loading])

  const ask = async (text) => {
    text = text.trim()
    if (!text || loading) return
    setError('')
    setLoading(true)
    setInput('')
    const pending = { id: `pending-${Date.now()}`, role: 'user', content: text, pending: true }
    setMessages((m) => [...m, pending])
    try {
      const res = await documentsApi.chat(documentId, text)
      setMessages((m) => [...m.filter((x) => x.id !== pending.id), res.user_message, res.assistant_message])
    } catch (err) {
      setMessages((m) => m.filter((x) => x.id !== pending.id))
      setInput(text)
      setError(errorMessage(err, 'The assistant could not answer. Please try again.'))
    } finally {
      setLoading(false)
    }
  }

  return (
    <section className="flex h-[40rem] flex-col rounded-xl border border-slate-200 bg-white shadow-sm xl:sticky xl:top-8">
      <div className="flex items-center gap-3 border-b border-slate-100 px-5 py-4">
        <div className="rounded-lg bg-indigo-50 p-2 text-indigo-600"><Icon name="chat" /></div>
        <div>
          <h2 className="text-sm font-semibold text-slate-900">Document assistant</h2>
          <p className="text-xs text-slate-500">Answers only from this document · protected IDs are never revealed</p>
        </div>
      </div>

      <div className="flex-1 space-y-4 overflow-y-auto bg-slate-50/60 px-5 py-4" aria-live="polite" data-testid="chat-log">
        {historyLoading && <p className="flex items-center gap-2 text-sm text-slate-500"><Spinner /> Loading conversation…</p>}
        {!historyLoading && messages.length === 0 && (
          <div className="py-6 text-center">
            <div className="mx-auto mb-3 w-fit rounded-full bg-indigo-50 p-3 text-indigo-600"><Icon name="sparkles" className="h-6 w-6" /></div>
            <p className="text-sm font-medium text-slate-900">Ask about this document</p>
            <p className="mt-1 text-xs text-slate-500">Try one of these:</p>
            <div className="mt-3 flex flex-wrap justify-center gap-2">
              {SUGGESTIONS.map((s) => (
                <button key={s} onClick={() => ask(s)}
                  className="rounded-full border border-slate-200 bg-white px-3 py-1.5 text-xs text-slate-700 hover:border-indigo-300 hover:text-indigo-700">
                  {s}
                </button>
              ))}
            </div>
          </div>
        )}
        {messages.map((m) => {
          const mine = m.role === 'user'
          const note = !mine && KIND_NOTE[m.kind]
          return (
            <div key={m.id} className={`flex gap-2.5 ${mine ? 'flex-row-reverse' : ''}`}>
              <div className={`flex h-7 w-7 shrink-0 items-center justify-center rounded-full ${mine ? 'bg-slate-200 text-slate-600' : 'bg-indigo-600 text-white'}`}>
                <Icon name={mine ? 'user' : 'shield'} className="h-4 w-4" />
              </div>
              <div className={`max-w-[80%] min-w-0 whitespace-pre-wrap break-words [overflow-wrap:anywhere] rounded-2xl px-3.5 py-2.5 text-sm leading-relaxed ${
                mine ? 'rounded-tr-sm bg-indigo-600 text-white' : 'rounded-tl-sm border border-slate-200 bg-white text-slate-800 shadow-sm'
              } ${m.pending ? 'opacity-70' : ''}`}>
                {m.content}
                {note && <div className={`mt-1.5 flex items-center gap-1 text-xs font-medium ${note[1]}`}><Icon name="lock" className="h-3 w-3" />{note[0]}</div>}
              </div>
            </div>
          )
        })}
        {loading && (
          <div className="flex items-center gap-2 text-sm text-slate-500" role="status">
            <Spinner /> Assistant is thinking…
          </div>
        )}
        <div ref={bottomRef} />
      </div>

      <div className="border-t border-slate-100 p-4">
        {error && <div className="mb-3"><Alert>{error}</Alert></div>}
        <form onSubmit={(e) => { e.preventDefault(); ask(input) }} className="flex gap-2">
          <input
            aria-label="Your question"
            className="flex-1 rounded-lg border-0 px-3.5 py-2.5 text-sm shadow-sm ring-1 ring-inset ring-slate-300 placeholder:text-slate-400 focus:ring-2 focus:ring-inset focus:ring-indigo-600"
            placeholder="Ask about this document…"
            maxLength={1000}
            value={input}
            onChange={(e) => setInput(e.target.value)}
          />
          <Button type="submit" disabled={loading || !input.trim()} aria-label="Send">
            <Icon name="send" className="h-4 w-4" /><span className="hidden sm:inline">Send</span>
          </Button>
        </form>
      </div>
    </section>
  )
}

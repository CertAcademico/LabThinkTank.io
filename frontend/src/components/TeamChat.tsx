import { useEffect, useRef, useState } from 'react'
import { useAuth } from '../contexts/AuthContext'

const API = import.meta.env.VITE_API_URL ?? 'http://127.0.0.1:8000'
const POLL_MS = 5000

interface Msg { id: number; user_email: string; user_name: string; role: string; body: string; created_at: string }

function hhmm(iso: string) {
  const d = new Date(iso.endsWith('Z') ? iso : iso + 'Z')
  return isNaN(d.getTime()) ? '' : d.toLocaleString('es-CO', { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' })
}

/** Chat del grupo entre el instructor (admin) y los integrantes. Se actualiza cada 5 s. */
export default function TeamChat({ teamId, teamName, height = 380 }: { teamId: number; teamName: string; height?: number }) {
  const { token, user } = useAuth()
  const isAdmin = user?.role === 'admin'
  const [msgs, setMsgs]       = useState<Msg[]>([])
  const [text, setText]       = useState('')
  const [error, setError]     = useState('')
  const [sending, setSending] = useState(false)
  const lastId  = useRef(0)
  const listRef = useRef<HTMLDivElement>(null)
  const headers = { Authorization: `Bearer ${token}` }

  const scrollDown = () => requestAnimationFrame(() => {
    const el = listRef.current
    if (el) el.scrollTop = el.scrollHeight
  })

  useEffect(() => {
    let alive = true
    lastId.current = 0
    setMsgs([])
    const load = async () => {
      try {
        const r = await fetch(`${API}/teams/${teamId}/chat?after=${lastId.current}`, { headers })
        if (!r.ok) { if (alive) setError((await r.json().catch(() => ({}))).detail ?? 'No se pudo cargar el chat'); return }
        const data: Msg[] = await r.json()
        if (!alive || data.length === 0) return
        lastId.current = data[data.length - 1].id
        setMsgs(prev => [...prev, ...data.filter(m => !prev.some(p => p.id === m.id))])
        setError('')
        scrollDown()
      } catch { /* red intermitente: se reintenta en el siguiente ciclo */ }
    }
    load()
    const t = setInterval(load, POLL_MS)
    return () => { alive = false; clearInterval(t) }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [teamId, token])

  const send = async (e: React.FormEvent) => {
    e.preventDefault()
    const body = text.trim()
    if (!body || sending) return
    setSending(true)
    try {
      const r = await fetch(`${API}/teams/${teamId}/chat`, {
        method: 'POST', headers: { ...headers, 'Content-Type': 'application/json' }, body: JSON.stringify({ body }),
      })
      const data = await r.json()
      if (!r.ok) throw new Error(data.detail ?? 'No se pudo enviar')
      setText('')
      lastId.current = Math.max(lastId.current, data.id)
      setMsgs(prev => prev.some(p => p.id === data.id) ? prev : [...prev, data])
      scrollDown()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'No se pudo enviar')
    } finally {
      setSending(false)
    }
  }

  const remove = async (id: number) => {
    await fetch(`${API}/admin/teams/${teamId}/chat/${id}`, { method: 'DELETE', headers }).catch(() => {})
    setMsgs(prev => prev.filter(m => m.id !== id))
  }

  return (
    <div className="rounded-xl flex flex-col"
         style={{ background: 'rgba(26,31,19,0.6)', border: '1px solid rgba(212,189,85,0.25)' }}>
      <div className="flex items-center justify-between px-4 py-2.5 border-b" style={{ borderColor: 'rgba(212,189,85,0.15)' }}>
        <p className="text-xs font-bold tracking-wider uppercase" style={{ color: '#d4bd55' }}>
          💬 Canal del grupo {teamName}
        </p>
        <span className="text-[10px] text-slate-500">{isAdmin ? 'Hablas como instructor' : 'Instructor e integrantes'}</span>
      </div>

      <div ref={listRef} className="flex-1 overflow-y-auto px-4 py-3 space-y-2.5" style={{ height }}>
        {msgs.length === 0 && !error && (
          <p className="text-xs text-slate-500 text-center mt-8">
            {isAdmin ? 'Aún no hay mensajes. Escribe el primero para el grupo.' : 'Aún no hay mensajes. Escribe tu pregunta al instructor.'}
          </p>
        )}
        {msgs.map(m => {
          const mine = m.user_email === user?.email
          const instructor = m.role === 'admin'
          return (
            <div key={m.id} className={`flex ${mine ? 'justify-end' : 'justify-start'}`}>
              <div className="max-w-[80%] rounded-lg px-3 py-2 group"
                   style={{
                     background: instructor ? 'rgba(212,189,85,0.12)' : mine ? 'rgba(147,169,84,0.14)' : 'rgba(255,255,255,0.04)',
                     border: `1px solid ${instructor ? 'rgba(212,189,85,0.35)' : 'rgba(255,255,255,0.07)'}`,
                   }}>
                <div className="flex items-center gap-2 mb-0.5">
                  <span className="text-[10px] font-semibold" style={{ color: instructor ? '#d4bd55' : '#aec174' }}>
                    {instructor ? '🎖️ Instructor' : (m.user_name || m.user_email)}
                  </span>
                  <span className="text-[9px] text-slate-600">{hhmm(m.created_at)}</span>
                  {isAdmin && (
                    <button onClick={() => remove(m.id)} title="Borrar mensaje"
                            className="text-[9px] text-slate-600 hover:text-red-400 opacity-0 group-hover:opacity-100">✕</button>
                  )}
                </div>
                <p className="text-xs text-slate-200 whitespace-pre-wrap break-words">{m.body}</p>
              </div>
            </div>
          )
        })}
      </div>

      {error && <p className="px-4 pb-1 text-[11px] text-red-400">{error}</p>}
      <form onSubmit={send} className="flex gap-2 p-3 border-t" style={{ borderColor: 'rgba(212,189,85,0.15)' }}>
        <textarea value={text} onChange={e => setText(e.target.value)} rows={1} maxLength={2000}
                  onKeyDown={e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(e) } }}
                  placeholder={isAdmin ? 'Mensaje para el grupo…' : 'Escribe al instructor y al grupo…'}
                  className="flex-1 resize-none rounded-lg px-3 py-2 text-xs text-slate-200 outline-none"
                  style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)' }} />
        <button type="submit" disabled={sending || !text.trim()}
                className="rounded-lg px-4 text-xs font-semibold disabled:opacity-40"
                style={{ background: 'rgba(212,189,85,0.15)', border: '1px solid rgba(212,189,85,0.4)', color: '#e0cf74' }}>
          Enviar
        </button>
      </form>
    </div>
  )
}

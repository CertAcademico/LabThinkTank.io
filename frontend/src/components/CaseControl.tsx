import { useCallback, useEffect, useState } from 'react'
import { useAuth } from '../contexts/AuthContext'

const API = import.meta.env.VITE_API_URL ?? 'http://127.0.0.1:8000'
const glass = { background: 'rgba(15,23,42,0.55)', backdropFilter: 'blur(16px)', border: '1px solid rgba(255,255,255,0.07)', borderRadius: 12 }
const inputStyle = { background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.1)' }

interface Ch {
  id: number; title: string; status: 'draft' | 'active' | 'closed'; starts_at?: string | null; deadline?: string | null
  difficulty: string; stage?: string; case_key?: string; case_chapter?: number; assigned_count: number; submission_count: number
}
interface Crit { label: string; weight: number; hint: string; expected: string }
interface Solution { title: string; variant: string | null; variant_email: string | null; reference_code: string; criteria: Crit[] }
interface Ann { id: number; title: string; body: string; publish_at: string; expires_at?: string | null }
interface UserRow { email: string; name: string; role: string }

// Ciclo de inteligencia al que apunta cada capítulo del Caso Aurora
const CYCLE: Record<number, string> = { 1: 'Recolección', 2: 'Procesamiento', 3: 'Análisis', 4: 'Análisis', 5: 'Procesamiento', 6: 'Análisis predictivo', 7: 'Análisis predictivo', 8: 'Diseminación' }
const STATUS: Record<string, { label: string; color: string }> = {
  draft: { label: 'Borrador (oculto)', color: '#64748b' }, active: { label: 'Activo', color: '#4ade80' }, closed: { label: 'Cerrado', color: '#f87171' },
}

// ISO (cualquier zona) -> valor de <input type="datetime-local"> en hora de Bogotá
const toInput = (iso?: string | null) => {
  if (!iso) return ''
  const d = new Date(iso); if (isNaN(d.getTime())) return ''
  const parts = new Intl.DateTimeFormat('sv-SE', { timeZone: 'America/Bogota', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' }).format(d)
  return parts.replace(' ', 'T')
}
const fromInput = (v: string) => (v ? `${v}:00-05:00` : null)

export default function CaseControl() {
  const { token } = useAuth()
  const headers = { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` }
  const [chs, setChs] = useState<Ch[]>([])
  const [anns, setAnns] = useState<Ann[]>([])
  const [users, setUsers] = useState<UserRow[]>([])
  const [sol, setSol] = useState<Solution | null>(null)
  const [solFor, setSolFor] = useState<{ id: number; email: string } | null>(null)
  const [msg, setMsg] = useState('')
  const [openTo, setOpenTo] = useState<number>(0)
  const [flow, setFlow] = useState<{ start: string; active: boolean; badges: { chapter: number; name: string; tier: string }[] } | null>(null)
  const [form, setForm] = useState({ title: '', body: '', publish_at: '', expires_at: '' })

  const api = useCallback(async (path: string, init?: RequestInit) => {
    const r = await fetch(`${API}${path}`, { ...init, headers })
    const d = await r.json().catch(() => ({}))
    if (!r.ok) throw new Error(typeof d.detail === 'string' ? d.detail : 'Error')
    return d
  }, [token]) // eslint-disable-line react-hooks/exhaustive-deps

  const load = useCallback(() => {
    api('/admin/challenges').then(setChs).catch(() => {})
    api('/admin/announcements').then(setAnns).catch(() => {})
    api('/admin/users').then(setUsers).catch(() => {})
    api('/admin/badge-flow').then(setFlow).catch(() => {})
    api('/admin/path-open').then(d => setOpenTo(d.open_up_to ?? 0)).catch(() => {})
  }, [api])
  useEffect(() => { load() }, [load])

  const patch = async (id: number, body: Record<string, unknown>) => {
    try { await api(`/admin/challenges/${id}`, { method: 'PATCH', body: JSON.stringify(body) }); setMsg(''); load() } catch (e) { setMsg(String(e instanceof Error ? e.message : e)) }
  }
  const aurora = chs.filter(c => c.case_key === 'aurora').sort((a, b) => (a.case_chapter ?? 0) - (b.case_chapter ?? 0))
  const others = chs.filter(c => c.case_key !== 'aurora').sort((a, b) => a.id - b.id)
  const nextDraft = aurora.find(c => c.status === 'draft')

  const openSolution = async (id: number, email = '') => {
    try {
      const d = await api(`/admin/challenges/${id}/solution${email ? `?email=${encodeURIComponent(email)}` : ''}`)
      setSol(d); setSolFor({ id, email: d.variant_email ?? '' })
    } catch (e) { setMsg(String(e instanceof Error ? e.message : e)) }
  }
  const createAnn = async () => {
    try {
      await api('/admin/announcements', { method: 'POST', body: JSON.stringify({
        title: form.title, body: form.body, publish_at: fromInput(form.publish_at) ?? new Date().toISOString(), expires_at: fromInput(form.expires_at) }) })
      setForm({ title: '', body: '', publish_at: '', expires_at: '' }); load()
    } catch (e) { setMsg(String(e instanceof Error ? e.message : e)) }
  }

  const row = (c: Ch) => {
    const st = STATUS[c.status] ?? STATUS.active
    return (
      <div key={c.id} className="px-4 py-3 grid gap-2 items-center border-t border-white/5" style={{ gridTemplateColumns: 'minmax(0,2.2fr) 150px 170px 170px auto' }}>
        <div className="min-w-0">
          <p className="text-xs text-slate-200 truncate">{c.case_chapter ? `${c.case_chapter}. ` : ''}{c.title.replace(/^Caso Aurora \d — /, '')}</p>
          <p className="text-[9px] text-slate-600">
            {c.case_chapter ? <span className="text-violet-400">Ciclo: {CYCLE[c.case_chapter]} · </span> : null}
            {c.difficulty} · {c.assigned_count} asignados · {c.submission_count} entregas
          </p>
        </div>
        <select value={c.status} onChange={e => patch(c.id, { status: e.target.value })}
                className="rounded px-2 py-1.5 text-[11px] font-semibold outline-none" style={{ ...inputStyle, color: st.color }}>
          {Object.entries(STATUS).map(([k, v]) => <option key={k} value={k} className="bg-slate-900">{v.label}</option>)}
        </select>
        <input type="datetime-local" defaultValue={toInput(c.starts_at)} key={`s${c.id}${c.starts_at}`} title="Inicio (hora Bogotá)"
               onBlur={e => { if (e.target.value !== toInput(c.starts_at)) patch(c.id, { starts_at: fromInput(e.target.value) }) }}
               className="rounded px-2 py-1 text-[10px] text-slate-300 outline-none" style={inputStyle} />
        <input type="datetime-local" defaultValue={toInput(c.deadline)} key={`d${c.id}${c.deadline}`} title="Cierre (hora Bogotá)"
               onBlur={e => { if (e.target.value !== toInput(c.deadline)) patch(c.id, { deadline: fromInput(e.target.value) }) }}
               className="rounded px-2 py-1 text-[10px] text-slate-300 outline-none" style={inputStyle} />
        <button onClick={() => openSolution(c.id)} className="text-[10px] px-2.5 py-1.5 rounded font-semibold text-cyan-300 whitespace-nowrap"
                style={{ background: 'rgba(34,211,238,0.08)', border: '1px solid rgba(34,211,238,0.25)' }}>Ver soluciones</button>
      </div>
    )
  }
  const header = (
    <div className="px-4 py-2 grid gap-2 text-[9px] font-bold text-slate-600 uppercase tracking-wider" style={{ gridTemplateColumns: 'minmax(0,2.2fr) 150px 170px 170px auto' }}>
      <span>Reto</span><span>Estado</span><span>Inicio (Bogotá)</span><span>Cierre (Bogotá)</span><span />
    </div>
  )

  return (
    <div className="space-y-5">
      <div className="rounded-xl p-5 space-y-1" style={glass}>
        <h2 className="text-base font-bold text-slate-100">Control del caso y de los retos</h2>
        <p className="text-[11px] text-slate-500">
          Solo tú activas los retos. Un reto en <strong>Borrador</strong> no lo ve ni lo puede usar ningún estudiante. Puedes programar inicio y cierre,
          y revisar la solución esperada de cada reto para la variante de cualquier estudiante.
        </p>
        {msg && <p className="text-[11px] text-red-400">{msg}</p>}
      </div>

      <div className="rounded-xl p-5 space-y-2" style={glass}>
        <p className="text-xs font-bold text-cyan-300">🔓 Abrir capítulos sin requisito</p>
        <p className="text-[10px] text-slate-500">Abre los capítulos hasta el número elegido para <strong>todos</strong> los estudiantes, sin exigir superar el anterior. 0 = desbloqueo secuencial (con 60 puntos o la insignia). Solo se abren los que estén Activos.</p>
        <div className="flex items-center gap-2 flex-wrap">
          <select value={openTo} onChange={e => setOpenTo(Number(e.target.value))} className="rounded px-2 py-1.5 text-[11px] text-slate-200" style={inputStyle}>
            <option value={0} className="bg-slate-900">Ninguno (secuencial)</option>
            {[1, 2, 3, 4, 5, 6, 7, 8].map(n => <option key={n} value={n} className="bg-slate-900">Hasta el capítulo {n}</option>)}
          </select>
          <button onClick={async () => { try { await api('/admin/path-open', { method: 'POST', body: JSON.stringify({ open_up_to: openTo }) }); setMsg(''); load() } catch (e) { setMsg(String(e instanceof Error ? e.message : e)) } }}
                  className="text-[11px] px-3 py-1.5 rounded font-semibold text-cyan-300" style={{ background: 'rgba(34,211,238,0.1)', border: '1px solid rgba(34,211,238,0.3)' }}>Guardar</button>
        </div>
      </div>

      {flow && (
        <div className="rounded-xl p-5 space-y-3" style={glass}>
          <div className="flex items-center gap-3 flex-wrap">
            <p className="text-xs font-bold text-yellow-300 flex-1">🏅 Insignias de habilidad: cada capítulo superado entrega la suya y habilita el siguiente</p>
            <span className="text-[10px] font-bold px-2 py-0.5 rounded" style={flow.active ? { color: '#4ade80', background: 'rgba(74,222,128,0.12)' } : { color: '#facc15', background: 'rgba(250,204,21,0.1)' }}>
              {flow.active ? 'Rigiendo ahora' : 'Aún no rige'}
            </span>
          </div>
          <div className="flex items-end gap-3 flex-wrap">
            <label className="text-[10px] text-slate-500">Rige desde (hora Bogotá)
              <input type="datetime-local" defaultValue={toInput(flow.start)} key={flow.start} id="flow-start" className="block mt-1 rounded px-2 py-1 text-[11px] text-slate-300" style={inputStyle} /></label>
            <button onClick={async () => { const v = (document.getElementById('flow-start') as HTMLInputElement).value; if (!v) return
                      try { await api('/admin/badge-flow', { method: 'POST', body: JSON.stringify({ start: fromInput(v) }) }); load() } catch (e) { setMsg(String(e instanceof Error ? e.message : e)) } }}
                    className="text-[11px] px-3 py-1.5 rounded font-semibold text-yellow-300" style={{ background: 'rgba(250,204,21,0.1)', border: '1px solid rgba(250,204,21,0.3)' }}>Guardar</button>
          </div>
          <div className="flex gap-1.5 flex-wrap">
            {flow.badges.map(b => <span key={b.chapter} className="text-[10px] px-2 py-1 rounded" style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)', color: '#94a3b8' }}>Cap {b.chapter} · {b.name}</span>)}
          </div>
          <p className="text-[10px] text-slate-600">Antes de esa hora los capítulos siguen desbloqueándose con 60 puntos, pero la insignia no se otorga. A la hora indicada, quien ya había superado un capítulo la recibe al abrir sus retos.</p>
        </div>
      )}

      <div className="rounded-xl overflow-hidden" style={glass}>
        <div className="px-4 py-3 flex items-center gap-3 flex-wrap">
          <p className="text-xs font-bold text-violet-300 flex-1">Caso Aurora — ciclo de ciberinteligencia</p>
          <button disabled={!nextDraft} onClick={() => nextDraft && patch(nextDraft.id, { status: 'active' })}
                  className="text-[11px] px-3 py-1.5 rounded font-semibold text-green-400 disabled:opacity-40"
                  style={{ background: 'rgba(74,222,128,0.1)', border: '1px solid rgba(74,222,128,0.3)' }}>
            {nextDraft ? `Activar capítulo ${nextDraft.case_chapter}` : 'Todos activados'}
          </button>
        </div>
        {header}{aurora.map(row)}
        {aurora.length === 0 && <p className="px-4 pb-4 text-xs text-slate-600">El caso aparece aquí después del primer arranque del backend actualizado.</p>}
      </div>

      <div className="rounded-xl overflow-hidden" style={glass}>
        <p className="px-4 py-3 text-xs font-bold text-slate-300">Retos de práctica</p>
        {header}{others.map(row)}
      </div>

      <div className="rounded-xl p-5 space-y-3" style={glass}>
        <p className="text-xs font-bold text-yellow-400">Anuncios a los estudiantes</p>
        <p className="text-[11px] text-slate-500">Se muestran como banner a partir de la hora de publicación y hasta que caduquen (o el estudiante los cierre).</p>
        <input value={form.title} onChange={e => setForm({ ...form, title: e.target.value })} placeholder="Título" className="w-full rounded-lg px-3 py-2 text-xs text-slate-100 outline-none" style={inputStyle} />
        <textarea value={form.body} onChange={e => setForm({ ...form, body: e.target.value })} rows={3} placeholder="Mensaje (por ejemplo, una novedad de inteligencia que cambia el caso)" className="w-full rounded-lg px-3 py-2 text-xs text-slate-100 outline-none resize-none" style={inputStyle} />
        <div className="flex gap-3 flex-wrap items-end">
          <label className="text-[10px] text-slate-500">Publicar<input type="datetime-local" value={form.publish_at} onChange={e => setForm({ ...form, publish_at: e.target.value })} className="block mt-1 rounded px-2 py-1 text-[11px] text-slate-300" style={inputStyle} /></label>
          <label className="text-[10px] text-slate-500">Caduca (opcional)<input type="datetime-local" value={form.expires_at} onChange={e => setForm({ ...form, expires_at: e.target.value })} className="block mt-1 rounded px-2 py-1 text-[11px] text-slate-300" style={inputStyle} /></label>
          <button onClick={createAnn} disabled={!form.title.trim() || !form.body.trim()} className="text-[11px] px-4 py-2 rounded font-semibold text-yellow-300 disabled:opacity-40"
                  style={{ background: 'rgba(250,204,21,0.1)', border: '1px solid rgba(250,204,21,0.3)' }}>{form.publish_at ? 'Programar' : 'Publicar ahora'}</button>
        </div>
        {anns.map(a => (
          <div key={a.id} className="flex items-start gap-3 rounded-lg p-3" style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.06)' }}>
            <div className="flex-1 min-w-0"><p className="text-xs text-slate-200">{a.title}</p><p className="text-[10px] text-slate-500 whitespace-pre-line">{a.body}</p>
              <p className="text-[9px] text-slate-700 mt-1">Publica: {toInput(a.publish_at).replace('T', ' ')}{a.expires_at ? ` · caduca ${toInput(a.expires_at).replace('T', ' ')}` : ''}</p></div>
            <button onClick={async () => { await api(`/admin/announcements/${a.id}`, { method: 'DELETE' }); load() }} className="text-[10px] text-red-400">Eliminar</button>
          </div>
        ))}
      </div>

      {sol && solFor && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4" style={{ background: 'rgba(3,7,18,0.8)' }} onClick={() => setSol(null)}>
          <div className="w-full max-w-4xl max-h-[88vh] overflow-y-auto rounded-xl p-5 space-y-4" style={{ ...glass, background: 'rgba(8,12,25,0.98)' }} onClick={e => e.stopPropagation()}>
            <div className="flex items-start gap-3">
              <div className="flex-1"><h3 className="text-sm font-bold text-slate-100">{sol.title}</h3>
                {sol.variant && <p className="text-[11px] text-violet-300">Variante {sol.variant} · {sol.variant_email}</p>}</div>
              <button onClick={() => setSol(null)} className="text-slate-500 hover:text-slate-300">✕</button>
            </div>
            {sol.variant !== null && (
              <label className="block text-[10px] text-slate-500">Ver la solución para el estudiante:
                <select value={solFor.email} onChange={e => openSolution(solFor.id, e.target.value)} className="block mt-1 rounded px-2 py-1.5 text-[11px] text-slate-200 w-full max-w-sm" style={inputStyle}>
                  {users.filter(u => u.role === 'student' || u.role === 'admin').map(u => <option key={u.email} value={u.email} className="bg-slate-900">{u.name} — {u.email}</option>)}
                </select></label>
            )}
            <div>
              <p className="text-[10px] font-bold text-slate-500 uppercase tracking-wider mb-2">Criterios y respuesta esperada</p>
              {sol.criteria.map((c, i) => (
                <div key={i} className="py-2 border-t border-white/5 text-[11px]">
                  <div className="flex gap-2"><span className="flex-1 text-slate-300">{c.label}</span><span className="text-slate-600">{c.weight} pts</span></div>
                  <p className="text-green-300 mt-0.5 break-words">✔ {c.expected}</p>
                  <p className="text-slate-600 text-[10px]">Pista al estudiante: {c.hint}</p>
                </div>
              ))}
            </div>
            {sol.reference_code && (
              <div><p className="text-[10px] font-bold text-slate-500 uppercase tracking-wider mb-1">Solución de referencia</p>
                <pre className="text-[11px] text-green-300 whitespace-pre-wrap font-mono rounded-lg p-3" style={{ background: '#050a14' }}>{sol.reference_code}</pre></div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

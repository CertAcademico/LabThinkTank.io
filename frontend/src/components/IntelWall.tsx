import { useCallback, useEffect, useState } from 'react'
import { useAuth } from '../contexts/AuthContext'

const API = import.meta.env.VITE_API_URL ?? 'http://127.0.0.1:8000'
const glass = { background: 'rgba(26,31,19,0.55)', backdropFilter: 'blur(16px)', border: '1px solid rgba(255,255,255,0.07)', borderRadius: 12 }

interface Report {
  id: number; user_email: string; user_name: string; title: string; summary: string
  evidence: string; confidence: string; recommendations: string; pinned: number; updated_at: string
}
interface Wall { opens_at?: string | null; open: boolean; mine: Report | null; reports: Report[]; total: number }

const CONF: Record<string, string> = { baja: '#f87171', media: '#facc15', alta: '#4ade80' }
const inputCls = 'w-full rounded-lg px-3 py-2 text-xs text-slate-100 outline-none resize-none'
const inputStyle = { background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)' }

export default function IntelWall() {
  const { token, user } = useAuth()
  const isAdmin = user?.role === 'admin'
  const headers = { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` }
  const [wall, setWall] = useState<Wall | null>(null)
  const [form, setForm] = useState({ title: '', summary: '', evidence: '', confidence: 'media', recommendations: '' })
  const [msg, setMsg] = useState('')
  const [saving, setSaving] = useState(false)
  const [editing, setEditing] = useState(false)

  const load = useCallback(() => {
    fetch(`${API}/intel-wall`, { headers }).then(r => r.ok ? r.json() : null).then((w: Wall | null) => {
      if (!w) return
      setWall(w)
      if (w.mine && !editing) setForm({ title: w.mine.title, summary: w.mine.summary, evidence: w.mine.evidence, confidence: w.mine.confidence, recommendations: w.mine.recommendations })
    }).catch(() => {})
  }, [token, editing]) // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => { load(); const t = setInterval(load, 20_000); return () => clearInterval(t) }, [load])

  const save = async () => {
    setSaving(true); setMsg('')
    try {
      const r = await fetch(`${API}/intel-wall/mine`, { method: 'PUT', headers, body: JSON.stringify(form) })
      const d = await r.json().catch(() => ({}))
      if (!r.ok) throw new Error(typeof d.detail === 'string' ? d.detail : 'No se pudo guardar')
      setMsg('✓ Reporte guardado. Puedes editarlo hasta que cierre la sesión.'); setEditing(false); load()
    } catch (e) { setMsg(String(e instanceof Error ? e.message : e)) } finally { setSaving(false) }
  }
  const adminCall = async (path: string, init: RequestInit) => { await fetch(`${API}${path}`, { ...init, headers }); load() }
  const exportCsv = async () => {
    const r = await fetch(`${API}/admin/intel-wall/export`, { headers })
    const blob = await r.blob(); const a = document.createElement('a')
    a.href = URL.createObjectURL(blob); a.download = 'muro_inteligencia.csv'; a.click()
  }

  return (
    <div className="space-y-4 max-w-4xl">
      <div className="rounded-xl p-5 space-y-1" style={glass}>
        <h2 className="text-base font-bold text-slate-100">Muro de resultados de inteligencia</h2>
        <p className="text-[11px] text-slate-500">
          Redacta tu reporte final de inteligencia: qué encontraste, con qué datos lo sustentas y qué recomiendas.
          {wall && !wall.open && !isAdmin && (wall.opens_at ? ` Tu reporte es privado hasta las ${new Date(wall.opens_at).toLocaleTimeString('es-CO', { timeZone: 'America/Bogota', hour: 'numeric', minute: '2-digit', hour12: true })}, cuando el Muro se abre para todos y hacemos el diálogo.` : ' Tu reporte es privado hasta que el docente abra el muro para el diálogo.')}
        </p>
        {isAdmin && wall && (
          <div className="flex items-center gap-2 pt-2 flex-wrap">
            <span className="text-[11px] text-slate-400 flex-1">{wall.total} reporte(s) · Muro {wall.open ? 'ABIERTO: todos ven todos' : 'CERRADO: cada estudiante ve solo el suyo'}</span>
            <button onClick={() => adminCall('/admin/intel-wall/open', { method: 'POST', body: JSON.stringify({ open: !wall.open }) })}
                    className="text-[11px] px-3 py-1.5 rounded font-semibold"
                    style={wall.open ? { background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.12)', color: '#a3a27c' }
                                     : { background: 'rgba(74,222,128,0.12)', border: '1px solid rgba(74,222,128,0.35)', color: '#4ade80' }}>
              {wall.open ? 'Cerrar muro' : 'Abrir muro a todos'}
            </button>
            <button onClick={exportCsv} className="text-[11px] px-3 py-1.5 rounded font-semibold text-cyan-300"
                    style={{ background: 'rgba(212,189,85,0.08)', border: '1px solid rgba(212,189,85,0.25)' }}>Exportar CSV</button>
          </div>
        )}
      </div>

      {!isAdmin && (
        <div className="rounded-xl p-5 space-y-3" style={{ ...glass, border: '1px solid rgba(74,222,128,0.18)' }}>
          <p className="text-[10px] font-bold text-green-600 uppercase tracking-wider">{wall?.mine ? 'Tu reporte' : 'Nuevo reporte'}</p>
          <input value={form.title} maxLength={140} onChange={e => { setEditing(true); setForm({ ...form, title: e.target.value }) }}
                 placeholder="Título del hallazgo principal" className={inputCls} style={inputStyle} />
          <textarea value={form.summary} rows={3} maxLength={1500} onChange={e => { setEditing(true); setForm({ ...form, summary: e.target.value }) }}
                    placeholder="Resumen ejecutivo: ¿qué pasó y por qué importa? (2 a 4 frases)" className={inputCls} style={inputStyle} />
          <textarea value={form.evidence} rows={4} maxLength={3000} onChange={e => { setEditing(true); setForm({ ...form, evidence: e.target.value }) }}
                    placeholder="Evidencia: datos concretos que lo sustentan (IPs, hosts, cifras, cruces entre datasets)" className={inputCls} style={inputStyle} />
          <div className="flex items-center gap-2">
            <span className="text-[11px] text-slate-500">Confianza en tu conclusión:</span>
            {['baja', 'media', 'alta'].map(c => (
              <button key={c} onClick={() => { setEditing(true); setForm({ ...form, confidence: c }) }}
                      className="text-[11px] px-3 py-1 rounded font-semibold capitalize"
                      style={form.confidence === c ? { background: `${CONF[c]}22`, border: `1px solid ${CONF[c]}66`, color: CONF[c] }
                                                   : { background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)', color: '#7f8360' }}>{c}</button>
            ))}
          </div>
          <textarea value={form.recommendations} rows={3} maxLength={2000} onChange={e => { setEditing(true); setForm({ ...form, recommendations: e.target.value }) }}
                    placeholder="Recomendaciones priorizadas: ¿qué debería hacer la organización primero?" className={inputCls} style={inputStyle} />
          <div className="flex items-center gap-3">
            <p className="text-[11px] flex-1" style={{ color: msg.startsWith('✓') ? '#4ade80' : '#f87171' }}>{msg}</p>
            <button onClick={save} disabled={saving || !form.title.trim() || !form.summary.trim()}
                    className="px-5 py-2 rounded-lg text-xs font-bold disabled:opacity-40"
                    style={{ background: 'rgba(74,222,128,0.15)', border: '1px solid rgba(74,222,128,0.4)', color: '#4ade80' }}>
              {saving ? 'Guardando...' : wall?.mine ? 'Actualizar reporte' : 'Publicar en el muro'}
            </button>
          </div>
        </div>
      )}

      <div className="space-y-3">
        {(wall?.reports ?? []).filter(r => isAdmin || wall?.open || r.user_email === user?.email).map(r => (
          <div key={r.id} className="rounded-xl p-4 space-y-2" style={{ ...glass, border: r.pinned ? '1px solid rgba(250,204,21,0.4)' : glass.border }}>
            <div className="flex items-center gap-2 flex-wrap">
              {r.pinned ? <span title="Destacado">📌</span> : null}
              <h3 className="text-sm font-semibold text-slate-100 flex-1 min-w-40">{r.title}</h3>
              <span className="text-[10px] font-bold px-2 py-0.5 rounded capitalize"
                    style={{ color: CONF[r.confidence] ?? '#a3a27c', background: `${CONF[r.confidence] ?? '#a3a27c'}18` }}>confianza {r.confidence}</span>
            </div>
            <p className="text-[10px] text-slate-600">{r.user_name} · {new Date(r.updated_at + 'Z').toLocaleString('es-CO')}</p>
            <p className="text-xs text-slate-300 whitespace-pre-line">{r.summary}</p>
            {r.evidence && <div><p className="text-[9px] uppercase tracking-wider text-slate-600">Evidencia</p><p className="text-[11px] text-slate-400 whitespace-pre-line">{r.evidence}</p></div>}
            {r.recommendations && <div><p className="text-[9px] uppercase tracking-wider text-slate-600">Recomendaciones</p><p className="text-[11px] text-slate-400 whitespace-pre-line">{r.recommendations}</p></div>}
            {isAdmin && (
              <div className="flex gap-2 pt-1">
                <button onClick={() => adminCall(`/admin/intel-wall/${r.id}/pin`, { method: 'PATCH', body: JSON.stringify({ pinned: !r.pinned }) })}
                        className="text-[10px] px-2 py-1 rounded text-yellow-400" style={{ border: '1px solid rgba(250,204,21,0.3)' }}>{r.pinned ? 'Quitar destacado' : 'Destacar'}</button>
                <button onClick={() => { if (confirm('¿Eliminar este reporte?')) adminCall(`/admin/intel-wall/${r.id}`, { method: 'DELETE' }) }}
                        className="text-[10px] px-2 py-1 rounded text-red-400" style={{ border: '1px solid rgba(248,113,113,0.3)' }}>Eliminar</button>
              </div>
            )}
          </div>
        ))}
        {wall && wall.reports.length === 0 && (
          <p className="text-xs text-slate-600 text-center py-6">{isAdmin ? 'Aún no hay reportes.' : 'Aún no has publicado tu reporte.'}</p>
        )}
      </div>
    </div>
  )
}

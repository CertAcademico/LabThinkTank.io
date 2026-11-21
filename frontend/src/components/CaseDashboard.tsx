import { useEffect, useState } from 'react'
import { useAuth } from '../contexts/AuthContext'

const API = import.meta.env.VITE_API_URL ?? 'http://127.0.0.1:8000'
const glass = { background: 'rgba(15,23,42,0.55)', backdropFilter: 'blur(16px)', border: '1px solid rgba(255,255,255,0.07)', borderRadius: 12 }

interface Chapter { chapter: number; title: string; status: string; starts_at?: string | null; deadline?: string | null; assigned: number; worked: number; submitted: number; passed: number; avg_score: number | null; dist: number[]; hint_students: number; hints_total: number }
interface Row { name: string; email: string; variant: string; passed: number; current: number | null; current_hints: number; best: number | null; last_activity: string | null; status: string; wall: boolean; reason?: string }
interface Dash {
  kpis: Record<string, number>; chapters: Chapter[]; stuck: Row[]; students: Row[]; events: { t: string; who: string; what: string }[]
  flow: { start: string; active: boolean }; server_time: string
}
const STATUS_COLOR: Record<string, string> = { draft: '#64748b', active: '#4ade80', closed: '#f87171' }
const STATUS_LABEL: Record<string, string> = { draft: 'Borrador', active: 'Activo', closed: 'Cerrado' }
const fmt = (iso?: string | null) => iso ? new Date(iso.includes('T') || iso.includes('Z') ? iso : iso.replace(' ', 'T') + 'Z').toLocaleString('es-CO', { timeZone: 'America/Bogota', day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' }) : '—'
const ago = (iso?: string | null) => {
  if (!iso) return 'sin actividad'
  const m = Math.round((Date.now() - new Date(iso.replace(' ', 'T') + (iso.includes('Z') || iso.includes('+') ? '' : 'Z')).getTime()) / 60000)
  return m < 1 ? 'ahora' : m < 60 ? `hace ${m} min` : `hace ${Math.floor(m / 60)} h ${m % 60} min`
}

function Kpi({ label, value, sub, color }: { label: string; value: string | number; sub?: string; color: string }) {
  return (
    <div className="rounded-xl p-4" style={{ ...glass, background: `linear-gradient(135deg, ${color}14 0%, rgba(15,23,42,0.55) 60%)` }}>
      <p className="text-[9px] font-bold uppercase tracking-wider text-slate-500">{label}</p>
      <p className="text-2xl font-bold mt-1" style={{ color }}>{value}</p>
      {sub && <p className="text-[10px] text-slate-600">{sub}</p>}
    </div>
  )
}
function Bar({ pct, color }: { pct: number; color: string }) {
  return <div className="h-2 rounded bg-white/[0.05] overflow-hidden"><div className="h-full rounded" style={{ width: `${Math.min(100, pct)}%`, background: color }} /></div>
}

export default function CaseDashboard() {
  const { token } = useAuth()
  const [d, setD] = useState<Dash | null>(null)
  const [err, setErr] = useState('')
  const [updated, setUpdated] = useState<Date | null>(null)
  useEffect(() => {
    const load = () => fetch(`${API}/admin/case/aurora/dashboard`, { headers: { Authorization: `Bearer ${token}` } })
      .then(r => r.ok ? r.json() : Promise.reject(new Error('No se pudo cargar el tablero'))).then(x => { setD(x); setUpdated(new Date()); setErr('') }).catch(e => setErr(String(e.message ?? e)))
    load(); const t = setInterval(load, 15_000); return () => clearInterval(t)
  }, [token])

  if (err && !d) return <p className="text-xs text-red-400">{err}</p>
  if (!d) return <p className="text-xs text-slate-600">Cargando tablero…</p>
  const k = d.kpis
  const maxAssigned = Math.max(...d.chapters.map(c => c.assigned), 1)

  return (
    <div className="space-y-5">
      <div className="rounded-xl p-5 flex items-center gap-3 flex-wrap" style={glass}>
        <div className="flex-1 min-w-48">
          <h2 className="text-base font-bold text-slate-100">Tablero del caso — progreso y retos</h2>
          <p className="text-[11px] text-slate-500">Vista exclusiva del admin. Se actualiza cada 15 segundos{updated ? ` · última: ${updated.toLocaleTimeString('es-CO')}` : ''}.</p>
        </div>
        <span className="text-[10px] font-bold px-2 py-1 rounded" style={d.flow.active ? { color: '#4ade80', background: 'rgba(74,222,128,0.12)' } : { color: '#facc15', background: 'rgba(250,204,21,0.1)' }}>
          🏅 Insignias {d.flow.active ? 'activas' : `desde ${fmt(d.flow.start)}`}
        </span>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <Kpi label="Estudiantes en el caso" value={k.students} sub={`${k.working} trabajando · ${k.not_started} sin empezar`} color="#22d3ee" />
        <Kpi label="Entregas" value={k.submissions} sub={`${k.passed_any} estudiantes ya superaron un capítulo`} color="#4ade80" />
        <Kpi label="Insignias otorgadas" value={k.badges} sub={`${k.wall} reportes en el Muro`} color="#facc15" />
        <Kpi label="Pistas pedidas" value={k.hints} sub="en todos los capítulos" color="#a78bfa" />
      </div>

      {d.stuck.length > 0 && (
        <div className="rounded-xl overflow-hidden" style={{ ...glass, border: '1px solid rgba(248,113,113,0.3)' }}>
          <p className="px-5 py-3 text-xs font-bold text-red-300">⚠ Requieren atención ({d.stuck.length})</p>
          {d.stuck.map(s => (
            <div key={s.email} className="px-5 py-2.5 border-t border-white/5 flex items-center gap-3 flex-wrap">
              <div className="min-w-48 flex-1"><p className="text-xs text-slate-200">{s.name}</p><p className="text-[10px] text-slate-500">{s.reason}</p></div>
              <span className="text-[10px] font-mono text-violet-300">{s.variant}</span>
              <span className="text-[10px] text-slate-600">{ago(s.last_activity)}</span>
            </div>
          ))}
        </div>
      )}

      <div className="rounded-xl p-5 space-y-3" style={glass}>
        <p className="text-[10px] font-bold uppercase tracking-wider text-slate-500">Embudo por capítulo</p>
        {d.chapters.map(c => (
          <div key={c.chapter} className="space-y-1.5 pb-3 border-b border-white/5 last:border-0">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-xs text-slate-200 flex-1 min-w-40">{c.chapter}. {c.title.replace(/^Caso Aurora \d — /, '')}</span>
              <span className="text-[10px] font-bold px-2 py-0.5 rounded" style={{ color: STATUS_COLOR[c.status], background: `${STATUS_COLOR[c.status]}18` }}>{STATUS_LABEL[c.status]}</span>
              {c.starts_at && <span className="text-[9px] text-slate-600">abre {fmt(c.starts_at)}</span>}
              {c.deadline && <span className="text-[9px] text-slate-600">cierra {fmt(c.deadline)}</span>}
              {c.avg_score != null && <span className="text-[10px] text-slate-400">nota media <strong className="text-slate-200">{c.avg_score}</strong></span>}
            </div>
            {c.status !== 'draft' && (
              <div className="grid grid-cols-3 gap-3 text-[10px]">
                {([['Trabajaron', c.worked, '#22d3ee'], ['Entregaron', c.submitted, '#facc15'], ['Superaron (≥60)', c.passed, '#4ade80']] as [string, number, string][]).map(([l, v, col]) => (
                  <div key={l}><div className="flex justify-between text-slate-500 mb-0.5"><span>{l}</span><span className="text-slate-300">{v}/{maxAssigned}</span></div><Bar pct={(v / maxAssigned) * 100} color={col} /></div>
                ))}
              </div>
            )}
            {c.submitted > 0 && (
              <div className="flex items-center gap-2 text-[9px] text-slate-600">
                <span>Notas:</span>
                {['0–39', '40–59', '60–79', '80–100'].map((l, i) => <span key={l} className="px-1.5 py-0.5 rounded" style={{ background: 'rgba(255,255,255,0.04)', color: i >= 2 ? '#4ade80' : '#94a3b8' }}>{l}: {c.dist[i]}</span>)}
                <span className="ml-auto">💡 {c.hints_total} pistas · {c.hint_students} estudiantes</span>
              </div>
            )}
          </div>
        ))}
      </div>

      <div className="grid lg:grid-cols-3 gap-5">
        <div className="lg:col-span-2 rounded-xl overflow-x-auto" style={glass}>
          <p className="px-5 py-3 text-[10px] font-bold uppercase tracking-wider text-slate-500">Estudiantes</p>
          <table className="w-full text-xs">
            <thead><tr className="text-[9px] uppercase tracking-wider text-slate-600 text-left"><th className="px-5 py-2">Estudiante</th><th>Variante</th><th>Va en</th><th>Superados</th><th>Pistas</th><th>Última actividad</th></tr></thead>
            <tbody>
              {d.students.map(s => (
                <tr key={s.email} className="border-t border-white/5">
                  <td className="px-5 py-2"><p className="text-slate-200">{s.name}</p></td>
                  <td className="font-mono text-[10px] text-violet-300">{s.variant}</td>
                  <td className="text-slate-400">{s.status === 'completo' ? '✅ completo' : s.current ? `cap. ${s.current}${s.best != null ? ` (mejor ${s.best})` : ''}` : '—'}</td>
                  <td className="text-slate-300 font-bold">{s.passed}</td>
                  <td className="text-yellow-600">{s.current_hints > 0 ? `💡 ${s.current_hints}` : '—'}</td>
                  <td className="text-[10px] text-slate-500">{ago(s.last_activity)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="rounded-xl p-5 space-y-2" style={glass}>
          <p className="text-[10px] font-bold uppercase tracking-wider text-slate-500">Actividad reciente</p>
          {d.events.length === 0 && <p className="text-xs text-slate-600">Sin actividad aún.</p>}
          {d.events.map((e, i) => (
            <div key={i} className="text-[11px] border-t border-white/5 pt-1.5"><p className="text-slate-300"><strong>{e.who}</strong> {e.what}</p><p className="text-[9px] text-slate-600">{ago(e.t)}</p></div>
          ))}
        </div>
      </div>
    </div>
  )
}

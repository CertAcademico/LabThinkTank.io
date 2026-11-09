import { useEffect, useState } from 'react'
import { useAuth } from '../contexts/AuthContext'

const API = import.meta.env.VITE_API_URL ?? 'http://127.0.0.1:8000'
const glass = { background: 'rgba(15,23,42,0.55)', backdropFilter: 'blur(16px)', border: '1px solid rgba(255,255,255,0.07)', borderRadius: 12 }

const TEAM_COLORS: Record<string, { label: string; color: string }> = {
  red:    { label: 'Red',    color: '#ef4444' },
  blue:   { label: 'Blue',   color: '#3b82f6' },
  white:  { label: 'White',  color: '#e2e8f0' },
  purple: { label: 'Purple', color: '#a855f7' },
}

interface Row {
  team_id: number; team: string; color: string; rank: number; points: number; solves: number
  members: { name: string; email: string; points: number; solves: number }[]
  assigned: { id: number; title: string; team_color: string; points: number; difficulty: string; solved: boolean }[]
  solved: { challenge: string; team_color: string; points: number; solved_by: string; solved_at: string }[]
}
interface Announcement { id: number; title: string; body: string; publish_at: string }

function ColorChip({ c }: { c: string }) {
  const t = TEAM_COLORS[c]
  if (!t) return null
  return (
    <span className="text-[8px] font-bold uppercase px-1.5 py-0.5 rounded"
          style={{ color: t.color, background: `${t.color}1a`, border: `1px solid ${t.color}55` }}>{t.label}</span>
  )
}

export function AnnouncementBanner() {
  const { token } = useAuth()
  const [items, setItems] = useState<Announcement[]>([])
  const [hidden, setHidden] = useState<number[]>(() => {
    try { return JSON.parse(localStorage.getItem('cti_ann_hidden') ?? '[]') } catch { return [] }
  })
  useEffect(() => {
    if (!token) return
    const load = () => fetch(`${API}/student/announcements`, { headers: { Authorization: `Bearer ${token}` } })
      .then(r => r.ok ? r.json() : []).then(setItems).catch(() => {})
    load()
    const t = setInterval(load, 60_000) // aparece solo al llegar la hora de publicación
    return () => clearInterval(t)
  }, [token])
  const visible = items.filter(a => !hidden.includes(a.id))
  if (!visible.length) return null
  const dismiss = (id: number) => {
    const next = [...hidden, id]; setHidden(next)
    try { localStorage.setItem('cti_ann_hidden', JSON.stringify(next)) } catch { /* ignore */ }
  }
  return (
    <div className="space-y-2">
      {visible.map(a => (
        <div key={a.id} className="rounded-xl px-4 py-3 flex gap-3 items-start"
             style={{ background: 'rgba(250,204,21,0.08)', border: '1px solid rgba(250,204,21,0.35)' }}>
          <div className="flex-1">
            <p className="text-xs font-bold text-yellow-300">{a.title}</p>
            <p className="text-[11px] text-slate-300 mt-1 whitespace-pre-line">{a.body}</p>
          </div>
          <button onClick={() => dismiss(a.id)} className="text-slate-500 hover:text-slate-300 text-xs">✕</button>
        </div>
      ))}
    </div>
  )
}

export default function CtfScoreboard() {
  const { token, user } = useAuth()
  const [rows, setRows] = useState<Row[]>([])
  const [open, setOpen] = useState<number | null>(null)
  useEffect(() => {
    if (!token) return
    const load = () => fetch(`${API}/student/scoreboard`, { headers: { Authorization: `Bearer ${token}` } })
      .then(r => r.ok ? r.json() : []).then(setRows).catch(() => {})
    load()
    const t = setInterval(load, 30_000)
    return () => clearInterval(t)
  }, [token])
  if (!rows.length) return null
  const max = Math.max(...rows.map(r => r.points), 0)
  const email = (user as { email?: string } | null)?.email

  return (
    <div className="rounded-xl overflow-hidden" style={glass}>
      <div className="px-5 py-3 border-b text-xs font-bold text-slate-500 tracking-widest uppercase"
           style={{ borderColor: 'rgba(255,255,255,0.06)' }}>Scoreboard por equipo</div>
      <div className="divide-y divide-white/5">
        {rows.map(r => {
          const mine = r.members.some(m => m.email === email)
          return (
            <div key={r.team_id} className="px-5 py-3 space-y-2" style={mine ? { background: 'rgba(34,211,238,0.05)' } : undefined}>
              <button className="w-full flex items-center gap-3 text-left" onClick={() => setOpen(open === r.team_id ? null : r.team_id)}>
                <span className="text-[10px] text-slate-600 w-5">#{r.rank}</span>
                <span className="w-2 h-2 rounded-full shrink-0" style={{ background: r.color }} />
                <span className="text-xs text-slate-200 flex-1 truncate">{r.team}{mine && <span className="text-cyan-400 ml-2 text-[9px]">tu equipo</span>}</span>
                <span className="text-[10px] text-slate-500">{r.solves} solves</span>
                <span className="text-xs font-bold text-green-400">{r.points} pts</span>
              </button>
              <div className="h-1.5 rounded-full overflow-hidden bg-white/[0.04]">
                <div className="h-full rounded-full" style={{ width: `${max > 0 ? (r.points / max) * 100 : 0}%`, background: r.color }} />
              </div>
              {open === r.team_id && (
                <div className="grid md:grid-cols-2 gap-3 pt-1">
                  <div>
                    <p className="text-[9px] uppercase tracking-wider text-slate-600 mb-1">Retos asignados</p>
                    {r.assigned.length === 0 && <p className="text-[10px] text-slate-700">Sin retos asignados</p>}
                    {r.assigned.map(a => (
                      <div key={a.id} className="flex items-center gap-2 text-[11px] py-0.5">
                        <ColorChip c={a.team_color} />
                        <span className={a.solved ? 'text-green-400 line-through' : 'text-slate-300'}>{a.title}</span>
                        <span className="ml-auto text-slate-600">{a.points} pts</span>
                      </div>
                    ))}
                  </div>
                  <div>
                    <p className="text-[9px] uppercase tracking-wider text-slate-600 mb-1">Integrantes</p>
                    {r.members.map(m => (
                      <div key={m.email} className="flex items-center gap-2 text-[11px] py-0.5">
                        <span className="text-slate-300">{m.name}</span>
                        <span className="ml-auto text-slate-500">{m.solves} solves · {m.points} pts</span>
                      </div>
                    ))}
                    {r.solved.length > 0 && <p className="text-[9px] uppercase tracking-wider text-slate-600 mt-2 mb-1">Resueltos</p>}
                    {r.solved.map((s, i) => (
                      <div key={i} className="flex items-center gap-2 text-[11px] py-0.5">
                        <ColorChip c={s.team_color} />
                        <span className="text-slate-300 truncate">{s.challenge}</span>
                        <span className="ml-auto text-slate-600 shrink-0">{s.solved_by} · +{s.points}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}

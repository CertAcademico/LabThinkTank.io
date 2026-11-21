import { useEffect, useRef, useState } from 'react'
import { useAuth } from '../contexts/AuthContext'

const API = import.meta.env.VITE_API_URL ?? 'http://127.0.0.1:8000'
interface Data { milestone: { at: string; title: string; message: string } | null; wall_open_at: string | null; wall_open: boolean; server_time: string }

const two = (n: number) => String(n).padStart(2, '0')
const fmtHM = (iso: string) => new Date(iso).toLocaleTimeString('es-CO', { timeZone: 'America/Bogota', hour: 'numeric', minute: '2-digit', hour12: true })

// Reloj con cuenta regresiva hacia un hito del docente (p. ej. la validación del Muro). Usa la hora del servidor, no la del equipo.
export default function MilestoneBar() {
  const { token } = useAuth()
  const [d, setD] = useState<Data | null>(null)
  const [now, setNow] = useState(Date.now())
  const skew = useRef(0)
  useEffect(() => {
    const load = () => fetch(`${API}/student/milestone`, { headers: { Authorization: `Bearer ${token}` } })
      .then(r => r.ok ? r.json() : null).then((x: Data | null) => { if (x) { skew.current = new Date(x.server_time).getTime() - Date.now(); setD(x) } }).catch(() => {})
    load(); const t = setInterval(load, 60_000); return () => clearInterval(t)
  }, [token])
  useEffect(() => { const t = setInterval(() => setNow(Date.now()), 1000); return () => clearInterval(t) }, [])
  if (!d?.milestone) return null
  const at = new Date(d.milestone.at).getTime()
  const left = Math.round((at - (now + skew.current)) / 1000)
  const over = left <= 0
  if (over && left < -30 * 60) return null                      // 30 min después del hito deja de mostrarse
  const abs = Math.abs(left)
  const clock = `${two(Math.floor(abs / 3600))}:${two(Math.floor((abs % 3600) / 60))}:${two(abs % 60)}`
  const color = over ? '#4ade80' : left < 300 ? '#f87171' : left < 900 ? '#fb923c' : '#facc15'
  const wallLeft = d.wall_open_at && !d.wall_open ? Math.round((new Date(d.wall_open_at).getTime() - (now + skew.current)) / 1000) : null

  return (
    <div className="px-5 py-2.5 flex items-center gap-4 flex-wrap" style={{ background: `${color}12`, borderBottom: `1px solid ${color}55` }}>
      <div className="flex items-center gap-2.5">
        <span className="text-lg">⏰</span>
        <div className="font-mono text-xl font-bold tabular-nums leading-none" style={{ color }}>{over ? '+' : ''}{clock}</div>
      </div>
      <div className="flex-1 min-w-56">
        <p className="text-xs font-bold" style={{ color }}>{d.milestone.title} · {fmtHM(d.milestone.at)}{over ? ' — ¡en curso!' : ''}</p>
        <p className="text-[11px] text-slate-300 leading-snug">{d.milestone.message}</p>
      </div>
      {d.wall_open_at && (
        <span className="text-[10px] px-2.5 py-1 rounded font-semibold" style={{ color: d.wall_open ? '#4ade80' : '#94a3b8', background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)' }}>
          {d.wall_open ? '🟢 Muro abierto para todos' : `🔒 El Muro se abre a las ${fmtHM(d.wall_open_at)}${wallLeft && wallLeft > 0 ? ` (en ${Math.ceil(wallLeft / 60)} min)` : ''}`}
        </span>
      )}
    </div>
  )
}

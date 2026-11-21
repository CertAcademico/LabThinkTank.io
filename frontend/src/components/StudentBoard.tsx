import { useEffect, useState } from 'react'
import { useAuth } from '../contexts/AuthContext'

const API = import.meta.env.VITE_API_URL ?? 'http://127.0.0.1:8000'
const glass = { background: 'rgba(15,23,42,0.55)', backdropFilter: 'blur(16px)', border: '1px solid rgba(255,255,255,0.07)', borderRadius: 12 }

interface Col { name: string; kind: 'num' | 'time' | 'text'; nulls: number; distinct: number; min?: number; max?: number; mean?: number; dist?: { value: string; n: number }[]; hist?: { label: string; n: number }[] }
interface Ds { name: string; rows: number; duplicates: number; columns: Col[] }
interface Rel { a: string; col_a: string; b: string; col_b: string; shared: number; how: string }
interface Chap { chapter: number; title: string; status: string; locked: boolean; locked_by?: string | null; score: number | null; hints_used: number; deadline?: string | null; checks: string[] }
interface Board { variant: string; chapters: Chap[]; datasets: Ds[]; relations: Rel[] }

function Bars({ data, color }: { data: { label: string; n: number }[]; color: string }) {
  const max = Math.max(...data.map(d => d.n), 1)
  return (
    <div className="flex items-end gap-1 h-16">
      {data.map(d => (
        <div key={d.label} className="flex-1 flex flex-col items-center justify-end h-full" title={`${d.label}: ${d.n}`}>
          <div className="w-full rounded-t" style={{ height: `${(d.n / max) * 100}%`, minHeight: d.n ? 2 : 0, background: color }} />
        </div>
      ))}
    </div>
  )
}
const fmtN = (n: number) => (Math.abs(n) >= 1e6 ? `${(n / 1e6).toFixed(1)}M` : Math.abs(n) >= 1e3 ? `${(n / 1e3).toFixed(1)}k` : String(n))
const fmtDate = (iso?: string | null) => iso ? new Date(iso).toLocaleString('es-CO', { timeZone: 'America/Bogota', day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' }) : ''

export default function StudentBoard() {
  const { token } = useAuth()
  const [board, setBoard] = useState<Board | null>(null)
  const [err, setErr] = useState('')
  useEffect(() => {
    const load = () => fetch(`${API}/student/case/board`, { headers: { Authorization: `Bearer ${token}` } })
      .then(r => r.ok ? r.json() : Promise.reject(new Error('No se pudo cargar tu tablero'))).then(setBoard).catch(e => setErr(String(e.message ?? e)))
    load(); const t = setInterval(load, 30_000); return () => clearInterval(t)
  }, [token])

  if (err) return <p className="text-xs text-red-400">{err}</p>
  if (!board) return <p className="text-xs text-slate-600">Cargando tu tablero…</p>
  const done = board.chapters.filter(c => c.score != null && c.score >= 60).length

  return (
    <div className="space-y-5 max-w-5xl">
      <div className="rounded-xl p-5 space-y-1" style={glass}>
        <h2 className="text-base font-bold text-slate-100">Mi tablero · Caso Aurora</h2>
        <p className="text-[11px] text-slate-500">
          Aquí ves qué pasa con <strong className="text-slate-300">tus</strong> datos, qué datasets se pueden cruzar y cómo vas. Tu variante es <span className="font-mono text-violet-300">{board.variant}</span>:
          tus datos son distintos a los de tus compañeros. Este tablero te ayuda a entender y explorar; las respuestas las encuentras tú.
        </p>
      </div>

      {board.chapters.length === 0 ? (
        <div className="rounded-xl p-8 text-center" style={glass}><p className="text-sm text-slate-500">Todavía no hay capítulos activos. Tu docente los irá habilitando.</p></div>
      ) : (
        <>
          <div className="rounded-xl p-5 space-y-3" style={glass}>
            <div className="flex items-center gap-2"><p className="text-[10px] font-bold uppercase tracking-wider text-slate-500 flex-1">Mi progreso</p><span className="text-xs font-bold text-cyan-300">{done}/{board.chapters.length} superados</span></div>
            {board.chapters.map(c => (
              <details key={c.chapter} className="rounded-lg" style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.06)' }}>
                <summary className="flex items-center gap-3 px-3 py-2.5 cursor-pointer list-none">
                  <span className="text-[11px] text-slate-200 flex-1 min-w-0 truncate">{c.locked ? '🔒 ' : ''}{c.title.replace(/^Caso Aurora \d — /, `${c.chapter}. `)}</span>
                  {c.hints_used > 0 && <span className="text-[10px] text-yellow-600">💡 {c.hints_used}</span>}
                  {c.deadline && !c.locked && <span className="text-[9px] text-slate-600">cierra {fmtDate(c.deadline)}</span>}
                  <span className="text-[11px] font-bold px-2 py-0.5 rounded min-w-12 text-center"
                        style={c.locked ? { color: '#475569', background: 'rgba(255,255,255,0.03)' } : c.score == null ? { color: '#94a3b8', background: 'rgba(255,255,255,0.05)' }
                          : c.score >= 60 ? { color: '#4ade80', background: 'rgba(74,222,128,0.12)' } : { color: '#facc15', background: 'rgba(250,204,21,0.1)' }}>
                    {c.locked ? 'bloqueado' : c.score == null ? 'sin entrega' : `${c.score}/100`}
                  </span>
                </summary>
                <div className="px-3 pb-3 space-y-1">
                  {c.locked && <p className="text-[10px] text-slate-500">Se desbloquea al sacar 60 o más en «{c.locked_by}».</p>}
                  {!c.locked && c.score != null && c.checks.map((l, i) => (
                    <p key={i} className="text-[11px]" style={{ color: l.startsWith('✓') ? '#4ade80' : l.startsWith('◐') ? '#facc15' : '#94a3b8' }}>{l}</p>
                  ))}
                  {!c.locked && c.score == null && <p className="text-[10px] text-slate-500">Aún no entregas este capítulo. Ve a «Mis Retos» para empezar.</p>}
                </div>
              </details>
            ))}
          </div>

          {board.relations.length > 0 && (
            <div className="rounded-xl p-5 space-y-2" style={glass}>
              <p className="text-[10px] font-bold uppercase tracking-wider text-slate-500">Cruces posibles entre tus datasets</p>
              <p className="text-[11px] text-slate-500">Estas columnas comparten valores. Es donde se esconden las conexiones del caso: prueba a unirlas (merge) o a filtrar una con la otra.</p>
              {board.relations.map((r, i) => (
                <div key={i} className="flex items-center gap-2 text-[11px] flex-wrap">
                  <code className="text-cyan-300 font-mono">{r.a}.{r.col_a}</code><span className="text-slate-600">↔</span>
                  <code className="text-violet-300 font-mono">{r.b}.{r.col_b}</code>
                  <span className="text-slate-500">· {r.shared} {r.how}</span>
                </div>
              ))}
            </div>
          )}

          {board.datasets.map(d => (
            <div key={d.name} className="rounded-xl p-5 space-y-3" style={glass}>
              <div className="flex items-center gap-3 flex-wrap">
                <code className="text-sm font-bold text-cyan-300 font-mono">{d.name}</code>
                <span className="text-[11px] text-slate-500">{d.rows} filas · {d.columns.length} columnas</span>
                <span className="text-[10px] px-2 py-0.5 rounded" style={d.duplicates ? { color: '#facc15', background: 'rgba(250,204,21,0.1)' } : { color: '#4ade80', background: 'rgba(74,222,128,0.1)' }}>
                  {d.duplicates ? `${d.duplicates} filas duplicadas` : 'sin duplicados'}
                </span>
              </div>
              <div className="grid md:grid-cols-2 gap-3">
                {d.columns.map(c => (
                  <div key={c.name} className="rounded-lg p-3 space-y-1.5" style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.05)' }}>
                    <div className="flex items-center gap-2">
                      <code className="text-[11px] font-mono text-slate-200 flex-1 truncate">{c.name}</code>
                      <span className="text-[9px] text-slate-600">{c.kind === 'num' ? 'número' : c.kind === 'time' ? 'fecha/hora' : 'texto'}</span>
                    </div>
                    <p className="text-[10px] text-slate-500">
                      {c.distinct} valores distintos
                      {c.nulls > 0 && <span className="text-amber-400"> · {c.nulls} vacíos ({Math.round(c.nulls / d.rows * 100)}%)</span>}
                    </p>
                    {c.kind === 'num' && c.min != null && <p className="text-[10px] text-slate-400">mín {fmtN(c.min)} · media {fmtN(c.mean ?? 0)} · máx {fmtN(c.max ?? 0)}</p>}
                    {c.hist && c.hist.length > 0 && <><Bars data={c.hist} color="#22d3ee" /><p className="text-[9px] text-slate-700">{c.hist[0].label} → {c.hist[c.hist.length - 1].label}</p></>}
                    {c.dist && <div className="space-y-0.5">{c.dist.map(v => (
                      <div key={v.value} className="flex items-center gap-2 text-[10px]">
                        <span className="w-24 truncate text-slate-400">{v.value}</span>
                        <div className="flex-1 h-1.5 rounded bg-white/[0.05]"><div className="h-full rounded bg-violet-400" style={{ width: `${(v.n / d.rows) * 100}%` }} /></div>
                        <span className="text-slate-600 w-8 text-right">{v.n}</span>
                      </div>))}</div>}
                  </div>
                ))}
              </div>
            </div>
          ))}
        </>
      )}
    </div>
  )
}

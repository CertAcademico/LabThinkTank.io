import { useCallback, useEffect, useState } from 'react'
import { useAuth } from '../contexts/AuthContext'

const API = import.meta.env.VITE_API_URL ?? 'http://127.0.0.1:8000'
const glass = { background: 'rgba(15,23,42,0.55)', backdropFilter: 'blur(16px)', border: '1px solid rgba(255,255,255,0.07)', borderRadius: 12 }
const inputStyle = { background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.1)' }

interface ProgressChapter { chapter: number; title: string; status: string; starts_at?: string | null; deadline?: string | null }
interface ProgressStudent { name: string; email: string; variant: string; wall: boolean; passed: number; chapters: { chapter: number; score: number | null; submitted_at: string | null; hints_used: number }[] }
interface Progress { pass_score?: number; chapters: ProgressChapter[]; students: ProgressStudent[] }
interface GuideChapter {
  chapter: number; title: string; cycle: string; difficulty: string; briefing: string; objective: string; criteria_text: string; hints: string[]; hint_labels?: string[]
  challenge?: { status: string } | null
  dataset: { name: string; rows: number; columns: string[]; preview: Record<string, unknown>[] } | null
  rubric: { label: string; weight: number; hint: string; expected: string }[]
  reference_code: string
}
interface Guide { variant: string; variant_email: string; facts: Record<string, unknown>; truth: { timestamp: string; host: string; usuario: string; fase: string; detalle: string }[]; chapters: GuideChapter[] }

const STATUS_COLOR: Record<string, string> = { draft: '#64748b', active: '#4ade80', closed: '#f87171' }
const STATUS_LABEL: Record<string, string> = { draft: 'Borrador', active: 'Activo', closed: 'Cerrado' }
const fmt = (iso?: string | null) => iso ? new Date(iso).toLocaleString('es-CO', { timeZone: 'America/Bogota', day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' }) : null

function Section({ title, children, color = '#64748b' }: { title: string; children: React.ReactNode; color?: string }) {
  return <div className="space-y-1.5"><p className="text-[10px] font-bold uppercase tracking-wider" style={{ color }}>{title}</p>{children}</div>
}

export default function CaseGuide() {
  const { token, user } = useAuth()
  const headers = { Authorization: `Bearer ${token}` }
  const [view, setView] = useState<'avance' | 'guia'>('avance')
  const [prog, setProg] = useState<Progress | null>(null)
  const [guide, setGuide] = useState<Guide | null>(null)
  const [who, setWho] = useState('')
  const [open, setOpen] = useState<number | null>(1)
  const [err, setErr] = useState('')

  const loadProg = useCallback(() => {
    fetch(`${API}/admin/case/aurora/progress`, { headers }).then(r => r.ok ? r.json() : null).then(setProg).catch(() => {})
  }, [token]) // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => { loadProg(); const t = setInterval(loadProg, 15_000); return () => clearInterval(t) }, [loadProg])

  const loadGuide = useCallback((email: string) => {
    setErr('')
    fetch(`${API}/admin/case/aurora/guide${email ? `?email=${encodeURIComponent(email)}` : ''}`, { headers })
      .then(r => r.ok ? r.json() : Promise.reject(new Error('No se pudo cargar la guía')))
      .then(setGuide).catch(e => setErr(String(e.message ?? e)))
  }, [token]) // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => { if (view === 'guia') loadGuide(who) }, [view, who, loadGuide])

  const pass = prog?.pass_score ?? 50
  const chip = (score: number | null, hints: number) => (
    <div className="flex items-center justify-center gap-1">
      <span className="text-[11px] font-bold px-2 py-0.5 rounded min-w-9 text-center"
            style={score == null ? { color: '#475569', background: 'rgba(255,255,255,0.03)' }
              : score >= pass ? { color: '#4ade80', background: 'rgba(74,222,128,0.12)' } : { color: '#facc15', background: 'rgba(250,204,21,0.1)' }}>{score ?? '—'}</span>
      {hints > 0 && <span title={`${hints} pista(s) pedidas`} className="text-[9px] text-yellow-600">💡{hints}</span>}
    </div>
  )

  return (
    <div className="space-y-4">
      <div className="rounded-xl p-5 space-y-3" style={glass}>
        <div className="flex items-center gap-3 flex-wrap">
          <div className="flex-1 min-w-48">
            <h2 className="text-base font-bold text-slate-100">Guía del docente — Caso Aurora</h2>
            <p className="text-[11px] text-slate-500">Vista exclusiva del admin: el desarrollo de cada capítulo, las soluciones posibles y el avance de cada estudiante. Los estudiantes no ven nada de esto.</p>
          </div>
          {(['avance', 'guia'] as const).map(v => (
            <button key={v} onClick={() => setView(v)} className="text-xs px-4 py-2 rounded-lg font-semibold"
                    style={view === v ? { background: 'rgba(249,115,22,0.12)', border: '1px solid rgba(249,115,22,0.4)', color: '#f97316' }
                                      : { background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)', color: '#64748b' }}>
              {v === 'avance' ? 'Avance de estudiantes' : 'Guía y soluciones'}
            </button>
          ))}
        </div>
      </div>

      {view === 'avance' && (
        <div className="rounded-xl overflow-x-auto" style={glass}>
          {!prog ? <p className="p-5 text-xs text-slate-600">Cargando…</p> : prog.students.length === 0 ? <p className="p-5 text-xs text-slate-600">Aún no hay estudiantes con el caso asignado.</p> : (
            <table className="w-full text-xs">
              <thead>
                <tr className="text-[9px] uppercase tracking-wider text-slate-600">
                  <th className="text-left px-4 py-3">Estudiante</th><th className="px-2">Variante</th>
                  {prog.chapters.map(c => (
                    <th key={c.chapter} className="px-2 py-3 font-semibold" title={c.title}>
                      Cap {c.chapter}<br /><span style={{ color: STATUS_COLOR[c.status] }}>{STATUS_LABEL[c.status]}</span>
                      {c.starts_at && <><br /><span className="text-slate-600 normal-case">abre {fmt(c.starts_at)}</span></>}
                      {c.deadline && <><br /><span className="text-slate-600 normal-case">cierra {fmt(c.deadline)}</span></>}
                    </th>
                  ))}
                  <th className="px-2">Muro</th><th className="px-3">Superados</th>
                </tr>
              </thead>
              <tbody>
                {prog.students.map(s => (
                  <tr key={s.email} className="border-t border-white/5 hover:bg-white/[0.02] cursor-pointer" onClick={() => { setWho(s.email); setView('guia') }} title="Ver la guía con la variante de este estudiante">
                    <td className="px-4 py-2.5"><p className="text-slate-200">{s.name}</p><p className="text-[9px] text-slate-600">{s.email}</p></td>
                    <td className="px-2 text-center text-violet-300 font-mono text-[10px]">{s.variant}</td>
                    {s.chapters.map(c => <td key={c.chapter} className="px-2">{chip(c.score, c.hints_used)}</td>)}
                    <td className="px-2 text-center">{s.wall ? '✅' : <span className="text-slate-700">—</span>}</td>
                    <td className="px-3 text-center font-bold text-slate-300">{s.passed}/{prog.chapters.length}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          <p className="px-4 py-2 text-[9px] text-slate-700 border-t border-white/5">Verde = {pass} o más (supera el capítulo) · 💡 = pistas pedidas · Clic en un estudiante para ver la guía con su variante · se actualiza cada 15 s</p>
        </div>
      )}

      {view === 'guia' && (
        <>
          <div className="rounded-xl p-4 flex items-center gap-3 flex-wrap" style={glass}>
            <label className="text-[11px] text-slate-500">Ver el caso con la variante de:</label>
            <select value={who || guide?.variant_email || ''} onChange={e => setWho(e.target.value)} className="rounded px-2 py-1.5 text-[11px] text-slate-200 min-w-64" style={inputStyle}>
              <option value={user?.email ?? ''} className="bg-slate-900">Mi variante de ejemplo ({user?.email})</option>
              {(prog?.students ?? []).map(s => <option key={s.email} value={s.email} className="bg-slate-900">{s.name} — {s.variant}</option>)}
            </select>
            {guide && <span className="text-[11px] text-violet-300 font-mono">Variante {guide.variant}</span>}
          </div>
          {err && <p className="text-xs text-red-400">{err}</p>}
          {!guide ? <p className="text-xs text-slate-600 px-1">Cargando guía…</p> : (
            <>
              <div className="rounded-xl p-5 space-y-3" style={glass}>
                <Section title="Lo que realmente pasó en esta variante (la «verdad» del caso)" color="#f87171">
                  <div className="overflow-x-auto"><table className="w-full text-[11px]"><thead><tr className="text-[9px] uppercase text-slate-600 text-left"><th className="pr-3">Hora</th><th className="pr-3">Host</th><th className="pr-3">Cuenta</th><th className="pr-3">Fase</th><th>Detalle</th></tr></thead>
                    <tbody>{guide.truth.map((t, i) => <tr key={i} className="border-t border-white/5 text-slate-300 align-top"><td className="pr-3 py-1 whitespace-nowrap text-slate-500">{t.timestamp}</td><td className="pr-3 font-mono text-cyan-300">{t.host}</td><td className="pr-3 font-mono">{t.usuario}</td><td className="pr-3 text-orange-300">{t.fase}</td><td className="text-slate-400">{t.detalle}</td></tr>)}</tbody></table></div>
                </Section>
                <Section title="Datos clave de esta variante" color="#a78bfa">
                  <div className="grid sm:grid-cols-2 gap-x-6 gap-y-1 text-[11px]">
                    {Object.entries(guide.facts).filter(([k]) => !['siblings', 'lateral_path', 'vector_text'].includes(k)).map(([k, v]) => (
                      <div key={k} className="flex gap-2 border-b border-white/5 py-0.5"><span className="text-slate-600 w-40 shrink-0">{k}</span><span className="text-slate-300 font-mono break-all">{String(v)}</span></div>
                    ))}
                    <div className="flex gap-2 border-b border-white/5 py-0.5 sm:col-span-2"><span className="text-slate-600 w-40 shrink-0">ruta lateral</span><span className="text-slate-300 font-mono">{(guide.facts.lateral_path as string[]).join(' → ')}</span></div>
                    <div className="flex gap-2 border-b border-white/5 py-0.5 sm:col-span-2"><span className="text-slate-600 w-40 shrink-0">dominios hermanos</span><span className="text-slate-300 font-mono break-all">{(guide.facts.siblings as string[]).join(', ')}</span></div>
                  </div>
                </Section>
              </div>

              {guide.chapters.map(c => {
                const isOpen = open === c.chapter
                const st = c.challenge?.status ?? 'draft'
                return (
                  <div key={c.chapter} className="rounded-xl overflow-hidden" style={glass}>
                    <button className="w-full flex items-center gap-3 px-5 py-4 text-left hover:bg-white/[0.02]" onClick={() => setOpen(isOpen ? null : c.chapter)}>
                      <span className="text-sm font-bold text-slate-100 flex-1">{c.title}</span>
                      <span className="text-[10px] text-violet-300">Ciclo: {c.cycle}</span>
                      <span className="text-[10px] font-bold px-2 py-0.5 rounded" style={{ color: STATUS_COLOR[st], background: `${STATUS_COLOR[st]}18` }}>{STATUS_LABEL[st]}</span>
                      <span className="text-slate-600">{isOpen ? '▲' : '▼'}</span>
                    </button>
                    {isOpen && (
                      <div className="px-5 pb-5 space-y-4 border-t border-white/5 pt-4">
                        <Section title="Expediente (lo que lee el estudiante)"><p className="text-xs text-slate-300 whitespace-pre-line">{c.briefing}</p></Section>
                        <Section title="Misión"><p className="text-xs text-slate-400 whitespace-pre-line">{c.objective}</p></Section>
                        {c.dataset && (
                          <Section title={`Datos de este capítulo · ${c.dataset.name} (${c.dataset.rows} filas)`} color="#22d3ee">
                            <div className="overflow-x-auto rounded-lg" style={{ background: '#050a14' }}>
                              <table className="text-[10px] w-full"><thead><tr className="text-slate-500 text-left">{c.dataset.columns.map(k => <th key={k} className="px-2 py-1.5 whitespace-nowrap">{k}</th>)}</tr></thead>
                                <tbody>{c.dataset.preview.map((r, i) => <tr key={i} className="border-t border-white/5 text-slate-300">{c.dataset!.columns.map(k => <td key={k} className="px-2 py-1 whitespace-nowrap max-w-64 truncate">{String(r[k] ?? '')}</td>)}</tr>)}</tbody></table>
                            </div>
                            <p className="text-[9px] text-slate-700">Se muestran las primeras 8 filas.</p>
                          </Section>
                        )}
                        <Section title="Pistas graduales (el estudiante las pide de a una)" color="#facc15">
                          {c.hints.map((h, i) => (
                            <div key={i} className="rounded-lg p-3" style={{ background: 'rgba(250,204,21,0.04)', border: '1px solid rgba(250,204,21,0.12)' }}>
                              <p className="text-[9px] font-bold text-yellow-600 uppercase tracking-wider mb-1">{i + 1} · {c.hint_labels?.[i] ?? `Pista ${i + 1}`}</p>
                              {['Esqueleto de código', 'Solución de referencia', 'Plantilla de informe', 'Lo mínimo para pasar'].includes(c.hint_labels?.[i] ?? '') ? <pre className="text-[11px] text-green-300 whitespace-pre-wrap font-mono">{h}</pre> : <p className="text-[11px] text-slate-300">{h}</p>}
                            </div>
                          ))}
                        </Section>
                        <Section title="Rúbrica y respuesta esperada (para esta variante)" color="#4ade80">
                          {c.rubric.map((r, i) => (
                            <div key={i} className="py-1.5 border-t border-white/5 text-[11px]">
                              <div className="flex gap-2"><span className="flex-1 text-slate-300">{r.label}</span><span className="text-slate-600">{r.weight} pts</span></div>
                              <p className="text-green-300 break-words">✔ {r.expected}</p>
                            </div>
                          ))}
                        </Section>
                        <Section title={c.chapter === 8 ? 'Informe de ejemplo' : 'Solución de referencia (Python)'} color="#4ade80">
                          <pre className="text-[11px] text-green-300 whitespace-pre-wrap font-mono rounded-lg p-3" style={{ background: '#050a14' }}>{c.reference_code}</pre>
                        </Section>
                      </div>
                    )}
                  </div>
                )
              })}
            </>
          )}
        </>
      )}
    </div>
  )
}

import { useState } from 'react'

export interface Learn {
  fase?: string; por_que?: string; aprenderas?: string[]; conceptos?: [string, string][]; exito?: string; reflexion?: string[]
  ciclo?: [string, string][]
}

const PHASE_COLOR = ['#7f8360', '#d4bd55', '#93a954', '#f97316', '#4ade80', '#facc15']

// «Antes de empezar»: dónde estás en el ciclo de inteligencia, qué vas a aprender, glosario y cómo sabrás que lo lograste.
export default function CasePrimer({ learn, storageKey }: { learn?: Learn; storageKey: string }) {
  const [open, setOpen] = useState(() => { try { return localStorage.getItem(storageKey) !== 'closed' } catch { return true } })
  const [term, setTerm] = useState<number | null>(null)
  if (!learn || !learn.aprenderas) return null
  const toggle = () => { const n = !open; setOpen(n); try { localStorage.setItem(storageKey, n ? 'open' : 'closed') } catch { /* ok */ } }
  const here = (learn.fase ?? '').split(' ')[0]
  const cycle = learn.ciclo ?? []
  const phaseIdx = cycle.findIndex(([n]) => n === here)

  return (
    <div className="rounded-xl overflow-hidden" style={{ background: 'rgba(26,31,19,0.55)', border: '1px solid rgba(147,169,84,0.25)' }}>
      <button onClick={toggle} className="w-full flex items-center gap-2 px-4 py-3 text-left hover:bg-white/[0.02]">
        <span className="text-xs font-bold text-violet-300 flex-1">📚 Antes de empezar</span>
        <span className="text-[10px] text-slate-600">{open ? 'ocultar' : 'mostrar'}</span>
      </button>
      {open && (
        <div className="px-4 pb-4 space-y-4">
          {cycle.length > 0 && (
            <div className="space-y-1.5">
              <p className="text-[10px] font-bold uppercase tracking-wider text-slate-500">Dónde estás en el ciclo de inteligencia</p>
              <div className="flex gap-1 flex-wrap">
                {cycle.map(([name], i) => {
                  const isHere = name === here
                  return (
                    <div key={name} className="flex-1 min-w-24 rounded-md px-2 py-1.5 text-center text-[10px] font-semibold"
                         style={isHere ? { background: `${PHASE_COLOR[i]}22`, border: `1px solid ${PHASE_COLOR[i]}`, color: PHASE_COLOR[i] }
                                       : { background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.06)', color: '#5f6646' }}>
                      {i + 1}. {name}{isHere ? ' ← aquí' : ''}
                    </div>
                  )
                })}
              </div>
              {phaseIdx >= 0 && <p className="text-[11px] text-slate-400"><strong style={{ color: PHASE_COLOR[phaseIdx] }}>{cycle[phaseIdx][0]}:</strong> {cycle[phaseIdx][1]}</p>}
            </div>
          )}
          {learn.por_que && <p className="text-xs text-slate-300 leading-relaxed"><strong className="text-slate-200">Por qué importa: </strong>{learn.por_que}</p>}
          <div className="space-y-1">
            <p className="text-[10px] font-bold uppercase tracking-wider text-slate-500">Al terminar sabrás…</p>
            <ul className="space-y-0.5">{learn.aprenderas.map((a, i) => <li key={i} className="text-[11px] text-slate-400 flex gap-2"><span className="text-violet-400">▸</span>{a}</li>)}</ul>
          </div>
          {learn.conceptos && learn.conceptos.length > 0 && (
            <div className="space-y-1.5">
              <p className="text-[10px] font-bold uppercase tracking-wider text-slate-500">Glosario de este capítulo <span className="normal-case text-slate-700">(toca un término)</span></p>
              <div className="flex gap-1.5 flex-wrap">
                {learn.conceptos.map(([t], i) => (
                  <button key={t} onClick={() => setTerm(term === i ? null : i)} className="text-[10px] px-2 py-1 rounded font-semibold"
                          style={term === i ? { background: 'rgba(147,169,84,0.2)', border: '1px solid rgba(147,169,84,0.5)', color: '#c4b5fd' }
                                            : { background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)', color: '#a3a27c' }}>{t}</button>
                ))}
              </div>
              {term !== null && <p className="text-[11px] text-slate-300 rounded-lg p-3" style={{ background: 'rgba(147,169,84,0.07)' }}>{learn.conceptos[term][1]}</p>}
            </div>
          )}
          {learn.exito && <p className="text-[11px] text-green-300 rounded-lg p-3" style={{ background: 'rgba(74,222,128,0.06)', border: '1px solid rgba(74,222,128,0.15)' }}>✔ {learn.exito}</p>}
          {learn.reflexion && learn.reflexion.length > 0 && (
            <div className="space-y-1">
              <p className="text-[10px] font-bold uppercase tracking-wider text-yellow-600">Para pensar (y para el diálogo de la tarde)</p>
              {learn.reflexion.map((q, i) => <p key={i} className="text-[11px] text-slate-400">❓ {q}</p>)}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

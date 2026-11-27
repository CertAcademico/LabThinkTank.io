import { useState, type ReactNode } from 'react'
import { BRIEFINGS, DOMAINS, METHODS, PASS_SCORE, PHASES, PHASE_COLOR, RANKS, ROUTE, distintivoName } from '../data/orionBriefings'
import OrionLogo, { GotecLogo } from './OrionLogo'
import { Distintivo, RankInsignia } from './MilitaryInsignia'
import { DomainChips } from './MissionBriefing'
import TeacherDeck from './TeacherDeck'

const GOLD = '#d4bd55'
const box = { background: 'rgba(26,31,19,0.6)', border: '1px solid rgba(212,189,85,0.22)', borderRadius: 12 }

export interface ProgramChallenge {
  id: number; title: string; difficulty?: string; submitted: number; my_score?: number; min_score_badge?: number; badge_earned?: number
  locked?: boolean
}

const CICLO = ['Planear (PIR)', 'Recolectar', 'Procesar', 'Analizar', 'Difundir (BLUF · TLP)', 'Retroalimentar']
const PASOS = [
  ['🎯', 'Lee la ficha táctica', 'Misión, metodología y dossier del dataset.'],
  ['🎓', 'Ve la presentación del reto', 'Conceptos, marco y preguntas guía.'],
  ['💡', 'Pide pistas por niveles', '5 niveles: de la orientación al esqueleto de código.'],
  ['🤖', 'Consulta al asistente', 'Dudas de Python o del método, dentro de la arena.'],
  ['💬', 'Escribe al instructor', 'Canal del grupo ORION.'],
  ['📤', 'Entrega tu informe BLUF', `Aprueba con ${PASS_SCORE}/100; el distintivo exige la nota indicada.`],
]

/** Vista de «Mis Retos» para integrantes del programa ORION: metodología, escalafón, ruta por fases y chat. */
export default function OrionProgram({ challenges, onOpen, chat }:
  { challenges: ProgramChallenge[]; onOpen: (id: number) => void; chat?: ReactNode }) {
  const [deck, setDeck] = useState(false)
  const byId = new Map(challenges.map(c => [c.id, c]))
  const approved = challenges.filter(c => (c.my_score ?? -1) >= PASS_SCORE).length
  const hasDistintivo = (c: ProgramChallenge) => Boolean(c.badge_earned) || (c.my_score != null && c.my_score >= (c.min_score_badge ?? 70))
  const distintivos = challenges.filter(hasDistintivo).length
  const rank = Math.min(approved, RANKS.length - 1)

  return (
    <div className="space-y-4">
      {deck && <TeacherDeck audience="estudiante" onClose={() => setDeck(false)} />}

      {/* Encabezado + escalafón */}
      <div className="p-5" style={box}>
        <div className="flex flex-wrap items-center gap-4">
          <GotecLogo height={40} />
          <OrionLogo size={52} />
          <div className="flex-1 min-w-[200px]">
            <p className="text-[10px] font-bold tracking-[0.25em]" style={{ color: GOLD }}>PROGRAMA ORION · CCOCI</p>
            <h2 className="text-xl font-bold text-slate-100">Entrenamiento táctico en Ciberinteligencia</h2>
            <p className="text-xs text-slate-500">{challenges.length} retos en 4 fases · {challenges.filter(c => !c.locked).length} habilitados por el instructor · con pistas, asistente y canal con el instructor</p>
          </div>
          <div className="flex items-center gap-3 rounded-xl px-4 py-2" style={{ background: 'rgba(212,189,85,0.07)', border: '1px solid rgba(212,189,85,0.3)' }}>
            <RankInsignia level={rank} size={58} />
            <div>
              <p className="text-[9px] font-bold uppercase tracking-widest text-slate-500">Tu grado</p>
              <p className="text-lg font-bold" style={{ color: GOLD }}>{RANKS[rank]}</p>
              <p className="text-[10px] text-slate-400">{approved}/{challenges.length} aprobados · {distintivos} distintivos</p>
            </div>
          </div>
        </div>
        <div className="mt-4 h-2 rounded-full overflow-hidden bg-white/[0.05]">
          <div className="h-full rounded-full" style={{ width: `${(approved / Math.max(challenges.length, 1)) * 100}%`, background: GOLD }} />
        </div>
        <div className="mt-3 flex items-end gap-1 overflow-x-auto pb-1">
          {RANKS.map((r, i) => (
            <div key={r} className="flex flex-col items-center gap-1 min-w-[58px]" style={{ opacity: i <= rank ? 1 : 0.35 }}>
              <RankInsignia level={i} size={i === rank ? 34 : 26} />
              <span className="text-[8px] text-center leading-tight" style={{ color: i === rank ? GOLD : '#7f8360' }}>{r}</span>
            </div>
          ))}
        </div>
        {rank < RANKS.length - 1 && (
          <p className="mt-2 text-[10px] text-slate-500">Próximo grado: <b className="text-slate-300">{RANKS[rank + 1]}</b> — aprueba un reto más con {PASS_SCORE}/100 o más.</p>
        )}
      </div>

      {/* Metodología del entrenamiento */}
      <div className="p-5 space-y-4" style={box}>
        <div className="flex flex-wrap items-center gap-3">
          <p className="flex-1 text-[11px] font-bold uppercase tracking-wider" style={{ color: GOLD }}>🧭 Metodología del entrenamiento</p>
          <button onClick={() => setDeck(true)} className="rounded-lg px-3 py-1.5 text-[11px] font-semibold"
                  style={{ background: 'rgba(212,189,85,0.15)', border: '1px solid rgba(212,189,85,0.45)', color: '#e0cf74' }}>
            🎓 Presentación del programa
          </button>
        </div>
        <div>
          <p className="text-[9px] font-bold uppercase tracking-wider text-slate-500 mb-1.5">Ciclo de inteligencia — el hilo de cada reto</p>
          <div className="flex flex-wrap items-center gap-1.5">
            {CICLO.map((c, i) => (
              <span key={c} className="flex items-center gap-1.5">
                <span className="text-[10px] px-2 py-1 rounded-md text-slate-200" style={{ background: 'rgba(147,169,84,0.12)', border: '1px solid rgba(147,169,84,0.3)' }}>{i + 1}. {c}</span>
                {i < CICLO.length - 1 && <span className="text-slate-600 text-[10px]">→</span>}
              </span>
            ))}
          </div>
        </div>
        <div className="grid gap-2 md:grid-cols-3">
          {Object.values(DOMAINS).map(d => (
            <div key={d.label} className="rounded-lg p-3" style={{ background: `${d.color}0d`, border: `1px solid ${d.color}40` }}>
              <p className="text-xs font-bold" style={{ color: d.color }}>{d.icon} {d.label}</p>
              <p className="text-[11px] text-slate-400 mt-1 leading-relaxed">{d.desc}</p>
            </div>
          ))}
        </div>
        <div>
          <p className="text-[9px] font-bold uppercase tracking-wider text-slate-500 mb-1.5">Marcos que se aplican en la ruta</p>
          <div className="flex flex-wrap gap-1.5">
            {Object.values(METHODS).map(m => (
              <span key={m.name} title={m.short} className="text-[10px] px-2 py-0.5 rounded-full text-slate-300" style={{ border: '1px solid rgba(255,255,255,0.12)' }}>{m.name}</span>
            ))}
          </div>
        </div>
        <div>
          <p className="text-[9px] font-bold uppercase tracking-wider text-slate-500 mb-1.5">Cómo trabajar cada reto (ayudas disponibles)</p>
          <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
            {PASOS.map(([ic, t, d], i) => (
              <div key={t} className="flex gap-2 rounded-lg p-2.5" style={{ background: 'rgba(255,255,255,0.03)' }}>
                <span className="text-base">{ic}</span>
                <div><p className="text-[11px] font-semibold text-slate-200">{i + 1}. {t}</p><p className="text-[10px] text-slate-500">{d}</p></div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {chat}

      {/* Ruta táctica por fases */}
      {ROUTE.map(({ phase, ids }) => {
        const items = ids.map(id => byId.get(id)).filter((c): c is ProgramChallenge => Boolean(c))
        if (!items.length) return null
        const pc = PHASE_COLOR[phase]
        return (
          <div key={phase} className="space-y-2">
            <div className="flex items-center gap-3">
              <span className="text-[11px] font-bold tracking-[0.2em]" style={{ color: pc }}>{PHASES[phase].name.toUpperCase()}</span>
              <span className="text-[10px] text-slate-500">{PHASES[phase].focus}</span>
              <span className="flex-1 h-px" style={{ background: `${pc}40` }} />
            </div>
            {items.map(c => {
              const b = BRIEFINGS[c.id]
              const ok = (c.my_score ?? -1) >= PASS_SCORE
              const dist = hasDistintivo(c)
              return (
                <div key={c.id} onClick={() => { if (!c.locked) onOpen(c.id) }}
                     className={`rounded-xl p-4 flex gap-4 items-start transition-colors ${c.locked ? 'opacity-55 cursor-not-allowed' : 'cursor-pointer hover:bg-white/[0.02]'}`}
                     style={{ background: 'rgba(26,31,19,0.55)', border: `1px solid ${ok ? `${pc}55` : 'rgba(255,255,255,0.07)'}` }}>
                  <Distintivo id={c.id} phase={phase} earned={dist} size={52} />
                  <div className="flex-1 min-w-0 space-y-1.5">
                    <p className="text-[10px] font-mono tracking-widest" style={{ color: pc }}>RETO {String(c.id).padStart(2, '0')} · {b?.codename}</p>
                    <h3 className="text-sm font-bold text-slate-100">{c.title}</h3>
                    <DomainChips id={c.id} />
                    {b && <p className="text-[11px] text-slate-400 line-clamp-2">{b.pir}</p>}
                    <div className="flex flex-wrap items-center gap-2 pt-0.5">
                      {c.difficulty && <span className="text-[9px] px-1.5 py-0.5 rounded text-slate-400" style={{ border: '1px solid rgba(255,255,255,0.1)' }}>{c.difficulty}</span>}
                      <span className="text-[9px] px-1.5 py-0.5 rounded font-semibold"
                            style={dist ? { color: pc, border: `1px solid ${pc}66`, background: `${pc}14` } : { color: '#7f8360', border: '1px solid rgba(127,131,96,0.3)' }}>
                        🎖️ {distintivoName(c.id)} · ≥{c.min_score_badge ?? 70} pts{dist ? ' · ganado' : ''}
                      </span>
                    </div>
                  </div>
                  <div className="shrink-0 text-right space-y-1">
                    {c.locked
                      ? <><span className="text-[10px] font-bold px-2 py-0.5 rounded" style={{ color: '#a3a27c', border: '1px solid rgba(163,162,124,0.3)' }}>🔒 Bloqueado</span>
                          <p className="text-[10px] text-slate-600 max-w-[150px]">Se habilita cuando el instructor lo indique</p></>
                      : c.submitted > 0
                      ? <span className="text-[10px] font-bold px-2 py-0.5 rounded" style={ok
                          ? { background: 'rgba(74,222,128,0.1)', color: '#4ade80', border: '1px solid rgba(74,222,128,0.25)' }
                          : { background: 'rgba(250,204,21,0.08)', color: '#facc15', border: '1px solid rgba(250,204,21,0.25)' }}>
                          {ok ? '✓ Aprobado' : 'Entregado'}{c.my_score != null ? ` · ${c.my_score}/100` : ''}
                        </span>
                      : <span className="text-[10px] font-bold px-2 py-0.5 rounded" style={{ color: '#facc15', border: '1px solid rgba(250,204,21,0.2)' }}>Pendiente</span>}
                    {!c.locked && <p className="text-[10px] text-slate-600">Abrir arena →</p>}
                  </div>
                </div>
              )
            })}
          </div>
        )
      })}
    </div>
  )
}

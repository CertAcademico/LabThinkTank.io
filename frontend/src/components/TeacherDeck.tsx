import { useEffect, useMemo, useState, type ReactNode } from 'react'
import { createPortal } from 'react-dom'
import { BRIEFINGS, DOMAINS, METHODS, ORION_INTRO, PHASES } from '../data/orionBriefings'
import OrionLogo, { GotecLogo } from './OrionLogo'

const GOLD = '#d4bd55'

interface Slide { kicker: string; title: string; body: ReactNode; teacherOnly?: boolean }

const List = ({ items }: { items: ReactNode[] }) => (
  <ul className="space-y-4 text-xl md:text-2xl text-slate-200 leading-snug">
    {items.map((x, i) => (
      <li key={i} className="flex gap-3"><span style={{ color: GOLD }}>▸</span><span>{x}</span></li>
    ))}
  </ul>
)

function buildSlides(retoId: number | undefined, title: string, criteria: string): Slide[] {
  if (retoId == null || !BRIEFINGS[retoId]) {
    return ORION_INTRO.map((s, i) => ({
      kicker: `Programa ORION · ${i + 1}/${ORION_INTRO.length}`, title: s.title,
      body: <><p className="text-2xl mb-6" style={{ color: '#aec174' }}>{s.subtitle}</p><List items={s.bullets} /></>,
    }))
  }
  const b = BRIEFINGS[retoId]
  const n = String(retoId).padStart(2, '0')
  const total = b.teacher.flow.reduce((a, f) => a + f.min, 0)
  return [
    { kicker: `Reto ${n} · ${PHASES[b.phase].name}`, title,
      body: (
        <div className="space-y-6">
          <p className="text-3xl font-mono tracking-widest" style={{ color: GOLD }}>{b.codename}</p>
          <div className="flex flex-wrap gap-3">
            {b.domains.map(d => (
              <span key={d} className="text-xl px-3 py-1 rounded-lg"
                    style={{ color: DOMAINS[d].color, border: `1px solid ${DOMAINS[d].color}66` }}>
                {DOMAINS[d].icon} {DOMAINS[d].label}
              </span>
            ))}
          </div>
          <p className="text-2xl text-slate-300">Tema: {b.teacher.tema}</p>
        </div>
      ) },
    { kicker: 'Situación táctica', title: 'Escenario y requerimiento',
      body: (
        <div className="space-y-6">
          <p className="text-2xl text-slate-200 leading-relaxed">{b.scenario}</p>
          <div className="rounded-xl p-5" style={{ background: 'rgba(212,189,85,0.08)', borderLeft: `4px solid ${GOLD}` }}>
            <p className="text-2xl font-semibold text-slate-100">{b.pir}</p>
            <p className="text-xl text-slate-400 mt-2">Producto: {b.product}</p>
          </div>
          <p className="text-xl text-slate-400">Actores: <span className="text-orange-300">{b.actors.join(' · ')}</span></p>
        </div>
      ) },
    { kicker: 'Explicación del tema', title: 'Conceptos clave',
      body: (
        <div className="grid gap-4 md:grid-cols-3">
          {b.teacher.concepts.map(c => (
            <div key={c.t} className="rounded-xl p-5" style={{ background: 'rgba(147,169,84,0.08)', border: '1px solid rgba(147,169,84,0.25)' }}>
              <p className="text-2xl font-bold mb-2" style={{ color: GOLD }}>{c.t}</p>
              <p className="text-xl text-slate-300 leading-relaxed">{c.d}</p>
            </div>
          ))}
        </div>
      ) },
    { kicker: 'Marco metodológico', title: 'Metodologías del reto',
      body: (
        <div className="space-y-4">
          {b.methods.map(m => METHODS[m] && (
            <div key={m}>
              <p className="text-2xl font-bold text-slate-100">{METHODS[m].name}</p>
              <p className="text-xl font-mono" style={{ color: '#aec174' }}>{METHODS[m].short}</p>
              <p className="text-xl text-slate-400">{METHODS[m].detail}</p>
            </div>
          ))}
        </div>
      ) },
    { kicker: 'Dossier del dataset', title: `${b.dataset.rows} registros · ${b.dataset.origin}`,
      body: (
        <div className="space-y-5">
          <p className="text-xl text-slate-300">Cada fila es: {b.dataset.grain}</p>
          <div className="flex flex-wrap gap-2">
            {Object.keys(b.dataset.columns).map(c => (
              <span key={c} className="font-mono text-base px-2 py-1 rounded text-cyan-300" style={{ background: 'rgba(255,255,255,0.05)' }}>{c}</span>
            ))}
          </div>
          <p className="text-xl font-bold text-green-400">Qué deben buscar</p>
          <List items={b.dataset.lookFor} />
        </div>
      ) },
    { kicker: 'Conducción de la clase', title: `Guion de la sesión · ${total} min`,
      body: (
        <div className="space-y-5">
          {b.teacher.flow.map((f, i) => (
            <div key={i} className="flex items-center gap-4 text-xl">
              <span className="w-20 shrink-0 text-right font-mono" style={{ color: GOLD }}>{f.min} min</span>
              <div className="w-56 shrink-0 h-3 rounded" style={{ background: 'rgba(255,255,255,0.06)' }}>
                <div className="h-3 rounded" style={{ width: `${(f.min / total) * 100}%`, minWidth: 12, background: 'rgba(212,189,85,0.55)' }} />
              </div>
              <span className="text-slate-200">{f.step}</span>
            </div>
          ))}
        </div>
      ) },
    { kicker: 'Discusión guiada', title: 'Preguntas para el grupo', body: <List items={b.teacher.questions} /> },
    { kicker: 'Solo docente', title: 'Respuestas esperadas', teacherOnly: true,
      body: <><List items={b.teacher.expected} /><p className="text-base text-slate-500 mt-6">Calculadas sobre el dataset real de la plataforma. No proyectar ante el grupo antes de la entrega.</p></> },
    { kicker: 'Evaluación', title: 'Errores comunes y criterios',
      body: (
        <div className="grid gap-6 md:grid-cols-2">
          <div><p className="text-xl font-bold text-yellow-400 mb-3">⚠ Errores comunes</p><List items={[...b.teacher.errors, ...b.dataset.pitfalls]} /></div>
          <div><p className="text-xl font-bold mb-3" style={{ color: GOLD }}>Criterios de calificación</p>
            <List items={criteria ? criteria.split(/\s\+\s/) : ['Ver criterios del reto']} />
            <p className="text-base text-slate-500 mt-4">Nota mínima aprobatoria: 50/100.</p></div>
        </div>
      ) },
  ]
}

/** Presentación a pantalla completa para el docente. Sin retoId muestra la introducción general del programa. */
export default function TeacherDeck({ retoId, title = '', criteria = '', onClose }:
  { retoId?: number; title?: string; criteria?: string; onClose: () => void }) {
  const slides = useMemo(() => buildSlides(retoId, title, criteria), [retoId, title, criteria])
  const [i, setI] = useState(0)
  const [hideAnswers, setHideAnswers] = useState(true)
  const s = slides[i]

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
      else if (e.key === 'ArrowRight' || e.key === 'PageDown' || e.key === ' ') { e.preventDefault(); setI(v => Math.min(v + 1, slides.length - 1)) }
      else if (e.key === 'ArrowLeft' || e.key === 'PageUp') setI(v => Math.max(v - 1, 0))
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [slides.length, onClose])

  const fullscreen = () => {
    const el = document.documentElement
    if (document.fullscreenElement) document.exitFullscreen().catch(() => {})
    else el.requestFullscreen?.().catch(() => {})
  }

  return createPortal(
    <div className="fixed inset-0 z-[100] flex flex-col"
         style={{ background: 'radial-gradient(ellipse at top, #1f2616 0%, #0e110a 70%)' }}>
      {/* Barra superior */}
      <div className="flex items-center gap-3 px-6 py-3 border-b" style={{ borderColor: 'rgba(212,189,85,0.2)' }}>
        <OrionLogo size={34} />
        <div className="flex-1 min-w-0">
          <p className="text-xs font-bold tracking-[0.25em]" style={{ color: GOLD }}>ORION · CCOCI</p>
          <p className="text-[11px] text-slate-500 truncate">{s.kicker}</p>
        </div>
        <GotecLogo height={28} />
        {s.teacherOnly && (
          <button onClick={() => setHideAnswers(h => !h)} className="text-xs px-3 py-1.5 rounded-lg"
                  style={{ border: '1px solid rgba(250,204,21,0.4)', color: '#facc15' }}>
            {hideAnswers ? 'Mostrar respuestas' : 'Ocultar respuestas'}
          </button>
        )}
        <button onClick={fullscreen} className="text-xs px-3 py-1.5 rounded-lg text-slate-300" style={{ border: '1px solid rgba(255,255,255,0.15)' }}>⛶ Pantalla completa</button>
        <button onClick={onClose} className="text-xs px-3 py-1.5 rounded-lg text-slate-300" style={{ border: '1px solid rgba(255,255,255,0.15)' }}>✕ Cerrar (Esc)</button>
      </div>

      {/* Diapositiva */}
      <div className="flex-1 overflow-y-auto px-8 md:px-20 py-10">
        <div className="max-w-6xl mx-auto">
          {i === 0 && (
            <div className="flex items-center gap-6 mb-10">
              <GotecLogo height={72} />
              <OrionLogo size={88} />
            </div>
          )}
          <p className="text-base font-mono tracking-widest mb-3" style={{ color: s.teacherOnly ? '#facc15' : '#93a954' }}>
            {s.teacherOnly ? '🔒 ' : ''}{s.kicker.toUpperCase()}
          </p>
          <h1 className="text-4xl md:text-6xl font-bold text-slate-50 mb-8">{s.title}</h1>
          {s.teacherOnly && hideAnswers
            ? <p className="text-2xl text-slate-500">Contenido oculto. Pulse “Mostrar respuestas” cuando el grupo haya entregado.</p>
            : s.body}
        </div>
      </div>

      {/* Navegación */}
      <div className="flex items-center gap-4 px-6 py-3 border-t" style={{ borderColor: 'rgba(212,189,85,0.2)' }}>
        <button onClick={() => setI(v => Math.max(v - 1, 0))} disabled={i === 0}
                className="px-4 py-1.5 rounded-lg text-base text-slate-200 disabled:opacity-30" style={{ border: '1px solid rgba(255,255,255,0.15)' }}>← Anterior</button>
        <div className="flex-1 flex justify-center gap-1.5">
          {slides.map((_, k) => (
            <button key={k} onClick={() => setI(k)} aria-label={`Diapositiva ${k + 1}`}
                    className="h-2 rounded-full transition-all" style={{ width: k === i ? 28 : 8, background: k === i ? GOLD : 'rgba(255,255,255,0.15)' }} />
          ))}
        </div>
        <span className="text-xs font-mono text-slate-500">{i + 1} / {slides.length}</span>
        <button onClick={() => setI(v => Math.min(v + 1, slides.length - 1))} disabled={i === slides.length - 1}
                className="px-4 py-1.5 rounded-lg text-base font-semibold disabled:opacity-30"
                style={{ background: 'rgba(212,189,85,0.15)', border: '1px solid rgba(212,189,85,0.45)', color: '#e0cf74' }}>Siguiente →</button>
      </div>
    </div>,
    document.body,
  )
}

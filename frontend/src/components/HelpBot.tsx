import { useState, useRef, useEffect } from 'react'
import { useAuth } from '../contexts/AuthContext'

const API = import.meta.env.VITE_API_URL ?? 'http://127.0.0.1:8000'

interface Mensaje { rol: 'usuario' | 'bot'; texto: string; tipo?: 'error' | 'idea' }

interface Props {
  currentCode:     string
  lessonTitle:     string
  challengeTitle?: string
  challengeDesc?:  string
  challengeObj?:   string
  challengeCrit?:  string
  challengeHints?: string[]
}

/** Extrae los pasos numerados del objetivo como pistas */
function parsearPistas(objetivo: string): string[] {
  const pasos = objetivo.match(/\d+\)[^0-9(]{5,}/g) ?? []
  if (pasos.length >= 2)
    return pasos.map(p => p.replace(/^\d+\)\s*/, '').trim())
  return objetivo
    .split(/[.;]/)
    .map(s => s.trim())
    .filter(s => s.length > 12)
    .slice(0, 6)
}

export default function HelpBot({
  currentCode, lessonTitle, challengeTitle,
  challengeDesc, challengeObj, challengeCrit, challengeHints,
}: Props) {
  const { token } = useAuth()

  const pistas: string[] = challengeHints?.length
    ? challengeHints
    : challengeObj ? parsearPistas(challengeObj) : []

  const enReto = Boolean(challengeTitle)

  const [abierto,    setAbierto]    = useState(false)
  const [minimizado, setMinimizado] = useState(false)
  const [tab,        setTab]        = useState<'chat' | 'ideas'>('ideas')   // abre en Ideas si hay reto
  const [mensajes,   setMensajes]   = useState<Mensaje[]>([{
    rol: 'bot',
    texto: enReto
      ? `¡Hola! Soy **ARIA**, tu asistente para este reto.\n\nRevisa la pestaña **💡 Ideas** para ver el plan de trabajo con todos los pasos. Cuando tengas dudas sobre el código, errores o conceptos, escríbeme aquí.`
      : `¡Hola! Soy ARIA, tu asistente de CTI-Lab. Puedo ver tu código y ayudarte con errores, conceptos o ideas. ¿En qué te ayudo?`,
  }])
  const [entrada,      setEntrada]      = useState('')
  const [cargando,     setCargando]     = useState(false)
  const [pistaActiva,  setPistaActiva]  = useState<number | null>(null)
  const [ideasEnviadas, setIdeasEnviadas] = useState(false)
  const bottomRef = useRef<HTMLDivElement>(null)

  // Cambia a tab ideas cuando hay reto
  useEffect(() => {
    if (enReto) setTab('ideas')
  }, [enReto])

  useEffect(() => {
    if (!minimizado && tab === 'chat')
      bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [mensajes, abierto, minimizado, tab])

  // Auto-mensaje con ideas cuando el estudiante cambia a chat por primera vez
  const irAChat = () => {
    setTab('chat')
    if (!ideasEnviadas && enReto && pistas.length > 0) {
      setIdeasEnviadas(true)
      const resumen = pistas.map((p, i) => `${i + 1}. ${p}`).join('\n')
      setMensajes(prev => [...prev, {
        rol: 'bot',
        tipo: 'idea',
        texto: `📋 **Resumen del reto: ${challengeTitle}**\n\n${challengeDesc ? challengeDesc + '\n\n' : ''}**Pasos a seguir:**\n${resumen}\n\n_Usa los botones de pista cuando necesites ayuda con un paso específico._`,
      }])
    }
  }

  const buildSystemPrompt = () => {
    const ctx = [
      challengeTitle ? `Reto: "${challengeTitle}"` : '',
      challengeDesc  ? `Descripción: ${challengeDesc}` : '',
      challengeObj   ? `Objetivo (pasos):\n${challengeObj}` : '',
      challengeCrit  ? `Criterios: ${challengeCrit}` : '',
    ].filter(Boolean).join('\n\n')

    const pistasStr = pistas.length
      ? `\nPISTAS (una a la vez cuando el estudiante lo pida):\n${pistas.map((p, i) => `Pista ${i + 1}: ${p}`).join('\n')}`
      : ''

    const codeStr = currentCode
      ? `\nCódigo actual:\n\`\`\`python\n${currentCode.slice(0, 1500)}\n\`\`\``
      : ''

    return `Eres ARIA, asistente de CTI-Lab (Universidad Ean, Colombia).
Ayudas con Python, pandas, sklearn y análisis de ciberseguridad.

${ctx}${pistasStr}${codeStr}

REGLAS:
- Responde SIEMPRE en español colombiano, de forma amigable y motivadora.
- Cuando pidan "Pista N", entrega solo esa pista, sin adelantar las siguientes.
- Guía al estudiante, NUNCA des el código completo si está intentando resolverlo.
- Si hay error en el código, explica el POR QUÉ sin dar la solución directa.
- Usa ejemplos de ciberseguridad (IOCs, MITRE ATT&CK, threat actors) cuando sea útil.
- Máximo 3 párrafos cortos por respuesta.`.trim()
  }

  const enviar = async (textoOverride?: string) => {
    const texto = (textoOverride ?? entrada).trim()
    if (!texto || cargando) return
    setEntrada('')
    setTab('chat')
    setMensajes(p => [...p, { rol: 'usuario', texto }])
    setCargando(true)
    try {
      const r = await fetch(`${API}/ai/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
        body: JSON.stringify({ message: texto, system_override: buildSystemPrompt() }),
      })
      const data = await r.json()
      setMensajes(p => [...p, { rol: 'bot', texto: data.response ?? 'No pude procesar la respuesta.' }])
    } catch {
      setMensajes(p => [...p, { rol: 'bot', texto: 'Error al conectar. Verifica que el servidor esté activo.', tipo: 'error' }])
    } finally { setCargando(false) }
  }

  const pedirPista = (idx: number) => {
    setPistaActiva(idx)
    enviar(`Dame la pista ${idx + 1}: "${pistas[idx]}"`)
  }

  const SUGERENCIAS = ['¿Por qué da error?', 'Explica el concepto', '¿Cómo lo uso en CTI?', 'Dame un ejemplo']

  return (
    <>
      {/* ── Botón flotante ──────────────────────────────────────────────── */}
      <button
        onClick={() => abierto ? (minimizado ? setMinimizado(false) : setMinimizado(true)) : setAbierto(true)}
        className="fixed bottom-6 right-6 z-50 w-12 h-12 rounded-full flex items-center justify-center transition-all shadow-2xl"
        style={{
          background: abierto && !minimizado
            ? 'rgba(167,139,250,0.25)'
            : 'linear-gradient(135deg, rgba(167,139,250,0.35), rgba(34,211,238,0.2))',
          border: '1px solid rgba(167,139,250,0.45)',
          boxShadow: abierto && !minimizado ? 'none' : '0 0 24px rgba(167,139,250,0.35)',
        }}
        title="Asistente ARIA">
        {!abierto || minimizado ? (
          <svg viewBox="0 0 24 24" className="w-5 h-5 text-violet-400" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z" />
          </svg>
        ) : (
          <svg viewBox="0 0 24 24" className="w-5 h-5 text-violet-400" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M5 12h14" />
          </svg>
        )}
      </button>

      {/* ── Panel principal ─────────────────────────────────────────────── */}
      {abierto && (
        <div className="fixed bottom-20 right-6 z-50 w-88 flex flex-col rounded-2xl overflow-hidden shadow-2xl"
             style={{
               width: 340,
               background: 'rgba(10,15,30,0.97)',
               border: '1px solid rgba(167,139,250,0.25)',
               backdropFilter: 'blur(20px)',
               height: minimizado ? 'auto' : 500,
             }}>

          {/* Cabecera */}
          <div className="px-4 py-2.5 border-b flex items-center gap-2 shrink-0"
               style={{ borderColor: 'rgba(255,255,255,0.07)' }}>
            <div className="w-6 h-6 rounded-full flex items-center justify-center shrink-0"
                 style={{ background: 'rgba(167,139,250,0.2)' }}>
              <svg viewBox="0 0 24 24" className="w-3.5 h-3.5 text-violet-400" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z" />
              </svg>
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-xs font-semibold text-violet-300">ARIA — Asistente CTI-Lab</p>
              <p className="text-[9px] text-slate-600 truncate">
                {challengeTitle ? `📋 ${challengeTitle}` : lessonTitle}
              </p>
            </div>
            <span className="flex items-center gap-1 text-[9px] text-green-600 shrink-0">
              <span className="w-1.5 h-1.5 bg-green-500 rounded-full animate-pulse" />
              En línea
            </span>
            <button onClick={() => setMinimizado(m => !m)}
                    className="w-6 h-6 flex items-center justify-center rounded text-slate-600 hover:text-slate-300 shrink-0">
              {minimizado
                ? <svg viewBox="0 0 24 24" className="w-3.5 h-3.5" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M8 3v3a2 2 0 0 1-2 2H3m18 0h-3a2 2 0 0 1-2-2V3m0 18v-3a2 2 0 0 1 2-2h3M3 16h3a2 2 0 0 1 2 2v3" /></svg>
                : <svg viewBox="0 0 24 24" className="w-3.5 h-3.5" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M5 12h14" /></svg>
              }
            </button>
            <button onClick={() => { setAbierto(false); setMinimizado(false) }}
                    className="w-6 h-6 flex items-center justify-center rounded text-slate-700 hover:text-red-400 shrink-0">
              <svg viewBox="0 0 24 24" className="w-3.5 h-3.5" fill="none" stroke="currentColor" strokeWidth="2.5">
                <path d="M18 6L6 18M6 6l12 12" />
              </svg>
            </button>
          </div>

          {/* Tabs (solo cuando hay reto) */}
          {!minimizado && enReto && (
            <div className="flex border-b shrink-0" style={{ borderColor: 'rgba(255,255,255,0.06)' }}>
              <button onClick={() => setTab('ideas')}
                      className="flex-1 py-2 text-[10px] font-bold transition-all"
                      style={{ color: tab === 'ideas' ? '#a78bfa' : '#475569', borderBottom: tab === 'ideas' ? '2px solid #a78bfa' : '2px solid transparent', background: tab === 'ideas' ? 'rgba(167,139,250,0.05)' : 'transparent' }}>
                💡 Ideas y Pistas
              </button>
              <button onClick={irAChat}
                      className="flex-1 py-2 text-[10px] font-bold transition-all"
                      style={{ color: tab === 'chat' ? '#22d3ee' : '#475569', borderBottom: tab === 'chat' ? '2px solid #22d3ee' : '2px solid transparent', background: tab === 'chat' ? 'rgba(34,211,238,0.05)' : 'transparent' }}>
                💬 Chat con ARIA
              </button>
            </div>
          )}

          {/* ── Tab: Ideas y Pistas ──────────────────────────────────────── */}
          {!minimizado && tab === 'ideas' && (
            <div className="flex-1 overflow-y-auto px-4 py-3 space-y-3">

              {/* Descripción del reto */}
              {challengeDesc && (
                <div className="rounded-lg p-3" style={{ background: 'rgba(34,211,238,0.05)', border: '1px solid rgba(34,211,238,0.12)' }}>
                  <p className="text-[9px] font-bold text-cyan-600 uppercase mb-1">📌 Contexto del reto</p>
                  <p className="text-[10px] text-slate-400 leading-relaxed">{challengeDesc}</p>
                </div>
              )}

              {/* Pasos / Pistas */}
              {pistas.length > 0 && (
                <div className="space-y-2">
                  <p className="text-[9px] font-bold text-violet-600 uppercase tracking-wider">
                    🗺 Hoja de ruta — {pistas.length} pasos
                  </p>
                  {pistas.map((pista, i) => (
                    <div key={i}
                         className="rounded-lg p-3 space-y-2 transition-all"
                         style={{
                           background: pistaActiva === i ? 'rgba(167,139,250,0.12)' : 'rgba(255,255,255,0.02)',
                           border: `1px solid ${pistaActiva === i ? 'rgba(167,139,250,0.35)' : 'rgba(255,255,255,0.06)'}`,
                         }}>
                      <div className="flex items-start gap-2">
                        <span className="w-5 h-5 rounded-full flex items-center justify-center text-[9px] font-black shrink-0 mt-0.5"
                              style={{ background: pistaActiva === i ? 'rgba(167,139,250,0.3)' : 'rgba(255,255,255,0.06)', color: pistaActiva === i ? '#c4b5fd' : '#64748b' }}>
                          {i + 1}
                        </span>
                        <p className="text-[10px] text-slate-300 leading-relaxed flex-1">{pista}</p>
                      </div>
                      <button
                        onClick={() => pedirPista(i)}
                        disabled={cargando}
                        className="w-full text-[9px] py-1 rounded font-bold transition-all disabled:opacity-40"
                        style={{
                          background: pistaActiva === i ? 'rgba(167,139,250,0.2)' : 'rgba(167,139,250,0.06)',
                          border: `1px solid rgba(167,139,250,${pistaActiva === i ? '0.4' : '0.15'})`,
                          color: '#a78bfa',
                        }}>
                        {pistaActiva === i ? '✓ Pista solicitada — ver en Chat →' : `💬 Pedir ayuda con el paso ${i + 1}`}
                      </button>
                    </div>
                  ))}
                </div>
              )}

              {/* Criterios */}
              {challengeCrit && (
                <div className="rounded-lg p-3" style={{ background: 'rgba(250,204,21,0.04)', border: '1px solid rgba(250,204,21,0.1)' }}>
                  <p className="text-[9px] font-bold text-yellow-600 uppercase mb-1">📊 Criterios de evaluación</p>
                  <p className="text-[10px] text-slate-400 leading-relaxed">{challengeCrit}</p>
                </div>
              )}

              <button onClick={irAChat}
                      className="w-full py-2 rounded-lg text-[10px] font-bold transition-all"
                      style={{ background: 'rgba(34,211,238,0.08)', border: '1px solid rgba(34,211,238,0.2)', color: '#22d3ee' }}>
                💬 Ir al chat con ARIA →
              </button>
            </div>
          )}

          {/* ── Tab: Chat ────────────────────────────────────────────────── */}
          {!minimizado && (!enReto || tab === 'chat') && (
            <>
              <div className="flex-1 overflow-y-auto px-4 py-3 space-y-3">
                {mensajes.map((m, i) => (
                  <div key={i} className={`flex ${m.rol === 'usuario' ? 'justify-end' : 'justify-start'}`}>
                    <div className="max-w-[88%] rounded-xl px-3 py-2 text-xs leading-relaxed whitespace-pre-wrap"
                         style={m.rol === 'usuario' ? {
                           background: 'rgba(167,139,250,0.2)', border: '1px solid rgba(167,139,250,0.25)', color: '#e2e8f0',
                         } : {
                           background: m.tipo === 'error' ? 'rgba(239,68,68,0.08)' : m.tipo === 'idea' ? 'rgba(167,139,250,0.07)' : 'rgba(255,255,255,0.04)',
                           border: `1px solid ${m.tipo === 'error' ? 'rgba(239,68,68,0.2)' : m.tipo === 'idea' ? 'rgba(167,139,250,0.15)' : 'rgba(255,255,255,0.07)'}`,
                           color: m.tipo === 'error' ? '#fca5a5' : '#94a3b8',
                         }}>
                      {m.texto}
                    </div>
                  </div>
                ))}
                {cargando && (
                  <div className="flex justify-start">
                    <div className="px-3 py-2 rounded-xl text-xs"
                         style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.07)' }}>
                      <span className="text-violet-400 animate-pulse">ARIA está pensando…</span>
                    </div>
                  </div>
                )}
                <div ref={bottomRef} />
              </div>

              {/* Sugerencias rápidas */}
              <div className="px-3 pb-1.5 flex gap-1.5 flex-wrap shrink-0">
                {SUGERENCIAS.map(s => (
                  <button key={s} onClick={() => enviar(s)} disabled={cargando}
                          className="text-[9px] px-2 py-1 rounded-full transition-colors disabled:opacity-40"
                          style={{ background: 'rgba(34,211,238,0.06)', border: '1px solid rgba(34,211,238,0.15)', color: '#0891b2' }}>
                    {s}
                  </button>
                ))}
                {enReto && (
                  <button onClick={() => setTab('ideas')}
                          className="text-[9px] px-2 py-1 rounded-full transition-colors"
                          style={{ background: 'rgba(167,139,250,0.08)', border: '1px solid rgba(167,139,250,0.2)', color: '#7c3aed' }}>
                    Ver ideas →
                  </button>
                )}
              </div>

              {/* Entrada */}
              <div className="px-3 pb-3 flex gap-2 shrink-0">
                <input
                  value={entrada}
                  onChange={e => setEntrada(e.target.value)}
                  onKeyDown={e => e.key === 'Enter' && !e.shiftKey && enviar()}
                  placeholder="Escribe tu pregunta…"
                  disabled={cargando}
                  className="flex-1 rounded-lg px-3 py-2 text-xs text-slate-100 placeholder-slate-700 outline-none disabled:opacity-50"
                  style={{ background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.09)' }}
                />
                <button onClick={() => enviar()} disabled={cargando || !entrada.trim()}
                        className="px-3 py-2 rounded-lg text-xs font-bold disabled:opacity-40 transition-all"
                        style={{ background: 'rgba(167,139,250,0.2)', border: '1px solid rgba(167,139,250,0.35)', color: '#a78bfa' }}>
                  Enviar
                </button>
              </div>
            </>
          )}
        </div>
      )}
    </>
  )
}

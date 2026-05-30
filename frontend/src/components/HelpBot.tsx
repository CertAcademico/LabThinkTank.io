import { useState, useRef, useEffect } from 'react'
import { useAuth } from '../contexts/AuthContext'

const API = import.meta.env.VITE_API_URL ?? 'http://127.0.0.1:8000'

interface Mensaje { rol: 'usuario' | 'bot'; texto: string; tipo?: 'pista' | 'error' | 'normal' }

interface Props {
  currentCode:      string
  lessonTitle:      string
  challengeTitle?:  string
  challengeDesc?:   string
  challengeObj?:    string
  challengeCrit?:   string
  challengeHints?:  string[]   // pistas explícitas (CTF) o derivadas del objetivo
}

/** Extrae los pasos numerados del objetivo como pistas */
function parsearPistas(objetivo: string): string[] {
  const pasos = objetivo.match(/\d+\)[^0-9)]+/g) ?? []
  if (pasos.length) return pasos.map(p => p.replace(/^\d+\)\s*/, '').trim())
  // Fallback: dividir por puntos/comas si no hay numeración
  return objetivo.split(/[.;]/).map(s => s.trim()).filter(s => s.length > 10).slice(0, 5)
}

export default function HelpBot({
  currentCode, lessonTitle, challengeTitle,
  challengeDesc, challengeObj, challengeCrit, challengeHints,
}: Props) {
  const { token } = useAuth()

  // Derivo las pistas del objetivo si no vienen explícitas
  const pistas: string[] = challengeHints?.length
    ? challengeHints
    : challengeObj ? parsearPistas(challengeObj) : []

  const [abierto,    setAbierto]    = useState(false)
  const [minimizado, setMinimizado] = useState(false)
  const [mensajes,   setMensajes]   = useState<Mensaje[]>([{
    rol: 'bot',
    texto: challengeTitle
      ? `¡Hola! Soy ARIA, tu asistente para el reto **"${challengeTitle}"**.\n\nPuedo ver tu código y ayudarte con errores, conceptos o pistas paso a paso. ¿En qué te ayudo?\n\n${pistas.length ? `💡 Tienes ${pistas.length} pistas disponibles — usa los botones de abajo.` : ''}`.trim()
      : '¡Hola! Soy ARIA, tu asistente de CTI-Lab. Puedo ver tu código y ayudarte con errores, conceptos o ideas. ¿En qué te ayudo?',
  }])
  const [entrada,  setEntrada]  = useState('')
  const [cargando, setCargando] = useState(false)
  const [pistasUsadas, setPistasUsadas] = useState<number[]>([])
  const bottomRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!minimizado) bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [mensajes, abierto, minimizado])

  const abrir  = () => { setAbierto(true); setMinimizado(false) }
  const cerrar = () => { setAbierto(false); setMinimizado(false) }

  // Construye el contexto completo del reto para el sistema
  const buildSystemPrompt = () => {
    const retoParts = [
      challengeTitle ? `Reto del estudiante: "${challengeTitle}"` : '',
      challengeDesc  ? `Descripción: ${challengeDesc}` : '',
      challengeObj   ? `Objetivo (pasos a seguir):\n${challengeObj}` : '',
      challengeCrit  ? `Criterios de evaluación: ${challengeCrit}` : '',
    ].filter(Boolean).join('\n\n')

    const pistasStr = pistas.length
      ? `\nPISTAS DEL RETO (dálas solo cuando el estudiante las pida, una por vez):\n${pistas.map((p, i) => `Pista ${i + 1}: ${p}`).join('\n')}`
      : ''

    const codigoStr = currentCode
      ? `\nCódigo actual del estudiante:\n\`\`\`python\n${currentCode.slice(0, 1500)}\n\`\`\``
      : ''

    return `Eres ARIA, asistente de aprendizaje de CTI-Lab (Universidad Ean, Colombia).
Ayudas a estudiantes con Python, pandas, sklearn y análisis de ciberseguridad.

${retoParts}
${pistasStr}
${codigoStr}

INSTRUCCIONES IMPORTANTES:
- Responde SIEMPRE en español colombiano, de forma amigable, clara y motivadora.
- Cuando el estudiante pida "Pista N", entrega SOLO esa pista específica, sin adelantar las siguientes.
- Da orientación y guía, NUNCA el código completo si el estudiante intenta resolverlo.
- Si hay un error en el código, explica POR QUÉ ocurre sin dar la solución directa.
- Usa ejemplos de ciberseguridad (IOCs, threat actors, MITRE ATT&CK) cuando sean relevantes.
- Sé conciso: máximo 3 párrafos cortos por respuesta.
- Si ya usaron todas las pistas, ayuda con el razonamiento pero sin revelar la respuesta final.`.trim()
  }

  const enviar = async (textoOverride?: string) => {
    const texto = (textoOverride ?? entrada).trim()
    if (!texto || cargando) return
    setEntrada('')
    setMensajes(p => [...p, { rol: 'usuario', texto }])
    setCargando(true)

    try {
      const r = await fetch(`${API}/ai/chat`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({ message: texto, system_override: buildSystemPrompt() }),
      })
      const data = await r.json()
      setMensajes(p => [...p, {
        rol: 'bot',
        texto: data.response ?? 'No pude procesar la respuesta.',
      }])
    } catch {
      setMensajes(p => [...p, {
        rol: 'bot',
        texto: 'Error al conectar con el asistente. Verifica que el servidor esté activo.',
        tipo: 'error',
      }])
    } finally {
      setCargando(false)
    }
  }

  const pedirPista = (idx: number) => {
    setPistasUsadas(p => [...new Set([...p, idx])])
    enviar(`Dame la pista ${idx + 1}`)
  }

  const SUGERENCIAS_BASE = ['¿Por qué da error?', 'Explica el concepto', '¿Cómo se usa en CTI?', 'Muéstrame un ejemplo']

  return (
    <>
      {/* ── Botón flotante ──────────────────────────────────────────────── */}
      <button
        onClick={() => abierto ? (minimizado ? setMinimizado(false) : setMinimizado(true)) : abrir()}
        className="fixed bottom-6 right-6 z-50 w-12 h-12 rounded-full flex items-center justify-center transition-all shadow-2xl"
        style={{
          background: abierto && !minimizado
            ? 'rgba(167,139,250,0.25)'
            : 'linear-gradient(135deg, rgba(167,139,250,0.35), rgba(34,211,238,0.2))',
          border: '1px solid rgba(167,139,250,0.45)',
          boxShadow: abierto && !minimizado ? 'none' : '0 0 24px rgba(167,139,250,0.35)',
        }}
        title={abierto ? (minimizado ? 'Expandir ARIA' : 'Minimizar ARIA') : 'Abrir asistente ARIA'}>
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

      {/* ── Panel del chat ──────────────────────────────────────────────── */}
      {abierto && (
        <div
          className="fixed bottom-20 right-6 z-50 w-80 flex flex-col rounded-2xl overflow-hidden shadow-2xl"
          style={{
            background: 'rgba(10,15,30,0.97)',
            border: '1px solid rgba(167,139,250,0.25)',
            backdropFilter: 'blur(20px)',
            height: minimizado ? 'auto' : 460,
          }}>

          {/* ── Cabecera ────────────────────────────────────────────────── */}
          <div className="px-4 py-3 border-b flex items-center gap-2 shrink-0"
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
                    className="w-6 h-6 flex items-center justify-center rounded transition-colors text-slate-600 hover:text-slate-300 shrink-0"
                    title={minimizado ? 'Expandir' : 'Minimizar'}>
              {minimizado ? (
                <svg viewBox="0 0 24 24" className="w-3.5 h-3.5" fill="none" stroke="currentColor" strokeWidth="2.5">
                  <path d="M8 3v3a2 2 0 0 1-2 2H3m18 0h-3a2 2 0 0 1-2-2V3m0 18v-3a2 2 0 0 1 2-2h3M3 16h3a2 2 0 0 1 2 2v3" />
                </svg>
              ) : (
                <svg viewBox="0 0 24 24" className="w-3.5 h-3.5" fill="none" stroke="currentColor" strokeWidth="2.5">
                  <path d="M5 12h14" />
                </svg>
              )}
            </button>
            <button onClick={cerrar}
                    className="w-6 h-6 flex items-center justify-center rounded transition-colors text-slate-700 hover:text-red-400 shrink-0"
                    title="Cerrar asistente">
              <svg viewBox="0 0 24 24" className="w-3.5 h-3.5" fill="none" stroke="currentColor" strokeWidth="2.5">
                <path d="M18 6L6 18M6 6l12 12" />
              </svg>
            </button>
          </div>

          {/* ── Pistas del reto ─────────────────────────────────────────── */}
          {!minimizado && pistas.length > 0 && (
            <div className="px-3 py-2 border-b shrink-0 space-y-1"
                 style={{ borderColor: 'rgba(255,255,255,0.06)', background: 'rgba(167,139,250,0.04)' }}>
              <p className="text-[8px] text-violet-700 uppercase tracking-wider font-bold">
                Pistas del reto ({pistasUsadas.length}/{pistas.length} reveladas)
              </p>
              <div className="flex gap-1.5 flex-wrap">
                {pistas.map((_, i) => {
                  const usada = pistasUsadas.includes(i)
                  return (
                    <button key={i}
                            onClick={() => pedirPista(i)}
                            disabled={cargando}
                            className="text-[9px] px-2 py-1 rounded-full font-bold transition-all disabled:opacity-40"
                            style={{
                              background: usada ? 'rgba(167,139,250,0.2)' : 'rgba(167,139,250,0.08)',
                              border: `1px solid ${usada ? 'rgba(167,139,250,0.5)' : 'rgba(167,139,250,0.2)'}`,
                              color: usada ? '#c4b5fd' : '#7c3aed',
                            }}>
                      {usada ? `✓ Pista ${i + 1}` : `💡 Pista ${i + 1}`}
                    </button>
                  )
                })}
              </div>
            </div>
          )}

          {/* ── Mensajes ────────────────────────────────────────────────── */}
          {!minimizado && (
            <>
              <div className="flex-1 overflow-y-auto px-4 py-3 space-y-3">
                {mensajes.map((m, i) => (
                  <div key={i} className={`flex ${m.rol === 'usuario' ? 'justify-end' : 'justify-start'}`}>
                    <div
                      className="max-w-[85%] rounded-xl px-3 py-2 text-xs leading-relaxed whitespace-pre-wrap"
                      style={m.rol === 'usuario' ? {
                        background: 'rgba(167,139,250,0.2)',
                        border: '1px solid rgba(167,139,250,0.25)',
                        color: '#e2e8f0',
                      } : {
                        background: m.tipo === 'error' ? 'rgba(239,68,68,0.08)' : 'rgba(255,255,255,0.04)',
                        border: `1px solid ${m.tipo === 'error' ? 'rgba(239,68,68,0.2)' : 'rgba(255,255,255,0.07)'}`,
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
              <div className="px-3 pb-2 flex gap-1.5 flex-wrap shrink-0">
                {SUGERENCIAS_BASE.map(s => (
                  <button key={s} onClick={() => enviar(s)}
                          disabled={cargando}
                          className="text-[9px] px-2 py-1 rounded-full transition-colors disabled:opacity-40"
                          style={{ background: 'rgba(34,211,238,0.06)', border: '1px solid rgba(34,211,238,0.15)', color: '#0891b2' }}>
                    {s}
                  </button>
                ))}
              </div>

              {/* Campo de entrada */}
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
                <button
                  onClick={() => enviar()}
                  disabled={cargando || !entrada.trim()}
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

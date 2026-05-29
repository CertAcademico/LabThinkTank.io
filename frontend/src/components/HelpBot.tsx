import { useState, useRef, useEffect } from 'react'
import { useAuth } from '../contexts/AuthContext'

const API = import.meta.env.VITE_API_URL ?? 'http://127.0.0.1:8000'

interface Message { role: 'user' | 'bot'; text: string }

interface Props {
  currentCode:   string
  lessonTitle:   string
  challengeTitle?: string
}

export default function HelpBot({ currentCode, lessonTitle, challengeTitle }: Props) {
  const { token }                 = useAuth()
  const [open,    setOpen]        = useState(false)
  const [msgs,    setMsgs]        = useState<Message[]>([
    { role: 'bot', text: '¡Hola! Soy tu asistente de CTI Lab. Puedo ver tu código actual y ayudarte con errores, conceptos o ideas. ¿En qué te ayudo?' }
  ])
  const [input,   setInput]       = useState('')
  const [loading, setLoading]     = useState(false)
  const bottomRef                 = useRef<HTMLDivElement>(null)

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [msgs, open])

  const send = async () => {
    const text = input.trim()
    if (!text || loading) return
    setInput('')
    setMsgs(p => [...p, { role: 'user', text }])
    setLoading(true)

    const context = [
      challengeTitle ? `El estudiante está trabajando en el reto: "${challengeTitle}".` : '',
      `Lección actual: "${lessonTitle}".`,
      currentCode ? `\nCódigo actual del estudiante:\n\`\`\`python\n${currentCode.slice(0, 1500)}\n\`\`\`` : '',
    ].filter(Boolean).join('\n')

    const systemPrompt = `Eres un asistente de aprendizaje de Python y ciencia de datos para ciberseguridad.
Ayudas a estudiantes universitarios de la Universidad Ean.
${context}

REGLAS IMPORTANTES:
- Responde SIEMPRE en español.
- Da pistas y guía, NO des el código completo si el estudiante está tratando de resolverlo.
- Si hay un error en el código, explica POR QUÉ ocurre sin dar la solución directa.
- Usa ejemplos de ciberseguridad cuando sea posible.
- Sé conciso y amigable. Máximo 3 párrafos.`

    try {
      const r = await fetch(`${API}/ai/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
        body: JSON.stringify({ message: text, system_override: systemPrompt }),
      })
      const data = await r.json()
      setMsgs(p => [...p, { role: 'bot', text: data.response ?? 'No pude procesar la respuesta.' }])
    } catch {
      setMsgs(p => [...p, { role: 'bot', text: 'Error al conectar con el asistente. Verifica que el servidor esté activo.' }])
    } finally {
      setLoading(false)
    }
  }

  return (
    <>
      {/* Floating toggle button */}
      <button
        onClick={() => setOpen(o => !o)}
        className="fixed bottom-6 right-6 z-50 w-12 h-12 rounded-full flex items-center justify-center transition-all shadow-2xl"
        style={{
          background: open ? 'rgba(167,139,250,0.2)' : 'linear-gradient(135deg, rgba(167,139,250,0.3), rgba(34,211,238,0.2))',
          border: '1px solid rgba(167,139,250,0.4)',
          boxShadow: open ? 'none' : '0 0 24px rgba(167,139,250,0.3)',
        }}
        title="Asistente IA">
        {open ? (
          <svg viewBox="0 0 24 24" className="w-5 h-5 text-violet-400" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M18 6L6 18M6 6l12 12" />
          </svg>
        ) : (
          <svg viewBox="0 0 24 24" className="w-5 h-5 text-violet-400" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z" />
          </svg>
        )}
      </button>

      {/* Chat panel */}
      {open && (
        <div className="fixed bottom-20 right-6 z-50 w-80 flex flex-col rounded-2xl overflow-hidden shadow-2xl"
             style={{
               background: 'rgba(10,15,30,0.97)',
               border: '1px solid rgba(167,139,250,0.25)',
               backdropFilter: 'blur(20px)',
               height: 420,
             }}>

          {/* Header */}
          <div className="px-4 py-3 border-b flex items-center gap-2 shrink-0"
               style={{ borderColor: 'rgba(255,255,255,0.06)' }}>
            <div className="w-6 h-6 rounded-full flex items-center justify-center shrink-0"
                 style={{ background: 'rgba(167,139,250,0.2)' }}>
              <svg viewBox="0 0 24 24" className="w-3.5 h-3.5 text-violet-400" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z" />
              </svg>
            </div>
            <div className="flex-1">
              <p className="text-xs font-semibold text-slate-200">Asistente IA</p>
              <p className="text-[9px] text-slate-600 truncate">
                {challengeTitle ?? lessonTitle}
              </p>
            </div>
            <span className="flex items-center gap-1 text-[9px] text-green-600">
              <span className="w-1.5 h-1.5 bg-green-500 rounded-full animate-pulse" />
              En línea
            </span>
          </div>

          {/* Messages */}
          <div className="flex-1 overflow-y-auto px-4 py-3 space-y-3">
            {msgs.map((m, i) => (
              <div key={i} className={`flex ${m.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                <div className="max-w-[85%] rounded-xl px-3 py-2 text-xs leading-relaxed whitespace-pre-wrap"
                     style={m.role === 'user' ? {
                       background: 'rgba(167,139,250,0.2)',
                       border: '1px solid rgba(167,139,250,0.25)',
                       color: '#e2e8f0',
                     } : {
                       background: 'rgba(255,255,255,0.04)',
                       border: '1px solid rgba(255,255,255,0.07)',
                       color: '#94a3b8',
                     }}>
                  {m.text}
                </div>
              </div>
            ))}
            {loading && (
              <div className="flex justify-start">
                <div className="px-3 py-2 rounded-xl text-xs"
                     style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.07)' }}>
                  <span className="text-violet-400 animate-pulse">Pensando...</span>
                </div>
              </div>
            )}
            <div ref={bottomRef} />
          </div>

          {/* Quick prompts */}
          <div className="px-3 pb-2 flex gap-1.5 flex-wrap shrink-0">
            {['¿Por qué da error?', 'Dame una pista', 'Explica el concepto', '¿Cómo se usa en CTI?'].map(q => (
              <button key={q} onClick={() => { setInput(q); }}
                      className="text-[9px] px-2 py-1 rounded-full transition-colors"
                      style={{ background: 'rgba(167,139,250,0.08)', border: '1px solid rgba(167,139,250,0.2)', color: '#a78bfa' }}>
                {q}
              </button>
            ))}
          </div>

          {/* Input */}
          <div className="px-3 pb-3 flex gap-2 shrink-0">
            <input
              value={input}
              onChange={e => setInput(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && !e.shiftKey && send()}
              placeholder="Pregunta algo sobre tu código..."
              disabled={loading}
              className="flex-1 rounded-lg px-3 py-2 text-xs text-slate-100 placeholder-slate-700 outline-none disabled:opacity-50"
              style={{ background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.09)' }}
            />
            <button onClick={send} disabled={loading || !input.trim()}
                    className="px-3 py-2 rounded-lg text-xs font-bold disabled:opacity-40 transition-all"
                    style={{ background: 'rgba(167,139,250,0.2)', border: '1px solid rgba(167,139,250,0.35)', color: '#a78bfa' }}>
              →
            </button>
          </div>
        </div>
      )}
    </>
  )
}

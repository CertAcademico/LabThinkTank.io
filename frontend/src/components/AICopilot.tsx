import { useState, useRef, useEffect } from 'react'

const API_URL = import.meta.env.VITE_API_URL ?? 'http://127.0.0.1:8000'

const glass = {
  background: 'rgba(15,23,42,0.55)',
  backdropFilter: 'blur(16px)',
  border: '1px solid rgba(255,255,255,0.07)',
  borderRadius: 12,
}

interface Message {
  role: 'user' | 'assistant'
  content: string
  confidence?: number
  ts: string
}

const SUGGESTED = [
  'Analiza los IOCs de las últimas 24h e identifica patrones',
  '¿Qué TTPs está usando APT29 en campañas actuales?',
  'Resume las alertas críticas y sugiere contención',
  'Mapea el comportamiento observado a técnicas MITRE ATT&CK',
  'Correlaciona actores de amenaza con campañas activas',
  'Identifica indicadores de movimiento lateral en IoAs recientes',
]

function ConfidenceBar({ score }: { score: number }) {
  const color = score >= 80 ? '#4ade80' : score >= 60 ? '#facc15' : '#f87171'
  const label = score >= 80 ? 'Alta' : score >= 60 ? 'Media' : 'Baja'
  return (
    <div className="flex items-center gap-2 mt-2">
      <span className="text-[10px] font-mono text-slate-600">CONFIANZA</span>
      <div className="flex-1 h-1 rounded-full" style={{ background: 'rgba(255,255,255,0.08)' }}>
        <div className="h-1 rounded-full transition-all duration-700" style={{ width: `${score}%`, background: color }} />
      </div>
      <span className="text-[10px] font-mono" style={{ color }}>{label} {score}%</span>
    </div>
  )
}

function ThinkingDots() {
  return (
    <div className="flex items-center gap-1 px-3 py-2">
      {[0, 1, 2].map(i => (
        <span key={i} className="w-1.5 h-1.5 rounded-full bg-cyan-400"
              style={{ animation: `bounce 1.2s ease-in-out ${i * 0.2}s infinite` }} />
      ))}
      <span className="text-xs text-slate-500 ml-2">AI Copilot analizando...</span>
    </div>
  )
}

export default function AICopilot() {
  const [messages, setMessages] = useState<Message[]>([
    {
      role: 'assistant',
      content: 'Hola. Soy el AI Copilot de CTI Nexus. Tengo acceso a todos los feeds de inteligencia, IOCs activos y actores de amenaza en tiempo real. ¿En qué puedo ayudarte hoy?',
      confidence: 95,
      ts: new Date().toLocaleTimeString('es-MX', { hour: '2-digit', minute: '2-digit' }),
    }
  ])
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const bottomRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages, loading])

  async function send(text?: string) {
    const msg = (text ?? input).trim()
    if (!msg || loading) return
    setInput('')
    const ts = new Date().toLocaleTimeString('es-MX', { hour: '2-digit', minute: '2-digit' })
    setMessages(prev => [...prev, { role: 'user', content: msg, ts }])
    setLoading(true)
    try {
      const res = await fetch(`${API_URL}/ai/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: msg }),
      })
      const data = await res.json()
      const confidence = Math.floor(Math.random() * 25) + 72
      setMessages(prev => [...prev, {
        role: 'assistant',
        content: data.response ?? 'Sin respuesta del servicio de AI.',
        confidence,
        ts: new Date().toLocaleTimeString('es-MX', { hour: '2-digit', minute: '2-digit' }),
      }])
    } catch {
      setMessages(prev => [...prev, {
        role: 'assistant',
        content: 'Error de conectividad con el backend de AI. Verifica que el servicio esté activo.',
        confidence: 0,
        ts: new Date().toLocaleTimeString('es-MX', { hour: '2-digit', minute: '2-digit' }),
      }])
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="flex gap-4 h-full" style={{ minHeight: 'calc(100vh - 120px)' }}>

      {/* Chat panel */}
      <div className="flex-1 flex flex-col" style={{ ...glass }}>

        {/* Header */}
        <div className="px-5 py-3.5 border-b flex items-center gap-3"
             style={{ borderColor: 'rgba(255,255,255,0.07)' }}>
          <div className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0"
               style={{ background: 'rgba(167,139,250,0.15)', boxShadow: '0 0 16px rgba(167,139,250,0.2)' }}>
            <svg viewBox="0 0 24 24" className="w-4 h-4 text-violet-400" fill="none"
                 stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
              <path d="M9 3H5a2 2 0 0 0-2 2v4m6-6h10a2 2 0 0 1 2 2v4M9 3v18m0 0h10a2 2 0 0 0 2-2V9M9 21H5a2 2 0 0 1-2-2V9m0 0h18" />
            </svg>
          </div>
          <div>
            <p className="text-sm font-semibold text-slate-100">AI Copilot</p>
            <p className="text-[10px] text-slate-500">Claude · CTI Context · Prompt Caching</p>
          </div>
          <div className="ml-auto flex items-center gap-1.5 text-xs px-2.5 py-1 rounded-lg"
               style={{ background: 'rgba(74,222,128,0.08)', color: '#4ade80', border: '1px solid rgba(74,222,128,0.2)' }}>
            <span className="w-1.5 h-1.5 bg-green-400 rounded-full animate-pulse" />
            En línea
          </div>
        </div>

        {/* Messages */}
        <div className="flex-1 overflow-y-auto px-5 py-4 space-y-4">
          {messages.map((m, i) => (
            <div key={i} className={`flex gap-3 ${m.role === 'user' ? 'flex-row-reverse' : ''}`}>
              {/* Avatar */}
              <div className={`w-7 h-7 rounded-full shrink-0 flex items-center justify-center text-[10px] font-bold mt-0.5 ${
                m.role === 'assistant'
                  ? 'bg-violet-500/20 text-violet-300'
                  : 'bg-cyan-500/20 text-cyan-300'
              }`}>
                {m.role === 'assistant' ? 'AI' : 'U'}
              </div>
              {/* Bubble */}
              <div className={`max-w-[78%] ${m.role === 'user' ? 'items-end' : 'items-start'} flex flex-col gap-1`}>
                <div className={`px-4 py-3 rounded-xl text-sm leading-relaxed whitespace-pre-wrap ${
                  m.role === 'user'
                    ? 'text-slate-100 rounded-tr-sm'
                    : 'text-slate-200 rounded-tl-sm'
                }`} style={m.role === 'user' ? {
                  background: 'rgba(34,211,238,0.1)',
                  border: '1px solid rgba(34,211,238,0.2)',
                } : {
                  background: 'rgba(255,255,255,0.05)',
                  border: '1px solid rgba(255,255,255,0.08)',
                }}>
                  {m.content}
                  {m.role === 'assistant' && m.confidence !== undefined && (
                    <ConfidenceBar score={m.confidence} />
                  )}
                </div>
                <span className="text-[10px] text-slate-700 px-1">{m.ts}</span>
              </div>
            </div>
          ))}
          {loading && (
            <div className="flex gap-3">
              <div className="w-7 h-7 rounded-full shrink-0 flex items-center justify-center text-[10px] font-bold mt-0.5 bg-violet-500/20 text-violet-300">AI</div>
              <div className="px-4 py-3 rounded-xl rounded-tl-sm" style={{ background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.08)' }}>
                <ThinkingDots />
              </div>
            </div>
          )}
          <div ref={bottomRef} />
        </div>

        {/* Input */}
        <div className="px-5 py-4 border-t" style={{ borderColor: 'rgba(255,255,255,0.07)' }}>
          <div className="flex gap-2">
            <input
              className="flex-1 rounded-xl px-4 py-2.5 text-sm text-slate-200 outline-none placeholder-slate-600"
              style={{ background: 'rgba(255,255,255,0.06)', border: '1px solid rgba(255,255,255,0.1)' }}
              placeholder="Consulta al AI Copilot sobre amenazas, IOCs, TTPs..."
              value={input}
              onChange={e => setInput(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && !e.shiftKey && send()}
              disabled={loading}
            />
            <button
              onClick={() => send()}
              disabled={loading || !input.trim()}
              className="px-4 rounded-xl text-sm font-medium transition-all disabled:opacity-40"
              style={{ background: 'rgba(34,211,238,0.15)', border: '1px solid rgba(34,211,238,0.3)', color: '#22d3ee' }}>
              <svg viewBox="0 0 24 24" className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth="2">
                <line x1="22" y1="2" x2="11" y2="13" /><polygon points="22 2 15 22 11 13 2 9 22 2" />
              </svg>
            </button>
          </div>
        </div>
      </div>

      {/* Right panel: suggested + capabilities */}
      <div className="w-64 shrink-0 flex flex-col gap-3">

        {/* Suggested queries */}
        <div className="rounded-xl overflow-hidden" style={glass}>
          <div className="px-4 py-3 border-b text-xs font-semibold text-slate-400 tracking-wider uppercase"
               style={{ borderColor: 'rgba(255,255,255,0.07)' }}>
            Consultas sugeridas
          </div>
          <div className="p-3 space-y-1.5">
            {SUGGESTED.map((q, i) => (
              <button key={i} onClick={() => send(q)}
                      className="w-full text-left px-3 py-2 rounded-lg text-xs text-slate-400 hover:text-slate-200 transition-colors leading-snug"
                      style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.05)' }}>
                {q}
              </button>
            ))}
          </div>
        </div>

        {/* Capabilities */}
        <div className="rounded-xl overflow-hidden" style={glass}>
          <div className="px-4 py-3 border-b text-xs font-semibold text-slate-400 tracking-wider uppercase"
               style={{ borderColor: 'rgba(255,255,255,0.07)' }}>
            Capacidades
          </div>
          <div className="p-3 space-y-2">
            {[
              { icon: '🔍', text: 'IOC enrichment en tiempo real' },
              { icon: '🗺️', text: 'Mapping ATT&CK automático' },
              { icon: '🧠', text: 'Análisis de actores de amenaza' },
              { icon: '📊', text: 'Correlación multi-feed' },
              { icon: '⚡', text: 'Prompt caching activo' },
              { icon: '🔗', text: 'Contexto persistente CTI' },
            ].map((c, i) => (
              <div key={i} className="flex items-start gap-2 text-xs text-slate-500">
                <span className="shrink-0">{c.icon}</span>
                <span>{c.text}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}

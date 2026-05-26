import { useState, useRef, useEffect } from 'react'

const API_URL = import.meta.env.VITE_API_URL ?? 'http://127.0.0.1:8000'

interface Message {
  role: 'user' | 'assistant'
  content: string
}

function AIChat() {
  const [input, setInput] = useState('')
  const [messages, setMessages] = useState<Message[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const bottomRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages, loading])

  const sendMessage = async () => {
    const trimmed = input.trim()
    if (!trimmed || loading) return

    const userMsg: Message = { role: 'user', content: trimmed }
    setMessages(prev => [...prev, userMsg])
    setInput('')
    setLoading(true)
    setError(null)

    try {
      const res = await fetch(`${API_URL}/ai/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: trimmed })
      })

      if (!res.ok) throw new Error(`Server error: ${res.status}`)

      const data = await res.json()
      const assistantMsg: Message = { role: 'assistant', content: data.response }
      setMessages(prev => [...prev, assistantMsg])
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Connection failed — is the backend running?')
    } finally {
      setLoading(false)
    }
  }

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      sendMessage()
    }
  }

  return (
    <div className="bg-slate-900 rounded-xl p-6 border border-cyan-900 flex flex-col h-full">
      <h2 className="text-2xl font-semibold mb-5 text-cyan-400">
        AI SOC Assistant
      </h2>

      <div className="flex-1 overflow-y-auto space-y-4 mb-4 min-h-[300px] max-h-[400px] pr-1">
        {messages.length === 0 && (
          <p className="text-slate-500 text-sm">
            Ask about threats, IOCs, malware, or MITRE ATT&amp;CK techniques...
          </p>
        )}

        {messages.map((msg, i) => (
          <div
            key={i}
            className={`rounded-lg p-3 text-sm whitespace-pre-wrap ${
              msg.role === 'user'
                ? 'bg-cyan-950 border border-cyan-800 text-cyan-100 ml-6'
                : 'bg-slate-800 border border-slate-700 text-slate-200 mr-6'
            }`}
          >
            <span className="block text-xs font-bold mb-1 opacity-60">
              {msg.role === 'user' ? 'You' : 'AI Analyst'}
            </span>
            {msg.content}
          </div>
        ))}

        {loading && (
          <div className="bg-slate-800 border border-slate-700 rounded-lg p-3 mr-6">
            <span className="text-xs font-bold mb-1 opacity-60 block">AI Analyst</span>
            <span className="text-cyan-400 text-sm animate-pulse">Analyzing...</span>
          </div>
        )}

        {error && (
          <div className="bg-red-950 border border-red-800 rounded-lg p-3 text-red-300 text-sm">
            {error}
          </div>
        )}

        <div ref={bottomRef} />
      </div>

      <div className="flex gap-3 mt-auto">
        <textarea
          className="flex-1 bg-slate-950 border border-slate-700 rounded-lg p-3 text-white text-sm resize-none focus:outline-none focus:border-cyan-600"
          rows={2}
          placeholder="Ask a question... (Enter to send, Shift+Enter for newline)"
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={handleKeyDown}
          disabled={loading}
        />
        <button
          onClick={sendMessage}
          disabled={loading || !input.trim()}
          className="bg-cyan-500 hover:bg-cyan-600 disabled:opacity-40 disabled:cursor-not-allowed px-5 py-2 rounded-lg font-bold text-sm self-end"
        >
          Send
        </button>
      </div>
    </div>
  )
}

export default AIChat

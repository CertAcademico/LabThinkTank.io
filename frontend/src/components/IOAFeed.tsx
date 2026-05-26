import { useEffect, useState } from 'react'

const API_URL = import.meta.env.VITE_API_URL ?? 'http://127.0.0.1:8000'

interface IOA {
  ttp: string
  ttp_name: string
  tactic: string
  ioa: string
  detection_source: string
  detection_rule: string
  priority: string
  attributed_actor: string
  attributed_campaign: string
  campaign_status: string
}

const PRIORITY_STYLES: Record<string, { badge: string; row: string; dot: string }> = {
  critical: { badge: 'bg-red-900 text-red-300 border-red-700',    row: 'border-l-red-600',    dot: 'bg-red-500' },
  high:     { badge: 'bg-orange-900 text-orange-300 border-orange-700', row: 'border-l-orange-500', dot: 'bg-orange-400' },
  medium:   { badge: 'bg-yellow-900 text-yellow-300 border-yellow-700', row: 'border-l-yellow-600', dot: 'bg-yellow-400' },
  low:      { badge: 'bg-slate-700 text-slate-300 border-slate-600', row: 'border-l-slate-500', dot: 'bg-slate-400' },
}

function IOAFeed() {
  const [ioas, setIoas]           = useState<IOA[]>([])
  const [selected, setSelected]   = useState<IOA | null>(null)
  const [filter, setFilter]       = useState('all')
  const [loading, setLoading]     = useState(true)
  const [error, setError]         = useState<string | null>(null)

  useEffect(() => {
    fetch(`${API_URL}/ioas`)
      .then(r => r.json())
      .then(setIoas)
      .catch(() => setError('Failed to load IOA feed'))
      .finally(() => setLoading(false))
  }, [])

  if (loading) return <div className="text-slate-400 text-sm p-4 animate-pulse">Generando IOAs desde TTPs activos...</div>
  if (error)   return <div className="text-red-400 text-sm p-4">{error}</div>

  const priorities = ['all', 'critical', 'high', 'medium']
  const visible = ioas.filter(i => filter === 'all' || i.priority === filter)

  return (
    <div className="bg-slate-900 rounded-xl p-6 border border-slate-800">
      <div className="flex items-start justify-between mb-5">
        <div>
          <h2 className="text-xl font-bold">IOA Feed</h2>
          <p className="text-slate-500 text-xs mt-0.5">
            Indicators of Attack derivados de TTPs de actores activos · {ioas.length} total
          </p>
        </div>
        <div className="flex gap-1">
          {priorities.map(p => (
            <button
              key={p}
              onClick={() => setFilter(p)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium capitalize transition-colors ${
                filter === p ? 'bg-cyan-700 text-white' : 'bg-slate-800 text-slate-400 hover:text-white'
              }`}
            >
              {p}
            </button>
          ))}
        </div>
      </div>

      <div className="space-y-2">
        {visible.map(ioa => {
          const s = PRIORITY_STYLES[ioa.priority] ?? PRIORITY_STYLES.medium
          return (
            <div
              key={ioa.ttp}
              className={`border-l-4 ${s.row} bg-slate-800/50 rounded-r-lg px-4 py-3 cursor-pointer hover:bg-slate-800 transition-colors`}
              onClick={() => setSelected(ioa === selected ? null : ioa)}
            >
              <div className="flex items-start justify-between gap-3">
                <div className="flex items-start gap-3 min-w-0">
                  <div className={`w-2 h-2 rounded-full mt-1.5 shrink-0 ${s.dot}`} />
                  <div className="min-w-0">
                    <div className="flex items-center gap-2 mb-1 flex-wrap">
                      <code className="text-purple-400 text-xs font-mono">{ioa.ttp}</code>
                      <span className="text-white text-sm font-medium">{ioa.ttp_name}</span>
                      <span className="text-slate-500 text-xs">·</span>
                      <span className="text-slate-400 text-xs">{ioa.tactic}</span>
                    </div>
                    <p className="text-slate-300 text-sm">{ioa.ioa}</p>
                    <div className="flex items-center gap-3 mt-1.5 flex-wrap">
                      <span className="text-slate-600 text-xs">via {ioa.detection_source}</span>
                      {ioa.attributed_actor && (
                        <span className="text-cyan-600 text-xs">actor: {ioa.attributed_actor}</span>
                      )}
                      {ioa.attributed_campaign && (
                        <span className="text-slate-600 text-xs">campaign: {ioa.attributed_campaign}</span>
                      )}
                    </div>
                  </div>
                </div>
                <span className={`px-2 py-0.5 rounded border text-xs font-bold uppercase shrink-0 ${s.badge}`}>
                  {ioa.priority}
                </span>
              </div>

              {selected === ioa && (
                <div className="mt-3 pt-3 border-t border-slate-700">
                  <p className="text-slate-500 text-xs uppercase tracking-wider mb-2">Detection Rule</p>
                  <code className="block bg-black/50 text-green-300 text-xs p-3 rounded font-mono leading-relaxed whitespace-pre-wrap border border-slate-700">
                    {ioa.detection_rule}
                  </code>
                </div>
              )}
            </div>
          )
        })}
      </div>

      {visible.length === 0 && (
        <p className="text-slate-500 text-sm text-center py-8">Sin IOAs para el filtro seleccionado.</p>
      )}
    </div>
  )
}

export default IOAFeed

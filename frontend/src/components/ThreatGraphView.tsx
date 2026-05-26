import ThreatGraph from './ThreatGraph'

const glass = {
  background: 'rgba(15,23,42,0.55)',
  backdropFilter: 'blur(16px)',
  border: '1px solid rgba(255,255,255,0.07)',
  borderRadius: 12,
}

function Legend({ color, label }: { color: string; label: string }) {
  return (
    <div className="flex items-center gap-2">
      <span className="w-3 h-3 rounded-sm shrink-0" style={{ background: color }} />
      <span className="text-xs text-slate-400">{label}</span>
    </div>
  )
}

export default function ThreatGraphView() {
  return (
    <div className="space-y-4">

      {/* Header row */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-base font-semibold text-slate-100">Threat Intelligence Graph</h2>
          <p className="text-xs text-slate-500 mt-0.5">Actor → IOC → Campaign correlation network</p>
        </div>
        <div className="flex items-center gap-2 text-xs text-slate-500 rounded-lg border px-3 py-1.5"
             style={{ background: 'rgba(255,255,255,0.03)', borderColor: 'rgba(255,255,255,0.06)' }}>
          <span className="w-1.5 h-1.5 bg-cyan-400 rounded-full animate-pulse" />
          Auto-refreshing
        </div>
      </div>

      {/* Legend */}
      <div className="flex flex-wrap gap-4 px-4 py-3 rounded-lg"
           style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.06)' }}>
        <Legend color="#a855f7" label="Threat Actor" />
        <Legend color="#ef4444" label="Critical IOC" />
        <Legend color="#f97316" label="High IOC" />
        <Legend color="#3b82f6" label="Medium IOC" />
        <Legend color="#22c55e" label="Low IOC" />
        <Legend color="#78716c" label="Campaign" />
      </div>

      {/* Graph container */}
      <div style={{ ...glass, overflow: 'hidden' }}>
        <div className="px-4 py-3 border-b flex items-center gap-2"
             style={{ borderColor: 'rgba(255,255,255,0.07)' }}>
          <svg viewBox="0 0 24 24" className="w-4 h-4 text-cyan-400" fill="none"
               stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 5a2 2 0 1 0 0-4 2 2 0 0 0 0 4zM5 19a2 2 0 1 0 0-4 2 2 0 0 0 0 4zM19 19a2 2 0 1 0 0-4 2 2 0 0 0 0 4zM12 5l-5.5 9.5M12 5l5.5 9.5" />
          </svg>
          <span className="text-sm font-medium text-slate-200">Correlation Network</span>
          <span className="ml-auto text-xs text-slate-600 font-mono">ReactFlow · interactive</span>
        </div>
        <div style={{ background: 'rgba(3,7,18,0.6)' }}>
          <ThreatGraph />
        </div>
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-3 gap-3">
        {[
          { label: 'Threat Actors', value: '12', sub: '3 nation-state', color: '#a855f7' },
          { label: 'Active IOCs', value: '847', sub: '23 critical', color: '#ef4444' },
          { label: 'Campaigns', value: '6', sub: 'last 30 days', color: '#f97316' },
        ].map(s => (
          <div key={s.label} className="px-4 py-3 rounded-xl flex flex-col gap-1" style={glass}>
            <span className="text-xs text-slate-500">{s.label}</span>
            <span className="text-2xl font-bold" style={{ color: s.color }}>{s.value}</span>
            <span className="text-xs text-slate-600">{s.sub}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

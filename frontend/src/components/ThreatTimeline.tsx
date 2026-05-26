import { useState, useEffect } from 'react'

const API_URL = import.meta.env.VITE_API_URL ?? 'http://127.0.0.1:8000'

const glass = {
  background: 'rgba(15,23,42,0.55)',
  backdropFilter: 'blur(16px)',
  border: '1px solid rgba(255,255,255,0.07)',
  borderRadius: 12,
}

interface TimelineEvent {
  time: string
  title: string
  phase: string
  actor?: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  ioc?: string
  technique?: string
}

const SEVERITY_COLOR: Record<string, string> = {
  critical: '#ef4444',
  high:     '#f97316',
  medium:   '#facc15',
  low:      '#4ade80',
  info:     '#22d3ee',
}

const KILL_CHAIN = [
  { phase: 'Reconnaissance',   color: '#818cf8', id: 'recon' },
  { phase: 'Weaponization',    color: '#a78bfa', id: 'weapon' },
  { phase: 'Delivery',         color: '#c084fc', id: 'delivery' },
  { phase: 'Exploitation',     color: '#ef4444', id: 'exploit' },
  { phase: 'Installation',     color: '#f97316', id: 'install' },
  { phase: 'C2',               color: '#facc15', id: 'c2' },
  { phase: 'Actions on Obj.',  color: '#fb923c', id: 'actions' },
]

const STATIC_EVENTS: TimelineEvent[] = [
  { time: '08:14', title: 'Spearphishing email detected', phase: 'Delivery', actor: 'APT29', severity: 'critical', technique: 'T1566.001' },
  { time: '08:31', title: 'Malicious macro execution', phase: 'Exploitation', actor: 'APT29', severity: 'critical', ioc: '198.51.100.42', technique: 'T1059.005' },
  { time: '08:47', title: 'PowerShell encoded command', phase: 'Installation', severity: 'high', technique: 'T1059.001' },
  { time: '09:02', title: 'Scheduled task created', phase: 'Installation', severity: 'high', technique: 'T1053.005' },
  { time: '09:18', title: 'LSASS memory dump', phase: 'Exploitation', severity: 'critical', technique: 'T1003.001' },
  { time: '09:35', title: 'SMB lateral movement', phase: 'C2', ioc: '10.0.0.87', severity: 'high', technique: 'T1021.002' },
  { time: '09:52', title: 'Exfil via encrypted C2', phase: 'C2', ioc: '203.0.113.77', severity: 'critical', technique: 'T1041' },
  { time: '10:15', title: 'Data staged in temp folder', phase: 'Actions on Obj.', severity: 'medium', technique: 'T1074.001' },
  { time: '10:28', title: 'Ransomware dropped (WannaCry variant)', phase: 'Actions on Obj.', severity: 'critical', technique: 'T1486' },
]

export default function ThreatTimeline() {
  const [events, setEvents] = useState<TimelineEvent[]>(STATIC_EVENTS)
  const [filter, setFilter] = useState<string>('all')
  const [selectedPhase, setSelectedPhase] = useState<string | null>(null)

  useEffect(() => {
    fetch(`${API_URL}/ioas`)
      .then(r => r.json())
      .then((ioas: { description?: string; severity?: string; source?: string }[]) => {
        const mapped: TimelineEvent[] = ioas.slice(0, 5).map((ioa, i) => ({
          time: `${10 + i}:${String(i * 7 % 60).padStart(2, '0')}`,
          title: ioa.description ?? 'IOA detected',
          phase: KILL_CHAIN[i % KILL_CHAIN.length].phase,
          severity: (ioa.severity as TimelineEvent['severity']) ?? 'medium',
          actor: ioa.source,
        }))
        setEvents(prev => [...prev, ...mapped])
      })
      .catch(() => {})
  }, [])

  const filtered = events.filter(e => {
    if (filter !== 'all' && e.severity !== filter) return false
    if (selectedPhase && e.phase !== selectedPhase) return false
    return true
  })

  return (
    <div className="space-y-4">

      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-base font-semibold text-slate-100">Attack Timeline</h2>
          <p className="text-xs text-slate-500 mt-0.5">Chronological kill-chain progression · {events.length} events</p>
        </div>
        <div className="flex items-center gap-2">
          {(['all', 'critical', 'high', 'medium', 'low'] as const).map(f => (
            <button key={f} onClick={() => setFilter(f)}
                    className="px-3 py-1 rounded-lg text-xs font-medium transition-all capitalize"
                    style={filter === f ? {
                      background: SEVERITY_COLOR[f] ? `${SEVERITY_COLOR[f]}22` : 'rgba(255,255,255,0.08)',
                      border: `1px solid ${SEVERITY_COLOR[f] ?? 'rgba(255,255,255,0.2)'}`,
                      color: SEVERITY_COLOR[f] ?? '#e2e8f0',
                    } : {
                      background: 'rgba(255,255,255,0.03)',
                      border: '1px solid rgba(255,255,255,0.07)',
                      color: '#475569',
                    }}>
              {f}
            </button>
          ))}
        </div>
      </div>

      {/* Kill chain phases */}
      <div className="rounded-xl overflow-hidden" style={glass}>
        <div className="px-4 py-3 border-b text-xs font-semibold text-slate-500 tracking-wider uppercase"
             style={{ borderColor: 'rgba(255,255,255,0.07)' }}>
          Cyber Kill Chain
        </div>
        <div className="p-4 flex items-center gap-0">
          {KILL_CHAIN.map((phase, i) => (
            <button key={phase.id}
                    onClick={() => setSelectedPhase(selectedPhase === phase.phase ? null : phase.phase)}
                    className="flex-1 flex flex-col items-center gap-1 relative"
                    style={{ opacity: selectedPhase && selectedPhase !== phase.phase ? 0.4 : 1 }}>
              {/* Connector line */}
              {i < KILL_CHAIN.length - 1 && (
                <div className="absolute top-4 left-1/2 w-full h-px"
                     style={{ background: `linear-gradient(to right, ${phase.color}, ${KILL_CHAIN[i+1].color})`, opacity: 0.3, zIndex: 0 }} />
              )}
              {/* Circle */}
              <div className="w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold z-10 transition-all"
                   style={{
                     background: selectedPhase === phase.phase ? phase.color : `${phase.color}22`,
                     border: `2px solid ${phase.color}`,
                     color: selectedPhase === phase.phase ? 'white' : phase.color,
                     boxShadow: selectedPhase === phase.phase ? `0 0 12px ${phase.color}66` : 'none',
                   }}>
                {i + 1}
              </div>
              <span className="text-[9px] text-center leading-tight px-1" style={{ color: phase.color }}>
                {phase.phase}
              </span>
              {/* Event count badge */}
              {(() => {
                const n = events.filter(e => e.phase === phase.phase).length
                return n > 0 ? (
                  <span className="text-[9px] font-bold px-1.5 py-0.5 rounded-full"
                        style={{ background: `${phase.color}33`, color: phase.color }}>
                    {n}
                  </span>
                ) : <span className="h-4" />
              })()}
            </button>
          ))}
        </div>
      </div>

      {/* Timeline events */}
      <div className="rounded-xl overflow-hidden" style={glass}>
        <div className="px-4 py-3 border-b flex items-center justify-between"
             style={{ borderColor: 'rgba(255,255,255,0.07)' }}>
          <span className="text-xs font-semibold text-slate-400 tracking-wider uppercase">
            Events {selectedPhase ? `· ${selectedPhase}` : ''}
          </span>
          {selectedPhase && (
            <button onClick={() => setSelectedPhase(null)} className="text-xs text-slate-600 hover:text-slate-400">
              Clear filter ✕
            </button>
          )}
        </div>
        <div className="divide-y divide-white/5">
          {filtered.length === 0 && (
            <div className="px-4 py-6 text-center text-xs text-slate-600">No events match the current filter</div>
          )}
          {filtered.map((e, i) => {
            const phaseColor = KILL_CHAIN.find(k => k.phase === e.phase)?.color ?? '#64748b'
            return (
              <div key={i} className="flex items-start gap-4 px-4 py-3 hover:bg-white/[0.02] transition-colors">
                {/* Time */}
                <span className="font-mono text-xs text-slate-600 shrink-0 w-12 pt-0.5">{e.time}</span>

                {/* Severity dot */}
                <div className="mt-1.5 shrink-0">
                  <span className="w-2 h-2 rounded-full block"
                        style={{ background: SEVERITY_COLOR[e.severity], boxShadow: `0 0 6px ${SEVERITY_COLOR[e.severity]}` }} />
                </div>

                {/* Content */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-sm font-medium text-slate-200">{e.title}</span>
                    <span className="text-[10px] font-bold px-1.5 py-0.5 rounded uppercase"
                          style={{ background: `${SEVERITY_COLOR[e.severity]}22`, color: SEVERITY_COLOR[e.severity] }}>
                      {e.severity}
                    </span>
                  </div>
                  <div className="flex items-center gap-3 mt-1 flex-wrap">
                    <span className="text-[10px] px-1.5 py-0.5 rounded"
                          style={{ background: `${phaseColor}18`, color: phaseColor }}>
                      {e.phase}
                    </span>
                    {e.actor && (
                      <span className="text-[10px] text-slate-500">
                        <span className="text-slate-700">Actor: </span>{e.actor}
                      </span>
                    )}
                    {e.technique && (
                      <span className="text-[10px] font-mono text-slate-600">{e.technique}</span>
                    )}
                    {e.ioc && (
                      <span className="text-[10px] font-mono text-cyan-700">{e.ioc}</span>
                    )}
                  </div>
                </div>
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}

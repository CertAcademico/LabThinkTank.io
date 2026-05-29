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
  description?: string
  phase: string
  actor?: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  ioc?: string
  technique?: string
  detectionSource?: string
  origin: 'simulation' | 'live'
}

interface IOAItem {
  ttp: string
  ttp_name: string
  tactic: string
  ioa: string
  detection_source: string
  priority: 'critical' | 'high' | 'medium' | 'low'
  attributed_actor: string
  attributed_campaign: string
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

const TACTIC_TO_PHASE: Record<string, string> = {
  'Reconnaissance':       'Reconnaissance',
  'Resource Development': 'Weaponization',
  'Initial Access':       'Delivery',
  'Execution':            'Exploitation',
  'Persistence':          'Installation',
  'Privilege Escalation': 'Installation',
  'Defense Evasion':      'Installation',
  'Credential Access':    'Actions on Obj.',
  'Discovery':            'Reconnaissance',
  'Lateral Movement':     'C2',
  'Collection':           'Actions on Obj.',
  'Command and Control':  'C2',
  'Exfiltration':         'Actions on Obj.',
  'Impact':               'Actions on Obj.',
}

const STATIC_EVENTS: TimelineEvent[] = [
  { time: '08:14', title: 'Spearphishing email detected',       phase: 'Delivery',         actor: 'APT29', severity: 'critical', technique: 'T1566.001', origin: 'simulation' },
  { time: '08:31', title: 'Malicious macro execution',          phase: 'Exploitation',     actor: 'APT29', severity: 'critical', ioc: '198.51.100.42', technique: 'T1059.005', origin: 'simulation' },
  { time: '08:47', title: 'PowerShell encoded command',         phase: 'Installation',     severity: 'high',     technique: 'T1059.001', origin: 'simulation' },
  { time: '09:02', title: 'Scheduled task created',             phase: 'Installation',     severity: 'high',     technique: 'T1053.005', origin: 'simulation' },
  { time: '09:18', title: 'LSASS memory dump',                  phase: 'Exploitation',     severity: 'critical', technique: 'T1003.001', origin: 'simulation' },
  { time: '09:35', title: 'SMB lateral movement',               phase: 'C2',               ioc: '10.0.0.87',  severity: 'high',     technique: 'T1021.002', origin: 'simulation' },
  { time: '09:52', title: 'Exfil via encrypted C2',             phase: 'C2',               ioc: '203.0.113.77', severity: 'critical', technique: 'T1041', origin: 'simulation' },
  { time: '10:15', title: 'Data staged in temp folder',         phase: 'Actions on Obj.',  severity: 'medium', technique: 'T1074.001', origin: 'simulation' },
  { time: '10:28', title: 'Ransomware dropped (WannaCry variant)', phase: 'Actions on Obj.', severity: 'critical', technique: 'T1486', origin: 'simulation' },
]

function formatEventTime(offsetMinutes: number): string {
  const base = 10 * 60 + 43
  const total = base + offsetMinutes
  const h = Math.floor(total / 60) % 24
  const m = total % 60
  return `${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}`
}

export default function ThreatTimeline() {
  const [events, setEvents] = useState<TimelineEvent[]>(STATIC_EVENTS)
  const [filter, setFilter] = useState<string>('all')
  const [selectedPhase, setSelectedPhase] = useState<string | null>(null)
  const [showOrigin, setShowOrigin] = useState<'all' | 'simulation' | 'live'>('all')
  const [expanded, setExpanded] = useState<number | null>(null)
  const [liveCount, setLiveCount] = useState(0)

  useEffect(() => {
    fetch(`${API_URL}/ioas`)
      .then(r => r.json())
      .then((ioas: IOAItem[]) => {
        const mapped: TimelineEvent[] = ioas.map((ioa, i) => ({
          time:            formatEventTime(i * 15),
          title:           ioa.ttp_name,
          description:     ioa.ioa,
          phase:           TACTIC_TO_PHASE[ioa.tactic] ?? 'Actions on Obj.',
          severity:        ioa.priority ?? 'medium',
          actor:           ioa.attributed_actor,
          technique:       ioa.ttp,
          detectionSource: ioa.detection_source,
          origin:          'live' as const,
        }))
        setLiveCount(mapped.length)
        setEvents(prev => [...prev, ...mapped])
      })
      .catch(() => {})
  }, [])

  const filtered = events.filter(e => {
    if (filter !== 'all' && e.severity !== filter) return false
    if (selectedPhase && e.phase !== selectedPhase) return false
    if (showOrigin !== 'all' && e.origin !== showOrigin) return false
    return true
  })

  const today = new Date().toLocaleDateString('es-MX', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' })

  return (
    <div className="space-y-4">

      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-base font-semibold text-slate-100">Attack Timeline</h2>
          <p className="text-xs text-slate-500 mt-0.5">
            {today} · {filtered.length} de {events.length} eventos
            {liveCount > 0 && (
              <span className="ml-2 px-1.5 py-0.5 rounded text-[9px] font-bold"
                    style={{ background: 'rgba(34,211,238,0.12)', color: '#22d3ee' }}>
                {liveCount} live IOAs
              </span>
            )}
          </p>
        </div>

        <div className="flex items-center gap-2 flex-wrap justify-end">
          {/* Origin filter */}
          <div className="flex items-center gap-1 rounded-lg border overflow-hidden"
               style={{ borderColor: 'rgba(255,255,255,0.08)' }}>
            {(['all', 'live', 'simulation'] as const).map(o => (
              <button key={o} onClick={() => setShowOrigin(o)}
                      className="px-2.5 py-1 text-xs transition-all capitalize"
                      style={showOrigin === o ? {
                        background: 'rgba(255,255,255,0.08)',
                        color: '#e2e8f0',
                      } : { color: '#475569' }}>
                {o === 'all' ? 'Todos' : o === 'live' ? 'Live IOA' : 'Simulación'}
              </button>
            ))}
          </div>

          {/* Severity filter */}
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
              {i < KILL_CHAIN.length - 1 && (
                <div className="absolute top-4 left-1/2 w-full h-px"
                     style={{ background: `linear-gradient(to right, ${phase.color}, ${KILL_CHAIN[i+1].color})`, opacity: 0.3, zIndex: 0 }} />
              )}
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
            Eventos{selectedPhase ? ` · ${selectedPhase}` : ''}
          </span>
          {(selectedPhase || filter !== 'all' || showOrigin !== 'all') && (
            <button onClick={() => { setSelectedPhase(null); setFilter('all'); setShowOrigin('all') }}
                    className="text-xs text-slate-600 hover:text-slate-400 transition-colors">
              Limpiar filtros ✕
            </button>
          )}
        </div>
        <div className="divide-y divide-white/5">
          {filtered.length === 0 && (
            <div className="px-4 py-6 text-center text-xs text-slate-600">
              No hay eventos con los filtros actuales
            </div>
          )}
          {filtered.map((e, i) => {
            const phaseColor = KILL_CHAIN.find(k => k.phase === e.phase)?.color ?? '#64748b'
            const isExpanded = expanded === i
            return (
              <div key={i}
                   className="hover:bg-white/[0.02] transition-colors cursor-pointer"
                   onClick={() => setExpanded(isExpanded ? null : i)}>
                <div className="flex items-start gap-4 px-4 py-3">
                  {/* Time + origin */}
                  <div className="shrink-0 w-14 pt-0.5 flex flex-col gap-1">
                    <span className="font-mono text-xs text-slate-600">{e.time}</span>
                    {e.origin === 'live' && (
                      <span className="text-[8px] font-bold px-1 py-0.5 rounded text-center"
                            style={{ background: 'rgba(34,211,238,0.1)', color: '#22d3ee' }}>
                        LIVE
                      </span>
                    )}
                  </div>

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
                      {e.detectionSource && (
                        <span className="text-[10px] text-slate-600">
                          <span className="text-slate-700">Fuente: </span>{e.detectionSource}
                        </span>
                      )}
                    </div>
                  </div>

                  {/* Expand arrow */}
                  {(e.description) && (
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"
                         className="w-3.5 h-3.5 shrink-0 mt-1 text-slate-700 transition-transform"
                         style={{ transform: isExpanded ? 'rotate(180deg)' : 'rotate(0deg)' }}>
                      <path d="M6 9l6 6 6-6" />
                    </svg>
                  )}
                </div>

                {/* Expanded: IOA description */}
                {isExpanded && e.description && (
                  <div className="px-4 pb-3 ml-18">
                    <div className="ml-[4.5rem] rounded-lg p-3 text-xs text-slate-400 leading-relaxed"
                         style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.05)' }}>
                      <span className="text-slate-600 font-semibold uppercase text-[9px] tracking-wider block mb-1">
                        Indicador de Ataque (IOA)
                      </span>
                      {e.description}
                    </div>
                  </div>
                )}
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}

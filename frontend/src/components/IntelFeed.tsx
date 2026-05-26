import { useState, useEffect } from 'react'

const API_URL = import.meta.env.VITE_API_URL ?? 'http://127.0.0.1:8000'

const glass = {
  background: 'rgba(15,23,42,0.55)',
  backdropFilter: 'blur(16px)',
  border: '1px solid rgba(255,255,255,0.07)',
  borderRadius: 12,
}

interface FeedEntry {
  id: number | string
  source: string
  title: string
  type: string
  severity: string
  ts: string
  tags?: string[]
  ioc?: string
}

const SEVERITY_COLOR: Record<string, string> = {
  critical: '#ef4444',
  high:     '#f97316',
  medium:   '#facc15',
  low:      '#4ade80',
  info:     '#22d3ee',
}

const SOURCE_STYLE: Record<string, { color: string; bg: string }> = {
  VirusTotal:  { color: '#60a5fa', bg: 'rgba(96,165,250,0.12)' },
  ThreatFox:   { color: '#f87171', bg: 'rgba(248,113,113,0.12)' },
  'Abuse.ch':  { color: '#fb923c', bg: 'rgba(251,146,60,0.12)' },
  MISP:        { color: '#a78bfa', bg: 'rgba(167,139,250,0.12)' },
  OpenCTI:     { color: '#34d399', bg: 'rgba(52,211,153,0.12)' },
  AbuseIPDB:   { color: '#fbbf24', bg: 'rgba(251,191,36,0.12)' },
  Shodan:      { color: '#22d3ee', bg: 'rgba(34,211,238,0.12)' },
  Internal:    { color: '#94a3b8', bg: 'rgba(148,163,184,0.1)' },
}

const STATIC_FEED: FeedEntry[] = [
  { id: 's1', source: 'ThreatFox', title: 'New Cobalt Strike beacon C2 infrastructure', type: 'C2', severity: 'critical', ts: '10:47', tags: ['cobaltstrike', 'apt'], ioc: '198.51.100.42:443' },
  { id: 's2', source: 'Abuse.ch', title: 'Emotet botnet resuming campaigns — new wave', type: 'Malware', severity: 'high', ts: '10:31', tags: ['emotet', 'banking'] },
  { id: 's3', source: 'VirusTotal', title: 'WannaCry variant hash seen in 14 submissions', type: 'Ransomware', severity: 'critical', ts: '10:12', ioc: 'b47a42c...9d1f', tags: ['ransomware', 'wannacry'] },
  { id: 's4', source: 'MISP', title: 'APT29 phishing domain cluster — EU targets', type: 'Phishing', severity: 'high', ts: '09:58', tags: ['apt29', 'phishing', 'eu'] },
  { id: 's5', source: 'OpenCTI', title: 'Lazarus Group toolkit TTPs updated in framework', type: 'TTP', severity: 'medium', ts: '09:33', tags: ['lazarus', 'dprk'] },
  { id: 's6', source: 'AbuseIPDB', title: 'Mass SSH brute-force campaign from 5 ASNs', type: 'Scanning', severity: 'medium', ts: '09:15', tags: ['bruteforce', 'ssh'] },
  { id: 's7', source: 'Shodan', title: 'Exposed Fortinet devices — 3,400 new CVE-2024 hits', type: 'Vuln', severity: 'high', ts: '08:52', tags: ['fortinet', 'cve-2024'] },
  { id: 's8', source: 'Internal', title: 'Honeypot triggered — SMB probing from 10.0.0.0/8', type: 'IOA', severity: 'low', ts: '08:30', tags: ['honeypot', 'smb'] },
]

const SOURCES = Object.keys(SOURCE_STYLE)

function SourceTag({ source }: { source: string }) {
  const st = SOURCE_STYLE[source] ?? { color: '#94a3b8', bg: 'rgba(148,163,184,0.1)' }
  return (
    <span className="text-[10px] font-semibold px-2 py-0.5 rounded shrink-0"
          style={{ background: st.bg, color: st.color }}>
      {source}
    </span>
  )
}

export default function IntelFeed() {
  const [feed, setFeed] = useState<FeedEntry[]>(STATIC_FEED)
  const [activeSource, setActiveSource] = useState<string>('all')
  const [activeSev, setActiveSev] = useState<string>('all')
  const [pulse, setPulse] = useState(false)

  useEffect(() => {
    fetch(`${API_URL}/ioc-feed`)
      .then(r => r.json())
      .then((iocs: { id: number; ioc: string; type: string; severity: string; threat_actor: string }[]) => {
        const mapped: FeedEntry[] = iocs.slice(0, 8).map(i => ({
          id: `ioc-${i.id}`,
          source: 'Internal',
          title: `${i.type.toUpperCase()} indicator — ${i.ioc}`,
          type: i.type,
          severity: i.severity,
          ts: new Date().toLocaleTimeString('es-MX', { hour: '2-digit', minute: '2-digit' }),
          tags: [i.threat_actor, i.type],
          ioc: i.ioc,
        }))
        setFeed(prev => [...mapped, ...prev])
        setPulse(true)
        setTimeout(() => setPulse(false), 1500)
      })
      .catch(() => {})
  }, [])

  const filtered = feed.filter(e => {
    const matchSrc = activeSource === 'all' || e.source === activeSource
    const matchSev = activeSev === 'all' || e.severity === activeSev
    return matchSrc && matchSev
  })

  const sourceCounts = SOURCES.reduce<Record<string, number>>((acc, s) => {
    acc[s] = feed.filter(e => e.source === s).length
    return acc
  }, {})

  return (
    <div className="space-y-4">

      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-base font-semibold text-slate-100">Intelligence Feeds</h2>
          <p className="text-xs text-slate-500 mt-0.5">Aggregated OSINT & CTI — {feed.length} entries ingested</p>
        </div>
        <div className="flex items-center gap-2">
          <div className={`flex items-center gap-2 px-3 py-1.5 rounded-lg border text-xs transition-all ${pulse ? 'scale-105' : ''}`}
               style={{ background: 'rgba(74,222,128,0.06)', borderColor: 'rgba(74,222,128,0.2)', color: '#4ade80' }}>
            <span className="w-1.5 h-1.5 bg-green-400 rounded-full animate-pulse" />
            {filtered.length} entries
          </div>
        </div>
      </div>

      <div className="flex gap-4">

        {/* Left: source sidebar */}
        <div className="w-48 shrink-0 space-y-2">
          <div className="rounded-xl overflow-hidden" style={glass}>
            <div className="px-3 py-2.5 border-b text-[10px] font-semibold text-slate-600 uppercase tracking-wider"
                 style={{ borderColor: 'rgba(255,255,255,0.07)' }}>
              Fuentes
            </div>
            <div className="p-2 space-y-0.5">
              <button onClick={() => setActiveSource('all')}
                      className="w-full flex items-center justify-between px-3 py-2 rounded-lg text-xs transition-all"
                      style={activeSource === 'all' ? { background: 'rgba(255,255,255,0.08)', color: '#e2e8f0' } : { color: '#475569' }}>
                <span>Todas</span>
                <span className="font-mono text-[10px]">{feed.length}</span>
              </button>
              {SOURCES.map(s => {
                const st = SOURCE_STYLE[s]
                const count = sourceCounts[s] ?? 0
                if (!count) return null
                return (
                  <button key={s} onClick={() => setActiveSource(s)}
                          className="w-full flex items-center justify-between px-3 py-2 rounded-lg text-xs transition-all"
                          style={activeSource === s ? {
                            background: st.bg,
                            color: st.color,
                          } : { color: '#475569' }}>
                    <span>{s}</span>
                    <span className="font-mono text-[10px]">{count}</span>
                  </button>
                )
              })}
            </div>
          </div>

          {/* Severity filter */}
          <div className="rounded-xl overflow-hidden" style={glass}>
            <div className="px-3 py-2.5 border-b text-[10px] font-semibold text-slate-600 uppercase tracking-wider"
                 style={{ borderColor: 'rgba(255,255,255,0.07)' }}>
              Severidad
            </div>
            <div className="p-2 space-y-0.5">
              {['all', 'critical', 'high', 'medium', 'low', 'info'].map(sev => (
                <button key={sev} onClick={() => setActiveSev(sev)}
                        className="w-full flex items-center justify-between px-3 py-2 rounded-lg text-xs transition-all capitalize"
                        style={activeSev === sev ? {
                          background: sev === 'all' ? 'rgba(255,255,255,0.08)' : `${SEVERITY_COLOR[sev]}18`,
                          color: sev === 'all' ? '#e2e8f0' : SEVERITY_COLOR[sev],
                        } : { color: '#475569' }}>
                  <span>{sev}</span>
                  <span className="font-mono text-[10px]">
                    {sev === 'all' ? feed.length : feed.filter(e => e.severity === sev).length}
                  </span>
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Right: feed entries */}
        <div className="flex-1 rounded-xl overflow-hidden" style={glass}>
          <div className="divide-y divide-white/5">
            {filtered.length === 0 && (
              <div className="px-4 py-8 text-center text-xs text-slate-600">No hay entradas para los filtros seleccionados</div>
            )}
            {filtered.map((entry, i) => (
              <div key={`${entry.id}-${i}`}
                   className="flex items-start gap-3 px-4 py-3.5 hover:bg-white/[0.02] transition-colors">
                {/* Severity bar */}
                <div className="w-0.5 self-stretch rounded-full shrink-0 mt-0.5"
                     style={{ background: SEVERITY_COLOR[entry.severity] ?? '#475569', opacity: 0.7 }} />

                {/* Content */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-start gap-2 flex-wrap">
                    <SourceTag source={entry.source} />
                    <span className="text-[10px] font-mono uppercase px-1.5 py-0.5 rounded shrink-0"
                          style={{ background: 'rgba(255,255,255,0.05)', color: '#64748b' }}>
                      {entry.type}
                    </span>
                    <span className="text-[10px] font-bold px-1.5 py-0.5 rounded-full uppercase shrink-0"
                          style={{ color: SEVERITY_COLOR[entry.severity] ?? '#64748b', background: `${SEVERITY_COLOR[entry.severity] ?? '#64748b'}18` }}>
                      {entry.severity}
                    </span>
                    <span className="ml-auto text-[10px] font-mono text-slate-700 shrink-0">{entry.ts}</span>
                  </div>
                  <p className="text-sm text-slate-200 mt-1.5 leading-snug">{entry.title}</p>
                  {entry.ioc && (
                    <p className="text-[10px] font-mono text-cyan-600 mt-1">{entry.ioc}</p>
                  )}
                  {entry.tags && entry.tags.length > 0 && (
                    <div className="flex gap-1 mt-1.5 flex-wrap">
                      {entry.tags.filter(Boolean).map(tag => (
                        <span key={tag} className="text-[9px] px-1.5 py-0.5 rounded font-mono text-slate-600"
                              style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.07)' }}>
                          #{tag}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}

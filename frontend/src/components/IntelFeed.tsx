import { useState, useEffect, useCallback } from 'react'

const API_URL = import.meta.env.VITE_API_URL ?? 'http://127.0.0.1:8000'

const glass = {
  background: 'rgba(15,23,42,0.55)',
  backdropFilter: 'blur(16px)',
  border: '1px solid rgba(255,255,255,0.07)',
  borderRadius: 12,
}

// ── Types ─────────────────────────────────────────────────────────────────────

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

interface MispIoc {
  ioc: string
  type: string
  threat_actor: string
  severity: string
  mitre: string
  source: string
  event_id?: string
}

interface MispStatus {
  mode: 'public' | 'private'
  configured: boolean
  sources?: string[]
  url?: string
  note?: string
}

interface ImportResult {
  fetched: number
  added: number
  skipped: number
}

// ── Constants ─────────────────────────────────────────────────────────────────

const SEVERITY_COLOR: Record<string, string> = {
  critical: '#ef4444',
  high:     '#f97316',
  medium:   '#facc15',
  low:      '#4ade80',
  info:     '#22d3ee',
}

const SOURCE_STYLE: Record<string, { color: string; bg: string }> = {
  VirusTotal:     { color: '#60a5fa', bg: 'rgba(96,165,250,0.12)' },
  ThreatFox:      { color: '#f87171', bg: 'rgba(248,113,113,0.12)' },
  'Abuse.ch':     { color: '#fb923c', bg: 'rgba(251,146,60,0.12)' },
  MISP:           { color: '#a78bfa', bg: 'rgba(167,139,250,0.12)' },
  malwarebazaar:  { color: '#a78bfa', bg: 'rgba(167,139,250,0.12)' },
  urlhaus:        { color: '#fb923c', bg: 'rgba(251,146,60,0.12)' },
  OpenCTI:        { color: '#34d399', bg: 'rgba(52,211,153,0.12)' },
  AbuseIPDB:      { color: '#fbbf24', bg: 'rgba(251,191,36,0.12)' },
  Shodan:         { color: '#22d3ee', bg: 'rgba(34,211,238,0.12)' },
  Internal:       { color: '#94a3b8', bg: 'rgba(148,163,184,0.1)' },
}

const STATIC_FEED: FeedEntry[] = [
  { id: 's1', source: 'ThreatFox',  title: 'New Cobalt Strike beacon C2 infrastructure',       type: 'C2',         severity: 'critical', ts: '10:47', tags: ['cobaltstrike', 'apt'],        ioc: '198.51.100.42:443' },
  { id: 's2', source: 'Abuse.ch',   title: 'Emotet botnet resuming campaigns — new wave',       type: 'Malware',    severity: 'high',     ts: '10:31', tags: ['emotet', 'banking'] },
  { id: 's3', source: 'VirusTotal', title: 'WannaCry variant hash seen in 14 submissions',      type: 'Ransomware', severity: 'critical', ts: '10:12', tags: ['ransomware', 'wannacry'],    ioc: 'b47a42c...9d1f' },
  { id: 's4', source: 'MISP',       title: 'APT29 phishing domain cluster — EU targets',        type: 'Phishing',   severity: 'high',     ts: '09:58', tags: ['apt29', 'phishing', 'eu'] },
  { id: 's5', source: 'OpenCTI',    title: 'Lazarus Group toolkit TTPs updated in framework',   type: 'TTP',        severity: 'medium',   ts: '09:33', tags: ['lazarus', 'dprk'] },
  { id: 's6', source: 'AbuseIPDB',  title: 'Mass SSH brute-force campaign from 5 ASNs',         type: 'Scanning',   severity: 'medium',   ts: '09:15', tags: ['bruteforce', 'ssh'] },
  { id: 's7', source: 'Shodan',     title: 'Exposed Fortinet devices — 3,400 new CVE-2024 hits',type: 'Vuln',       severity: 'high',     ts: '08:52', tags: ['fortinet', 'cve-2024'] },
  { id: 's8', source: 'Internal',   title: 'Honeypot triggered — SMB probing from 10.0.0.0/8', type: 'IOA',        severity: 'low',      ts: '08:30', tags: ['honeypot', 'smb'] },
]

// ── Sub-components ────────────────────────────────────────────────────────────

function SourceTag({ source }: { source: string }) {
  const st = SOURCE_STYLE[source] ?? { color: '#94a3b8', bg: 'rgba(148,163,184,0.1)' }
  const label = source === 'malwarebazaar' ? 'MalwareBazaar' : source === 'urlhaus' ? 'URLhaus' : source
  return (
    <span className="text-[10px] font-semibold px-2 py-0.5 rounded shrink-0"
          style={{ background: st.bg, color: st.color }}>
      {label}
    </span>
  )
}

function SevBadge({ sev }: { sev: string }) {
  const c = SEVERITY_COLOR[sev] ?? '#64748b'
  return (
    <span className="text-[10px] font-bold px-1.5 py-0.5 rounded-full uppercase shrink-0"
          style={{ color: c, background: `${c}18` }}>
      {sev}
    </span>
  )
}

// ── MISP Panel ────────────────────────────────────────────────────────────────

function MispPanel() {
  const [status, setStatus]       = useState<MispStatus | null>(null)
  const [iocs, setIocs]           = useState<MispIoc[]>([])
  const [loading, setLoading]     = useState(false)
  const [importing, setImporting] = useState(false)
  const [importResult, setImportResult] = useState<ImportResult | null>(null)
  const [error, setError]         = useState('')
  const [limit, setLimit]         = useState(30)
  const [filterType, setFilterType] = useState('all')
  const [filterSev, setFilterSev]   = useState('all')

  const fetchStatus = useCallback(() => {
    fetch(`${API_URL}/misp/status`)
      .then(r => r.json())
      .then(setStatus)
      .catch(() => {})
  }, [])

  const fetchIocs = useCallback(() => {
    setLoading(true)
    setError('')
    setImportResult(null)
    fetch(`${API_URL}/misp/iocs?limit=${limit}`)
      .then(r => r.json())
      .then(d => {
        if (d.detail) throw new Error(d.detail)
        setIocs(d.iocs ?? [])
      })
      .catch(e => setError(e.message))
      .finally(() => setLoading(false))
  }, [limit])

  const handleImport = () => {
    setImporting(true)
    setImportResult(null)
    fetch(`${API_URL}/misp/import?limit=${limit}`, { method: 'POST' })
      .then(r => r.json())
      .then(d => {
        if (d.detail) throw new Error(d.detail)
        setImportResult(d)
      })
      .catch(e => setError(e.message))
      .finally(() => setImporting(false))
  }

  useEffect(() => { fetchStatus(); fetchIocs() }, [fetchStatus, fetchIocs])

  const types = ['all', ...Array.from(new Set(iocs.map(i => i.type)))]
  const sevs  = ['all', 'critical', 'high', 'medium', 'low']
  const filtered = iocs.filter(i =>
    (filterType === 'all' || i.type === filterType) &&
    (filterSev  === 'all' || i.severity === filterSev)
  )

  return (
    <div className="space-y-4">

      {/* Status + controls */}
      <div className="rounded-xl p-4 flex flex-wrap items-center gap-4" style={glass}>

        {/* Mode badge */}
        {status && (
          <div className="flex items-center gap-2">
            <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold"
                 style={status.configured
                   ? { background: 'rgba(167,139,250,0.12)', color: '#a78bfa', border: '1px solid rgba(167,139,250,0.3)' }
                   : { background: 'rgba(251,146,60,0.1)',   color: '#fb923c', border: '1px solid rgba(251,146,60,0.25)' }}>
              <span className={`w-1.5 h-1.5 rounded-full ${status.configured ? 'bg-violet-400' : 'bg-orange-400'} animate-pulse`} />
              {status.configured ? `MISP Privado · ${status.url}` : 'Modo Público'}
            </div>
            {!status.configured && status.sources && (
              <div className="flex gap-1">
                {status.sources.map(s => <SourceTag key={s} source={s} />)}
              </div>
            )}
          </div>
        )}

        <div className="flex items-center gap-2 ml-auto flex-wrap">
          {/* limit selector */}
          <select value={limit} onChange={e => setLimit(Number(e.target.value))}
                  className="text-xs rounded-lg px-2 py-1.5 border outline-none"
                  style={{ background: 'rgba(255,255,255,0.05)', borderColor: 'rgba(255,255,255,0.1)', color: '#94a3b8' }}>
            {[10, 20, 30, 50, 100].map(n => <option key={n} value={n}>{n} IOCs</option>)}
          </select>

          {/* refresh */}
          <button onClick={fetchIocs} disabled={loading}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs border transition-all disabled:opacity-40"
                  style={{ background: 'rgba(34,211,238,0.07)', borderColor: 'rgba(34,211,238,0.25)', color: '#22d3ee' }}>
            <svg viewBox="0 0 24 24" className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`}
                 fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M23 4v6h-6M1 20v-6h6" />
              <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15" />
            </svg>
            {loading ? 'Cargando…' : 'Actualizar'}
          </button>

          {/* import */}
          <button onClick={handleImport} disabled={importing || iocs.length === 0}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs border transition-all disabled:opacity-40"
                  style={{ background: 'rgba(167,139,250,0.1)', borderColor: 'rgba(167,139,250,0.3)', color: '#a78bfa' }}>
            <svg viewBox="0 0 24 24" className={`w-3.5 h-3.5 ${importing ? 'animate-pulse' : ''}`}
                 fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
              <polyline points="7 10 12 15 17 10" />
              <line x1="12" y1="15" x2="12" y2="3" />
            </svg>
            {importing ? 'Importando…' : 'Importar a DB'}
          </button>
        </div>
      </div>

      {/* Config hint */}
      {status && !status.configured && (
        <div className="rounded-xl px-4 py-3 text-xs flex items-start gap-3"
             style={{ background: 'rgba(167,139,250,0.06)', border: '1px solid rgba(167,139,250,0.15)' }}>
          <svg viewBox="0 0 24 24" className="w-4 h-4 text-violet-400 shrink-0 mt-0.5"
               fill="none" stroke="currentColor" strokeWidth="2">
            <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
          </svg>
          <span className="text-violet-300/70">
            Usando feeds públicos (MalwareBazaar + URLhaus). Para conectar tu instancia MISP privada,
            agrega <code className="font-mono text-violet-300 bg-white/5 px-1 rounded">MISP_URL</code> y{' '}
            <code className="font-mono text-violet-300 bg-white/5 px-1 rounded">MISP_KEY</code> en tu <code className="font-mono text-violet-300 bg-white/5 px-1 rounded">.env</code>.
          </span>
        </div>
      )}

      {/* Import result */}
      {importResult && (
        <div className="rounded-xl px-4 py-3 text-xs flex items-center gap-4"
             style={{ background: 'rgba(74,222,128,0.07)', border: '1px solid rgba(74,222,128,0.2)' }}>
          <svg viewBox="0 0 24 24" className="w-4 h-4 text-green-400 shrink-0"
               fill="none" stroke="currentColor" strokeWidth="2">
            <polyline points="20 6 9 17 4 12"/>
          </svg>
          <span className="text-green-300">Import completado —</span>
          <span className="text-green-400 font-semibold">{importResult.added} nuevos</span>
          <span className="text-slate-500">· {importResult.skipped} ya existían · {importResult.fetched} fetched</span>
        </div>
      )}

      {/* Error */}
      {error && (
        <div className="rounded-xl px-4 py-3 text-xs text-red-400"
             style={{ background: 'rgba(239,68,68,0.07)', border: '1px solid rgba(239,68,68,0.2)' }}>
          {error}
        </div>
      )}

      <div className="flex gap-4">

        {/* Filters sidebar */}
        <div className="w-44 shrink-0 space-y-2">
          <div className="rounded-xl overflow-hidden" style={glass}>
            <div className="px-3 py-2 border-b text-[10px] font-semibold text-slate-600 uppercase tracking-wider"
                 style={{ borderColor: 'rgba(255,255,255,0.07)' }}>
              Tipo
            </div>
            <div className="p-1.5 space-y-0.5">
              {types.map(t => (
                <button key={t} onClick={() => setFilterType(t)}
                        className="w-full flex items-center justify-between px-2.5 py-1.5 rounded-lg text-xs transition-all capitalize"
                        style={filterType === t
                          ? { background: 'rgba(34,211,238,0.1)', color: '#22d3ee' }
                          : { color: '#475569' }}>
                  <span>{t === 'all' ? 'Todos' : t}</span>
                  <span className="font-mono text-[10px]">
                    {t === 'all' ? iocs.length : iocs.filter(i => i.type === t).length}
                  </span>
                </button>
              ))}
            </div>
          </div>

          <div className="rounded-xl overflow-hidden" style={glass}>
            <div className="px-3 py-2 border-b text-[10px] font-semibold text-slate-600 uppercase tracking-wider"
                 style={{ borderColor: 'rgba(255,255,255,0.07)' }}>
              Severidad
            </div>
            <div className="p-1.5 space-y-0.5">
              {sevs.map(s => {
                const c = SEVERITY_COLOR[s]
                return (
                  <button key={s} onClick={() => setFilterSev(s)}
                          className="w-full flex items-center justify-between px-2.5 py-1.5 rounded-lg text-xs capitalize transition-all"
                          style={filterSev === s
                            ? { background: s === 'all' ? 'rgba(255,255,255,0.08)' : `${c}18`, color: s === 'all' ? '#e2e8f0' : c }
                            : { color: '#475569' }}>
                    <span>{s === 'all' ? 'Todas' : s}</span>
                    <span className="font-mono text-[10px]">
                      {s === 'all' ? iocs.length : iocs.filter(i => i.severity === s).length}
                    </span>
                  </button>
                )
              })}
            </div>
          </div>
        </div>

        {/* IOC table */}
        <div className="flex-1 rounded-xl overflow-hidden" style={glass}>
          {loading && iocs.length === 0 ? (
            <div className="flex items-center justify-center h-48 text-xs text-slate-600">
              <svg viewBox="0 0 24 24" className="w-4 h-4 animate-spin mr-2"
                   fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M21 12a9 9 0 1 1-6.219-8.56" />
              </svg>
              Obteniendo IOCs del feed…
            </div>
          ) : filtered.length === 0 ? (
            <div className="flex items-center justify-center h-48 text-xs text-slate-600">
              Sin resultados para los filtros seleccionados
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
                    {['Indicador', 'Tipo', 'Severidad', 'Actor', 'MITRE', 'Fuente'].map(h => (
                      <th key={h} className="text-left px-4 py-2.5 text-[10px] font-semibold text-slate-600 uppercase tracking-wider whitespace-nowrap">
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((ioc, i) => (
                    <tr key={`${ioc.ioc}-${i}`}
                        className="hover:bg-white/[0.02] transition-colors"
                        style={{ borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                      <td className="px-4 py-2.5">
                        <span className="font-mono text-cyan-400/80 text-[11px] block max-w-[260px] truncate">
                          {ioc.ioc}
                        </span>
                      </td>
                      <td className="px-4 py-2.5 whitespace-nowrap">
                        <span className="font-mono text-[10px] px-1.5 py-0.5 rounded"
                              style={{ background: 'rgba(255,255,255,0.05)', color: '#64748b' }}>
                          {ioc.type}
                        </span>
                      </td>
                      <td className="px-4 py-2.5 whitespace-nowrap">
                        <SevBadge sev={ioc.severity} />
                      </td>
                      <td className="px-4 py-2.5 text-slate-400 whitespace-nowrap max-w-[140px] truncate">
                        {ioc.threat_actor || '—'}
                      </td>
                      <td className="px-4 py-2.5">
                        {ioc.mitre
                          ? <span className="font-mono text-[10px] text-violet-400/70">{ioc.mitre}</span>
                          : <span className="text-slate-700">—</span>}
                      </td>
                      <td className="px-4 py-2.5 whitespace-nowrap">
                        <SourceTag source={ioc.source} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

// ── Intel Feed Panel ──────────────────────────────────────────────────────────

const SOURCES = Object.keys(SOURCE_STYLE).filter(s => !['malwarebazaar', 'urlhaus'].includes(s))

export default function IntelFeed() {
  const [tab, setTab]               = useState<'feeds' | 'misp'>('feeds')
  const [feed, setFeed]             = useState<FeedEntry[]>(STATIC_FEED)
  const [activeSource, setActiveSource] = useState('all')
  const [activeSev, setActiveSev]   = useState('all')
  const [pulse, setPulse]           = useState(false)

  useEffect(() => {
    fetch(`${API_URL}/ioc-feed`)
      .then(r => r.json())
      .then((iocs: { id: number; ioc: string; type: string; severity: string; threat_actor: string }[]) => {
        const mapped: FeedEntry[] = iocs.map(i => ({
          id:       `ioc-${i.id}`,
          source:   'Internal',
          title:    `${i.type.toUpperCase()} indicator — ${i.ioc}`,
          type:     i.type,
          severity: i.severity,
          ts:       new Date().toLocaleTimeString('es-MX', { hour: '2-digit', minute: '2-digit' }),
          tags:     [i.threat_actor, i.type].filter(Boolean),
          ioc:      i.ioc,
        }))
        setFeed(prev => [...mapped, ...prev])
        setPulse(true)
        setTimeout(() => setPulse(false), 1500)
      })
      .catch(() => {})
  }, [])

  const filtered = feed.filter(e =>
    (activeSource === 'all' || e.source === activeSource) &&
    (activeSev    === 'all' || e.severity === activeSev)
  )

  const sourceCounts = SOURCES.reduce<Record<string, number>>((acc, s) => {
    acc[s] = feed.filter(e => e.source === s).length
    return acc
  }, {})

  return (
    <div className="space-y-4">

      {/* Header + tabs */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-base font-semibold text-slate-100">Intelligence Feeds</h2>
          <p className="text-xs text-slate-500 mt-0.5">Aggregated OSINT &amp; CTI</p>
        </div>
        <div className="flex items-center gap-2">
          {/* tab switcher */}
          <div className="flex rounded-lg overflow-hidden border text-xs"
               style={{ borderColor: 'rgba(255,255,255,0.08)', background: 'rgba(255,255,255,0.03)' }}>
            {([['feeds', 'Intel Feeds'], ['misp', 'MISP Live']] as const).map(([id, label]) => (
              <button key={id} onClick={() => setTab(id)}
                      className="px-4 py-1.5 transition-all"
                      style={tab === id
                        ? { background: id === 'misp' ? 'rgba(167,139,250,0.15)' : 'rgba(34,211,238,0.1)',
                            color: id === 'misp' ? '#a78bfa' : '#22d3ee' }
                        : { color: '#475569' }}>
                {label}
                {id === 'misp' && (
                  <span className="ml-1.5 text-[9px] font-bold px-1 py-0.5 rounded"
                        style={{ background: 'rgba(167,139,250,0.15)', color: '#a78bfa' }}>
                    LIVE
                  </span>
                )}
              </button>
            ))}
          </div>

          {tab === 'feeds' && (
            <div className={`flex items-center gap-2 px-3 py-1.5 rounded-lg border text-xs transition-all ${pulse ? 'scale-105' : ''}`}
                 style={{ background: 'rgba(74,222,128,0.06)', borderColor: 'rgba(74,222,128,0.2)', color: '#4ade80' }}>
              <span className="w-1.5 h-1.5 bg-green-400 rounded-full animate-pulse" />
              {filtered.length} entries
            </div>
          )}
        </div>
      </div>

      {/* Tab content */}
      {tab === 'misp' ? <MispPanel /> : (
        <div className="flex gap-4">

          {/* Source + severity sidebar */}
          <div className="w-48 shrink-0 space-y-2">
            <div className="rounded-xl overflow-hidden" style={glass}>
              <div className="px-3 py-2.5 border-b text-[10px] font-semibold text-slate-600 uppercase tracking-wider"
                   style={{ borderColor: 'rgba(255,255,255,0.07)' }}>Fuentes</div>
              <div className="p-2 space-y-0.5">
                <button onClick={() => setActiveSource('all')}
                        className="w-full flex items-center justify-between px-3 py-2 rounded-lg text-xs transition-all"
                        style={activeSource === 'all' ? { background: 'rgba(255,255,255,0.08)', color: '#e2e8f0' } : { color: '#475569' }}>
                  <span>Todas</span><span className="font-mono text-[10px]">{feed.length}</span>
                </button>
                {SOURCES.map(s => {
                  const count = sourceCounts[s] ?? 0
                  if (!count) return null
                  const st = SOURCE_STYLE[s]
                  return (
                    <button key={s} onClick={() => setActiveSource(s)}
                            className="w-full flex items-center justify-between px-3 py-2 rounded-lg text-xs transition-all"
                            style={activeSource === s ? { background: st.bg, color: st.color } : { color: '#475569' }}>
                      <span>{s}</span><span className="font-mono text-[10px]">{count}</span>
                    </button>
                  )
                })}
              </div>
            </div>

            <div className="rounded-xl overflow-hidden" style={glass}>
              <div className="px-3 py-2.5 border-b text-[10px] font-semibold text-slate-600 uppercase tracking-wider"
                   style={{ borderColor: 'rgba(255,255,255,0.07)' }}>Severidad</div>
              <div className="p-2 space-y-0.5">
                {['all', 'critical', 'high', 'medium', 'low', 'info'].map(sev => (
                  <button key={sev} onClick={() => setActiveSev(sev)}
                          className="w-full flex items-center justify-between px-3 py-2 rounded-lg text-xs transition-all capitalize"
                          style={activeSev === sev
                            ? { background: sev === 'all' ? 'rgba(255,255,255,0.08)' : `${SEVERITY_COLOR[sev]}18`,
                                color: sev === 'all' ? '#e2e8f0' : SEVERITY_COLOR[sev] }
                            : { color: '#475569' }}>
                    <span>{sev}</span>
                    <span className="font-mono text-[10px]">
                      {sev === 'all' ? feed.length : feed.filter(e => e.severity === sev).length}
                    </span>
                  </button>
                ))}
              </div>
            </div>
          </div>

          {/* Feed entries */}
          <div className="flex-1 rounded-xl overflow-hidden" style={glass}>
            <div className="divide-y divide-white/5">
              {filtered.length === 0 && (
                <div className="px-4 py-8 text-center text-xs text-slate-600">
                  No hay entradas para los filtros seleccionados
                </div>
              )}
              {filtered.map((entry, i) => (
                <div key={`${entry.id}-${i}`}
                     className="flex items-start gap-3 px-4 py-3.5 hover:bg-white/[0.02] transition-colors">
                  <div className="w-0.5 self-stretch rounded-full shrink-0 mt-0.5"
                       style={{ background: SEVERITY_COLOR[entry.severity] ?? '#475569', opacity: 0.7 }} />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-start gap-2 flex-wrap">
                      <SourceTag source={entry.source} />
                      <span className="text-[10px] font-mono uppercase px-1.5 py-0.5 rounded shrink-0"
                            style={{ background: 'rgba(255,255,255,0.05)', color: '#64748b' }}>
                        {entry.type}
                      </span>
                      <SevBadge sev={entry.severity} />
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
      )}
    </div>
  )
}

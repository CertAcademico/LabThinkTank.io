import { useState, useEffect } from 'react'
import RuleDepuration from './RuleDepuration'

const API_URL = import.meta.env.VITE_API_URL ?? 'http://127.0.0.1:8000'

const glass = {
  background: 'rgba(15,23,42,0.55)',
  backdropFilter: 'blur(16px)',
  border: '1px solid rgba(255,255,255,0.07)',
  borderRadius: 12,
}

interface IOC {
  id: number
  ioc: string
  type: string
  threat_actor: string
  severity: string
  mitre: string
}

interface IOA {
  id: number
  description: string
  severity: string
  tactic?: string
  source?: string
}

type Tab = 'ioc' | 'ioa' | 'depuracion'

const SEVERITY_STYLE: Record<string, { bg: string; border: string; text: string; dot: string }> = {
  critical: { bg: 'rgba(239,68,68,0.12)',  border: 'rgba(239,68,68,0.3)',  text: '#ef4444', dot: '#ef4444' },
  high:     { bg: 'rgba(249,115,22,0.12)', border: 'rgba(249,115,22,0.3)', text: '#f97316', dot: '#f97316' },
  medium:   { bg: 'rgba(250,204,21,0.1)',  border: 'rgba(250,204,21,0.3)', text: '#facc15', dot: '#facc15' },
  low:      { bg: 'rgba(74,222,128,0.08)', border: 'rgba(74,222,128,0.25)',text: '#4ade80', dot: '#4ade80' },
}

const TYPE_ICON: Record<string, string> = {
  ip:     '🌐',
  domain: '🔗',
  hash:   '🔑',
  url:    '📎',
  email:  '✉️',
}

function SeverityBadge({ severity }: { severity: string }) {
  const s = SEVERITY_STYLE[severity?.toLowerCase()] ?? SEVERITY_STYLE.medium
  return (
    <span className="text-[10px] font-bold px-2 py-0.5 rounded-full uppercase"
          style={{ background: s.bg, border: `1px solid ${s.border}`, color: s.text }}>
      {severity}
    </span>
  )
}

export default function IOCIOABoard() {
  const [tab, setTab] = useState<Tab>('ioc')
  const [iocs, setIocs] = useState<IOC[]>([])
  const [ioas, setIoas] = useState<IOA[]>([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [severityFilter, setSeverityFilter] = useState('all')

  useEffect(() => {
    Promise.all([
      fetch(`${API_URL}/ioc-feed`).then(r => r.json()),
      fetch(`${API_URL}/ioas`).then(r => r.json()),
    ])
      .then(([iocData, ioaData]) => {
        setIocs(iocData)
        setIoas(ioaData)
      })
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [])

  const filteredIOCs = iocs.filter(i => {
    const matchSearch = !search || i.ioc.toLowerCase().includes(search.toLowerCase()) || i.threat_actor.toLowerCase().includes(search.toLowerCase())
    const matchSev = severityFilter === 'all' || i.severity === severityFilter
    return matchSearch && matchSev
  })

  const filteredIOAs = ioas.filter(i => {
    const matchSearch = !search || i.description.toLowerCase().includes(search.toLowerCase())
    const matchSev = severityFilter === 'all' || i.severity === severityFilter
    return matchSearch && matchSev
  })

  const criticalIOCs = iocs.filter(i => i.severity === 'critical').length
  const criticalIOAs = ioas.filter(i => i.severity === 'critical').length

  function renderTableContent() {
    if (loading) return (
      <div className="px-4 py-8 text-center text-xs text-slate-600">Cargando indicadores...</div>
    )
    if (tab === 'ioc') return (
      <table className="w-full text-xs">
        <thead>
          <tr className="border-b" style={{ borderColor: 'rgba(255,255,255,0.07)' }}>
            {['Indicador', 'Tipo', 'Actor', 'Técnica', 'Severidad', 'Enriquecimiento'].map(h => (
              <th key={h} className="text-left px-4 py-3 text-[10px] font-semibold text-slate-600 uppercase tracking-wider">{h}</th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y" style={{ borderColor: 'rgba(255,255,255,0.05)' }}>
          {filteredIOCs.length === 0 && (
            <tr><td colSpan={6} className="px-4 py-6 text-center text-slate-600">Sin resultados</td></tr>
          )}
          {filteredIOCs.map(ioc => (
            <tr key={ioc.id} className="hover:bg-white/[0.02] transition-colors">
              <td className="px-4 py-3">
                <div className="flex items-center gap-2">
                  <span className="text-base">{TYPE_ICON[ioc.type] ?? '📌'}</span>
                  <span className="font-mono text-cyan-300 truncate max-w-[180px]">{ioc.ioc}</span>
                </div>
              </td>
              <td className="px-4 py-3">
                <span className="font-mono text-[10px] uppercase px-1.5 py-0.5 rounded text-slate-500"
                      style={{ background: 'rgba(255,255,255,0.05)' }}>
                  {ioc.type}
                </span>
              </td>
              <td className="px-4 py-3 text-slate-400">{ioc.threat_actor}</td>
              <td className="px-4 py-3 font-mono text-violet-400">{ioc.mitre}</td>
              <td className="px-4 py-3"><SeverityBadge severity={ioc.severity} /></td>
              <td className="px-4 py-3">
                <div className="flex gap-1.5">
                  {['VT', 'AIPDB', 'Shodan'].map(tag => (
                    <span key={tag} className="text-[9px] px-1.5 py-0.5 rounded font-mono"
                          style={{ background: 'rgba(34,211,238,0.08)', color: '#22d3ee', border: '1px solid rgba(34,211,238,0.15)' }}>
                      {tag}
                    </span>
                  ))}
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    )
    return (
      <table className="w-full text-xs">
        <thead>
          <tr className="border-b" style={{ borderColor: 'rgba(255,255,255,0.07)' }}>
            {['Descripción', 'Táctica', 'Fuente', 'Severidad'].map(h => (
              <th key={h} className="text-left px-4 py-3 text-[10px] font-semibold text-slate-600 uppercase tracking-wider">{h}</th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y" style={{ borderColor: 'rgba(255,255,255,0.05)' }}>
          {filteredIOAs.length === 0 && (
            <tr><td colSpan={4} className="px-4 py-6 text-center text-slate-600">Sin resultados</td></tr>
          )}
          {filteredIOAs.map(ioa => (
            <tr key={ioa.id} className="hover:bg-white/[0.02] transition-colors">
              <td className="px-4 py-3 text-slate-300 max-w-xs">
                <div className="truncate">{ioa.description}</div>
              </td>
              <td className="px-4 py-3 text-slate-500">{ioa.tactic ?? '—'}</td>
              <td className="px-4 py-3">
                {ioa.source ? (
                  <span className="text-[10px] px-1.5 py-0.5 rounded font-mono"
                        style={{ background: 'rgba(167,139,250,0.1)', color: '#a78bfa', border: '1px solid rgba(167,139,250,0.2)' }}>
                    {ioa.source}
                  </span>
                ) : <span className="text-slate-700">—</span>}
              </td>
              <td className="px-4 py-3"><SeverityBadge severity={ioa.severity} /></td>
            </tr>
          ))}
        </tbody>
      </table>
    )
  }

  return (
    <div className="space-y-4">

      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-base font-semibold text-slate-100">IOC / IOA Intelligence Board</h2>
          <p className="text-xs text-slate-500 mt-0.5">Indicators of Compromise & Attack enriched with threat context</p>
        </div>
        <div className="flex items-center gap-3">
          {[
            { label: 'IOCs', value: iocs.length, sub: `${criticalIOCs} critical`, color: '#ef4444' },
            { label: 'IOAs', value: ioas.length, sub: `${criticalIOAs} critical`, color: '#f97316' },
          ].map(s => (
            <div key={s.label} className="text-center px-3 py-2 rounded-lg"
                 style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.07)' }}>
              <div className="text-lg font-bold" style={{ color: s.color }}>{s.value}</div>
              <div className="text-[9px] text-slate-600 uppercase tracking-wide">{s.label}</div>
              <div className="text-[9px]" style={{ color: s.color }}>{s.sub}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Controls */}
      <div className="flex items-center gap-3">
        {/* Tabs */}
        <div className="flex rounded-lg overflow-hidden border" style={{ borderColor: 'rgba(255,255,255,0.08)' }}>
          {([['ioc', 'IOC Feed'], ['ioa', 'IOA Feed'], ['depuracion', '🛡 Depuración']] as [Tab, string][]).map(([t, label]) => (
            <button key={t} onClick={() => setTab(t)}
                    className="px-4 py-2 text-xs font-semibold transition-all"
                    style={tab === t ? {
                      background: 'rgba(34,211,238,0.12)',
                      color: '#22d3ee',
                    } : {
                      background: 'rgba(255,255,255,0.03)',
                      color: '#475569',
                    }}>
              {label}
            </button>
          ))}
        </div>

        {/* Search + filters — hidden in depuration tab */}
        {tab !== 'depuracion' && (
          <>
            <div className="flex items-center gap-2 flex-1 px-3 py-2 rounded-lg"
                 style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.07)' }}>
              <svg viewBox="0 0 24 24" className="w-3.5 h-3.5 text-slate-600 shrink-0" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="11" cy="11" r="8" /><path d="m21 21-4.35-4.35" />
              </svg>
              <input className="flex-1 bg-transparent text-xs text-slate-300 outline-none placeholder-slate-700"
                     placeholder={tab === 'ioc' ? 'Buscar IOC, actor, tipo...' : 'Buscar IOA, descripción...'}
                     value={search}
                     onChange={e => setSearch(e.target.value)} />
            </div>

            {['all', 'critical', 'high', 'medium', 'low'].map(sev => {
              const st = SEVERITY_STYLE[sev]
              return (
                <button key={sev} onClick={() => setSeverityFilter(sev)}
                        className="px-2.5 py-1.5 rounded-lg text-[10px] font-semibold uppercase transition-all capitalize"
                        style={severityFilter === sev ? {
                          background: st?.bg ?? 'rgba(255,255,255,0.08)',
                          border: `1px solid ${st?.border ?? 'rgba(255,255,255,0.2)'}`,
                          color: st?.text ?? '#e2e8f0',
                        } : {
                          background: 'rgba(255,255,255,0.03)',
                          border: '1px solid rgba(255,255,255,0.06)',
                          color: '#475569',
                        }}>
                  {sev}
                </button>
              )
            })}
          </>
        )}
      </div>

      {/* Depuration pipeline or Table */}
      {tab === 'depuracion'
        ? <RuleDepuration />
        : <div className="rounded-xl overflow-hidden" style={glass}>{renderTableContent()}</div>
      }
    </div>
  )
}

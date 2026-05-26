import { useEffect, useState } from 'react'

const API_URL = import.meta.env.VITE_API_URL ?? 'http://127.0.0.1:8000'

interface ThreatActor {
  id: number
  name: string
  aliases: string[]
  country: string
  motivation: string
  severity: string
  active_campaign: string
  malware: string[]
  ttps: string[]
  targeted_sectors: string[]
  first_seen: string
  last_seen: string
  description: string
  infrastructure: string[]
  ioc_count: number
}

const SEVERITY_STYLES: Record<string, string> = {
  critical: 'bg-red-900 text-red-300 border-red-700',
  high:     'bg-orange-900 text-orange-300 border-orange-700',
  medium:   'bg-yellow-900 text-yellow-300 border-yellow-700',
  low:      'bg-green-900 text-green-300 border-green-700',
}

const COUNTRY_FLAGS: Record<string, string> = {
  RU: '🇷🇺', CN: '🇨🇳', US: '🇺🇸', KP: '🇰🇵', IR: '🇮🇷',
  UA: '🇺🇦', DE: '🇩🇪', GB: '🇬🇧', FR: '🇫🇷', Unknown: '🌐',
}

function SeverityBadge({ severity }: { severity: string }) {
  const style = SEVERITY_STYLES[severity] ?? SEVERITY_STYLES.medium
  return (
    <span className={`px-2 py-0.5 rounded border text-xs font-bold uppercase tracking-wider ${style}`}>
      {severity}
    </span>
  )
}

function ActorCard({ actor, onSelect }: { actor: ThreatActor; onSelect: (a: ThreatActor) => void }) {
  const flag = COUNTRY_FLAGS[actor.country] ?? '🌐'
  const daysSince = Math.floor(
    (Date.now() - new Date(actor.last_seen).getTime()) / 86_400_000
  )

  return (
    <div
      className="bg-slate-900 border border-slate-800 hover:border-cyan-800 rounded-xl p-5 cursor-pointer transition-colors group"
      onClick={() => onSelect(actor)}
    >
      <div className="flex items-start justify-between mb-3">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-xl">{flag}</span>
            <h3 className="font-bold text-white group-hover:text-cyan-400 transition-colors">{actor.name}</h3>
          </div>
          {actor.aliases.length > 0 && (
            <p className="text-slate-500 text-xs">aka {actor.aliases.join(', ')}</p>
          )}
        </div>
        <SeverityBadge severity={actor.severity} />
      </div>

      <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs mb-3">
        <span className="text-slate-500">Motivation</span>
        <span className="text-slate-300">{actor.motivation}</span>
        <span className="text-slate-500">Campaign</span>
        <span className="text-cyan-400 truncate">{actor.active_campaign}</span>
        <span className="text-slate-500">Last seen</span>
        <span className={`font-mono ${daysSince <= 7 ? 'text-red-400' : 'text-slate-300'}`}>
          {daysSince}d ago
        </span>
        <span className="text-slate-500">IOCs tracked</span>
        <span className="text-slate-300">{actor.ioc_count}</span>
      </div>

      <div className="mb-3">
        <p className="text-slate-500 text-xs mb-1.5">Malware</p>
        <div className="flex flex-wrap gap-1">
          {actor.malware.map(m => (
            <span key={m} className="bg-red-950 border border-red-900 text-red-300 px-1.5 py-0.5 rounded text-xs font-mono">
              {m}
            </span>
          ))}
        </div>
      </div>

      <div>
        <p className="text-slate-500 text-xs mb-1.5">Target sectors</p>
        <div className="flex flex-wrap gap-1">
          {actor.targeted_sectors.map(s => (
            <span key={s} className="bg-slate-800 text-slate-400 px-1.5 py-0.5 rounded text-xs">{s}</span>
          ))}
        </div>
      </div>
    </div>
  )
}

function ActorDetail({ actor, onClose }: { actor: ThreatActor; onClose: () => void }) {
  const flag = COUNTRY_FLAGS[actor.country] ?? '🌐'

  return (
    <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-6" onClick={onClose}>
      <div
        className="bg-slate-900 border border-slate-700 rounded-2xl max-w-2xl w-full max-h-[85vh] overflow-y-auto"
        onClick={e => e.stopPropagation()}
      >
        <div className="p-6">
          {/* Header */}
          <div className="flex items-start justify-between mb-5">
            <div className="flex items-center gap-3">
              <span className="text-3xl">{flag}</span>
              <div>
                <h2 className="text-xl font-bold text-white">{actor.name}</h2>
                {actor.aliases.length > 0 && (
                  <p className="text-slate-400 text-sm">aka {actor.aliases.join(' · ')}</p>
                )}
              </div>
            </div>
            <div className="flex items-center gap-2">
              <SeverityBadge severity={actor.severity} />
              <button onClick={onClose} className="text-slate-500 hover:text-white text-xl leading-none">×</button>
            </div>
          </div>

          {/* Description */}
          <p className="text-slate-300 text-sm leading-relaxed mb-5">{actor.description}</p>

          {/* Stats row */}
          <div className="grid grid-cols-3 gap-3 mb-5">
            {[
              { label: 'First seen',  value: actor.first_seen },
              { label: 'Last seen',   value: actor.last_seen },
              { label: 'IOCs tracked', value: actor.ioc_count },
            ].map(({ label, value }) => (
              <div key={label} className="bg-slate-800 rounded-lg p-3 text-center">
                <p className="text-slate-500 text-xs mb-1">{label}</p>
                <p className="text-white font-mono text-sm">{value}</p>
              </div>
            ))}
          </div>

          <div className="space-y-4">
            {/* MITRE TTPs */}
            <div>
              <p className="text-slate-500 text-xs uppercase tracking-wider mb-2">MITRE ATT&CK TTPs</p>
              <div className="flex flex-wrap gap-1.5">
                {actor.ttps.map(t => (
                  <span key={t} className="bg-purple-950 border border-purple-800 text-purple-300 px-2 py-0.5 rounded text-xs font-mono">
                    {t}
                  </span>
                ))}
              </div>
            </div>

            {/* Malware */}
            <div>
              <p className="text-slate-500 text-xs uppercase tracking-wider mb-2">Malware Arsenal</p>
              <div className="flex flex-wrap gap-1.5">
                {actor.malware.map(m => (
                  <span key={m} className="bg-red-950 border border-red-800 text-red-300 px-2 py-0.5 rounded text-xs font-mono">
                    {m}
                  </span>
                ))}
              </div>
            </div>

            {/* Sectors */}
            <div>
              <p className="text-slate-500 text-xs uppercase tracking-wider mb-2">Targeted Sectors</p>
              <div className="flex flex-wrap gap-1.5">
                {actor.targeted_sectors.map(s => (
                  <span key={s} className="bg-slate-800 border border-slate-600 text-slate-300 px-2 py-0.5 rounded text-xs">{s}</span>
                ))}
              </div>
            </div>

            {/* Infrastructure IOCs */}
            <div>
              <p className="text-slate-500 text-xs uppercase tracking-wider mb-2">Known Infrastructure</p>
              <div className="space-y-1">
                {actor.infrastructure.map(ioc => (
                  <code key={ioc} className="block bg-slate-800 text-cyan-300 text-xs px-3 py-1.5 rounded font-mono">{ioc}</code>
                ))}
              </div>
            </div>

            {/* Active campaign */}
            <div className="bg-cyan-950 border border-cyan-900 rounded-lg p-3 flex items-center justify-between">
              <span className="text-xs text-cyan-500 uppercase tracking-wider">Active Campaign</span>
              <span className="text-cyan-300 font-semibold">{actor.active_campaign}</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

function ThreatActorsPage() {
  const [actors, setActors]       = useState<ThreatActor[]>([])
  const [selected, setSelected]   = useState<ThreatActor | null>(null)
  const [filter, setFilter]       = useState<string>('all')
  const [search, setSearch]       = useState('')
  const [loading, setLoading]     = useState(true)
  const [error, setError]         = useState<string | null>(null)

  useEffect(() => {
    fetch(`${API_URL}/threat-actors`)
      .then(r => r.json())
      .then(setActors)
      .catch(() => setError('Failed to load threat actors'))
      .finally(() => setLoading(false))
  }, [])

  const severities = ['all', ...Array.from(new Set(actors.map(a => a.severity)))]

  const visible = actors.filter(a => {
    const matchSev = filter === 'all' || a.severity === filter
    const q = search.toLowerCase()
    const matchSearch = !q || a.name.toLowerCase().includes(q) ||
      a.motivation.toLowerCase().includes(q) ||
      a.targeted_sectors.some(s => s.toLowerCase().includes(q))
    return matchSev && matchSearch
  })

  if (loading) return <div className="text-slate-400 text-sm p-8">Loading threat actors...</div>
  if (error)   return <div className="text-red-400 text-sm p-8">{error}</div>

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold">Threat Actors</h2>
          <p className="text-slate-500 text-xs mt-0.5">{actors.length} tracked groups</p>
        </div>
        <div className="flex gap-2">
          <input
            className="bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-sm text-white placeholder-slate-600 focus:outline-none focus:border-cyan-600 w-48"
            placeholder="Search actors..."
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
          <div className="flex gap-1">
            {severities.map(s => (
              <button
                key={s}
                onClick={() => setFilter(s)}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium capitalize transition-colors ${
                  filter === s
                    ? 'bg-cyan-700 text-white'
                    : 'bg-slate-800 text-slate-400 hover:text-white'
                }`}
              >
                {s}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Cards grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
        {visible.map(actor => (
          <ActorCard key={actor.id} actor={actor} onSelect={setSelected} />
        ))}
      </div>

      {visible.length === 0 && (
        <p className="text-slate-500 text-sm text-center py-10">No actors match the current filter.</p>
      )}

      {selected && <ActorDetail actor={selected} onClose={() => setSelected(null)} />}
    </div>
  )
}

export default ThreatActorsPage

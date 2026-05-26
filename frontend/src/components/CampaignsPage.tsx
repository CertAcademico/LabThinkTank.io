import { useEffect, useState } from 'react'

const API_URL = import.meta.env.VITE_API_URL ?? 'http://127.0.0.1:8000'

interface Campaign {
  id: number
  name: string
  actor: string
  target_sectors: string[]
  affected_countries: string[]
  status: string
  start_date: string
  last_activity: string
  mitre: string[]
  ioc_count: number
  confirmed_victims: number
  description: string
  kill_chain_phase: string
}

const STATUS_STYLES: Record<string, { card: string; badge: string; dot: string }> = {
  critical: {
    card:  'border-red-800 bg-gradient-to-b from-red-950/30 to-slate-900',
    badge: 'bg-red-900 text-red-300 border-red-700',
    dot:   'bg-red-500',
  },
  active: {
    card:  'border-cyan-900 bg-gradient-to-b from-cyan-950/20 to-slate-900',
    badge: 'bg-cyan-900 text-cyan-300 border-cyan-700',
    dot:   'bg-cyan-400',
  },
  closed: {
    card:  'border-slate-700 bg-slate-900',
    badge: 'bg-slate-700 text-slate-400 border-slate-600',
    dot:   'bg-slate-500',
  },
}

const KILL_CHAIN_ORDER = [
  'Reconnaissance', 'Weaponization', 'Delivery', 'Exploitation',
  'Installation', 'Command & Control', 'Credential Access', 'Exfiltration', 'Impact',
]

const COUNTRY_FLAGS: Record<string, string> = {
  US: '🇺🇸', GB: '🇬🇧', DE: '🇩🇪', FR: '🇫🇷', UA: '🇺🇦',
  PL: '🇵🇱', CN: '🇨🇳', RU: '🇷🇺', SG: '🇸🇬', JP: '🇯🇵',
  MX: '🇲🇽', ES: '🇪🇸', AR: '🇦🇷', CO: '🇨🇴',
}

function KillChainBar({ phase }: { phase: string }) {
  const idx = KILL_CHAIN_ORDER.indexOf(phase)
  const progress = idx >= 0 ? ((idx + 1) / KILL_CHAIN_ORDER.length) * 100 : 0

  return (
    <div>
      <div className="flex justify-between items-center mb-1">
        <span className="text-slate-500 text-xs">Kill Chain</span>
        <span className="text-xs text-orange-400 font-semibold">{phase}</span>
      </div>
      <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
        <div
          className="h-full bg-gradient-to-r from-cyan-600 to-orange-500 rounded-full transition-all"
          style={{ width: `${progress}%` }}
        />
      </div>
      <div className="flex justify-between mt-0.5">
        <span className="text-slate-600 text-[10px]">Recon</span>
        <span className="text-slate-600 text-[10px]">Impact</span>
      </div>
    </div>
  )
}

function CampaignCard({ campaign, onSelect }: { campaign: Campaign; onSelect: (c: Campaign) => void }) {
  const styles = STATUS_STYLES[campaign.status] ?? STATUS_STYLES.active
  const daysActive = Math.floor(
    (new Date(campaign.last_activity).getTime() - new Date(campaign.start_date).getTime()) / 86_400_000
  )

  return (
    <div
      className={`border rounded-xl p-5 cursor-pointer transition-all hover:scale-[1.01] ${styles.card}`}
      onClick={() => onSelect(campaign)}
    >
      {/* Header */}
      <div className="flex items-start justify-between mb-3">
        <div className="flex items-start gap-2">
          <div className={`w-2 h-2 rounded-full mt-1.5 animate-pulse ${styles.dot}`} />
          <div>
            <h3 className="font-bold text-white text-sm">{campaign.name}</h3>
            <p className="text-slate-500 text-xs">by <span className="text-slate-300">{campaign.actor}</span></p>
          </div>
        </div>
        <span className={`px-2 py-0.5 rounded border text-xs font-bold uppercase ${styles.badge}`}>
          {campaign.status}
        </span>
      </div>

      {/* Kill chain progress */}
      <div className="mb-4">
        <KillChainBar phase={campaign.kill_chain_phase} />
      </div>

      {/* Stats */}
      <div className="grid grid-cols-3 gap-2 mb-3">
        {[
          { label: 'IOCs',    value: campaign.ioc_count },
          { label: 'Victims', value: campaign.confirmed_victims },
          { label: 'Days',    value: daysActive },
        ].map(({ label, value }) => (
          <div key={label} className="bg-slate-800/50 rounded-lg p-2 text-center">
            <p className="text-white font-bold text-base">{value}</p>
            <p className="text-slate-500 text-[10px]">{label}</p>
          </div>
        ))}
      </div>

      {/* Countries */}
      <div className="flex items-center gap-1 mb-3">
        <span className="text-slate-500 text-xs mr-1">Targets:</span>
        {campaign.affected_countries.map(c => (
          <span key={c} title={c}>{COUNTRY_FLAGS[c] ?? c}</span>
        ))}
      </div>

      {/* MITRE */}
      <div className="flex flex-wrap gap-1">
        {campaign.mitre.map(t => (
          <span key={t} className="bg-purple-950 border border-purple-900 text-purple-400 px-1.5 py-0.5 rounded text-[10px] font-mono">
            {t}
          </span>
        ))}
      </div>
    </div>
  )
}

function CampaignDetail({ campaign, onClose }: { campaign: Campaign; onClose: () => void }) {
  const styles = STATUS_STYLES[campaign.status] ?? STATUS_STYLES.active

  return (
    <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-6" onClick={onClose}>
      <div
        className="bg-slate-900 border border-slate-700 rounded-2xl max-w-2xl w-full max-h-[85vh] overflow-y-auto"
        onClick={e => e.stopPropagation()}
      >
        <div className="p-6">
          {/* Header */}
          <div className="flex items-start justify-between mb-4">
            <div className="flex items-center gap-3">
              <div className={`w-3 h-3 rounded-full animate-pulse ${styles.dot}`} />
              <div>
                <h2 className="text-xl font-bold text-white">{campaign.name}</h2>
                <p className="text-slate-400 text-sm">Attributed to <span className="text-cyan-400">{campaign.actor}</span></p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <span className={`px-2 py-0.5 rounded border text-xs font-bold uppercase ${styles.badge}`}>
                {campaign.status}
              </span>
              <button onClick={onClose} className="text-slate-500 hover:text-white text-xl leading-none">×</button>
            </div>
          </div>

          {/* Kill chain */}
          <div className="mb-5">
            <KillChainBar phase={campaign.kill_chain_phase} />
          </div>

          {/* Description */}
          <p className="text-slate-300 text-sm leading-relaxed mb-5">{campaign.description}</p>

          {/* Stats */}
          <div className="grid grid-cols-4 gap-3 mb-5">
            {[
              { label: 'Start date',       value: campaign.start_date },
              { label: 'Last activity',    value: campaign.last_activity },
              { label: 'IOCs tracked',     value: campaign.ioc_count },
              { label: 'Confirmed victims', value: campaign.confirmed_victims },
            ].map(({ label, value }) => (
              <div key={label} className="bg-slate-800 rounded-lg p-3 text-center">
                <p className="text-slate-500 text-xs mb-1">{label}</p>
                <p className="text-white font-mono text-sm">{value}</p>
              </div>
            ))}
          </div>

          <div className="space-y-4">
            {/* MITRE */}
            <div>
              <p className="text-slate-500 text-xs uppercase tracking-wider mb-2">MITRE ATT&CK</p>
              <div className="flex flex-wrap gap-1.5">
                {campaign.mitre.map(t => (
                  <span key={t} className="bg-purple-950 border border-purple-800 text-purple-300 px-2 py-0.5 rounded text-xs font-mono">
                    {t}
                  </span>
                ))}
              </div>
            </div>

            {/* Target sectors */}
            <div>
              <p className="text-slate-500 text-xs uppercase tracking-wider mb-2">Target Sectors</p>
              <div className="flex flex-wrap gap-1.5">
                {campaign.target_sectors.map(s => (
                  <span key={s} className="bg-slate-800 border border-slate-600 text-slate-300 px-2 py-0.5 rounded text-xs">{s}</span>
                ))}
              </div>
            </div>

            {/* Affected countries */}
            <div>
              <p className="text-slate-500 text-xs uppercase tracking-wider mb-2">Affected Countries</p>
              <div className="flex flex-wrap gap-2">
                {campaign.affected_countries.map(c => (
                  <span key={c} className="flex items-center gap-1 bg-slate-800 border border-slate-700 px-2 py-1 rounded text-xs text-slate-300">
                    <span>{COUNTRY_FLAGS[c] ?? '🌐'}</span>
                    <span>{c}</span>
                  </span>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

function CampaignsPage() {
  const [campaigns, setCampaigns]   = useState<Campaign[]>([])
  const [selected, setSelected]     = useState<Campaign | null>(null)
  const [filter, setFilter]         = useState('all')
  const [loading, setLoading]       = useState(true)
  const [error, setError]           = useState<string | null>(null)

  useEffect(() => {
    fetch(`${API_URL}/campaigns`)
      .then(r => r.json())
      .then(setCampaigns)
      .catch(() => setError('Failed to load campaigns'))
      .finally(() => setLoading(false))
  }, [])

  const statuses = ['all', ...Array.from(new Set(campaigns.map(c => c.status)))]
  const visible = campaigns.filter(c => filter === 'all' || c.status === filter)

  if (loading) return <div className="text-slate-400 text-sm p-8">Loading campaigns...</div>
  if (error)   return <div className="text-red-400 text-sm p-8">{error}</div>

  const totalVictims = campaigns.reduce((s, c) => s + c.confirmed_victims, 0)
  const totalIOCs    = campaigns.reduce((s, c) => s + c.ioc_count, 0)

  return (
    <div className="space-y-5">
      {/* Header + summary */}
      <div className="flex items-start justify-between">
        <div>
          <h2 className="text-2xl font-bold">Active Campaigns</h2>
          <p className="text-slate-500 text-xs mt-0.5">{campaigns.length} campaigns tracked</p>
        </div>
        <div className="flex gap-3">
          {[
            { label: 'Campaigns', value: campaigns.length },
            { label: 'Total IOCs', value: totalIOCs },
            { label: 'Victims', value: totalVictims },
          ].map(({ label, value }) => (
            <div key={label} className="bg-slate-900 border border-slate-800 rounded-lg px-4 py-2 text-center">
              <p className="text-white font-bold text-lg">{value}</p>
              <p className="text-slate-500 text-xs">{label}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Status filter */}
      <div className="flex gap-1">
        {statuses.map(s => (
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

      {/* Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
        {visible.map(c => (
          <CampaignCard key={c.id} campaign={c} onSelect={setSelected} />
        ))}
      </div>

      {visible.length === 0 && (
        <p className="text-slate-500 text-sm text-center py-10">No campaigns match the current filter.</p>
      )}

      {selected && <CampaignDetail campaign={selected} onClose={() => setSelected(null)} />}
    </div>
  )
}

export default CampaignsPage

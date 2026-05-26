import { useState } from 'react'

const API_URL = import.meta.env.VITE_API_URL ?? 'http://127.0.0.1:8000'

interface VTResult {
  malicious?: number
  suspicious?: number
  harmless?: number
  undetected?: number
  reputation?: number
  country?: string
  asn?: string
  as_owner?: string
  network?: string
  registrar?: string
  creation_date?: number
  categories?: Record<string, string>
  type_description?: string
  size?: number
  meaningful_name?: string
  tags?: string[]
  final_url?: string
  title?: string
  error?: string
}

interface AbuseResult {
  abuse_confidence_score?: number
  total_reports?: number
  distinct_users?: number
  country?: string
  isp?: string
  domain?: string
  is_tor?: boolean
  usage_type?: string
  last_reported?: string
  error?: string
}

interface ShodanResult {
  ports?: number[]
  country_name?: string
  org?: string
  isp?: string
  os?: string | null
  hostnames?: string[]
  vulns?: string[]
  tags?: string[]
  last_update?: string
  error?: string
}

interface EnrichResult {
  ioc: string
  type: string
  sources: {
    virustotal?: VTResult
    abuseipdb?: AbuseResult
    shodan?: ShodanResult
  }
}

function RiskBadge({ score, max = 100 }: { score: number; max?: number }) {
  const pct = (score / max) * 100
  const color =
    pct >= 75 ? 'bg-red-600 text-white' :
    pct >= 40 ? 'bg-orange-500 text-white' :
    pct >= 10 ? 'bg-yellow-500 text-black' :
    'bg-green-700 text-white'
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-bold ${color}`}>
      {score}
    </span>
  )
}

function SourceBadge({ label, hasError }: { label: string; hasError: boolean }) {
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-semibold ${hasError ? 'bg-slate-700 text-slate-400' : 'bg-cyan-900 text-cyan-300'}`}>
      {label}
    </span>
  )
}

function VTCard({ data, type }: { data: VTResult; type: string }) {
  if (data.error) {
    return (
      <div className="bg-slate-800 rounded-lg p-4 border border-slate-700">
        <p className="text-xs font-bold text-slate-400 mb-1">VIRUSTOTAL</p>
        <p className="text-slate-500 text-sm">{data.error}</p>
      </div>
    )
  }
  const total = (data.malicious ?? 0) + (data.suspicious ?? 0) + (data.harmless ?? 0) + (data.undetected ?? 0)
  return (
    <div className="bg-slate-800 rounded-lg p-4 border border-slate-700 space-y-3">
      <div className="flex items-center justify-between">
        <p className="text-xs font-bold text-cyan-400">VIRUSTOTAL</p>
        {data.reputation !== undefined && (
          <span className="text-xs text-slate-400">Reputation: <RiskBadge score={data.reputation} max={100} /></span>
        )}
      </div>

      {/* Detection bar */}
      <div>
        <div className="flex justify-between text-xs text-slate-400 mb-1">
          <span>Detections</span>
          <span className="font-mono">{data.malicious}/{total} engines</span>
        </div>
        <div className="h-2 w-full bg-slate-700 rounded-full overflow-hidden flex">
          {total > 0 && <>
            <div className="bg-red-600 h-full" style={{ width: `${((data.malicious ?? 0) / total) * 100}%` }} />
            <div className="bg-orange-500 h-full" style={{ width: `${((data.suspicious ?? 0) / total) * 100}%` }} />
            <div className="bg-green-700 h-full" style={{ width: `${((data.harmless ?? 0) / total) * 100}%` }} />
          </>}
        </div>
        <div className="flex gap-3 mt-1 text-xs">
          <span className="text-red-400">{data.malicious} malicious</span>
          <span className="text-orange-400">{data.suspicious} suspicious</span>
          <span className="text-green-400">{data.harmless} harmless</span>
        </div>
      </div>

      {/* Type-specific metadata */}
      {type === 'IP' && (
        <div className="grid grid-cols-2 gap-1 text-xs text-slate-300">
          {data.country  && <span><span className="text-slate-500">Country:</span> {data.country}</span>}
          {data.asn      && <span><span className="text-slate-500">ASN:</span> {data.asn}</span>}
          {data.as_owner && <span className="col-span-2"><span className="text-slate-500">Owner:</span> {data.as_owner}</span>}
          {data.network  && <span className="col-span-2"><span className="text-slate-500">Network:</span> {data.network}</span>}
        </div>
      )}
      {type === 'DOMAIN' && (
        <div className="grid grid-cols-2 gap-1 text-xs text-slate-300">
          {data.registrar && <span className="col-span-2"><span className="text-slate-500">Registrar:</span> {data.registrar}</span>}
          {data.creation_date && <span className="col-span-2"><span className="text-slate-500">Created:</span> {new Date(data.creation_date * 1000).toLocaleDateString()}</span>}
          {data.categories && Object.values(data.categories).length > 0 && (
            <span className="col-span-2"><span className="text-slate-500">Categories:</span> {[...new Set(Object.values(data.categories))].join(', ')}</span>
          )}
        </div>
      )}
      {type === 'HASH' && (
        <div className="grid grid-cols-2 gap-1 text-xs text-slate-300">
          {data.type_description && <span className="col-span-2"><span className="text-slate-500">Type:</span> {data.type_description}</span>}
          {data.meaningful_name  && <span className="col-span-2"><span className="text-slate-500">Name:</span> {data.meaningful_name}</span>}
          {data.size             && <span><span className="text-slate-500">Size:</span> {(data.size / 1024).toFixed(1)} KB</span>}
          {data.tags && data.tags.length > 0 && (
            <span className="col-span-2 flex flex-wrap gap-1">
              {data.tags.map(t => <span key={t} className="bg-slate-700 px-1 rounded">{t}</span>)}
            </span>
          )}
        </div>
      )}
      {type === 'URL' && (
        <div className="text-xs text-slate-300 space-y-1">
          {data.title    && <p><span className="text-slate-500">Title:</span> {data.title}</p>}
          {data.final_url && <p className="truncate"><span className="text-slate-500">Final URL:</span> {data.final_url}</p>}
        </div>
      )}
    </div>
  )
}

function AbuseCard({ data }: { data: AbuseResult }) {
  if (data.error) {
    return (
      <div className="bg-slate-800 rounded-lg p-4 border border-slate-700">
        <p className="text-xs font-bold text-slate-400 mb-1">ABUSEIPDB</p>
        <p className="text-slate-500 text-sm">{data.error}</p>
      </div>
    )
  }
  const score = data.abuse_confidence_score ?? 0
  return (
    <div className="bg-slate-800 rounded-lg p-4 border border-slate-700 space-y-3">
      <div className="flex items-center justify-between">
        <p className="text-xs font-bold text-cyan-400">ABUSEIPDB</p>
        <div className="flex items-center gap-2">
          <span className="text-xs text-slate-400">Abuse Score:</span>
          <RiskBadge score={score} />
          {data.is_tor && <span className="bg-purple-900 text-purple-300 px-2 py-0.5 rounded text-xs font-bold">TOR</span>}
        </div>
      </div>

      <div className="w-full bg-slate-700 rounded-full h-2">
        <div
          className={`h-2 rounded-full ${score >= 75 ? 'bg-red-600' : score >= 40 ? 'bg-orange-500' : 'bg-green-600'}`}
          style={{ width: `${score}%` }}
        />
      </div>

      <div className="grid grid-cols-2 gap-1 text-xs text-slate-300">
        <span><span className="text-slate-500">Reports:</span> {data.total_reports}</span>
        <span><span className="text-slate-500">Users:</span> {data.distinct_users}</span>
        {data.country     && <span><span className="text-slate-500">Country:</span> {data.country}</span>}
        {data.usage_type  && <span><span className="text-slate-500">Usage:</span> {data.usage_type}</span>}
        {data.isp         && <span className="col-span-2"><span className="text-slate-500">ISP:</span> {data.isp}</span>}
        {data.domain      && <span className="col-span-2"><span className="text-slate-500">Domain:</span> {data.domain}</span>}
        {data.last_reported && <span className="col-span-2"><span className="text-slate-500">Last reported:</span> {new Date(data.last_reported).toLocaleDateString()}</span>}
      </div>
    </div>
  )
}

function ShodanCard({ data }: { data: ShodanResult }) {
  if (data.error) {
    return (
      <div className="bg-slate-800 rounded-lg p-4 border border-slate-700">
        <p className="text-xs font-bold text-slate-400 mb-1">SHODAN</p>
        <p className="text-slate-500 text-sm">{data.error}</p>
      </div>
    )
  }
  return (
    <div className="bg-slate-800 rounded-lg p-4 border border-slate-700 space-y-3">
      <div className="flex items-center justify-between">
        <p className="text-xs font-bold text-cyan-400">SHODAN</p>
        {data.vulns && data.vulns.length > 0 && (
          <span className="bg-red-900 text-red-300 px-2 py-0.5 rounded text-xs font-bold">
            {data.vulns.length} CVE{data.vulns.length > 1 ? 's' : ''}
          </span>
        )}
      </div>

      {data.ports && data.ports.length > 0 && (
        <div>
          <p className="text-xs text-slate-500 mb-1">Open ports ({data.ports.length})</p>
          <div className="flex flex-wrap gap-1">
            {data.ports.map(p => (
              <span key={p} className="bg-slate-700 text-slate-300 px-1.5 py-0.5 rounded text-xs font-mono">{p}</span>
            ))}
          </div>
        </div>
      )}

      {data.vulns && data.vulns.length > 0 && (
        <div>
          <p className="text-xs text-slate-500 mb-1">CVEs</p>
          <div className="flex flex-wrap gap-1">
            {data.vulns.map(v => (
              <span key={v} className="bg-red-950 text-red-300 border border-red-800 px-1.5 py-0.5 rounded text-xs font-mono">{v}</span>
            ))}
          </div>
        </div>
      )}

      <div className="grid grid-cols-2 gap-1 text-xs text-slate-300">
        {data.country_name && <span><span className="text-slate-500">Country:</span> {data.country_name}</span>}
        {data.org          && <span><span className="text-slate-500">Org:</span> {data.org}</span>}
        {data.isp          && <span className="col-span-2"><span className="text-slate-500">ISP:</span> {data.isp}</span>}
        {data.os           && <span><span className="text-slate-500">OS:</span> {data.os}</span>}
        {data.hostnames && data.hostnames.length > 0 && (
          <span className="col-span-2"><span className="text-slate-500">Hostnames:</span> {data.hostnames.join(', ')}</span>
        )}
        {data.tags && data.tags.length > 0 && (
          <span className="col-span-2 flex flex-wrap gap-1">
            {data.tags.map(t => <span key={t} className="bg-slate-700 px-1 rounded">{t}</span>)}
          </span>
        )}
      </div>
    </div>
  )
}

function IOCEnrichment() {
  const [input, setInput] = useState('')
  const [result, setResult] = useState<EnrichResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const lookup = async () => {
    const ioc = input.trim()
    if (!ioc || loading) return
    setLoading(true)
    setError(null)
    setResult(null)
    try {
      const res = await fetch(`${API_URL}/enrich/${encodeURIComponent(ioc)}`)
      if (!res.ok) throw new Error(`Server error: ${res.status}`)
      setResult(await res.json())
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Request failed')
    } finally {
      setLoading(false)
    }
  }

  const sources = result?.sources ?? {}
  const configuredCount = Object.values(sources).filter(s => !('error' in (s ?? {})) || !(s as { error?: string }).error?.includes('not configured')).length

  return (
    <div className="bg-slate-900 rounded-xl p-6 border border-slate-800">
      <div className="flex items-center justify-between mb-5">
        <div>
          <h2 className="text-xl font-bold">IOC Enrichment</h2>
          <p className="text-slate-500 text-xs mt-0.5">VirusTotal · AbuseIPDB · Shodan</p>
        </div>
        {result && (
          <div className="flex gap-1">
            {sources.virustotal && <SourceBadge label="VT" hasError={!!sources.virustotal.error} />}
            {sources.abuseipdb  && <SourceBadge label="Abuse" hasError={!!sources.abuseipdb.error} />}
            {sources.shodan     && <SourceBadge label="Shodan" hasError={!!sources.shodan.error} />}
          </div>
        )}
      </div>

      <div className="flex gap-3 mb-5">
        <input
          className="flex-1 bg-slate-950 border border-slate-700 rounded-lg px-4 py-2.5 text-white text-sm font-mono focus:outline-none focus:border-cyan-600 placeholder-slate-600"
          placeholder="IP, domain, hash (MD5/SHA1/SHA256) or URL"
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && lookup()}
          disabled={loading}
        />
        <button
          onClick={lookup}
          disabled={loading || !input.trim()}
          className="bg-cyan-600 hover:bg-cyan-500 disabled:opacity-40 disabled:cursor-not-allowed px-5 py-2.5 rounded-lg font-bold text-sm"
        >
          {loading ? 'Enriching…' : 'Enrich'}
        </button>
      </div>

      {error && (
        <div className="bg-red-950 border border-red-800 rounded-lg p-3 text-red-300 text-sm mb-4">{error}</div>
      )}

      {result && (
        <div className="space-y-3">
          <div className="flex items-center gap-3 px-1">
            <span className="font-mono text-cyan-300 text-sm">{result.ioc}</span>
            <span className="bg-slate-700 text-slate-300 px-2 py-0.5 rounded text-xs">{result.type}</span>
            {configuredCount === 0 && (
              <span className="text-yellow-500 text-xs">Configure API keys in .env to enable enrichment</span>
            )}
          </div>

          <div className="grid gap-3" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))' }}>
            {sources.virustotal && <VTCard data={sources.virustotal} type={result.type} />}
            {sources.abuseipdb  && <AbuseCard data={sources.abuseipdb} />}
            {sources.shodan     && <ShodanCard data={sources.shodan} />}
          </div>
        </div>
      )}
    </div>
  )
}

export default IOCEnrichment

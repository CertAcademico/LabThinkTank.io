import { useEffect, useMemo, useRef, useState } from 'react'
import { useAuth } from '../contexts/AuthContext'

const API_URL = import.meta.env.VITE_API_URL ?? 'http://127.0.0.1:8000'

const glass = {
  background: 'rgba(15,23,42,0.55)',
  border: '1px solid rgba(255,255,255,0.07)',
  borderRadius: 12,
}

interface SourceRow {
  id: number
  name: string
  category: string
  url: string
  feed_type: string
  requires_auth: number
  description: string
  formats: string
  group_label: string
  status: string
  last_count: number
}

interface IocRow {
  ioc: string
  type: string
  threat_actor: string
  severity: string
  mitre: string
  country?: string
  source?: string
}

interface IoaRow {
  ttp: string
  ttp_name: string
  tactic: string
  priority: string
  attributed_actor: string
  ioa?: string
}

type TabId = 'sources' | 'stix' | 'sigma' | 'yara'

const tabs: { id: TabId; label: string }[] = [
  { id: 'sources', label: 'Fuentes CTI' },
  { id: 'stix', label: 'STIX / TAXII' },
  { id: 'sigma', label: 'Sigma' },
  { id: 'yara', label: 'YARA' },
]

const severityColor: Record<string, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#facc15',
  low: '#4ade80',
}

function safeFilename(value: string) {
  return value
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[^\w.-]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .slice(0, 70) || 'cti-export'
}

function downloadText(filename: string, content: string, type: string) {
  const url = URL.createObjectURL(new Blob([content], { type }))
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}

function stixType(iocType: string) {
  const t = iocType.toLowerCase()
  if (t.includes('domain')) return 'domain-name:value'
  if (t.includes('hash')) return "file:hashes.'SHA-256'"
  if (t.includes('url')) return 'url:value'
  return 'ipv4-addr:value'
}

function generateStixBundle(iocs: IocRow[], ioas: IoaRow[]) {
  const now = new Date().toISOString()
  const selected = iocs.slice(0, 12)
  const attackPatterns = ioas.slice(0, 6).map((ioa, index) => ({
    type: 'attack-pattern',
    spec_version: '2.1',
    id: `attack-pattern--cti-lab-${index + 1}`,
    created: now,
    modified: now,
    name: `${ioa.ttp} ${ioa.ttp_name}`,
    kill_chain_phases: [{ kill_chain_name: 'mitre-attack', phase_name: ioa.tactic }],
    external_references: [{ source_name: 'mitre-attack', external_id: ioa.ttp }],
  }))
  const indicators = selected.map((ioc, index) => ({
    type: 'indicator',
    spec_version: '2.1',
    id: `indicator--cti-lab-${index + 1}`,
    created: now,
    modified: now,
    name: `${ioc.type} IOC - ${ioc.ioc}`,
    description: `Indicador ${ioc.severity} atribuido a ${ioc.threat_actor || 'Unknown'} y observado en CTI Nexus.`,
    pattern: `[${stixType(ioc.type)} = '${ioc.ioc}']`,
    pattern_type: 'stix',
    valid_from: now,
    labels: [ioc.severity || 'medium', ioc.type || 'ioc'].map(v => v.toLowerCase()),
    external_references: ioc.mitre ? [{ source_name: 'mitre-attack', external_id: ioc.mitre }] : [],
  }))
  return {
    type: 'bundle',
    id: `bundle--cti-lab-${Date.now()}`,
    objects: [...indicators, ...attackPatterns],
  }
}

function sigmaTemplate(ioc: IocRow, ioa?: IoaRow) {
  const value = ioc.ioc || 'example.com'
  const field = ioc.type?.toLowerCase().includes('domain')
    ? 'DestinationHostname'
    : ioc.type?.toLowerCase().includes('hash')
      ? 'Hashes'
      : 'DestinationIp'
  return `title: CTI Nexus - ${ioc.threat_actor || 'IOC'} ${ioa?.ttp || ioc.mitre || 'Detection'}
id: cti-nexus-${safeFilename(value).toLowerCase()}
status: experimental
description: Detecta actividad asociada al indicador ${value} enriquecido en la plataforma CTI.
author: RedCiber - CertAcademico
date: ${new Date().toISOString().slice(0, 10)}
references:
  - https://attack.mitre.org/techniques/${(ioa?.ttp || ioc.mitre || 'T1071').replace('.', '/')}
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    ${field}|contains: '${value}'
  condition: selection
falsepositives:
  - Pruebas internas o infraestructura permitida del laboratorio
level: ${(ioc.severity || 'medium').toLowerCase()}
tags:
  - attack.${(ioa?.ttp || ioc.mitre || 't1071').toLowerCase()}
  - cti.nexus
`
}

function yaraTemplate(ioc: IocRow) {
  const actor = safeFilename(ioc.threat_actor || 'unknown_actor')
  const value = ioc.ioc || 'malicious-string'
  return `rule RedCiber_${actor}_${safeFilename(value)}
{
    meta:
        author = "RedCiber - CertAcademico"
        description = "Regla de entrenamiento asociada al indicador ${value}"
        threat_actor = "${ioc.threat_actor || 'Unknown'}"
        severity = "${ioc.severity || 'medium'}"
        mitre = "${ioc.mitre || 'T1071'}"
        date = "${new Date().toISOString().slice(0, 10)}"

    strings:
        $ioc_1 = "${value}" ascii wide nocase
        $marker_1 = "${ioc.threat_actor || 'cti-nexus'}" ascii wide nocase

    condition:
        any of them
}
`
}

function validateSigma(rule: string) {
  const checks = [
    ['title:', 'Incluye título'],
    ['logsource:', 'Define logsource'],
    ['detection:', 'Incluye bloque detection'],
    ['condition:', 'Incluye condición'],
    ['level:', 'Define nivel'],
  ]
  return checks.map(([needle, label]) => ({ label, ok: rule.includes(needle) }))
}

function validateYara(rule: string) {
  const checks = [
    [/rule\s+\w+/i, 'Incluye nombre de regla'],
    [/meta:/i, 'Incluye metadata'],
    [/strings:/i, 'Incluye strings'],
    [/condition:/i, 'Incluye condición'],
    [/\$[a-z0-9_]+\s*=/i, 'Tiene al menos un patrón'],
  ] as const
  return checks.map(([pattern, label]) => ({ label, ok: pattern.test(rule) }))
}

function Pill({ children, color = '#94a3b8' }: { children: React.ReactNode; color?: string }) {
  return (
    <span className="text-[10px] px-2 py-0.5 rounded-full font-semibold"
          style={{ color, background: `${color}14`, border: `1px solid ${color}25` }}>
      {children}
    </span>
  )
}

export default function CTIToolkit() {
  const { token } = useAuth()
  const [tab, setTab] = useState<TabId>('sources')
  const [sources, setSources] = useState<SourceRow[]>([])
  const [sourcesLoading, setSourcesLoading] = useState(true)
  const [iocs, setIocs] = useState<IocRow[]>([])
  const [ioas, setIoas] = useState<IoaRow[]>([])
  const [selectedIoc, setSelectedIoc] = useState('')
  const [sigma, setSigma] = useState('')
  const [yara, setYara] = useState('')
  const [copied, setCopied] = useState(false)
  const copyTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  useEffect(() => {
    if (!token) return
    setSourcesLoading(true)
    fetch(`${API_URL}/cti/sources`, { headers: { Authorization: `Bearer ${token}` } })
      .then(r => r.ok ? r.json() : [])
      .then(setSources)
      .catch(() => {})
      .finally(() => setSourcesLoading(false))
    fetch(`${API_URL}/ioc-feed`)
      .then(r => r.json())
      .then((rows) => {
        setIocs(rows)
        setSelectedIoc(rows[0]?.ioc ?? '')
      })
      .catch(() => {})
    fetch(`${API_URL}/ioas`)
      .then(r => r.json())
      .then(setIoas)
      .catch(() => {})
  }, [token])

  const currentIoc = useMemo(() => iocs.find(i => i.ioc === selectedIoc) ?? iocs[0], [iocs, selectedIoc])
  const currentIoa = useMemo(() => {
    if (!currentIoc) return undefined
    return ioas.find(i => i.ttp === currentIoc.mitre) ?? ioas[0]
  }, [currentIoc, ioas])
  const sourceGroups = useMemo(() => {
    return sources.reduce<Record<string, SourceRow[]>>((acc, source) => {
      const key = source.category || 'OTRAS'
      acc[key] = [...(acc[key] ?? []), source]
      return acc
    }, {})
  }, [sources])
  const stixBundle = useMemo(() => generateStixBundle(iocs, ioas), [iocs, ioas])

  const copyRule = () => {
    const content = tab === 'sigma' ? sigma : yara
    navigator.clipboard.writeText(content).then(() => {
      setCopied(true)
      if (copyTimerRef.current) clearTimeout(copyTimerRef.current)
      copyTimerRef.current = setTimeout(() => setCopied(false), 2000)
    }).catch(() => {})
  }

  useEffect(() => {
    if (!currentIoc) return
    setSigma(sigmaTemplate(currentIoc, currentIoa))
    setYara(yaraTemplate(currentIoc))
  }, [currentIoc, currentIoa])

  return (
    <div className="h-full overflow-y-auto p-6 space-y-5">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100">CTI Toolkit</h1>
          <p className="text-xs text-slate-500 mt-1">
            Fuentes, STIX/TAXII, reglas Sigma y YARA listas para apoyar los retos en curso.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Pill color="#22d3ee">{sources.length} fuentes</Pill>
          <Pill color="#f97316">{iocs.length} IOCs</Pill>
          <Pill color="#a78bfa">{ioas.length} TTPs</Pill>
        </div>
      </div>

      <div className="flex gap-1 rounded-xl p-1 w-fit" style={glass}>
        {tabs.map(item => (
          <button key={item.id} onClick={() => setTab(item.id)}
                  className="px-3 py-1.5 rounded-lg text-xs font-bold transition-colors"
                  style={tab === item.id
                    ? { background: 'rgba(34,211,238,0.12)', color: '#22d3ee' }
                    : { color: '#64748b' }}>
            {item.label}
          </button>
        ))}
      </div>

      {tab === 'sources' && sourcesLoading && (
        <div className="flex items-center gap-3 py-8">
          <div className="w-4 h-4 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin" />
          <span className="text-xs text-slate-500">Cargando fuentes CTI...</span>
        </div>
      )}

      {tab === 'sources' && !sourcesLoading && sources.length === 0 && (
        <div className="rounded-xl p-10 text-center" style={glass}>
          <p className="text-slate-600 text-sm">No hay fuentes configuradas.</p>
        </div>
      )}

      {tab === 'sources' && !sourcesLoading && sources.length > 0 && (
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
          {Object.entries(sourceGroups).map(([category, rows]) => (
            <section key={category} className="rounded-xl overflow-hidden" style={glass}>
              <div className="px-4 py-3 flex items-center justify-between border-b border-white/[0.06]">
                <h2 className="text-sm font-bold text-slate-200">{category}</h2>
                <Pill>{rows.length} fuentes</Pill>
              </div>
              <div className="divide-y divide-white/[0.05]">
                {rows.map(source => (
                  <div key={source.id} className="p-4 space-y-2">
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <p className="text-xs font-bold text-slate-200">{source.name}</p>
                        <p className="text-[10px] text-slate-600">{source.url}</p>
                      </div>
                      <div className="flex gap-1 flex-wrap justify-end">
                        <Pill color={source.status === 'active' ? '#4ade80' : source.status === 'needs_key' ? '#facc15' : '#94a3b8'}>
                          {source.status}
                        </Pill>
                        <Pill color="#a78bfa">{source.feed_type}</Pill>
                      </div>
                    </div>
                    <p className="text-[11px] text-slate-500 leading-relaxed">{source.description}</p>
                    <div className="flex gap-1 flex-wrap">
                      {source.formats.split(',').filter(Boolean).map(format => <Pill key={format} color="#22d3ee">{format}</Pill>)}
                      {source.requires_auth ? <Pill color="#f97316">API key</Pill> : <Pill color="#4ade80">sin auth</Pill>}
                    </div>
                  </div>
                ))}
              </div>
            </section>
          ))}
        </div>
      )}

      {tab === 'stix' && (
        <div className="grid grid-cols-1 xl:grid-cols-[360px_1fr] gap-4">
          <section className="rounded-xl p-4 space-y-3" style={glass}>
            <h2 className="text-sm font-bold text-slate-200">Paquete STIX 2.1</h2>
            <p className="text-xs text-slate-500 leading-relaxed">
              Genera un bundle con indicadores y técnicas ATT&CK para compartir por TAXII, MISP u OpenCTI.
            </p>
            <button
              onClick={() => downloadText('cti-nexus-stix-bundle.json', JSON.stringify(stixBundle, null, 2), 'application/json;charset=utf-8')}
              className="w-full px-3 py-2 rounded-lg text-xs font-bold"
              style={{ background: 'rgba(34,211,238,0.1)', color: '#22d3ee', border: '1px solid rgba(34,211,238,0.25)' }}>
              Exportar STIX JSON
            </button>
            <div className="grid grid-cols-2 gap-2">
              <div className="rounded-lg p-3 bg-white/[0.03]">
                <p className="text-[9px] text-slate-600 uppercase font-bold">Indicadores</p>
                <p className="text-lg font-bold text-slate-200">{Math.min(iocs.length, 12)}</p>
              </div>
              <div className="rounded-lg p-3 bg-white/[0.03]">
                <p className="text-[9px] text-slate-600 uppercase font-bold">Attack patterns</p>
                <p className="text-lg font-bold text-slate-200">{Math.min(ioas.length, 6)}</p>
              </div>
            </div>
          </section>
          <pre className="rounded-xl p-4 overflow-auto max-h-[620px] text-[11px] text-slate-400"
               style={{ ...glass, background: '#050a14' }}>
            {JSON.stringify(stixBundle, null, 2)}
          </pre>
        </div>
      )}

      {(tab === 'sigma' || tab === 'yara') && (
        <div className="grid grid-cols-1 xl:grid-cols-[360px_1fr] gap-4">
          <section className="rounded-xl p-4 space-y-4" style={glass}>
            <div>
              <p className="text-[9px] text-slate-600 uppercase font-bold mb-1">IOC base</p>
              <select value={selectedIoc} onChange={e => setSelectedIoc(e.target.value)}
                      className="w-full rounded-lg px-3 py-2 text-xs outline-none"
                      style={{ background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)', color: '#cbd5e1' }}>
                {iocs.map(ioc => <option key={ioc.ioc} value={ioc.ioc}>{ioc.ioc} · {ioc.threat_actor}</option>)}
              </select>
            </div>
            {currentIoc && (
              <div className="rounded-lg p-3 space-y-2 bg-white/[0.03]">
                <div className="flex items-center gap-2 flex-wrap">
                  <Pill color={severityColor[currentIoc.severity] ?? '#94a3b8'}>{currentIoc.severity}</Pill>
                  <Pill color="#a78bfa">{currentIoc.mitre || 'sin MITRE'}</Pill>
                  <Pill color="#22d3ee">{currentIoc.type}</Pill>
                </div>
                <p className="text-xs text-slate-300 font-mono break-all">{currentIoc.ioc}</p>
                <p className="text-[11px] text-slate-500">Actor: {currentIoc.threat_actor || 'Unknown'}</p>
              </div>
            )}
            <div className="space-y-1">
              {(tab === 'sigma' ? validateSigma(sigma) : validateYara(yara)).map(check => (
                <div key={check.label} className="flex items-center gap-2 text-[11px]">
                  <span className="w-1.5 h-1.5 rounded-full" style={{ background: check.ok ? '#4ade80' : '#ef4444' }} />
                  <span className={check.ok ? 'text-slate-400' : 'text-red-300'}>{check.label}</span>
                </div>
              ))}
            </div>
            <div className="flex gap-2">
              <button
                onClick={() => {
                  const content = tab === 'sigma' ? sigma : yara
                  const ext = tab === 'sigma' ? 'yml' : 'yar'
                  downloadText(`${safeFilename(currentIoc?.ioc ?? tab)}.${ext}`, content, 'text/plain;charset=utf-8')
                }}
                className="flex-1 px-3 py-2 rounded-lg text-xs font-bold"
                style={{ background: 'rgba(167,139,250,0.1)', color: '#a78bfa', border: '1px solid rgba(167,139,250,0.28)' }}>
                Descargar {tab === 'sigma' ? 'Sigma' : 'YARA'}
              </button>
              <button
                onClick={copyRule}
                className="px-3 py-2 rounded-lg text-xs font-bold transition-colors"
                style={copied
                  ? { background: 'rgba(74,222,128,0.12)', color: '#4ade80', border: '1px solid rgba(74,222,128,0.3)' }
                  : { background: 'rgba(255,255,255,0.04)', color: '#64748b', border: '1px solid rgba(255,255,255,0.1)' }}>
                {copied ? '✓' : 'Copiar'}
              </button>
            </div>
          </section>

          <textarea
            value={tab === 'sigma' ? sigma : yara}
            onChange={e => tab === 'sigma' ? setSigma(e.target.value) : setYara(e.target.value)}
            spellCheck={false}
            className="rounded-xl p-4 min-h-[620px] resize-none outline-none font-mono text-xs leading-relaxed"
            style={{ ...glass, background: '#050a14', color: '#86efac' }}
          />
        </div>
      )}
    </div>
  )
}

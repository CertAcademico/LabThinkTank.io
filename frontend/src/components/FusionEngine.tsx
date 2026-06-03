/**
 * RedCiber × CTI-Lab — Motor de Fusión de Amenazas
 * Powered by Google Gemini via the CTI-Lab backend proxy (/ai/gemini/*)
 */
import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  BarChart, Bar, CartesianGrid, XAxis, YAxis, Tooltip as RTooltip, ResponsiveContainer,
  PieChart, Pie, Cell,
} from 'recharts'
import {
  Shield, Zap, Globe, Brain, Users, FileText,
  Download, AlertCircle, ChevronDown, ChevronRight,
  Search, Cpu, Map, TrendingUp, GitBranch,
} from 'lucide-react'
import ReactFlow, { Background, Controls, MiniMap, Handle, Position } from 'reactflow'
import type { NodeProps } from 'reactflow'
import 'reactflow/dist/style.css'
import { useAuth } from '../contexts/AuthContext'

const API = import.meta.env.VITE_API_URL ?? 'http://127.0.0.1:8000'

// ── Types ──────────────────────────────────────────────────────────────────────

interface ThreatEvent {
  id: string; timestamp: string; threatType: string; severity: string
  sourceCountry: string; targetCountry: string; description: string
  ioc: string; malware: string; threatActor: string; threatName: string
  victim: string; mitreTactic: string; mitreTechniqueId: string
  confidenceScore: number; isFalsePositive: boolean
}

type SubKey = 'predictive' | 'quantum' | 'geopolitical' | 'scenarios' | 'ml' | 'weekly' | 'colombia' | 'graph'

// ── Constants ──────────────────────────────────────────────────────────────────

const glass = { background: 'rgba(15,23,42,0.6)', border: '1px solid rgba(255,255,255,0.07)', borderRadius: 12 }
const glassRed = { background: 'rgba(30,10,12,0.6)', border: '1px solid rgba(239,68,68,0.18)', borderRadius: 12 }

const SEV_COLOR: Record<string, string> = {
  Critical: '#ef4444', High: '#f97316', Medium: '#facc15', Low: '#4ade80',
}
const PIE_COLORS = ['#ef4444', '#f97316', '#facc15', '#4ade80', '#22d3ee']

import type { ReactNode } from 'react'
const SUB_ANALYSES: { key: SubKey; label: string; icon: ReactNode; desc: string }[] = [
  { key: 'predictive',  label: 'Análisis Predictivo',  icon: <TrendingUp size={13} />,  desc: 'Próxima táctica + nexo cruzado' },
  { key: 'quantum',     label: 'Cuántico / PQC',       icon: <Cpu size={13} />,         desc: 'Riesgo PQC y algoritmos expuestos' },
  { key: 'geopolitical',label: 'Geopolítico',          icon: <Globe size={13} />,        desc: 'Score de estabilidad + amenazas anticipadas' },
  { key: 'scenarios',   label: 'Escenarios de Equipo', icon: <Users size={13} />,        desc: 'Red / Blue / Purple / White Team' },
  { key: 'ml',          label: 'Propuestas ML',        icon: <Brain size={13} />,        desc: 'RF / LSTM / SVM / Clustering por evento' },
  { key: 'weekly',      label: 'Reporte Flash Semanal',icon: <FileText size={13} />,     desc: 'Hunting queries Sigma/KQL/YARA + PDF' },
  { key: 'colombia',    label: 'Riesgo Colombia',      icon: <Map size={13} />,          desc: 'Infraestructura crítica (Decreto 338/2022)' },
  { key: 'graph',       label: 'Grafo de Correlación', icon: <GitBranch size={13} />,    desc: 'Actor → IOC → Campaña · enriquecido con CISA' },
]

// ── Small helpers ──────────────────────────────────────────────────────────────

async function readApiJson<T = Record<string, unknown>>(res: Response): Promise<T> {
  const text = await res.text()
  if (!text.trim()) return {} as T

  try {
    return JSON.parse(text) as T
  } catch {
    const label = res.status ? `HTTP ${res.status}` : 'Respuesta inválida'
    const preview = text.replace(/\s+/g, ' ').trim().slice(0, 180)
    throw new Error(`${label}: el backend no devolvió JSON válido${preview ? ` (${preview})` : ''}`)
  }
}

function Pill({ children, color = '#94a3b8' }: { children: React.ReactNode; color?: string }) {
  return (
    <span className="text-[9px] px-2 py-0.5 rounded-full font-bold"
          style={{ color, background: `${color}16`, border: `1px solid ${color}28` }}>
      {children}
    </span>
  )
}

function Spinner({ color = '#22d3ee' }: { color?: string }) {
  return <div className="w-4 h-4 border-2 border-t-transparent rounded-full animate-spin" style={{ borderColor: color, borderTopColor: 'transparent' }} />
}

function Section({ title, icon, open, onToggle, children, accent = '#22d3ee' }: {
  title: string; icon: ReactNode; open: boolean; onToggle: () => void
  children: ReactNode; accent?: string
}) {
  return (
    <div className="rounded-xl overflow-hidden" style={{ ...glass, border: `1px solid ${accent}25` }}>
      <button onClick={onToggle} className="w-full flex items-center gap-2.5 px-4 py-3 text-left hover:bg-white/[0.02]">
        <span style={{ color: accent }}>{icon}</span>
        <span className="text-xs font-bold text-slate-200 flex-1">{title}</span>
        {open ? <ChevronDown size={13} className="text-slate-600" /> : <ChevronRight size={13} className="text-slate-600" />}
      </button>
      {open && <div className="px-4 pb-4 pt-1 space-y-3">{children}</div>}
    </div>
  )
}

// ── Export helpers ─────────────────────────────────────────────────────────────

function exportEventsXlsx(events: ThreatEvent[]) {
  import('xlsx').then(XLSX => {
    const ws = XLSX.utils.json_to_sheet(events)
    const wb = XLSX.utils.book_new()
    XLSX.utils.book_append_sheet(wb, ws, 'Eventos')
    XLSX.writeFile(wb, `fusion-events-${Date.now()}.xlsx`)
  })
}

function safeFilename(value: string) {
  return value
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[^\w.-]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .slice(0, 70) || 'fusion-events'
}

function downloadText(filename: string, content: string, type: string) {
  const url = URL.createObjectURL(new Blob([content], { type }))
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}

function rowsToCsv(rows: Record<string, unknown>[]) {
  if (!rows.length) return ''
  const cols = [...new Set(rows.flatMap(row => Object.keys(row)))]
  const esc = (value: unknown) => {
    const text = value == null ? '' : typeof value === 'object' ? JSON.stringify(value) : String(value)
    return /[",\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text
  }
  return [cols.map(esc).join(','), ...rows.map(row => cols.map(col => esc(row[col])).join(','))].join('\n')
}

function exportEventsCsv(query: string, events: ThreatEvent[]) {
  downloadText(
    `${safeFilename(`fusion-${query}`)}-${Date.now()}.csv`,
    `\uFEFF${rowsToCsv(events as unknown as Record<string, unknown>[])}`,
    'text/csv;charset=utf-8',
  )
}

function exportEventsJson(query: string, events: ThreatEvent[]) {
  downloadText(
    `${safeFilename(`fusion-${query}`)}-${Date.now()}.json`,
    JSON.stringify({
      exportedAt: new Date().toISOString(),
      query,
      count: events.length,
      events,
    }, null, 2),
    'application/json;charset=utf-8',
  )
}

function exportReportPdf(query: string, events: ThreatEvent[], weekly: Record<string, unknown> | null) {
  import('jspdf').then((mod) => {
    // jspdf v2 exports as default or named jsPDF
    const jsPDFClass = (mod as { default?: unknown; jsPDF?: unknown }).jsPDF ?? (mod as { default?: unknown }).default ?? mod
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const doc = new (jsPDFClass as any)()
    const now = new Date().toLocaleDateString('es-CO', { year: 'numeric', month: 'long', day: 'numeric' })
    let y = 20

    doc.setFontSize(16); doc.setTextColor(30, 30, 30)
    doc.text('RedCiber × CTI-Lab — Reporte de Fusión de Amenazas', 14, y); y += 8
    doc.setFontSize(10); doc.setTextColor(80, 80, 80)
    doc.text(`Consulta: ${query}`, 14, y); y += 5
    doc.text(`Fecha: ${now}  |  Eventos analizados: ${events.length}`, 14, y); y += 10

    if (weekly) {
      doc.setFontSize(13); doc.setTextColor(30, 30, 30)
      doc.text(String(weekly.reportTitle ?? 'Informe Flash'), 14, y); y += 7
      doc.setFontSize(9); doc.setTextColor(60, 60, 60)
      const summary = String(weekly.executiveSummary ?? '')
      const lines = doc.splitTextToSize(summary, 180)
      doc.text(lines, 14, y); y += lines.length * 5 + 5

      if (Array.isArray(weekly.mitigationRecommendations)) {
        doc.setFontSize(11); doc.setTextColor(30, 30, 30)
        doc.text('Recomendaciones', 14, y); y += 6
        doc.setFontSize(9); doc.setTextColor(60, 60, 60)
        ;(weekly.mitigationRecommendations as string[]).forEach((rec, i) => {
          const recLines = doc.splitTextToSize(`${i + 1}. ${rec}`, 180)
          if (y + recLines.length * 5 > 280) { doc.addPage(); y = 20 }
          doc.text(recLines, 14, y); y += recLines.length * 5 + 2
        })
      }
    }

    // Events sample
    y += 5
    doc.setFontSize(11); doc.setTextColor(30, 30, 30)
    doc.text('Muestra de eventos (20)', 14, y); y += 6
    doc.setFontSize(7); doc.setTextColor(80, 80, 80)
    events.slice(0, 20).forEach(ev => {
      const line = `[${ev.severity}] ${ev.threatActor} · ${ev.mitreTactic} · ${ev.ioc || ev.malware || '—'}`
      if (y > 280) { doc.addPage(); y = 20 }
      doc.text(line.slice(0, 110), 14, y); y += 4
    })

    doc.save(`fusion-report-${Date.now()}.pdf`)
  })
}

// ── Charts ─────────────────────────────────────────────────────────────────────

function SeverityPie({ events }: { events: ThreatEvent[] }) {
  const data = useMemo(() => {
    const counts: Record<string, number> = {}
    events.forEach(e => { counts[e.severity] = (counts[e.severity] ?? 0) + 1 })
    return Object.entries(counts).map(([name, value]) => ({ name, value }))
  }, [events])

  return (
    <ResponsiveContainer width="100%" height={180}>
      <PieChart>
        <Pie data={data} cx="50%" cy="50%" outerRadius={65} dataKey="value" labelLine={false}
             label={({ name, percent }: { name?: string; percent?: number }) => `${name ?? ''} ${((percent ?? 0) * 100).toFixed(0)}%`}>
          {data.map((_, i) => (
            <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />
          ))}
        </Pie>
        <RTooltip contentStyle={{ background: '#0f172a', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 8, fontSize: 11 }} />
      </PieChart>
    </ResponsiveContainer>
  )
}

function TacticBar({ events }: { events: ThreatEvent[] }) {
  const data = useMemo(() => {
    const counts: Record<string, number> = {}
    events.forEach(e => {
      if (e.mitreTactic) counts[e.mitreTactic] = (counts[e.mitreTactic] ?? 0) + 1
    })
    return Object.entries(counts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8)
      .map(([tactic, count]) => ({ tactic: tactic.slice(0, 16), count }))
  }, [events])

  return (
    <ResponsiveContainer width="100%" height={180}>
      <BarChart data={data} margin={{ top: 4, right: 8, left: -20, bottom: 40 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
        <XAxis dataKey="tactic" tick={{ fill: '#64748b', fontSize: 9 }} angle={-35} textAnchor="end" />
        <YAxis tick={{ fill: '#64748b', fontSize: 9 }} />
        <RTooltip contentStyle={{ background: '#0f172a', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 8, fontSize: 11 }} />
        <Bar dataKey="count" fill="#ef4444" radius={[3, 3, 0, 0]} />
      </BarChart>
    </ResponsiveContainer>
  )
}

function ActorBar({ events }: { events: ThreatEvent[] }) {
  const data = useMemo(() => {
    const counts: Record<string, number> = {}
    events.forEach(e => {
      if (e.threatActor && e.threatActor !== 'Unknown') counts[e.threatActor] = (counts[e.threatActor] ?? 0) + 1
    })
    return Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 7).map(([actor, count]) => ({ actor: actor.slice(0, 18), count }))
  }, [events])

  return (
    <ResponsiveContainer width="100%" height={180}>
      <BarChart data={data} layout="vertical" margin={{ top: 4, right: 16, left: 8, bottom: 4 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" horizontal={false} />
        <XAxis type="number" tick={{ fill: '#64748b', fontSize: 9 }} />
        <YAxis type="category" dataKey="actor" tick={{ fill: '#94a3b8', fontSize: 9 }} width={80} />
        <RTooltip contentStyle={{ background: '#0f172a', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 8, fontSize: 11 }} />
        <Bar dataKey="count" fill="#22d3ee" radius={[0, 3, 3, 0]} />
      </BarChart>
    </ResponsiveContainer>
  )
}

// ── Visibility dashboard ──────────────────────────────────────────────────────

const SEV_WEIGHT: Record<string, number> = { Critical: 100, High: 72, Medium: 42, Low: 18 }
const KILL_CHAIN_ORDER = [
  'Reconnaissance', 'Resource Development', 'Initial Access', 'Execution', 'Persistence',
  'Privilege Escalation', 'Defense Evasion', 'Credential Access', 'Discovery',
  'Lateral Movement', 'Collection', 'Command and Control', 'Exfiltration', 'Impact',
]

function topCounts(values: string[], limit = 6) {
  const counts = values.reduce<Record<string, number>>((acc, value) => {
    if (value && value !== 'Unknown' && value !== 'N/A') acc[value] = (acc[value] ?? 0) + 1
    return acc
  }, {})
  return Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, limit)
}

function eventRiskScore(event: ThreatEvent) {
  const sev = SEV_WEIGHT[event.severity] ?? 35
  const conf = Number(event.confidenceScore) || 50
  const criticalAsset = /bank|financ|energy|energ|gov|gobierno|salud|health|telecom|infra/i.test(
    `${event.victim} ${event.targetCountry} ${event.description}`,
  ) ? 10 : 0
  return Math.min(100, Math.round(sev * 0.66 + conf * 0.24 + criticalAsset))
}

function buildVisibility(events: ThreatEvent[], query: string) {
  const topActors = topCounts(events.map(e => e.threatActor), 5)
  const topTactics = topCounts(events.map(e => e.mitreTactic), 8)
  const topTargets = topCounts(events.map(e => e.targetCountry || e.victim), 5)
  const topSources = topCounts(events.map(e => e.sourceCountry), 5)
  const critical = events.filter(e => e.severity === 'Critical').length
  const high = events.filter(e => e.severity === 'High').length
  const weighted = events.reduce((sum, event) => sum + eventRiskScore(event), 0)
  const riskScore = events.length ? Math.round(weighted / events.length) : 0
  const dominantActor = topActors[0]?.[0] ?? 'Sin atribución dominante'
  const dominantTactic = topTactics[0]?.[0] ?? 'Sin táctica dominante'
  const exposedTarget = topTargets[0]?.[0] ?? 'Objetivo mixto'
  const sourcePressure = topSources[0]?.[0] ?? 'Origen mixto'
  const avgConf = events.length
    ? Math.round(events.reduce((sum, event) => sum + (Number(event.confidenceScore) || 0), 0) / events.length)
    : 0

  const timeline = KILL_CHAIN_ORDER.map((tactic, index) => {
    const tacticEvents = events.filter(e => e.mitreTactic === tactic)
    const score = tacticEvents.reduce((sum, event) => sum + eventRiskScore(event), 0)
    return {
      tactic,
      index,
      count: tacticEvents.length,
      score,
      severity: tacticEvents.some(e => e.severity === 'Critical') ? 'Critical'
        : tacticEvents.some(e => e.severity === 'High') ? 'High'
        : tacticEvents.length ? 'Medium' : 'Low',
    }
  }).filter(t => t.count > 0)

  const priorities = events
    .filter(e => e.ioc || e.threatActor || e.mitreTechniqueId)
    .map(event => ({
      event,
      score: eventRiskScore(event),
      evidence: [
        event.threatActor,
        event.mitreTechniqueId || event.mitreTactic,
        event.ioc,
        event.sourceCountry && event.targetCountry ? `${event.sourceCountry}→${event.targetCountry}` : '',
      ].filter(Boolean).join(' · '),
      action: event.severity === 'Critical'
        ? 'Aislar evidencia, enriquecer IOC y activar hunting inmediato'
        : event.severity === 'High'
          ? 'Priorizar hunting y validación de controles'
          : 'Monitorear correlaciones y enriquecer contexto',
    }))
    .sort((a, b) => b.score - a.score)
    .slice(0, 8)

  const brief = [
    '# Brief SOC - Motor de Fusion CTI',
    '',
    `Consulta: ${query || 'Sin consulta'}`,
    `Eventos analizados: ${events.length}`,
    `Riesgo ejecutivo: ${riskScore}/100`,
    `Actor dominante: ${dominantActor}`,
    `Tactica dominante: ${dominantTactic}`,
    `Objetivo mas expuesto: ${exposedTarget}`,
    `Presion de origen: ${sourcePressure}`,
    `Severidad: ${critical} criticos, ${high} altos`,
    `Confianza media: ${avgConf}%`,
    '',
    '## Prioridades',
    ...priorities.slice(0, 5).map((p, i) => `${i + 1}. [${p.score}/100] ${p.evidence} - ${p.action}`),
    '',
    '## Tacticas observadas',
    ...topTactics.map(([tactic, count]) => `- ${tactic}: ${count} eventos`),
    '',
    '## Acciones SOC',
    '- Enriquecer IOCs prioritarios con VT/AbuseIPDB/Shodan/MISP.',
    '- Buscar TTPs dominantes en SIEM/EDR durante las ultimas 24h, 7d y 30d.',
    '- Validar cobertura ATT&CK para tacticas criticas y altas.',
    '- Escalar eventos con score >= 80 a respuesta de incidentes.',
  ].join('\n')

  return {
    riskScore,
    riskLabel: riskScore >= 78 ? 'Crítico' : riskScore >= 58 ? 'Alto' : riskScore >= 36 ? 'Medio' : 'Bajo',
    dominantActor,
    dominantTactic,
    exposedTarget,
    sourcePressure,
    avgConf,
    topActors,
    topTactics,
    timeline,
    priorities,
    brief,
  }
}

function IntelVisibilityDashboard({ events, query }: { events: ThreatEvent[]; query: string }) {
  const visibility = useMemo(() => buildVisibility(events, query), [events, query])
  const riskColor = visibility.riskScore >= 78 ? '#ef4444'
    : visibility.riskScore >= 58 ? '#f97316'
      : visibility.riskScore >= 36 ? '#facc15'
        : '#4ade80'

  return (
    <div className="rounded-xl overflow-hidden" style={{ ...glass, border: `1px solid ${riskColor}24` }}>
      <div className="px-4 py-3 border-b flex items-center gap-3 flex-wrap" style={{ borderColor: 'rgba(255,255,255,0.06)', background: 'rgba(0,0,0,0.22)' }}>
        <div>
          <p className="text-xs font-bold text-slate-200">Intel Visibility Dashboard</p>
          <p className="text-[9px] text-slate-600">Radar ejecutivo · Timeline ATT&CK · Ranking SOC</p>
        </div>
        <div className="flex-1" />
        <button onClick={() => downloadText(`soc-brief-${Date.now()}.md`, visibility.brief, 'text/markdown;charset=utf-8')}
                className="flex items-center gap-1.5 px-2.5 py-1.5 rounded text-[10px] font-bold"
                style={{ background: 'rgba(34,211,238,0.08)', color: '#22d3ee', border: '1px solid rgba(34,211,238,0.22)' }}>
          <Download size={10} /> Brief SOC
        </button>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-4 gap-4 p-4">
        <div className="rounded-lg p-4 xl:row-span-2 flex flex-col justify-between" style={{ background: `${riskColor}08`, border: `1px solid ${riskColor}24` }}>
          <div>
            <p className="text-[9px] font-bold uppercase tracking-wider" style={{ color: riskColor }}>Riesgo ejecutivo</p>
            <p className="text-4xl font-black mt-1" style={{ color: riskColor }}>{visibility.riskScore}</p>
            <p className="text-xs font-bold text-slate-300">{visibility.riskLabel}</p>
          </div>
          <div className="space-y-2 mt-5">
            {[
              ['Actor', visibility.dominantActor],
              ['Táctica', visibility.dominantTactic],
              ['Objetivo', visibility.exposedTarget],
              ['Origen', visibility.sourcePressure],
            ].map(([label, value]) => (
              <div key={label}>
                <p className="text-[8px] text-slate-700 uppercase font-bold">{label}</p>
                <p className="text-[10px] text-slate-300 truncate">{value}</p>
              </div>
            ))}
          </div>
        </div>

        <div className="xl:col-span-3 grid grid-cols-2 lg:grid-cols-4 gap-2">
          {[
            { label: 'Actor dominante', value: visibility.dominantActor, color: '#a78bfa' },
            { label: 'TTP dominante', value: visibility.dominantTactic, color: '#f87171' },
            { label: 'Objetivo expuesto', value: visibility.exposedTarget, color: '#22d3ee' },
            { label: 'Confianza media', value: `${visibility.avgConf}%`, color: '#4ade80' },
          ].map(item => (
            <div key={item.label} className="rounded-lg px-3 py-2.5 min-w-0" style={{ background: 'rgba(255,255,255,0.025)', border: '1px solid rgba(255,255,255,0.05)' }}>
              <p className="text-[8px] text-slate-700 uppercase font-bold">{item.label}</p>
              <p className="text-[11px] font-bold truncate mt-1" style={{ color: item.color }}>{item.value}</p>
            </div>
          ))}
        </div>

        <div className="xl:col-span-2 rounded-lg p-3" style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.05)' }}>
          <p className="text-[9px] font-bold text-slate-600 uppercase tracking-wider mb-3">Timeline ATT&CK</p>
          <div className="flex items-end gap-2 h-28 overflow-x-auto pb-1">
            {visibility.timeline.map(item => {
              const color = SEV_COLOR[item.severity] ?? '#64748b'
              const height = Math.max(16, Math.min(96, item.count * 14))
              return (
                <div key={item.tactic} className="flex flex-col items-center gap-1 min-w-16">
                  <div className="w-full rounded-t" title={`${item.tactic}: ${item.count} eventos`}
                       style={{ height, background: `${color}66`, border: `1px solid ${color}88` }} />
                  <span className="text-[8px] text-slate-600 text-center leading-tight">{item.tactic.split(' ').slice(0, 2).join(' ')}</span>
                </div>
              )
            })}
          </div>
        </div>

        <div className="xl:col-span-1 rounded-lg p-3" style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.05)' }}>
          <p className="text-[9px] font-bold text-slate-600 uppercase tracking-wider mb-2">Top actores</p>
          <div className="space-y-2">
            {visibility.topActors.slice(0, 5).map(([actor, count]) => (
              <div key={actor} className="flex items-center gap-2">
                <span className="text-[10px] text-slate-400 truncate flex-1">{actor}</span>
                <span className="text-[9px] font-mono text-violet-400">{count}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="xl:col-span-1 rounded-lg p-3" style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.05)' }}>
          <p className="text-[9px] font-bold text-slate-600 uppercase tracking-wider mb-2">Top TTPs</p>
          <div className="space-y-2">
            {visibility.topTactics.slice(0, 5).map(([tactic, count]) => (
              <div key={tactic} className="flex items-center gap-2">
                <span className="text-[10px] text-slate-400 truncate flex-1">{tactic}</span>
                <span className="text-[9px] font-mono text-red-400">{count}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="xl:col-span-4 rounded-lg overflow-hidden" style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.05)' }}>
          <div className="px-3 py-2 border-b" style={{ borderColor: 'rgba(255,255,255,0.05)' }}>
            <p className="text-[9px] font-bold text-slate-600 uppercase tracking-wider">Ranking de prioridad CTI/SOC</p>
          </div>
          <div className="divide-y divide-white/[0.03]">
            {visibility.priorities.slice(0, 6).map((p, i) => {
              const color = p.score >= 80 ? '#ef4444' : p.score >= 60 ? '#f97316' : '#facc15'
              return (
                <div key={`${p.event.id}-${i}`} className="grid grid-cols-[44px_1fr_180px] gap-3 px-3 py-2 items-center">
                  <span className="text-sm font-black" style={{ color }}>{p.score}</span>
                  <div className="min-w-0">
                    <p className="text-[10px] text-slate-300 truncate">{p.evidence}</p>
                    <p className="text-[9px] text-slate-700 truncate">{p.event.description}</p>
                  </div>
                  <p className="text-[9px] text-slate-500 leading-tight">{p.action}</p>
                </div>
              )
            })}
          </div>
        </div>
      </div>
    </div>
  )
}

// ── Sub-analysis result renderers ──────────────────────────────────────────────

function PredictivePanel({ data }: { data: Record<string, unknown> }) {
  const impact = data.potentialImpact as Record<string, unknown>
  const next = data.predictedNextTactic as Record<string, unknown>
  const attr = data.recalculatedAttribution as Record<string, unknown>
  return (
    <div className="space-y-3">
      {data.analysisMode === 'heuristic-fallback' && (
        <div className="rounded-lg px-3 py-2 flex items-start gap-2"
             style={{ background: 'rgba(250,204,21,0.06)', border: '1px solid rgba(250,204,21,0.16)' }}>
          <AlertCircle size={13} className="text-yellow-500 shrink-0 mt-0.5" />
          <p className="text-[10px] text-yellow-200/80">
            Modo predictivo local activo. El motor IA externo no respondió correctamente, pero el análisis se generó con los eventos disponibles.
          </p>
        </div>
      )}
      {impact && (
        <div className="rounded-lg p-3 space-y-1" style={{ background: `${SEV_COLOR[String(impact.severity)] ?? '#94a3b8'}0a`, border: `1px solid ${SEV_COLOR[String(impact.severity)] ?? '#94a3b8'}25` }}>
          <div className="flex items-center gap-2">
            <Pill color={SEV_COLOR[String(impact.severity)] ?? '#94a3b8'}>{String(impact.severity)}</Pill>
            <span className="text-[10px] text-slate-500">Probabilidad: {Math.round(Number(impact.probability) * 100)}%</span>
          </div>
          <p className="text-xs text-slate-300">{String(impact.reasoning ?? '')}</p>
        </div>
      )}
      {next && (
        <div className="rounded-lg p-3" style={{ background: 'rgba(167,139,250,0.06)', border: '1px solid rgba(167,139,250,0.15)' }}>
          <p className="text-[9px] font-bold text-violet-500 uppercase mb-1">Próxima táctica probable</p>
          <p className="text-xs font-bold text-slate-200">{String(next.tactic ?? '')}</p>
          <p className="text-[10px] text-slate-500 mt-1">{String(next.reasoning ?? '')}</p>
        </div>
      )}
      {attr && (
        <div className="rounded-lg p-3" style={{ background: 'rgba(34,211,238,0.05)', border: '1px solid rgba(34,211,238,0.12)' }}>
          <p className="text-[9px] font-bold text-cyan-600 uppercase mb-1">Atribución recalculada</p>
          <p className="text-xs font-bold text-slate-200">{String(attr.actor ?? '')}</p>
          <p className="text-[10px] text-slate-500 mt-0.5">Confianza: {Math.round(Number(attr.confidence) * 100)}% · {String(attr.reasoning ?? '')}</p>
        </div>
      )}
      {Boolean(data.multiActorCorrelation) && (
        <p className="text-[10px] text-slate-400 italic">{String(data.multiActorCorrelation)}</p>
      )}
    </div>
  )
}

function QuantumPanel({ data }: { data: Record<string, unknown> }) {
  const hndl = data.hndlRisk as Record<string, unknown>
  const pqc  = data.pqcVulnerability as Record<string, unknown>
  const ttps = data.quantumTTPs as Record<string, unknown>[]
  return (
    <div className="space-y-3">
      {hndl && (
        <div className="rounded-lg p-3 grid grid-cols-3 gap-3" style={{ background: 'rgba(239,68,68,0.05)', border: '1px solid rgba(239,68,68,0.15)' }}>
          <div className="text-center">
            <p className="text-2xl font-black" style={{ color: Number(hndl.score) > 70 ? '#ef4444' : Number(hndl.score) > 40 ? '#f97316' : '#4ade80' }}>{Math.round(Number(hndl.score))}</p>
            <p className="text-[9px] text-slate-600 uppercase">Score HNDL</p>
          </div>
          <div className="col-span-2">
            <p className="text-[10px] text-slate-400">{String(hndl.justification ?? '')}</p>
          </div>
        </div>
      )}
      {pqc && (
        <div className="rounded-lg p-3 space-y-2" style={{ background: 'rgba(167,139,250,0.05)', border: '1px solid rgba(167,139,250,0.12)' }}>
          <div className="flex items-center gap-2 flex-wrap">
            <Pill color="#a78bfa">Migración: {String(pqc.migrationPriority ?? '')}</Pill>
            {(pqc.exposedAlgorithms as string[] ?? []).map((a, i) => <Pill key={i} color="#f97316">{a}</Pill>)}
          </div>
          <p className="text-[10px] text-slate-500">{String(pqc.sectorStatus ?? '')}</p>
        </div>
      )}
      {ttps?.slice(0, 4).map((t, i) => (
        <div key={i} className="rounded-lg px-3 py-2 space-y-0.5" style={{ background: 'rgba(255,255,255,0.025)', border: '1px solid rgba(255,255,255,0.05)' }}>
          <p className="text-[10px] font-bold text-slate-300">{String(t.technique ?? '')}</p>
          <p className="text-[9px] text-slate-500">{String(t.mitigation ?? '')}</p>
        </div>
      ))}
    </div>
  )
}

function ScenariosPanel({ data }: { data: Record<string, unknown> }) {
  const teams = [
    { key: 'redTeam',    label: 'Red Team',    color: '#ef4444' },
    { key: 'blueTeam',   label: 'Blue Team',   color: '#3b82f6' },
    { key: 'purpleTeam', label: 'Purple Team', color: '#a78bfa' },
    { key: 'whiteTeam',  label: 'White Team',  color: '#e2e8f0' },
  ]
  return (
    <div className="grid grid-cols-1 gap-3">
      {teams.map(({ key, label, color }) => {
        const team = data[key] as Record<string, unknown>
        if (!team) return null
        const phases = team.phases as Record<string, unknown>[]
        return (
          <div key={key} className="rounded-lg p-3 space-y-2" style={{ background: `${color}07`, border: `1px solid ${color}25` }}>
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full shrink-0" style={{ background: color }} />
              <p className="text-xs font-bold" style={{ color }}>{label}</p>
              <span className="text-[10px] text-slate-500">{String(team.scenarioTitle ?? '')}</span>
            </div>
            {phases?.slice(0, 3).map((p, i) => (
              <div key={i}>
                <p className="text-[9px] font-bold text-slate-500 uppercase">{String(p.phaseName ?? '')}</p>
                <ul className="text-[9px] text-slate-400 space-y-0.5 mt-0.5">
                  {(p.actions as string[] ?? []).slice(0, 3).map((a, j) => <li key={j}>· {a}</li>)}
                </ul>
              </div>
            ))}
          </div>
        )
      })}
    </div>
  )
}

function MLPanel({ data }: { data: Record<string, unknown> }) {
  const proposals = data.proposals as Record<string, unknown>[]
  return (
    <div className="space-y-2">
      {data.analysisMode === 'heuristic-fallback' && (
        <div className="rounded-lg px-3 py-2 flex items-start gap-2"
             style={{ background: 'rgba(250,204,21,0.06)', border: '1px solid rgba(250,204,21,0.16)' }}>
          <AlertCircle size={13} className="text-yellow-500 shrink-0 mt-0.5" />
          <p className="text-[10px] text-yellow-200/80">
            Propuestas ML generadas localmente porque el motor IA externo falló temporalmente.
          </p>
        </div>
      )}
      <p className="text-[10px] text-slate-400">{String(data.summary ?? '')}</p>
      {proposals?.slice(0, 6).map((p, i) => (
        <div key={i} className="rounded-lg px-3 py-2.5 space-y-1" style={{ background: 'rgba(255,255,255,0.025)', border: '1px solid rgba(255,255,255,0.05)' }}>
          <div className="flex items-center gap-2 flex-wrap">
            <Pill color="#22d3ee">{String(p.suggestedModel ?? '')}</Pill>
            <span className="text-[10px] font-bold text-slate-300">{String(p.actor ?? '')}</span>
          </div>
          <p className="text-[9px] text-slate-500">{String(p.reasoning ?? '')}</p>
          <div className="flex flex-wrap gap-1">
            {(p.featuresToUse as string[] ?? []).slice(0, 4).map((f, j) => <Pill key={j} color="#a78bfa">{f}</Pill>)}
          </div>
        </div>
      ))}
    </div>
  )
}

function WeeklyPanel({ data, query, events, token }: {
  data: Record<string, unknown>; query: string; events: ThreatEvent[]; token: string | null | undefined
}) {
  const ttps = data.mitreAttackTTPs as Record<string, unknown>[]
  const queries = data.threatHuntingQueries as Record<string, unknown>[]
  const iocs = data.indicatorsOfCompromise as Record<string, unknown>[]

  const importIocs = async () => {
    if (!iocs?.length) return
    const rows = iocs.map(i => ({ ioc: String(i.value ?? ''), type: String(i.type ?? 'URL'), threat_actor: 'Weekly Report', severity: 'high', mitre: '', country: '' }))
    const form = new FormData()
    form.append('raw_text', JSON.stringify(rows))
    form.append('format_hint', 'json')
    await fetch(`${API}/logs/ingest`, { method: 'POST', headers: token ? { Authorization: `Bearer ${token}` } : {}, body: form })
    alert(`${rows.length} IOCs importados a CTI-Lab.`)
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm font-bold text-slate-100">{String(data.reportTitle ?? '')}</p>
          <p className="text-[10px] text-slate-500">{String(data.dateRange ?? '')}</p>
        </div>
        <div className="flex gap-1.5">
          {iocs?.length > 0 && (
            <button onClick={importIocs}
                    className="flex items-center gap-1.5 px-2.5 py-1.5 rounded text-[10px] font-bold"
                    style={{ background: 'rgba(34,211,238,0.08)', color: '#22d3ee', border: '1px solid rgba(34,211,238,0.22)' }}>
              <Shield size={10} /> Importar IOCs
            </button>
          )}
          <button onClick={() => exportReportPdf(query, events, data)}
                  className="flex items-center gap-1.5 px-2.5 py-1.5 rounded text-[10px] font-bold"
                  style={{ background: 'rgba(239,68,68,0.08)', color: '#f87171', border: '1px solid rgba(239,68,68,0.22)' }}>
            <Download size={10} /> PDF
          </button>
        </div>
      </div>

      <p className="text-[10px] text-slate-400 leading-relaxed">{String(data.executiveSummary ?? '')}</p>

      {ttps?.slice(0, 4).map((t, i) => (
        <div key={i} className="rounded-lg p-3 space-y-1.5" style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.05)' }}>
          <p className="text-[9px] font-bold text-violet-500 uppercase">{String(t.tactic ?? '')}</p>
          <div className="flex flex-wrap gap-1">
            {(t.techniques as Record<string, unknown>[] ?? []).map((tech, j) => (
              <span key={j} className="text-[9px] px-2 py-0.5 rounded font-mono" style={{ background: 'rgba(167,139,250,0.08)', color: '#a78bfa' }}>
                {String(tech.id ?? '')} {String(tech.name ?? '')}
              </span>
            ))}
          </div>
        </div>
      ))}

      {queries?.length > 0 && (
        <div className="space-y-2">
          <p className="text-[9px] font-bold text-slate-600 uppercase tracking-wider">Hunting Queries</p>
          {queries.slice(0, 4).map((q, i) => (
            <div key={i} className="rounded-lg p-3 space-y-1" style={{ background: '#050a14', border: '1px solid rgba(255,255,255,0.06)' }}>
              <Pill color="#4ade80">{String(q.platform ?? '')}</Pill>
              <pre className="text-[9px] text-green-400 font-mono whitespace-pre-wrap mt-1">{String(q.query ?? '')}</pre>
              <p className="text-[9px] text-slate-600">{String(q.description ?? '')}</p>
            </div>
          ))}
        </div>
      )}

      {(data.mitigationRecommendations as string[] ?? []).length > 0 && (
        <div className="space-y-1">
          <p className="text-[9px] font-bold text-slate-600 uppercase tracking-wider">Mitigaciones</p>
          {(data.mitigationRecommendations as string[]).map((r, i) => (
            <div key={i} className="flex items-start gap-2 text-[10px] text-slate-400">
              <span className="text-green-500 shrink-0 mt-0.5">✓</span> {r}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function ColombiaPanel({ data }: { data: Record<string, unknown> }) {
  const sectors = data.sectorAssessments as Record<string, unknown>[]
  const RISK_COLOR: Record<string, string> = { High: '#ef4444', Medium: '#f97316', Low: '#facc15', None: '#4ade80' }
  return (
    <div className="space-y-3">
      <p className="text-[10px] text-slate-400 leading-relaxed">{String(data.riskSummary ?? '')}</p>
      <div className="grid grid-cols-1 gap-2">
        {sectors?.map((s, i) => {
          const color = RISK_COLOR[String(s.riskLevel)] ?? '#94a3b8'
          return (
            <div key={i} className="rounded-lg p-3 space-y-1" style={{ background: `${color}07`, border: `1px solid ${color}22` }}>
              <div className="flex items-center gap-2">
                <Pill color={color}>{String(s.riskLevel ?? '')}</Pill>
                <span className="text-xs font-bold text-slate-200">{String(s.sector ?? '')}</span>
              </div>
              <p className="text-[9px] text-slate-500">{String(s.potentialImpact ?? '')}</p>
            </div>
          )
        })}
      </div>
    </div>
  )
}

function GeopoliticalPanel({ data }: { data: Record<string, unknown> }) {
  const events = data.recentEvents as Record<string, unknown>[]
  const threats = data.anticipatoryThreats as Record<string, unknown>[]
  return (
    <div className="space-y-3">
      <div className="flex items-center gap-3">
        <div className="rounded-lg p-3 text-center flex-1" style={{ background: 'rgba(34,211,238,0.06)', border: '1px solid rgba(34,211,238,0.15)' }}>
          <p className="text-2xl font-black text-cyan-400">{Number(data.regionalStabilityScore ?? 0).toFixed(1)}</p>
          <p className="text-[9px] text-slate-600 uppercase">Score de Estabilidad</p>
        </div>
        <p className="text-[10px] text-slate-400 flex-1 leading-relaxed">{String(data.summary ?? '')}</p>
      </div>
      {events?.slice(0, 4).map((ev, i) => (
        <div key={i} className="rounded-lg p-3 space-y-0.5" style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.05)' }}>
          <div className="flex items-center gap-2">
            <span className="text-[9px] font-mono text-slate-600">{String(ev.date ?? '')}</span>
          </div>
          <p className="text-[10px] text-slate-300">{String(ev.event ?? '')}</p>
          <p className="text-[9px] text-slate-500">{String(ev.impactOnCybersecurity ?? '')}</p>
        </div>
      ))}
      {threats?.slice(0, 3).map((t, i) => (
        <div key={i} className="rounded-lg px-3 py-2 space-y-0.5" style={{ background: 'rgba(250,204,21,0.05)', border: '1px solid rgba(250,204,21,0.12)' }}>
          <div className="flex items-center gap-2">
            <Pill color={t.probability === 'High' ? '#ef4444' : t.probability === 'Medium' ? '#f97316' : '#4ade80'}>{String(t.probability ?? '')}</Pill>
            <span className="text-[10px] text-slate-300">{String(t.threat ?? '')}</span>
          </div>
          <p className="text-[9px] text-slate-600">{String(t.estimatedTimeframe ?? '')} · {String(t.mitigationStrategy ?? '')}</p>
        </div>
      ))}
    </div>
  )
}

// ── Threat Graph Panel (Actor → IOC → Campaign) ────────────────────────────────

const RISK_COLOR_MAP: Record<string, string> = {
  Critical: '#ef4444', High: '#f97316', Medium: '#facc15', Low: '#4ade80',
}

function ActorGraphNode({ data }: NodeProps) {
  const color = (data.riskColor as string) || RISK_COLOR_MAP[data.risk as string] || '#94a3b8'
  return (
    <div style={{ background: 'rgba(30,10,40,0.97)', border: `1.5px solid ${color}`, borderRadius: 10, padding: '8px 12px', minWidth: 155, maxWidth: 195, boxShadow: `0 0 14px ${color}28` }}>
      <Handle type="source" position={Position.Right} style={{ background: color }} />
      <div style={{ display: 'flex', alignItems: 'center', gap: 5, marginBottom: 4, flexWrap: 'wrap' }}>
        <span style={{ fontSize: 7, fontWeight: 700, color, background: `${color}18`, border: `1px solid ${color}30`, borderRadius: 4, padding: '1px 5px' }}>{String(data.risk ?? 'N/A')}</span>
        {data.cisaMatch && <span style={{ fontSize: 7, fontWeight: 700, color: '#22d3ee', background: 'rgba(34,211,238,0.1)', border: '1px solid rgba(34,211,238,0.25)', borderRadius: 4, padding: '1px 5px' }}>✓ CISA</span>}
      </div>
      <div style={{ fontWeight: 700, fontSize: 12, color: '#e2e8f0', marginBottom: 2 }}>{String(data.label ?? '')}</div>
      <div style={{ fontSize: 9, color: '#64748b' }}>{String(data.country ?? '')}</div>
      {(data.cisaAdvisories as string[] | undefined)?.length ? (
        <div style={{ fontSize: 7, color: '#22d3ee', marginTop: 3 }}>{(data.cisaAdvisories as string[]).slice(0, 2).join(' · ')}</div>
      ) : null}
      <div style={{ marginTop: 3, fontSize: 8, color: '#94a3b8' }}>{Number(data.eventCount ?? 0)} evento{Number(data.eventCount) !== 1 ? 's' : ''}</div>
    </div>
  )
}

function CampaignGraphNode({ data }: NodeProps) {
  return (
    <div style={{ background: 'rgba(20,15,40,0.97)', border: '1.5px solid rgba(167,139,250,0.45)', borderRadius: 9, padding: '7px 12px', minWidth: 145, maxWidth: 185, boxShadow: '0 0 10px rgba(167,139,250,0.1)' }}>
      <Handle type="target" position={Position.Left} style={{ background: '#a78bfa' }} />
      <Handle type="source" position={Position.Right} style={{ background: '#a78bfa' }} />
      <div style={{ fontSize: 7, color: '#a78bfa', fontWeight: 700, textTransform: 'uppercase', marginBottom: 3 }}>Campaña</div>
      <div style={{ fontSize: 11, color: '#ddd6fe', fontWeight: 600 }}>{String(data.label ?? '')}</div>
      {data.timeframe ? <div style={{ fontSize: 8, color: '#64748b', marginTop: 2 }}>{String(data.timeframe)}</div> : null}
    </div>
  )
}

function IocGraphNode({ data }: NodeProps) {
  return (
    <div style={{ background: 'rgba(5,18,42,0.97)', border: '1px solid rgba(34,211,238,0.35)', borderRadius: 7, padding: '5px 10px', minWidth: 125, maxWidth: 175 }}>
      <Handle type="target" position={Position.Left} style={{ background: '#22d3ee' }} />
      <div style={{ fontSize: 8, color: '#22d3ee', fontWeight: 700, marginBottom: 2 }}>IOC</div>
      <div style={{ fontFamily: 'monospace', fontSize: 9, color: '#67e8f9', wordBreak: 'break-all' }}>{String(data.label ?? '')}</div>
      {(data.usedBy as string[] | undefined)?.length ? (
        <div style={{ fontSize: 7, color: '#475569', marginTop: 3 }}>
          {(data.usedBy as string[]).slice(0, 2).join(', ')}
        </div>
      ) : null}
    </div>
  )
}

const GRAPH_NODE_TYPES = { actor: ActorGraphNode, campaign: CampaignGraphNode, ioc: IocGraphNode }

function ThreatGraphPanel({ data }: { data: Record<string, unknown> }) {
  const nodes = (data.nodes as Record<string, unknown>[] | undefined) ?? []
  const edges = (data.edges as Record<string, unknown>[] | undefined) ?? []
  const correlations = (data.crossCorrelations as Record<string, unknown>[] | undefined) ?? []

  return (
    <div className="space-y-3">
      {/* Stats bar */}
      <div className="grid grid-cols-4 gap-2">
        {(
          [
            { label: 'Actores',   val: Number(data.totalActors   ?? 0), color: '#a855f7' },
            { label: 'IOCs',      val: Number(data.totalIocs     ?? 0), color: '#22d3ee' },
            { label: 'Campañas',  val: Number(data.totalCampaigns?? 0), color: '#a78bfa' },
            { label: '✓ CISA',    val: Number(data.cisaMatchCount?? 0), color: '#4ade80' },
          ] as { label: string; val: number; color: string }[]
        ).map(s => (
          <div key={s.label} className="rounded-lg p-2 text-center" style={{ background: `${s.color}09`, border: `1px solid ${s.color}22` }}>
            <p className="text-lg font-black" style={{ color: s.color }}>{s.val}</p>
            <p className="text-[8px] text-slate-600 uppercase tracking-wider">{s.label}</p>
          </div>
        ))}
      </div>

      {/* Summary */}
      {data.summary ? (
        <div className="rounded-lg p-3 text-[10px] text-slate-400 leading-relaxed" style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.05)' }}>
          {String(data.summary)}
        </div>
      ) : null}

      {/* ReactFlow graph */}
      <div className="rounded-xl overflow-hidden" style={{ border: '1px solid rgba(255,255,255,0.06)', height: 420 }}>
        <ReactFlow
          nodes={nodes as Parameters<typeof ReactFlow>[0]['nodes']}
          edges={edges as Parameters<typeof ReactFlow>[0]['edges']}
          nodeTypes={GRAPH_NODE_TYPES}
          fitView
          fitViewOptions={{ padding: 0.15 }}
          minZoom={0.25}
          maxZoom={2}
        >
          <Background color="#1e293b" gap={18} />
          <Controls style={{ background: 'rgba(15,23,42,0.9)', border: '1px solid rgba(255,255,255,0.07)', borderRadius: 8 }} />
          <MiniMap
            style={{ background: 'rgba(5,10,20,0.9)', border: '1px solid rgba(255,255,255,0.07)' }}
            nodeColor={(n) => n.type === 'actor' ? '#a855f7' : n.type === 'campaign' ? '#a78bfa' : '#22d3ee'}
          />
        </ReactFlow>
      </div>

      {/* Legend */}
      <div className="flex flex-wrap gap-3">
        {[
          { color: '#a855f7', label: 'Actor / APT' },
          { color: '#a78bfa', label: 'Campaña' },
          { color: '#22d3ee', label: 'IOC' },
          { color: '#4ade80', label: 'Verificado CISA' },
        ].map(l => (
          <div key={l.label} className="flex items-center gap-1.5 text-[9px] text-slate-500">
            <span className="w-2 h-2 rounded-full shrink-0" style={{ background: l.color }} />
            {l.label}
          </div>
        ))}
        <span className="text-[9px] text-slate-700 ml-auto">Fuente: CISA Known APT Groups · MITRE ATT&CK</span>
      </div>

      {/* Cross-actor correlations */}
      {correlations.length > 0 && (
        <div className="space-y-2">
          <p className="text-[9px] font-bold text-slate-600 uppercase tracking-wider">Correlaciones cruzadas</p>
          {correlations.map((c, i) => (
            <div key={i} className="rounded-lg px-3 py-2 space-y-0.5" style={{ background: 'rgba(239,68,68,0.04)', border: '1px solid rgba(239,68,68,0.12)' }}>
              <div className="flex items-center gap-2 flex-wrap">
                {(c.actors as string[] | undefined)?.map((a, j) => (
                  <span key={j} className="text-[9px] font-bold text-red-400">{a}</span>
                ))}
                <span className="text-[9px] text-slate-600">·</span>
                <span className="text-[9px] text-orange-400">{String(c.relationship ?? '')}</span>
              </div>
              <p className="text-[9px] text-slate-500">{String(c.evidence ?? '')}</p>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// ── Main component ─────────────────────────────────────────────────────────────

export default function FusionEngine() {
  const { token, user } = useAuth()
  const isAdmin = user?.role === 'admin'

  // Query state
  const [query, setQuery] = useState('')
  const [mode, setMode] = useState<'simple' | 'text'>('simple')
  const [isAnnual, setIsAnnual] = useState(false)

  // Results state
  const [loading, setLoading]     = useState(false)
  const [error, setError]         = useState('')
  const [events, setEvents]       = useState<ThreatEvent[]>([])
  const [sectorInfo, setSectorInfo] = useState('')
  const [page, setPage]           = useState(0)
  const PAGE_SIZE = 20

  // Gemini status
  const [geminiOk, setGeminiOk] = useState<boolean | null>(null)

  // Sub-analyses
  const [subOpen, setSubOpen]     = useState<Partial<Record<SubKey, boolean>>>({})
  const [subLoading, setSubLoading] = useState<Partial<Record<SubKey, boolean>>>({})
  const [subData, setSubData]     = useState<Partial<Record<SubKey, Record<string, unknown>>>>({})
  const [subError, setSubError]   = useState<Partial<Record<SubKey, string>>>({})

  // Table filter
  const [filterSev, setFilterSev] = useState('')
  const [filterActor, setFilterActor] = useState('')

  // Import state
  const [importing, setImporting] = useState(false)

  useEffect(() => {
    if (!token) return
    fetch(`${API}/ai/gemini/status`, {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then(r => readApiJson<{ configured?: boolean }>(r))
      .then(d => setGeminiOk(Boolean(d.configured)))
      .catch(() => setGeminiOk(false))
  }, [token])

  // ── Generate events ────────────────────────────────────────────────────────

  const generate = useCallback(async () => {
    const q = query.trim()
    if (!q) { setError('Escribe un actor, sector o amenaza.'); return }
    setError(''); setLoading(true); setEvents([]); setSectorInfo(''); setPage(0)
    setSubData({}); setSubOpen({})
    try {
      const res = await fetch(`${API}/ai/gemini/threat-data`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
        body: JSON.stringify({ topic: q, is_annual: isAnnual }),
      })
      const data = await readApiJson<{ detail?: string; threats?: ThreatEvent[]; sector_analysis?: string }>(res)
      if (res.status === 402) throw new Error(
        isAdmin
          ? '💳 ' + (data.detail ?? 'Créditos agotados. Ve a console.anthropic.com → Plans & Billing.')
          : 'El motor CTI no está disponible en este momento. Contacta al administrador.'
      )
      if (!res.ok) throw new Error(
        isAdmin ? (data.detail ?? 'Error generando eventos.') : 'El motor CTI no está disponible en este momento.'
      )
      setEvents(data.threats ?? [])
      if (data.sector_analysis) setSectorInfo(data.sector_analysis)
    } catch (e) {
      setError(String(e instanceof Error ? e.message : e))
    } finally {
      setLoading(false)
    }
  }, [query, isAnnual, token])

  // ── Sub-analyses ───────────────────────────────────────────────────────────

  const runSubAnalysis = useCallback(async (key: SubKey) => {
    if (subData[key]) { setSubOpen(p => ({ ...p, [key]: !p[key] })); return }
    setSubOpen(p => ({ ...p, [key]: true }))
    setSubLoading(p => ({ ...p, [key]: true }))
    setSubError(p => ({ ...p, [key]: '' }))
    const actors = [...new Set(events.map(e => e.threatActor).filter(Boolean))].slice(0, 3)
    const ttps = [...new Set(events.map(e => e.mitreTechniqueId).filter(Boolean))].slice(0, 8)
    const topActor = actors[0] ?? query

    const endpoints: Record<SubKey, [string, Record<string, unknown>]> = {
      predictive:   ['/ai/gemini/predictive',   { threats: events.slice(0, 30), query }],
      quantum:      ['/ai/gemini/quantum',       { actor: topActor, events: events.slice(0, 10) }],
      geopolitical: ['/ai/gemini/geopolitical',  { query }],
      scenarios:    ['/ai/gemini/team-scenarios',{ actor: topActor, ttps }],
      ml:           ['/ai/gemini/ml-proposals',  { events: events.slice(0, 20) }],
      weekly:       ['/ai/gemini/weekly-report', { query, events: events.slice(0, 10) }],
      colombia:     ['/ai/gemini/colombia-risk', { actor: topActor, events: events.slice(0, 10) }],
      graph:        ['/ai/gemini/threat-graph',  { events: events.slice(0, 40), query }],
    }

    const [path, body] = endpoints[key]
    try {
      const res = await fetch(`${API}${path}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
        body: JSON.stringify(body),
      })
      const data = await readApiJson<Record<string, unknown> & { detail?: string }>(res)
      if (!res.ok) throw new Error(
        res.status === 402
          ? (isAdmin ? '💳 ' + (data.detail ?? 'Créditos agotados.') : 'Motor CTI no disponible. Contacta al administrador.')
          : (isAdmin ? (data.detail ?? 'Error') : 'Motor CTI no disponible en este momento.')
      )
      setSubData(p => ({ ...p, [key]: data }))
    } catch (e) {
      setSubError(p => ({ ...p, [key]: String(e instanceof Error ? e.message : e) }))
    } finally {
      setSubLoading(p => ({ ...p, [key]: false }))
    }
  }, [events, query, token])

  // ── Import IOCs to CTI-Lab ─────────────────────────────────────────────────

  const importIocs = useCallback(async () => {
    if (!events.length) return
    setImporting(true)
    const rows = events.filter(e => e.ioc && e.ioc !== 'N/A').map(e => ({
      ioc: e.ioc, type: 'unknown', threat_actor: e.threatActor, severity: e.severity?.toLowerCase() ?? 'medium', mitre: e.mitreTechniqueId, country: e.sourceCountry, source: 'fusion-engine'
    }))
    const form = new FormData()
    form.append('raw_text', JSON.stringify(rows))
    form.append('format_hint', 'json')
    form.append('dataset_name', `Fusión — ${query.slice(0, 60)}`)
    if (isAdmin) form.append('save_dataset', 'true')
    try {
      const res = await fetch(`${API}/logs/ingest`, { method: 'POST', headers: token ? { Authorization: `Bearer ${token}` } : {}, body: form })
      const d = await readApiJson<{ iocs_added?: number; dataset_id?: number }>(res)
      alert(`✓ ${d.iocs_added} IOCs importados a CTI-Lab${d.dataset_id ? ` · Dataset #${d.dataset_id} creado` : ''}.`)
    } catch { alert('Error al importar IOCs.') }
    finally { setImporting(false) }
  }, [events, query, token, isAdmin])

  // ── Filtered events ────────────────────────────────────────────────────────

  const filtered = useMemo(() =>
    events.filter(e =>
      (!filterSev   || e.severity?.toLowerCase() === filterSev) &&
      (!filterActor || e.threatActor?.toLowerCase().includes(filterActor.toLowerCase()))
    ), [events, filterSev, filterActor])

  const paginated = filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE)
  const totalPages = Math.ceil(filtered.length / PAGE_SIZE)

  const stats = useMemo(() => {
    if (!events.length) return null
    const critical = events.filter(e => e.severity === 'Critical').length
    const actors = [...new Set(events.map(e => e.threatActor))].filter(a => a && a !== 'Unknown')
    const topActor = actors.length ? actors.reduce((best, a) => {
      const ca = events.filter(e => e.threatActor === a).length
      const cb = events.filter(e => e.threatActor === best).length
      return ca > cb ? a : best
    }, actors[0]) : '—'
    const avgConf = events.reduce((s, e) => s + (Number(e.confidenceScore) || 0), 0) / events.length
    return { total: events.length, critical, topActor, actors: actors.length, avgConf: Math.round(avgConf) }
  }, [events])

  // ── Render ─────────────────────────────────────────────────────────────────

  return (
    <div className="h-full overflow-y-auto p-6 space-y-5">

      {/* ── Header ──────────────────────────────────────────────────────────── */}
      <div className="flex items-start justify-between gap-4">
        <div className="flex items-start gap-3">
          <div className="w-10 h-10 rounded-xl flex items-center justify-center shrink-0"
               style={{ background: 'rgba(239,68,68,0.12)', border: '1px solid rgba(239,68,68,0.25)', boxShadow: '0 0 20px rgba(239,68,68,0.15)' }}>
            <Shield size={18} className="text-red-400" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-xl font-bold text-slate-100">Motor de Fusión de Amenazas</h1>
              <span className="text-[9px] font-black px-2 py-0.5 rounded-full"
                    style={{ background: 'rgba(239,68,68,0.1)', color: '#f87171', border: '1px solid rgba(239,68,68,0.25)' }}>
                RedCiber × CTI-Lab
              </span>
            </div>
            <p className="text-xs text-slate-500 mt-0.5">
              Extractor CTI · Fusión masiva de inteligencia · Escenarios tácticos y análisis predictivo
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {geminiOk !== null && (isAdmin || geminiOk) && (
            <div className="flex items-center gap-1.5 text-[10px] px-2.5 py-1 rounded-lg"
                 style={geminiOk
                   ? { background: 'rgba(74,222,128,0.07)', color: '#4ade80', border: '1px solid rgba(74,222,128,0.2)' }
                   : { background: 'rgba(239,68,68,0.07)', color: '#f87171', border: '1px solid rgba(239,68,68,0.2)' }}>
              <span className="w-1.5 h-1.5 rounded-full animate-pulse"
                    style={{ background: geminiOk ? '#4ade80' : '#ef4444' }} />
              {geminiOk ? 'Motor CTI activo' : 'Motor CTI inactivo · configura API key'}
            </div>
          )}
        </div>
      </div>

      {/* ── Query bar ───────────────────────────────────────────────────────── */}
      <div className="rounded-xl p-5 space-y-4" style={glassRed}>
        {/* Mode toggle */}
        <div className="flex items-center gap-2">
          {(['simple', 'text'] as const).map(m => (
            <button key={m} onClick={() => setMode(m)}
                    className="px-3 py-1 rounded text-[10px] font-bold transition-colors"
                    style={mode === m
                      ? { background: 'rgba(239,68,68,0.15)', color: '#f87171', border: '1px solid rgba(239,68,68,0.3)' }
                      : { color: '#64748b', border: '1px solid transparent' }}>
              {m === 'simple' ? 'Consulta Táctica' : 'Ingesta de Texto'}
            </button>
          ))}
          <span className="text-[10px] text-slate-600 ml-2">
            {mode === 'simple' ? 'Describe un actor, sector o amenaza' : 'Pega un reporte o log sin procesar'}
          </span>
        </div>

        {/* Input */}
        {mode === 'simple' ? (
          <div className="relative">
            <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-600" />
            <input value={query} onChange={e => setQuery(e.target.value)}
                   onKeyDown={e => e.key === 'Enter' && generate()}
                   placeholder="APT29, Lazarus Group, ransomware Colombia, sector financiero LATAM..."
                   className="w-full rounded-lg pl-9 pr-4 py-2.5 text-sm text-slate-200 outline-none"
                   style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)' }} />
          </div>
        ) : (
          <textarea value={query} onChange={e => setQuery(e.target.value)}
                    placeholder="Pega aquí un informe de incidente, log de SIEM, reporte de amenazas o texto libre..."
                    rows={5} spellCheck={false}
                    className="w-full rounded-lg px-3 py-2.5 text-sm text-slate-200 outline-none resize-none font-mono"
                    style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)' }} />
        )}

        <div className="flex items-center gap-3 flex-wrap">
          {/* Annual toggle */}
          <label className="flex items-center gap-2 cursor-pointer">
            <button onClick={() => setIsAnnual(v => !v)}
                    className="w-8 h-4 rounded-full transition-colors relative"
                    style={{ background: isAnnual ? 'rgba(239,68,68,0.5)' : 'rgba(255,255,255,0.1)' }}>
              <span className="absolute top-0.5 w-3 h-3 rounded-full bg-white transition-all"
                    style={{ left: isAnnual ? '50%' : '2px' }} />
            </button>
            <span className="text-[10px] text-slate-500">
              {isAnnual ? '500 eventos · 2020–2026 (anual)' : '60 eventos · últimos 7 días (operativo)'}
            </span>
          </label>

          <div className="flex-1" />

          {error && <p className="text-[10px] text-red-400">{error}</p>}

          {!geminiOk && isAdmin && (
            <p className="text-[10px] text-yellow-600 flex items-center gap-1">
              <AlertCircle size={10} /> Motor CTI no activo — configura ANTHROPIC_API_KEY o GEMINI_API_KEY en el .env
            </p>
          )}

          <button onClick={generate} disabled={loading || !query.trim() || geminiOk === false}
                  className="flex items-center gap-2 px-5 py-2 rounded-lg text-sm font-bold disabled:opacity-40 transition-all"
                  style={{ background: 'rgba(239,68,68,0.15)', border: '1px solid rgba(239,68,68,0.35)', color: '#f87171' }}>
            {loading ? <><Spinner color="#f87171" /> Extrayendo inteligencia...</> : <><Zap size={14} /> Iniciar fusión CTI</>}
          </button>
        </div>
      </div>

      {/* ── Results ─────────────────────────────────────────────────────────── */}
      {events.length > 0 && stats && (
        <>
          {/* Stats row */}
          <div className="grid grid-cols-2 xl:grid-cols-4 gap-3">
            {[
              { label: 'Eventos',      val: stats.total,           color: '#22d3ee' },
              { label: 'Críticos',     val: stats.critical,        color: '#ef4444' },
              { label: 'Actores únicos',val: stats.actors,          color: '#a78bfa' },
              { label: 'Conf. media',  val: `${stats.avgConf}%`,   color: '#4ade80' },
            ].map(s => (
              <div key={s.label} className="rounded-xl p-4 text-center" style={glass}>
                <p className="text-2xl font-black" style={{ color: s.color }}>{s.val}</p>
                <p className="text-[9px] text-slate-600 uppercase tracking-wider mt-0.5">{s.label}</p>
              </div>
            ))}
          </div>

          {sectorInfo && (() => {
            try { const p = JSON.parse(sectorInfo); return (
              <div className="rounded-xl p-3 flex items-center gap-4 flex-wrap" style={{ ...glass, border: '1px solid rgba(239,68,68,0.15)' }}>
                <Pill color="#ef4444">{p.regressionTrend}</Pill>
                <Pill color="#f97316">Sector: {p.topPostulatedSector}</Pill>
                <Pill color="#facc15">Confianza: {p.confidenceScore}%</Pill>
                {p.multiActorCorrelation && <span className="text-[10px] text-slate-500 flex-1">{p.multiActorCorrelation}</span>}
              </div>
            )} catch { return null }
          })()}

          <IntelVisibilityDashboard events={events} query={query} />

          {/* Charts */}
          <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
            <div className="rounded-xl p-4 space-y-2" style={glass}>
              <p className="text-[9px] font-bold text-slate-600 uppercase tracking-wider">Distribución de Severidad</p>
              <SeverityPie events={events} />
            </div>
            <div className="rounded-xl p-4 space-y-2" style={glass}>
              <p className="text-[9px] font-bold text-slate-600 uppercase tracking-wider">Top Tácticas MITRE</p>
              <TacticBar events={events} />
            </div>
            <div className="rounded-xl p-4 space-y-2" style={glass}>
              <p className="text-[9px] font-bold text-slate-600 uppercase tracking-wider">Top Actores</p>
              <ActorBar events={events} />
            </div>
          </div>

          {/* Events table */}
          <div className="rounded-xl overflow-hidden" style={glass}>
            <div className="flex items-center gap-3 px-4 py-3 border-b flex-wrap" style={{ borderColor: 'rgba(255,255,255,0.06)', background: 'rgba(0,0,0,0.2)' }}>
              <p className="text-xs font-bold text-slate-300">Eventos generados</p>
              <span className="text-[10px] text-slate-600">{filtered.length} / {events.length}</span>
              <div className="flex-1" />
              {/* Filters */}
              <select value={filterSev} onChange={e => { setFilterSev(e.target.value); setPage(0) }}
                      className="rounded px-2 py-1 text-[10px] outline-none"
                      style={{ background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)', color: '#cbd5e1' }}>
                <option value="">Todas las severidades</option>
                {['Critical','High','Medium','Low'].map(s => <option key={s} value={s.toLowerCase()}>{s}</option>)}
              </select>
              <input value={filterActor} onChange={e => { setFilterActor(e.target.value); setPage(0) }}
                     placeholder="Filtrar actor..."
                     className="rounded px-2 py-1 text-[10px] outline-none w-32"
                     style={{ background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)', color: '#cbd5e1' }} />
              {/* Export buttons */}
              <button onClick={() => exportEventsXlsx(filtered)}
                      className="flex items-center gap-1.5 px-2.5 py-1.5 rounded text-[10px] font-bold"
                      style={{ background: 'rgba(74,222,128,0.08)', color: '#4ade80', border: '1px solid rgba(74,222,128,0.22)' }}>
                <Download size={10} /> XLSX
              </button>
              <button onClick={() => exportEventsCsv(query, filtered)}
                      className="flex items-center gap-1.5 px-2.5 py-1.5 rounded text-[10px] font-bold"
                      style={{ background: 'rgba(250,204,21,0.08)', color: '#facc15', border: '1px solid rgba(250,204,21,0.22)' }}>
                <Download size={10} /> CSV
              </button>
              <button onClick={() => exportEventsJson(query, filtered)}
                      className="flex items-center gap-1.5 px-2.5 py-1.5 rounded text-[10px] font-bold"
                      style={{ background: 'rgba(167,139,250,0.08)', color: '#a78bfa', border: '1px solid rgba(167,139,250,0.22)' }}>
                <Download size={10} /> JSON
              </button>
              <button onClick={importIocs} disabled={importing}
                      className="flex items-center gap-1.5 px-2.5 py-1.5 rounded text-[10px] font-bold disabled:opacity-40"
                      style={{ background: 'rgba(34,211,238,0.08)', color: '#22d3ee', border: '1px solid rgba(34,211,238,0.22)' }}>
                <Shield size={10} /> {importing ? 'Importando...' : 'IOCs → CTI-Lab'}
              </button>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-[9px]">
                <thead>
                  <tr style={{ background: 'rgba(255,255,255,0.025)' }}>
                    {['Timestamp','Actor','Táctica','Severidad','IOC','Malware','País Origen','Conf.'].map(h => (
                      <th key={h} className="px-3 py-2 text-left text-slate-600 font-bold uppercase tracking-wide whitespace-nowrap">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/[0.03]">
                  {paginated.map((ev, i) => {
                    const sc = SEV_COLOR[ev.severity] ?? '#94a3b8'
                    return (
                      <tr key={i} className="hover:bg-white/[0.02]">
                        <td className="px-3 py-1.5 font-mono text-slate-600 whitespace-nowrap">{(ev.timestamp ?? '').slice(0, 16)}</td>
                        <td className="px-3 py-1.5 text-slate-300 max-w-32 truncate">{ev.threatActor}</td>
                        <td className="px-3 py-1.5 text-violet-400 whitespace-nowrap">{ev.mitreTactic}</td>
                        <td className="px-3 py-1.5"><span className="px-1.5 py-0.5 rounded font-bold" style={{ color: sc, background: `${sc}16` }}>{ev.severity}</span></td>
                        <td className="px-3 py-1.5 font-mono text-cyan-400 max-w-36 truncate">{ev.ioc || '—'}</td>
                        <td className="px-3 py-1.5 text-orange-400 max-w-32 truncate">{ev.malware || '—'}</td>
                        <td className="px-3 py-1.5 text-slate-500">{ev.sourceCountry}</td>
                        <td className="px-3 py-1.5 text-green-400">{ev.confidenceScore ? `${ev.confidenceScore}%` : '—'}</td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>

            {totalPages > 1 && (
              <div className="flex items-center justify-between px-4 py-2.5 border-t" style={{ borderColor: 'rgba(255,255,255,0.06)' }}>
                <button onClick={() => setPage(p => Math.max(0, p - 1))} disabled={page === 0}
                        className="text-[10px] text-slate-500 hover:text-slate-300 disabled:opacity-30">← Anterior</button>
                <span className="text-[10px] text-slate-600">{page + 1} / {totalPages}</span>
                <button onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))} disabled={page === totalPages - 1}
                        className="text-[10px] text-slate-500 hover:text-slate-300 disabled:opacity-30">Siguiente →</button>
              </div>
            )}
          </div>

          {/* Sub-analysis buttons */}
          <div>
            <p className="text-[9px] font-bold text-slate-600 uppercase tracking-wider mb-3">Análisis adicionales</p>
            <div className="grid grid-cols-2 xl:grid-cols-4 gap-2">
              {SUB_ANALYSES.map(({ key, label, icon, desc }) => {
                const isLoading = subLoading[key]
                const isDone = Boolean(subData[key])
                const isOpen = subOpen[key]
                return (
                  <button key={key} onClick={() => runSubAnalysis(key)}
                          className="flex flex-col items-start gap-1 rounded-xl p-3 text-left transition-all hover:bg-white/[0.04]"
                          style={{
                            ...glass,
                            border: isDone ? '1px solid rgba(239,68,68,0.3)' : '1px solid rgba(255,255,255,0.06)',
                            background: isOpen && isDone ? 'rgba(239,68,68,0.05)' : 'rgba(15,23,42,0.55)',
                          }}>
                    <div className="flex items-center gap-1.5 w-full">
                      <span style={{ color: isDone ? '#f87171' : '#64748b' }}>{icon}</span>
                      <span className="text-[10px] font-bold flex-1" style={{ color: isDone ? '#f87171' : '#94a3b8' }}>{label}</span>
                      {isLoading && <Spinner color="#f87171" />}
                      {isDone && !isLoading && (isOpen ? <ChevronDown size={10} className="text-red-400" /> : <ChevronRight size={10} className="text-red-400" />)}
                    </div>
                    <p className="text-[9px] text-slate-600">{desc}</p>
                  </button>
                )
              })}
            </div>
          </div>

          {/* Sub-analysis results */}
          <div className="space-y-3">
            {SUB_ANALYSES.map(({ key, label, icon }) => {
              if (!subOpen[key]) return null
              const data = subData[key]
              const err = subError[key]
              const isLoading = subLoading[key]
              return (
                <Section key={key} title={label} icon={icon}
                         open={subOpen[key] ?? false}
                         onToggle={() => setSubOpen(p => ({ ...p, [key]: !p[key] }))}
                         accent="#ef4444">
                  {isLoading && (
                    <div className="flex items-center gap-3 py-4">
                      <Spinner color="#f87171" />
                      <span className="text-xs text-slate-500">Procesando análisis CTI...</span>
                    </div>
                  )}
                  {err && <p className="text-[11px] text-red-400">{err}</p>}
                  {data && !isLoading && (
                    key === 'predictive'   ? <PredictivePanel data={data} /> :
                    key === 'quantum'      ? <QuantumPanel data={data} /> :
                    key === 'scenarios'    ? <ScenariosPanel data={data} /> :
                    key === 'ml'           ? <MLPanel data={data} /> :
                    key === 'weekly'       ? <WeeklyPanel data={data} query={query} events={events} token={token} /> :
                    key === 'colombia'     ? <ColombiaPanel data={data} /> :
                    key === 'geopolitical' ? <GeopoliticalPanel data={data} /> :
                    key === 'graph'        ? <ThreatGraphPanel data={data} /> :
                    <pre className="text-[9px] text-slate-400 font-mono overflow-auto max-h-64">{JSON.stringify(data, null, 2)}</pre>
                  )}
                </Section>
              )
            })}
          </div>
        </>
      )}

      {/* ── Empty state ──────────────────────────────────────────────────────── */}
      {!loading && events.length === 0 && (
        <div className="rounded-xl p-12 text-center space-y-3" style={glass}>
          <div className="w-14 h-14 rounded-2xl mx-auto flex items-center justify-center"
               style={{ background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.15)' }}>
            <Shield size={24} className="text-red-500 opacity-50" />
          </div>
          <p className="text-slate-500 text-sm">Escribe una consulta para iniciar el Motor de Fusión</p>
          <div className="flex flex-wrap gap-2 justify-center">
            {['APT29 Cozy Bear', 'LockBit Colombia', 'Lazarus Group fintech LATAM', 'ransomware sector energético'].map(s => (
              <button key={s} onClick={() => setQuery(s)}
                      className="text-[10px] px-3 py-1.5 rounded-lg"
                      style={{ background: 'rgba(239,68,68,0.07)', color: '#f87171', border: '1px solid rgba(239,68,68,0.18)' }}>
                {s}
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

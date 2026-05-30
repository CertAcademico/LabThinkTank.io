import { useState, useEffect, useRef } from 'react'
import { useAuth } from '../contexts/AuthContext'
import HelpBot from './HelpBot'
import type { PyodideInterface } from '../types/pyodide'

const API = import.meta.env.VITE_API_URL ?? 'http://127.0.0.1:8000'

// ── Types ─────────────────────────────────────────────────────────────────────

interface Challenge {
  id: number; title: string; description: string; objective: string
  criteria: string; hints_json?: string; starts_at?: string; deadline?: string; stage?: string; status: string; difficulty?: string
  dataset_name?: string; schema_json?: string
  badge_id?: number; badge_name?: string; badge_org?: string
  badge_tier?: string; badge_icon?: string; min_score_badge?: number
  badge_earned?: number
  submitted: number; my_score?: number
}

interface SolvedChallenge {
  id: number; title: string; stage?: string; difficulty?: string
  score?: number; feedback?: string; submitted_at: string; badge_name?: string; badge_tier?: string
}

const TIER_COLOR: Record<string, string> = {
  bronze: '#cd7f32', silver: '#c0c0c0', gold: '#ffd700',
  platinum: '#e5e4e2', diamond: '#b9f2ff',
}

const DIFF_COLOR: Record<string, string> = {
  básico: '#4ade80', intermedio: '#facc15', avanzado: '#f97316', experto: '#ef4444',
}

interface OutputPart { type: 'text' | 'plot'; content: string }

// ── Helpers ───────────────────────────────────────────────────────────────────

const glass = { background: 'rgba(15,23,42,0.55)', border: '1px solid rgba(255,255,255,0.07)', borderRadius: 12 }

function parseOutput(raw: string): OutputPart[] {
  return raw.split(/(__PLOT__:[A-Za-z0-9+/=]+)/).map(p => ({
    type: (p.startsWith('__PLOT__:') ? 'plot' : 'text') as 'text' | 'plot',
    content: p.startsWith('__PLOT__:') ? p.slice(9) : p,
  })).filter(p => p.content)
}

// ── Dataset Diagram ───────────────────────────────────────────────────────────

function DatasetDiagram({ schema, name }: { schema: Record<string, string>; name: string }) {
  const TYPE_COLOR: Record<string, string> = {
    str: '#22d3ee', int: '#4ade80', float: '#f97316',
    bool: '#a78bfa', object: '#facc15', string: '#22d3ee',
  }
  const CTI_USE: Record<string, string> = {
    ip:          'Indicador de Compromiso (IOC) — se cruza con listas de reputación',
    src_ip:      'IP origen — analiza si pertenece a infraestructura C2 conocida',
    dst_ip:      'IP destino — verifica contra feeds de amenazas (AbuseIPDB, VirusTotal)',
    port:        'Puerto de comunicación — identifica protocolos no estándar (ej: 4444 = C2)',
    proto:       'Protocolo de red — detecta tunelización DNS o beaconing HTTP',
    action:      'Acción del firewall — correlaciona BLOCKs con alertas del SIEM',
    timestamp:   'Marca de tiempo — crucial para timeline de ataque y kill chain',
    severity:    'Nivel de riesgo — prioriza triage en SOC',
    bytes:       'Volumen de datos — anomalías pueden indicar exfiltración',
    ioc:         'Indicador — enriquece con threat intelligence feeds',
    hash:        'Hash de archivo — busca en VirusTotal para clasificar como malware',
    domain:      'Dominio — verifica antigüedad WHOIS y passive DNS',
    mitre:       'Técnica ATT&CK — mapea el comportamiento al kill chain',
    type:        'Tipo de IOC — determina el motor de análisis correcto',
    country:     'País de origen — aplica reglas geopolíticas de bloqueo',
    threat_actor:'Grupo APT — consulta perfil en MITRE ATT&CK o Mandiant',
  }

  const entries = Object.entries(schema)
  if (entries.length === 0) return null

  return (
    <div className="rounded-xl p-4 space-y-3" style={glass}>
      <div className="flex items-center gap-2">
        <svg viewBox="0 0 24 24" className="w-4 h-4 text-cyan-400" fill="none" stroke="currentColor" strokeWidth="2">
          <rect x="3" y="3" width="18" height="18" rx="2" />
          <path d="M3 9h18M3 15h18M9 3v18" />
        </svg>
        <p className="text-xs font-semibold text-slate-200">Estructura del dataset: <span className="text-cyan-400">{name}</span></p>
      </div>

      {/* Column diagram */}
      <div className="overflow-x-auto">
        <div className="flex items-stretch gap-0 min-w-max">
          {entries.map(([col, type], i) => {
            const color = TYPE_COLOR[type] ?? '#64748b'
            return (
              <div key={col} className="flex flex-col items-center relative">
                {/* Connector */}
                {i < entries.length - 1 && (
                  <div className="absolute top-6 left-full w-full h-px z-0"
                       style={{ background: 'rgba(255,255,255,0.06)' }} />
                )}
                <div className="rounded-xl px-3 py-2 mx-1 flex flex-col items-center gap-1 z-10 w-28"
                     style={{ background: `${color}0f`, border: `1px solid ${color}33` }}>
                  <span className="text-[9px] font-mono font-bold text-center leading-tight" style={{ color }}>
                    {col}
                  </span>
                  <span className="text-[8px] px-1.5 py-0.5 rounded font-mono"
                        style={{ background: `${color}18`, color: '#64748b' }}>
                    {type}
                  </span>
                </div>
              </div>
            )
          })}
        </div>
      </div>

      {/* CTI significance per column */}
      <div className="space-y-1.5 max-h-36 overflow-y-auto">
        <p className="text-[9px] font-bold text-slate-600 uppercase tracking-wider">
          Significado en Ciberseguridad
        </p>
        {entries.map(([col, type]) => {
          const hint = CTI_USE[col.toLowerCase()] ?? `Campo "${col}" — analiza su distribución y valores atípicos`
          const color = TYPE_COLOR[type] ?? '#64748b'
          return (
            <div key={col} className="flex items-start gap-2">
              <span className="text-[9px] font-mono font-bold shrink-0 w-20 truncate" style={{ color }}>
                {col}
              </span>
              <span className="text-[9px] text-slate-500 leading-relaxed">{hint}</span>
            </div>
          )
        })}
      </div>
    </div>
  )
}

// ── Arena (challenge sandbox) ─────────────────────────────────────────────────

function Arena({ challenge }: { challenge: Challenge }) {
  const { token, user } = useAuth()
  const [pyodide,    setPyodide]    = useState<PyodideInterface | null>(null)
  const [initStatus, setInitStatus] = useState<'loading' | 'ready' | 'error'>('loading')
  const [code,       setCode]       = useState('')
  const [output,     setOutput]     = useState('')
  const [running,    setRunning]    = useState(false)
  const [notes,      setNotes]      = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [submitted,  setSubmitted]  = useState(challenge.submitted > 0)
  const [schema,     setSchema]     = useState<Record<string, string>>({})
  const textareaRef = useRef<HTMLTextAreaElement>(null)

  const STARTER = `# Dataset: ${challenge.dataset_name ?? 'sin dataset'}
# Reto: ${challenge.title}
# Objetivo: ${challenge.objective}

import pandas as pd
import numpy as np
import json

# Tu dataset ya está cargado en la variable: challenge_df
print("=== DATASET DEL RETO ===")
print(challenge_df.head())
print(f"\\nShape: {challenge_df.shape}")
print(f"Columnas: {challenge_df.columns.tolist()}")
print(f"\\nEstadísticas:")
print(challenge_df.describe(include='all'))
`

  useEffect(() => {
    setCode(STARTER)
    // Load dataset into pyodide if available
    if (!challenge.id) return
    fetch(`${API}/student/challenges/${challenge.id}/dataset`, {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then(r => r.ok ? r.json() : Promise.reject())
      .then(d => {
        try { setSchema(JSON.parse(d.schema_json)) } catch { /* ok */ }
        return d
      })
      .catch(() => {})
  }, [challenge.id, token])  // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    let cancelled = false
    async function init() {
      try {
        if (!window.loadPyodide) {
          await new Promise<void>((res, rej) => {
            const s = document.createElement('script')
            s.src = 'https://cdn.jsdelivr.net/pyodide/v0.27.5/full/pyodide.js'
            s.onload = () => res(); s.onerror = () => rej()
            document.head.appendChild(s)
          })
        }
        const py = await window.loadPyodide!({ indexURL: 'https://cdn.jsdelivr.net/pyodide/v0.27.5/full/' })
        await py.loadPackage(['pandas', 'numpy'])

        // Load ioc_df
        const iocRes = await fetch(`${API}/ioc-feed`)
        const iocs   = await iocRes.json()
        py.globals.set('_ioc_json', JSON.stringify(iocs))
        await py.runPythonAsync(`import pandas as pd, json; ioc_df = pd.DataFrame(json.loads(_ioc_json))`)

        // Load challenge dataset if available
        if (challenge.id) {
          const dsRes = await fetch(`${API}/student/challenges/${challenge.id}/dataset`, {
            headers: { Authorization: `Bearer ${token}` },
          })
          if (dsRes.ok) {
            const ds = await dsRes.json()
            py.globals.set('_challenge_json', ds.data_json)
            await py.runPythonAsync(`challenge_df = pd.DataFrame(json.loads(_challenge_json))`)
          }
        }

        if (!cancelled) { setPyodide(py); setInitStatus('ready') }
      } catch { if (!cancelled) setInitStatus('error') }
    }
    init()
    return () => { cancelled = true }
  }, [challenge.id, token])

  const runCode = async () => {
    if (!pyodide || running) return
    setRunning(true); setOutput('')
    try {
      await pyodide.runPythonAsync(`import sys, io; _cap = io.StringIO(); sys.stdout = _cap`)
      await pyodide.loadPackagesFromImports(code)
      await pyodide.runPythonAsync(code)
      const out = String(await pyodide.runPythonAsync(`sys.stdout = sys.__stdout__; _cap.getvalue()`))
      setOutput(out || '(sin output)')
    } catch (err) {
      try { await pyodide.runPythonAsync('import sys; sys.stdout = sys.__stdout__') } catch { /* ok */ }
      setOutput(`Error:\n${err}`)
    } finally { setRunning(false) }
  }

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Tab') {
      e.preventDefault()
      const el = textareaRef.current!
      const { selectionStart: s, selectionEnd: end } = el
      setCode(code.slice(0, s) + '    ' + code.slice(end))
      requestAnimationFrame(() => { el.selectionStart = el.selectionEnd = s + 4 })
    }
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') runCode()
  }

  const submit = async () => {
    if (!output) return alert('Ejecuta tu código primero para generar output.')
    setSubmitting(true)
    const parts = parseOutput(output)
    const plots = parts.filter(p => p.type === 'plot').map(p => p.content)
    try {
      await fetch(`${API}/student/challenges/${challenge.id}/submit`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ code, output, plots, notes }),
      })
      setSubmitted(true)
    } catch { alert('Error al entregar. Intenta de nuevo.') }
    finally { setSubmitting(false) }
  }

  const outputParts = parseOutput(output)

  return (
    <div className="space-y-4">
      {/* Challenge header */}
      <div className="rounded-xl p-5 space-y-3" style={glass}>
        <div className="flex items-start justify-between gap-3">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <h3 className="text-base font-bold text-slate-100">{challenge.title}</h3>
              {submitted && (
                <span className="text-[10px] font-bold px-2 py-0.5 rounded"
                      style={{ background: 'rgba(74,222,128,0.12)', color: '#4ade80', border: '1px solid rgba(74,222,128,0.3)' }}>
                  ✓ Entregado{challenge.my_score != null ? ` · ${challenge.my_score}/100` : ''}
                </span>
              )}
            </div>
            {challenge.description && <p className="text-xs text-slate-500">{challenge.description}</p>}
          </div>
          {challenge.deadline && (
            <div className="shrink-0 text-right">
              <p className="text-[9px] text-slate-700">Límite</p>
              <p className="text-xs text-slate-400">
                {new Date(challenge.deadline).toLocaleDateString('es-MX', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' })}
              </p>
            </div>
          )}
        </div>
        <div className="grid grid-cols-2 gap-3">
          {challenge.objective && (
            <div className="rounded-lg p-3" style={{ background: 'rgba(34,211,238,0.05)', border: '1px solid rgba(34,211,238,0.1)' }}>
              <p className="text-[9px] text-cyan-700 font-bold uppercase mb-1">Objetivo</p>
              <p className="text-xs text-slate-400">{challenge.objective}</p>
            </div>
          )}
          {challenge.criteria && (
            <div className="rounded-lg p-3" style={{ background: 'rgba(167,139,250,0.05)', border: '1px solid rgba(167,139,250,0.1)' }}>
              <p className="text-[9px] text-violet-700 font-bold uppercase mb-1">Criterios</p>
              <p className="text-xs text-slate-400">{challenge.criteria}</p>
            </div>
          )}
        </div>
      </div>

      {/* Dataset diagram */}
      {Object.keys(schema).length > 0 && (
        <DatasetDiagram schema={schema} name={challenge.dataset_name ?? 'Dataset'} />
      )}

      {/* Python editor */}
      <div className="rounded-xl overflow-hidden" style={glass}>
        {initStatus === 'loading' && (
          <div className="p-6 flex items-center gap-3">
            <div className="w-5 h-5 border-2 border-violet-400 border-t-transparent rounded-full animate-spin" />
            <p className="text-xs text-violet-400">Cargando entorno Python + dataset del reto...</p>
          </div>
        )}
        {initStatus === 'error' && (
          <p className="p-6 text-xs text-red-400">Error cargando Python. Verifica tu conexión a internet.</p>
        )}
        {initStatus === 'ready' && (
          <>
            <div className="flex items-center justify-between px-4 py-2 border-b"
                 style={{ borderColor: 'rgba(255,255,255,0.06)', background: 'rgba(0,0,0,0.3)' }}>
              <span className="text-[10px] font-mono text-slate-700">reto_{challenge.id}.py</span>
              <div className="flex items-center gap-2">
                <button onClick={() => { setCode(STARTER); setOutput('') }}
                        className="text-[10px] text-slate-600 hover:text-slate-400 px-2 py-1 rounded">
                  Resetear
                </button>
                <button onClick={runCode} disabled={running}
                        className="text-xs font-semibold px-3 py-1.5 rounded disabled:opacity-40"
                        style={{ background: 'rgba(167,139,250,0.2)', border: '1px solid rgba(167,139,250,0.4)', color: '#a78bfa' }}>
                  {running ? 'Ejecutando...' : '▶ Ejecutar (Ctrl+Enter)'}
                </button>
              </div>
            </div>
            <textarea ref={textareaRef} value={code}
                      onChange={e => setCode(e.target.value)}
                      onKeyDown={handleKeyDown} spellCheck={false}
                      className="w-full resize-none focus:outline-none font-mono text-sm p-4 leading-relaxed"
                      style={{ background: '#050a14', color: '#86efac', height: 280 }} />
          </>
        )}
      </div>

      {/* Output */}
      {output && (
        <div className="rounded-xl overflow-hidden" style={glass}>
          <div className="flex items-center gap-2 px-4 py-2 border-b"
               style={{ borderColor: 'rgba(255,255,255,0.06)', background: 'rgba(0,0,0,0.3)' }}>
            <span className="text-[10px] text-slate-600 uppercase tracking-wider">Output</span>
            <button onClick={() => setOutput('')} className="ml-auto text-[10px] text-slate-700 hover:text-slate-500">Limpiar</button>
          </div>
          <div className="p-4 text-xs font-mono text-slate-300 max-h-64 overflow-y-auto space-y-2">
            {outputParts.map((p, i) =>
              p.type === 'plot'
                ? <img key={i} src={`data:image/png;base64,${p.content}`} className="max-w-full rounded-lg" alt={`plot ${i}`} />
                : <span key={i} className="whitespace-pre-wrap block">{p.content}</span>
            )}
          </div>
        </div>
      )}

      {/* Submit section */}
      <div className="rounded-xl p-4 space-y-3" style={{ ...glass, border: `1px solid rgba(74,222,128,${submitted ? '0.25' : '0.1'})` }}>
        <p className="text-[10px] font-bold text-green-700 uppercase tracking-wider">
          {submitted ? '✓ Entrega registrada' : 'Entregar análisis'}
        </p>
        {!submitted && (
          <>
            <textarea value={notes} onChange={e => setNotes(e.target.value)}
                      placeholder="Notas para el docente: metodología usada, hallazgos principales, conclusiones..."
                      rows={3}
                      className="w-full rounded-lg px-3 py-2 text-xs text-slate-100 outline-none resize-none"
                      style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)' }} />
            <div className="flex items-center gap-3">
              <p className="text-[10px] text-slate-600 flex-1">
                Se entregará: tu código, el output y {parseOutput(output).filter(p => p.type === 'plot').length} gráficas.
                {!output && ' ⚠ Ejecuta el código primero.'}
              </p>
              <button onClick={submit} disabled={submitting || !output}
                      className="px-5 py-2 rounded-lg text-xs font-bold disabled:opacity-40 shrink-0"
                      style={{ background: 'rgba(74,222,128,0.15)', border: '1px solid rgba(74,222,128,0.4)', color: '#4ade80' }}>
                {submitting ? 'Enviando...' : `Entregar → (${user?.name})`}
              </button>
            </div>
          </>
        )}
        {submitted && challenge.my_score != null && (
          <p className="text-xs text-slate-400">
            Calificación: <span className="text-green-400 font-bold">{challenge.my_score}/100</span>
          </p>
        )}
      </div>

      {/* HelpBot con contexto completo del reto */}
      <HelpBot
        currentCode={code}
        lessonTitle="Sandbox CTI-Lab"
        challengeTitle={challenge.title}
        challengeDesc={challenge.description}
        challengeObj={challenge.objective}
        challengeCrit={challenge.criteria}
      />
    </div>
  )
}

// ── Team Challenge Card ───────────────────────────────────────────────────────

interface TeamChallenge {
  id: number; title: string; description: string; objective: string; criteria: string
  hints_json?: string; deadline?: string; difficulty: string; badge_name?: string; badge_org?: string; badge_tier?: string
  min_score_badge?: number; dataset_name?: string; badge_earned?: number
  submitted?: number; my_score?: number
}
interface TeamInfo {
  team:        { id: number; name: string; color: string }
  challenges:  TeamChallenge[]
  members:     { name: string; email: string; role: string }[]
  team_badges: { id: number; name: string; org: string; tier: string; icon: string; awarded_at: string }[]
}

const ROLE_META: Record<string, { label: string; color: string; short: string }> = {
  analista_datos:   { label: 'Analista de Datos',  color: '#22d3ee', short: 'AD' },
  ciberseguridad:   { label: 'Ciberseguridad',      color: '#f97316', short: 'CS' },
  ciencia_datos:    { label: 'Ciencia de Datos',    color: '#a78bfa', short: 'CD' },
  machine_learning: { label: 'Machine Learning',    color: '#4ade80', short: 'ML' },
  all:              { label: 'Todos',               color: '#facc15', short: '★'  },
}

const TAG_TO_ROLE: Record<string, string> = {
  AD: 'analista_datos', CS: 'ciberseguridad',
  CD: 'ciencia_datos',  ML: 'machine_learning', ALL: 'all',
}

interface RoleStep { roleKey: string; task: string }
interface DatasetPayload {
  name: string; description: string; data_json: string; schema_json: string; source: string
}

function parseRoleSteps(objective: string): RoleStep[] {
  return objective.split('\n')
    .map(line => line.trim())
    .filter(Boolean)
    .map(line => {
      const m = line.match(/^\[([A-Z]+)\]\s*(.+)/)
      if (m) return { roleKey: TAG_TO_ROLE[m[1]] ?? 'all', task: m[2].trim() }
      return { roleKey: 'all', task: line }
    })
}

/** Criteria breakdown: "Feature X (30%) + Classifier Y (25%)" → [{label, pct}] */
function parseCriteria(criteria: string): { label: string; pct: string }[] {
  return criteria.split('+').map(part => {
    const m = part.trim().match(/^(.+?)\s*\((\d+%)\)$/)
    return m ? { label: m[1].trim(), pct: m[2] } : { label: part.trim(), pct: '' }
  })
}

function parseHints(raw?: string): string[] {
  try {
    const parsed = JSON.parse(raw || '[]')
    return Array.isArray(parsed) ? parsed.map(String).filter(Boolean) : []
  } catch {
    return []
  }
}

function escapeHtml(value: string) {
  return value.replace(/[&<>"']/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]!))
}

function formatRemaining(deadline?: string, now = new Date()) {
  if (!deadline) return null
  const target = new Date(deadline)
  const diff = target.getTime() - now.getTime()
  if (Number.isNaN(target.getTime())) return null
  if (diff <= 0) return { label: 'Tiempo finalizado', expired: true, at: target }
  const totalSeconds = Math.floor(diff / 1000)
  const hours = Math.floor(totalSeconds / 3600)
  const minutes = Math.floor((totalSeconds % 3600) / 60)
  const seconds = totalSeconds % 60
  return {
    label: `${String(hours).padStart(2, '0')}:${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`,
    expired: false,
    at: target,
  }
}

function TeamChallengeCard({ teamInfo }: { teamInfo: TeamInfo }) {
  const { user, token } = useAuth()
  const { team, challenges, members, team_badges } = teamInfo
  const [open, setOpen] = useState(true)
  const [datasetOpen, setDatasetOpen] = useState<Record<number, boolean>>({})
  const [datasets, setDatasets] = useState<Record<number, DatasetPayload | null>>({})
  const [reports, setReports] = useState<Record<number, string>>({})
  const [images, setImages] = useState<Record<number, string[]>>({})
  const [submitting, setSubmitting] = useState<Record<number, boolean>>({})
  const [now, setNow] = useState(() => new Date())

  useEffect(() => {
    const id = window.setInterval(() => setNow(new Date()), 1000)
    return () => window.clearInterval(id)
  }, [])

  if (!challenges.length) return null

  // Find current user's team role
  const myMember  = members.find(m => m.email === user?.email)
  const myRoleKey = myMember?.role ?? ''
  const myRoleMeta = myRoleKey ? (ROLE_META[myRoleKey] ?? ROLE_META.analista_datos) : null

  const loadDataset = async (challengeId: number) => {
    setDatasetOpen(p => ({ ...p, [challengeId]: !p[challengeId] }))
    if (datasets[challengeId] !== undefined) return
    try {
      const res = await fetch(`${API}/student/challenges/${challengeId}/dataset`, {
        headers: { Authorization: `Bearer ${token}` },
      })
      if (!res.ok) throw new Error('Dataset no disponible')
      const data = await res.json()
      setDatasets(p => ({ ...p, [challengeId]: data }))
    } catch {
      setDatasets(p => ({ ...p, [challengeId]: null }))
    }
  }

  const handleImages = async (challengeId: number, fileList: FileList | null) => {
    const files = Array.from(fileList ?? []).filter(f => f.type.startsWith('image/')).slice(0, 4)
    const encoded = await Promise.all(files.map(file => new Promise<string>((resolve, reject) => {
      const reader = new FileReader()
      reader.onload = () => resolve(String(reader.result).split(',')[1] ?? '')
      reader.onerror = () => reject(reader.error)
      reader.readAsDataURL(file)
    })))
    setImages(p => ({ ...p, [challengeId]: encoded.filter(Boolean) }))
  }

  const exportReport = (challenge: TeamChallenge, steps: RoleStep[]) => {
    const ds = datasets[challenge.id]
    const rows = ds ? JSON.parse(ds.data_json || '[]').slice(0, 10) : []
    const reportText = reports[challenge.id] || 'Informe pendiente de completar.'
    const html = `<!doctype html>
<html lang="es"><head><meta charset="utf-8"><title>${escapeHtml(challenge.title)}</title>
<style>body{font-family:Arial,sans-serif;line-height:1.5;color:#0f172a;margin:32px}h1{font-size:24px}h2{font-size:16px;margin-top:24px}table{border-collapse:collapse;width:100%;font-size:12px}td,th{border:1px solid #cbd5e1;padding:6px;text-align:left}pre{white-space:pre-wrap;background:#f8fafc;border:1px solid #cbd5e1;padding:12px}</style></head>
<body><h1>${escapeHtml(challenge.title)}</h1><p><strong>Equipo:</strong> ${escapeHtml(team.name)} · <strong>Estudiante:</strong> ${escapeHtml(user?.name ?? '')}</p>
<h2>Roles y tareas</h2><ul>${steps.map(s => `<li><strong>${escapeHtml(ROLE_META[s.roleKey]?.label ?? 'Equipo')}:</strong> ${escapeHtml(s.task)}</li>`).join('')}</ul>
<h2>Criterios</h2><p>${escapeHtml(challenge.criteria)}</p>
<h2>Informe de entrega</h2><pre>${escapeHtml(reportText)}</pre>
${ds ? `<h2>Dataset explorado: ${escapeHtml(ds.name)}</h2><p>${escapeHtml(ds.description || ds.source)}</p>${rows.length ? `<table><thead><tr>${Object.keys(rows[0]).map(c => `<th>${escapeHtml(c)}</th>`).join('')}</tr></thead><tbody>${rows.map((r: Record<string, unknown>) => `<tr>${Object.keys(rows[0]).map(c => `<td>${escapeHtml(String(r[c] ?? ''))}</td>`).join('')}</tr>`).join('')}</tbody></table>` : ''}` : ''}
</body></html>`
    const url = URL.createObjectURL(new Blob([html], { type: 'text/html;charset=utf-8' }))
    const a = document.createElement('a')
    a.href = url
    a.download = `${challenge.title.replace(/[^\w]+/g, '_').slice(0, 60)}_informe.html`
    a.click()
    URL.revokeObjectURL(url)
  }

  const submitTeamWork = async (challenge: TeamChallenge) => {
    const notes = reports[challenge.id]?.trim() ?? ''
    if (!notes) return alert('Escribe el texto de entrega antes de enviar.')
    setSubmitting(p => ({ ...p, [challenge.id]: true }))
    try {
      const res = await fetch(`${API}/student/challenges/${challenge.id}/submit`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({
          code: '',
          output: `Entrega grupal desde plataforma\nEquipo: ${team.name}\nRol: ${myRoleMeta?.label ?? 'Sin rol'}\nEstudiante: ${user?.name ?? ''}`,
          notes,
          plots: images[challenge.id] ?? [],
        }),
      })
      if (!res.ok) throw new Error('No se pudo registrar la entrega')
      alert('Entrega registrada.')
    } catch (err) {
      alert(String(err))
    } finally {
      setSubmitting(p => ({ ...p, [challenge.id]: false }))
    }
  }

  return (
    <div className="rounded-2xl overflow-hidden"
         style={{ background: `${team.color}07`, border: `2px solid ${team.color}40`, boxShadow: `0 0 32px ${team.color}15` }}>

      {/* ── Header ────────────────────────────────────────────────────── */}
      <button onClick={() => setOpen(o => !o)}
              className="w-full flex items-center gap-3 px-5 py-4 text-left hover:bg-white/[0.02] transition-colors"
              style={{ background: `${team.color}10` }}>
        <div className="w-3 h-3 rounded-full shrink-0 animate-pulse"
             style={{ background: team.color, boxShadow: `0 0 10px ${team.color}` }} />
        <div className="flex-1 min-w-0">
          <p className="text-sm font-bold" style={{ color: team.color }}>
            🏆 Equipo {team.name} — Reto Grupal
          </p>
          <div className="flex items-center gap-3 mt-0.5 flex-wrap">
            <span className="text-[10px] text-slate-500">{members.length} integrantes</span>
            {myRoleMeta && (
              <span className="text-[9px] font-bold px-1.5 py-0.5 rounded"
                    style={{ background: `${myRoleMeta.color}18`, color: myRoleMeta.color, border: `1px solid ${myRoleMeta.color}33` }}>
                Tu rol: {myRoleMeta.short} {myRoleMeta.label}
              </span>
            )}
            {team_badges.length > 0 && (
              <span className="text-[9px] text-yellow-600">★ {team_badges.length} insignia(s) ganadas</span>
            )}
          </div>
        </div>
        <svg viewBox="0 0 24 24" className="w-4 h-4 transition-transform shrink-0"
             style={{ color: team.color, transform: open ? 'rotate(180deg)' : undefined }}
             fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M6 9l6 6 6-6" />
        </svg>
      </button>

      {open && (
        <div className="px-5 pb-5 pt-4 space-y-5">

          {/* ── Integrantes del equipo con roles ──────────────────────── */}
          <div className="rounded-xl p-3 space-y-2"
               style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)' }}>
            <p className="text-[9px] font-bold text-slate-600 uppercase tracking-wider">Integrantes y Roles</p>
            <div className="grid grid-cols-2 gap-1.5">
              {members.map(m => {
                const rm = ROLE_META[m.role] ?? ROLE_META.analista_datos
                const isMe = m.email === user?.email
                return (
                  <div key={m.email}
                       className="flex items-center gap-2 rounded-lg px-2.5 py-2"
                       style={{
                         background: isMe ? `${rm.color}10` : 'rgba(255,255,255,0.02)',
                         border: `1px solid ${isMe ? rm.color+'33' : 'rgba(255,255,255,0.05)'}`,
                       }}>
                    <div className="w-6 h-6 rounded-full flex items-center justify-center text-[9px] font-black shrink-0"
                         style={{ background: `${rm.color}20`, color: rm.color }}>
                      {rm.short}
                    </div>
                    <div className="min-w-0">
                      <p className="text-[10px] font-semibold truncate" style={{ color: isMe ? rm.color : '#94a3b8' }}>
                        {m.name.split(' ').slice(0, 2).join(' ')} {isMe && '(yo)'}
                      </p>
                      <p className="text-[8px] truncate" style={{ color: rm.color + '99' }}>{rm.label}</p>
                    </div>
                  </div>
                )
              })}
            </div>
          </div>

          {/* ── Insignias de equipo ganadas ───────────────────────────── */}
          {team_badges.length > 0 && (
            <div className="flex flex-wrap gap-2">
              {team_badges.map(b => {
                const tc = TIER_COLOR[b.tier] ?? '#facc15'
                return (
                  <span key={b.id} className="text-[9px] px-2.5 py-1 rounded-full font-bold"
                        style={{ background: `${tc}15`, color: tc, border: `1px solid ${tc}33` }}>
                    ★ {b.name} <span className="opacity-60 font-normal">({b.org})</span>
                  </span>
                )
              })}
            </div>
          )}

          {/* ── Retos del equipo ──────────────────────────────────────── */}
          {challenges.map(c => {
            const tc     = c.badge_tier ? (TIER_COLOR[c.badge_tier] ?? '#facc15') : undefined
            const dc     = DIFF_COLOR[c.difficulty] ?? '#64748b'
            const earned = Boolean(c.badge_earned)
            const steps  = parseRoleSteps(c.objective)
            const criteriaItems = parseCriteria(c.criteria)
            const hints = parseHints(c.hints_json)
            const remaining = formatRemaining(c.deadline, now)
            const ds = datasets[c.id]
            const dsRows: Record<string, unknown>[] = ds
              ? (() => { try { return JSON.parse(ds.data_json).slice(0, 25) } catch { return [] } })()
              : []
            const dsCols = dsRows[0] ? Object.keys(dsRows[0]) : []

            return (
              <div key={c.id} className="rounded-xl overflow-hidden"
                   style={{ background: 'rgba(10,15,30,0.7)', border: `1px solid ${team.color}28` }}>

                {/* Badge ganada */}
                {earned && tc && (
                  <div className="px-4 py-2 flex items-center gap-2"
                       style={{ background: `${tc}12`, borderBottom: `1px solid ${tc}20` }}>
                    <span style={{ color: tc }} className="text-base">★</span>
                    <p className="text-[10px] font-bold" style={{ color: tc }}>
                      ¡Insignia de equipo ganada! — {c.badge_name} ({c.badge_org})
                    </p>
                  </div>
                )}

                <div className="p-4 space-y-4">

                  {/* Título + pills */}
                  <div className="flex items-start gap-3">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap mb-1.5">
                        <h3 className="text-sm font-bold text-slate-100">{c.title}</h3>
                        <span className="text-[9px] px-1.5 py-0.5 rounded font-bold"
                              style={{ background: `${dc}12`, color: dc, border: `1px solid ${dc}28` }}>
                          {c.difficulty}
                        </span>
                        <span className="text-[9px] px-1.5 py-0.5 rounded font-bold"
                              style={{ background: `${team.color}12`, color: team.color, border: `1px solid ${team.color}28` }}>
                          👥 Grupal
                        </span>
                        {c.dataset_name && (
                          <span className="text-[9px] px-1.5 py-0.5 rounded"
                                style={{ background: 'rgba(249,115,22,0.08)', color: '#f97316', border: '1px solid rgba(249,115,22,0.2)' }}>
                            📊 {c.dataset_name}
                          </span>
                        )}
                        {remaining && (
                          <span className="text-[9px] px-1.5 py-0.5 rounded font-bold"
                                style={{
                                  background: remaining.expired ? 'rgba(239,68,68,0.1)' : 'rgba(34,211,238,0.08)',
                                  color: remaining.expired ? '#ef4444' : '#22d3ee',
                                  border: `1px solid ${remaining.expired ? 'rgba(239,68,68,0.24)' : 'rgba(34,211,238,0.22)'}`,
                                }}>
                            ⏱ {remaining.label}
                          </span>
                        )}
                      </div>
                      {c.description && (
                        <p className="text-xs text-slate-500 leading-relaxed">{c.description}</p>
                      )}
                      {remaining && (
                        <p className="text-[10px] text-slate-600 mt-1">
                          Cierre del reto: {remaining.at.toLocaleString('es-CO', {
                            timeZone: 'America/Bogota',
                            hour: '2-digit',
                            minute: '2-digit',
                            day: 'numeric',
                            month: 'short',
                          })} hora Colombia
                        </p>
                      )}
                    </div>
                  </div>

                  {/* ── Rol + Integrante + Campo de análisis ──────────── */}
                  {steps.length > 0 && (
                    <div className="rounded-xl overflow-hidden"
                         style={{ border: '1px solid rgba(255,255,255,0.07)' }}>
                      <div className="px-3 py-2 flex items-center gap-2"
                           style={{ background: 'rgba(255,255,255,0.03)', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
                        <svg viewBox="0 0 24 24" className="w-3.5 h-3.5 text-slate-600" fill="none" stroke="currentColor" strokeWidth="2">
                          <path d="M9 5H7a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V7a2 2 0 0 0-2-2h-2M9 5a2 2 0 0 0 2 2h2a2 2 0 0 0 2-2M9 5a2 2 0 0 1 2-2h2a2 2 0 0 1 2 2" />
                        </svg>
                        <p className="text-[9px] font-bold text-slate-500 uppercase tracking-wider">
                          Rol · Integrante · Campo de análisis
                        </p>
                      </div>
                      <div className="divide-y divide-white/[0.04]">
                        {steps.map((step, i) => {
                          const rm       = ROLE_META[step.roleKey] ?? ROLE_META.all
                          const assigned = step.roleKey === 'all'
                            ? members
                            : members.filter(m => m.role === step.roleKey)
                          const isMyStep = step.roleKey === 'all' || step.roleKey === myRoleKey

                          return (
                            <div key={i}
                                 className="flex items-start gap-3 px-3 py-2.5 transition-all"
                                 style={{
                                   background: isMyStep ? `${rm.color}07` : 'transparent',
                                   borderLeft: isMyStep ? `3px solid ${rm.color}50` : '3px solid transparent',
                                 }}>

                              {/* Rol pill */}
                              <div className="flex flex-col items-center gap-1 shrink-0 pt-0.5">
                                <span className="w-6 h-6 rounded-full flex items-center justify-center text-[8px] font-black"
                                      style={{ background: `${rm.color}20`, color: rm.color }}>
                                  {rm.short}
                                </span>
                                {isMyStep && myRoleKey && (
                                  <span className="text-[7px] font-bold" style={{ color: rm.color }}>Tú</span>
                                )}
                              </div>

                              {/* Integrante(s) */}
                              <div className="shrink-0 w-28 pt-0.5 space-y-0.5">
                                {assigned.length > 0 ? assigned.map(m => (
                                  <p key={m.email}
                                     className="text-[9px] font-medium truncate"
                                     style={{ color: m.email === user?.email ? rm.color : '#64748b' }}>
                                    {m.name.split(' ')[0]}
                                    {m.email === user?.email ? ' ✓' : ''}
                                  </p>
                                )) : (
                                  <p className="text-[9px] text-slate-700">Todo el equipo</p>
                                )}
                              </div>

                              {/* Tarea de análisis */}
                              <p className="flex-1 text-[10px] leading-relaxed"
                                 style={{ color: isMyStep ? '#cbd5e1' : '#64748b' }}>
                                {step.task}
                              </p>
                            </div>
                          )
                        })}
                      </div>
                    </div>
                  )}

                  {/* ── Pistas ───────────────────────────────────────── */}
                  {hints.length > 0 && (
                    <div className="rounded-xl p-3"
                         style={{ background: 'rgba(250,204,21,0.04)', border: '1px solid rgba(250,204,21,0.12)' }}>
                      <p className="text-[9px] font-bold text-yellow-700 uppercase tracking-wider mb-2">Pistas del reto</p>
                      <div className="grid gap-1.5">
                        {hints.map((hint, i) => (
                          <div key={i} className="flex items-start gap-2">
                            <span className="w-4 h-4 rounded-full flex items-center justify-center text-[8px] font-black shrink-0 mt-0.5"
                                  style={{ background: 'rgba(250,204,21,0.14)', color: '#facc15' }}>
                              {i + 1}
                            </span>
                            <p className="text-[10px] leading-relaxed text-slate-400">{hint}</p>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* ── Criterios de evaluación ───────────────────────── */}
                  {criteriaItems.length > 0 && (
                    <div className="space-y-1.5">
                      <p className="text-[9px] font-bold text-slate-600 uppercase tracking-wider">Criterios de evaluación</p>
                      <div className="flex flex-wrap gap-1.5">
                        {criteriaItems.map((cr, i) => (
                          <span key={i} className="text-[9px] px-2 py-1 rounded"
                                style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.07)', color: '#94a3b8' }}>
                            <span className="font-bold text-slate-300">{cr.pct}</span>
                            {cr.pct && ' '}
                            {cr.label}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* ── Dataset en plataforma ─────────────────────────── */}
                  {c.dataset_name && (
                    <div className="rounded-xl overflow-hidden"
                         style={{ border: '1px solid rgba(249,115,22,0.13)' }}>
                      <div className="flex items-center justify-between gap-3 px-3 py-2"
                           style={{ background: 'rgba(249,115,22,0.04)', borderBottom: datasetOpen[c.id] ? '1px solid rgba(249,115,22,0.12)' : 'none' }}>
                        <div>
                          <p className="text-[9px] font-bold text-orange-500 uppercase tracking-wider">Explorar dataset</p>
                          <p className="text-[10px] text-slate-600">{c.dataset_name}</p>
                        </div>
                        <button onClick={() => loadDataset(c.id)}
                                className="px-2.5 py-1 rounded text-[10px] font-bold"
                                style={{ background: 'rgba(249,115,22,0.1)', color: '#f97316', border: '1px solid rgba(249,115,22,0.25)' }}>
                          {datasetOpen[c.id] ? 'Ocultar' : 'Abrir'}
                        </button>
                      </div>
                      {datasetOpen[c.id] && (
                        <div className="p-3 space-y-3">
                          {ds === undefined && <p className="text-xs text-slate-700 animate-pulse">Cargando dataset...</p>}
                          {ds === null && <p className="text-xs text-red-400">No se pudo cargar el dataset.</p>}
                          {ds && (
                            <>
                              <div className="flex flex-wrap gap-1.5">
                                {Object.entries(JSON.parse(ds.schema_json || '{}')).map(([col, type]) => (
                                  <span key={col} className="text-[8px] font-mono px-1.5 py-0.5 rounded"
                                        style={{ background: 'rgba(34,211,238,0.08)', color: '#67e8f9' }}>
                                    {col}: <span className="text-slate-500">{String(type)}</span>
                                  </span>
                                ))}
                              </div>
                              <div className="overflow-x-auto rounded-lg" style={{ border: '1px solid rgba(255,255,255,0.06)' }}>
                                <table className="w-full text-[9px]">
                                  <thead>
                                    <tr style={{ background: 'rgba(255,255,255,0.04)' }}>
                                      {dsCols.map(col => <th key={col} className="px-2 py-1.5 text-left text-slate-500 font-mono">{col}</th>)}
                                    </tr>
                                  </thead>
                                  <tbody className="divide-y divide-white/[0.03]">
                                    {dsRows.map((row, i) => (
                                      <tr key={i} className="hover:bg-white/[0.02]">
                                        {dsCols.map(col => (
                                          <td key={col} className="px-2 py-1.5 text-slate-400 font-mono truncate max-w-32">
                                            {String(row[col] ?? '')}
                                          </td>
                                        ))}
                                      </tr>
                                    ))}
                                  </tbody>
                                </table>
                              </div>
                              <p className="text-[9px] text-slate-700">Mostrando hasta 25 filas para exploración rápida.</p>
                            </>
                          )}
                        </div>
                      )}
                    </div>
                  )}

                  {/* ── Entrega grupal ───────────────────────────────── */}
                  <div className="rounded-xl p-3 space-y-3"
                       style={{ background: 'rgba(74,222,128,0.035)', border: '1px solid rgba(74,222,128,0.12)' }}>
                    <div className="flex items-center justify-between gap-3">
                      <div>
                        <p className="text-[9px] font-bold text-green-600 uppercase tracking-wider">Caja de entrega</p>
                        {c.submitted ? (
                          <p className="text-[9px] text-green-500">Ya registraste una entrega{c.my_score != null ? ` · ${c.my_score}/100` : ''}</p>
                        ) : (
                          <p className="text-[9px] text-slate-600">Texto del informe y evidencias visuales del análisis.</p>
                        )}
                      </div>
                      <button onClick={() => exportReport(c, steps)}
                              className="px-2.5 py-1 rounded text-[10px] font-bold"
                              style={{ background: 'rgba(34,211,238,0.08)', color: '#22d3ee', border: '1px solid rgba(34,211,238,0.22)' }}>
                        Exportar informe
                      </button>
                    </div>
                    <textarea
                      value={reports[c.id] ?? ''}
                      onChange={e => setReports(p => ({ ...p, [c.id]: e.target.value }))}
                      placeholder="Describe hallazgos, metodología, evidencias, visualizaciones, conclusiones y recomendaciones del equipo..."
                      rows={5}
                      className="w-full rounded-lg px-3 py-2 text-xs text-slate-100 outline-none resize-none"
                      style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)' }} />
                    <div className="flex items-center gap-3 flex-wrap">
                      <label className="px-2.5 py-1.5 rounded text-[10px] font-bold cursor-pointer"
                             style={{ background: 'rgba(255,255,255,0.04)', color: '#94a3b8', border: '1px solid rgba(255,255,255,0.09)' }}>
                        Cargar imágenes
                        <input type="file" accept="image/*" multiple className="hidden"
                               onChange={e => handleImages(c.id, e.target.files)} />
                      </label>
                      <span className="text-[9px] text-slate-700">Solo imágenes · máximo 4 archivos</span>
                      <button onClick={() => submitTeamWork(c)} disabled={Boolean(submitting[c.id])}
                              className="ml-auto px-3 py-1.5 rounded text-[10px] font-bold disabled:opacity-40"
                              style={{ background: 'rgba(74,222,128,0.14)', color: '#4ade80', border: '1px solid rgba(74,222,128,0.35)' }}>
                        {submitting[c.id] ? 'Enviando...' : 'Enviar entrega'}
                      </button>
                    </div>
                    {(images[c.id] ?? []).length > 0 && (
                      <div className="flex gap-2 overflow-x-auto pb-1">
                        {(images[c.id] ?? []).map((img, i) => (
                          <img key={i} src={`data:image/png;base64,${img}`} alt={`evidencia ${i + 1}`}
                               className="h-20 rounded border shrink-0"
                               style={{ borderColor: 'rgba(255,255,255,0.08)' }} />
                        ))}
                      </div>
                    )}
                  </div>

                  {/* Badge a ganar */}
                  {c.badge_name && tc && !earned && (
                    <div className="flex items-center gap-2 rounded-lg px-3 py-2"
                         style={{ background: `${tc}05`, border: `1px solid ${tc}18` }}>
                      <span style={{ color: tc }}>★</span>
                      <p className="text-[9px]" style={{ color: tc }}>
                        El equipo gana <strong>{c.badge_name}</strong>
                        <span className="font-normal opacity-70"> ({c.badge_org} · {c.badge_tier})</span>
                        <span className="font-normal opacity-60"> al completar este reto.</span>
                      </p>
                    </div>
                  )}
                </div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

// ── Challenge List ────────────────────────────────────────────────────────────

export default function ChallengeArena() {
  const { token }                       = useAuth()
  const [challenges, setChallenges]     = useState<Challenge[]>([])
  const [teamInfo,   setTeamInfo]       = useState<TeamInfo | null>(null)
  const [solved,     setSolved]         = useState<SolvedChallenge[]>([])
  const [loading,    setLoading]        = useState(true)
  const [active,     setActive]         = useState<Challenge | null>(null)

  useEffect(() => {
    Promise.all([
      fetch(`${API}/student/challenges`,    { headers: { Authorization: `Bearer ${token}` } }).then(r => r.json()),
      fetch(`${API}/student/team-challenge`, { headers: { Authorization: `Bearer ${token}` } }).then(r => r.json()).catch(() => null),
      fetch(`${API}/student/solved-challenges`, { headers: { Authorization: `Bearer ${token}` } }).then(r => r.json()).catch(() => []),
    ]).then(([chs, team, solvedRows]) => {
      setChallenges(chs)
      setSolved(solvedRows)
      if (team?.team) setTeamInfo(team)
      if (chs.length === 1) setActive(chs[0])
    }).catch(() => {})
      .finally(() => setLoading(false))
  }, [token])

  if (loading) return (
    <div className="flex items-center gap-3 p-8">
      <div className="w-5 h-5 border-2 border-violet-400 border-t-transparent rounded-full animate-spin" />
      <p className="text-xs text-slate-500">Cargando retos asignados...</p>
    </div>
  )

  if (active) return (
    <div className="space-y-3">
      <button onClick={() => setActive(null)}
              className="flex items-center gap-2 text-xs text-slate-500 hover:text-slate-300 transition-colors">
        <svg viewBox="0 0 24 24" className="w-3.5 h-3.5" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M19 12H5M12 19l-7-7 7-7" />
        </svg>
        Volver a mis retos
      </button>
      <Arena challenge={active} />
    </div>
  )

  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-base font-semibold text-slate-100">Mis Retos</h2>
        <p className="text-xs text-slate-500 mt-0.5">{challenges.length} retos individuales asignados</p>
      </div>

      {/* Reto grupal del equipo */}
      {teamInfo && <TeamChallengeCard teamInfo={teamInfo} />}

      {solved.length > 0 && (
        <div className="rounded-xl p-4 space-y-3" style={glass}>
          <div className="flex items-center justify-between">
            <p className="text-[10px] font-bold text-green-500 uppercase tracking-wider">Retos solucionados</p>
            <span className="text-[10px] text-slate-600">{solved.length} entregas registradas</span>
          </div>
          <div className="grid gap-2">
            {solved.slice(0, 6).map(s => {
              const tc = s.badge_tier ? (TIER_COLOR[s.badge_tier] ?? '#facc15') : '#4ade80'
              return (
                <div key={`${s.id}-${s.submitted_at}`} className="flex items-center gap-3 rounded-lg px-3 py-2"
                     style={{ background: 'rgba(255,255,255,0.025)', border: '1px solid rgba(255,255,255,0.06)' }}>
                  <span className="w-6 h-6 rounded-full flex items-center justify-center text-[10px] font-black"
                        style={{ background: 'rgba(74,222,128,0.12)', color: '#4ade80' }}>✓</span>
                  <div className="flex-1 min-w-0">
                    <p className="text-xs text-slate-300 truncate">{s.title}</p>
                    <p className="text-[9px] text-slate-700">
                      {(s.stage ?? 'reto').toUpperCase()} · {new Date(s.submitted_at).toLocaleString('es-CO', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' })}
                    </p>
                  </div>
                  {s.score != null && <span className="text-[10px] font-bold text-green-400">{s.score}/100</span>}
                  {s.badge_name && (
                    <span className="text-[9px] px-2 py-0.5 rounded font-bold"
                          style={{ background: `${tc}12`, color: tc, border: `1px solid ${tc}25` }}>
                      ★ {s.badge_name}
                    </span>
                  )}
                </div>
              )
            })}
          </div>
        </div>
      )}

      {challenges.length === 0 ? (
        <div className="rounded-xl p-10 text-center" style={{ background: 'rgba(15,23,42,0.4)', border: '1px solid rgba(255,255,255,0.06)' }}>
          <p className="text-slate-600 text-sm">No tienes retos asignados aún.</p>
          <p className="text-slate-700 text-xs mt-1">Tu instructor te asignará datasets y desafíos próximamente.</p>
        </div>
      ) : (
        <div className="grid gap-3">
          {challenges.map(c => {
            const tierColor  = c.badge_tier ? (TIER_COLOR[c.badge_tier] ?? '#facc15') : undefined
            const diffColor  = c.difficulty ? (DIFF_COLOR[c.difficulty] ?? '#64748b') : undefined
            const earned     = Boolean(c.badge_earned)
            const scoreOk    = c.my_score != null && c.min_score_badge != null && c.my_score >= c.min_score_badge
            const borderColor = c.submitted > 0 ? 'rgba(74,222,128,0.18)' : 'rgba(255,255,255,0.07)'

            return (
              <div key={c.id}
                   className="rounded-xl overflow-hidden cursor-pointer group transition-all hover:bg-white/[0.02]"
                   style={{ background: 'rgba(15,23,42,0.55)', border: `1px solid ${borderColor}` }}
                   onClick={() => setActive(c)}>

                {/* Badge earned top bar */}
                {earned && tierColor && (
                  <div className="px-5 py-1.5 flex items-center gap-2"
                       style={{ background: `${tierColor}12`, borderBottom: `1px solid ${tierColor}22` }}>
                    <span style={{ color: tierColor }}>★</span>
                    <p className="text-[9px] font-bold" style={{ color: tierColor }}>
                      Insignia ganada: {c.badge_name}
                    </p>
                  </div>
                )}

                <div className="flex items-start gap-4 p-5">
                  {/* Left: info */}
                  <div className="flex-1 min-w-0">
                    {/* Title + pills */}
                    <div className="flex items-center gap-2 mb-2 flex-wrap">
                      <h3 className="text-sm font-semibold text-slate-100">{c.title}</h3>

                      {diffColor && (
                        <span className="text-[9px] font-bold px-1.5 py-0.5 rounded"
                              style={{ background: `${diffColor}15`, color: diffColor, border: `1px solid ${diffColor}33` }}>
                          {c.difficulty}
                        </span>
                      )}

                      {c.stage && c.stage !== 'individual' && (
                        <span className="text-[9px] font-bold px-1.5 py-0.5 rounded"
                              style={{ background: 'rgba(34,211,238,0.08)', color: '#22d3ee', border: '1px solid rgba(34,211,238,0.22)' }}>
                          {c.stage === 'parejas' ? 'Por parejas' : c.stage}
                        </span>
                      )}

                      {c.submitted > 0 ? (
                        <span className="text-[10px] font-bold px-1.5 py-0.5 rounded"
                              style={{ background: 'rgba(74,222,128,0.1)', color: '#4ade80', border: '1px solid rgba(74,222,128,0.2)' }}>
                          ✓ Entregado{c.my_score != null ? ` · ${c.my_score}/100` : ''}
                        </span>
                      ) : (
                        <span className="text-[10px] font-bold px-1.5 py-0.5 rounded"
                              style={{ background: 'rgba(250,204,21,0.08)', color: '#facc15', border: '1px solid rgba(250,204,21,0.15)' }}>
                          Pendiente
                        </span>
                      )}

                      {c.status === 'closed' && (
                        <span className="text-[10px] px-1.5 py-0.5 rounded text-slate-600 border border-white/5">Cerrado</span>
                      )}
                    </div>

                    {c.description && (
                      <p className="text-xs text-slate-500 mb-2 leading-relaxed line-clamp-2">{c.description}</p>
                    )}
                    {c.objective && (
                      <p className="text-[10px] text-slate-600 line-clamp-1">
                        <span className="text-slate-700">Objetivo: </span>{c.objective}
                      </p>
                    )}

                    {/* Bottom row: dataset + badge reward */}
                    <div className="flex items-center gap-3 mt-2 flex-wrap">
                      {c.dataset_name && (
                        <span className="text-[9px] px-2 py-0.5 rounded"
                              style={{ background: 'rgba(249,115,22,0.08)', color: '#f97316', border: '1px solid rgba(249,115,22,0.2)' }}>
                          📊 {c.dataset_name}
                        </span>
                      )}

                      {c.badge_name && tierColor && !earned && (
                        <span className="text-[9px] px-2 py-0.5 rounded flex items-center gap-1"
                              style={{ background: `${tierColor}08`, color: tierColor, border: `1px solid ${tierColor}22` }}>
                          ★ {c.badge_name}
                          {c.min_score_badge && (
                            <span className="text-slate-700 ml-0.5">≥{c.min_score_badge}pts</span>
                          )}
                        </span>
                      )}

                      {/* Score progress bar */}
                      {c.submitted > 0 && c.my_score != null && c.min_score_badge != null && (
                        <div className="flex items-center gap-1.5">
                          <div className="w-16 h-1.5 rounded-full bg-white/10 overflow-hidden">
                            <div className="h-full rounded-full transition-all"
                                 style={{ width: `${Math.min(100, (c.my_score / c.min_score_badge) * 100)}%`, background: scoreOk ? '#4ade80' : '#facc15' }} />
                          </div>
                          <span className="text-[8px]" style={{ color: scoreOk ? '#4ade80' : '#facc15' }}>
                            {c.my_score}/{c.min_score_badge}
                          </span>
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Right: deadline + CTA */}
                  <div className="text-right shrink-0 flex flex-col items-end gap-2">
                    {c.deadline && (
                      <p className="text-[10px] text-slate-600">
                        {new Date(c.deadline) < new Date()
                          ? <span className="text-red-500">Vencido</span>
                          : <>Límite: {new Date(c.deadline).toLocaleDateString('es-MX', { day: 'numeric', month: 'short' })}</>
                        }
                      </p>
                    )}
                    <span className="text-[10px] text-cyan-700 group-hover:text-cyan-400 transition-colors">
                      Abrir arena →
                    </span>
                  </div>
                </div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

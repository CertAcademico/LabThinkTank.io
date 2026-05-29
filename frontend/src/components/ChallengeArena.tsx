import { useState, useEffect, useRef } from 'react'
import { useAuth } from '../contexts/AuthContext'
import HelpBot from './HelpBot'
import type { PyodideInterface } from '../types/pyodide'

const API = import.meta.env.VITE_API_URL ?? 'http://127.0.0.1:8000'

// ── Types ─────────────────────────────────────────────────────────────────────

interface Challenge {
  id: number; title: string; description: string; objective: string
  criteria: string; deadline?: string; status: string
  dataset_name?: string; schema_json?: string
  submitted: number; my_score?: number
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

      {/* HelpBot */}
      <HelpBot currentCode={code} lessonTitle="Sandbox Lab" challengeTitle={challenge.title} />
    </div>
  )
}

// ── Challenge List ────────────────────────────────────────────────────────────

export default function ChallengeArena() {
  const { token }                       = useAuth()
  const [challenges, setChallenges]     = useState<Challenge[]>([])
  const [loading,    setLoading]        = useState(true)
  const [active,     setActive]         = useState<Challenge | null>(null)

  useEffect(() => {
    fetch(`${API}/student/challenges`, { headers: { Authorization: `Bearer ${token}` } })
      .then(r => r.json())
      .then(d => { setChallenges(d); if (d.length === 1) setActive(d[0]) })
      .catch(() => {})
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
        <p className="text-xs text-slate-500 mt-0.5">{challenges.length} retos asignados</p>
      </div>

      {challenges.length === 0 ? (
        <div className="rounded-xl p-10 text-center" style={{ background: 'rgba(15,23,42,0.4)', border: '1px solid rgba(255,255,255,0.06)' }}>
          <p className="text-slate-600 text-sm">No tienes retos asignados aún.</p>
          <p className="text-slate-700 text-xs mt-1">Tu instructor te asignará datasets y desafíos próximamente.</p>
        </div>
      ) : (
        <div className="grid gap-4">
          {challenges.map(c => (
            <div key={c.id} className="rounded-xl p-5 cursor-pointer hover:bg-white/[0.02] transition-colors"
                 style={{ background: 'rgba(15,23,42,0.55)', border: `1px solid rgba(255,255,255,${c.submitted ? '0.1' : '0.06'})` }}
                 onClick={() => setActive(c)}>
              <div className="flex items-start justify-between gap-3">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <h3 className="text-sm font-semibold text-slate-100">{c.title}</h3>
                    {c.submitted > 0
                      ? <span className="text-[10px] font-bold px-1.5 py-0.5 rounded" style={{ background: 'rgba(74,222,128,0.1)', color: '#4ade80' }}>
                          ✓ Entregado{c.my_score != null ? ` · ${c.my_score}/100` : ''}
                        </span>
                      : <span className="text-[10px] font-bold px-1.5 py-0.5 rounded" style={{ background: 'rgba(250,204,21,0.08)', color: '#facc15' }}>
                          Pendiente
                        </span>
                    }
                    {c.status === 'closed' && (
                      <span className="text-[10px] px-1.5 py-0.5 rounded" style={{ color: '#475569' }}>Cerrado</span>
                    )}
                  </div>
                  {c.description && <p className="text-xs text-slate-500 mb-2 leading-relaxed">{c.description}</p>}
                  {c.objective && (
                    <p className="text-[10px] text-slate-600">
                      <span className="text-slate-700">Objetivo: </span>{c.objective}
                    </p>
                  )}
                  {c.dataset_name && (
                    <p className="text-[10px] mt-1" style={{ color: '#f97316' }}>
                      Dataset: {c.dataset_name}
                    </p>
                  )}
                </div>
                <div className="text-right shrink-0">
                  {c.deadline && (
                    <p className="text-[10px] text-slate-600">
                      Límite: {new Date(c.deadline).toLocaleDateString('es-MX', { day: 'numeric', month: 'short' })}
                    </p>
                  )}
                  <p className="text-[10px] text-cyan-700 mt-1">Abrir arena →</p>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

import { useState, useEffect, useRef } from 'react'
import { useAuth } from '../contexts/AuthContext'
import HelpBot from './HelpBot'
import type { PyodideInterface } from '../types/pyodide'

import CasePrimer, { type Learn } from './CasePrimer'
import { TIER } from './BadgeCard'
import TeamChat from './TeamChat'

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
  hint_levels?: number
  case_key?: string; case_chapter?: number; case_code?: string; no_code?: boolean; learn?: Learn
  path_order?: number; path_total?: number; locked?: boolean; locked_by?: string; path_pass_score?: number
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

const glass = { background: 'rgba(26,31,19,0.55)', border: '1px solid rgba(255,255,255,0.07)', borderRadius: 12 }

// En los retos, plt.show() debe mostrar la gráfica en el panel de salida y adjuntarla a la entrega (igual que en el Sandbox Lab).
const PLT_HOOK = `import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as _plt
import io as _io, base64 as _b64
if not getattr(_plt, '_cti_patched', False):
    _plt.rcParams.update({
        'figure.facecolor': '#151a0f', 'axes.facecolor': '#1a1f13', 'axes.edgecolor': '#2c3320', 'text.color': '#a3a27c',
        'xtick.color': '#7f8360', 'ytick.color': '#7f8360', 'axes.labelcolor': '#a3a27c', 'grid.color': '#2c3320',
        'grid.linestyle': '--', 'grid.alpha': 0.6, 'font.size': 9,
    })
    def _cti_show(*a, **k):
        for n in _plt.get_fignums():
            f = _plt.figure(n)
            buf = _io.BytesIO()
            f.savefig(buf, format='png', bbox_inches='tight', facecolor=f.get_facecolor(), dpi=110)
            buf.seek(0)
            print('__PLOT__:' + _b64.b64encode(buf.read()).decode())
        _plt.close('all')
    _plt.show = _cti_show
    _plt._cti_patched = True
`

function parseOutput(raw: string): OutputPart[] {
  return raw.split(/(__PLOT__:[A-Za-z0-9+/=]+)/).map(p => ({
    type: (p.startsWith('__PLOT__:') ? 'plot' : 'text') as 'text' | 'plot',
    content: p.startsWith('__PLOT__:') ? p.slice(9) : p,
  })).filter(p => p.content)
}

function safeFilename(value: string) {
  return value
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[^\w.-]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .slice(0, 70) || 'dataset'
}

function rowsToCsv(rows: Record<string, unknown>[]) {
  if (!rows.length) return ''
  const columns = Array.from(new Set(rows.flatMap(row => Object.keys(row))))
  const escapeCell = (value: unknown) => {
    const text = value == null
      ? ''
      : typeof value === 'object'
        ? JSON.stringify(value)
        : String(value)
    return /[",\n\r]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text
  }
  return [
    columns.map(escapeCell).join(','),
    ...rows.map(row => columns.map(col => escapeCell(row[col])).join(',')),
  ].join('\n')
}

function downloadText(filename: string, content: string, type: string) {
  const url = URL.createObjectURL(new Blob([content], { type }))
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}

function datasetRows(payload: DatasetPayload): Record<string, unknown>[] {
  try {
    const parsed = JSON.parse(payload.data_json || '[]')
    if (Array.isArray(parsed)) return parsed.filter(row => row && typeof row === 'object')
  } catch {
    return []
  }
  return []
}

async function exportChallengeDataset(challengeId: number, token: string | null | undefined, fallbackName: string) {
  const res = await fetch(`${API}/student/challenges/${challengeId}/dataset`, {
    headers: { Authorization: `Bearer ${token}` },
  })
  if (!res.ok) throw new Error('Dataset no disponible para descarga')
  const payload: DatasetPayload = await res.json()
  const rows = datasetRows(payload)
  if (!rows.length) throw new Error('El dataset no tiene filas exportables')
  downloadText(
    `${safeFilename(payload.name || fallbackName)}.csv`,
    `\uFEFF${rowsToCsv(rows)}`,
    'text/csv;charset=utf-8',
  )
}

// ── Dataset Diagram ───────────────────────────────────────────────────────────

function DatasetDiagram({ schema, name }: { schema: Record<string, string>; name: string }) {
  const TYPE_COLOR: Record<string, string> = {
    str: '#d4bd55', int: '#4ade80', float: '#f97316',
    bool: '#93a954', object: '#facc15', string: '#d4bd55',
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
            const color = TYPE_COLOR[type] ?? '#7f8360'
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
                        style={{ background: `${color}18`, color: '#7f8360' }}>
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
          const color = TYPE_COLOR[type] ?? '#7f8360'
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
  const draftReady = useRef(false)
  const [output,     setOutput]     = useState('')
  const [running,    setRunning]    = useState(false)
  const [notes,      setNotes]      = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [submitted,  setSubmitted]  = useState(challenge.submitted > 0)
  const [teacherNotes, setTeacherNotes] = useState<{ id: number; challenge_id: number | null; body: string; created_at: string }[]>([])
  const [review,     setReview]     = useState<{ steps: string[]; reported: { entity: string; kind: string; facts: string[] }[]; observations: string[]; nudges: string[]; improve?: { label: string; points: number; tip: string; partial: boolean }[]; max_gain?: number; teacher_feedback?: string } | null>(null)
  const [hintData,   setHintData]   = useState<{ total: number; revealed: { level: number; label: string; text: string }[]; next_label: string | null } | null>(null)
  const [hintBusy,   setHintBusy]   = useState(false)
  const [myDs,       setMyDs]       = useState<{ name: string; var: string; filename: string; rows: number; columns: string[] }[]>([])
  const [myDsBusy,   setMyDsBusy]   = useState(false)
  const [myDsError,  setMyDsError]  = useState('')
  const [grading,    setGrading]    = useState<{ score: number; manual_override?: boolean; passed?: boolean; pass_score?: number; base_applied?: string; capped?: string; next_chapter?: string; badge?: { name: string; description: string; tier: string }; items: { label: string; weight: number; earned: number; ok: boolean; partial: boolean; hint: string }[] } | null>(null)
  const [docFile,    setDocFile]    = useState<File | null>(null)
  const [docStatus,  setDocStatus]  = useState<{ uploaded: boolean; filename?: string; pages?: number } | null>(null)
  const [docUploading, setDocUploading] = useState(false)
  const [docError,   setDocError]   = useState('')
  const [submitError, setSubmitError] = useState('')
  const [schema,     setSchema]     = useState<Record<string, string>>({})
  const [rawDs, setRawDs] = useState<{ filename: string; columns: string[]; count: number; preview: Record<string, unknown>[] } | null>(null)
  const [rawUploading, setRawUploading] = useState(false)
  const [rawError, setRawError] = useState('')
  const textareaRef = useRef<HTMLTextAreaElement>(null)

  const STARTER = `# Dataset: ${challenge.dataset_name ?? 'sin dataset'}
# Reto: ${challenge.title}
# Objetivo: ${challenge.objective}

import pandas as pd
import numpy as np
import json

${challenge.case_key === 'aurora' ? `# CASO AURORA — tu variante: ${challenge.case_code ?? ''}
# Tus datos son solo tuyos. Los dataframes del caso se llaman aurora_netflow, aurora_ioc_feed,
# aurora_malware_lab, aurora_siem_events, aurora_reportes_texto, aurora_dominios (según el capítulo).
# Puedes cruzarlos entre sí. Lista los que tienes con: print([n for n in dir() if n.startswith('aurora_')])
` : ''}# Variables disponibles:
#   challenge_df  -> dataset del reto (estructurado)
#   uploaded_df   -> dataset turbio subido por ti (si lo cargaste)
#   ioc_df        -> feed de IOCs del laboratorio
#   mis_datasets  -> dict con tus datasets subidos (también como up_<nombre>)

print("=== DATASET DEL RETO ===")
print(challenge_df.head())
print(f"\\nShape: {challenge_df.shape}")
print(f"Columnas: {challenge_df.columns.tolist()}")

# Explora el dataset turbio (si lo subiste):
if not uploaded_df.empty:
    print("\\n=== DATASET TURBIO SUBIDO ===")
    print(f"Shape: {uploaded_df.shape}")
    print(f"Columnas: {uploaded_df.columns.tolist()}")
    print(f"\\nNulos por columna:")
    print(uploaded_df.isnull().sum())
    print(f"\\nDuplicados: {uploaded_df.duplicated().sum()}")
    print(f"\\nTipos de datos:")
    print(uploaded_df.dtypes)
`

  // Borrador automático: código y notas se guardan en este navegador y se recuperan si se recarga la página o se actualiza la plataforma.
  const draftKey = `cti_draft_${user?.email ?? 'anon'}_${challenge.id}`
  useEffect(() => {
    let saved: { code?: string; notes?: string } | null = null
    try { saved = JSON.parse(localStorage.getItem(draftKey) ?? 'null') } catch { /* ok */ }
    setCode(saved?.code ?? STARTER)
    if (saved?.notes) setNotes(saved.notes)
    draftReady.current = true
    if (!challenge.id) return
    fetch(`${API}/student/teacher-notes`, { headers: { Authorization: `Bearer ${token}` } })
      .then(r => r.ok ? r.json() : []).then(n => setTeacherNotes((n as typeof teacherNotes).filter(x => x.challenge_id == null || x.challenge_id === challenge.id))).catch(() => {})
    if (challenge.case_key === 'aurora' && challenge.submitted > 0) {
      fetch(`${API}/student/challenges/${challenge.id}/review`, { headers: { Authorization: `Bearer ${token}` } })
        .then(r => r.ok ? r.json() : null).then(r => { if (r) setReview(r) }).catch(() => {})
    }
    if (challenge.hint_levels) {
      fetch(`${API}/student/challenges/${challenge.id}/hints`, { headers: { Authorization: `Bearer ${token}` } })
        .then(r => r.ok ? r.json() : null).then(setHintData).catch(() => {})
    }
    fetch(`${API}/student/challenges/${challenge.id}/dataset`, {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then(r => r.ok ? r.json() : Promise.reject())
      .then(d => { try { setSchema(JSON.parse(d.schema_json)) } catch { /* ok */ } })
      .catch(() => {})
    // Load existing document status
    fetch(`${API}/student/challenges/${challenge.id}/document-status`, {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then(r => r.ok ? r.json() : null)
      .then(d => { if (d) setDocStatus(d) })
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
        const iocRes = await fetch(`${API}/ioc-feed`, {
          headers: { Authorization: `Bearer ${token}` },
        })
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
            // Caso Aurora: datasets de este capítulo y de los anteriores, para cruzarlos
            for (const [name, rows] of Object.entries(ds.extras ?? {})) {
              if (!/^aurora_[a-z_]+$/.test(name)) continue
              py.globals.set('_ex_json', JSON.stringify(rows))
              await py.runPythonAsync(`${name} = pd.DataFrame(json.loads(_ex_json))`)
            }
          }
        }

        // Always define uploaded_df; overwrite if student already uploaded a raw dataset
        await py.runPythonAsync(`uploaded_df = pd.DataFrame()`)
        if (challenge.id) {
          try {
            const rawRes = await fetch(`${API}/student/challenges/${challenge.id}/raw-dataset`, {
              headers: { Authorization: `Bearer ${token}` },
            })
            if (rawRes.ok) {
              const raw = await rawRes.json()
              if (raw.exists && raw.rows?.length) {
                setRawDs({ filename: raw.filename ?? 'dataset', columns: raw.columns, count: raw.count, preview: raw.rows.slice(0, 5) })
                py.globals.set('_raw_json', JSON.stringify(raw.rows))
                await py.runPythonAsync(`uploaded_df = pd.DataFrame(json.loads(_raw_json))`)
              }
            }
          } catch { /* ok */ }
        }

        // Mis datasets: biblioteca personal, disponible en todos los capítulos como up_<nombre> y en el dict mis_datasets
        await py.runPythonAsync(`mis_datasets = {}`)
        try {
          const listRes = await fetch(`${API}/student/my-datasets`, { headers: { Authorization: `Bearer ${token}` } })
          const list = listRes.ok ? await listRes.json() : []
          if (!cancelled) setMyDs(list)
          for (const d of list) {
            const r = await fetch(`${API}/student/my-datasets/${d.name}`, { headers: { Authorization: `Bearer ${token}` } })
            if (!r.ok) continue
            const full = await r.json()
            py.globals.set('_my_json', JSON.stringify(full.rows))
            await py.runPythonAsync(`${full.var} = pd.DataFrame(json.loads(_my_json)); mis_datasets['${full.name}'] = ${full.var}`)
          }
        } catch { /* la biblioteca es opcional */ }

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
      if (/matplotlib|\bplt\b|\.plot\(|seaborn|\.hist\(|\.imshow\(/.test(code)) {
        await pyodide.loadPackage(['matplotlib'])          // df.plot() lo necesita aunque no se importe explícitamente
        await pyodide.runPythonAsync(PLT_HOOK)
      }
      await pyodide.runPythonAsync(code)
      const out = String(await pyodide.runPythonAsync(`sys.stdout = sys.__stdout__; _cap.getvalue()`))
      setOutput(out || '(sin output)')
    } catch (err) {
      try { await pyodide.runPythonAsync('import sys; sys.stdout = sys.__stdout__') } catch { /* ok */ }
      setOutput(`Error:\n${err}`)
    } finally { setRunning(false) }
  }

  const uploadRawDataset = async (file: File) => {
    setRawError('')
    const ext = file.name.split('.').pop()?.toLowerCase() ?? ''
    if (!['csv', 'json', 'tsv', 'txt'].includes(ext)) {
      setRawError('Solo se aceptan archivos CSV, JSON, TSV o TXT.')
      return
    }
    setRawUploading(true)
    try {
      const form = new FormData()
      form.append('file', file)
      const res = await fetch(`${API}/student/challenges/${challenge.id}/upload-raw-dataset`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
        body: form,
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.detail ?? 'Error al subir el dataset.')
      setRawDs({ filename: data.filename, columns: data.columns, count: data.rows, preview: data.preview })
      // Inject full dataset into live Pyodide session
      if (pyodide) {
        pyodide.globals.set('_raw_json', JSON.stringify(data.data))
        await pyodide.runPythonAsync(`uploaded_df = pd.DataFrame(json.loads(_raw_json))`)
      }
    } catch (e) {
      setRawError(String(e instanceof Error ? e.message : e))
    } finally {
      setRawUploading(false)
    }
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

  const uploadDoc = async (file: File) => {
    setDocError('')
    const allowed = ['application/pdf',
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      'application/msword']
    if (!allowed.includes(file.type) && !file.name.match(/\.(pdf|docx|doc)$/i)) {
      setDocError('Solo se aceptan PDF, DOCX o DOC.')
      return
    }
    setDocUploading(true)
    try {
      const form = new FormData()
      form.append('file', file)
      const res = await fetch(`${API}/student/challenges/${challenge.id}/upload-document`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
        body: form,
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.detail ?? 'Error al subir el documento.')
      setDocStatus({ uploaded: true, filename: data.filename, pages: data.pages })
      setDocFile(null)
    } catch (e) {
      setDocError(String(e instanceof Error ? e.message : e))
    } finally {
      setDocUploading(false)
    }
  }

  const uploadMyDataset = async (file: File) => {
    setMyDsError(''); setMyDsBusy(true)
    try {
      const form = new FormData(); form.append('file', file)
      const res = await fetch(`${API}/student/my-datasets`, { method: 'POST', headers: { Authorization: `Bearer ${token}` }, body: form })
      const data = await res.json()
      if (!res.ok) throw new Error(typeof data.detail === 'string' ? data.detail : 'No se pudo subir el archivo')
      setMyDs(prev => [...prev.filter(d => d.name !== data.name), { name: data.name, var: data.var, filename: data.filename, rows: data.rows, columns: data.columns }])
      if (pyodide) {
        pyodide.globals.set('_my_json', JSON.stringify(data.data))
        await pyodide.runPythonAsync(`${data.var} = pd.DataFrame(json.loads(_my_json)); mis_datasets['${data.name}'] = ${data.var}`)
      }
    } catch (e) { setMyDsError(String(e instanceof Error ? e.message : e)) } finally { setMyDsBusy(false) }
  }
  const deleteMyDataset = async (d: { name: string; var: string }) => {
    await fetch(`${API}/student/my-datasets/${d.name}`, { method: 'DELETE', headers: { Authorization: `Bearer ${token}` } }).catch(() => {})
    setMyDs(prev => prev.filter(x => x.name !== d.name))
    if (pyodide) await pyodide.runPythonAsync(`globals().pop('${d.var}', None); mis_datasets.pop('${d.name}', None)`).catch(() => {})
  }

  useEffect(() => {
    if (!draftReady.current) return
    const t = setTimeout(() => {
      try { localStorage.setItem(draftKey, JSON.stringify({ code, notes, saved_at: Date.now() })) } catch { /* ok */ }
    }, 600)
    return () => clearTimeout(t)
  }, [code, notes, draftKey])

  const askHint = async () => {
    setHintBusy(true)
    try {
      const r = await fetch(`${API}/student/challenges/${challenge.id}/hints/next`, {
        method: 'POST', headers: { Authorization: `Bearer ${token}` },
      })
      if (r.ok) setHintData(await r.json())
    } finally { setHintBusy(false) }
  }

  const submit = async () => {
    if (!output && !challenge.no_code) { setSubmitError('Ejecuta tu código primero para generar output.'); return }
    setSubmitError('')
    setSubmitting(true)
    const parts = parseOutput(output)
    const plots = parts.filter(p => p.type === 'plot').map(p => p.content)
    try {
      const res = await fetch(`${API}/student/challenges/${challenge.id}/submit`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ code, output, plots, notes }),
      })
      if (!res.ok) throw new Error('submit')
      const data = await res.json().catch(() => ({}))
      setGrading(data.grading ?? null)
      setReview(data.grading?.review ?? null)
      setSubmitted(true)
    } catch { setSubmitError('Error al entregar. Intenta de nuevo.') }
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
              {challenge.case_code && (
                <span className="text-[10px] font-bold px-2 py-0.5 rounded"
                      style={{ background: 'rgba(147,169,84,0.12)', color: '#93a954', border: '1px solid rgba(147,169,84,0.3)' }}>
                  Variante {challenge.case_code}
                </span>
              )}
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
            <div className="rounded-lg p-3" style={{ background: 'rgba(212,189,85,0.05)', border: '1px solid rgba(212,189,85,0.1)' }}>
              <p className="text-[9px] text-cyan-700 font-bold uppercase mb-1">Objetivo</p>
              <p className="text-xs text-slate-400">{challenge.objective}</p>
            </div>
          )}
          {challenge.criteria && (
            <div className="rounded-lg p-3" style={{ background: 'rgba(147,169,84,0.05)', border: '1px solid rgba(147,169,84,0.1)' }}>
              <p className="text-[9px] text-violet-700 font-bold uppercase mb-1">Criterios</p>
              <p className="text-xs text-slate-400">{challenge.criteria}</p>
            </div>
          )}
        </div>
      </div>

      {teacherNotes.length > 0 && (
        <div className="rounded-xl p-4 space-y-2" style={{ background: 'rgba(250,204,21,0.07)', border: '1px solid rgba(250,204,21,0.4)' }}>
          <p className="text-[10px] font-bold uppercase tracking-wider text-yellow-400">✉ Mensaje de tu docente</p>
          {teacherNotes.map(n => <p key={n.id} className="text-xs text-slate-200 whitespace-pre-line leading-relaxed">{n.body}</p>)}
        </div>
      )}

      {challenge.learn && <CasePrimer learn={challenge.learn} storageKey={`cti_primer_${challenge.id}`} />}

      {/* Dataset diagram */}
      {Object.keys(schema).length > 0 && (
        <div className="space-y-2">
          <div className="flex justify-end">
            <button
              onClick={() => exportChallengeDataset(challenge.id, token, challenge.dataset_name ?? challenge.title)
                .catch(err => alert(String(err)))}
              className="px-3 py-1.5 rounded-lg text-[10px] font-bold"
              style={{ background: 'rgba(249,115,22,0.1)', color: '#f97316', border: '1px solid rgba(249,115,22,0.25)' }}>
              Descargar dataset CSV
            </button>
          </div>
          <DatasetDiagram schema={schema} name={challenge.dataset_name ?? 'Dataset'} />
        </div>
      )}

      {/* ── Mis datasets (biblioteca personal) ──────────────────────────────── */}
      <div className="rounded-xl p-4 space-y-3" style={{ ...glass, border: '1px solid rgba(212,189,85,0.2)' }}>
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-xs text-cyan-400 font-bold">📁 Mis datasets</span>
          <span className="text-[9px] px-2 py-0.5 rounded-full font-mono" style={{ background: 'rgba(212,189,85,0.1)', color: '#d4bd55', border: '1px solid rgba(212,189,85,0.2)' }}>
            CSV · TSV · JSON · JSONL · TXT · LOG · máx 5 MB · hasta 8
          </span>
        </div>
        <p className="text-[10px] text-slate-500 leading-relaxed">
          Sube tus propios datos para responder lo que pide el capítulo: indicadores que recolectaste, un log, un informe en texto, resultados de otra herramienta.
          Quedan guardados y disponibles en <strong className="text-slate-400">todos los capítulos</strong> como <code className="text-cyan-400 font-mono">up_&lt;nombre&gt;</code> (DataFrame)
          y dentro del diccionario <code className="text-cyan-400 font-mono">mis_datasets</code>. Un archivo de texto sin columnas se carga con una fila por línea (columna <code className="font-mono text-cyan-400">linea</code>).
          Si tienes Excel, expórtalo a CSV.
        </p>
        {myDs.map(d => (
          <div key={d.name} className="flex items-center gap-3 rounded-lg px-3 py-2" style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.06)' }}>
            <div className="flex-1 min-w-0">
              <p className="text-[11px] text-slate-200 truncate"><code className="text-cyan-300 font-mono">{d.var}</code> <span className="text-slate-600">· {d.filename}</span></p>
              <p className="text-[9px] text-slate-600 truncate">{d.rows} filas · {d.columns.slice(0, 8).join(', ')}{d.columns.length > 8 ? '…' : ''}</p>
            </div>
            <button onClick={() => deleteMyDataset(d)} className="text-[10px] text-red-400 px-2 py-1 rounded" style={{ border: '1px solid rgba(248,113,113,0.25)' }}>Quitar</button>
          </div>
        ))}
        <label className={`flex items-center justify-center gap-2 rounded-lg p-3 cursor-pointer text-xs font-semibold text-cyan-300 ${myDsBusy ? 'opacity-50 pointer-events-none' : ''}`}
               style={{ border: '1.5px dashed rgba(212,189,85,0.3)', background: 'rgba(212,189,85,0.03)' }}>
          {myDsBusy ? 'Subiendo…' : '+ Subir un dataset'}
          <input type="file" accept=".csv,.tsv,.json,.jsonl,.ndjson,.txt,.log" className="hidden" disabled={myDsBusy}
                 onChange={e => { const f = e.target.files?.[0]; if (f) uploadMyDataset(f); e.target.value = '' }} />
        </label>
        {myDsError && <p className="text-[10px] text-red-400">{myDsError}</p>}
      </div>

      {challenge.case_key !== 'aurora' && (<>
      {/* ── Dataset turbio ────────────────────────────────────────────────── */}
      <div className="rounded-xl p-4 space-y-3" style={{ ...glass, border: '1px solid rgba(251,191,36,0.15)' }}>
        <div className="flex items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <span className="text-xs text-amber-400 font-bold">Dataset Turbio</span>
            <span className="text-[9px] px-2 py-0.5 rounded-full font-mono"
                  style={{ background: 'rgba(251,191,36,0.1)', color: '#fbbf24', border: '1px solid rgba(251,191,36,0.2)' }}>
              CSV · JSON · TSV · máx {5} MB
            </span>
          </div>
          {rawDs && (
            <span className="text-[10px] font-bold px-2 py-0.5 rounded-full"
                  style={{ background: 'rgba(74,222,128,0.1)', color: '#4ade80', border: '1px solid rgba(74,222,128,0.3)' }}>
              ✓ {rawDs.filename} · {rawDs.count} filas · {rawDs.columns.length} cols
            </span>
          )}
        </div>

        <p className="text-[10px] text-slate-500 leading-relaxed">
          Sube un archivo de datos desordenado o incompleto. Se cargará como{' '}
          <code className="text-amber-400 font-mono">uploaded_df</code> en tu sandbox Python.
          Tu misión: explorar, limpiar y determinar qué tipo de análisis aplicar.
        </p>

        {rawDs ? (
          <div className="space-y-2">
            {/* Column pills */}
            <div className="flex flex-wrap gap-1">
              {rawDs.columns.map(col => (
                <span key={col} className="text-[9px] font-mono px-2 py-0.5 rounded"
                      style={{ background: 'rgba(251,191,36,0.07)', color: '#fbbf24', border: '1px solid rgba(251,191,36,0.15)' }}>
                  {col}
                </span>
              ))}
            </div>
            {/* Preview table */}
            <div className="overflow-x-auto rounded-lg" style={{ border: '1px solid rgba(255,255,255,0.05)' }}>
              <table className="text-[9px] font-mono w-full">
                <thead>
                  <tr style={{ background: 'rgba(255,255,255,0.04)' }}>
                    {rawDs.columns.map(c => (
                      <th key={c} className="px-2 py-1 text-left text-slate-500 font-bold">{c}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {rawDs.preview.map((row, i) => (
                    <tr key={i} style={{ borderTop: '1px solid rgba(255,255,255,0.03)' }}>
                      {rawDs.columns.map(c => {
                        const val = row[c]
                        const isEmpty = val == null || val === '' || val === 'null' || val === 'NaN'
                        return (
                          <td key={c} className="px-2 py-1 max-w-[120px] truncate"
                              style={{ color: isEmpty ? '#5f6646' : '#a3a27c' }}>
                            {isEmpty ? '∅' : String(val)}
                          </td>
                        )
                      })}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <label className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg text-[10px] cursor-pointer"
                   style={{ background: 'rgba(251,191,36,0.08)', border: '1px solid rgba(251,191,36,0.2)', color: '#fbbf24' }}>
              {rawUploading ? 'Procesando...' : 'Reemplazar dataset'}
              <input type="file" accept=".csv,.json,.tsv,.txt" className="hidden" disabled={rawUploading}
                     onChange={e => { const f = e.target.files?.[0]; if (f) uploadRawDataset(f) }} />
            </label>
          </div>
        ) : (
          <label className={`flex items-center justify-center gap-3 rounded-xl p-6 cursor-pointer transition-all ${rawUploading ? 'opacity-60 pointer-events-none' : ''}`}
                 style={{ border: '2px dashed rgba(251,191,36,0.2)', background: 'rgba(251,191,36,0.03)' }}>
            <div className="text-center space-y-1">
              <p className="text-2xl">📂</p>
              <p className="text-xs font-semibold text-amber-400">
                {rawUploading ? 'Procesando dataset...' : 'Arrastra o haz clic para subir dataset turbio'}
              </p>
              <p className="text-[9px] text-slate-600">CSV, JSON, TSV · máx 5 MB</p>
            </div>
            <input type="file" accept=".csv,.json,.tsv,.txt" className="hidden" disabled={rawUploading}
                   onChange={e => { const f = e.target.files?.[0]; if (f) uploadRawDataset(f) }} />
          </label>
        )}
        {rawError && <p className="text-[10px] text-red-400">{rawError}</p>}
      </div>

      {/* ── Misión de exploración ML ────────────────────────────────────────── */}
      <div className="rounded-xl p-4 space-y-3" style={{ ...glass, border: '1px solid rgba(147,169,84,0.15)' }}>
        <div className="flex items-center gap-2">
          <span className="text-xs text-violet-400 font-bold">Misión: Descubre el análisis correcto</span>
          <span className="text-[9px] px-2 py-0.5 rounded-full font-mono"
                style={{ background: 'rgba(147,169,84,0.1)', color: '#93a954', border: '1px solid rgba(147,169,84,0.2)' }}>
            No hay una respuesta única
          </span>
        </div>
        <p className="text-[10px] text-slate-500">
          El dataset turbio <strong className="text-slate-400">no trae instrucciones</strong>. Debes explorar los datos,
          identificar sus problemas y <strong className="text-slate-400">justificar qué tipo de análisis o modelo ML es más adecuado</strong>.
        </p>
        <div className="grid grid-cols-2 gap-2">
          {[
            {
              phase: '01', color: '#d4bd55', label: 'Reconocimiento',
              tasks: ['df.shape, df.dtypes, df.head()', 'df.describe(include="all")', 'df.isnull().sum()', 'df.duplicated().sum()'],
            },
            {
              phase: '02', color: '#fbbf24', label: 'Calidad de datos',
              tasks: ['Valores nulos → ¿imputar o eliminar?', 'Outliers → IQR o Z-score', 'Tipos incorrectos → pd.to_numeric()', 'Duplicados → df.drop_duplicates()'],
            },
            {
              phase: '03', color: '#f97316', label: 'Diagnóstico ML',
              tasks: ['¿Variable objetivo? → Supervisado', 'Sin etiquetas → Clustering (K-Means)', 'Valores raros → Detección de anomalías', '¿Serie de tiempo? → ARIMA / LSTM'],
            },
            {
              phase: '04', color: '#4ade80', label: 'Análisis & resultados',
              tasks: ['Aplica el modelo elegido', 'Muestra métricas (accuracy, silhouette…)', 'Visualiza con matplotlib/seaborn', 'Documenta tu justificación en las notas'],
            },
          ].map(({ phase, color, label, tasks }) => (
            <div key={phase} className="rounded-lg p-3 space-y-1.5"
                 style={{ background: `${color}08`, border: `1px solid ${color}22` }}>
              <div className="flex items-center gap-1.5">
                <span className="text-[9px] font-bold font-mono px-1.5 py-0.5 rounded"
                      style={{ background: `${color}18`, color }}>
                  {phase}
                </span>
                <span className="text-[10px] font-semibold" style={{ color }}>{label}</span>
              </div>
              <ul className="space-y-0.5">
                {tasks.map(t => (
                  <li key={t} className="text-[9px] text-slate-500 flex items-start gap-1">
                    <span style={{ color }} className="shrink-0 mt-px">·</span>
                    <code className="font-mono leading-tight">{t}</code>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      </div>

      </>)}

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
                <button onClick={() => { if (confirm('¿Volver al código inicial? Se perderá lo que escribiste en este reto.')) { setCode(STARTER); setOutput('') } }}
                        className="text-[10px] text-slate-600 hover:text-slate-400 px-2 py-1 rounded">
                  Resetear
                </button>
                <button onClick={runCode} disabled={running}
                        className="text-xs font-semibold px-3 py-1.5 rounded disabled:opacity-40"
                        style={{ background: 'rgba(147,169,84,0.2)', border: '1px solid rgba(147,169,84,0.4)', color: '#93a954' }}>
                  {running ? 'Ejecutando...' : '▶ Ejecutar (Ctrl+Enter)'}
                </button>
              </div>
            </div>
            <textarea ref={textareaRef} value={code}
                      onChange={e => setCode(e.target.value)}
                      onKeyDown={handleKeyDown} spellCheck={false}
                      className="w-full resize-none focus:outline-none font-mono text-sm p-4 leading-relaxed"
                      style={{ background: '#11150c', color: '#86efac', height: 280 }} />
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

      {challenge.no_code && (
        <div className="rounded-xl p-4" style={{ background: 'rgba(212,189,85,0.05)', border: '1px solid rgba(212,189,85,0.2)' }}>
          <p className="text-xs text-cyan-300 font-semibold">Este capítulo no requiere código</p>
          <p className="text-[11px] text-slate-400 mt-1">Redacta tu informe ejecutivo en las notas de abajo y publícalo también en el <strong>Muro de Inteligencia</strong> (menú lateral): ese paso suma a tu nota.</p>
        </div>
      )}

      {/* Pistas graduales */}
      {hintData && hintData.total > 0 && (
        <div className="rounded-xl p-4 space-y-3" style={{ ...glass, border: '1px solid rgba(250,204,21,0.18)' }}>
          <div className="flex items-center gap-2">
            <p className="text-[10px] font-bold text-yellow-500 uppercase tracking-wider flex-1">💡 Pistas ({hintData.revealed.length}/{hintData.total})</p>
            {hintData.next_label && (
              <button onClick={askHint} disabled={hintBusy}
                      className="text-[11px] font-semibold px-3 py-1 rounded disabled:opacity-40"
                      style={{ background: 'rgba(250,204,21,0.1)', border: '1px solid rgba(250,204,21,0.3)', color: '#facc15' }}>
                {hintBusy ? '...' : `Pedir pista: ${hintData.next_label}`}
              </button>
            )}
          </div>
          {hintData.revealed.length === 0 && (
            <p className="text-[11px] text-slate-600">Inténtalo primero. Si te atascas, pide una pista: van de la más general a la más concreta.</p>
          )}
          {hintData.revealed.map(h => (
            <div key={h.level} className="rounded-lg p-3" style={{ background: 'rgba(250,204,21,0.04)', border: '1px solid rgba(250,204,21,0.12)' }}>
              <p className="text-[9px] font-bold text-yellow-600 uppercase tracking-wider mb-1">{h.level}. {h.label}</p>
              {['Esqueleto de código', 'Solución de referencia', 'Plantilla de informe', 'Lo mínimo para pasar'].includes(h.label)
                ? <pre className="text-[11px] text-green-300 whitespace-pre-wrap font-mono">{h.text}</pre>
                : <p className="text-[11px] text-slate-300 leading-relaxed">{h.text}</p>}
            </div>
          ))}
          {!hintData.next_label && <p className="text-[10px] text-slate-600">Ya viste todas las pistas. Completa los ___ del esqueleto y ejecútalo.</p>}
        </div>
      )}

      {/* Submit section */}
      <div className="rounded-xl p-4 space-y-3" style={{ ...glass, border: `1px solid rgba(74,222,128,${submitted ? '0.25' : '0.1'})` }}>
        <p className="text-[10px] font-bold text-green-700 uppercase tracking-wider">
          {submitted ? '✓ Entrega registrada — puedes mejorar y volver a entregar' : 'Entregar análisis'}
        </p>
        {/* Document upload — siempre visible */}
        <div className="rounded-lg p-3 space-y-2" style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.07)' }}>
          <p className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider">
            📄 Documento adjunto <span className="text-slate-700 font-normal normal-case">(PDF o Word · máx. 4 páginas)</span>
          </p>
          {docStatus?.uploaded ? (
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-[10px] font-bold px-2 py-0.5 rounded-full"
                    style={{ background: 'rgba(74,222,128,0.1)', color: '#4ade80', border: '1px solid rgba(74,222,128,0.3)' }}>
                ✓ {docStatus.filename}
                {docStatus.pages != null && ` · ${docStatus.pages} pág.`}
              </span>
              <label className="text-[10px] text-slate-600 hover:text-slate-300 cursor-pointer">
                Reemplazar
                <input type="file" accept=".pdf,.docx,.doc" className="hidden"
                       onChange={e => { const f = e.target.files?.[0]; if (f) uploadDoc(f) }} />
              </label>
            </div>
          ) : (
            <div className="flex items-center gap-2 flex-wrap">
              <label className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs cursor-pointer transition-all"
                     style={{ background: 'rgba(212,189,85,0.08)', border: '1px solid rgba(212,189,85,0.2)', color: '#d4bd55' }}>
                {docUploading ? 'Subiendo...' : (docFile ? `${docFile.name}` : 'Seleccionar archivo...')}
                <input type="file" accept=".pdf,.docx,.doc" className="hidden" disabled={docUploading}
                       onChange={e => { const f = e.target.files?.[0]; if (f) { setDocFile(f); setDocError('') } }} />
              </label>
              {docFile && !docUploading && (
                <button onClick={() => uploadDoc(docFile)}
                        className="px-3 py-1.5 rounded-lg text-xs font-bold"
                        style={{ background: 'rgba(212,189,85,0.12)', border: '1px solid rgba(212,189,85,0.35)', color: '#d4bd55' }}>
                  Subir →
                </button>
              )}
              {docUploading && <span className="text-[10px] text-slate-500 animate-pulse">Validando páginas...</span>}
            </div>
          )}
          {docError && <p className="text-[10px] text-red-400">{docError}</p>}
        </div>

        {(
          <>
            <textarea value={notes} onChange={e => setNotes(e.target.value)}
                      placeholder="Notas para el docente: metodología usada, hallazgos principales, conclusiones..."
                      rows={3}
                      className="w-full rounded-lg px-3 py-2 text-xs text-slate-100 outline-none resize-none"
                      style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)' }} />
            <div className="flex items-center gap-3">
              <p className="text-[10px] text-slate-600 flex-1">
                Se entregará: tu código, el output y {parseOutput(output).filter(p => p.type === 'plot').length} gráficas.
                {!output && !challenge.no_code && ' ⚠ Ejecuta el código primero.'}
                {docStatus?.uploaded && ' · 📄 Documento adjunto.'}
              </p>
              <button onClick={submit} disabled={submitting}
                      className="px-5 py-2 rounded-lg text-xs font-bold disabled:opacity-40 shrink-0"
                      style={{ background: 'rgba(74,222,128,0.15)', border: '1px solid rgba(74,222,128,0.4)', color: '#4ade80' }}>
                {submitting ? 'Evaluando...' : submitted ? 'Volver a entregar →' : `Entregar → (${user?.name})`}
              </button>
            </div>
            {submitError && (
              <p className="text-[11px] text-red-400">{submitError}</p>
            )}
          </>
        )}
        {grading && (
          <div className="rounded-lg p-3 space-y-2" style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)' }}>
            <div className="flex items-center gap-2">
              <p className="text-[10px] font-bold text-slate-500 uppercase tracking-wider flex-1">Resultado de tu entrega</p>
              <span className="text-sm font-bold" style={{ color: grading.score >= 70 ? '#4ade80' : grading.score >= 40 ? '#facc15' : '#f87171' }}>{grading.score}/100</span>
            </div>
            {grading.badge && (() => { const t = TIER[grading.badge.tier] ?? TIER.bronze; return (
              <div className="rounded-xl p-4 text-center space-y-1" style={{ background: `${t.color}14`, border: `1px solid ${t.color}88`, boxShadow: `0 0 24px ${t.glow}` }}>
                <p className="text-3xl">🏅</p>
                <p className="text-[10px] uppercase tracking-widest font-bold" style={{ color: t.color }}>¡Insignia de habilidad desbloqueada! · {t.label}</p>
                <p className="text-sm font-bold text-slate-100">{grading.badge.name}</p>
                <p className="text-[11px] text-slate-400">{grading.badge.description}</p>
                {grading.next_chapter && <p className="text-[11px] text-green-300 pt-1">✔ Se habilitó el siguiente capítulo: <strong>{grading.next_chapter.replace(/^Caso Aurora \d — /, '')}</strong></p>}
              </div>) })()}
            {grading.passed && !grading.badge && (
              <p className="text-[11px] text-green-300">✔ ¡Superaste este capítulo ({grading.pass_score ?? 50}+)! {grading.next_chapter ? 'Ya tienes su insignia.' : 'Tu insignia y el siguiente capítulo se habilitan a partir de las 2 pm, o ya los tienes si los desbloqueaste antes.'}</p>
            )}
            {grading.base_applied && <p className="text-[11px] text-green-300">✓ {grading.base_applied}</p>}
            {grading.capped && <p className="text-[11px] text-yellow-300">⚠ {grading.capped}</p>}
            {grading.manual_override && (
              <p className="text-[10px] text-yellow-400">Tu docente ya calificó este reto; su nota se conserva.</p>
            )}
            {grading.items.map(it => (
              <div key={it.label} className="text-[11px]">
                <div className="flex items-start gap-2">
                  <span style={{ color: it.ok ? '#4ade80' : it.partial ? '#facc15' : '#f87171' }}>{it.ok ? '✓' : it.partial ? '◐' : '✗'}</span>
                  <span className="flex-1 text-slate-300">{it.label}</span>
                  <span className="text-slate-600">{it.earned}/{it.weight}</span>
                </div>
                {it.hint && <p className="ml-5 text-[10px] text-slate-500">{it.hint}</p>}
              </div>
            ))}
            <p className="text-[9px] text-slate-700">Calificación automática provisional. Corrige lo que falta y vuelve a entregar.</p>
          </div>
        )}
        {review?.teacher_feedback && (
          <div className="rounded-lg p-3 space-y-1" style={{ background: 'rgba(250,204,21,0.07)', border: '1px solid rgba(250,204,21,0.4)' }}>
            <p className="text-[10px] font-bold uppercase tracking-wider text-yellow-400">✉ Retroalimentación de tu docente</p>
            <p className="text-xs text-slate-200 whitespace-pre-line leading-relaxed">{review.teacher_feedback}</p>
          </div>
        )}
        {review && ((review.steps?.length ?? 0) > 0 || (review.reported?.length ?? 0) > 0 || (review.observations?.length ?? 0) > 0 || (review.nudges?.length ?? 0) > 0) && (
          <div className="rounded-lg p-3 space-y-3" style={{ background: 'rgba(212,189,85,0.04)', border: '1px solid rgba(212,189,85,0.18)' }}>
            <p className="text-[10px] font-bold text-cyan-400 uppercase tracking-wider">🔎 Lo que revisé de tu entrega</p>
            {(review.observations ?? []).map((o, i) => <p key={i} className="text-[11px] text-red-300">⚠ {o}</p>)}
            {(review.steps?.length ?? 0) > 0 && (
              <div className="space-y-0.5">
                <p className="text-[9px] uppercase tracking-wider text-slate-500">Qué hace tu código</p>
                {(review.steps ?? []).map((st, i) => <p key={i} className="text-[11px] text-slate-300"><span className="text-slate-600">{i + 1}.</span> {st}</p>)}
              </div>
            )}
            {(review.reported?.length ?? 0) > 0 && (
              <div className="space-y-1.5">
                <p className="text-[9px] uppercase tracking-wider text-slate-500">Lo que reportaste y qué dicen TUS datos de eso</p>
                {(review.reported ?? []).map((r, i) => (
                  <div key={i} className="text-[11px]">
                    <p><span className="text-[9px] px-1.5 py-0.5 rounded mr-1.5" style={{ background: 'rgba(255,255,255,0.06)', color: '#a3a27c' }}>{r.kind}</span><code className="text-cyan-300 font-mono">{r.entity}</code></p>
                    {r.facts.map((f, j) => <p key={j} className="ml-4 text-slate-400">↳ {f}</p>)}
                    {r.facts.length === 0 && <p className="ml-4 text-slate-600">↳ No encontré esto en los datos de tu caso.</p>}
                  </div>
                ))}
              </div>
            )}
            {review.improve && review.improve.length > 0 && (
              <div className="space-y-1.5 rounded-lg p-2.5" style={{ background: 'rgba(74,222,128,0.05)', border: '1px solid rgba(74,222,128,0.18)' }}>
                <p className="text-[9px] uppercase tracking-wider text-green-500">Para subir tu nota{review.max_gain ? ` (aún puedes ganar hasta +${review.max_gain})` : ''}</p>
                {review.improve.map((m, i) => (
                  <p key={i} className="text-[11px] text-slate-300"><strong className="text-green-400">+{m.points}</strong> {m.label}<span className="block ml-5 text-slate-500">→ {m.tip}</span></p>
                ))}
                <p className="text-[10px] text-slate-600">Puedes repetir este capítulo las veces que quieras: corrige, ejecuta y vuelve a entregar.</p>
              </div>
            )}
            {(review.nudges?.length ?? 0) > 0 && (
              <div className="space-y-1">
                <p className="text-[9px] uppercase tracking-wider text-yellow-600">Por dónde seguir</p>
                {(review.nudges ?? []).map((n, i) => <p key={i} className="text-[11px] text-yellow-200/90">→ {n}</p>)}
              </div>
            )}
          </div>
        )}
        {submitted && !grading && challenge.my_score != null && (
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
  analista_datos:   { label: 'Analista de Datos',  color: '#d4bd55', short: 'AD' },
  ciberseguridad:   { label: 'Ciberseguridad',      color: '#f97316', short: 'CS' },
  ciencia_datos:    { label: 'Ciencia de Datos',    color: '#93a954', short: 'CD' },
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
  const [teamDocFiles,     setTeamDocFiles]     = useState<Record<number, File | null>>({})
  const [teamDocStatuses,  setTeamDocStatuses]  = useState<Record<number, { uploaded: boolean; filename?: string; pages?: number }>>({})
  const [teamDocUploading, setTeamDocUploading] = useState<Record<number, boolean>>({})
  const [teamDocErrors,    setTeamDocErrors]    = useState<Record<number, string>>({})
  const [teamSubmitErrors, setTeamSubmitErrors] = useState<Record<number, string>>({})

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
    const rows = ds ? (() => { try { return JSON.parse(ds.data_json || '[]').slice(0, 10) } catch { return [] } })() : []
    const reportText = reports[challenge.id] || 'Informe pendiente de completar.'
    const html = `<!doctype html>
<html lang="es"><head><meta charset="utf-8"><title>${escapeHtml(challenge.title)}</title>
<style>body{font-family:Arial,sans-serif;line-height:1.5;color:#1a1f13;margin:32px}h1{font-size:24px}h2{font-size:16px;margin-top:24px}table{border-collapse:collapse;width:100%;font-size:12px}td,th{border:1px solid #bfbb98;padding:6px;text-align:left}pre{white-space:pre-wrap;background:#f8fafc;border:1px solid #bfbb98;padding:12px}</style></head>
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

  const uploadTeamDoc = async (challengeId: number, file: File) => {
    setTeamDocErrors(p => ({ ...p, [challengeId]: '' }))
    setTeamDocUploading(p => ({ ...p, [challengeId]: true }))
    try {
      const form = new FormData()
      form.append('file', file)
      const res = await fetch(`${API}/student/challenges/${challengeId}/upload-document`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
        body: form,
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.detail ?? 'Error al subir el documento.')
      setTeamDocStatuses(p => ({ ...p, [challengeId]: { uploaded: true, filename: data.filename, pages: data.pages } }))
      setTeamDocFiles(p => ({ ...p, [challengeId]: null }))
    } catch (e) {
      setTeamDocErrors(p => ({ ...p, [challengeId]: String(e instanceof Error ? e.message : e) }))
    } finally {
      setTeamDocUploading(p => ({ ...p, [challengeId]: false }))
    }
  }

  const submitTeamWork = async (challenge: TeamChallenge) => {
    const notes = reports[challenge.id]?.trim() ?? ''
    if (!notes) { setTeamSubmitErrors(p => ({ ...p, [challenge.id]: 'Escribe el texto de entrega antes de enviar.' })); return }
    setTeamSubmitErrors(p => ({ ...p, [challenge.id]: '' }))
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
      setTeamSubmitErrors(p => ({ ...p, [challenge.id]: '✓ Entrega registrada correctamente.' }))
    } catch (err) {
      setTeamSubmitErrors(p => ({ ...p, [challenge.id]: String(err) }))
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
                      <p className="text-[10px] font-semibold truncate" style={{ color: isMe ? rm.color : '#a3a27c' }}>
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
            const dc     = DIFF_COLOR[c.difficulty] ?? '#7f8360'
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
                   style={{ background: 'rgba(21,26,15,0.7)', border: `1px solid ${team.color}28` }}>

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
                                  background: remaining.expired ? 'rgba(239,68,68,0.1)' : 'rgba(212,189,85,0.08)',
                                  color: remaining.expired ? '#ef4444' : '#d4bd55',
                                  border: `1px solid ${remaining.expired ? 'rgba(239,68,68,0.24)' : 'rgba(212,189,85,0.22)'}`,
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
                                     style={{ color: m.email === user?.email ? rm.color : '#7f8360' }}>
                                    {m.name.split(' ')[0]}
                                    {m.email === user?.email ? ' ✓' : ''}
                                  </p>
                                )) : (
                                  <p className="text-[9px] text-slate-700">Todo el equipo</p>
                                )}
                              </div>

                              {/* Tarea de análisis */}
                              <p className="flex-1 text-[10px] leading-relaxed"
                                 style={{ color: isMyStep ? '#bfbb98' : '#7f8360' }}>
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
                                style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.07)', color: '#a3a27c' }}>
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
                        <div className="flex items-center gap-1.5 shrink-0">
                          <button onClick={() => exportChallengeDataset(c.id, token, c.dataset_name ?? c.title)
                                  .catch(err => alert(String(err)))}
                                  className="px-2.5 py-1 rounded text-[10px] font-bold"
                                  style={{ background: 'rgba(212,189,85,0.08)', color: '#d4bd55', border: '1px solid rgba(212,189,85,0.22)' }}>
                            Descargar CSV
                          </button>
                          <button onClick={() => loadDataset(c.id)}
                                  className="px-2.5 py-1 rounded text-[10px] font-bold"
                                  style={{ background: 'rgba(249,115,22,0.1)', color: '#f97316', border: '1px solid rgba(249,115,22,0.25)' }}>
                            {datasetOpen[c.id] ? 'Ocultar' : 'Abrir'}
                          </button>
                        </div>
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
                                        style={{ background: 'rgba(212,189,85,0.08)', color: '#e0cf74' }}>
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
                              style={{ background: 'rgba(212,189,85,0.08)', color: '#d4bd55', border: '1px solid rgba(212,189,85,0.22)' }}>
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
                             style={{ background: 'rgba(255,255,255,0.04)', color: '#a3a27c', border: '1px solid rgba(255,255,255,0.09)' }}>
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
                    {teamSubmitErrors[c.id] && (
                      <p className="text-[11px]"
                         style={{ color: teamSubmitErrors[c.id]?.startsWith('✓') ? '#4ade80' : '#f87171' }}>
                        {teamSubmitErrors[c.id]}
                      </p>
                    )}

                    {/* Document upload — equipo */}
                    <div className="rounded-lg p-3 space-y-2" style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)' }}>
                      <p className="text-[9px] font-semibold text-slate-600 uppercase tracking-wider">
                        📄 Documento adjunto <span className="font-normal normal-case text-slate-700">(PDF o Word · máx. 4 páginas)</span>
                      </p>
                      {teamDocStatuses[c.id]?.uploaded ? (
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="text-[9px] font-bold px-2 py-0.5 rounded-full"
                                style={{ background: 'rgba(74,222,128,0.1)', color: '#4ade80', border: '1px solid rgba(74,222,128,0.3)' }}>
                            ✓ {teamDocStatuses[c.id].filename}
                            {teamDocStatuses[c.id].pages != null && ` · ${teamDocStatuses[c.id].pages} pág.`}
                          </span>
                          <label className="text-[9px] text-slate-600 hover:text-slate-300 cursor-pointer">
                            Reemplazar
                            <input type="file" accept=".pdf,.docx,.doc" className="hidden"
                                   onChange={e => { const f = e.target.files?.[0]; if (f) uploadTeamDoc(c.id, f) }} />
                          </label>
                        </div>
                      ) : (
                        <div className="flex items-center gap-2 flex-wrap">
                          <label className="flex items-center gap-1.5 px-2.5 py-1.5 rounded cursor-pointer text-[10px]"
                                 style={{ background: 'rgba(212,189,85,0.07)', border: '1px solid rgba(212,189,85,0.18)', color: '#d4bd55' }}>
                            {teamDocUploading[c.id] ? 'Subiendo...' : (teamDocFiles[c.id] ? teamDocFiles[c.id]!.name : 'Seleccionar PDF/Word...')}
                            <input type="file" accept=".pdf,.docx,.doc" className="hidden" disabled={Boolean(teamDocUploading[c.id])}
                                   onChange={e => { const f = e.target.files?.[0]; if (f) setTeamDocFiles(p => ({ ...p, [c.id]: f })) }} />
                          </label>
                          {teamDocFiles[c.id] && !teamDocUploading[c.id] && (
                            <button onClick={() => uploadTeamDoc(c.id, teamDocFiles[c.id]!)}
                                    className="px-2.5 py-1.5 rounded text-[10px] font-bold"
                                    style={{ background: 'rgba(212,189,85,0.1)', border: '1px solid rgba(212,189,85,0.3)', color: '#d4bd55' }}>
                              Subir →
                            </button>
                          )}
                          {teamDocUploading[c.id] && <span className="text-[9px] text-slate-600 animate-pulse">Validando...</span>}
                        </div>
                      )}
                      {teamDocErrors[c.id] && <p className="text-[9px] text-red-400">{teamDocErrors[c.id]}</p>}
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
  const { token, user }                 = useAuth()
  const isAdmin                         = user?.role === 'admin'
  const [chatTeam,   setChatTeam]       = useState<{ id: number; name: string } | null>(null)

  useEffect(() => {
    if (!token || isAdmin) return
    fetch(`${API}/student/team-chat`, { headers: { Authorization: `Bearer ${token}` } })
      .then(r => r.ok ? r.json() : null).then(setChatTeam).catch(() => {})
  }, [token, isAdmin])
  const [challenges, setChallenges]     = useState<Challenge[]>([])
  const [teamInfo,   setTeamInfo]       = useState<TeamInfo | null>(null)
  const [solved,     setSolved]         = useState<SolvedChallenge[]>([])
  const [loading,    setLoading]        = useState(true)
  const [active,     setActive]         = useState<Challenge | null>(null)
  const [showAllSolved, setShowAllSolved] = useState(false)

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
        <h2 className="text-base font-semibold text-slate-100">{isAdmin ? 'Retos diseñados' : 'Mis Retos'}</h2>
        <p className="text-xs text-slate-500 mt-0.5">
          {isAdmin ? `${challenges.length} retos en la plataforma (incluye borradores y programados)` : `${challenges.length} retos individuales asignados`}
        </p>
      </div>

      {isAdmin && (
        <div className="rounded-xl px-4 py-3 text-xs"
             style={{ background: 'rgba(212,189,85,0.08)', border: '1px solid rgba(212,189,85,0.3)', color: '#e0cf74' }}>
          🎖️ <b>Vista de admin:</b> puedes abrir cualquier reto para explicarlo (enunciado, pistas y dataset).
          Las entregas y subidas de archivos están deshabilitadas para no afectar calificaciones.
        </div>
      )}

      {chatTeam && <TeamChat teamId={chatTeam.id} teamName={chatTeam.name} height={260} />}

      {/* Reto grupal del equipo */}
      {teamInfo && <TeamChallengeCard teamInfo={teamInfo} />}

      {solved.length > 0 && (
        <div className="rounded-xl p-4 space-y-3" style={glass}>
          <div className="flex items-center justify-between">
            <p className="text-[10px] font-bold text-green-500 uppercase tracking-wider">Retos solucionados</p>
            <span className="text-[10px] text-slate-600">{solved.length} entregas registradas</span>
          </div>
          <div className="grid gap-2">
            {(showAllSolved ? solved : solved.slice(0, 6)).map(s => {
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
          {solved.length > 6 && (
            <button onClick={() => setShowAllSolved(v => !v)}
                    className="w-full py-1.5 rounded-lg text-[10px] text-slate-600 hover:text-slate-400 transition-colors"
                    style={{ border: '1px solid rgba(255,255,255,0.06)' }}>
              {showAllSolved ? `Ocultar (mostrar 6 de ${solved.length})` : `Ver los ${solved.length - 6} restantes ↓`}
            </button>
          )}
        </div>
      )}

      {challenges.length === 0 ? (
        <div className="rounded-xl p-10 text-center" style={{ background: 'rgba(26,31,19,0.4)', border: '1px solid rgba(255,255,255,0.06)' }}>
          <p className="text-slate-600 text-sm">No tienes retos asignados aún.</p>
          <p className="text-slate-700 text-xs mt-1">Tu instructor te asignará datasets y desafíos próximamente.</p>
        </div>
      ) : (
        <div className="grid gap-3">
          {challenges.some(c => c.path_order) && (() => {
            const path = challenges.filter(c => c.path_order)
            const pass = path[0]?.path_pass_score ?? 50
            const done = path.filter(c => c.my_score != null && c.my_score >= pass).length
            return (
              <div className="rounded-xl p-4 space-y-2" style={{ background: 'rgba(212,189,85,0.05)', border: '1px solid rgba(212,189,85,0.2)' }}>
                <div className="flex items-center gap-2">
                  <p className="text-[10px] font-bold text-cyan-400 uppercase tracking-widest flex-1">Tu ruta individual</p>
                  <span className="text-xs font-bold text-cyan-300">{done}/{path.length} completados</span>
                </div>
                <div className="h-1.5 rounded-full overflow-hidden bg-white/[0.05]">
                  <div className="h-full rounded-full bg-cyan-400" style={{ width: `${(done / path.length) * 100}%` }} />
                </div>
                <p className="text-[10px] text-slate-500">Cada reto se desbloquea al sacar al menos {pass}/100 en el anterior. Puedes repetir cualquier capítulo las veces que quieras hasta el cierre del curso para mejorar tu nota.</p>
              </div>
            )
          })()}
          {challenges.map(c => {
            const tierColor  = c.badge_tier ? (TIER_COLOR[c.badge_tier] ?? '#facc15') : undefined
            const diffColor  = c.difficulty ? (DIFF_COLOR[c.difficulty] ?? '#7f8360') : undefined
            const earned     = Boolean(c.badge_earned)
            const scoreOk    = c.my_score != null && c.min_score_badge != null && c.my_score >= c.min_score_badge
            const borderColor = c.submitted > 0 ? 'rgba(74,222,128,0.18)' : 'rgba(255,255,255,0.07)'

            return (
              <div key={c.id}
                   className={`rounded-xl overflow-hidden group transition-all ${c.locked ? 'opacity-60 cursor-not-allowed' : 'cursor-pointer hover:bg-white/[0.02]'}`}
                   style={{ background: 'rgba(26,31,19,0.55)', border: `1px solid ${borderColor}` }}
                   onClick={() => { if (!c.locked) setActive(c) }}>

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
                      {c.path_order && (
                        <span className="text-[9px] font-bold px-1.5 py-0.5 rounded"
                              style={{ background: 'rgba(212,189,85,0.1)', color: '#d4bd55', border: '1px solid rgba(212,189,85,0.25)' }}>
                          {c.path_order}/{c.path_total}
                        </span>
                      )}
                      <h3 className="text-sm font-semibold text-slate-100">{c.locked ? '🔒 ' : ''}{c.title}</h3>

                      {diffColor && (
                        <span className="text-[9px] font-bold px-1.5 py-0.5 rounded"
                              style={{ background: `${diffColor}15`, color: diffColor, border: `1px solid ${diffColor}33` }}>
                          {c.difficulty}
                        </span>
                      )}

                      {c.stage && c.stage !== 'individual' && (
                        <span className="text-[9px] font-bold px-1.5 py-0.5 rounded"
                              style={{ background: 'rgba(212,189,85,0.08)', color: '#d4bd55', border: '1px solid rgba(212,189,85,0.22)' }}>
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
                              style={c.locked
                                ? { background: 'rgba(127,131,96,0.1)', color: '#7f8360', border: '1px solid rgba(127,131,96,0.2)' }
                                : { background: 'rgba(250,204,21,0.08)', color: '#facc15', border: '1px solid rgba(250,204,21,0.15)' }}>
                          {c.locked ? 'Bloqueado' : 'Pendiente'}
                        </span>
                      )}

                      {c.status === 'closed' && (
                        <span className="text-[10px] px-1.5 py-0.5 rounded text-slate-600 border border-white/5">Cerrado</span>
                      )}
                    </div>

                    {c.locked && (
                      <p className="text-[10px] text-cyan-500/80 mb-2">
                        🔒 Se desbloquea al sacar al menos {c.path_pass_score ?? 50}/100 en «{c.locked_by}».
                      </p>
                    )}
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
                        <div className="flex items-center gap-1.5">
                          <span className="text-[9px] px-2 py-0.5 rounded"
                                style={{ background: 'rgba(249,115,22,0.08)', color: '#f97316', border: '1px solid rgba(249,115,22,0.2)' }}>
                            📊 {c.dataset_name}
                          </span>
                          <button
                            onClick={(event) => {
                              event.stopPropagation()
                              exportChallengeDataset(c.id, token, c.dataset_name ?? c.title)
                                .catch(err => alert(String(err)))
                            }}
                            className="text-[9px] px-2 py-0.5 rounded font-bold"
                            style={{ background: 'rgba(212,189,85,0.08)', color: '#d4bd55', border: '1px solid rgba(212,189,85,0.22)' }}>
                            Descargar CSV
                          </button>
                        </div>
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

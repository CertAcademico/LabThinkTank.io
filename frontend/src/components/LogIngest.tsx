import { useCallback, useEffect, useRef, useState } from 'react'
import { useAuth } from '../contexts/AuthContext'

const API = import.meta.env.VITE_API_URL ?? 'http://127.0.0.1:8000'

// ── Types ──────────────────────────────────────────────────────────────────────

interface IocRow { ioc: string; type: string }

interface IngestResult {
  format: string
  line_count: number
  rows: Record<string, unknown>[]
  schema: Record<string, string>
  iocs: IocRow[]
  iocs_added: number
  dataset_id: number | null
}

interface LiveEvent {
  type: string
  ts: string
  [key: string]: unknown
}

interface DatasetMeta {
  id: number
  name: string
  description: string
  source: string
  schema_json: string
  created_at: string
}

// ── Constants ─────────────────────────────────────────────────────────────────

const glass = {
  background: 'rgba(15,23,42,0.55)',
  border: '1px solid rgba(255,255,255,0.07)',
  borderRadius: 12,
}

const FORMAT_LABELS: Record<string, string> = {
  json: 'JSON', jsonl: 'JSON Lines', csv: 'CSV / TSV',
  syslog: 'Syslog RFC 3164/5424', cef: 'CEF (ArcSight)',
  leef: 'LEEF (IBM QRadar)', zeek: 'Zeek/Bro',
  w3c: 'W3C (IIS/Apache)', kvpairs: 'key=value (Splunk)',
  text: 'Texto libre', empty: '—',
}

const FORMAT_COLOR: Record<string, string> = {
  json: '#22d3ee', jsonl: '#22d3ee', csv: '#4ade80',
  syslog: '#a78bfa', cef: '#f97316', leef: '#f97316',
  zeek: '#facc15', w3c: '#facc15', kvpairs: '#94a3b8', text: '#64748b',
}

const IOC_COLOR: Record<string, string> = {
  'IP': '#f97316', 'URL': '#22d3ee', 'Domain': '#a78bfa',
  'Hash-SHA256': '#4ade80', 'Hash-SHA1': '#86efac', 'Hash-MD5': '#bbf7d0',
  'Email': '#facc15', 'CVE': '#ef4444',
}

const EVENT_COLOR: Record<string, string> = {
  ioc_added: '#4ade80', log_ingested: '#22d3ee',
  feed_synced: '#a78bfa', default: '#64748b',
}

// ── Small helpers ─────────────────────────────────────────────────────────────

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
    <span className="text-[10px] px-2 py-0.5 rounded-full font-semibold"
          style={{ color, background: `${color}14`, border: `1px solid ${color}25` }}>
      {children}
    </span>
  )
}

function downloadBlob(filename: string, content: string, mime: string) {
  const url = URL.createObjectURL(new Blob([content], { type: mime }))
  const a = document.createElement('a'); a.href = url; a.download = filename
  a.click(); URL.revokeObjectURL(url)
}

function rowsToCsv(rows: Record<string, unknown>[]): string {
  if (!rows.length) return ''
  const cols = [...new Set(rows.flatMap(r => Object.keys(r)))]
  const esc = (v: unknown) => {
    const s = v == null ? '' : typeof v === 'object' ? JSON.stringify(v) : String(v)
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s
  }
  return [cols.map(esc).join(','), ...rows.map(r => cols.map(c => esc(r[c])).join(','))].join('\n')
}

function exportLiveEvents(events: LiveEvent[], format: 'csv' | 'json') {
  const stamp = new Date().toISOString().replace(/[:.]/g, '-')
  if (format === 'csv') {
    downloadBlob(
      `cti-live-feed-${stamp}.csv`,
      `\uFEFF${rowsToCsv(events as unknown as Record<string, unknown>[])}`,
      'text/csv;charset=utf-8',
    )
    return
  }
  downloadBlob(
    `cti-live-feed-${stamp}.json`,
    JSON.stringify({ exportedAt: new Date().toISOString(), count: events.length, events }, null, 2),
    'application/json;charset=utf-8',
  )
}

// ── Live event row ────────────────────────────────────────────────────────────

function EventRow({ ev }: { ev: LiveEvent }) {
  const color = EVENT_COLOR[ev.type] ?? EVENT_COLOR.default
  const ts = new Date(ev.ts).toLocaleTimeString('es-MX', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
  const label = ev.type === 'log_ingested' ? `Logs: ${ev.source} · ${ev.line_count} líneas · ${ev.ioc_count} IOCs`
    : ev.type === 'feed_synced' ? `Feed: ${ev.feed} · +${ev.added} IOCs`
    : ev.type === 'ioc_added' ? `IOC: ${String(ev.ioc ?? '')} (${ev.type})`
    : JSON.stringify(ev).slice(0, 80)
  return (
    <div className="flex items-center gap-2 text-[10px] font-mono">
      <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: color }} />
      <span className="text-slate-600 shrink-0">{ts}</span>
      <span className="truncate" style={{ color }}>{label}</span>
    </div>
  )
}

// ── Dataset picker ────────────────────────────────────────────────────────────

function DatasetViewer({ token }: { token: string | null | undefined }) {
  const [datasets, setDatasets] = useState<DatasetMeta[]>([])
  const [selected, setSelected] = useState<number | null>(null)
  const [data, setData] = useState<{ rows: Record<string, unknown>[]; schema: Record<string, string>; iocs: IocRow[] } | null>(null)
  const [loading, setLoading] = useState(false)
  const [view, setView] = useState<'structured' | 'raw' | 'iocs'>('structured')

  useEffect(() => {
    fetch(`${API}/student/logs`, { headers: { Authorization: `Bearer ${token}` } })
      .then(r => r.ok ? readApiJson<DatasetMeta[]>(r) : [])
      .then(setDatasets)
      .catch(() => {})
  }, [token])

  const load = async (id: number) => {
    setSelected(id); setLoading(true); setData(null)
    try {
      const [rawRes, iocRes] = await Promise.all([
        fetch(`${API}/student/logs/${id}/raw`, { headers: { Authorization: `Bearer ${token}` } }),
        fetch(`${API}/student/logs/${id}/iocs`, { headers: { Authorization: `Bearer ${token}` } }),
      ])
      const raw = await readApiJson<{ data?: Record<string, unknown>[]; schema?: Record<string, string> }>(rawRes)
      const iocData = await readApiJson<{ iocs?: IocRow[] }>(iocRes)
      setData({ rows: raw.data || [], schema: raw.schema || {}, iocs: iocData.iocs || [] })
    } catch { /* silent */ } finally { setLoading(false) }
  }

  const cols = data ? Object.keys(data.schema) : []

  return (
    <div className="space-y-3">
      <div>
        <p className="text-[9px] font-bold text-slate-600 uppercase tracking-wider mb-2">Dataset</p>
        <select value={selected ?? ''} onChange={e => load(Number(e.target.value))}
                className="w-full rounded-lg px-3 py-2 text-xs outline-none"
                style={{ background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)', color: '#cbd5e1' }}>
          <option value="">Selecciona un dataset...</option>
          {datasets.map(d => (
            <option key={d.id} value={d.id}>{d.name} ({d.source})</option>
          ))}
        </select>
      </div>

      {loading && (
        <div className="flex items-center gap-2 py-3">
          <div className="w-4 h-4 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin" />
          <span className="text-xs text-slate-500">Cargando...</span>
        </div>
      )}

      {data && (
        <div className="space-y-3">
          {/* Tabs */}
          <div className="flex gap-1">
            {(['structured', 'raw', 'iocs'] as const).map(t => (
              <button key={t} onClick={() => setView(t)}
                      className="px-3 py-1 rounded text-[10px] font-bold transition-colors"
                      style={view === t
                        ? { background: 'rgba(34,211,238,0.12)', color: '#22d3ee' }
                        : { color: '#64748b' }}>
                {t === 'structured' ? 'Estructurado' : t === 'raw' ? 'Raw JSON' : `IOCs (${data.iocs.length})`}
              </button>
            ))}
          </div>

          {/* Structured table */}
          {view === 'structured' && cols.length > 0 && (
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <p className="text-[10px] text-slate-600">{data.rows.length} filas · {cols.length} columnas</p>
                <button onClick={() => downloadBlob('dataset.csv', '﻿' + rowsToCsv(data.rows), 'text/csv;charset=utf-8')}
                        className="px-2 py-1 rounded text-[9px] font-bold"
                        style={{ background: 'rgba(34,211,238,0.08)', color: '#22d3ee', border: '1px solid rgba(34,211,238,0.22)' }}>
                  CSV ↓
                </button>
              </div>
              <div className="overflow-x-auto rounded-lg" style={{ border: '1px solid rgba(255,255,255,0.06)', maxHeight: 320 }}>
                <table className="w-full text-[9px]">
                  <thead style={{ position: 'sticky', top: 0 }}>
                    <tr style={{ background: 'rgba(15,23,42,0.9)' }}>
                      {cols.map(c => <th key={c} className="px-2 py-1.5 text-left text-slate-500 font-mono">{c}</th>)}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-white/[0.03]">
                    {data.rows.slice(0, 200).map((row, i) => (
                      <tr key={i} className="hover:bg-white/[0.02]">
                        {cols.map(c => (
                          <td key={c} className="px-2 py-1.5 text-slate-400 font-mono truncate max-w-40">
                            {String(row[c] ?? '')}
                          </td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {data.rows.length > 200 && (
                <p className="text-[9px] text-slate-700">Mostrando 200 de {data.rows.length} filas. Descarga CSV para ver todo.</p>
              )}
            </div>
          )}

          {/* Raw JSON */}
          {view === 'raw' && (
            <div className="space-y-2">
              <div className="flex justify-end">
                <button onClick={() => downloadBlob('dataset.json', JSON.stringify(data.rows, null, 2), 'application/json')}
                        className="px-2 py-1 rounded text-[9px] font-bold"
                        style={{ background: 'rgba(167,139,250,0.08)', color: '#a78bfa', border: '1px solid rgba(167,139,250,0.22)' }}>
                  JSON ↓
                </button>
              </div>
              <pre className="rounded-xl p-4 overflow-auto text-[10px] text-slate-400 font-mono leading-relaxed"
                   style={{ ...glass, background: '#050a14', maxHeight: 320 }}>
                {JSON.stringify(data.rows.slice(0, 50), null, 2)}
              </pre>
            </div>
          )}

          {/* IOCs */}
          {view === 'iocs' && (
            <div className="space-y-2">
              {data.iocs.length === 0 ? (
                <p className="text-xs text-slate-600 py-3">No se encontraron IOCs en este dataset.</p>
              ) : (
                <>
                  <div className="flex items-center justify-between">
                    <p className="text-[10px] text-slate-600">{data.iocs.length} IOCs extraídos</p>
                    <button onClick={() => downloadBlob('iocs.csv', '﻿' + rowsToCsv(data.iocs as unknown as Record<string, unknown>[]), 'text/csv;charset=utf-8')}
                            className="px-2 py-1 rounded text-[9px] font-bold"
                            style={{ background: 'rgba(74,222,128,0.08)', color: '#4ade80', border: '1px solid rgba(74,222,128,0.22)' }}>
                      CSV ↓
                    </button>
                  </div>
                  <div className="space-y-1 max-h-72 overflow-y-auto">
                    {data.iocs.map((ioc, i) => {
                      const col = IOC_COLOR[ioc.type] ?? '#94a3b8'
                      return (
                        <div key={i} className="flex items-center gap-2 rounded px-2.5 py-1.5"
                             style={{ background: `${col}08`, border: `1px solid ${col}20` }}>
                          <span className="text-[9px] font-bold shrink-0 w-20 truncate" style={{ color: col }}>{ioc.type}</span>
                          <span className="text-[10px] font-mono text-slate-300 truncate">{ioc.ioc}</span>
                        </div>
                      )
                    })}
                  </div>
                </>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// ── Main component ────────────────────────────────────────────────────────────

export default function LogIngest() {
  const { token, user } = useAuth()
  const isAdmin = user?.role === 'admin'

  // Ingest state
  const [rawText, setRawText] = useState('')
  const [formatHint, setFormatHint] = useState('')
  const [saveDataset, setSaveDataset] = useState(false)
  const [datasetName, setDatasetName] = useState('')
  const [ingesting, setIngesting] = useState(false)
  const [result, setResult] = useState<IngestResult | null>(null)
  const [error, setError] = useState('')
  const [dragging, setDragging] = useState(false)
  const [resultView, setResultView] = useState<'rows' | 'iocs'>('rows')
  const [copied, setCopied] = useState(false)
  const fileInputRef = useRef<HTMLInputElement>(null)
  const copyTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  // Live feed state
  const [liveEvents, setLiveEvents] = useState<LiveEvent[]>([])
  const [liveConnected, setLiveConnected] = useState(false)
  const eventSourceRef = useRef<EventSource | null>(null)

  // Active tab
  const [tab, setTab] = useState<'ingest' | 'datasets' | 'live'>('ingest')

  // ── SSE connection ──────────────────────────────────────────────────────────

  useEffect(() => {
    if (!token) return
    const es = new EventSource(`${API}/live/feed?token=${encodeURIComponent(token)}`)
    eventSourceRef.current = es
    es.onopen = () => setLiveConnected(true)
    es.onmessage = (e) => {
      try {
        const ev: LiveEvent = JSON.parse(e.data)
        setLiveEvents(prev => [ev, ...prev].slice(0, 200))
      } catch { /* ignore parse errors */ }
    }
    es.onerror = () => { setLiveConnected(false) }
    return () => { es.close() }
  }, [token])

  // ── File drop ───────────────────────────────────────────────────────────────

  const handleDrop = useCallback(async (e: React.DragEvent) => {
    e.preventDefault(); setDragging(false)
    const file = e.dataTransfer.files[0]
    if (!file) return
    const text = await file.text()
    setRawText(text)
    setDatasetName(file.name.replace(/\.[^.]+$/, ''))
  }, [])

  const handleFileSelect = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    const text = await file.text()
    setRawText(text)
    setDatasetName(file.name.replace(/\.[^.]+$/, ''))
  }

  // ── Ingest submit ───────────────────────────────────────────────────────────

  const ingest = async () => {
    if (!rawText.trim()) { setError('Pega o arrastra logs para analizar.'); return }
    setError(''); setIngesting(true); setResult(null)
    try {
      const form = new FormData()
      form.append('raw_text', rawText)
      if (formatHint) form.append('format_hint', formatHint)
      if (saveDataset && isAdmin) {
        form.append('save_dataset', 'true')
        form.append('dataset_name', datasetName || 'Log Ingest')
      }
      const res = await fetch(`${API}/logs/ingest`, {
        method: 'POST',
        headers: token ? { Authorization: `Bearer ${token}` } : {},
        body: form,
      })
      const data = await readApiJson<IngestResult & { detail?: string }>(res)
      if (!res.ok) throw new Error(data.detail ?? 'Error al ingestar.')
      setResult(data)
      setResultView('rows')
    } catch (e) {
      setError(String(e instanceof Error ? e.message : e))
    } finally {
      setIngesting(false)
    }
  }

  const copyIocs = () => {
    if (!result?.iocs.length) return
    const text = result.iocs.map(i => `${i.type}\t${i.ioc}`).join('\n')
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true)
      if (copyTimerRef.current) clearTimeout(copyTimerRef.current)
      copyTimerRef.current = setTimeout(() => setCopied(false), 2000)
    }).catch(() => {})
  }

  const cols = result ? Object.keys(result.schema) : []

  return (
    <div className="h-full overflow-y-auto p-6 space-y-5">

      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100">Log Ingest & Live Feed</h1>
          <p className="text-xs text-slate-500 mt-1">
            Parsea logs en cualquier formato, extrae IOCs automáticamente y accede a los datasets del laboratorio.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span className="w-1.5 h-1.5 rounded-full"
                style={{ background: liveConnected ? '#4ade80' : '#ef4444',
                         boxShadow: liveConnected ? '0 0 6px #4ade80' : undefined }} />
          <span className="text-[10px] font-mono" style={{ color: liveConnected ? '#4ade80' : '#ef4444' }}>
            {liveConnected ? 'SSE conectado' : 'SSE desconectado'}
          </span>
          {liveEvents.length > 0 && (
            <Pill color="#a78bfa">{liveEvents.length} eventos</Pill>
          )}
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 rounded-xl p-1 w-fit" style={glass}>
        {[
          { id: 'ingest', label: 'Ingestar Logs' },
          { id: 'datasets', label: 'Datasets / Estudiantes' },
          { id: 'live', label: `Live Feed${liveEvents.length > 0 ? ` (${liveEvents.length})` : ''}` },
        ].map(t => (
          <button key={t.id} onClick={() => setTab(t.id as typeof tab)}
                  className="px-3 py-1.5 rounded-lg text-xs font-bold transition-colors"
                  style={tab === t.id
                    ? { background: 'rgba(34,211,238,0.12)', color: '#22d3ee' }
                    : { color: '#64748b' }}>
            {t.label}
          </button>
        ))}
      </div>

      {/* ── TAB: Ingest ─────────────────────────────────────────────────────── */}
      {tab === 'ingest' && (
        <div className="grid grid-cols-1 xl:grid-cols-[1fr_380px] gap-4">

          {/* Left: input */}
          <div className="space-y-3">

            {/* Drop zone */}
            <div
              onDragOver={e => { e.preventDefault(); setDragging(true) }}
              onDragLeave={() => setDragging(false)}
              onDrop={handleDrop}
              onClick={() => fileInputRef.current?.click()}
              className="rounded-xl p-4 text-center cursor-pointer transition-all"
              style={{
                border: `2px dashed ${dragging ? '#22d3ee' : 'rgba(255,255,255,0.1)'}`,
                background: dragging ? 'rgba(34,211,238,0.05)' : 'rgba(255,255,255,0.02)',
              }}>
              <p className="text-xs text-slate-500">
                Arrastra un archivo o <span className="text-cyan-400">haz clic para seleccionar</span>
              </p>
              <p className="text-[10px] text-slate-700 mt-1">
                Soporta: JSON · CSV · Syslog · CEF · LEEF · Zeek · W3C · key=value · texto libre
              </p>
              <input ref={fileInputRef} type="file" className="hidden"
                     accept=".log,.txt,.json,.csv,.tsv,.cef,.leef" onChange={handleFileSelect} />
            </div>

            {/* Paste area */}
            <textarea
              value={rawText}
              onChange={e => setRawText(e.target.value)}
              placeholder="O pega los logs aquí directamente..."
              spellCheck={false}
              className="w-full rounded-xl p-4 font-mono text-[11px] leading-relaxed resize-none outline-none"
              style={{ ...glass, background: '#050a14', color: '#86efac', minHeight: 200 }}
            />

            {/* Options row */}
            <div className="flex items-center gap-3 flex-wrap">
              <div className="flex items-center gap-2">
                <span className="text-[10px] text-slate-500">Formato:</span>
                <select value={formatHint} onChange={e => setFormatHint(e.target.value)}
                        className="rounded-lg px-2 py-1 text-[10px] outline-none"
                        style={{ background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)', color: '#cbd5e1' }}>
                  <option value="">Auto-detectar</option>
                  {Object.entries(FORMAT_LABELS).filter(([k]) => k !== 'empty').map(([k, v]) => (
                    <option key={k} value={k}>{v}</option>
                  ))}
                </select>
              </div>

              {isAdmin && (
                <label className="flex items-center gap-1.5 cursor-pointer">
                  <input type="checkbox" checked={saveDataset} onChange={e => setSaveDataset(e.target.checked)}
                         className="accent-cyan-400" />
                  <span className="text-[10px] text-slate-500">Guardar como dataset</span>
                </label>
              )}

              {isAdmin && saveDataset && (
                <input value={datasetName} onChange={e => setDatasetName(e.target.value)}
                       placeholder="Nombre del dataset..."
                       className="rounded-lg px-2 py-1 text-[10px] outline-none flex-1"
                       style={{ background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)', color: '#cbd5e1' }} />
              )}
            </div>

            {error && <p className="text-[11px] text-red-400">{error}</p>}

            <button onClick={ingest} disabled={ingesting || !rawText.trim()}
                    className="w-full py-2.5 rounded-xl text-sm font-bold disabled:opacity-40"
                    style={{ background: 'rgba(34,211,238,0.12)', border: '1px solid rgba(34,211,238,0.3)', color: '#22d3ee' }}>
              {ingesting ? 'Procesando...' : 'Analizar logs →'}
            </button>
          </div>

          {/* Right: results */}
          <div className="space-y-3">
            {result ? (
              <>
                {/* Summary */}
                <div className="rounded-xl p-4 space-y-3" style={glass}>
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-xs font-bold text-slate-200">Resultado</span>
                    <Pill color={FORMAT_COLOR[result.format] ?? '#94a3b8'}>
                      {FORMAT_LABELS[result.format] ?? result.format}
                    </Pill>
                  </div>
                  <div className="grid grid-cols-3 gap-2">
                    {[
                      { label: 'Filas', val: result.line_count },
                      { label: 'IOCs', val: result.iocs.length },
                      { label: 'IOCs guardados', val: result.iocs_added },
                    ].map(m => (
                      <div key={m.label} className="rounded-lg p-2.5 text-center bg-white/[0.03]">
                        <div className="text-base font-bold text-slate-200">{m.val}</div>
                        <div className="text-[9px] text-slate-600 uppercase">{m.label}</div>
                      </div>
                    ))}
                  </div>
                  {result.dataset_id && (
                    <p className="text-[10px] text-green-400">
                      ✓ Guardado como dataset #{result.dataset_id} — visible para estudiantes
                    </p>
                  )}
                  {/* Schema */}
                  {cols.length > 0 && (
                    <div className="flex flex-wrap gap-1">
                      {cols.map(c => (
                        <span key={c} className="text-[9px] font-mono px-1.5 py-0.5 rounded"
                              style={{ background: 'rgba(34,211,238,0.08)', color: '#67e8f9' }}>
                          {c}: <span className="text-slate-500">{result.schema[c]}</span>
                        </span>
                      ))}
                    </div>
                  )}
                </div>

                {/* Result tabs */}
                <div className="flex gap-1">
                  {(['rows', 'iocs'] as const).map(t => (
                    <button key={t} onClick={() => setResultView(t)}
                            className="px-3 py-1 rounded text-[10px] font-bold transition-colors"
                            style={resultView === t
                              ? { background: 'rgba(34,211,238,0.12)', color: '#22d3ee' }
                              : { color: '#64748b' }}>
                      {t === 'rows' ? `Filas (${Math.min(result.rows.length, 500)})` : `IOCs (${result.iocs.length})`}
                    </button>
                  ))}
                  {resultView === 'iocs' && result.iocs.length > 0 && (
                    <button onClick={copyIocs}
                            className="ml-auto px-2 py-1 rounded text-[9px] font-bold transition-colors"
                            style={copied
                              ? { background: 'rgba(74,222,128,0.1)', color: '#4ade80', border: '1px solid rgba(74,222,128,0.3)' }
                              : { color: '#64748b', border: '1px solid rgba(255,255,255,0.08)' }}>
                      {copied ? '✓ Copiado' : 'Copiar'}
                    </button>
                  )}
                </div>

                {resultView === 'rows' && (
                  <div className="overflow-x-auto rounded-xl" style={{ ...glass, maxHeight: 320 }}>
                    {cols.length > 0 ? (
                      <table className="w-full text-[9px]">
                        <thead style={{ position: 'sticky', top: 0 }}>
                          <tr style={{ background: 'rgba(15,23,42,0.9)' }}>
                            {cols.map(c => <th key={c} className="px-2 py-1.5 text-left text-slate-500 font-mono">{c}</th>)}
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-white/[0.03]">
                          {result.rows.slice(0, 100).map((row, i) => (
                            <tr key={i} className="hover:bg-white/[0.02]">
                              {cols.map(c => (
                                <td key={c} className="px-2 py-1.5 text-slate-400 font-mono truncate max-w-32">
                                  {String(row[c] ?? '')}
                                </td>
                              ))}
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    ) : (
                      <pre className="p-4 text-[10px] text-slate-400 font-mono overflow-auto">
                        {JSON.stringify(result.rows.slice(0, 10), null, 2)}
                      </pre>
                    )}
                  </div>
                )}

                {resultView === 'iocs' && (
                  <div className="space-y-1 max-h-72 overflow-y-auto">
                    {result.iocs.length === 0 ? (
                      <p className="text-xs text-slate-600 py-3">No se detectaron IOCs.</p>
                    ) : result.iocs.map((ioc, i) => {
                      const col = IOC_COLOR[ioc.type] ?? '#94a3b8'
                      return (
                        <div key={i} className="flex items-center gap-2 rounded px-2.5 py-1.5"
                             style={{ background: `${col}08`, border: `1px solid ${col}20` }}>
                          <span className="text-[9px] font-bold shrink-0 w-20 truncate" style={{ color: col }}>{ioc.type}</span>
                          <span className="text-[10px] font-mono text-slate-300 break-all">{ioc.ioc}</span>
                        </div>
                      )
                    })}
                  </div>
                )}
              </>
            ) : (
              <div className="rounded-xl p-10 text-center" style={glass}>
                <p className="text-slate-600 text-sm">El resultado aparecerá aquí.</p>
                <p className="text-slate-700 text-xs mt-1">
                  Formatos soportados: JSON, CSV, Syslog, CEF, LEEF, Zeek, W3C, key=value, texto libre.
                </p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── TAB: Datasets ───────────────────────────────────────────────────── */}
      {tab === 'datasets' && (
        <div className="grid grid-cols-1 xl:grid-cols-[1fr_1fr] gap-4">
          <div className="rounded-xl p-4 space-y-4" style={glass}>
            <div>
              <h2 className="text-sm font-bold text-slate-200">Datasets disponibles</h2>
              <p className="text-[10px] text-slate-500 mt-0.5">
                Los estudiantes pueden acceder, explorar y descargar estos datasets desde sus retos o desde aquí.
              </p>
            </div>
            <DatasetViewer token={token} />
          </div>

          <div className="rounded-xl p-5 space-y-4" style={glass}>
            <h2 className="text-sm font-bold text-slate-200">Formatos de salida</h2>
            <div className="space-y-2">
              {[
                { fmt: 'CSV estructurado', desc: 'Columnas parseadas, listo para pandas / Excel', color: '#4ade80' },
                { fmt: 'JSON raw', desc: 'Filas como objetos JSON, sin transformación', color: '#22d3ee' },
                { fmt: 'IOCs extraídos', desc: 'Lista deduplcada con tipo: IP, URL, Domain, Hash, Email, CVE', color: '#a78bfa' },
              ].map(f => (
                <div key={f.fmt} className="flex items-start gap-3 rounded-lg p-3"
                     style={{ background: `${f.color}07`, border: `1px solid ${f.color}1a` }}>
                  <span className="w-2 h-2 rounded-full mt-1 shrink-0" style={{ background: f.color }} />
                  <div>
                    <p className="text-[11px] font-bold" style={{ color: f.color }}>{f.fmt}</p>
                    <p className="text-[10px] text-slate-500">{f.desc}</p>
                  </div>
                </div>
              ))}
            </div>
            <div className="rounded-lg p-3 space-y-1.5" style={{ background: 'rgba(250,204,21,0.05)', border: '1px solid rgba(250,204,21,0.12)' }}>
              <p className="text-[9px] font-bold text-yellow-600 uppercase tracking-wider">Endpoints de estudiante</p>
              {[
                { path: 'GET /student/logs', desc: 'Lista todos los datasets' },
                { path: 'GET /student/logs/{id}/raw', desc: 'JSON original + schema' },
                { path: 'GET /student/logs/{id}/iocs', desc: 'IOCs re-extraídos del dataset' },
                { path: 'GET /student/challenges/{id}/dataset', desc: 'Dataset de un reto específico' },
              ].map(e => (
                <div key={e.path} className="flex items-start gap-2">
                  <code className="text-[9px] text-yellow-400 font-mono shrink-0">{e.path}</code>
                  <span className="text-[9px] text-slate-600">{e.desc}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* ── TAB: Live Feed ──────────────────────────────────────────────────── */}
      {tab === 'live' && (
        <div className="grid grid-cols-1 xl:grid-cols-[1fr_340px] gap-4">

          <div className="rounded-xl p-4 space-y-3" style={glass}>
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-bold text-slate-200">Eventos en tiempo real</h2>
              <div className="flex items-center gap-2">
                {liveEvents.length > 0 && (
                  <>
                    <button onClick={() => exportLiveEvents(liveEvents, 'csv')}
                            className="text-[9px] font-bold text-green-400 px-2 py-1 rounded"
                            style={{ background: 'rgba(74,222,128,0.08)', border: '1px solid rgba(74,222,128,0.2)' }}>
                      CSV
                    </button>
                    <button onClick={() => exportLiveEvents(liveEvents, 'json')}
                            className="text-[9px] font-bold text-violet-400 px-2 py-1 rounded"
                            style={{ background: 'rgba(167,139,250,0.08)', border: '1px solid rgba(167,139,250,0.2)' }}>
                      JSON
                    </button>
                    <button onClick={() => setLiveEvents([])}
                            className="text-[9px] text-slate-600 hover:text-slate-400 px-2 py-1 rounded"
                            style={{ border: '1px solid rgba(255,255,255,0.06)' }}>
                      Limpiar
                    </button>
                  </>
                )}
                <span className="flex items-center gap-1 text-[10px]"
                      style={{ color: liveConnected ? '#4ade80' : '#ef4444' }}>
                  <span className="w-1.5 h-1.5 rounded-full"
                        style={{ background: liveConnected ? '#4ade80' : '#ef4444',
                                 animation: liveConnected ? 'pulse 2s infinite' : undefined }} />
                  {liveConnected ? 'En vivo' : 'Desconectado'}
                </span>
              </div>
            </div>

            {liveEvents.length === 0 ? (
              <div className="py-10 text-center">
                <p className="text-slate-600 text-sm">Esperando eventos...</p>
                <p className="text-slate-700 text-xs mt-1">Los eventos aparecen cuando se ingestan logs o se sincronizan feeds.</p>
              </div>
            ) : (
              <div className="space-y-1.5 max-h-[520px] overflow-y-auto font-mono">
                {liveEvents.map((ev, i) => <EventRow key={i} ev={ev} />)}
              </div>
            )}
          </div>

          <div className="space-y-3">
            {/* Legend */}
            <div className="rounded-xl p-4 space-y-3" style={glass}>
              <h2 className="text-sm font-bold text-slate-200">Tipos de eventos</h2>
              {[
                { type: 'log_ingested',  desc: 'Batch de logs procesado (ingest)' },
                { type: 'feed_synced',   desc: 'Feed CTI sincronizado con nuevos IOCs' },
                { type: 'ioc_added',     desc: 'IOC individual persistido en la BD' },
              ].map(e => {
                const color = EVENT_COLOR[e.type]
                return (
                  <div key={e.type} className="flex items-start gap-2">
                    <span className="w-2 h-2 rounded-full mt-0.5 shrink-0" style={{ background: color }} />
                    <div>
                      <p className="text-[10px] font-bold font-mono" style={{ color }}>{e.type}</p>
                      <p className="text-[9px] text-slate-600">{e.desc}</p>
                    </div>
                  </div>
                )
              })}
            </div>

            {/* SSE endpoint info */}
            <div className="rounded-xl p-4 space-y-2" style={glass}>
              <p className="text-[9px] font-bold text-slate-600 uppercase tracking-wider">Endpoint SSE</p>
              <code className="text-[10px] text-cyan-400 font-mono block">GET /live/feed</code>
              <code className="text-[10px] text-violet-400 font-mono block">GET /live/export?format=csv</code>
              <p className="text-[10px] text-slate-500">
                Se puede consumir desde Python, Node.js o cualquier cliente SSE.
                Incluye replay de los últimos 100 eventos al conectar.
              </p>
              <div className="rounded-lg p-2.5" style={{ background: '#050a14', border: '1px solid rgba(255,255,255,0.06)' }}>
                <pre className="text-[9px] text-green-400 font-mono">{`import sseclient, requests
r = requests.get("${API}/live/feed", stream=True)
for ev in sseclient.SSEClient(r):
    print(ev.data)`}</pre>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

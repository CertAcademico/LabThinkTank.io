import { useState, useEffect } from 'react'

const API_URL = import.meta.env.VITE_API_URL ?? 'http://127.0.0.1:8000'

const glass = {
  background: 'rgba(15,23,42,0.55)',
  backdropFilter: 'blur(16px)',
  border: '1px solid rgba(255,255,255,0.07)',
  borderRadius: 12,
}

// ── Types ─────────────────────────────────────────────────────────────────────

interface IoacatalogEntry {
  ttp: string; name: string; tactic: string
  ioa: string; detection_rule: string; priority: string
}

interface DepurationResult {
  ttp: string; tactic: string; ioa_description: string; detection_rule: string; ioc_value: string
  cti_stage: string; cti_confidence: number
  ioc_lifecycle: { stage: string; days_active: number; ttl_days: number; confidence: number; note: string }
  ioa_lifecycle: { stage: string; coverage: string; desc: string }
  defend: { id: string; name: string; type: string; desc: string }[]
  rule_approved: boolean
  blockers: string[]; warnings: string[]
  recommendation: string
}

// ── Small helpers ──────────────────────────────────────────────────────────────

const STAGE_COLORS: Record<string, { color: string; bg: string; border: string }> = {
  activo:       { color: '#4ade80', bg: 'rgba(74,222,128,0.1)',  border: 'rgba(74,222,128,0.3)'  },
  envejeciendo: { color: '#facc15', bg: 'rgba(250,204,21,0.1)',  border: 'rgba(250,204,21,0.3)'  },
  estale:       { color: '#f97316', bg: 'rgba(249,115,22,0.1)',  border: 'rgba(249,115,22,0.3)'  },
  deprecado:    { color: '#ef4444', bg: 'rgba(239,68,68,0.1)',   border: 'rgba(239,68,68,0.3)'   },
  inactivo:     { color: '#ef4444', bg: 'rgba(239,68,68,0.1)',   border: 'rgba(239,68,68,0.3)'   },
}

const DEFEND_TYPE_COLOR: Record<string, string> = {
  Detectar:  '#22d3ee',
  Aislar:    '#f97316',
  Endurecer: '#a78bfa',
}

const PRIORITY_COLOR: Record<string, string> = {
  critical: '#ef4444', high: '#f97316', medium: '#facc15', low: '#4ade80',
}

const IOC_TYPES = ['ip', 'domain', 'url', 'hash', 'email']
const SEVERITIES = ['critical', 'high', 'medium', 'low']

function StageChip({ label, color }: { label: string; color: string }) {
  const s = STAGE_COLORS[label] ?? STAGE_COLORS.envejeciendo
  return (
    <span className="text-[10px] font-bold px-2.5 py-0.5 rounded-full uppercase tracking-wide"
          style={{ background: s.bg, border: `1px solid ${s.border}`, color: s.color }}>
      {label}
    </span>
  )
}

function ConfBar({ score }: { score: number }) {
  const color = score >= 70 ? '#4ade80' : score >= 40 ? '#facc15' : '#ef4444'
  return (
    <div className="flex items-center gap-2 w-full">
      <div className="flex-1 h-1.5 rounded-full" style={{ background: 'rgba(255,255,255,0.08)' }}>
        <div className="h-1.5 rounded-full transition-all duration-700" style={{ width: `${score}%`, background: color }} />
      </div>
      <span className="text-[10px] font-mono shrink-0" style={{ color }}>{score}%</span>
    </div>
  )
}

// ── Pipeline step card ─────────────────────────────────────────────────────────

function PipelineStep({
  step, title, icon, pass, children,
}: {
  step: number; title: string; icon: string; pass: boolean | null; children: React.ReactNode
}) {
  const borderColor = pass === null ? 'rgba(255,255,255,0.1)'
    : pass ? 'rgba(74,222,128,0.4)' : 'rgba(239,68,68,0.4)'
  const dotColor = pass === null ? '#475569' : pass ? '#4ade80' : '#ef4444'

  return (
    <div className="rounded-xl p-4 space-y-3" style={{ ...glass, border: `1px solid ${borderColor}` }}>
      <div className="flex items-center gap-3">
        <div className="w-7 h-7 rounded-full flex items-center justify-center text-sm shrink-0"
             style={{ background: `${dotColor}18`, border: `1px solid ${dotColor}44` }}>
          <span>{icon}</span>
        </div>
        <div className="flex-1">
          <div className="flex items-center gap-2">
            <span className="text-[10px] font-mono text-slate-600">ETAPA {step}</span>
            {pass !== null && (
              <span className="text-[9px] font-bold px-1.5 py-0.5 rounded uppercase"
                    style={{ background: pass ? 'rgba(74,222,128,0.1)' : 'rgba(239,68,68,0.1)',
                             color: pass ? '#4ade80' : '#ef4444' }}>
                {pass ? 'OK' : 'BLOQUEADO'}
              </span>
            )}
          </div>
          <p className="text-xs font-semibold text-slate-200">{title}</p>
        </div>
      </div>
      <div className="space-y-2">{children}</div>
    </div>
  )
}

// ── Main component ─────────────────────────────────────────────────────────────

export default function RuleDepuration() {
  const [catalog, setCatalog]   = useState<IoacatalogEntry[]>([])
  const [selTtp,  setSelTtp]    = useState('')
  const [iocVal,  setIocVal]    = useState('')
  const [iocType, setIocType]   = useState('ip')
  const [severity, setSeverity] = useState('high')
  const [loading, setLoading]   = useState(false)
  const [result,  setResult]    = useState<DepurationResult | null>(null)

  const selectStyle = {
    background: 'rgba(255,255,255,0.05)',
    border: '1px solid rgba(255,255,255,0.1)',
    borderRadius: 8,
    color: '#e2e8f0',
    outline: 'none',
    padding: '8px 12px',
    fontSize: 12,
    width: '100%',
  }

  useEffect(() => {
    fetch(`${API_URL}/rules/ioa-catalog`)
      .then(r => r.json())
      .then(setCatalog)
      .catch(() => {})
  }, [])

  const selectedMeta = catalog.find(c => c.ttp === selTtp)

  async function runDepuration() {
    if (!selTtp) return
    setLoading(true); setResult(null)
    try {
      const res = await fetch(`${API_URL}/rules/depurate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ttp:          selTtp,
          ioc_value:    iocVal,
          ioc_type:     iocType,
          severity:     severity,
          ioa_priority: selectedMeta?.priority ?? severity,
        }),
      })
      setResult(await res.json())
    } catch { /* silent */ } finally { setLoading(false) }
  }

  // Compute per-step pass/fail from result
  const step1Pass = result ? (result.cti_stage !== 'inactivo') : null
  const step2Pass = result ? (result.ioc_lifecycle.stage !== 'deprecado' && result.ioc_lifecycle.confidence >= 40) : null
  const step3Pass = result ? true : null  // IoA lifecycle is always informational
  const step4Pass = result ? (result.defend.length > 0) : null

  return (
    <div className="space-y-5">

      {/* Header */}
      <div>
        <h2 className="text-base font-semibold text-slate-100">Pipeline de Depuración de Reglas</h2>
        <p className="text-xs text-slate-500 mt-0.5">
          Valida un indicador a través del ciclo de vida CTI → IoC → IoA → D3FEND antes de desplegar una regla de detección.
        </p>
      </div>

      {/* Selector panel */}
      <div className="rounded-xl p-5 space-y-4" style={glass}>
        <p className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">Configurar análisis</p>

        <div className="grid grid-cols-2 gap-4">
          {/* TTP selector */}
          <div className="col-span-2 space-y-1.5">
            <label className="text-[10px] text-slate-500 uppercase tracking-wide font-semibold">Técnica ATT&CK (TTP)</label>
            <select value={selTtp} onChange={e => { setSelTtp(e.target.value); setResult(null) }} style={selectStyle}>
              <option value="">Selecciona una técnica...</option>
              {catalog.map(c => (
                <option key={c.ttp} value={c.ttp}>
                  {c.ttp} — {c.name} ({c.tactic})
                </option>
              ))}
            </select>
          </div>

          {/* IoC value */}
          <div className="space-y-1.5">
            <label className="text-[10px] text-slate-500 uppercase tracking-wide font-semibold">Valor del IoC (opcional)</label>
            <input
              value={iocVal}
              onChange={e => setIocVal(e.target.value)}
              placeholder="185.220.101.1 / evil.com / hash..."
              className="w-full rounded-lg px-3 py-2 text-xs text-slate-200 outline-none"
              style={{ background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)' }}
            />
          </div>

          {/* IoC type */}
          <div className="space-y-1.5">
            <label className="text-[10px] text-slate-500 uppercase tracking-wide font-semibold">Tipo de IoC</label>
            <select value={iocType} onChange={e => setIocType(e.target.value)} style={selectStyle}>
              {IOC_TYPES.map(t => <option key={t} value={t}>{t.toUpperCase()}</option>)}
            </select>
          </div>

          {/* Severity */}
          <div className="space-y-1.5">
            <label className="text-[10px] text-slate-500 uppercase tracking-wide font-semibold">Severidad observada</label>
            <select value={severity} onChange={e => setSeverity(e.target.value)} style={selectStyle}>
              {SEVERITIES.map(s => <option key={s} value={s}>{s.toUpperCase()}</option>)}
            </select>
          </div>

          {/* Selected IoA preview */}
          {selectedMeta && (
            <div className="col-span-2 rounded-lg p-3 space-y-1"
                 style={{ background: 'rgba(167,139,250,0.06)', border: '1px solid rgba(167,139,250,0.15)' }}>
              <div className="flex items-center gap-2">
                <span className="text-[9px] font-bold px-1.5 py-0.5 rounded uppercase"
                      style={{ background: 'rgba(167,139,250,0.15)', color: '#a78bfa' }}>
                  IoA seleccionada
                </span>
                <span className="text-[10px] font-mono"
                      style={{ color: PRIORITY_COLOR[selectedMeta.priority] ?? '#facc15' }}>
                  {selectedMeta.priority.toUpperCase()}
                </span>
              </div>
              <p className="text-[11px] text-slate-300 leading-relaxed">{selectedMeta.ioa}</p>
            </div>
          )}
        </div>

        <button
          onClick={runDepuration}
          disabled={loading || !selTtp}
          className="w-full py-2.5 rounded-xl text-sm font-bold transition-all disabled:opacity-40"
          style={{ background: 'rgba(34,211,238,0.12)', border: '1px solid rgba(34,211,238,0.3)', color: '#22d3ee' }}>
          {loading ? 'Analizando pipeline...' : 'Ejecutar depuración →'}
        </button>
      </div>

      {/* Pipeline stages */}
      {result && (
        <>
          {/* Flow diagram */}
          <div className="flex items-center gap-1 overflow-x-auto pb-1">
            {[
              { label: 'CTI',       pass: step1Pass },
              { label: 'IoC',       pass: step2Pass },
              { label: 'IoA',       pass: step3Pass },
              { label: 'D3FEND',    pass: step4Pass },
              { label: result.rule_approved ? 'APROBADA' : 'BLOQUEADA', pass: result.rule_approved },
            ].map((node, i) => (
              <div key={i} className="flex items-center gap-1 shrink-0">
                {i > 0 && (
                  <div className="w-6 h-px" style={{ background: 'rgba(255,255,255,0.15)' }} />
                )}
                <div className="px-3 py-1.5 rounded-lg text-[10px] font-bold uppercase"
                     style={{
                       background: node.pass === null ? 'rgba(255,255,255,0.05)'
                         : node.pass ? 'rgba(74,222,128,0.12)' : 'rgba(239,68,68,0.12)',
                       border: `1px solid ${node.pass === null ? 'rgba(255,255,255,0.1)'
                         : node.pass ? 'rgba(74,222,128,0.35)' : 'rgba(239,68,68,0.35)'}`,
                       color: node.pass === null ? '#475569'
                         : node.pass ? '#4ade80' : '#ef4444',
                     }}>
                  {node.label}
                </div>
              </div>
            ))}
          </div>

          <div className="grid grid-cols-2 gap-3">

            {/* Step 1 — CTI */}
            <PipelineStep step={1} title="Contexto CTI" icon="🧠" pass={step1Pass}>
              <div className="flex items-center justify-between">
                <span className="text-[11px] text-slate-400">Estado general</span>
                <StageChip label={result.cti_stage} color="#22d3ee" />
              </div>
              <div className="space-y-1">
                <span className="text-[10px] text-slate-600 uppercase tracking-wide">Confianza CTI</span>
                <ConfBar score={result.cti_confidence} />
              </div>
              {result.ioc_value && (
                <div className="flex items-center gap-2">
                  <span className="text-[10px] text-slate-600">IoC:</span>
                  <span className="font-mono text-[10px] text-cyan-400 truncate">{result.ioc_value}</span>
                </div>
              )}
              <div className="flex items-center gap-2">
                <span className="text-[10px] text-slate-600">Táctica:</span>
                <span className="text-[10px] text-violet-400">{result.tactic || '—'}</span>
              </div>
            </PipelineStep>

            {/* Step 2 — IoC Lifecycle */}
            <PipelineStep step={2} title="Ciclo de Vida del IoC" icon="📍" pass={step2Pass}>
              <div className="flex items-center justify-between">
                <span className="text-[11px] text-slate-400">Estado</span>
                <StageChip label={result.ioc_lifecycle.stage} color="#22d3ee" />
              </div>
              <div className="grid grid-cols-3 gap-1 text-center">
                {[
                  { label: 'Días activo', val: result.ioc_lifecycle.days_active || '—' },
                  { label: 'TTL (días)',  val: result.ioc_lifecycle.ttl_days },
                  { label: 'Confianza',  val: `${result.ioc_lifecycle.confidence}%` },
                ].map(m => (
                  <div key={m.label} className="rounded-lg p-2"
                       style={{ background: 'rgba(255,255,255,0.04)' }}>
                    <div className="text-sm font-bold text-slate-200">{m.val}</div>
                    <div className="text-[9px] text-slate-600 uppercase">{m.label}</div>
                  </div>
                ))}
              </div>
              <p className="text-[10px] text-slate-500 italic">{result.ioc_lifecycle.note}</p>
            </PipelineStep>

            {/* Step 3 — IoA Lifecycle */}
            <PipelineStep step={3} title="Ciclo de Vida del IoA" icon="🎯" pass={step3Pass}>
              <div className="flex items-center justify-between flex-wrap gap-2">
                <div>
                  <span className="text-[10px] text-slate-600 block uppercase tracking-wide mb-1">Etapa de detección</span>
                  <span className="text-xs font-bold text-slate-200 capitalize">{result.ioa_lifecycle.stage}</span>
                </div>
                <div className="text-right">
                  <span className="text-[10px] text-slate-600 block uppercase tracking-wide mb-1">Cobertura</span>
                  <span className="text-xs font-bold"
                        style={{ color: result.ioa_lifecycle.coverage === 'alta' ? '#4ade80'
                          : result.ioa_lifecycle.coverage === 'media' ? '#facc15' : '#f87171' }}>
                    {result.ioa_lifecycle.coverage}
                  </span>
                </div>
              </div>
              <p className="text-[10px] text-slate-500 leading-relaxed">{result.ioa_lifecycle.desc}</p>
              {result.ioa_description && (
                <div className="rounded-lg p-2.5" style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.06)' }}>
                  <p className="text-[10px] text-slate-400 leading-relaxed">{result.ioa_description}</p>
                </div>
              )}
            </PipelineStep>

            {/* Step 4 — D3FEND */}
            <PipelineStep step={4} title="MITRE D3FEND — Contramedidas" icon="🛡️" pass={step4Pass}>
              {result.defend.length === 0 ? (
                <p className="text-[11px] text-slate-600">Sin contramedidas mapeadas para {result.ttp}</p>
              ) : (
                <div className="space-y-2">
                  {result.defend.map(d => (
                    <div key={d.id} className="rounded-lg p-2.5 space-y-0.5"
                         style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.06)' }}>
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-[9px] text-slate-600">{d.id}</span>
                        <span className="text-[10px] font-semibold text-slate-200">{d.name}</span>
                        <span className="ml-auto text-[9px] font-bold px-1.5 py-0.5 rounded-full"
                              style={{ background: `${DEFEND_TYPE_COLOR[d.type] ?? '#a78bfa'}15`,
                                       color: DEFEND_TYPE_COLOR[d.type] ?? '#a78bfa',
                                       border: `1px solid ${DEFEND_TYPE_COLOR[d.type] ?? '#a78bfa'}30` }}>
                          {d.type}
                        </span>
                      </div>
                      <p className="text-[10px] text-slate-500 leading-relaxed">{d.desc}</p>
                    </div>
                  ))}
                </div>
              )}
            </PipelineStep>
          </div>

          {/* Final verdict */}
          <div className="rounded-xl p-5 space-y-3"
               style={{
                 ...glass,
                 border: `1px solid ${result.rule_approved ? 'rgba(74,222,128,0.4)' : 'rgba(239,68,68,0.4)'}`,
               }}>
            <div className="flex items-center gap-3">
              <span className="text-2xl">{result.rule_approved ? '✅' : '🚫'}</span>
              <div>
                <p className="text-sm font-bold" style={{ color: result.rule_approved ? '#4ade80' : '#ef4444' }}>
                  {result.rule_approved ? 'REGLA APROBADA' : 'REGLA BLOQUEADA'}
                </p>
                <p className="text-[11px] text-slate-400 leading-relaxed mt-0.5">{result.recommendation}</p>
              </div>
            </div>

            {/* Blockers */}
            {result.blockers.length > 0 && (
              <div className="space-y-1">
                {result.blockers.map((b, i) => (
                  <div key={i} className="flex items-start gap-2 rounded-lg px-3 py-2"
                       style={{ background: 'rgba(239,68,68,0.07)', border: '1px solid rgba(239,68,68,0.2)' }}>
                    <span className="text-red-400 shrink-0 text-xs">✕</span>
                    <p className="text-[11px] text-red-300">{b}</p>
                  </div>
                ))}
              </div>
            )}

            {/* Warnings */}
            {result.warnings.length > 0 && (
              <div className="space-y-1">
                {result.warnings.map((w, i) => (
                  <div key={i} className="flex items-start gap-2 rounded-lg px-3 py-2"
                       style={{ background: 'rgba(250,204,21,0.07)', border: '1px solid rgba(250,204,21,0.2)' }}>
                    <span className="text-yellow-400 shrink-0 text-xs">⚠</span>
                    <p className="text-[11px] text-yellow-200">{w}</p>
                  </div>
                ))}
              </div>
            )}

            {/* Detection rule */}
            {result.detection_rule && (
              <div className="space-y-1.5">
                <p className="text-[10px] text-slate-600 uppercase tracking-widest font-semibold">Regla de detección</p>
                <pre className="text-[10px] leading-relaxed rounded-lg px-4 py-3 overflow-x-auto whitespace-pre-wrap break-all"
                     style={{ background: 'rgba(0,0,0,0.35)', border: '1px solid rgba(255,255,255,0.07)', color: '#22d3ee' }}>
                  {result.detection_rule}
                </pre>
              </div>
            )}
          </div>
        </>
      )}

      {!result && !loading && (
        <div className="text-center py-10 text-slate-700 text-xs">
          Selecciona una técnica ATT&CK y ejecuta el análisis para iniciar el pipeline de depuración.
        </div>
      )}
    </div>
  )
}

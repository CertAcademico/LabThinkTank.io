import { useState, useEffect, useRef, useCallback } from 'react'
import { useAuth } from '../contexts/AuthContext'

const API = import.meta.env.VITE_API_URL ?? 'http://127.0.0.1:8000'

// ── Types ─────────────────────────────────────────────────────────────────────

interface IocItem    { ioc: string; type: string; severity: string; threat_actor: string; mitre: string; country: string }
interface ActorItem  { name: string; country: string; severity: string; active_campaign: string; motivation: string }
interface CampItem   { name: string; actor: string; status: string; last_activity: string; ioc_count: number }
interface TtpItem    { ttp: string; ttp_name: string; tactic: string; priority: string; attributed_actor: string }

interface Results {
  iocs:      IocItem[]
  actors:    ActorItem[]
  campaigns: CampItem[]
  ttps:      TtpItem[]
}

type ViewId = 'overview' | 'graph' | 'copilot' | 'attack' | 'timeline' | 'ioc' | 'feeds' | 'sandbox' | 'retos'

interface Props {
  onNavigate: (view: ViewId) => void
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const SEV: Record<string, string> = {
  critical: '#ef4444', high: '#f97316', medium: '#facc15', low: '#4ade80',
}

const TYPE_ICON: Record<string, string> = {
  IP: '🌐', DOMAIN: '🔗', HASH: '#️⃣', URL: '📎',
}

function highlight(text: string, q: string) {
  if (!q || !text) return <>{text}</>
  const idx = text.toLowerCase().indexOf(q.toLowerCase())
  if (idx === -1) return <>{text}</>
  return (
    <>
      {text.slice(0, idx)}
      <mark className="rounded px-0.5" style={{ background: 'rgba(34,211,238,0.3)', color: '#22d3ee' }}>
        {text.slice(idx, idx + q.length)}
      </mark>
      {text.slice(idx + q.length)}
    </>
  )
}

function copyToClipboard(text: string) {
  navigator.clipboard.writeText(text).catch(() => {})
}

// ── Component ─────────────────────────────────────────────────────────────────

export default function IOCSearch({ onNavigate }: Props) {
  const { token }                    = useAuth()
  const [open,     setOpen]          = useState(false)
  const [query,    setQuery]         = useState('')
  const [results,  setResults]       = useState<Results | null>(null)
  const [loading,  setLoading]       = useState(false)
  const [cursor,   setCursor]        = useState(-1)
  const [copied,   setCopied]        = useState<string | null>(null)
  const inputRef   = useRef<HTMLInputElement>(null)
  const panelRef   = useRef<HTMLDivElement>(null)
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  // Open on / or Cmd+K
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.key === 'k' && (e.metaKey || e.ctrlKey)) || (e.key === '/' && !['INPUT','TEXTAREA'].includes((e.target as HTMLElement).tagName))) {
        e.preventDefault()
        setOpen(true)
        setTimeout(() => inputRef.current?.focus(), 50)
      }
      if (e.key === 'Escape') { setOpen(false); setQuery('') }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  // Close on outside click
  useEffect(() => {
    const onClick = (e: MouseEvent) => {
      if (panelRef.current && !panelRef.current.contains(e.target as Node)) {
        setOpen(false)
      }
    }
    if (open) document.addEventListener('mousedown', onClick)
    return () => document.removeEventListener('mousedown', onClick)
  }, [open])

  // Debounced search
  const doSearch = useCallback(async (q: string) => {
    if (q.trim().length < 2) { setResults(null); return }
    setLoading(true)
    try {
      const r = await fetch(`${API}/search?q=${encodeURIComponent(q)}`, {
        headers: { Authorization: `Bearer ${token}` },
      })
      setResults(await r.json())
    } catch { setResults(null) }
    finally { setLoading(false) }
  }, [token])

  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current)
    debounceRef.current = setTimeout(() => doSearch(query), 280)
    return () => { if (debounceRef.current) clearTimeout(debounceRef.current) }
  }, [query, doSearch])

  // Flatten results for keyboard nav
  const flat: { type: string; label: string; action: () => void }[] = []
  if (results) {
    results.iocs.forEach(i => flat.push({ type: 'ioc', label: i.ioc, action: () => { onNavigate('ioc'); close() } }))
    results.actors.forEach(a => flat.push({ type: 'actor', label: a.name, action: () => { onNavigate('graph'); close() } }))
    results.campaigns.forEach(c => flat.push({ type: 'campaign', label: c.name, action: () => { onNavigate('timeline'); close() } }))
    results.ttps.forEach(t => flat.push({ type: 'ttp', label: `${t.ttp} – ${t.ttp_name}`, action: () => { onNavigate('attack'); close() } }))
  }

  const close = () => { setOpen(false); setQuery(''); setResults(null); setCursor(-1) }

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); setCursor(c => Math.min(c + 1, flat.length - 1)) }
    if (e.key === 'ArrowUp')   { e.preventDefault(); setCursor(c => Math.max(c - 1, 0)) }
    if (e.key === 'Enter' && cursor >= 0 && flat[cursor]) flat[cursor].action()
    if (e.key === 'Escape') close()
  }

  const copy = (text: string, e: React.MouseEvent) => {
    e.stopPropagation()
    copyToClipboard(text)
    setCopied(text)
    setTimeout(() => setCopied(null), 1500)
  }

  const totalResults = results ? (results.iocs.length + results.actors.length + results.campaigns.length + results.ttps.length) : 0
  const hasResults   = totalResults > 0

  return (
    <div className="relative" ref={panelRef}>

      {/* ── Trigger bar ─────────────────────────────────────────────────── */}
      <button
        onClick={() => { setOpen(true); setTimeout(() => inputRef.current?.focus(), 50) }}
        className="flex items-center gap-2 rounded-lg border px-3 py-1.5 text-xs text-slate-500 transition-colors hover:border-cyan-500/30 hover:text-slate-400"
        style={{ background: 'rgba(255,255,255,0.03)', borderColor: open ? 'rgba(34,211,238,0.3)' : 'rgba(255,255,255,0.06)', minWidth: 200 }}>
        <svg viewBox="0 0 24 24" className="w-3.5 h-3.5 shrink-0" fill="none" stroke="currentColor" strokeWidth="2">
          <circle cx="11" cy="11" r="8" /><path d="m21 21-4.35-4.35" />
        </svg>
        <span className="flex-1 text-left truncate">{query || 'Buscar IOC, actor, TTP…'}</span>
        <kbd className="hidden sm:inline text-[9px] px-1 py-0.5 rounded font-mono"
             style={{ background: 'rgba(255,255,255,0.06)', border: '1px solid rgba(255,255,255,0.1)' }}>
          ⌘K
        </kbd>
      </button>

      {/* ── Dropdown panel ──────────────────────────────────────────────── */}
      {open && (
        <div className="absolute top-full right-0 mt-2 w-[520px] rounded-2xl overflow-hidden shadow-2xl z-50"
             style={{
               background: 'rgba(8,12,25,0.98)',
               border: '1px solid rgba(34,211,238,0.2)',
               backdropFilter: 'blur(24px)',
             }}>

          {/* Input */}
          <div className="flex items-center gap-3 px-4 py-3 border-b"
               style={{ borderColor: 'rgba(255,255,255,0.07)' }}>
            <svg viewBox="0 0 24 24" className="w-4 h-4 text-cyan-400 shrink-0" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="11" cy="11" r="8" /><path d="m21 21-4.35-4.35" />
            </svg>
            <input
              ref={inputRef}
              value={query}
              onChange={e => { setQuery(e.target.value); setCursor(-1) }}
              onKeyDown={onKeyDown}
              placeholder="Buscar IOC, actor, campaña, TTP, MITRE…"
              autoComplete="off"
              spellCheck={false}
              className="flex-1 bg-transparent text-sm text-slate-100 placeholder-slate-600 outline-none"
            />
            {loading && (
              <div className="w-4 h-4 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin shrink-0" />
            )}
            <button onClick={close}
                    className="text-slate-700 hover:text-slate-400 transition-colors shrink-0 text-xs">
              Esc
            </button>
          </div>

          {/* Empty state */}
          {!query && (
            <div className="px-4 py-6 text-center space-y-1">
              <p className="text-xs text-slate-600">Escribe mínimo 2 caracteres para buscar</p>
              <p className="text-[10px] text-slate-700">IOC · Actores · Campañas · TTPs · MITRE · País</p>
            </div>
          )}

          {/* No results */}
          {query.length >= 2 && !loading && results && !hasResults && (
            <div className="px-4 py-6 text-center">
              <p className="text-xs text-slate-600">Sin resultados para "<span className="text-slate-400">{query}</span>"</p>
              <p className="text-[10px] text-slate-700 mt-1">Intenta con IP, dominio, hash, actor o código MITRE (ej: T1059)</p>
            </div>
          )}

          {/* Results */}
          {hasResults && (
            <div className="overflow-y-auto" style={{ maxHeight: 440 }}>

              {/* ── IOCs ────────────────────────────────────────────────── */}
              {results!.iocs.length > 0 && (
                <Section label="IOCs" count={results!.iocs.length} color="#22d3ee">
                  {results!.iocs.map((ioc, i) => {
                    const flatIdx = i
                    return (
                      <ResultRow
                        key={ioc.ioc}
                        active={cursor === flatIdx}
                        onClick={() => { onNavigate('ioc'); close() }}>
                        <span className="text-base shrink-0">{TYPE_ICON[ioc.type] ?? '🔍'}</span>
                        <div className="flex-1 min-w-0">
                          <p className="text-xs font-mono text-slate-200 truncate">
                            {highlight(ioc.ioc, query)}
                          </p>
                          <div className="flex items-center gap-2 mt-0.5 flex-wrap">
                            <span className="text-[9px]" style={{ color: SEV[ioc.severity] ?? '#64748b' }}>
                              ● {ioc.severity}
                            </span>
                            <span className="text-[9px] text-slate-600">{ioc.type}</span>
                            <span className="text-[9px] text-slate-600">
                              {highlight(ioc.threat_actor, query)}
                            </span>
                            {ioc.mitre && (
                              <span className="text-[9px] font-mono text-slate-700">
                                {highlight(ioc.mitre, query)}
                              </span>
                            )}
                            <span className="text-[9px] text-slate-700">{ioc.country}</span>
                          </div>
                        </div>
                        <button
                          onClick={e => copy(ioc.ioc, e)}
                          className="shrink-0 text-[9px] px-2 py-0.5 rounded transition-colors"
                          style={{
                            background: copied === ioc.ioc ? 'rgba(74,222,128,0.12)' : 'rgba(255,255,255,0.05)',
                            border: '1px solid rgba(255,255,255,0.08)',
                            color: copied === ioc.ioc ? '#4ade80' : '#475569',
                          }}>
                          {copied === ioc.ioc ? '✓ Copiado' : 'Copiar'}
                        </button>
                      </ResultRow>
                    )
                  })}
                </Section>
              )}

              {/* ── Actores ─────────────────────────────────────────────── */}
              {results!.actors.length > 0 && (
                <Section label="Actores de Amenaza" count={results!.actors.length} color="#a78bfa">
                  {results!.actors.map((a, i) => {
                    const flatIdx = results!.iocs.length + i
                    return (
                      <ResultRow
                        key={a.name}
                        active={cursor === flatIdx}
                        onClick={() => { onNavigate('graph'); close() }}>
                        <span className="text-base shrink-0">🎭</span>
                        <div className="flex-1 min-w-0">
                          <p className="text-xs font-semibold text-slate-200">
                            {highlight(a.name, query)}
                          </p>
                          <div className="flex items-center gap-2 mt-0.5">
                            <span className="text-[9px]" style={{ color: SEV[a.severity] ?? '#64748b' }}>
                              ● {a.severity}
                            </span>
                            <span className="text-[9px] text-slate-600">{a.country}</span>
                            <span className="text-[9px] text-slate-600 truncate">{a.active_campaign}</span>
                          </div>
                        </div>
                        <span className="text-[9px] px-1.5 py-0.5 rounded shrink-0"
                              style={{ background: 'rgba(167,139,250,0.1)', color: '#a78bfa' }}>
                          → Threat Graph
                        </span>
                      </ResultRow>
                    )
                  })}
                </Section>
              )}

              {/* ── Campañas ────────────────────────────────────────────── */}
              {results!.campaigns.length > 0 && (
                <Section label="Campañas" count={results!.campaigns.length} color="#f97316">
                  {results!.campaigns.map((c, i) => {
                    const flatIdx = results!.iocs.length + results!.actors.length + i
                    return (
                      <ResultRow
                        key={c.name}
                        active={cursor === flatIdx}
                        onClick={() => { onNavigate('timeline'); close() }}>
                        <span className="text-base shrink-0">🎯</span>
                        <div className="flex-1 min-w-0">
                          <p className="text-xs font-semibold text-slate-200">
                            {highlight(c.name, query)}
                          </p>
                          <div className="flex items-center gap-2 mt-0.5">
                            <span className="text-[9px] text-slate-600">{highlight(c.actor, query)}</span>
                            <span className="text-[9px]"
                                  style={{ color: c.status === 'active' ? '#4ade80' : '#475569' }}>
                              {c.status}
                            </span>
                            <span className="text-[9px] text-slate-700">{c.ioc_count} IOCs</span>
                          </div>
                        </div>
                        <span className="text-[9px] px-1.5 py-0.5 rounded shrink-0"
                              style={{ background: 'rgba(249,115,22,0.1)', color: '#f97316' }}>
                          → Timeline
                        </span>
                      </ResultRow>
                    )
                  })}
                </Section>
              )}

              {/* ── TTPs / MITRE ─────────────────────────────────────────── */}
              {results!.ttps.length > 0 && (
                <Section label="TTPs / MITRE ATT&CK" count={results!.ttps.length} color="#facc15">
                  {results!.ttps.map((t, i) => {
                    const flatIdx = results!.iocs.length + results!.actors.length + results!.campaigns.length + i
                    return (
                      <ResultRow
                        key={t.ttp}
                        active={cursor === flatIdx}
                        onClick={() => { onNavigate('attack'); close() }}>
                        <span className="text-base shrink-0">🛡️</span>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2">
                            <span className="text-[10px] font-bold font-mono"
                                  style={{ color: '#facc15' }}>
                              {highlight(t.ttp, query)}
                            </span>
                            <span className="text-xs text-slate-300 truncate">
                              {highlight(t.ttp_name, query)}
                            </span>
                          </div>
                          <div className="flex items-center gap-2 mt-0.5">
                            <span className="text-[9px] text-slate-600">
                              {highlight(t.tactic, query)}
                            </span>
                            <span className="text-[9px]" style={{ color: SEV[t.priority] ?? '#64748b' }}>
                              ● {t.priority}
                            </span>
                            <span className="text-[9px] text-slate-700">{t.attributed_actor}</span>
                          </div>
                        </div>
                        <span className="text-[9px] px-1.5 py-0.5 rounded shrink-0"
                              style={{ background: 'rgba(250,204,21,0.1)', color: '#facc15' }}>
                          → ATT&CK
                        </span>
                      </ResultRow>
                    )
                  })}
                </Section>
              )}

              {/* Footer */}
              <div className="px-4 py-2 border-t flex items-center justify-between"
                   style={{ borderColor: 'rgba(255,255,255,0.05)' }}>
                <span className="text-[9px] text-slate-700">
                  {totalResults} resultado{totalResults !== 1 ? 's' : ''} para "{query}"
                </span>
                <div className="flex items-center gap-2 text-[9px] text-slate-700">
                  <span>↑↓ navegar</span>
                  <span>⏎ ir</span>
                  <span>Esc cerrar</span>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// ── Sub-components ────────────────────────────────────────────────────────────

function Section({ label, count, color, children }: {
  label: string; count: number; color: string; children: React.ReactNode
}) {
  return (
    <div>
      <div className="flex items-center gap-2 px-4 py-1.5"
           style={{ background: 'rgba(255,255,255,0.02)' }}>
        <span className="text-[9px] font-bold uppercase tracking-widest" style={{ color }}>
          {label}
        </span>
        <span className="text-[9px] font-mono px-1.5 py-0.5 rounded"
              style={{ background: `${color}15`, color }}>
          {count}
        </span>
      </div>
      <div className="divide-y divide-white/[0.03]">{children}</div>
    </div>
  )
}

function ResultRow({ children, active, onClick }: {
  children: React.ReactNode; active: boolean; onClick: () => void
}) {
  return (
    <div
      onClick={onClick}
      className="flex items-center gap-3 px-4 py-2.5 cursor-pointer transition-colors"
      style={{ background: active ? 'rgba(34,211,238,0.06)' : 'transparent' }}
      onMouseEnter={e => { if (!active) (e.currentTarget as HTMLElement).style.background = 'rgba(255,255,255,0.02)' }}
      onMouseLeave={e => { if (!active) (e.currentTarget as HTMLElement).style.background = 'transparent' }}>
      {children}
    </div>
  )
}

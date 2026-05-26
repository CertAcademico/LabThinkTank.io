import { useEffect, useState } from 'react'

const API_URL = import.meta.env.VITE_API_URL ?? 'http://127.0.0.1:8000'

interface IOC  { id: number; ioc: string; type: string; threat_actor: string; severity: string; mitre: string }
interface Actor { name: string; country: string; motivation: string; malware: string[]; ttps: string[] }
interface IOA  { ttp: string; ttp_name: string; tactic: string; ioa: string; priority: string; attributed_actor: string }

// ─── static content ────────────────────────────────────────────────────────
const TACTICS = [
  { name: 'Acceso Inicial', color: '#ef4444', pct: 82 },
  { name: 'Ejecución',      color: '#f97316', pct: 67 },
  { name: 'Persistencia',   color: '#eab308', pct: 54 },
  { name: 'Mov. Lateral',   color: '#a855f7', pct: 41 },
  { name: 'Exfiltración',   color: '#ef4444', pct: 28 },
]

const LOG_POOL = [
  '► RDP anómala: 45.33.x.x → DC-PROD-01',
  '► PowerShell base64 ejecutado en WKS-FIN-01',
  '► Firewall deny: 1,247 intentos SSH brute-force',
  '► Servicio no firmado: svc_update.exe instalado',
  '► DGA domain query detectada en VLAN-CORP',
  '► lsass.exe accedido por herramienta de dump',
  '► Lateral movement SMB desde WKS-MKT-03',
  '► YARA: ShadowLoader en endpoint WKS-09',
  '► Exfiltración bloqueada 840 MB → 185.220.x.x',
  '► Scheduled task creada sin baseline detectada',
]

const INCIDENTS = [
  { id: 'INC-2026-0087', sev: 'Crítico', color: '#ef4444', bg: 'rgba(239,68,68,0.08)', border: 'rgba(239,68,68,0.3)' },
  { id: 'INC-2026-0086', sev: 'Alto',    color: '#f97316', bg: 'rgba(249,115,22,0.08)', border: 'rgba(249,115,22,0.3)' },
  { id: 'INC-2026-0084', sev: 'Medio',   color: '#eab308', bg: 'rgba(234,179,8,0.08)',  border: 'rgba(234,179,8,0.3)' },
]

// threat origins: [x%, y%, color, code]
const ORIGINS: [number, number, string, string][] = [
  [64, 20, '#ef4444', 'RU'],
  [76, 31, '#f97316', 'CN'],
  [78, 25, '#ef4444', 'KP'],
  [61, 36, '#f97316', 'IR'],
  [47, 25, '#eab308', 'EU'],
  [52, 22, '#ef4444', 'UA'],
]
const [TX, TY] = [23, 36]   // target %

const MODULES = [
  [
    { label: 'SIEM',                icon: '🗄️', color: '#22d3ee' },
    { label: 'Redes Neuronales',    icon: '🧠', color: '#22d3ee' },
    { label: 'Feature Engineering', icon: '📊', color: '#22d3ee' },
    { label: 'SOAR',                icon: '⚡', color: '#22d3ee' },
    { label: 'Regresión Logística', icon: '📈', color: '#a855f7' },
    { label: 'EDA',                 icon: '🔬', color: '#a855f7' },
    { label: 'MITRE ATT&CK',       icon: '🗺️', color: '#a855f7' },
  ],
  [
    { label: 'Random Forest',       icon: '🌲', color: '#4ade80' },
    { label: 'Data Wrangling',      icon: '🔧', color: '#4ade80' },
    { label: 'Zero Trust',          icon: '🛡️', color: '#4ade80' },
    { label: 'Deep Learning',       icon: '⚗️', color: '#60a5fa' },
    { label: 'ETL Pipeline',        icon: '🔁', color: '#60a5fa' },
    { label: 'Ransomware',          icon: '🔒', color: '#f87171' },
    { label: 'Anomaly Detection',   icon: '📡', color: '#fb923c' },
  ],
  [
    { label: 'Visualización',       icon: '📉', color: '#94a3b8' },
    { label: 'Threat Hunting',      icon: '🎯', color: '#94a3b8' },
    { label: 'NLP en Seguridad',    icon: '💬', color: '#94a3b8' },
    { label: 'Pandas & SQL',        icon: '🐼', color: '#94a3b8' },
    { label: 'Dark Web Intel',      icon: '🌐', color: '#94a3b8' },
    { label: 'Precisión & Recall',  icon: '🎯', color: '#94a3b8' },
    { label: 'Digital Forensics',   icon: '🔍', color: '#94a3b8' },
  ],
]

// ─── helpers ───────────────────────────────────────────────────────────────
function Panel({ children, className = '', style }: { children: React.ReactNode; className?: string; style?: React.CSSProperties }) {
  return (
    <div className={`rounded-xl border border-slate-800 bg-slate-900 ${className}`} style={style}>
      {children}
    </div>
  )
}

function SectionLabel({ icon, text }: { icon: string; text: string }) {
  return (
    <div className="flex items-center gap-2 mb-4">
      <span className="text-slate-500">{icon}</span>
      <span className="text-slate-400 text-[11px] font-bold uppercase tracking-widest">{text}</span>
    </div>
  )
}

// ─── KPI Cards ─────────────────────────────────────────────────────────────
function KPICards({ iocs, ioas }: { iocs: IOC[]; ioas: IOA[] }) {
  const critical = iocs.filter(i => i.severity === 'critical').length
  const active   = ioas.filter(i => ['critical', 'high'].includes(i.priority)).length

  const cards = [
    { label: 'Eventos SIEM / 24h',  value: '1,247',              color: '#22d3ee', glow: 'rgba(34,211,238,0.15)' },
    { label: 'Alertas Críticas',    value: String(critical || 23), color: '#f87171', glow: 'rgba(248,113,113,0.15)' },
    { label: 'Alertas Activas',     value: String(active   || 87), color: '#fb923c', glow: 'rgba(251,146,60,0.15)' },
    { label: 'MTTR Promedio',       value: '12m',                color: '#c084fc', glow: 'rgba(192,132,252,0.15)' },
    { label: 'Automatización SOAR', value: '94%',                color: '#4ade80', glow: 'rgba(74,222,128,0.15)' },
    { label: 'Score de Riesgo',     value: '78',                 color: '#facc15', glow: 'rgba(250,204,21,0.15)' },
  ]

  return (
    <div className="grid grid-cols-6 gap-3 mb-4">
      {cards.map(c => (
        <div key={c.label}
             className="rounded-xl border border-slate-800 p-4 text-center relative overflow-hidden"
             style={{ background: `linear-gradient(135deg, ${c.glow} 0%, #0f172a 60%)` }}>
          <div className="absolute inset-x-0 top-0 h-0.5 rounded-t-xl"
               style={{ backgroundColor: c.color }} />
          <p className="text-3xl font-black tabular-nums mt-1" style={{ color: c.color }}>
            {c.value}
          </p>
          <p className="text-slate-500 text-[11px] mt-1.5 leading-tight">{c.label}</p>
        </div>
      ))}
    </div>
  )
}

// ─── Threat Map ─────────────────────────────────────────────────────────────
function ThreatMap() {
  const W = 560, H = 300
  const tx = TX / 100 * W, ty = TY / 100 * H

  return (
    <Panel className="overflow-hidden relative" style={{ minHeight: 300 }}>
      {/* dark gradient background */}
      <div className="absolute inset-0"
           style={{ background: 'radial-gradient(ellipse at 30% 40%, #071826 0%, #020617 70%)' }} />

      {/* header overlay */}
      <div className="absolute top-4 left-4 z-10 flex items-center gap-2">
        <span className="w-2 h-2 bg-cyan-400 rounded-full animate-pulse" />
        <span className="text-cyan-400 text-[10px] font-mono tracking-widest">THREAT MAP · LIVE</span>
      </div>

      {/* attack counter */}
      <div className="absolute top-4 right-4 z-10 text-right">
        <p className="text-red-400 text-xl font-black tabular-nums">{ORIGINS.length}</p>
        <p className="text-slate-500 text-[10px]">orígenes activos</p>
      </div>

      <svg viewBox={`0 0 ${W} ${H}`} className="w-full relative z-0">
        {/* latitude grid lines */}
        {[0.2, 0.4, 0.6, 0.8].map(p => (
          <line key={`h${p}`} x1={0} y1={p * H} x2={W} y2={p * H}
                stroke="#1e293b" strokeWidth="0.6" />
        ))}
        {/* longitude grid lines */}
        {[0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9].map(p => (
          <line key={`v${p}`} x1={p * W} y1={0} x2={p * W} y2={H}
                stroke="#1e293b" strokeWidth="0.6" />
        ))}

        {/* connection lines */}
        {ORIGINS.map(([x, y, color], i) => (
          <line key={`line${i}`}
                x1={x / 100 * W} y1={y / 100 * H} x2={tx} y2={ty}
                stroke={color} strokeWidth="0.8" strokeDasharray="6 4" opacity="0.4">
            <animate attributeName="stroke-dashoffset" from="10" to="0"
                     dur={`${1.2 + i * 0.25}s`} repeatCount="indefinite" />
          </line>
        ))}

        {/* threat origin dots */}
        {ORIGINS.map(([x, y, color, code], i) => {
          const cx = x / 100 * W, cy = y / 100 * H
          return (
            <g key={`orig${i}`}>
              {/* outer pulse ring */}
              <circle cx={cx} cy={cy} r="6" fill="none" stroke={color} strokeWidth="1">
                <animate attributeName="r"       values="5;20;5"     dur={`${2.2 + i * 0.3}s`} repeatCount="indefinite" />
                <animate attributeName="opacity" values="0.8;0;0.8"  dur={`${2.2 + i * 0.3}s`} repeatCount="indefinite" />
              </circle>
              {/* inner dot */}
              <circle cx={cx} cy={cy} r="5" fill={color} />
              <circle cx={cx} cy={cy} r="5" fill={color} opacity="0.4">
                <animate attributeName="r" values="4;7;4" dur="1.5s" repeatCount="indefinite" />
                <animate attributeName="opacity" values="0.4;0;0.4" dur="1.5s" repeatCount="indefinite" />
              </circle>
              {/* label */}
              <text x={cx + 8} y={cy - 6} fill={color} fontSize="9"
                    fontFamily="monospace" fontWeight="bold" opacity="0.95">{code}</text>
            </g>
          )
        })}

        {/* target */}
        <circle cx={tx} cy={ty} r="22" fill="none" stroke="#22d3ee" strokeWidth="0.7" opacity="0.25">
          <animate attributeName="r"       values="10;26;10"  dur="3s"   repeatCount="indefinite" />
          <animate attributeName="opacity" values="0.3;0;0.3" dur="3s"   repeatCount="indefinite" />
        </circle>
        <circle cx={tx} cy={ty} r="10" fill="none" stroke="#22d3ee" strokeWidth="1" opacity="0.5">
          <animate attributeName="r"       values="6;13;6"    dur="2s"   repeatCount="indefinite" />
          <animate attributeName="opacity" values="0.5;0;0.5" dur="2s"   repeatCount="indefinite" />
        </circle>
        <circle cx={tx} cy={ty} r="5" fill="#22d3ee" />
        <text x={tx + 9} y={ty - 8} fill="#22d3ee" fontSize="9"
              fontFamily="monospace" fontWeight="bold">TARGET</text>
      </svg>
    </Panel>
  )
}

// ─── Alert Feed ─────────────────────────────────────────────────────────────
const P: Record<string, { badge: string; bg: string; border: string }> = {
  critical: { badge: 'bg-red-600    text-white', bg: 'bg-red-950/30',    border: 'border-red-800/50' },
  high:     { badge: 'bg-orange-600 text-white', bg: 'bg-orange-950/30', border: 'border-orange-800/50' },
  medium:   { badge: 'bg-yellow-700 text-white', bg: 'bg-yellow-950/30', border: 'border-yellow-800/50' },
}

function AlertFeed({ ioas }: { ioas: IOA[] }) {
  const dynamic = ioas.filter(i => ['critical', 'high'].includes(i.priority)).slice(0, 3)
  return (
    <Panel className="p-5 flex flex-col" style={{ minHeight: 300 }}>
      <SectionLabel icon="ⓘ" text="Alertas Activas" />
      <div className="space-y-2 flex-1 overflow-y-auto">
        {/* static pinned alerts */}
        {[
          { p: 'critical', title: 'Ransomware LockBit 4.0 detectado en DC-PROD-01', sub: 'DC-PROD-01 · hace 6 min' },
          { p: 'high',     title: 'Exfiltración de datos — 2.3 GB hacia IP externa', sub: 'srv-db-03 · hace 12 min' },
        ].map(a => {
          const s = P[a.p]
          return (
            <div key={a.title} className={`flex items-start gap-3 rounded-lg p-3 border ${s.bg} ${s.border}`}>
              <span className={`text-[10px] font-bold px-2 py-0.5 rounded uppercase shrink-0 ${s.badge}`}>
                {a.p}
              </span>
              <div>
                <p className="text-white text-sm font-semibold leading-snug">{a.title}</p>
                <p className="text-slate-500 text-xs mt-0.5">{a.sub}</p>
              </div>
            </div>
          )
        })}
        {/* dynamic from backend */}
        {dynamic.map(ioa => {
          const s = P[ioa.priority] ?? P.medium
          return (
            <div key={ioa.ttp} className={`flex items-start gap-3 rounded-lg p-3 border ${s.bg} ${s.border}`}>
              <span className={`text-[10px] font-bold px-2 py-0.5 rounded uppercase shrink-0 ${s.badge}`}>
                {ioa.priority}
              </span>
              <div>
                <p className="text-slate-200 text-sm leading-snug">{ioa.ioa}</p>
                <p className="text-slate-500 text-xs mt-0.5">{ioa.ttp} · {ioa.tactic}</p>
              </div>
            </div>
          )
        })}
      </div>
    </Panel>
  )
}

// ─── Kill Chain Coverage ────────────────────────────────────────────────────
function KillChainBars() {
  return (
    <Panel className="p-5">
      <SectionLabel icon="🔄" text="Kill Chain Coverage" />
      <div className="space-y-4">
        {TACTICS.map(t => (
          <div key={t.name}>
            <div className="flex justify-between text-xs mb-1.5">
              <span className="text-slate-300 font-medium">{t.name}</span>
              <span className="font-mono font-bold" style={{ color: t.color }}>{t.pct}%</span>
            </div>
            <div className="h-2.5 bg-slate-800 rounded-full overflow-hidden">
              <div className="h-full rounded-full"
                   style={{ width: `${t.pct}%`, backgroundColor: t.color,
                            boxShadow: `0 0 8px ${t.color}80` }} />
            </div>
          </div>
        ))}
      </div>
    </Panel>
  )
}

// ─── Live Log Feed ──────────────────────────────────────────────────────────
function LiveLogFeed() {
  const [logs, setLogs] = useState(() => LOG_POOL.slice(0, 5))

  useEffect(() => {
    let i = 5
    const t = setInterval(() => {
      const next = LOG_POOL[i % LOG_POOL.length]
      setLogs(prev => [next, ...prev.slice(0, 5)])
      i++
    }, 3000)
    return () => clearInterval(t)
  }, [])

  return (
    <Panel className="p-5">
      <div className="flex items-center gap-2 mb-4">
        <span className="text-green-400 font-mono text-sm font-bold">{'>'}_</span>
        <span className="text-slate-400 text-[11px] font-bold uppercase tracking-widest">Log Feed</span>
        <span className="ml-auto w-2 h-2 bg-green-500 rounded-full animate-pulse" />
      </div>
      <div className="font-mono text-xs space-y-2.5">
        {logs.map((log, i) => (
          <div key={`${i}-${log.slice(0, 10)}`}
               className="leading-relaxed"
               style={{ color: i === 0 ? '#86efac' : '#334155' }}>
            {log}
          </div>
        ))}
      </div>
    </Panel>
  )
}

// ─── Incident List ──────────────────────────────────────────────────────────
function IncidentList() {
  return (
    <Panel className="p-5">
      <SectionLabel icon="⚠" text="Incidentes" />
      <div className="space-y-2.5">
        {INCIDENTS.map(inc => (
          <div key={inc.id}
               className="flex items-center justify-between rounded-lg px-4 py-3 cursor-pointer
                          hover:brightness-125 transition-all border"
               style={{ background: inc.bg, borderColor: inc.border }}>
            <span className="font-mono text-sm text-slate-200">{inc.id}</span>
            <span className="text-xs font-bold uppercase" style={{ color: inc.color }}>
              {inc.sev}
            </span>
          </div>
        ))}
      </div>
    </Panel>
  )
}

// ─── Widget Row ─────────────────────────────────────────────────────────────
function DashboardWidgets({ iocs, actors: _actors }: { iocs: IOC[]; actors?: Actor[] }) {
  const topIOC = iocs.find(i => i.severity === 'critical') ?? iocs[0]

  return (
    <div className="grid grid-cols-4 gap-3 mb-4">

      {/* IOC */}
      <Panel className="p-4">
        <SectionLabel icon="🔄" text="IOC Activo" />
        {topIOC ? (
          <div className="font-mono text-xs space-y-1.5">
            <p className="text-cyan-300 font-bold truncate">{topIOC.ioc}</p>
            <p className="text-slate-500">{topIOC.type === 'IP' ? '→ Tor Exit Node' : '→ C2 Domain'}</p>
            <p className="text-slate-600 truncate">actor: {topIOC.threat_actor}</p>
          </div>
        ) : (
          <p className="text-slate-600 text-xs italic">Cargando...</p>
        )}
      </Panel>

      {/* Anomalous users */}
      <Panel className="p-4">
        <SectionLabel icon="👥" text="Usuarios Anómalos" />
        <div className="space-y-2 text-xs">
          {[
            { u: 'svc_backup',    d: '340 accesos en 10 min' },
            { u: 'jmartinez',     d: 'Login 3 países en 1h' },
            { u: 'administrador', d: 'Fuera de horario' },
          ].map(e => (
            <div key={e.u} className="flex items-start gap-2">
              <span className="text-yellow-400 shrink-0 mt-0.5">⚠</span>
              <span className="text-slate-400 leading-tight">
                <span className="text-slate-200 font-mono">{e.u}</span> → {e.d}
              </span>
            </div>
          ))}
        </div>
      </Panel>

      {/* Response */}
      <Panel className="p-4">
        <SectionLabel icon="⚡" text="Respuesta Rápida" />
        <div className="flex flex-wrap gap-2">
          {['Aislamiento de host', 'Bloquear IP C2', 'Reseteo credenciales'].map(a => (
            <button key={a}
                    className="bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white
                               text-[11px] px-2.5 py-1.5 rounded-lg border border-slate-700
                               hover:border-slate-500 transition-all">
              {a}
            </button>
          ))}
        </div>
      </Panel>

      {/* Assets */}
      <Panel className="p-4">
        <SectionLabel icon="🖥️" text="Estado de Assets" />
        <div className="space-y-2.5 text-xs">
          {[
            { n: 'DC-PROD-01 (Domain Controller)',   color: '#f87171' },
            { n: 'srv-db-03 (Base datos financiera)', color: '#f87171' },
            { n: 'fw-perimetro (Firewall principal)', color: '#facc15' },
          ].map(a => (
            <div key={a.n} className="flex items-center gap-2.5">
              <span className="w-2.5 h-2.5 rounded-full shrink-0"
                    style={{ backgroundColor: a.color, boxShadow: `0 0 6px ${a.color}` }} />
              <span className="text-slate-400 truncate">{a.n}</span>
            </div>
          ))}
        </div>
      </Panel>

    </div>
  )
}

// ─── Module Grid ────────────────────────────────────────────────────────────
function ModuleGrid() {
  return (
    <Panel className="p-5">
      <SectionLabel icon="📚" text="Módulos del Taller" />
      <div className="space-y-2">
        {MODULES.map((row, ri) => (
          <div key={ri} className="grid grid-cols-7 gap-2">
            {row.map(mod => (
              <button key={mod.label}
                      className="relative bg-slate-950 rounded-lg p-3 flex flex-col items-center gap-2
                                 hover:brightness-125 transition-all border border-slate-800
                                 hover:border-slate-600 group">
                <span className="absolute top-1.5 right-1.5 w-1.5 h-1.5 bg-green-500 rounded-full opacity-50" />
                <span className="text-xl">{mod.icon}</span>
                <span className="text-[10px] font-semibold text-center leading-tight"
                      style={{ color: mod.color }}>
                  {mod.label}
                </span>
              </button>
            ))}
          </div>
        ))}
      </div>
    </Panel>
  )
}

// ─── DashboardPage ──────────────────────────────────────────────────────────
export default function DashboardPage() {
  const [iocs,   setIocs]   = useState<IOC[]>([])
  const [actors, setActors] = useState<Actor[]>([])
  const [ioas,   setIoas]   = useState<IOA[]>([])

  useEffect(() => {
    Promise.all([
      fetch(`${API_URL}/ioc-feed`).then(r => r.json()),
      fetch(`${API_URL}/threat-actors`).then(r => r.json()),
      fetch(`${API_URL}/ioas`).then(r => r.json()),
    ]).then(([i, a, io]) => { setIocs(i); setActors(a); setIoas(io) })
      .catch(() => {})
  }, [])

  return (
    <div className="space-y-4">
      <KPICards iocs={iocs} ioas={ioas} />

      <div className="grid grid-cols-2 gap-4">
        <ThreatMap />
        <AlertFeed ioas={ioas} />
      </div>

      <div className="grid grid-cols-3 gap-4">
        <KillChainBars />
        <LiveLogFeed />
        <IncidentList />
      </div>

      <DashboardWidgets iocs={iocs} actors={actors} />

      <ModuleGrid />
    </div>
  )
}

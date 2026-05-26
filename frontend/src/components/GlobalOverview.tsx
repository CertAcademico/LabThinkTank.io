import { useEffect, useState } from 'react'

const API = import.meta.env.VITE_API_URL ?? 'http://127.0.0.1:8000'

interface IOC { id: number; ioc: string; type: string; threat_actor: string; severity: string; mitre: string }
interface IOA { ttp: string; ttp_name: string; tactic: string; ioa: string; priority: string; attributed_actor: string }
interface Actor { name: string; country: string; motivation: string; malware: string[]; ttps: string[]; active_campaign: string }

const glass = 'rounded-xl border' as const
const glassStyle = { background: 'rgba(15,23,42,0.55)', backdropFilter: 'blur(16px)', borderColor: 'rgba(255,255,255,0.07)' }

const TACTICS = [
  { name: 'Acceso Inicial', color: '#ef4444', pct: 82 },
  { name: 'Ejecución',      color: '#f97316', pct: 67 },
  { name: 'Persistencia',   color: '#eab308', pct: 54 },
  { name: 'Mov. Lateral',   color: '#a855f7', pct: 41 },
  { name: 'Exfiltración',   color: '#f43f5e', pct: 28 },
]
const LOG_POOL = [
  '► RDP anómala: 45.33.x.x → DC-PROD-01',
  '► PowerShell base64 en WKS-FIN-01',
  '► Firewall deny: 1,247 intentos SSH',
  '► svc_update.exe sin firma instalado',
  '► DGA domain query en VLAN-CORP',
  '► lsass.exe accedido por dump tool',
  '► SMB scan lateral desde WKS-MKT-03',
  '► YARA match: ShadowLoader en WKS-09',
  '► Exfil bloqueada 840MB → 185.220.x.x',
  '► Scheduled task sin baseline detectada',
]
const INCIDENTS = [
  { id: 'INC-2026-0087', sev: 'Crítico', c: '#ef4444' },
  { id: 'INC-2026-0086', sev: 'Alto',    c: '#f97316' },
  { id: 'INC-2026-0084', sev: 'Medio',   c: '#eab308' },
]
const ORIGINS: [number, number, string, string][] = [
  [64, 19, '#ef4444', 'RU'], [76, 31, '#f97316', 'CN'],
  [78, 25, '#ef4444', 'KP'], [61, 36, '#f97316', 'IR'],
  [47, 25, '#eab308', 'EU'], [52, 22, '#ef4444', 'UA'],
]

// ── Threat Gauge ───────────────────────────────────────────────────────────
function ThreatGauge({ level = 74 }: { level?: number }) {
  const r = 58, cx = 80, cy = 80, C = 2 * Math.PI * r
  const offset = ((100 - level) / 100) * C
  const color = level >= 80 ? '#ef4444' : level >= 60 ? '#f97316' : level >= 40 ? '#eab308' : '#4ade80'
  const label = level >= 80 ? 'CRÍTICO' : level >= 60 ? 'ALTO' : level >= 40 ? 'MEDIO' : 'BAJO'
  return (
    <div className="flex flex-col items-center justify-center h-full">
      <svg viewBox="0 0 160 160" className="w-44 h-44">
        <circle cx={cx} cy={cy} r={r} fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="10" />
        <circle cx={cx} cy={cy} r={r} fill="none" stroke={color} strokeWidth="10"
                strokeLinecap="round" strokeDasharray={`${C}`} strokeDashoffset={offset}
                transform={`rotate(-90 ${cx} ${cy})`}
                style={{ filter: `drop-shadow(0 0 10px ${color})`, transition: 'stroke-dashoffset 1s ease' }} />
        <text x={cx} y={cy - 8} textAnchor="middle" fill={color}
              fontSize="30" fontWeight="900" fontFamily="monospace">{level}</text>
        <text x={cx} y={cy + 12} textAnchor="middle" fill={color}
              fontSize="10" fontWeight="800" fontFamily="monospace" letterSpacing="2">{label}</text>
        <text x={cx} y={cy + 28} textAnchor="middle" fill="#475569"
              fontSize="7" fontFamily="monospace" letterSpacing="1">THREAT LEVEL</text>
      </svg>
      <p className="text-slate-600 text-[10px] mt-1">Actualizado hace 2 min</p>
    </div>
  )
}

// ── Threat Map ─────────────────────────────────────────────────────────────
function MiniThreatMap() {
  const W = 480, H = 240, tx = 0.23 * W, ty = 0.36 * H
  return (
    <div className="relative overflow-hidden rounded-xl h-full"
         style={{ background: 'radial-gradient(ellipse at 30% 40%, #071826 0%, #020617 100%)', minHeight: 240 }}>
      <div className="absolute top-3 left-3 z-10 flex items-center gap-1.5">
        <span className="w-1.5 h-1.5 bg-cyan-400 rounded-full animate-pulse" />
        <span className="text-cyan-400 text-[9px] font-mono tracking-widest">THREAT MAP · LIVE</span>
      </div>
      <div className="absolute top-3 right-3 z-10 text-right">
        <p className="text-red-400 text-lg font-black">{ORIGINS.length}</p>
        <p className="text-slate-600 text-[9px]">activos</p>
      </div>
      <svg viewBox={`0 0 ${W} ${H}`} className="w-full h-full">
        {[0.25, 0.5, 0.75].map(p => <line key={`h${p}`} x1={0} y1={p * H} x2={W} y2={p * H} stroke="#1e293b" strokeWidth="0.5" />)}
        {[0.17, 0.33, 0.5, 0.67, 0.83].map(p => <line key={`v${p}`} x1={p * W} y1={0} x2={p * W} y2={H} stroke="#1e293b" strokeWidth="0.5" />)}
        {ORIGINS.map(([x, y, color], i) => (
          <line key={`l${i}`} x1={x / 100 * W} y1={y / 100 * H} x2={tx} y2={ty}
                stroke={color} strokeWidth="0.7" strokeDasharray="5 4" opacity="0.4">
            <animate attributeName="stroke-dashoffset" from="9" to="0" dur={`${1.3 + i * 0.2}s`} repeatCount="indefinite" />
          </line>
        ))}
        {ORIGINS.map(([x, y, color, code], i) => {
          const [cx2, cy2] = [x / 100 * W, y / 100 * H]
          return (
            <g key={`o${i}`}>
              <circle cx={cx2} cy={cy2} r="5" fill="none" stroke={color} strokeWidth="1">
                <animate attributeName="r" values="4;17;4" dur={`${2.2 + i * 0.35}s`} repeatCount="indefinite" />
                <animate attributeName="opacity" values="0.8;0;0.8" dur={`${2.2 + i * 0.35}s`} repeatCount="indefinite" />
              </circle>
              <circle cx={cx2} cy={cy2} r="4" fill={color} />
              <text x={cx2 + 7} y={cy2 - 5} fill={color} fontSize="8" fontFamily="monospace" fontWeight="bold">{code}</text>
            </g>
          )
        })}
        <circle cx={tx} cy={ty} r="8" fill="none" stroke="#22d3ee" strokeWidth="0.8">
          <animate attributeName="r" values="6;20;6" dur="3s" repeatCount="indefinite" />
          <animate attributeName="opacity" values="0.4;0;0.4" dur="3s" repeatCount="indefinite" />
        </circle>
        <circle cx={tx} cy={ty} r="4.5" fill="#22d3ee" style={{ filter: 'drop-shadow(0 0 5px #22d3ee)' }} />
        <text x={tx + 8} y={ty - 7} fill="#22d3ee" fontSize="8" fontFamily="monospace" fontWeight="bold">TARGET</text>
      </svg>
    </div>
  )
}

// ── GlobalOverview ─────────────────────────────────────────────────────────
export default function GlobalOverview() {
  const [iocs,   setIocs]   = useState<IOC[]>([])
  const [actors, setActors] = useState<Actor[]>([])
  const [ioas,   setIoas]   = useState<IOA[]>([])
  const [logs,   setLogs]   = useState(LOG_POOL.slice(0, 5))

  useEffect(() => {
    Promise.all([
      fetch(`${API}/ioc-feed`).then(r => r.json()),
      fetch(`${API}/threat-actors`).then(r => r.json()),
      fetch(`${API}/ioas`).then(r => r.json()),
    ]).then(([i, a, io]) => { setIocs(i); setActors(a); setIoas(io) })
      .catch(() => {})
  }, [])

  useEffect(() => {
    let i = 5
    const t = setInterval(() => {
      setLogs(prev => [LOG_POOL[i++ % LOG_POOL.length], ...prev.slice(0, 5)])
    }, 3000)
    return () => clearInterval(t)
  }, [])

  const critical = iocs.filter(x => x.severity === 'critical').length
  const activeAlerts = ioas.filter(x => ['critical', 'high'].includes(x.priority)).length

  const KPIS = [
    { label: 'Eventos SIEM',   value: '1,247', sub: '/ 24h', c: '#22d3ee', glow: 'rgba(34,211,238,0.12)' },
    { label: 'IOCs Activos',   value: String(iocs.length || 18), sub: 'total', c: '#f87171', glow: 'rgba(248,113,113,0.12)' },
    { label: 'IOAs Detectados', value: String(activeAlerts || 14), sub: 'crítico/alto', c: '#fb923c', glow: 'rgba(251,146,60,0.12)' },
    { label: 'Campañas',       value: String(actors.length || 3), sub: 'activas', c: '#c084fc', glow: 'rgba(192,132,252,0.12)' },
    { label: 'ATT&CK Coverage', value: '61%', sub: 'técnicas', c: '#4ade80', glow: 'rgba(74,222,128,0.12)' },
    { label: 'AI Confidence',  value: '94%', sub: 'score', c: '#facc15', glow: 'rgba(250,204,21,0.12)' },
  ]

  const topAlerts = [
    { sev: 'CRÍTICO', c: '#ef4444', bg: 'rgba(239,68,68,0.1)', title: 'LockBit 4.0 detectado en DC-PROD-01', sub: 'hace 6 min' },
    { sev: 'ALTO',    c: '#f97316', bg: 'rgba(249,115,22,0.1)', title: 'Exfiltración 2.3 GB → IP externa', sub: 'hace 12 min' },
    ...ioas.filter(x => ['critical','high'].includes(x.priority)).slice(0, 3).map(x => ({
      sev: x.priority.toUpperCase(), c: x.priority === 'critical' ? '#ef4444' : '#f97316',
      bg: x.priority === 'critical' ? 'rgba(239,68,68,0.08)' : 'rgba(249,115,22,0.08)',
      title: x.ioa, sub: `${x.ttp} · ${x.tactic}`,
    })),
  ]

  const topIOC = iocs.find(x => x.severity === 'critical') ?? iocs[0]

  return (
    <div className="space-y-4">

      {/* ── KPI row ───────────────────────────────────────────────────────── */}
      <div className="grid grid-cols-6 gap-3">
        {KPIS.map(k => (
          <div key={k.label} className={`${glass} p-4 relative overflow-hidden`} style={{ ...glassStyle, background: `linear-gradient(135deg, ${k.glow} 0%, rgba(15,23,42,0.55) 60%)` }}>
            <div className="absolute inset-x-0 top-0 h-px" style={{ background: `linear-gradient(90deg, transparent, ${k.c}, transparent)` }} />
            <p className="text-2xl font-black tabular-nums" style={{ color: k.c, textShadow: `0 0 20px ${k.c}60` }}>{k.value}</p>
            <p className="text-slate-400 text-[10px] font-medium mt-0.5">{k.label}</p>
            <p className="text-slate-600 text-[9px]">{k.sub}</p>
          </div>
        ))}
      </div>

      {/* ── Row 2: gauge + map | alerts ───────────────────────────────────── */}
      <div className="grid grid-cols-5 gap-4">
        <div className={`col-span-2 ${glass} p-4`} style={glassStyle}>
          <p className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-3">Nivel de Amenaza</p>
          <ThreatGauge level={critical > 5 ? 85 : 74} />
        </div>
        <div className={`col-span-3 ${glass} overflow-hidden`} style={glassStyle}>
          <MiniThreatMap />
        </div>
      </div>

      {/* ── Row 3: alerts | kill chain | log | incidents ──────────────────── */}
      <div className="grid grid-cols-4 gap-4">

        {/* Alerts */}
        <div className={`${glass} p-4 flex flex-col`} style={glassStyle}>
          <div className="flex items-center gap-2 mb-3">
            <span className="w-1.5 h-1.5 bg-red-500 rounded-full animate-pulse" />
            <p className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">Alertas Activas</p>
          </div>
          <div className="space-y-2 flex-1 overflow-y-auto">
            {topAlerts.map((a, i) => (
              <div key={i} className="rounded-lg px-3 py-2 flex items-start gap-2 border"
                   style={{ background: a.bg, borderColor: `${a.c}30` }}>
                <span className="text-[9px] font-bold px-1.5 py-0.5 rounded mt-0.5 shrink-0"
                      style={{ background: `${a.c}25`, color: a.c }}>{a.sev}</span>
                <div className="min-w-0">
                  <p className="text-slate-200 text-xs leading-snug truncate">{a.title}</p>
                  <p className="text-slate-600 text-[9px] mt-0.5">{a.sub}</p>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Kill chain */}
        <div className={`${glass} p-4`} style={glassStyle}>
          <p className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-3">Kill Chain</p>
          <div className="space-y-3">
            {TACTICS.map(t => (
              <div key={t.name}>
                <div className="flex justify-between text-[10px] mb-1">
                  <span className="text-slate-400">{t.name}</span>
                  <span className="font-mono font-bold" style={{ color: t.color }}>{t.pct}%</span>
                </div>
                <div className="h-1.5 rounded-full overflow-hidden" style={{ background: 'rgba(255,255,255,0.05)' }}>
                  <div className="h-full rounded-full" style={{ width: `${t.pct}%`, background: t.color, boxShadow: `0 0 8px ${t.color}80` }} />
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Log */}
        <div className={`${glass} p-4`} style={glassStyle}>
          <div className="flex items-center gap-2 mb-3">
            <span className="font-mono text-green-400 text-xs font-bold">{'>'}_</span>
            <p className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">Log Feed</p>
            <span className="ml-auto w-1.5 h-1.5 bg-green-400 rounded-full animate-pulse" />
          </div>
          <div className="font-mono text-[10px] space-y-2">
            {logs.map((l, i) => (
              <div key={`${i}-${l.slice(0, 8)}`} style={{ color: i === 0 ? '#86efac' : '#1e293b' }}>{l}</div>
            ))}
          </div>
        </div>

        {/* Incidents */}
        <div className={`${glass} p-4`} style={glassStyle}>
          <p className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-3">Incidentes</p>
          <div className="space-y-2">
            {INCIDENTS.map(inc => (
              <div key={inc.id} className="flex items-center justify-between rounded-lg px-3 py-2.5 border cursor-pointer hover:brightness-110 transition-all"
                   style={{ background: `${inc.c}0d`, borderColor: `${inc.c}35` }}>
                <span className="font-mono text-xs text-slate-300">{inc.id}</span>
                <span className="text-[10px] font-bold uppercase" style={{ color: inc.c }}>{inc.sev}</span>
              </div>
            ))}
          </div>
          {/* Asset status */}
          <div className="mt-4 space-y-2">
            <p className="text-[9px] text-slate-700 uppercase tracking-widest">Assets</p>
            {[
              { n: 'DC-PROD-01', c: '#ef4444' },
              { n: 'srv-db-03',  c: '#ef4444' },
              { n: 'fw-perimetro', c: '#facc15' },
            ].map(a => (
              <div key={a.n} className="flex items-center gap-2 text-[10px]">
                <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ backgroundColor: a.c, boxShadow: `0 0 5px ${a.c}` }} />
                <span className="text-slate-500">{a.n}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* ── Row 4: widgets ────────────────────────────────────────────────── */}
      <div className="grid grid-cols-4 gap-4">
        {/* IOC widget */}
        <div className={`${glass} p-4`} style={glassStyle}>
          <p className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-2">IOC Top</p>
          {topIOC ? (
            <div className="font-mono text-[10px] space-y-1">
              <p className="text-cyan-300 font-bold truncate">{topIOC.ioc}</p>
              <p className="text-slate-600">{topIOC.type === 'IP' ? '→ Tor Exit Node' : '→ C2 Domain'}</p>
              <p className="text-slate-600">actor: <span className="text-slate-400">{topIOC.threat_actor}</span></p>
            </div>
          ) : <p className="text-slate-700 text-xs">—</p>}
        </div>

        {/* Anomalous users */}
        <div className={`${glass} p-4`} style={glassStyle}>
          <p className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-2">Usuarios Anómalos</p>
          <div className="space-y-1.5 text-[10px]">
            {[['svc_backup','340 accesos en 10m'],['jmartinez','3 países en 1h'],['administrador','Fuera de horario']].map(([u, d]) => (
              <div key={u} className="flex gap-1.5">
                <span className="text-yellow-400">⚠</span>
                <span className="text-slate-500"><span className="text-slate-300 font-mono">{u}</span> → {d}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Response */}
        <div className={`${glass} p-4`} style={glassStyle}>
          <p className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-2">Respuesta Rápida</p>
          <div className="flex flex-wrap gap-1.5">
            {['Aislar host', 'Bloquear IP', 'Reset creds'].map(a => (
              <button key={a} className="text-[10px] px-2 py-1 rounded-lg border text-slate-400 hover:text-white transition-all"
                      style={{ background: 'rgba(255,255,255,0.04)', borderColor: 'rgba(255,255,255,0.08)' }}>
                {a}
              </button>
            ))}
          </div>
        </div>

        {/* AI summary */}
        <div className={`${glass} p-4`} style={glassStyle}>
          <p className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-2">AI Summary</p>
          <p className="text-[10px] text-slate-400 leading-relaxed">
            {actors.length > 0
              ? `${actors.length} actores rastreados. Campaña activa de LockBit con TTPs en exfiltración detectados.`
              : 'Analizando inteligencia de amenazas...'}
          </p>
          <div className="mt-2 flex items-center gap-1.5">
            <div className="flex-1 h-1 rounded-full" style={{ background: 'rgba(255,255,255,0.05)' }}>
              <div className="h-full w-[94%] rounded-full bg-violet-500" style={{ boxShadow: '0 0 6px #a78bfa' }} />
            </div>
            <span className="text-violet-400 text-[9px] font-mono">94%</span>
          </div>
        </div>
      </div>

    </div>
  )
}

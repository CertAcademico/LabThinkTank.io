import { useEffect, useState } from 'react'
import { useAuth } from '../contexts/AuthContext'

const API = import.meta.env.VITE_API_URL ?? 'http://127.0.0.1:8000'

// ── Types ─────────────────────────────────────────────────────────────────────

interface IOC    { ioc: string; type: string; threat_actor: string; severity: string; mitre: string; country: string }
interface IOA    { ttp: string; ttp_name: string; tactic: string; ioa: string; priority: string; attributed_actor: string }
interface Actor  { name: string; country: string; motivation: string; severity: string; active_campaign: string; ttps: string[] }
interface Phase  { id: number; name: string; category: string; reto_count: number; emoji: string; status: string; solves: number }
interface Badge  { id: number; org: string; name: string; tier: string; icon: string; awarded_at: string }
interface Challenge { id: number; title: string; status: string; submitted: number; my_score?: number }
interface AdminStats { students: number; active_challenges: number; datasets: number; submissions_today: number; pending_scoring: number }

// ── Static data ───────────────────────────────────────────────────────────────

const glass     = { background: 'rgba(15,23,42,0.55)', backdropFilter: 'blur(16px)', border: '1px solid rgba(255,255,255,0.07)', borderRadius: 12 }
const TACTICS   = [
  { name: 'Acceso Inicial', color: '#ef4444', pct: 82 },
  { name: 'Ejecución',      color: '#f97316', pct: 67 },
  { name: 'Persistencia',   color: '#eab308', pct: 54 },
  { name: 'Mov. Lateral',   color: '#a855f7', pct: 41 },
  { name: 'Exfiltración',   color: '#f43f5e', pct: 28 },
]
const LOG_POOL  = [
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
const ORIGINS: [number, number, string, string][] = [
  [64, 19, '#ef4444', 'RU'], [76, 31, '#f97316', 'CN'],
  [78, 25, '#ef4444', 'KP'], [61, 36, '#f97316', 'IR'],
  [47, 25, '#eab308', 'EU'], [52, 22, '#ef4444', 'UA'],
]
const SEV: Record<string, string> = { critical:'#ef4444', high:'#f97316', medium:'#facc15', low:'#4ade80' }
const TIER_COLOR: Record<string, string> = { bronze:'#cd7f32', silver:'#c0c0c0', gold:'#ffd700', platinum:'#e5e4e2', diamond:'#b9f2ff' }
const ORG_COLOR: Record<string, string>  = { CertAcademico:'#60a5fa', redciber:'#f87171', LabThinkTank:'#22d3ee' }

// ── Sub-components ────────────────────────────────────────────────────────────

function ThreatGauge({ level = 74 }: { level?: number }) {
  const r = 58, cx = 80, cy = 80, C = 2 * Math.PI * r
  const offset = ((100 - level) / 100) * C
  const color = level >= 80 ? '#ef4444' : level >= 60 ? '#f97316' : level >= 40 ? '#eab308' : '#4ade80'
  const label = level >= 80 ? 'CRÍTICO' : level >= 60 ? 'ALTO' : level >= 40 ? 'MEDIO' : 'BAJO'
  return (
    <div className="flex flex-col items-center justify-center h-full">
      <svg viewBox="0 0 160 160" className="w-40 h-40">
        <circle cx={cx} cy={cy} r={r} fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="10" />
        <circle cx={cx} cy={cy} r={r} fill="none" stroke={color} strokeWidth="10"
                strokeLinecap="round" strokeDasharray={`${C}`} strokeDashoffset={offset}
                transform={`rotate(-90 ${cx} ${cy})`}
                style={{ filter: `drop-shadow(0 0 10px ${color})`, transition: 'stroke-dashoffset 1s ease' }} />
        <text x={cx} y={cy - 8} textAnchor="middle" fill={color} fontSize="30" fontWeight="900" fontFamily="monospace">{level}</text>
        <text x={cx} y={cy + 12} textAnchor="middle" fill={color} fontSize="10" fontWeight="800" fontFamily="monospace" letterSpacing="2">{label}</text>
        <text x={cx} y={cy + 28} textAnchor="middle" fill="#475569" fontSize="7" fontFamily="monospace" letterSpacing="1">THREAT LEVEL</text>
      </svg>
      <p className="text-slate-600 text-[10px] mt-1">Actualizado hace 2 min</p>
    </div>
  )
}

function MiniThreatMap() {
  const W = 480, H = 240, tx = 0.23 * W, ty = 0.36 * H
  return (
    <div className="relative overflow-hidden rounded-xl h-full"
         style={{ background: 'radial-gradient(ellipse at 30% 40%, #071826 0%, #020617 100%)', minHeight: 220 }}>
      <div className="absolute top-3 left-3 z-10 flex items-center gap-1.5">
        <span className="w-1.5 h-1.5 bg-cyan-400 rounded-full animate-pulse" />
        <span className="text-cyan-400 text-[9px] font-mono tracking-widest">THREAT MAP · LIVE</span>
      </div>
      <div className="absolute top-3 right-3 z-10 text-right">
        <p className="text-red-400 text-lg font-black">{ORIGINS.length}</p>
        <p className="text-slate-600 text-[9px]">activos</p>
      </div>
      <svg viewBox={`0 0 ${W} ${H}`} className="w-full h-full">
        {[0.25, 0.5, 0.75].map(p => <line key={`h${p}`} x1={0} y1={p*H} x2={W} y2={p*H} stroke="#1e293b" strokeWidth="0.5" />)}
        {[0.17, 0.33, 0.5, 0.67, 0.83].map(p => <line key={`v${p}`} x1={p*W} y1={0} x2={p*W} y2={H} stroke="#1e293b" strokeWidth="0.5" />)}
        {ORIGINS.map(([x, y, color], i) => (
          <line key={`l${i}`} x1={x/100*W} y1={y/100*H} x2={tx} y2={ty}
                stroke={color} strokeWidth="0.7" strokeDasharray="5 4" opacity="0.4">
            <animate attributeName="stroke-dashoffset" from="9" to="0" dur={`${1.3 + i*0.2}s`} repeatCount="indefinite" />
          </line>
        ))}
        {ORIGINS.map(([x, y, color, code], i) => {
          const [ox, oy] = [x/100*W, y/100*H]
          return (
            <g key={`o${i}`}>
              <circle cx={ox} cy={oy} r="5" fill="none" stroke={color} strokeWidth="1">
                <animate attributeName="r" values="4;17;4" dur={`${2.2 + i*0.35}s`} repeatCount="indefinite" />
                <animate attributeName="opacity" values="0.8;0;0.8" dur={`${2.2 + i*0.35}s`} repeatCount="indefinite" />
              </circle>
              <circle cx={ox} cy={oy} r="4" fill={color} />
              <text x={ox+7} y={oy-5} fill={color} fontSize="8" fontFamily="monospace" fontWeight="bold">{code}</text>
            </g>
          )
        })}
        <circle cx={tx} cy={ty} r="8" fill="none" stroke="#22d3ee" strokeWidth="0.8">
          <animate attributeName="r" values="6;20;6" dur="3s" repeatCount="indefinite" />
          <animate attributeName="opacity" values="0.4;0;0.4" dur="3s" repeatCount="indefinite" />
        </circle>
        <circle cx={tx} cy={ty} r="4.5" fill="#22d3ee" style={{ filter: 'drop-shadow(0 0 5px #22d3ee)' }} />
        <text x={tx+8} y={ty-7} fill="#22d3ee" fontSize="8" fontFamily="monospace" fontWeight="bold">TARGET</text>
      </svg>
    </div>
  )
}

// ── Main Component ────────────────────────────────────────────────────────────

export default function GlobalOverview() {
  const { token, user } = useAuth()
  const isAdmin = user?.role === 'admin'
  const headers: Record<string, string> = token ? { Authorization: `Bearer ${token}` } : {}

  const [iocs,       setIocs]       = useState<IOC[]>([])
  const [actors,     setActors]     = useState<Actor[]>([])
  const [ioas,       setIoas]       = useState<IOA[]>([])
  const [phases,     setPhases]     = useState<Phase[]>([])
  const [myBadges,   setMyBadges]   = useState<Badge[]>([])
  const [myChallenges, setMyChallenges] = useState<Challenge[]>([])
  const [adminStats, setAdminStats] = useState<AdminStats | null>(null)
  const [logs,       setLogs]       = useState(LOG_POOL.slice(0, 6))

  useEffect(() => {
    // Public CTI endpoints
    Promise.all([
      fetch(`${API}/ioc-feed`).then(r => r.json()),
      fetch(`${API}/threat-actors`).then(r => r.json()),
      fetch(`${API}/ioas`).then(r => r.json()),
    ]).then(([i, a, io]) => { setIocs(i); setActors(a); setIoas(io) }).catch(() => {})

    // Auth-gated endpoints
    if (token) {
      fetch(`${API}/student/ctf-phases`, { headers }).then(r => r.json()).then(setPhases).catch(() => {})
      fetch(`${API}/student/badges`,     { headers }).then(r => r.json()).then(setMyBadges).catch(() => {})
      fetch(`${API}/student/challenges`, { headers }).then(r => r.json()).then(setMyChallenges).catch(() => {})
      if (isAdmin) {
        fetch(`${API}/admin/stats`, { headers }).then(r => r.json()).then(setAdminStats).catch(() => {})
      }
    }
  }, [token]) // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    let i = 6
    const t = setInterval(() => {
      // Inject live IOC events into log
      const iocLog = iocs[i % iocs.length]
      const entry = iocLog
        ? `► IOC detectado: ${iocLog.ioc} [${iocLog.threat_actor}]`
        : LOG_POOL[i % LOG_POOL.length]
      setLogs(prev => [entry, ...prev.slice(0, 5)])
      i++
    }, 3000)
    return () => clearInterval(t)
  }, [iocs])

  // Derived values
  const criticalIOCs  = iocs.filter(x => x.severity === 'critical').length
  const highIoas      = ioas.filter(x => ['critical','high'].includes(x.priority)).length
  const activePhases  = phases.filter(p => p.status === 'active').length
  const pendingRetos  = myChallenges.filter(c => c.status === 'active' && !c.submitted).length
  const topIOC        = iocs.find(x => x.severity === 'critical') ?? iocs[0]

  // KPIs — mix of CTI and platform data
  const KPIS = [
    { label: 'IOCs Activos',      value: String(iocs.length || '—'),          sub: 'en el feed', c: '#f87171', glow: 'rgba(248,113,113,0.12)' },
    { label: 'IOAs Detectados',   value: String(highIoas || '—'),             sub: 'crítico/alto', c: '#fb923c', glow: 'rgba(251,146,60,0.12)' },
    { label: 'Actores Rastreados',value: String(actors.length || '—'),        sub: 'APT activos', c: '#c084fc', glow: 'rgba(192,132,252,0.12)' },
    { label: 'Fases CTF Activas', value: `${activePhases}/${phases.length || '—'}`, sub: 'habilitadas', c: '#22d3ee', glow: 'rgba(34,211,238,0.12)' },
    { label: isAdmin ? 'Estudiantes' : 'Mis Retos', value: isAdmin ? String(adminStats?.students ?? '—') : String(myChallenges.length || '—'), sub: isAdmin ? 'registrados' : pendingRetos > 0 ? `${pendingRetos} pendiente${pendingRetos > 1 ? 's':''}` : 'asignados', c: '#4ade80', glow: 'rgba(74,222,128,0.12)' },
    { label: isAdmin ? 'Entregas Hoy' : 'Mis Insignias', value: isAdmin ? String(adminStats?.submissions_today ?? '—') : String(myBadges.length || '0'), sub: isAdmin ? 'submissions' : 'obtenidas', c: '#facc15', glow: 'rgba(250,204,21,0.12)' },
  ]

  const topAlerts = [
    { sev: 'CRÍTICO', c: '#ef4444', bg: 'rgba(239,68,68,0.1)', title: 'LockBit 4.0 detectado en DC-PROD-01', sub: 'hace 6 min' },
    { sev: 'ALTO',    c: '#f97316', bg: 'rgba(249,115,22,0.1)', title: 'Exfiltración 2.3 GB → IP externa',   sub: 'hace 12 min' },
    ...ioas.filter(x => ['critical','high'].includes(x.priority)).slice(0, 3).map(x => ({
      sev: x.priority.toUpperCase(), c: SEV[x.priority], bg: `${SEV[x.priority]}14`,
      title: x.ttp_name, sub: `${x.ttp} · ${x.tactic}`,
    })),
  ].slice(0, 5)

  return (
    <div className="space-y-4">

      {/* ── KPI row ─────────────────────────────────────────────────────────── */}
      <div className="grid grid-cols-6 gap-3">
        {KPIS.map(k => (
          <div key={k.label} className="rounded-xl p-4 relative overflow-hidden"
               style={{ ...glass, background: `linear-gradient(135deg, ${k.glow} 0%, rgba(15,23,42,0.55) 60%)` }}>
            <div className="absolute inset-x-0 top-0 h-px"
                 style={{ background: `linear-gradient(90deg, transparent, ${k.c}, transparent)` }} />
            <p className="text-2xl font-black tabular-nums" style={{ color: k.c, textShadow: `0 0 20px ${k.c}60` }}>{k.value}</p>
            <p className="text-slate-400 text-[10px] font-medium mt-0.5">{k.label}</p>
            <p className="text-slate-600 text-[9px]">{k.sub}</p>
          </div>
        ))}
      </div>

      {/* ── CTF Phases strip ─────────────────────────────────────────────────── */}
      {phases.length > 0 && (
        <div className="rounded-xl p-4" style={glass}>
          <div className="flex items-center justify-between mb-3">
            <p className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">Estado Fases CTF</p>
            <span className="text-[10px] text-slate-600">
              {activePhases} activa{activePhases !== 1 ? 's' : ''} · {phases.length} totales
            </span>
          </div>
          <div className="flex gap-2 flex-wrap">
            {phases.map(p => (
              <div key={p.id}
                   className="flex-1 min-w-28 rounded-lg px-3 py-2.5 transition-all"
                   style={{
                     background: p.status === 'active' ? 'rgba(74,222,128,0.08)' : 'rgba(255,255,255,0.03)',
                     border: `1px solid ${p.status === 'active' ? 'rgba(74,222,128,0.3)' : 'rgba(255,255,255,0.06)'}`,
                     boxShadow: p.status === 'active' ? '0 0 12px rgba(74,222,128,0.1)' : 'none',
                   }}>
                <div className="flex items-center gap-1.5 mb-1">
                  <span className="text-sm">{p.emoji}</span>
                  <span className="w-1.5 h-1.5 rounded-full shrink-0"
                        style={{ background: p.status === 'active' ? '#4ade80' : '#334155', boxShadow: p.status === 'active' ? '0 0 4px #4ade80' : 'none' }} />
                </div>
                <p className="text-[10px] font-semibold text-slate-300 leading-tight truncate">{p.name}</p>
                <p className="text-[9px] truncate mt-0.5" style={{ color: p.status === 'active' ? '#86efac' : '#334155' }}>
                  {p.status === 'active' ? `${p.category} · ${p.reto_count} retos` : 'Desactivado'}
                </p>
                {p.solves > 0 && (
                  <p className="text-[8px] text-slate-700 mt-0.5">{p.solves} solves</p>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── Row 2: gauge + map ─────────────────────────────────────────────── */}
      <div className="grid grid-cols-5 gap-4">
        <div className="col-span-2 rounded-xl p-4" style={glass}>
          <p className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-2">Nivel de Amenaza</p>
          <ThreatGauge level={criticalIOCs > 5 ? 85 : 74} />
        </div>
        <div className="col-span-3 rounded-xl overflow-hidden" style={glass}>
          <MiniThreatMap />
        </div>
      </div>

      {/* ── Row 3: alerts | kill chain | log | actor feed ──────────────────── */}
      <div className="grid grid-cols-4 gap-4">

        {/* Active alerts */}
        <div className="rounded-xl p-4 flex flex-col" style={glass}>
          <div className="flex items-center gap-2 mb-3">
            <span className="w-1.5 h-1.5 bg-red-500 rounded-full animate-pulse" />
            <p className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">Alertas Activas</p>
          </div>
          <div className="space-y-2 flex-1 overflow-y-auto">
            {topAlerts.map((a, i) => (
              <div key={i} className="rounded-lg px-3 py-2 flex items-start gap-2"
                   style={{ background: a.bg, border: `1px solid ${a.c}30` }}>
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
        <div className="rounded-xl p-4" style={glass}>
          <p className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-3">Kill Chain Coverage</p>
          <div className="space-y-3">
            {TACTICS.map(t => (
              <div key={t.name}>
                <div className="flex justify-between text-[10px] mb-1">
                  <span className="text-slate-400">{t.name}</span>
                  <span className="font-mono font-bold" style={{ color: t.color }}>{t.pct}%</span>
                </div>
                <div className="h-1.5 rounded-full overflow-hidden" style={{ background: 'rgba(255,255,255,0.05)' }}>
                  <div className="h-full rounded-full transition-all"
                       style={{ width: `${t.pct}%`, background: t.color, boxShadow: `0 0 8px ${t.color}80` }} />
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Live log — now injects real IOC events */}
        <div className="rounded-xl p-4" style={glass}>
          <div className="flex items-center gap-2 mb-3">
            <span className="font-mono text-green-400 text-xs font-bold">{'>'}_</span>
            <p className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">Log Feed</p>
            <span className="ml-auto w-1.5 h-1.5 bg-green-400 rounded-full animate-pulse" />
          </div>
          <div className="font-mono text-[10px] space-y-2">
            {logs.map((l, i) => (
              <div key={`${i}-${l.slice(0, 10)}`} className="truncate"
                   style={{ color: i === 0 ? '#86efac' : `rgba(100,116,139,${1 - i * 0.15})` }}>
                {l}
              </div>
            ))}
          </div>
        </div>

        {/* Threat actors live feed */}
        <div className="rounded-xl p-4" style={glass}>
          <p className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-3">Actores Rastreados</p>
          <div className="space-y-2">
            {actors.slice(0, 3).map(a => (
              <div key={a.name} className="rounded-lg px-3 py-2.5"
                   style={{ background: `${SEV[a.severity] ?? '#64748b'}0d`, border: `1px solid ${SEV[a.severity] ?? '#64748b'}30` }}>
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-slate-200">{a.name}</span>
                  <span className="text-[9px] font-bold" style={{ color: SEV[a.severity] }}>{a.severity}</span>
                </div>
                <p className="text-[9px] text-slate-600 mt-0.5 truncate">{a.active_campaign}</p>
                <div className="flex gap-1 mt-1 flex-wrap">
                  {a.ttps.slice(0, 3).map(t => (
                    <span key={t} className="text-[8px] font-mono px-1 py-0.5 rounded"
                          style={{ background: 'rgba(255,255,255,0.05)', color: '#475569' }}>{t}</span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* ── Row 4: IOC top | badges | challenges | AI summary ─────────────── */}
      <div className="grid grid-cols-4 gap-4">

        {/* Top IOC */}
        <div className="rounded-xl p-4" style={glass}>
          <p className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-3">IOC de Máxima Prioridad</p>
          {topIOC ? (
            <div className="space-y-2">
              <div className="rounded-lg px-3 py-2.5" style={{ background: 'rgba(239,68,68,0.06)', border: '1px solid rgba(239,68,68,0.2)' }}>
                <p className="text-cyan-300 font-mono text-xs font-bold truncate">{topIOC.ioc}</p>
                <p className="text-[9px] text-slate-600 mt-1">
                  {topIOC.type} · <span className="text-slate-400">{topIOC.threat_actor}</span>
                </p>
                <p className="text-[9px] text-slate-700 mt-0.5">{topIOC.mitre} · {topIOC.country}</p>
              </div>
              <div className="space-y-1.5">
                {iocs.filter(x => x.severity === 'high').slice(0, 2).map(ioc => (
                  <div key={ioc.ioc} className="flex items-center gap-2">
                    <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: '#f97316' }} />
                    <span className="text-[9px] font-mono text-slate-500 truncate">{ioc.ioc}</span>
                  </div>
                ))}
              </div>
            </div>
          ) : <p className="text-slate-700 text-xs">Cargando feed...</p>}
        </div>

        {/* My badges / platform badges */}
        <div className="rounded-xl p-4" style={glass}>
          <div className="flex items-center justify-between mb-3">
            <p className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">
              {isAdmin ? 'Insignias Emitidas' : 'Mis Insignias'}
            </p>
            <span className="text-[10px] font-mono" style={{ color: '#facc15' }}>
              {myBadges.length}
            </span>
          </div>
          {myBadges.length > 0 ? (
            <div className="space-y-1.5">
              {myBadges.slice(0, 4).map(b => {
                const tc = TIER_COLOR[b.tier] ?? '#64748b'
                const oc = ORG_COLOR[b.org]   ?? '#64748b'
                return (
                  <div key={b.id} className="flex items-center gap-2 rounded-lg px-2 py-1.5"
                       style={{ background: `${tc}0a`, border: `1px solid ${tc}22` }}>
                    <span className="w-4 h-4 rounded shrink-0 flex items-center justify-center text-[8px] font-bold"
                          style={{ background: `${tc}20`, color: tc }}>★</span>
                    <div className="flex-1 min-w-0">
                      <p className="text-[10px] text-slate-300 font-medium truncate">{b.name}</p>
                      <p className="text-[8px]" style={{ color: oc }}>{b.org}</p>
                    </div>
                    <span className="text-[8px] font-bold capitalize shrink-0" style={{ color: tc }}>{b.tier}</span>
                  </div>
                )
              })}
              {myBadges.length > 4 && (
                <p className="text-[9px] text-slate-700 text-center">+{myBadges.length - 4} más</p>
              )}
            </div>
          ) : (
            <p className="text-[10px] text-slate-700 text-center py-4">
              {token ? 'Sin insignias aún — completa retos para ganar.' : 'Inicia sesión para ver tus insignias.'}
            </p>
          )}
        </div>

        {/* Active challenges / admin pending */}
        <div className="rounded-xl p-4" style={glass}>
          <p className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-3">
            {isAdmin ? 'Estado Plataforma' : 'Mis Retos Activos'}
          </p>
          {isAdmin && adminStats ? (
            <div className="space-y-2">
              {[
                { label: 'Retos activos',    value: adminStats.active_challenges, color: '#a78bfa' },
                { label: 'Datasets',         value: adminStats.datasets,          color: '#f97316' },
                { label: 'Por calificar',    value: adminStats.pending_scoring,   color: '#facc15' },
                { label: 'Entregas hoy',     value: adminStats.submissions_today, color: '#4ade80' },
              ].map(s => (
                <div key={s.label} className="flex items-center justify-between rounded-lg px-3 py-1.5"
                     style={{ background: `${s.color}0a`, border: `1px solid ${s.color}20` }}>
                  <span className="text-[10px] text-slate-400">{s.label}</span>
                  <span className="text-sm font-bold font-mono" style={{ color: s.color }}>{s.value}</span>
                </div>
              ))}
            </div>
          ) : myChallenges.length > 0 ? (
            <div className="space-y-1.5">
              {myChallenges.slice(0, 4).map(c => (
                <div key={c.id} className="flex items-center gap-2 rounded-lg px-3 py-2"
                     style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.06)' }}>
                  <span className="w-1.5 h-1.5 rounded-full shrink-0"
                        style={{ background: c.submitted ? '#4ade80' : '#facc15' }} />
                  <span className="text-[10px] text-slate-400 flex-1 truncate">{c.title}</span>
                  {c.submitted > 0 && (
                    <span className="text-[9px] font-bold shrink-0" style={{ color: c.my_score != null ? '#4ade80' : '#facc15' }}>
                      {c.my_score != null ? `${c.my_score}/100` : '✓'}
                    </span>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <p className="text-[10px] text-slate-700 text-center py-4">Sin retos asignados.</p>
          )}
        </div>

        {/* AI summary — real data */}
        <div className="rounded-xl p-4" style={glass}>
          <div className="flex items-center gap-2 mb-2">
            <span className="w-1.5 h-1.5 bg-violet-400 rounded-full animate-pulse" />
            <p className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">AI Summary</p>
          </div>
          <p className="text-[10px] text-slate-400 leading-relaxed">
            {actors.length > 0
              ? `${actors.length} actores rastreados. ${criticalIOCs} IOCs críticos activos. ${highIoas} IOAs de alta prioridad. ${activePhases > 0 ? `Fase${activePhases > 1 ? 's' : ''} CTF activa${activePhases > 1 ? 's' : ''}: ${phases.filter(p => p.status==='active').map(p => p.name).join(', ')}.` : 'Sin fases CTF activas.'}`
              : 'Analizando inteligencia de amenazas...'}
          </p>
          <div className="mt-3 space-y-1.5">
            <div className="flex items-center gap-2">
              <div className="flex-1 h-1 rounded-full" style={{ background: 'rgba(255,255,255,0.05)' }}>
                <div className="h-full rounded-full" style={{ width: '94%', background: '#a78bfa', boxShadow: '0 0 6px #a78bfa' }} />
              </div>
              <span className="text-violet-400 text-[9px] font-mono shrink-0">94% conf.</span>
            </div>
            <div className="flex items-center gap-2 text-[9px] text-slate-600">
              <span className="text-cyan-700">{iocs.length} IOCs</span>
              <span>·</span>
              <span className="text-orange-700">{ioas.length} IOAs</span>
              <span>·</span>
              <span className="text-violet-700">{actors.length} actores</span>
            </div>
          </div>
        </div>
      </div>

    </div>
  )
}

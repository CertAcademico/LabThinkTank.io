import { useState, useEffect, useCallback } from 'react'
import { useAuth } from '../contexts/AuthContext'
import { BadgeCard, TIER, type Badge } from './BadgeCard'

const API = import.meta.env.VITE_API_URL ?? 'http://127.0.0.1:8000'

// ── Types ─────────────────────────────────────────────────────────────────────

interface User       { id: number; name: string; email: string; role: string; created_at: string }
interface Dataset    { id: number; name: string; description: string; source: string; schema_json: string; created_by: string; created_at: string }
interface Challenge  { id: number; title: string; description: string; objective: string; criteria: string; deadline?: string; status: string; difficulty: string; dataset_name?: string; badge_id?: number; badge_name?: string; badge_org?: string; badge_tier?: string; badge_icon?: string; min_score_badge: number; assigned_count: number; submission_count: number; created_at: string }
interface Team       { id: number; name: string; color: string; created_by: string; members: { name: string; email: string; role: string; joined_at: string }[] }
interface CtfChallenge { id: number; phase_id: number; phase_name: string; order_idx: number; title: string; description: string; flag: string; flag_format: string; hints_json: string; category: string; difficulty: string; points: number; docker_image: string; docker_port: string; tools_json: string; roles_json: string; dataset_id?: number; dataset_name?: string; is_team: number; status: string; solve_count: number }
interface BadgeProgress { name: string; email: string; role: string; badges: { id: number; name: string; org: string; tier: string; earned: boolean; earned_at?: string }[]; badge_count: number; ctf_solves: number; ctf_points: number; avg_score: number; submissions: number }
interface AwardedBadge { user_email: string; user_name: string; org: string; badge_name: string; tier: string; icon: string; awarded_by: string; awarded_at: string; badge_id: number }
interface Assignment { name: string; email: string; assigned_at: string; submitted: number }
interface Submission { id: number; challenge_id: number; challenge_title: string; user_name: string; user_email: string; code: string; output: string; plots_json: string; notes: string; score?: number; feedback: string; submitted_at: string }
interface Stats      { students: number; active_challenges: number; datasets: number; submissions_today: number; pending_scoring: number; recent_submissions: { user_name: string; challenge: string; submitted_at: string; score?: number }[] }

type Tab = 'dashboard' | 'users' | 'teams' | 'badges' | 'progreso' | 'fases' | 'datasets' | 'retos' | 'submissions' | 'fuentes'

interface CtfPhase {
  id: number; order_idx: number; name: string; category: string
  reto_count: number; group_label: string; emoji: string
  status: 'active' | 'inactive'; solves: number
}

const ROLE_OPTS = ['student', 'analyst', 'senior_analyst', 'instructor', 'admin']
const ROLE_COLOR: Record<string, string> = {
  student:        '#22d3ee',
  analyst:        '#4ade80',
  senior_analyst: '#a78bfa',
  instructor:     '#f97316',
  admin:          '#ef4444',
}

// ── Small helpers ─────────────────────────────────────────────────────────────

const glass = { background: 'rgba(15,23,42,0.6)', border: '1px solid rgba(255,255,255,0.07)', borderRadius: 12 }
const CYAN  = '#22d3ee'
const RED   = '#ef4444'

function StatCard({ label, value, sub, color = CYAN }: { label: string; value: number | string; sub?: string; color?: string }) {
  return (
    <div className="rounded-xl p-5 flex flex-col gap-1" style={glass}>
      <p className="text-[10px] font-bold tracking-widest uppercase" style={{ color }}>{label}</p>
      <p className="text-3xl font-bold text-white">{value}</p>
      {sub && <p className="text-xs text-slate-600">{sub}</p>}
    </div>
  )
}

function Badge({ label, color }: { label: string; color: string }) {
  return (
    <span className="text-[9px] font-bold px-1.5 py-0.5 rounded uppercase"
          style={{ background: `${color}20`, color }}>
      {label}
    </span>
  )
}

function apiFetch(path: string, token: string, opts?: RequestInit) {
  return fetch(`${API}${path}`, {
    ...opts,
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}`, ...(opts?.headers ?? {}) },
  }).then(r => {
    if (!r.ok) return r.json().then(e => Promise.reject(e.detail ?? 'Error'))
    return r.json()
  })
}

// ── Dashboard Tab ─────────────────────────────────────────────────────────────

function DashboardTab({ stats }: { stats: Stats | null }) {
  if (!stats) return <div className="text-slate-600 text-sm">Cargando estadísticas...</div>
  const isTunnel = window.location.hostname !== 'localhost' && window.location.hostname !== '127.0.0.1'
  const publicUrl = window.location.origin

  return (
    <div className="space-y-6">
      {/* Access URL banner */}
      <div className="rounded-xl px-4 py-3 flex items-center gap-3"
           style={{ background: isTunnel ? 'rgba(74,222,128,0.06)' : 'rgba(34,211,238,0.06)', border: `1px solid ${isTunnel ? 'rgba(74,222,128,0.2)' : 'rgba(34,211,238,0.15)'}` }}>
        <div className="w-2 h-2 rounded-full shrink-0 animate-pulse"
             style={{ background: isTunnel ? '#4ade80' : CYAN }} />
        <div className="flex-1 min-w-0">
          <p className="text-[10px] font-bold" style={{ color: isTunnel ? '#4ade80' : CYAN }}>
            {isTunnel ? '🌐 Acceso público activo (Cloudflare Tunnel)' : '🖥 Acceso local'}
          </p>
          <p className="text-xs font-mono text-slate-300 truncate">{publicUrl}</p>
        </div>
        <button onClick={() => navigator.clipboard?.writeText(publicUrl)}
                className="text-[9px] px-2 py-1 rounded shrink-0 transition-all hover:opacity-80"
                style={{ background: 'rgba(255,255,255,0.06)', color: '#64748b', border: '1px solid rgba(255,255,255,0.08)' }}>
          Copiar URL
        </button>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-5 gap-4">
        <StatCard label="Estudiantes"       value={stats.students}           color={CYAN}      />
        <StatCard label="Retos activos"     value={stats.active_challenges}  color="#a78bfa"   />
        <StatCard label="Datasets"          value={stats.datasets}           color="#f97316"   />
        <StatCard label="Entregas hoy"      value={stats.submissions_today}  color="#4ade80"   />
        <StatCard label="Por calificar"     value={stats.pending_scoring}    color="#facc15"   />
      </div>

      <div className="rounded-xl overflow-hidden" style={glass}>
        <div className="px-5 py-3 border-b text-xs font-bold text-slate-500 tracking-widest uppercase"
             style={{ borderColor: 'rgba(255,255,255,0.06)' }}>
          Actividad reciente
        </div>
        {stats.recent_submissions.length === 0 ? (
          <p className="px-5 py-6 text-xs text-slate-700">Sin entregas aún.</p>
        ) : (
          <div className="divide-y divide-white/5">
            {stats.recent_submissions.map((s, i) => (
              <div key={i} className="flex items-center gap-4 px-5 py-3">
                <div className="w-7 h-7 rounded-full flex items-center justify-center text-xs font-bold shrink-0"
                     style={{ background: `${CYAN}18`, color: CYAN }}>
                  {s.user_name[0]?.toUpperCase()}
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-xs text-slate-200 truncate">{s.user_name}</p>
                  <p className="text-[10px] text-slate-600 truncate">{s.challenge}</p>
                </div>
                <div className="text-right shrink-0">
                  {s.score != null
                    ? <Badge label={`${s.score}/100`} color="#4ade80" />
                    : <Badge label="Sin calificar" color="#facc15" />}
                  <p className="text-[9px] text-slate-700 mt-0.5">
                    {new Date(s.submitted_at).toLocaleString('es-MX', { hour: '2-digit', minute: '2-digit', day: 'numeric', month: 'short' })}
                  </p>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

// ── Users Tab ─────────────────────────────────────────────────────────────────

function UsersTab({ users, challenges, allBadges, token, onRefresh }: {
  users: User[]; challenges: Challenge[]; allBadges: Badge[]; token: string; onRefresh: () => void
}) {
  const [assignTo,  setAssignTo]  = useState('')
  const [selChal,   setSelChal]   = useState<number | ''>('')
  const [loading,   setLoading]   = useState(false)
  const [expanded,  setExpanded]  = useState<string | null>(null)
  const [roleSel,   setRoleSel]   = useState<Record<string, string>>({})
  const [badgeSel,  setBadgeSel]  = useState<Record<string, number | ''>>({})

  const nonAdmin = users.filter(u => u.role !== 'admin')

  const doAssign = async () => {
    if (!assignTo || !selChal) return
    setLoading(true)
    try {
      await apiFetch(`/admin/challenges/${selChal}/assign`, token, {
        method: 'POST', body: JSON.stringify({ emails: [assignTo] }),
      })
      onRefresh(); setAssignTo(''); setSelChal('')
    } catch (e) { alert(e) } finally { setLoading(false) }
  }

  const changeRole = async (email: string) => {
    const role = roleSel[email]
    if (!role) return
    try {
      await apiFetch(`/admin/users/${encodeURIComponent(email)}/role`, token, {
        method: 'PATCH', body: JSON.stringify({ role }),
      })
      onRefresh()
    } catch (e) { alert(e) }
  }

  const awardBadge = async (email: string) => {
    const badge_id = badgeSel[email]
    if (!badge_id) return
    try {
      await apiFetch('/admin/badges/award', token, {
        method: 'POST', body: JSON.stringify({ user_email: email, badge_id }),
      })
      setBadgeSel(p => ({ ...p, [email]: '' }))
      onRefresh()
    } catch (e) { alert(e) }
  }

  const selectStyle = { background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)' }

  return (
    <div className="space-y-4">
      {/* Quick assign bar */}
      <div className="rounded-xl p-4 flex items-center gap-3 flex-wrap" style={glass}>
        <p className="text-xs font-semibold text-slate-400 shrink-0">Asignación rápida a reto:</p>
        <select value={assignTo} onChange={e => setAssignTo(e.target.value)}
                className="flex-1 min-w-40 rounded-lg px-3 py-2 text-xs text-slate-100 outline-none"
                style={selectStyle}>
          <option value="">Seleccionar usuario...</option>
          {nonAdmin.map(u => <option key={u.email} value={u.email}>{u.name} ({u.email})</option>)}
        </select>
        <select value={selChal} onChange={e => setSelChal(Number(e.target.value) || '')}
                className="flex-1 min-w-52 rounded-lg px-3 py-2 text-xs text-slate-100 outline-none"
                style={selectStyle}>
          <option value="">Seleccionar reto...</option>
          {challenges.filter(c => c.status === 'active').map(c =>
            <option key={c.id} value={c.id}>{c.title}</option>)}
        </select>
        <button onClick={doAssign} disabled={loading || !assignTo || !selChal}
                className="px-4 py-2 rounded-lg text-xs font-bold disabled:opacity-40"
                style={{ background: `${CYAN}18`, border: `1px solid ${CYAN}44`, color: CYAN }}>
          {loading ? 'Asignando...' : 'Asignar →'}
        </button>
      </div>

      {/* Users list */}
      <div className="rounded-xl overflow-hidden" style={glass}>
        <div className="px-5 py-3 border-b grid grid-cols-5 text-[10px] font-bold text-slate-600 uppercase tracking-wider"
             style={{ borderColor: 'rgba(255,255,255,0.06)' }}>
          <span className="col-span-2">Usuario</span>
          <span>Rol actual</span>
          <span>Registrado</span>
          <span />
        </div>
        <div className="divide-y divide-white/[0.04]">
          {users.map(u => {
            const isOpen = expanded === u.email
            const rc     = ROLE_COLOR[u.role] ?? CYAN
            return (
              <div key={u.email}>
                <div className="px-5 py-3 grid grid-cols-5 items-center hover:bg-white/[0.02] cursor-pointer transition-colors"
                     onClick={() => setExpanded(isOpen ? null : u.email)}>
                  <div className="col-span-2 flex items-center gap-2">
                    <div className="w-7 h-7 rounded-full flex items-center justify-center text-xs font-bold shrink-0"
                         style={{ background: `${rc}18`, color: rc }}>
                      {u.name[0]?.toUpperCase()}
                    </div>
                    <div className="min-w-0">
                      <p className="text-xs text-slate-200 truncate">{u.name}</p>
                      <p className="text-[9px] text-slate-600 truncate">{u.email}</p>
                    </div>
                  </div>
                  <Badge label={u.role} color={rc} />
                  <span className="text-[10px] text-slate-700">
                    {new Date(u.created_at).toLocaleDateString('es-MX')}
                  </span>
                  <svg viewBox="0 0 24 24" className="w-3.5 h-3.5 text-slate-700 ml-auto transition-transform"
                       style={{ transform: isOpen ? 'rotate(180deg)' : undefined }}
                       fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M6 9l6 6 6-6" />
                  </svg>
                </div>

                {isOpen && (
                  <div className="px-5 py-4 border-t space-y-4"
                       style={{ borderColor: 'rgba(255,255,255,0.05)', background: 'rgba(255,255,255,0.015)' }}>
                    {/* Change role */}
                    <div className="flex items-center gap-3 flex-wrap">
                      <p className="text-[10px] text-slate-600 font-bold uppercase tracking-wider shrink-0">Cambiar rol:</p>
                      <select value={roleSel[u.email] ?? u.role}
                              onChange={e => setRoleSel(p => ({ ...p, [u.email]: e.target.value }))}
                              className="rounded-lg px-3 py-1.5 text-xs text-slate-100 outline-none"
                              style={selectStyle}>
                        {ROLE_OPTS.map(r => (
                          <option key={r} value={r}>{r}</option>
                        ))}
                      </select>
                      <button onClick={() => changeRole(u.email)}
                              disabled={!roleSel[u.email] || roleSel[u.email] === u.role}
                              className="px-3 py-1.5 rounded-lg text-xs font-bold disabled:opacity-30"
                              style={{ background: 'rgba(167,139,250,0.15)', border: '1px solid rgba(167,139,250,0.35)', color: '#a78bfa' }}>
                        Actualizar
                      </button>
                    </div>

                    {/* Award badge */}
                    <div className="flex items-center gap-3 flex-wrap">
                      <p className="text-[10px] text-slate-600 font-bold uppercase tracking-wider shrink-0">Otorgar insignia:</p>
                      <select value={badgeSel[u.email] ?? ''}
                              onChange={e => setBadgeSel(p => ({ ...p, [u.email]: Number(e.target.value) || '' }))}
                              className="flex-1 min-w-52 rounded-lg px-3 py-1.5 text-xs text-slate-100 outline-none"
                              style={selectStyle}>
                        <option value="">Seleccionar insignia...</option>
                        {['CertAcademico', 'redciber', 'LabThinkTank'].map(org => (
                          <optgroup key={org} label={`── ${org} ──`}>
                            {allBadges.filter(b => b.org === org).map(b => (
                              <option key={b.id} value={b.id}>
                                [{b.tier.toUpperCase()}] {b.name}
                              </option>
                            ))}
                          </optgroup>
                        ))}
                      </select>
                      <button onClick={() => awardBadge(u.email)}
                              disabled={!badgeSel[u.email]}
                              className="px-3 py-1.5 rounded-lg text-xs font-bold disabled:opacity-30"
                              style={{ background: 'rgba(250,204,21,0.12)', border: '1px solid rgba(250,204,21,0.3)', color: '#facc15' }}>
                        Otorgar 🏅
                      </button>
                    </div>
                  </div>
                )}
              </div>
            )
          })}
          {users.length === 0 && (
            <p className="px-5 py-6 text-xs text-slate-700">No hay usuarios registrados.</p>
          )}
        </div>
      </div>
    </div>
  )
}

// ── Equipos Tab ───────────────────────────────────────────────────────────────

const TEAM_ROLES: Record<string, { label: string; color: string; short: string }> = {
  analista_datos:   { label: 'Analista de Datos',  color: '#22d3ee', short: 'AD' },
  ciberseguridad:   { label: 'Ciberseguridad',      color: '#f97316', short: 'CS' },
  ciencia_datos:    { label: 'Ciencia de Datos',    color: '#a78bfa', short: 'CD' },
  machine_learning: { label: 'Machine Learning',    color: '#4ade80', short: 'ML' },
}

function EquiposTab({ teams, users, challenges, allBadges, token, onRefresh }: {
  teams: Team[]; users: User[]; challenges: Challenge[]; allBadges: Badge[]; token: string; onRefresh: () => void
}) {
  const [showForm,   setShowForm]   = useState(false)
  const [form,       setForm]       = useState({ name: '', color: '#22d3ee' })
  const [selUsers,   setSelUsers]   = useState<Record<number, string[]>>({})
  const [selChal,    setSelChal]    = useState<Record<number, number | ''>>({})
  const [loading,    setLoading]    = useState(false)
  // Retos grupales por equipo
  const [groupChallenges, setGroupChallenges] = useState<Record<number, {id:number;title:string;badge_name?:string;badge_tier?:string;badge_earned?:number}[]>>({})
  const [selGroupChal, setSelGroupChal] = useState<Record<number, number | ''>>({})
  // Insignias de equipo
  const [teamBadgesAwarded, setTeamBadgesAwarded] = useState<Record<number,{id:number;name:string;org:string;tier:string}[]>>({})
  const [selTeamBadge, setSelTeamBadge] = useState<Record<number, number | ''>>({})
  const [expandedTeam, setExpandedTeam] = useState<number | null>(null)

  const create = async () => {
    if (!form.name) return
    setLoading(true)
    try {
      await apiFetch('/admin/teams', token, { method: 'POST', body: JSON.stringify(form) })
      setShowForm(false); setForm({ name: '', color: '#22d3ee' }); onRefresh()
    } catch (e) { alert(e) } finally { setLoading(false) }
  }

  const addMembers = async (teamId: number) => {
    const emails = selUsers[teamId] ?? []
    if (!emails.length) return
    await apiFetch(`/admin/teams/${teamId}/members`, token, {
      method: 'POST', body: JSON.stringify({ emails }),
    }).catch(alert)
    setSelUsers(p => ({ ...p, [teamId]: [] })); onRefresh()
  }

  const removeMember = async (teamId: number, email: string) => {
    await apiFetch(`/admin/teams/${teamId}/members/${encodeURIComponent(email)}`, token, { method: 'DELETE' }).catch(alert)
    onRefresh()
  }

  const assignTeamToChallenge = async (teamId: number) => {
    const chalId = selChal[teamId]
    if (!chalId) return
    const memberEmails = teams.find(t => t.id === teamId)?.members.map(m => m.email) ?? []
    if (!memberEmails.length) return alert('El equipo no tiene miembros')
    await apiFetch(`/admin/challenges/${chalId}/assign`, token, {
      method: 'POST', body: JSON.stringify({ emails: memberEmails }),
    }).catch(alert)
    setSelChal(p => ({ ...p, [teamId]: '' })); onRefresh()
  }

  const loadGroupChallenges = async (teamId: number) => {
    const data = await apiFetch(`/admin/teams/${teamId}/group-challenges`, token).catch(() => [])
    setGroupChallenges(p => ({ ...p, [teamId]: data }))
    const badges = await apiFetch('/admin/team-badges/awarded', token).catch(() => [])
    const byTeam: Record<number, {id:number;name:string;org:string;tier:string}[]> = {}
    for (const b of badges) {
      if (!byTeam[b.team_id]) byTeam[b.team_id] = []
      byTeam[b.team_id].push({ id: b.badge_id, name: b.badge_name, org: b.org, tier: b.tier })
    }
    setTeamBadgesAwarded(byTeam)
  }

  const assignGroupChallenge = async (teamId: number) => {
    const cid = selGroupChal[teamId]
    if (!cid) return
    await apiFetch(`/admin/teams/${teamId}/group-challenges`, token, {
      method: 'POST', body: JSON.stringify({ challenge_id: cid }),
    }).catch(alert)
    setSelGroupChal(p => ({ ...p, [teamId]: '' }))
    loadGroupChallenges(teamId)
  }

  const removeGroupChallenge = async (teamId: number, cid: number) => {
    await apiFetch(`/admin/teams/${teamId}/group-challenges/${cid}`, token, { method: 'DELETE' }).catch(alert)
    loadGroupChallenges(teamId)
  }

  const awardTeamBadge = async (teamId: number) => {
    const bid = selTeamBadge[teamId]
    if (!bid) return
    await apiFetch('/admin/team-badges/award', token, {
      method: 'POST', body: JSON.stringify({ team_id: teamId, badge_id: bid }),
    }).catch(alert)
    setSelTeamBadge(p => ({ ...p, [teamId]: '' }))
    loadGroupChallenges(teamId)
  }

  const revokeTeamBadge = async (teamId: number, badgeId: number) => {
    await apiFetch('/admin/team-badges/revoke', token, {
      method: 'DELETE', body: JSON.stringify({ team_id: teamId, badge_id: badgeId }),
    }).catch(alert)
    loadGroupChallenges(teamId)
  }

  const toggleTeam = (id: number) => {
    const next = expandedTeam === id ? null : id
    setExpandedTeam(next)
    if (next !== null) loadGroupChallenges(next)
  }

  const deleteTeam = async (id: number) => {
    if (!confirm('¿Eliminar equipo?')) return
    await apiFetch(`/admin/teams/${id}`, token, { method: 'DELETE' }).catch(alert)
    onRefresh()
  }

  const nonTeamUsers = (teamId: number) =>
    users.filter(u => u.role !== 'admin' && !teams.find(t => t.id === teamId)?.members.find(m => m.email === u.email))

  const selectStyle = { background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)' }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-xs text-slate-500">{teams.length} equipos · {users.filter(u => u.role !== 'admin').length} usuarios disponibles</p>
        <button onClick={() => setShowForm(s => !s)}
                className="px-4 py-2 rounded-lg text-xs font-bold"
                style={{ background: 'rgba(34,211,238,0.1)', border: '1px solid rgba(34,211,238,0.3)', color: CYAN }}>
          {showForm ? 'Cancelar' : '+ Nuevo equipo'}
        </button>
      </div>

      {showForm && (
        <div className="rounded-xl p-4 flex items-center gap-3 flex-wrap" style={glass}>
          <input value={form.name} onChange={e => setForm(p => ({ ...p, name: e.target.value }))}
                 placeholder="Nombre del equipo (ej: Equipo Alpha)"
                 className="flex-1 rounded-lg px-3 py-2 text-xs text-slate-100 outline-none"
                 style={selectStyle} />
          <div className="flex items-center gap-2">
            <label className="text-[10px] text-slate-600">Color:</label>
            <input type="color" value={form.color} onChange={e => setForm(p => ({ ...p, color: e.target.value }))}
                   className="w-8 h-8 rounded cursor-pointer border-0" style={{ background: 'transparent' }} />
          </div>
          <button onClick={create} disabled={loading || !form.name}
                  className="px-4 py-2 rounded-lg text-xs font-bold disabled:opacity-40"
                  style={{ background: `${CYAN}18`, border: `1px solid ${CYAN}44`, color: CYAN }}>
            {loading ? 'Creando...' : 'Crear equipo →'}
          </button>
        </div>
      )}

      <div className="space-y-3">
        {teams.map(t => {
          const notIn = nonTeamUsers(t.id)
          return (
            <div key={t.id} className="rounded-xl overflow-hidden" style={glass}>
              {/* Header */}
              <div className="flex items-center gap-3 px-5 py-4 border-b"
                   style={{ borderColor: 'rgba(255,255,255,0.06)' }}>
                <div className="w-3 h-3 rounded-full shrink-0" style={{ background: t.color, boxShadow: `0 0 8px ${t.color}88` }} />
                <p className="text-sm font-semibold text-slate-100 flex-1">{t.name}</p>
                <span className="text-[10px] text-slate-600">{t.members.length} miembros</span>
                <button onClick={() => deleteTeam(t.id)}
                        className="text-[10px] px-2 py-1 rounded"
                        style={{ border: `1px solid ${RED}30`, color: RED }}>✕</button>
              </div>

              <div className="p-4 space-y-4">
                {/* Members with roles */}
                <div className="space-y-1.5">
                  <p className="text-[9px] text-slate-600 uppercase tracking-wider font-bold">
                    Miembros y Roles
                    <span className="ml-2 text-[8px] text-slate-700 normal-case font-normal">— selecciona el rol por persona</span>
                  </p>
                  <div className="grid grid-cols-2 gap-1.5">
                    {t.members.map(m => {
                      const roleMeta = TEAM_ROLES[m.role] ?? TEAM_ROLES.analista_datos
                      return (
                        <div key={m.email} className="flex items-center gap-2 rounded-lg px-2.5 py-2"
                             style={{ background: `${t.color}08`, border: `1px solid ${t.color}22` }}>
                          <div className="w-6 h-6 rounded-full flex items-center justify-center text-[9px] font-black shrink-0"
                               style={{ background: `${roleMeta.color}20`, color: roleMeta.color }}>
                            {roleMeta.short}
                          </div>
                          <div className="flex-1 min-w-0">
                            <p className="text-[10px] font-semibold text-slate-200 truncate">{m.name}</p>
                            <select
                              value={m.role || 'analista_datos'}
                              onChange={async e => {
                                await apiFetch(`/admin/teams/${t.id}/members/${encodeURIComponent(m.email)}/role`, token, {
                                  method: 'PATCH', body: JSON.stringify({ role: e.target.value })
                                }).catch(alert)
                                onRefresh()
                              }}
                              className="text-[8px] rounded px-1 py-0.5 outline-none w-full"
                              style={{ background: `${roleMeta.color}12`, color: roleMeta.color, border: `1px solid ${roleMeta.color}33` }}>
                              {Object.entries(TEAM_ROLES).map(([k, v]) =>
                                <option key={k} value={k}>{v.label}</option>
                              )}
                            </select>
                          </div>
                          <button onClick={() => removeMember(t.id, m.email)}
                                  className="text-[9px] opacity-40 hover:opacity-100 shrink-0"
                                  style={{ color: RED }}>✕</button>
                        </div>
                      )
                    })}
                    {t.members.length === 0 && (
                      <p className="text-[10px] text-slate-700 col-span-2">Sin miembros aún.</p>
                    )}
                  </div>

                  {/* Role coverage indicator */}
                  {t.members.length > 0 && (
                    <div className="flex items-center gap-2 flex-wrap pt-1">
                      {Object.entries(TEAM_ROLES).map(([k, v]) => {
                        const has = t.members.some(m => m.role === k)
                        return (
                          <span key={k} className="text-[8px] px-2 py-0.5 rounded-full"
                                style={{ background: has ? `${v.color}15` : 'rgba(255,255,255,0.03)', color: has ? v.color : '#475569', border: `1px solid ${has ? v.color+'33' : 'rgba(255,255,255,0.06)'}` }}>
                            {has ? '✓' : '✗'} {v.short}
                          </span>
                        )
                      })}
                      {Object.values(TEAM_ROLES).every(v => t.members.some(m => m.role === Object.keys(TEAM_ROLES).find(k => TEAM_ROLES[k] === v)!)) && (
                        <span className="text-[8px] text-green-500">✓ Todos los roles cubiertos</span>
                      )}
                    </div>
                  )}
                </div>

                <div className="grid grid-cols-2 gap-3">
                  {/* Add members */}
                  <div className="space-y-2">
                    <p className="text-[9px] text-slate-600 uppercase tracking-wider font-bold">Agregar miembros</p>
                    <div className="space-y-1 max-h-28 overflow-y-auto">
                      {notIn.map(u => (
                        <label key={u.email} className="flex items-center gap-2 cursor-pointer">
                          <input type="checkbox"
                                 checked={(selUsers[t.id] ?? []).includes(u.email)}
                                 onChange={e => setSelUsers(p => {
                                   const cur = p[t.id] ?? []
                                   return { ...p, [t.id]: e.target.checked ? [...cur, u.email] : cur.filter(x => x !== u.email) }
                                 })}
                                 className="accent-cyan-400" />
                          <span className="text-[10px] text-slate-400">{u.name}</span>
                        </label>
                      ))}
                      {notIn.length === 0 && <p className="text-[10px] text-slate-700">Todos asignados.</p>}
                    </div>
                    <button onClick={() => addMembers(t.id)} disabled={!(selUsers[t.id]?.length)}
                            className="w-full py-1.5 rounded text-[10px] font-bold disabled:opacity-30"
                            style={{ background: `${t.color}15`, border: `1px solid ${t.color}33`, color: t.color }}>
                      Agregar seleccionados
                    </button>
                  </div>

                  {/* Assign team to individual challenge */}
                  <div className="space-y-2">
                    <p className="text-[9px] text-slate-600 uppercase tracking-wider font-bold">Reto individual → todos los miembros</p>
                    <select value={selChal[t.id] ?? ''}
                            onChange={e => setSelChal(p => ({ ...p, [t.id]: Number(e.target.value) || '' }))}
                            className="w-full rounded-lg px-3 py-2 text-xs text-slate-100 outline-none"
                            style={selectStyle}>
                      <option value="">Seleccionar reto...</option>
                      {challenges.filter(c => c.status === 'active').map(c =>
                        <option key={c.id} value={c.id}>{c.title}</option>)}
                    </select>
                    <button onClick={() => assignTeamToChallenge(t.id)} disabled={!selChal[t.id]}
                            className="w-full py-1.5 rounded text-[10px] font-bold disabled:opacity-30"
                            style={{ background: 'rgba(167,139,250,0.12)', border: '1px solid rgba(167,139,250,0.3)', color: '#a78bfa' }}>
                      Asignar a cada miembro →
                    </button>
                  </div>
                </div>

                {/* ── Reto Grupal (separado de insignias individuales) ──────── */}
                <div className="rounded-xl p-3 space-y-3 mt-1"
                     style={{ background: `${t.color}06`, border: `1px solid ${t.color}22` }}>
                  <div className="flex items-center justify-between">
                    <p className="text-[9px] font-bold uppercase tracking-wider" style={{ color: t.color }}>
                      🏆 Reto Grupal del Equipo
                    </p>
                    <button onClick={() => toggleTeam(t.id)}
                            className="text-[8px] px-2 py-0.5 rounded transition-all"
                            style={{ background: `${t.color}15`, color: t.color, border: `1px solid ${t.color}33` }}>
                      {expandedTeam === t.id ? 'Cerrar ▲' : 'Gestionar ▼'}
                    </button>
                  </div>

                  {/* Current group challenges */}
                  {(groupChallenges[t.id] ?? []).length > 0 ? (
                    <div className="space-y-1.5">
                      {(groupChallenges[t.id] ?? []).map(gc => {
                        const tc = gc.badge_tier ? (TIER[gc.badge_tier]?.color ?? '#facc15') : null
                        return (
                          <div key={gc.id} className="flex items-center justify-between gap-2 rounded-lg px-3 py-2"
                               style={{ background: 'rgba(15,23,42,0.5)', border: '1px solid rgba(255,255,255,0.07)' }}>
                            <div className="flex-1 min-w-0">
                              <p className="text-[10px] font-semibold text-slate-200 truncate">{gc.title}</p>
                              {gc.badge_name && tc && (
                                <p className="text-[8px]" style={{ color: gc.badge_earned ? tc : '#475569' }}>
                                  {gc.badge_earned ? '★ Insignia ganada: ' : '○ Al completar: '}
                                  {gc.badge_name}
                                </p>
                              )}
                            </div>
                            <button onClick={() => removeGroupChallenge(t.id, gc.id)}
                                    className="text-[8px] px-1.5 py-0.5 rounded shrink-0"
                                    style={{ border: `1px solid ${RED}30`, color: RED }}>✕</button>
                          </div>
                        )
                      })}
                    </div>
                  ) : (
                    expandedTeam === t.id
                      ? <p className="text-[10px] text-slate-700">Sin reto grupal asignado.</p>
                      : <p className="text-[10px] text-slate-700">Toca "Gestionar" para ver y asignar.</p>
                  )}

                  {expandedTeam === t.id && (
                    <div className="flex gap-2">
                      <select value={selGroupChal[t.id] ?? ''}
                              onChange={e => setSelGroupChal(p => ({ ...p, [t.id]: Number(e.target.value) || '' }))}
                              className="flex-1 rounded-lg px-2 py-1.5 text-[10px] text-slate-100 outline-none"
                              style={selectStyle}>
                        <option value="">Seleccionar reto grupal...</option>
                        {challenges.filter(c => c.status === 'active').map(c =>
                          <option key={c.id} value={c.id}>{c.title}</option>)}
                      </select>
                      <button onClick={() => assignGroupChallenge(t.id)} disabled={!selGroupChal[t.id]}
                              className="px-3 py-1.5 rounded text-[10px] font-bold disabled:opacity-30 shrink-0"
                              style={{ background: `${t.color}20`, border: `1px solid ${t.color}44`, color: t.color }}>
                        Asignar →
                      </button>
                    </div>
                  )}
                </div>

                {/* ── Insignias del Equipo (NO afecta perfiles individuales) ─── */}
                {expandedTeam === t.id && (
                  <div className="rounded-xl p-3 space-y-3"
                       style={{ background: 'rgba(250,204,21,0.04)', border: '1px solid rgba(250,204,21,0.12)' }}>
                    <p className="text-[9px] font-bold uppercase tracking-wider text-yellow-700">
                      ★ Insignias del Equipo <span className="font-normal text-slate-600 normal-case">(independientes del perfil individual)</span>
                    </p>

                    {/* Awarded team badges */}
                    {(teamBadgesAwarded[t.id] ?? []).length > 0 ? (
                      <div className="flex flex-wrap gap-1.5">
                        {(teamBadgesAwarded[t.id] ?? []).map(b => {
                          const tc = TIER[b.tier]?.color ?? '#facc15'
                          return (
                            <div key={b.id} className="flex items-center gap-1 rounded-full px-2 py-0.5"
                                 style={{ background: `${tc}12`, border: `1px solid ${tc}33` }}>
                              <span className="text-[9px] font-bold" style={{ color: tc }}>★ {b.name}</span>
                              <span className="text-[8px] text-slate-700">({b.org})</span>
                              <button onClick={() => revokeTeamBadge(t.id, b.id)}
                                      className="text-[8px] ml-1 opacity-40 hover:opacity-100"
                                      style={{ color: RED }}>✕</button>
                            </div>
                          )
                        })}
                      </div>
                    ) : (
                      <p className="text-[10px] text-slate-700">Sin insignias de equipo aún.</p>
                    )}

                    {/* Award new team badge */}
                    <div className="flex gap-2">
                      <select value={selTeamBadge[t.id] ?? ''}
                              onChange={e => setSelTeamBadge(p => ({ ...p, [t.id]: Number(e.target.value) || '' }))}
                              className="flex-1 rounded-lg px-2 py-1.5 text-[10px] text-slate-100 outline-none"
                              style={selectStyle}>
                        <option value="">Seleccionar insignia...</option>
                        {Object.entries(allBadges.reduce((acc, b) => { (acc[b.org] = acc[b.org] || []).push(b); return acc }, {} as Record<string, Badge[]>)).map(([org, bs]) => (
                          <optgroup key={org} label={org}>
                            {bs.map(b => <option key={b.id} value={b.id}>{b.name} ({b.tier})</option>)}
                          </optgroup>
                        ))}
                      </select>
                      <button onClick={() => awardTeamBadge(t.id)} disabled={!selTeamBadge[t.id]}
                              className="px-3 py-1.5 rounded text-[10px] font-bold disabled:opacity-30 shrink-0"
                              style={{ background: 'rgba(250,204,21,0.15)', border: '1px solid rgba(250,204,21,0.35)', color: '#facc15' }}>
                        Otorgar ★
                      </button>
                    </div>
                  </div>
                )}

              </div>
            </div>
          )
        })}
        {teams.length === 0 && <p className="text-xs text-slate-700 px-2">Sin equipos. Crea uno arriba.</p>}
      </div>
    </div>
  )
}

// ── Insignias Tab ─────────────────────────────────────────────────────────────

function InsigniasTab({ allBadges, awarded, token, onRefresh }: {
  allBadges: Badge[]; awarded: AwardedBadge[]; token: string; onRefresh: () => void
}) {
  const ORG_COLOR: Record<string, string> = {
    CertAcademico: '#60a5fa',
    redciber:      '#f87171',
    LabThinkTank:  '#22d3ee',
  }

  const revoke = async (email: string, badge_id: number) => {
    if (!confirm('¿Revocar esta insignia?')) return
    await apiFetch('/admin/badges/revoke', token, {
      method: 'DELETE', body: JSON.stringify({ user_email: email, badge_id }),
    }).catch(alert)
    onRefresh()
  }

  return (
    <div className="space-y-8">
      {/* Catalogue */}
      <div>
        <p className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-4">Catálogo de insignias</p>
        {(['CertAcademico', 'redciber', 'LabThinkTank'] as const).map(org => {
          const orgBadges = allBadges.filter(b => b.org === org)
          const c = ORG_COLOR[org]
          return (
            <div key={org} className="mb-6">
              <div className="flex items-center gap-2 mb-3">
                <span className="text-[10px] font-bold px-2.5 py-1 rounded-full font-mono"
                      style={{ background: `${c}12`, border: `1px solid ${c}33`, color: c }}>
                  {org}
                </span>
                <div className="flex-1 h-px" style={{ background: `${c}22` }} />
              </div>
              <div className="flex flex-wrap gap-5">
                {orgBadges.map(b => {
                  const count = awarded.filter(a => a.badge_id === b.id).length
                  return (
                    <div key={b.id} className="flex flex-col items-center gap-1 w-20">
                      <BadgeCard badge={b} size="md" showOrg={false} />
                      <span className="text-[8px] font-mono text-slate-700">
                        {count > 0 ? `${count} otorgada${count > 1 ? 's' : ''}` : 'Sin otorgar'}
                      </span>
                    </div>
                  )
                })}
              </div>
            </div>
          )
        })}
      </div>

      {/* Awarded log */}
      <div>
        <p className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-3">
          Insignias otorgadas ({awarded.length})
        </p>
        <div className="rounded-xl overflow-hidden" style={glass}>
          {awarded.length === 0 ? (
            <p className="px-5 py-6 text-xs text-slate-700">No se han otorgado insignias aún.</p>
          ) : (
            <div className="divide-y divide-white/[0.04]">
              {awarded.map((a, i) => {
                const t   = TIER[a.tier] ?? TIER.bronze
                const col = ORG_COLOR[a.org] ?? CYAN
                return (
                  <div key={i} className="flex items-center gap-4 px-5 py-3 hover:bg-white/[0.02]">
                    <div className="w-7 h-7 rounded-full flex items-center justify-center text-xs font-bold shrink-0"
                         style={{ background: `${col}18`, color: col }}>
                      {a.user_name[0]?.toUpperCase()}
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="text-xs text-slate-200 truncate">{a.user_name}</p>
                      <p className="text-[9px] text-slate-600 truncate">{a.user_email}</p>
                    </div>
                    <div className="text-center shrink-0">
                      <p className="text-[10px] font-bold" style={{ color: t.color }}>{a.badge_name}</p>
                      <p className="text-[9px]" style={{ color: col }}>{a.org}</p>
                    </div>
                    <span className="text-[9px] font-bold px-1.5 py-0.5 rounded capitalize"
                          style={{ background: `${t.color}15`, color: t.color }}>
                      {a.tier}
                    </span>
                    <p className="text-[9px] text-slate-700 shrink-0">
                      {new Date(a.awarded_at).toLocaleDateString('es-MX')}
                    </p>
                    <button onClick={() => revoke(a.user_email, a.badge_id)}
                            className="text-[9px] px-2 py-1 rounded shrink-0"
                            style={{ border: `1px solid ${RED}30`, color: RED }}>✕</button>
                  </div>
                )
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

// ── Fases CTF Tab ────────────────────────────────────────────────────────────

const CAT_CTF_COLOR: Record<string, string> = {
  Intro: '#22d3ee', IOC: '#06b6d4', Malware: '#f97316', OSINT: '#a78bfa',
  Network: '#4ade80', Crypto: '#facc15', 'ATT&CK': '#ef4444', Data: '#22d3ee',
  'Machine Learning': '#10b981', Ransomware: '#f43f5e', 'Data Engineering': '#6366f1',
  CTI: '#64748b', Team: '#fbbf24',
}

const DIFF_CTF: Record<string, string> = {
  fácil: '#4ade80', medio: '#facc15', difícil: '#f97316', experto: '#ef4444',
}

function FasesCTFTab({ phases, datasets, token, onRefresh }: {
  phases: CtfPhase[]; datasets: Dataset[]; token: string; onRefresh: () => void
}) {
  const [showPhaseForm, setShowPhaseForm] = useState(false)
  const [phaseForm, setPhaseForm] = useState({ name: '', category: '', reto_count: '', group_label: '', emoji: '📅' })
  const [toggling,  setToggling]  = useState<number | null>(null)
  const [creating,  setCreating]  = useState(false)
  const [expanded,  setExpanded]  = useState<number | null>(null)
  const [challenges, setChallenges] = useState<Record<number, CtfChallenge[]>>({})
  const [showChalForm, setShowChalForm] = useState<number | null>(null)
  const EMPTY_CH = { title: '', description: '', flag: '', flag_format: 'CTI{...}', category: 'CTI', difficulty: 'fácil', points: '100', docker_image: '', docker_port: '8080', roles: [] as string[], dataset_id: '' as string | number, is_team: false }
  const [chalForm, setChalForm] = useState(EMPTY_CH)

  const loadChallenges = useCallback(async (phaseId: number) => {
    const data = await apiFetch(`/admin/ctf-challenges?phase_id=${phaseId}`, token).catch(() => [])
    setChallenges(p => ({ ...p, [phaseId]: data }))
  }, [token])

  useEffect(() => { if (expanded !== null) loadChallenges(expanded) }, [expanded, loadChallenges])

  const toggle = async (phase: CtfPhase) => {
    setToggling(phase.id)
    const next = phase.status === 'active' ? 'inactive' : 'active'
    await apiFetch(`/admin/ctf-phases/${phase.id}`, token, { method: 'PATCH', body: JSON.stringify({ status: next }) }).catch(alert)
    onRefresh()
    setToggling(null)
  }

  const createPhase = async () => {
    if (!phaseForm.name) return
    setCreating(true)
    await apiFetch('/admin/ctf-phases', token, { method: 'POST', body: JSON.stringify({ ...phaseForm, reto_count: Number(phaseForm.reto_count) || 0 }) }).catch(alert)
    setShowPhaseForm(false); setPhaseForm({ name: '', category: '', reto_count: '', group_label: '', emoji: '📅' }); onRefresh()
    setCreating(false)
  }

  const delPhase = async (id: number) => {
    if (!confirm('¿Eliminar esta fase?')) return
    await apiFetch(`/admin/ctf-phases/${id}`, token, { method: 'DELETE' }).catch(alert)
    onRefresh()
  }

  const createChallenge = async (phaseId: number) => {
    if (!chalForm.title || !chalForm.flag) return alert('Título y bandera requeridos')
    await apiFetch('/admin/ctf-challenges', token, {
      method: 'POST',
      body: JSON.stringify({
        ...chalForm,
        phase_id: phaseId,
        points: Number(chalForm.points) || 100,
        dataset_id: chalForm.dataset_id || null,
        is_team: chalForm.is_team,
        roles: chalForm.roles,
      }),
    }).catch(alert)
    setShowChalForm(null)
    setChalForm(EMPTY_CH)
    loadChallenges(phaseId)
    onRefresh()
  }

  const delChallenge = async (id: number, phaseId: number) => {
    if (!confirm('¿Eliminar este reto CTF?')) return
    await apiFetch(`/admin/ctf-challenges/${id}`, token, { method: 'DELETE' }).catch(alert)
    loadChallenges(phaseId)
    onRefresh()
  }

  const updateSolves = async (phase: CtfPhase, delta: number) => {
    const next = Math.max(0, phase.solves + delta)
    await apiFetch(`/admin/ctf-phases/${phase.id}`, token, { method: 'PATCH', body: JSON.stringify({ solves: next }) }).catch(alert)
    onRefresh()
  }

  const ALL_ROLES = Object.keys(TEAM_ROLES)
  const active = phases.filter(p => p.status === 'active').length

  return (
    <div className="space-y-5">
      <div className="grid grid-cols-4 gap-3">
        <StatCard label="Fases totales"  value={phases.length} color="#a78bfa" />
        <StatCard label="Activas"        value={active}        color="#4ade80" />
        <StatCard label="Desactivadas"   value={phases.length - active} color="#475569" />
        <StatCard label="CTF Challenges" value={Object.values(challenges).flat().length} color="#f97316" />
      </div>

      <div className="flex justify-end">
        <button onClick={() => setShowPhaseForm(s => !s)}
                className="px-4 py-2 rounded-lg text-xs font-bold"
                style={{ background: 'rgba(167,139,250,0.12)', border: '1px solid rgba(167,139,250,0.3)', color: '#a78bfa' }}>
          {showPhaseForm ? 'Cancelar' : '+ Nueva fase'}
        </button>
      </div>

      {showPhaseForm && (
        <div className="rounded-xl p-5 space-y-3" style={glass}>
          <p className="text-xs font-bold text-slate-300">Nueva fase / día</p>
          <div className="grid grid-cols-2 gap-3">
            {[
              { label: 'Nombre *', key: 'name', placeholder: 'Día 5 — Post-Explotación' },
              { label: 'Categoría', key: 'category', placeholder: 'Post-Explotación' },
              { label: 'Nº de retos', key: 'reto_count', placeholder: '13' },
              { label: 'Grupos', key: 'group_label', placeholder: 'G1 / G2 / G3' },
            ].map(f => (
              <div key={f.key} className="space-y-1">
                <label className="text-[10px] text-slate-600">{f.label}</label>
                <input value={(phaseForm as Record<string, string>)[f.key]}
                       onChange={e => setPhaseForm(p => ({ ...p, [f.key]: e.target.value }))}
                       placeholder={f.placeholder}
                       className="w-full rounded-lg px-3 py-2 text-xs text-slate-100 outline-none"
                       style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)' }} />
              </div>
            ))}
          </div>
          <div className="flex items-center gap-3">
            <label className="text-[10px] text-slate-600">Emoji:</label>
            <input value={phaseForm.emoji} onChange={e => setPhaseForm(p => ({ ...p, emoji: e.target.value }))}
                   className="w-16 rounded-lg px-2 py-1.5 text-sm text-center outline-none"
                   style={{ background: 'rgba(255,255,255,0.06)', border: '1px solid rgba(255,255,255,0.1)' }} />
            <span className="text-[10px] text-slate-700">📅 🔥 ☠️ ⚡ 🧨 🏴‍☠️ 🎯 💀</span>
          </div>
          <button onClick={createPhase} disabled={creating}
                  className="px-5 py-2 rounded-lg text-xs font-bold disabled:opacity-40"
                  style={{ background: 'rgba(167,139,250,0.15)', border: '1px solid rgba(167,139,250,0.4)', color: '#a78bfa' }}>
            {creating ? 'Creando...' : 'Crear fase →'}
          </button>
        </div>
      )}

      {/* Phase cards with expandable CTF challenges */}
      <div className="space-y-3">
        {phases.map(phase => {
          const isActive   = phase.status === 'active'
          const isToggling = toggling === phase.id
          const isOpen     = expanded === phase.id
          const chals      = challenges[phase.id] ?? []
          const totalPts   = chals.reduce((s, c) => s + c.points, 0)
          const accentColor = isActive ? '#4ade80' : '#475569'

          return (
            <div key={phase.id} className="rounded-xl overflow-hidden transition-all"
                 style={{ ...glass, border: `1px solid ${isActive ? 'rgba(74,222,128,0.25)' : 'rgba(255,255,255,0.07)'}`, background: isActive ? 'rgba(74,222,128,0.03)' : 'rgba(15,23,42,0.6)' }}>

              {/* Phase header */}
              <div className="flex items-center gap-4 px-5 py-4">
                <div className="flex flex-col items-center shrink-0 w-10 cursor-pointer" onClick={() => setExpanded(isOpen ? null : phase.id)}>
                  <span className="text-2xl">{phase.emoji}</span>
                  <span className="text-[9px] text-slate-700 font-mono mt-0.5">#{phase.order_idx}</span>
                </div>

                <div className="flex-1 min-w-0 cursor-pointer" onClick={() => setExpanded(isOpen ? null : phase.id)}>
                  <div className="flex items-center gap-2 mb-0.5 flex-wrap">
                    <p className="text-sm font-bold text-slate-100">{phase.name}</p>
                    {phase.category && (
                      <span className="text-[10px] font-semibold px-2 py-0.5 rounded"
                            style={{ background: `${accentColor}15`, color: accentColor }}>{phase.category}</span>
                    )}
                    {chals.length > 0 && (
                      <span className="text-[9px] px-1.5 py-0.5 rounded"
                            style={{ background: 'rgba(249,115,22,0.1)', color: '#f97316' }}>{chals.length} retos · {totalPts} pts</span>
                    )}
                  </div>
                  <div className="flex items-center gap-4 text-[10px] text-slate-600">
                    {phase.reto_count > 0 && <span>{phase.reto_count} retos esperados</span>}
                    <div className="flex items-center gap-1">
                      <span>{phase.solves} solves</span>
                      <button onClick={e => { e.stopPropagation(); updateSolves(phase, 1) }} className="px-1 hover:text-slate-400">+</button>
                      <button onClick={e => { e.stopPropagation(); updateSolves(phase, -1) }} className="px-1 hover:text-slate-400">−</button>
                    </div>
                    <span className="text-[8px] animate-pulse" style={{ color: CYAN }}>
                      {isOpen ? '▲ ocultar retos' : '▼ ver retos'}
                    </span>
                  </div>
                </div>

                <div className="shrink-0 text-right mr-2">
                  <p className="text-[10px] font-bold" style={{ color: isActive ? '#4ade80' : '#475569' }}>
                    {isActive ? 'Activo' : 'Inactivo'}
                  </p>
                  <p className="text-[9px] text-slate-700">{isActive ? 'Visible' : 'Oculto'}</p>
                </div>

                <button onClick={() => toggle(phase)} disabled={isToggling}
                        className="shrink-0 relative w-12 h-6 rounded-full transition-all duration-300 disabled:opacity-50"
                        style={{ background: isActive ? 'rgba(74,222,128,0.3)' : 'rgba(255,255,255,0.1)', border: `1px solid ${isActive ? 'rgba(74,222,128,0.6)' : 'rgba(255,255,255,0.15)'}`, boxShadow: isActive ? '0 0 10px rgba(74,222,128,0.3)' : 'none' }}>
                  <span className="absolute top-0.5 w-5 h-5 rounded-full transition-all duration-300 flex items-center justify-center"
                        style={{ left: isActive ? 'calc(100% - 22px)' : '2px', background: isActive ? '#4ade80' : '#475569', boxShadow: isActive ? '0 0 6px rgba(74,222,128,0.8)' : 'none' }}>
                    {isToggling
                      ? <span className="w-2.5 h-2.5 border border-white border-t-transparent rounded-full animate-spin block" />
                      : <span className="text-[8px] font-bold text-white">{isActive ? '✓' : '○'}</span>
                    }
                  </span>
                </button>

                <button onClick={() => delPhase(phase.id)}
                        className="shrink-0 text-[10px] px-2 py-1 rounded"
                        style={{ border: `1px solid ${RED}30`, color: RED }}>✕</button>
              </div>

              {/* Expandable CTF challenges */}
              {isOpen && (
                <div className="border-t px-5 py-4 space-y-3" style={{ borderColor: 'rgba(255,255,255,0.06)' }}>
                  <div className="flex items-center justify-between">
                    <p className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">
                      Retos CTF — {phase.name}
                      <span className="ml-2 text-[8px] text-slate-700 normal-case font-normal">{chals.length} cargados</span>
                    </p>
                    <button onClick={() => setShowChalForm(showChalForm === phase.id ? null : phase.id)}
                            className="text-[9px] px-2.5 py-1 rounded font-bold"
                            style={{ background: 'rgba(249,115,22,0.1)', border: '1px solid rgba(249,115,22,0.3)', color: '#f97316' }}>
                      {showChalForm === phase.id ? 'Cancelar' : '+ Nuevo reto'}
                    </button>
                  </div>

                  {/* New challenge form */}
                  {showChalForm === phase.id && (
                    <div className="rounded-xl p-4 space-y-3" style={{ background: 'rgba(249,115,22,0.04)', border: '1px solid rgba(249,115,22,0.15)' }}>
                      <p className="text-[10px] font-bold text-orange-400">Nuevo reto CTF</p>
                      <div className="grid grid-cols-2 gap-2">
                        {[
                          { label: 'Título *', key: 'title', placeholder: 'Reputación de IP — APT28' },
                          { label: 'Bandera * (CTI{...})', key: 'flag', placeholder: 'CTI{respuesta_exacta}' },
                          { label: 'Formato pista', key: 'flag_format', placeholder: 'CTI{actor_país}' },
                          { label: 'Docker Image', key: 'docker_image', placeholder: 'ctinexus/ioc-hunter:latest' },
                        ].map(f => (
                          <div key={f.key} className="space-y-0.5">
                            <label className="text-[9px] text-slate-600">{f.label}</label>
                            <input value={(chalForm as unknown as Record<string, string>)[f.key]}
                                   onChange={e => setChalForm(p => ({ ...p, [f.key]: e.target.value }))}
                                   placeholder={f.placeholder}
                                   className="w-full rounded px-2 py-1.5 text-[10px] text-slate-100 outline-none"
                                   style={{ background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.08)' }} />
                          </div>
                        ))}
                      </div>
                      <div className="space-y-0.5">
                        <label className="text-[9px] text-slate-600">Descripción del reto</label>
                        <textarea value={chalForm.description}
                                  onChange={e => setChalForm(p => ({ ...p, description: e.target.value }))}
                                  rows={3} placeholder="Analiza el dataset X y encuentra..."
                                  className="w-full rounded px-2 py-1.5 text-[10px] text-slate-100 outline-none resize-none"
                                  style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)' }} />
                      </div>
                      <div className="grid grid-cols-4 gap-2">
                        <div className="space-y-0.5">
                          <label className="text-[9px] text-slate-600">Categoría</label>
                          <select value={chalForm.category} onChange={e => setChalForm(p => ({ ...p, category: e.target.value }))}
                                  className="w-full rounded px-2 py-1.5 text-[10px] text-slate-100 outline-none"
                                  style={{ background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.08)' }}>
                            {['CTI','IOC','Malware','OSINT','Network','Crypto','ATT&CK','Data','Machine Learning','Ransomware','Data Engineering','Team'].map(c =>
                              <option key={c} value={c}>{c}</option>
                            )}
                          </select>
                        </div>
                        <div className="space-y-0.5">
                          <label className="text-[9px] text-slate-600">Dificultad</label>
                          <select value={chalForm.difficulty} onChange={e => setChalForm(p => ({ ...p, difficulty: e.target.value }))}
                                  className="w-full rounded px-2 py-1.5 text-[10px] text-slate-100 outline-none"
                                  style={{ background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.08)' }}>
                            {['fácil','medio','difícil','experto'].map(d => <option key={d} value={d}>{d}</option>)}
                          </select>
                        </div>
                        <div className="space-y-0.5">
                          <label className="text-[9px] text-slate-600">Puntos</label>
                          <input type="number" value={chalForm.points} onChange={e => setChalForm(p => ({ ...p, points: e.target.value }))}
                                 className="w-full rounded px-2 py-1.5 text-[10px] text-slate-100 outline-none"
                                 style={{ background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.08)' }} />
                        </div>
                        <div className="space-y-0.5">
                          <label className="text-[9px] text-slate-600">Dataset</label>
                          <select value={chalForm.dataset_id} onChange={e => setChalForm(p => ({ ...p, dataset_id: e.target.value }))}
                                  className="w-full rounded px-2 py-1.5 text-[10px] text-slate-100 outline-none"
                                  style={{ background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.08)' }}>
                            <option value="">Sin dataset</option>
                            {datasets.map(d => <option key={d.id} value={d.id}>{d.name.slice(0, 30)}</option>)}
                          </select>
                        </div>
                      </div>

                      {/* Roles required */}
                      <div className="space-y-1">
                        <label className="text-[9px] text-slate-600">Roles requeridos</label>
                        <div className="flex gap-2 flex-wrap">
                          {ALL_ROLES.map(r => {
                            const meta = TEAM_ROLES[r]
                            const sel  = chalForm.roles.includes(meta.label)
                            return (
                              <button key={r} onClick={() => setChalForm(p => ({
                                ...p,
                                roles: sel ? p.roles.filter(x => x !== meta.label) : [...p.roles, meta.label]
                              }))}
                                      className="text-[9px] px-2 py-1 rounded font-bold transition-all"
                                      style={{ background: sel ? `${meta.color}20` : 'rgba(255,255,255,0.04)', color: sel ? meta.color : '#475569', border: `1px solid ${sel ? meta.color+'44' : 'rgba(255,255,255,0.08)'}` }}>
                                {meta.short} {meta.label}
                              </button>
                            )
                          })}
                          <label className="flex items-center gap-1.5 cursor-pointer">
                            <input type="checkbox" checked={chalForm.is_team} onChange={e => setChalForm(p => ({ ...p, is_team: e.target.checked }))} className="accent-yellow-400" />
                            <span className="text-[9px] text-yellow-500 font-bold">Team challenge</span>
                          </label>
                        </div>
                      </div>

                      <button onClick={() => createChallenge(phase.id)}
                              className="px-4 py-1.5 rounded text-[10px] font-bold"
                              style={{ background: 'rgba(249,115,22,0.15)', border: '1px solid rgba(249,115,22,0.4)', color: '#f97316' }}>
                        Crear reto →
                      </button>
                    </div>
                  )}

                  {/* Challenge list */}
                  <div className="space-y-1.5">
                    {chals.map(ch => {
                      const catColor  = CAT_CTF_COLOR[ch.category] ?? '#64748b'
                      const diffColor = DIFF_CTF[ch.difficulty] ?? '#64748b'
                      let roles: string[] = []
                      try { roles = JSON.parse(ch.roles_json) } catch { /* */ }

                      return (
                        <div key={ch.id} className="rounded-lg px-4 py-3 flex items-start gap-3"
                             style={{ background: ch.is_team ? 'rgba(251,191,36,0.05)' : 'rgba(255,255,255,0.02)', border: `1px solid ${ch.is_team ? 'rgba(251,191,36,0.2)' : 'rgba(255,255,255,0.06)'}` }}>
                          <div className="w-8 h-8 rounded-lg flex items-center justify-center text-xs font-black shrink-0"
                               style={{ background: `${catColor}15`, color: catColor }}>
                            {ch.order_idx}
                          </div>
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2 flex-wrap mb-1">
                              <p className="text-xs font-semibold text-slate-100">{ch.title}</p>
                              {ch.is_team === 1 && <span className="text-[8px] px-1.5 py-0.5 rounded font-bold" style={{ background: 'rgba(251,191,36,0.15)', color: '#fbbf24', border: '1px solid rgba(251,191,36,0.3)' }}>TEAM</span>}
                              <span className="text-[9px] px-1.5 py-0.5 rounded" style={{ background: `${catColor}12`, color: catColor }}>{ch.category}</span>
                              <span className="text-[9px] px-1.5 py-0.5 rounded" style={{ background: `${diffColor}12`, color: diffColor }}>{ch.difficulty}</span>
                              <span className="text-[9px] font-bold text-slate-400">{ch.points} pts</span>
                              <span className="text-[9px] text-green-500">{ch.solve_count} solves</span>
                            </div>
                            <p className="text-[9px] text-slate-600 truncate mb-1">{ch.description.slice(0, 80)}{ch.description.length > 80 ? '…' : ''}</p>
                            <div className="flex items-center gap-2 flex-wrap">
                              {ch.docker_image && (
                                <span className="text-[8px] font-mono px-1.5 py-0.5 rounded"
                                      style={{ background: 'rgba(34,211,238,0.06)', color: '#67e8f9', border: '1px solid rgba(34,211,238,0.1)' }}>
                                  {ch.docker_image}:{ch.docker_port}
                                </span>
                              )}
                              {roles.map(r => {
                                const rm = Object.values(TEAM_ROLES).find(v => v.label === r)
                                return rm ? (
                                  <span key={r} className="text-[8px] px-1.5 py-0.5 rounded"
                                        style={{ background: `${rm.color}10`, color: rm.color }}>
                                    {rm.short}
                                  </span>
                                ) : null
                              })}
                              {ch.dataset_name && (
                                <span className="text-[8px] text-orange-700">{ch.dataset_name.slice(0, 25)}…</span>
                              )}
                            </div>
                          </div>
                          <div className="shrink-0 space-y-1 text-right">
                            <p className="text-[8px] font-mono text-slate-700 max-w-[120px] truncate" title={ch.flag}>
                              {ch.flag.slice(0, 20)}{ch.flag.length > 20 ? '…' : ''}
                            </p>
                            <button onClick={() => delChallenge(ch.id, phase.id)}
                                    className="text-[8px] px-1.5 py-0.5 rounded"
                                    style={{ border: `1px solid ${RED}30`, color: RED }}>✕</button>
                          </div>
                        </div>
                      )
                    })}
                    {chals.length === 0 && (
                      <p className="text-[10px] text-slate-700">Sin retos CTF para esta fase. Usa "+ Nuevo reto" para agregar.</p>
                    )}
                  </div>
                </div>
              )}
            </div>
          )
        })}
        {phases.length === 0 && <p className="text-xs text-slate-700 px-2">Sin fases. Crea una arriba.</p>}
      </div>
    </div>
  )
}

// ── Datasets Tab ──────────────────────────────────────────────────────────────

function DatasetsTab({ datasets, token, onRefresh }: {
  datasets: Dataset[]; token: string; onRefresh: () => void
}) {
  const [showForm, setShowForm] = useState(false)
  const [form, setForm]   = useState({ name: '', description: '', source: 'manual', data: '' })
  const [loading, setLoading] = useState(false)
  const [preview, setPreview] = useState<Dataset | null>(null)

  const create = async () => {
    if (!form.name || !form.data) return alert('Nombre y datos requeridos')
    setLoading(true)
    try {
      await apiFetch('/admin/datasets', token, { method: 'POST', body: JSON.stringify(form) })
      setShowForm(false)
      setForm({ name: '', description: '', source: 'manual', data: '' })
      onRefresh()
    } catch (e) { alert(e) }
    finally { setLoading(false) }
  }

  const del = async (id: number) => {
    if (!confirm('¿Eliminar dataset?')) return
    await apiFetch(`/admin/datasets/${id}`, token, { method: 'DELETE' }).catch(alert)
    onRefresh()
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-xs text-slate-500">{datasets.length} datasets disponibles</p>
        <button onClick={() => setShowForm(s => !s)}
                className="px-4 py-2 rounded-lg text-xs font-bold transition-all"
                style={{ background: 'rgba(249,115,22,0.12)', border: '1px solid rgba(249,115,22,0.3)', color: '#f97316' }}>
          {showForm ? 'Cancelar' : '+ Nuevo dataset'}
        </button>
      </div>

      {showForm && (
        <div className="rounded-xl p-5 space-y-3" style={glass}>
          <p className="text-xs font-bold text-slate-300">Crear dataset</p>
          {[
            { label: 'Nombre', key: 'name', placeholder: 'Logs de Firewall — Mayo 2026' },
            { label: 'Descripción', key: 'description', placeholder: 'Dataset de eventos de red para análisis CTI' },
            { label: 'Fuente', key: 'source', placeholder: 'MISP / AbuseIPDB / manual / simulado' },
          ].map(f => (
            <div key={f.key} className="space-y-1">
              <label className="text-[10px] text-slate-500">{f.label}</label>
              <input value={(form as Record<string, string>)[f.key]}
                     onChange={e => setForm(p => ({ ...p, [f.key]: e.target.value }))}
                     placeholder={f.placeholder}
                     className="w-full rounded-lg px-3 py-2 text-xs text-slate-100 outline-none"
                     style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)' }} />
            </div>
          ))}
          <div className="space-y-1">
            <label className="text-[10px] text-slate-500">Datos (JSON array o CSV con cabecera)</label>
            <textarea value={form.data} onChange={e => setForm(p => ({ ...p, data: e.target.value }))}
                      rows={8} placeholder={'[\n  {"ip":"185.220.101.1","port":443,"action":"BLOCK"},\n  ...\n]'}
                      className="w-full rounded-lg px-3 py-2 text-xs font-mono text-green-300 outline-none resize-none"
                      style={{ background: '#050a14', border: '1px solid rgba(255,255,255,0.08)' }} />
          </div>
          <button onClick={create} disabled={loading}
                  className="px-5 py-2 rounded-lg text-xs font-bold disabled:opacity-40"
                  style={{ background: 'rgba(249,115,22,0.15)', border: '1px solid rgba(249,115,22,0.4)', color: '#f97316' }}>
            {loading ? 'Guardando...' : 'Guardar dataset →'}
          </button>
        </div>
      )}

      <div className="grid grid-cols-1 gap-3">
        {datasets.map(d => {
          const schema = (() => { try { return JSON.parse(d.schema_json) } catch { return {} } })()
          return (
            <div key={d.id} className="rounded-xl p-4" style={glass}>
              <div className="flex items-start justify-between gap-3">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <p className="text-sm font-semibold text-slate-100">{d.name}</p>
                    <Badge label={d.source} color="#f97316" />
                  </div>
                  {d.description && <p className="text-xs text-slate-500 mb-2">{d.description}</p>}
                  <div className="flex flex-wrap gap-1.5">
                    {Object.entries(schema).map(([col, type]) => (
                      <span key={col} className="text-[9px] font-mono px-1.5 py-0.5 rounded"
                            style={{ background: 'rgba(34,211,238,0.08)', color: '#67e8f9' }}>
                        {col}: <span style={{ color: '#94a3b8' }}>{String(type)}</span>
                      </span>
                    ))}
                  </div>
                </div>
                <div className="flex gap-2 shrink-0">
                  <button onClick={() => setPreview(preview?.id === d.id ? null : d)}
                          className="text-[10px] px-2 py-1 rounded text-slate-500 hover:text-slate-300 transition-colors"
                          style={{ border: '1px solid rgba(255,255,255,0.07)' }}>
                    Vista previa
                  </button>
                  <button onClick={() => del(d.id)}
                          className="text-[10px] px-2 py-1 rounded transition-colors"
                          style={{ border: `1px solid ${RED}30`, color: RED }}>
                    ✕
                  </button>
                </div>
              </div>
              {preview?.id === d.id && (
                <DatasetPreview token={token} datasetId={d.id} />
              )}
            </div>
          )
        })}
        {datasets.length === 0 && (
          <p className="text-xs text-slate-700 px-2">No hay datasets. Crea uno con el botón de arriba.</p>
        )}
      </div>
    </div>
  )
}

function DatasetPreview({ token, datasetId }: { token: string; datasetId: number }) {
  const [data, setData] = useState<Record<string, unknown>[] | null>(null)
  useEffect(() => {
    apiFetch(`/admin/datasets/${datasetId}`, token)
      .then(d => setData(JSON.parse(d.data_json).slice(0, 5)))
      .catch(() => setData([]))
  }, [datasetId, token])

  if (!data) return <p className="text-xs text-slate-700 mt-3 animate-pulse">Cargando...</p>
  if (data.length === 0) return <p className="text-xs text-slate-700 mt-3">Sin datos.</p>

  const cols = Object.keys(data[0])
  return (
    <div className="mt-3 overflow-x-auto rounded-lg" style={{ border: '1px solid rgba(255,255,255,0.06)' }}>
      <table className="w-full text-[10px]">
        <thead>
          <tr style={{ background: 'rgba(255,255,255,0.04)' }}>
            {cols.map(c => <th key={c} className="px-3 py-2 text-left text-slate-500 font-mono">{c}</th>)}
          </tr>
        </thead>
        <tbody className="divide-y divide-white/[0.03]">
          {data.map((row, i) => (
            <tr key={i} className="hover:bg-white/[0.02]">
              {cols.map(c => (
                <td key={c} className="px-3 py-1.5 text-slate-400 font-mono truncate max-w-32">
                  {String(row[c] ?? '')}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

// ── Retos Tab ─────────────────────────────────────────────────────────────────

const DIFF_COLOR: Record<string, string> = {
  básico:      '#4ade80',
  intermedio:  '#facc15',
  avanzado:    '#f97316',
  experto:     '#ef4444',
}

function RetosTab({ challenges, datasets, users, allBadges, token, onRefresh }: {
  challenges: Challenge[]; datasets: Dataset[]; users: User[]; allBadges: Badge[]; token: string; onRefresh: () => void
}) {
  const EMPTY_FORM = { title: '', description: '', objective: '', criteria: '', dataset_id: '' as string | number, deadline: '', badge_id: '' as string | number, min_score_badge: '70', difficulty: 'básico' }
  const [showForm,    setShowForm]    = useState(false)
  const [form,        setForm]        = useState(EMPTY_FORM)
  const [loading,     setLoading]     = useState(false)
  const [seeding,     setSeeding]     = useState(false)
  const [seedMsg,     setSeedMsg]     = useState('')
  const [expanded,    setExpanded]    = useState<number | null>(null)
  const [assignments, setAssignments] = useState<Record<number, Assignment[]>>({})
  const [selUsers,    setSelUsers]    = useState<Record<number, string[]>>({})
  // Asignación masiva selectiva
  const [bulkOpen,    setBulkOpen]    = useState(false)
  const [bulkRetos,   setBulkRetos]   = useState<number[]>([])
  const [bulkStudents,setBulkStudents]= useState<string[]>([])
  const [bulkLoading, setBulkLoading] = useState(false)

  const loadAssignments = useCallback(async (cid: number) => {
    const data = await apiFetch(`/admin/challenges/${cid}/assignments`, token).catch(() => [])
    setAssignments(p => ({ ...p, [cid]: data }))
  }, [token])

  useEffect(() => {
    if (expanded !== null) loadAssignments(expanded)
  }, [expanded, loadAssignments])

  useEffect(() => {
    if (expanded === null) return
    const id = setInterval(() => loadAssignments(expanded), 5000)
    return () => clearInterval(id)
  }, [expanded, loadAssignments])

  const create = async () => {
    if (!form.title) return alert('Título requerido')
    setLoading(true)
    try {
      await apiFetch('/admin/challenges', token, {
        method: 'POST',
        body: JSON.stringify({
          ...form,
          dataset_id: form.dataset_id || null,
          badge_id: form.badge_id || null,
          min_score_badge: Number(form.min_score_badge) || 70,
        }),
      })
      setShowForm(false)
      setForm(EMPTY_FORM)
      onRefresh()
    } catch (e) { alert(e) }
    finally { setLoading(false) }
  }

  const seedDemo = async () => {
    setSeeding(true)
    setSeedMsg('')
    try {
      const res = await apiFetch('/admin/seed-demo', token, { method: 'POST' })
      setSeedMsg(`✓ ${res.datasets_added} datasets + ${res.challenges_added} retos cargados (total: ${res.total_challenges} retos, ${res.total_datasets} datasets)`)
      onRefresh()
    } catch (e) { setSeedMsg(`Error: ${e}`) }
    finally { setSeeding(false) }
  }

  const assignAllToAll = async () => {
    const active = challenges.filter(c => c.status === 'active')
    if (!active.length || !students.length) return
    for (const c of active) {
      await apiFetch(`/admin/challenges/${c.id}/assign`, token, {
        method: 'POST', body: JSON.stringify({ emails: students.map(s => s.email) }),
      }).catch(() => {})
    }
    setSeedMsg(`✓ ${active.length} retos asignados a ${students.length} estudiante(s)`)
    onRefresh()
  }

  const assignBulkSelected = async () => {
    if (!bulkRetos.length || !bulkStudents.length) return
    setBulkLoading(true)
    for (const cid of bulkRetos) {
      await apiFetch(`/admin/challenges/${cid}/assign`, token, {
        method: 'POST', body: JSON.stringify({ emails: bulkStudents }),
      }).catch(() => {})
    }
    setSeedMsg(`✓ ${bulkRetos.length} retos asignados a ${bulkStudents.length} estudiante(s)`)
    setBulkOpen(false)
    setBulkRetos([]); setBulkStudents([])
    onRefresh()
    setBulkLoading(false)
  }

  const toggleBulkReto    = (id: number)  => setBulkRetos(p => p.includes(id) ? p.filter(x => x !== id) : [...p, id])
  const toggleBulkStudent = (e: string)   => setBulkStudents(p => p.includes(e) ? p.filter(x => x !== e) : [...p, e])

  const toggleStatus = async (c: Challenge) => {
    const next = c.status === 'active' ? 'closed' : 'active'
    await apiFetch(`/admin/challenges/${c.id}`, token, { method: 'PATCH', body: JSON.stringify({ status: next }) })
    onRefresh()
  }

  const del = async (id: number) => {
    if (!confirm('¿Eliminar reto y sus entregas?')) return
    await apiFetch(`/admin/challenges/${id}`, token, { method: 'DELETE' }).catch(alert)
    onRefresh()
  }

  const assign = async (cid: number, all = false) => {
    const emails = all ? students.filter(u => !(assignments[cid] ?? []).find(a => a.email === u.email)).map(u => u.email) : (selUsers[cid] ?? [])
    if (!emails.length) return
    await apiFetch(`/admin/challenges/${cid}/assign`, token, { method: 'POST', body: JSON.stringify({ emails }) })
    setSelUsers(p => ({ ...p, [cid]: [] }))
    loadAssignments(cid)
    onRefresh()
  }

  const unassign = async (cid: number, email: string) => {
    await apiFetch(`/admin/challenges/${cid}/assign/${encodeURIComponent(email)}`, token, { method: 'DELETE' })
    loadAssignments(cid)
    onRefresh()
  }

  const students = users.filter(u => u.role === 'student')

  const activeCount  = challenges.filter(c => c.status === 'active').length

  return (
    <div className="space-y-4">

      {/* ── Asignación masiva selectiva ─────────────────────────────────────── */}
      <div className="rounded-xl overflow-hidden"
           style={{ background: 'rgba(34,211,238,0.03)', border: '1px solid rgba(34,211,238,0.12)' }}>

        {/* Header del panel */}
        <div className="flex items-center justify-between gap-3 px-4 py-3">
          <div>
            <p className="text-xs font-bold text-slate-200">Asignación de retos</p>
            <p className="text-[10px] text-slate-600">{activeCount} retos activos · {students.length} estudiante(s)</p>
          </div>
          <div className="flex gap-2">
            <button onClick={assignAllToAll} disabled={!activeCount || !students.length}
                    className="text-[10px] px-3 py-1.5 rounded-lg font-bold disabled:opacity-30 transition-all"
                    style={{ background: `${CYAN}12`, border: `1px solid ${CYAN}33`, color: CYAN }}>
              Todos → Todos
            </button>
            <button onClick={() => { setBulkOpen(o => !o); setBulkRetos(challenges.filter(c => c.status === 'active').map(c => c.id)); setBulkStudents([]) }}
                    className="text-[10px] px-3 py-1.5 rounded-lg font-bold transition-all"
                    style={{ background: 'rgba(167,139,250,0.12)', border: '1px solid rgba(167,139,250,0.3)', color: '#a78bfa' }}>
              {bulkOpen ? 'Cerrar selector' : '+ Asignación selectiva'}
            </button>
          </div>
        </div>

        {/* Panel selectivo expandible */}
        {bulkOpen && (
          <div className="border-t px-4 pb-4 space-y-4" style={{ borderColor: 'rgba(255,255,255,0.06)' }}>

            <div className="grid grid-cols-2 gap-4 pt-3">
              {/* Selector de retos */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <p className="text-[9px] font-bold text-slate-500 uppercase tracking-wider">
                    Retos ({bulkRetos.length}/{challenges.length} sel.)
                  </p>
                  <div className="flex gap-1.5">
                    <button onClick={() => setBulkRetos(challenges.map(c => c.id))}
                            className="text-[8px] px-1.5 py-0.5 rounded" style={{ color: CYAN, border: `1px solid ${CYAN}33` }}>
                      Todos
                    </button>
                    <button onClick={() => setBulkRetos([])}
                            className="text-[8px] px-1.5 py-0.5 rounded" style={{ color: '#475569', border: '1px solid rgba(255,255,255,0.08)' }}>
                      Ninguno
                    </button>
                  </div>
                </div>
                <div className="space-y-1 max-h-52 overflow-y-auto pr-1">
                  {challenges.map(c => {
                    const sel = bulkRetos.includes(c.id)
                    const diffColor = DIFF_COLOR[c.difficulty] ?? '#64748b'
                    return (
                      <label key={c.id} className="flex items-start gap-2 cursor-pointer rounded-lg px-2 py-1.5 transition-all"
                             style={{ background: sel ? 'rgba(34,211,238,0.06)' : 'rgba(255,255,255,0.02)', border: `1px solid ${sel ? 'rgba(34,211,238,0.2)' : 'rgba(255,255,255,0.05)'}` }}>
                        <input type="checkbox" checked={sel} onChange={() => toggleBulkReto(c.id)} className="accent-cyan-400 mt-0.5 shrink-0" />
                        <div className="min-w-0">
                          <p className="text-[10px] text-slate-200 leading-tight truncate">{c.title}</p>
                          <div className="flex items-center gap-1.5 mt-0.5">
                            <span className="text-[8px] px-1 py-0.5 rounded" style={{ background: `${diffColor}12`, color: diffColor }}>{c.difficulty}</span>
                            {c.badge_name && <span className="text-[8px] text-yellow-700">★ {c.badge_name}</span>}
                          </div>
                        </div>
                      </label>
                    )
                  })}
                </div>
              </div>

              {/* Selector de estudiantes */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <p className="text-[9px] font-bold text-slate-500 uppercase tracking-wider">
                    Estudiantes ({bulkStudents.length}/{students.length} sel.)
                  </p>
                  <div className="flex gap-1.5">
                    <button onClick={() => setBulkStudents(students.map(s => s.email))}
                            className="text-[8px] px-1.5 py-0.5 rounded" style={{ color: '#a78bfa', border: '1px solid rgba(167,139,250,0.3)' }}>
                      Todos
                    </button>
                    <button onClick={() => setBulkStudents([])}
                            className="text-[8px] px-1.5 py-0.5 rounded" style={{ color: '#475569', border: '1px solid rgba(255,255,255,0.08)' }}>
                      Ninguno
                    </button>
                  </div>
                </div>
                <div className="space-y-1 max-h-52 overflow-y-auto pr-1">
                  {students.map(s => {
                    const sel = bulkStudents.includes(s.email)
                    return (
                      <label key={s.email} className="flex items-center gap-2 cursor-pointer rounded-lg px-2 py-1.5 transition-all"
                             style={{ background: sel ? 'rgba(167,139,250,0.07)' : 'rgba(255,255,255,0.02)', border: `1px solid ${sel ? 'rgba(167,139,250,0.25)' : 'rgba(255,255,255,0.05)'}` }}>
                        <input type="checkbox" checked={sel} onChange={() => toggleBulkStudent(s.email)} className="accent-violet-400 shrink-0" />
                        <div className="min-w-0">
                          <p className="text-[10px] text-slate-200 truncate">{s.name}</p>
                          <p className="text-[8px] text-slate-700 truncate">{s.email}</p>
                        </div>
                      </label>
                    )
                  })}
                </div>
              </div>
            </div>

            {/* Botón asignar */}
            <button
              onClick={assignBulkSelected}
              disabled={bulkLoading || !bulkRetos.length || !bulkStudents.length}
              className="w-full py-2.5 rounded-lg text-xs font-bold disabled:opacity-30 transition-all"
              style={{ background: 'rgba(34,211,238,0.12)', border: '1px solid rgba(34,211,238,0.35)', color: CYAN }}>
              {bulkLoading
                ? 'Asignando...'
                : `Asignar ${bulkRetos.length} reto(s) → ${bulkStudents.length} estudiante(s) seleccionados`}
            </button>
          </div>
        )}
      </div>

      {/* Header */}
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <p className="text-xs text-slate-500">{challenges.length} retos creados</p>
        <div className="flex items-center gap-2">
          <button onClick={seedDemo} disabled={seeding}
                  className="px-3 py-1.5 rounded-lg text-xs font-bold disabled:opacity-40 transition-all"
                  style={{ background: 'rgba(249,115,22,0.1)', border: '1px solid rgba(249,115,22,0.3)', color: '#f97316' }}>
            {seeding ? 'Cargando...' : '⚡ Datos de prueba CTI'}
          </button>
          <button onClick={() => setShowForm(s => !s)}
                  className="px-4 py-2 rounded-lg text-xs font-bold"
                  style={{ background: 'rgba(167,139,250,0.12)', border: '1px solid rgba(167,139,250,0.3)', color: '#a78bfa' }}>
            {showForm ? 'Cancelar' : '+ Nuevo reto'}
          </button>
        </div>
      </div>

      {seedMsg && (
        <p className="text-[10px] px-3 py-2 rounded-lg"
           style={{ background: seedMsg.startsWith('✓') ? 'rgba(74,222,128,0.08)' : 'rgba(239,68,68,0.08)', color: seedMsg.startsWith('✓') ? '#4ade80' : '#ef4444', border: `1px solid ${seedMsg.startsWith('✓') ? 'rgba(74,222,128,0.2)' : 'rgba(239,68,68,0.2)'}` }}>
          {seedMsg}
        </p>
      )}

      {/* Create form */}
      {showForm && (
        <div className="rounded-xl p-5 space-y-3" style={glass}>
          <p className="text-xs font-bold text-slate-300">Crear reto</p>
          {[
            { label: 'Título *',                  key: 'title',       placeholder: 'Análisis de ataque Supply Chain XZ Utils' },
            { label: 'Descripción',               key: 'description', placeholder: 'Contexto del reto...' },
            { label: 'Objetivo del estudiante',   key: 'objective',   placeholder: 'Identificar el vector de entrada y crear 2 visualizaciones' },
            { label: 'Criterios de evaluación',   key: 'criteria',    placeholder: 'Creatividad (40%) + Precisión del análisis (60%)' },
          ].map(f => (
            <div key={f.key} className="space-y-1">
              <label className="text-[10px] text-slate-500">{f.label}</label>
              <input value={(form as Record<string, string>)[f.key]}
                     onChange={e => setForm(p => ({ ...p, [f.key]: e.target.value }))}
                     placeholder={f.placeholder}
                     className="w-full rounded-lg px-3 py-2 text-xs text-slate-100 outline-none"
                     style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)' }} />
            </div>
          ))}

          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1">
              <label className="text-[10px] text-slate-500">Dataset</label>
              <select value={form.dataset_id} onChange={e => setForm(p => ({ ...p, dataset_id: e.target.value }))}
                      className="w-full rounded-lg px-3 py-2 text-xs text-slate-100 outline-none"
                      style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)' }}>
                <option value="">Sin dataset asignado</option>
                {datasets.map(d => <option key={d.id} value={d.id}>{d.name}</option>)}
              </select>
            </div>
            <div className="space-y-1">
              <label className="text-[10px] text-slate-500">Dificultad</label>
              <select value={form.difficulty} onChange={e => setForm(p => ({ ...p, difficulty: e.target.value }))}
                      className="w-full rounded-lg px-3 py-2 text-xs text-slate-100 outline-none"
                      style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)' }}>
                {['básico','intermedio','avanzado','experto'].map(d => <option key={d} value={d}>{d}</option>)}
              </select>
            </div>
          </div>

          {/* Badge reward */}
          <div className="rounded-lg p-3 space-y-2" style={{ background: 'rgba(250,204,21,0.04)', border: '1px solid rgba(250,204,21,0.12)' }}>
            <p className="text-[10px] font-bold text-yellow-700 uppercase tracking-wider">Insignia al completar</p>
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1">
                <label className="text-[10px] text-slate-500">Insignia a otorgar</label>
                <select value={form.badge_id} onChange={e => setForm(p => ({ ...p, badge_id: e.target.value }))}
                        className="w-full rounded-lg px-3 py-2 text-xs text-slate-100 outline-none"
                        style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)' }}>
                  <option value="">Sin insignia</option>
                  {Object.entries(
                    allBadges.reduce((acc, b) => { (acc[b.org] = acc[b.org] || []).push(b); return acc }, {} as Record<string, Badge[]>)
                  ).map(([org, bs]) => (
                    <optgroup key={org} label={org}>
                      {bs.map(b => <option key={b.id} value={b.id}>{b.name} ({b.tier})</option>)}
                    </optgroup>
                  ))}
                </select>
              </div>
              <div className="space-y-1">
                <label className="text-[10px] text-slate-500">Score mínimo para ganarla (0–100)</label>
                <input type="number" min="1" max="100"
                       value={form.min_score_badge}
                       onChange={e => setForm(p => ({ ...p, min_score_badge: e.target.value }))}
                       className="w-full rounded-lg px-3 py-2 text-xs text-slate-100 outline-none"
                       style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)' }} />
              </div>
            </div>
          </div>

          <div className="space-y-1">
            <label className="text-[10px] text-slate-500">Fecha límite</label>
            <input type="datetime-local" value={form.deadline}
                   onChange={e => setForm(p => ({ ...p, deadline: e.target.value }))}
                   className="w-full rounded-lg px-3 py-2 text-xs text-slate-100 outline-none"
                   style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)' }} />
          </div>

          <button onClick={create} disabled={loading}
                  className="px-5 py-2 rounded-lg text-xs font-bold disabled:opacity-40"
                  style={{ background: 'rgba(167,139,250,0.15)', border: '1px solid rgba(167,139,250,0.4)', color: '#a78bfa' }}>
            {loading ? 'Creando...' : 'Crear reto →'}
          </button>
        </div>
      )}

      {/* Challenge list */}
      <div className="space-y-3">
        {challenges.map(c => {
          const isOpen      = expanded === c.id
          const asmts       = assignments[c.id] ?? []
          const notAssigned = students.filter(u => !asmts.find(a => a.email === u.email))
          const diffColor   = DIFF_COLOR[c.difficulty] ?? '#64748b'
          const tierColor   = c.badge_tier ? (TIER[c.badge_tier]?.color ?? '#facc15') : null

          return (
            <div key={c.id} className="rounded-xl overflow-hidden" style={glass}>
              {/* Challenge header */}
              <div className="flex items-center gap-4 px-5 py-4 cursor-pointer hover:bg-white/[0.02]"
                   onClick={() => setExpanded(isOpen ? null : c.id)}>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1 flex-wrap">
                    <p className="text-sm font-semibold text-slate-100 truncate">{c.title}</p>
                    <Badge label={c.status} color={c.status === 'active' ? '#4ade80' : '#475569'} />
                    {c.difficulty && <Badge label={c.difficulty} color={diffColor} />}
                    {c.dataset_name && <Badge label={c.dataset_name} color="#f97316" />}
                  </div>
                  <div className="flex items-center gap-4 text-[10px] text-slate-600 flex-wrap">
                    <span>{c.assigned_count} asignados · {c.submission_count} entregas</span>
                    {c.deadline && <span>Límite: {new Date(c.deadline).toLocaleDateString('es-MX')}</span>}
                    {c.badge_name && tierColor && (
                      <span className="flex items-center gap-1" style={{ color: tierColor }}>
                        ★ {c.badge_name}
                        <span className="text-slate-700">({c.badge_org})</span>
                        <span className="text-slate-700">≥{c.min_score_badge} pts</span>
                      </span>
                    )}
                  </div>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <button onClick={e => { e.stopPropagation(); toggleStatus(c) }}
                          className="text-[10px] px-2.5 py-1 rounded transition-colors"
                          style={{ border: `1px solid ${c.status === 'active' ? '#47556966' : '#4ade8066'}`, color: c.status === 'active' ? '#475569' : '#4ade80' }}>
                    {c.status === 'active' ? 'Cerrar' : 'Reabrir'}
                  </button>
                  <button onClick={e => { e.stopPropagation(); del(c.id) }}
                          className="text-[10px] px-2 py-1 rounded"
                          style={{ border: `1px solid ${RED}30`, color: RED }}>✕</button>
                  <svg viewBox="0 0 24 24" className="w-3.5 h-3.5 text-slate-700 transition-transform"
                       style={{ transform: isOpen ? 'rotate(180deg)' : undefined }}
                       fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M6 9l6 6 6-6" />
                  </svg>
                </div>
              </div>

              {isOpen && (
                <div className="border-t px-5 py-4 space-y-4" style={{ borderColor: 'rgba(255,255,255,0.06)' }}>
                  {c.objective && <p className="text-xs text-slate-400"><span className="text-slate-600">Objetivo: </span>{c.objective}</p>}
                  {c.criteria  && <p className="text-xs text-slate-400"><span className="text-slate-600">Criterios: </span>{c.criteria}</p>}

                  {/* Badge reward banner */}
                  {c.badge_name && tierColor && (
                    <div className="rounded-lg px-4 py-2.5 flex items-center gap-3"
                         style={{ background: `${tierColor}08`, border: `1px solid ${tierColor}22` }}>
                      <svg viewBox="0 0 24 24" className="w-4 h-4 shrink-0" fill="none" stroke={tierColor} strokeWidth="2">
                        <path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z" />
                      </svg>
                      <div>
                        <p className="text-[10px] font-bold" style={{ color: tierColor }}>
                          Insignia: {c.badge_name}
                          <span className="ml-2 text-slate-600 font-normal">({c.badge_org} · {c.badge_tier})</span>
                        </p>
                        <p className="text-[9px] text-slate-600">Se otorga automáticamente al calificar con ≥ {c.min_score_badge} puntos</p>
                      </div>
                    </div>
                  )}

                  {/* Assignment board */}
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <p className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">
                        Asignación en tiempo real
                        <span className="ml-2 text-[8px] text-cyan-700 animate-pulse">● live</span>
                      </p>
                      {notAssigned.length > 0 && (
                        <button onClick={() => assign(c.id, true)}
                                className="text-[9px] px-2 py-1 rounded font-bold"
                                style={{ background: `${CYAN}12`, border: `1px solid ${CYAN}33`, color: CYAN }}>
                          Asignar todos ({notAssigned.length})
                        </button>
                      )}
                    </div>
                    <div className="grid grid-cols-2 gap-3">
                      {/* Assigned */}
                      <div className="rounded-lg p-3 space-y-2" style={{ background: 'rgba(74,222,128,0.04)', border: '1px solid rgba(74,222,128,0.1)' }}>
                        <p className="text-[9px] text-green-700 font-bold uppercase">Asignados ({asmts.length})</p>
                        {asmts.map(a => (
                          <div key={a.email} className="flex items-center justify-between gap-2">
                            <div>
                              <p className="text-xs text-slate-300">{a.name}</p>
                              <p className="text-[9px] text-slate-600">
                                {a.submitted ? <span className="text-green-500">✓ Entregó</span> : <span className="text-yellow-700">⏳ Pendiente</span>}
                              </p>
                            </div>
                            <button onClick={() => unassign(c.id, a.email)}
                                    className="text-[9px] px-1.5 py-0.5 rounded shrink-0"
                                    style={{ border: `1px solid ${RED}30`, color: RED }}>✕</button>
                          </div>
                        ))}
                        {asmts.length === 0 && <p className="text-[10px] text-slate-700">Nadie asignado aún.</p>}
                      </div>

                      {/* Available to assign */}
                      <div className="rounded-lg p-3 space-y-2" style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)' }}>
                        <p className="text-[9px] text-slate-600 font-bold uppercase">Agregar estudiantes</p>
                        <div className="space-y-1 max-h-32 overflow-y-auto">
                          {notAssigned.map(u => (
                            <label key={u.email} className="flex items-center gap-2 cursor-pointer">
                              <input type="checkbox"
                                     checked={(selUsers[c.id] ?? []).includes(u.email)}
                                     onChange={e => setSelUsers(p => {
                                       const cur = p[c.id] ?? []
                                       return { ...p, [c.id]: e.target.checked ? [...cur, u.email] : cur.filter(x => x !== u.email) }
                                     })}
                                     className="accent-cyan-400" />
                              <span className="text-xs text-slate-400">{u.name}</span>
                            </label>
                          ))}
                          {notAssigned.length === 0 && <p className="text-[10px] text-slate-700">Todos asignados.</p>}
                        </div>
                        <button onClick={() => assign(c.id)}
                                disabled={!(selUsers[c.id]?.length)}
                                className="w-full py-1.5 rounded text-[10px] font-bold disabled:opacity-30 transition-all"
                                style={{ background: `${CYAN}18`, border: `1px solid ${CYAN}44`, color: CYAN }}>
                          Asignar seleccionados
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )
        })}
        {challenges.length === 0 && <p className="text-xs text-slate-700 px-2">Sin retos creados.</p>}
      </div>
    </div>
  )
}

// ── Submissions Tab ───────────────────────────────────────────────────────────

function SubmissionsTab({ token, challenges }: { token: string; challenges: Challenge[] }) {
  const [subs,         setSubs]         = useState<Submission[]>([])
  const [expanded,     setExpanded]     = useState<number | null>(null)
  const [scoring,      setScoring]      = useState<Record<number, { score: string; feedback: string }>>({})
  const [badgeToasts,  setBadgeToasts]  = useState<Record<number, { name: string; org: string; tier: string } | null>>({})
  const chalMap = Object.fromEntries(challenges.map(c => [c.id, c]))

  const load = useCallback(() => {
    apiFetch('/admin/submissions', token).then(setSubs).catch(() => {})
  }, [token])

  useEffect(() => { load(); const id = setInterval(load, 5000); return () => clearInterval(id) }, [load])

  const saveScore = async (sid: number) => {
    const s = scoring[sid]
    if (!s?.score) return
    const res = await apiFetch(`/admin/submissions/${sid}/score`, token, {
      method: 'PUT',
      body: JSON.stringify({ score: Number(s.score), feedback: s.feedback ?? '' }),
    }).catch(alert)
    if (res?.badge_awarded) {
      setBadgeToasts(p => ({ ...p, [sid]: res.badge_awarded }))
      setTimeout(() => setBadgeToasts(p => ({ ...p, [sid]: null })), 6000)
    }
    load()
  }

  return (
    <div className="space-y-3">
      <p className="text-xs text-slate-500">{subs.length} entregas · <span className="text-yellow-700">{subs.filter(s => s.score == null).length} por calificar</span></p>
      {subs.map(s => {
        const plots: string[] = (() => { try { return JSON.parse(s.plots_json) } catch { return [] } })()
        const isOpen   = expanded === s.id
        const ch       = chalMap[s.challenge_id]
        const badgeMsg = badgeToasts[s.id]
        const pendingScore = Number(scoring[s.id]?.score ?? s.score ?? 0)
        const willEarnBadge = ch?.badge_name && ch.badge_id && s.score == null && pendingScore >= (ch.min_score_badge ?? 70)

        return (
          <div key={s.id} className="rounded-xl overflow-hidden" style={glass}>
            <div className="flex items-center gap-4 px-5 py-4 cursor-pointer hover:bg-white/[0.02]"
                 onClick={() => setExpanded(isOpen ? null : s.id)}>
              <div className="w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold shrink-0"
                   style={{ background: `${CYAN}18`, color: CYAN }}>
                {s.user_name[0]?.toUpperCase()}
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-sm font-semibold text-slate-100">{s.user_name}</p>
                <div className="flex items-center gap-2 flex-wrap">
                  <p className="text-xs text-slate-500 truncate">{s.challenge_title}</p>
                  {ch?.badge_name && ch.badge_tier && (
                    <span className="text-[9px] px-1.5 py-0.5 rounded font-bold"
                          style={{ background: `${TIER[ch.badge_tier]?.color ?? '#facc15'}12`, color: TIER[ch.badge_tier]?.color ?? '#facc15', border: `1px solid ${TIER[ch.badge_tier]?.color ?? '#facc15'}22` }}>
                      ★ {ch.badge_name}
                    </span>
                  )}
                </div>
              </div>
              <div className="text-right shrink-0">
                {s.score != null
                  ? <Badge label={`${s.score}/100`} color="#4ade80" />
                  : <Badge label="Sin calificar" color="#facc15" />}
                <p className="text-[9px] text-slate-700 mt-0.5">
                  {new Date(s.submitted_at).toLocaleString('es-MX', { day:'numeric', month:'short', hour:'2-digit', minute:'2-digit' })}
                </p>
              </div>
              {plots.length > 0 && (
                <span className="text-[9px] px-1.5 py-0.5 rounded shrink-0"
                      style={{ background: 'rgba(249,115,22,0.1)', color: '#f97316' }}>
                  {plots.length} plot{plots.length > 1 ? 's' : ''}
                </span>
              )}
            </div>

            {isOpen && (
              <div className="border-t px-5 py-4 space-y-4" style={{ borderColor: 'rgba(255,255,255,0.06)' }}>
                {/* Badge awarded toast */}
                {badgeMsg && (
                  <div className="rounded-lg px-4 py-3 flex items-center gap-3 animate-pulse"
                       style={{ background: `${TIER[badgeMsg.tier]?.color ?? '#facc15'}12`, border: `1px solid ${TIER[badgeMsg.tier]?.color ?? '#facc15'}33` }}>
                    <svg viewBox="0 0 24 24" className="w-4 h-4 shrink-0" fill="none" stroke={TIER[badgeMsg.tier]?.color ?? '#facc15'} strokeWidth="2">
                      <path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z" />
                    </svg>
                    <p className="text-xs font-bold" style={{ color: TIER[badgeMsg.tier]?.color ?? '#facc15' }}>
                      ¡Insignia otorgada automáticamente! — {badgeMsg.name}
                      <span className="ml-2 text-slate-600 font-normal">({badgeMsg.org})</span>
                    </p>
                  </div>
                )}

                {/* Plots */}
                {plots.length > 0 && (
                  <div>
                    <p className="text-[10px] text-slate-600 uppercase tracking-wider mb-2">Visualizaciones entregadas</p>
                    <div className="flex gap-3 overflow-x-auto pb-2">
                      {plots.map((p, i) => (
                        <img key={i} src={`data:image/png;base64,${p}`}
                             className="h-48 rounded-lg border shrink-0"
                             style={{ borderColor: 'rgba(255,255,255,0.08)' }} alt={`Plot ${i+1}`} />
                      ))}
                    </div>
                  </div>
                )}

                {/* Code */}
                {s.code && (
                  <div>
                    <p className="text-[10px] text-slate-600 uppercase tracking-wider mb-2">Código</p>
                    <pre className="text-[10px] font-mono text-green-300 p-3 rounded-lg overflow-x-auto"
                         style={{ background: '#050a14', border: '1px solid rgba(255,255,255,0.06)', maxHeight: 180 }}>
                      {s.code}
                    </pre>
                  </div>
                )}

                {/* Output */}
                {s.output && (
                  <div>
                    <p className="text-[10px] text-slate-600 uppercase tracking-wider mb-2">Output</p>
                    <pre className="text-[10px] font-mono text-slate-300 p-3 rounded-lg overflow-x-auto"
                         style={{ background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,255,255,0.06)', maxHeight: 120 }}>
                      {s.output.replace(/__PLOT__:[A-Za-z0-9+/=]+/g, '[gráfica]')}
                    </pre>
                  </div>
                )}

                {s.notes && <p className="text-xs text-slate-400"><span className="text-slate-600">Notas: </span>{s.notes}</p>}

                {/* Scoring */}
                <div className="rounded-lg p-4 space-y-3" style={{ background: 'rgba(74,222,128,0.04)', border: '1px solid rgba(74,222,128,0.1)' }}>
                  <div className="flex items-center justify-between">
                    <p className="text-[10px] text-green-700 font-bold uppercase">Calificación</p>
                    {ch?.badge_name && ch.badge_tier && s.score == null && (
                      <p className="text-[9px]" style={{ color: TIER[ch.badge_tier]?.color ?? '#facc15' }}>
                        ★ Otorga &quot;{ch.badge_name}&quot; si ≥ {ch.min_score_badge} pts
                        {willEarnBadge && <span className="ml-1 text-green-400">← ¡este score lo logrará!</span>}
                      </p>
                    )}
                  </div>
                  <div className="flex items-center gap-3">
                    <input type="number" min="0" max="100" placeholder="0–100"
                           value={scoring[s.id]?.score ?? (s.score ?? '')}
                           onChange={e => setScoring(p => ({ ...p, [s.id]: { ...p[s.id], score: e.target.value } }))}
                           className="w-20 rounded-lg px-3 py-2 text-xs text-slate-100 outline-none"
                           style={{ background: 'rgba(255,255,255,0.06)', border: '1px solid rgba(255,255,255,0.1)' }} />
                    <input placeholder="Retroalimentación al estudiante..."
                           value={scoring[s.id]?.feedback ?? (s.feedback ?? '')}
                           onChange={e => setScoring(p => ({ ...p, [s.id]: { ...p[s.id], feedback: e.target.value } }))}
                           className="flex-1 rounded-lg px-3 py-2 text-xs text-slate-100 outline-none"
                           style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)' }} />
                    <button onClick={() => saveScore(s.id)}
                            className="px-4 py-2 rounded-lg text-xs font-bold"
                            style={{ background: 'rgba(74,222,128,0.15)', border: '1px solid rgba(74,222,128,0.4)', color: '#4ade80' }}>
                      Guardar
                    </button>
                  </div>
                </div>
              </div>
            )}
          </div>
        )
      })}
      {subs.length === 0 && <p className="text-xs text-slate-700 px-2">No hay entregas todavía.</p>}
    </div>
  )
}

// ── Fuentes CTI Tab ───────────────────────────────────────────────────────────

interface FeedSource {
  id: number; name: string; category: string; url: string; feed_type: string
  requires_auth: number; api_key_env: string; description: string; formats: string
  group_label: string; status: string; last_fetched?: string; last_count: number
}

const CAT_COLOR: Record<string, string> = {
  IOC:        '#22d3ee',
  IoA:        '#a78bfa',
  Botnet:     '#f97316',
  Ransomware: '#ef4444',
  Malware:    '#facc15',
}

const STATUS_META: Record<string, { label: string; color: string; dot: string }> = {
  active:    { label: 'Activo',      color: '#4ade80', dot: '🟢' },
  needs_key: { label: 'API Key',     color: '#facc15', dot: '🟡' },
  manual:    { label: 'Manual',      color: '#94a3b8', dot: '⚪' },
  unavailable:{ label: 'No disp.',   color: '#ef4444', dot: '🔴' },
}

function FuentesTab({ token }: { token: string }) {
  const [sources,   setSources]   = useState<FeedSource[]>([])
  const [catFilter, setCatFilter] = useState('ALL')
  const [fetching,  setFetching]  = useState<number | null>(null)
  const [fetchRes,  setFetchRes]  = useState<Record<number, { count: number; sample: unknown[]; error?: string }>>({})

  useEffect(() => {
    apiFetch('/admin/sources', token).then(setSources).catch(() => {})
  }, [token])

  const doFetch = async (src: FeedSource) => {
    setFetching(src.id)
    setFetchRes(p => ({ ...p, [src.id]: undefined! }))
    try {
      const res = await apiFetch(`/admin/sources/${src.id}/fetch`, token, { method: 'POST' })
      setSources(p => p.map(s => s.id === src.id ? { ...s, status: 'active', last_fetched: new Date().toISOString(), last_count: res.count } : s))
      setFetchRes(p => ({ ...p, [src.id]: { count: res.count, sample: res.sample } }))
    } catch (e: unknown) {
      setFetchRes(p => ({ ...p, [src.id]: { count: 0, sample: [], error: String(e) } }))
    } finally { setFetching(null) }
  }

  const filtered   = catFilter === 'ALL' ? sources : sources.filter(s => s.category === catFilter)
  const grouped    = filtered.reduce((acc, s) => {
    const k = s.group_label || s.category
    ;(acc[k] = acc[k] || []).push(s)
    return acc
  }, {} as Record<string, FeedSource[]>)

  const totalActive = sources.filter(s => s.status === 'active').length
  const totalKey    = sources.filter(s => s.status === 'needs_key').length

  return (
    <div className="space-y-5">
      {/* Summary bar */}
      <div className="grid grid-cols-5 gap-3">
        {(['IOC','IoA','Botnet','Ransomware','Malware'] as const).map(cat => {
          const catSrcs = sources.filter(s => s.category === cat)
          const color   = CAT_COLOR[cat] ?? '#64748b'
          return (
            <button key={cat} onClick={() => setCatFilter(catFilter === cat ? 'ALL' : cat)}
                    className="rounded-xl p-3 text-left transition-all"
                    style={{ background: catFilter === cat ? `${color}18` : 'rgba(255,255,255,0.03)', border: `1px solid ${catFilter === cat ? color+'44' : 'rgba(255,255,255,0.06)'}` }}>
              <p className="text-[10px] font-bold uppercase tracking-wider mb-1" style={{ color }}>{cat}</p>
              <p className="text-lg font-black text-white">{catSrcs.length}</p>
              <p className="text-[9px] text-slate-600">{catSrcs.filter(s => s.status === 'active').length} activos</p>
            </button>
          )
        })}
      </div>

      <div className="flex items-center gap-3 text-xs text-slate-500">
        <span>🟢 {totalActive} activos (sin auth)</span>
        <span>🟡 {totalKey} necesitan API key</span>
        <span>⚪ {sources.filter(s => s.status === 'manual').length} manuales</span>
        <button onClick={() => setCatFilter('ALL')} className="ml-auto text-[10px] text-cyan-700 hover:text-cyan-400">Mostrar todos</button>
      </div>

      {/* Source groups */}
      {Object.entries(grouped).map(([group, srcs]) => (
        <div key={group} className="space-y-2">
          <div className="flex items-center gap-2">
            <p className="text-[10px] font-bold uppercase tracking-wider"
               style={{ color: CAT_COLOR[srcs[0]?.category] ?? '#64748b' }}>
              {group}
            </p>
            <span className="text-[9px] text-slate-700">({srcs.length} fuentes)</span>
          </div>

          <div className="space-y-1.5">
            {srcs.map(src => {
              const st      = STATUS_META[src.status] ?? STATUS_META.unavailable
              const color   = CAT_COLOR[src.category] ?? '#64748b'
              const canFetch = src.status !== 'manual' && !src.requires_auth
              const res     = fetchRes[src.id]
              const isFetching = fetching === src.id

              return (
                <div key={src.id} className="rounded-xl overflow-hidden" style={glass}>
                  <div className="flex items-start gap-4 px-4 py-3">
                    {/* Category dot */}
                    <div className="w-2 h-2 rounded-full mt-1.5 shrink-0" style={{ background: color }} />

                    {/* Info */}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap mb-0.5">
                        <p className="text-sm font-semibold text-slate-100">{src.name}</p>
                        <span className="text-[9px] px-1.5 py-0.5 rounded font-bold"
                              style={{ background: `${color}12`, color, border: `1px solid ${color}22` }}>
                          {src.category}
                        </span>
                        <span className="text-[9px] px-1.5 py-0.5 rounded"
                              style={{ background: 'rgba(255,255,255,0.04)', color: '#64748b', border: '1px solid rgba(255,255,255,0.06)' }}>
                          {src.feed_type}
                        </span>
                        <span className="text-[9px]" style={{ color: st.color }}>{st.dot} {st.label}</span>
                        {src.formats && (
                          <span className="text-[9px] text-slate-700">{src.formats}</span>
                        )}
                      </div>
                      <p className="text-[10px] text-slate-500 mb-1">{src.description}</p>
                      <div className="flex items-center gap-3 text-[9px] text-slate-700 flex-wrap">
                        <a href={src.url} target="_blank" rel="noopener noreferrer"
                           className="text-cyan-800 hover:text-cyan-500 transition-colors truncate max-w-xs"
                           onClick={e => e.stopPropagation()}>
                          {src.url}
                        </a>
                        {src.api_key_env && (
                          <span className="font-mono px-1.5 py-0.5 rounded"
                                style={{ background: 'rgba(250,204,21,0.08)', color: '#facc15', border: '1px solid rgba(250,204,21,0.15)' }}>
                            env: {src.api_key_env}
                          </span>
                        )}
                        {src.last_fetched && (
                          <span>Último fetch: {new Date(src.last_fetched).toLocaleString('es-MX', { day:'numeric', month:'short', hour:'2-digit', minute:'2-digit' })} · {src.last_count} IOCs</span>
                        )}
                      </div>

                      {/* Fetch result */}
                      {res && (
                        <div className="mt-2 rounded-lg px-3 py-2 space-y-1"
                             style={res.error
                               ? { background: 'rgba(239,68,68,0.06)', border: '1px solid rgba(239,68,68,0.15)' }
                               : { background: 'rgba(74,222,128,0.04)', border: '1px solid rgba(74,222,128,0.1)' }}>
                          {res.error
                            ? <p className="text-[9px] text-red-400">{res.error}</p>
                            : <>
                                <p className="text-[9px] font-bold text-green-500">✓ {res.count} registros obtenidos</p>
                                <pre className="text-[8px] font-mono text-slate-500 overflow-x-auto max-h-24">
                                  {JSON.stringify(res.sample?.[0], null, 2)}
                                </pre>
                              </>
                          }
                        </div>
                      )}
                    </div>

                    {/* Actions */}
                    <div className="flex items-center gap-2 shrink-0 mt-0.5">
                      {canFetch && (
                        <button onClick={() => doFetch(src)} disabled={isFetching}
                                className="text-[9px] px-2.5 py-1 rounded font-bold disabled:opacity-40 transition-all"
                                style={{ background: `${color}12`, border: `1px solid ${color}33`, color }}>
                          {isFetching ? '...' : '⬇ Fetch'}
                        </button>
                      )}
                      {src.requires_auth === 1 && !canFetch && (
                        <span className="text-[9px] px-2 py-1 rounded"
                              style={{ background: 'rgba(250,204,21,0.06)', color: '#854d0e', border: '1px solid rgba(250,204,21,0.15)' }}>
                          Necesita key
                        </span>
                      )}
                    </div>
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      ))}

      {sources.length === 0 && (
        <p className="text-xs text-slate-700 px-2">Cargando fuentes...</p>
      )}
    </div>
  )
}

// ── Badge Progress Tab ────────────────────────────────────────────────────────

function BadgeProgressTab({ token }: { token: string }) {
  const [progress, setProgress] = useState<BadgeProgress[]>([])
  const [filter,   setFilter]   = useState<'all' | 'student'>('student')

  useEffect(() => {
    apiFetch('/admin/badge-progress', token).then(setProgress).catch(() => {})
    const id = setInterval(() => apiFetch('/admin/badge-progress', token).then(setProgress).catch(() => {}), 10000)
    return () => clearInterval(id)
  }, [token])

  const shown = filter === 'student' ? progress.filter(p => p.role === 'student') : progress

  if (progress.length === 0) return (
    <p className="text-xs text-slate-700 animate-pulse">Cargando progreso...</p>
  )

  const allBadgeNames = progress[0]?.badges.map(b => ({ id: b.id, name: b.name, org: b.org, tier: b.tier })) ?? []
  const orgGroups = allBadgeNames.reduce((acc, b) => {
    ;(acc[b.org] = acc[b.org] || []).push(b)
    return acc
  }, {} as Record<string, typeof allBadgeNames>)

  return (
    <div className="space-y-5">
      {/* Summary */}
      <div className="grid grid-cols-4 gap-3">
        <StatCard label="Estudiantes"      value={progress.filter(p => p.role === 'student').length} color={CYAN} />
        <StatCard label="Insignias ganadas" value={progress.reduce((s, p) => s + p.badge_count, 0)}  color="#facc15" />
        <StatCard label="CTF solves total" value={progress.reduce((s, p) => s + p.ctf_solves, 0)}    color="#4ade80" />
        <StatCard label="CTF puntos total" value={progress.reduce((s, p) => s + p.ctf_points, 0)}    color="#a78bfa" />
      </div>

      <div className="flex items-center gap-3">
        <p className="text-xs text-slate-500 flex-1">Matriz de progreso — {shown.length} usuarios</p>
        <div className="flex rounded-lg overflow-hidden" style={{ border: '1px solid rgba(255,255,255,0.07)' }}>
          {(['student', 'all'] as const).map(f => (
            <button key={f} onClick={() => setFilter(f)}
                    className="text-[10px] px-3 py-1.5 transition-all"
                    style={{ background: filter === f ? 'rgba(249,115,22,0.15)' : 'transparent', color: filter === f ? '#f97316' : '#475569' }}>
              {f === 'student' ? 'Solo estudiantes' : 'Todos'}
            </button>
          ))}
        </div>
      </div>

      {/* Per-org badge sections */}
      {Object.entries(orgGroups).map(([org, orgBadges]) => (
        <div key={org} className="rounded-xl overflow-hidden" style={glass}>
          <div className="px-4 py-3 border-b" style={{ borderColor: 'rgba(255,255,255,0.06)' }}>
            <p className="text-xs font-bold text-slate-300">{org}
              <span className="ml-2 text-[10px] font-normal text-slate-600">({orgBadges.length} insignias)</span>
            </p>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-[10px]">
              <thead>
                <tr style={{ background: 'rgba(255,255,255,0.03)' }}>
                  <th className="px-4 py-2 text-left text-slate-500 font-medium sticky left-0" style={{ background: 'rgba(8,12,25,0.97)', minWidth: 160 }}>Estudiante</th>
                  <th className="px-2 py-2 text-center text-slate-500 font-medium">CTF pts</th>
                  <th className="px-2 py-2 text-center text-slate-500 font-medium">Prom</th>
                  {orgBadges.map(b => {
                    const t = TIER[b.tier] ?? TIER.bronze
                    return (
                      <th key={b.id} className="px-2 py-2 text-center font-medium max-w-20"
                          title={b.name} style={{ color: t.color }}>
                        <div className="truncate max-w-[72px]">{b.name.split(' ').slice(0, 2).join(' ')}</div>
                        <div className="text-[8px] opacity-50">{t.label}</div>
                      </th>
                    )
                  })}
                </tr>
              </thead>
              <tbody className="divide-y divide-white/[0.03]">
                {shown.map(p => {
                  return (
                    <tr key={p.email} className="hover:bg-white/[0.015]">
                      <td className="px-4 py-2 sticky left-0" style={{ background: 'rgba(8,12,25,0.97)' }}>
                        <p className="font-medium text-slate-200 truncate max-w-36">{p.name}</p>
                        <p className="text-slate-700 truncate max-w-36">{p.email}</p>
                      </td>
                      <td className="px-2 py-2 text-center">
                        <span className="font-bold" style={{ color: p.ctf_points > 0 ? '#4ade80' : '#475569' }}>
                          {p.ctf_points}
                        </span>
                        <p className="text-[8px] text-slate-700">{p.ctf_solves} solves</p>
                      </td>
                      <td className="px-2 py-2 text-center">
                        {p.avg_score > 0
                          ? <span className="font-bold" style={{ color: p.avg_score >= 70 ? '#4ade80' : '#facc15' }}>{p.avg_score}</span>
                          : <span className="text-slate-700">—</span>
                        }
                      </td>
                      {orgBadges.map(b => {
                        const ub = p.badges.find(x => x.id === b.id)
                        const t  = TIER[b.tier] ?? TIER.bronze
                        return (
                          <td key={b.id} className="px-2 py-2 text-center">
                            {ub?.earned
                              ? <span title={ub.earned_at ?? ''} style={{ color: t.color }} className="text-base">★</span>
                              : <span className="text-slate-800 text-xs">○</span>
                            }
                          </td>
                        )
                      })}
                    </tr>
                  )
                })}
              </tbody>
              <tfoot>
                <tr style={{ background: 'rgba(255,255,255,0.02)' }}>
                  <td className="px-4 py-2 text-slate-600 font-bold sticky left-0" style={{ background: 'rgba(8,12,25,0.97)' }}>Total ganaron</td>
                  <td colSpan={2} />
                  {orgBadges.map(b => {
                    const count = shown.filter(p => p.badges.find(x => x.id === b.id)?.earned).length
                    const t = TIER[b.tier] ?? TIER.bronze
                    return (
                      <td key={b.id} className="px-2 py-2 text-center">
                        <span className="font-bold text-xs" style={{ color: count > 0 ? t.color : '#475569' }}>{count}</span>
                      </td>
                    )
                  })}
                </tr>
              </tfoot>
            </table>
          </div>
          {/* Summary bar per student */}
          <div className="px-4 py-3 border-t flex flex-wrap gap-2" style={{ borderColor: 'rgba(255,255,255,0.06)' }}>
            {shown.filter(p => {
              const count = p.badges.filter(b => orgBadges.some(ob => ob.id === b.id) && b.earned).length
              return count > 0
            }).map(p => {
              const count  = p.badges.filter(b => orgBadges.some(ob => ob.id === b.id) && b.earned).length
              return (
                <span key={p.email} className="text-[9px] px-2 py-1 rounded-full"
                      style={{ background: 'rgba(250,204,21,0.08)', color: '#facc15', border: '1px solid rgba(250,204,21,0.15)' }}>
                  {p.name.split(' ')[0]} · {count}/{orgBadges.length}
                </span>
              )
            })}
            {shown.every(p => p.badges.filter(b => orgBadges.some(ob => ob.id === b.id) && b.earned).length === 0) && (
              <p className="text-[10px] text-slate-700">Ningún estudiante ha ganado insignias de este grupo aún.</p>
            )}
          </div>
        </div>
      ))}
    </div>
  )
}

// ── Main AdminPanel ───────────────────────────────────────────────────────────

const TABS: { id: Tab; label: string; icon: string; badge?: number }[] = [
  { id: 'dashboard',   label: 'Dashboard',  icon: 'M3 3h7v7H3zM14 3h7v7h-7zM3 14h7v7H3zM14 14h7v7h-7z' },
  { id: 'users',       label: 'Usuarios',   icon: 'M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM23 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75' },
  { id: 'teams',       label: 'Equipos',    icon: 'M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2zM9 22V12h6v10' },
  { id: 'badges',      label: 'Insignias',  icon: 'M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z' },
  { id: 'progreso',    label: 'Progreso',   icon: 'M22 12h-4l-3 9L9 3l-3 9H2' },
  { id: 'fases',       label: 'Fases CTF',  icon: 'M13 2L3 14h9l-1 8 10-12h-9l1-8z' },
  { id: 'datasets',    label: 'Datasets',   icon: 'M4 7h16M4 12h16M4 17h16' },
  { id: 'retos',       label: 'Retos',      icon: 'M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z' },
  { id: 'submissions', label: 'Entregas',   icon: 'M9 5H7a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V7a2 2 0 0 0-2-2h-2M9 5a2 2 0 0 0 2 2h2a2 2 0 0 0 2-2M9 5a2 2 0 0 1 2-2h2a2 2 0 0 1 2 2' },
]

export default function AdminPanel({ onExitAdmin }: { onExitAdmin: () => void }) {
  const { user, logout, token } = useAuth()
  const [tab,        setTab]        = useState<Tab>('dashboard')
  const [stats,      setStats]      = useState<Stats | null>(null)
  const [users,      setUsers]      = useState<User[]>([])
  const [datasets,   setDatasets]   = useState<Dataset[]>([])
  const [challenges, setChallenges] = useState<Challenge[]>([])
  const [teams,      setTeams]      = useState<Team[]>([])
  const [allBadges,  setAllBadges]  = useState<Badge[]>([])
  const [awarded,    setAwarded]    = useState<AwardedBadge[]>([])
  const [phases,     setPhases]     = useState<CtfPhase[]>([])

  const tk = token ?? ''

  const fetchAll = useCallback(() => {
    apiFetch('/admin/stats',           tk).then(setStats).catch(() => {})
    apiFetch('/admin/users',           tk).then(setUsers).catch(() => {})
    apiFetch('/admin/datasets',        tk).then(setDatasets).catch(() => {})
    apiFetch('/admin/challenges',      tk).then(setChallenges).catch(() => {})
    apiFetch('/admin/teams',           tk).then(setTeams).catch(() => {})
    apiFetch('/admin/badges',          tk).then(setAllBadges).catch(() => {})
    apiFetch('/admin/badges/awarded',  tk).then(setAwarded).catch(() => {})
    apiFetch('/admin/ctf-phases',      tk).then(setPhases).catch(() => {})
  }, [tk])

  useEffect(() => {
    fetchAll()
    const id = setInterval(fetchAll, 5000)
    return () => clearInterval(id)
  }, [fetchAll])

  return (
    <div className="min-h-screen flex" style={{ background: '#030712' }}>

      {/* ── Sidebar ──────────────────────────────────────────────────────── */}
      <aside className="w-56 shrink-0 flex flex-col border-r"
             style={{ background: 'rgba(8,12,25,0.97)', borderColor: 'rgba(255,255,255,0.05)' }}>

        <div className="h-14 flex items-center gap-3 px-4 border-b" style={{ borderColor: 'rgba(255,255,255,0.05)' }}>
          <div className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0"
               style={{ background: 'rgba(249,115,22,0.15)', boxShadow: '0 0 16px rgba(249,115,22,0.2)' }}>
            <svg viewBox="0 0 24 24" className="w-4 h-4" fill="none" stroke="#f97316" strokeWidth="2">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            </svg>
          </div>
          <div>
            <p className="text-sm font-bold text-white leading-none">Admin Panel</p>
            <p className="text-[9px] font-mono text-orange-900 tracking-widest mt-0.5">CTI NEXUS</p>
          </div>
        </div>

        <nav className="flex-1 px-2 py-4 space-y-0.5">
          {TABS.map(t => {
            const active = tab === t.id
            return (
              <button key={t.id} onClick={() => setTab(t.id)}
                      className="w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-xs transition-all group"
                      style={active ? {
                        background: 'rgba(249,115,22,0.1)', borderLeft: '2px solid #f97316',
                        paddingLeft: 10, color: '#f97316',
                      } : { color: '#475569', borderLeft: '2px solid transparent' }}>
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"
                     strokeLinecap="round" strokeLinejoin="round"
                     className={`w-4 h-4 shrink-0 ${active ? 'text-orange-400' : 'text-slate-700 group-hover:text-slate-500'}`}>
                  <path d={t.icon} />
                </svg>
                <span className={`font-medium ${active ? '' : 'group-hover:text-slate-300'}`}>{t.label}</span>
                {t.id === 'submissions' && stats?.pending_scoring ? (
                  <span className="ml-auto text-[9px] font-bold px-1.5 py-0.5 rounded-full"
                        style={{ background: 'rgba(250,204,21,0.15)', color: '#facc15' }}>
                    {stats.pending_scoring}
                  </span>
                ) : t.id === 'badges' && awarded.length > 0 ? (
                  <span className="ml-auto text-[9px] font-bold px-1.5 py-0.5 rounded-full"
                        style={{ background: 'rgba(255,215,0,0.15)', color: '#ffd700' }}>
                    {awarded.length}
                  </span>
                ) : t.id === 'teams' && teams.length > 0 ? (
                  <span className="ml-auto text-[9px] font-bold px-1.5 py-0.5 rounded-full"
                        style={{ background: 'rgba(34,211,238,0.15)', color: CYAN }}>
                    {teams.length}
                  </span>
                ) : null}
              </button>
            )
          })}
        </nav>

        <div className="px-4 py-3 border-t space-y-3" style={{ borderColor: 'rgba(255,255,255,0.05)' }}>
          <div>
            <p className="text-xs text-orange-400 truncate">{user?.name}</p>
            <p className="text-[9px] text-slate-700 truncate">{user?.email}</p>
          </div>
          <div className="flex gap-2">
            <button onClick={onExitAdmin}
                    className="flex-1 text-[10px] py-1.5 rounded-lg transition-colors text-slate-500 hover:text-slate-300"
                    style={{ border: '1px solid rgba(255,255,255,0.06)' }}>
              Ver plataforma
            </button>
            <button onClick={logout}
                    className="flex-1 text-[10px] py-1.5 rounded-lg transition-colors"
                    style={{ border: '1px solid rgba(239,68,68,0.2)', color: '#ef4444' }}>
              Salir
            </button>
          </div>
        </div>
      </aside>

      {/* ── Main content ─────────────────────────────────────────────────── */}
      <div className="flex-1 flex flex-col overflow-hidden">
        <header className="h-14 flex items-center justify-between px-6 border-b shrink-0"
                 style={{ background: 'rgba(8,12,25,0.85)', backdropFilter: 'blur(20px)', borderColor: 'rgba(255,255,255,0.05)' }}>
          <div>
            <p className="text-sm font-semibold text-slate-200">
              {TABS.find(t => t.id === tab)?.label}
            </p>
            <p className="text-[10px] text-slate-600 font-mono">
              CTI Nexus · Panel de Administración · {new Date().toLocaleDateString('es-MX', { weekday: 'long', day: 'numeric', month: 'long' })}
            </p>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-[9px] px-2 py-1 rounded font-bold"
                  style={{ background: 'rgba(249,115,22,0.1)', border: '1px solid rgba(249,115,22,0.25)', color: '#f97316' }}>
              ADMIN
            </span>
            <span className="text-[9px] text-slate-700 animate-pulse">● actualizando cada 5s</span>
          </div>
        </header>

        <main className="flex-1 overflow-y-auto p-6">
          {tab === 'dashboard'   && <DashboardTab   stats={stats} />}
          {tab === 'users'       && <UsersTab       users={users} challenges={challenges} allBadges={allBadges} token={tk} onRefresh={fetchAll} />}
          {tab === 'teams'       && <EquiposTab     teams={teams} users={users} challenges={challenges} allBadges={allBadges} token={tk} onRefresh={fetchAll} />}
          {tab === 'badges'      && <InsigniasTab     allBadges={allBadges} awarded={awarded} token={tk} onRefresh={fetchAll} />}
          {tab === 'progreso'    && <BadgeProgressTab token={tk} />}
          {tab === 'fases'       && <FasesCTFTab    phases={phases} datasets={datasets} token={tk} onRefresh={fetchAll} />}
          {tab === 'datasets'    && <DatasetsTab    datasets={datasets} token={tk} onRefresh={fetchAll} />}
          {tab === 'fuentes'     && <FuentesTab     token={tk} />}
          {tab === 'retos'       && <RetosTab       challenges={challenges} datasets={datasets} users={users} allBadges={allBadges} token={tk} onRefresh={fetchAll} />}
          {tab === 'submissions' && <SubmissionsTab token={tk} challenges={challenges} />}
        </main>
      </div>
    </div>
  )
}

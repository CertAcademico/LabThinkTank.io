import { useState, useEffect, useCallback } from 'react'
import { useAuth } from '../contexts/AuthContext'
import { BadgeCard, TIER, type Badge } from './BadgeCard'

const API = import.meta.env.VITE_API_URL ?? 'http://127.0.0.1:8000'

// ── Types ─────────────────────────────────────────────────────────────────────

interface User       { id: number; name: string; email: string; role: string; created_at: string }
interface Dataset    { id: number; name: string; description: string; source: string; schema_json: string; created_by: string; created_at: string }
interface Challenge  { id: number; title: string; description: string; objective: string; criteria: string; deadline?: string; status: string; dataset_name?: string; assigned_count: number; submission_count: number; created_at: string }
interface Team       { id: number; name: string; color: string; created_by: string; members: { name: string; email: string; role: string }[] }
interface AwardedBadge { user_email: string; user_name: string; org: string; badge_name: string; tier: string; icon: string; awarded_by: string; awarded_at: string; badge_id: number }
interface Assignment { name: string; email: string; assigned_at: string; submitted: number }
interface Submission { id: number; challenge_id: number; challenge_title: string; user_name: string; user_email: string; code: string; output: string; plots_json: string; notes: string; score?: number; feedback: string; submitted_at: string }
interface Stats      { students: number; active_challenges: number; datasets: number; submissions_today: number; pending_scoring: number; recent_submissions: { user_name: string; challenge: string; submitted_at: string; score?: number }[] }

type Tab = 'dashboard' | 'users' | 'teams' | 'badges' | 'datasets' | 'retos' | 'submissions'

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
  return (
    <div className="space-y-6">
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

function EquiposTab({ teams, users, challenges, token, onRefresh }: {
  teams: Team[]; users: User[]; challenges: Challenge[]; token: string; onRefresh: () => void
}) {
  const [showForm, setShowForm] = useState(false)
  const [form,     setForm]     = useState({ name: '', color: '#22d3ee' })
  const [selUsers, setSelUsers] = useState<Record<number, string[]>>({})
  const [selChal,  setSelChal]  = useState<Record<number, number | ''>>({})
  const [loading,  setLoading]  = useState(false)

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
                {/* Members */}
                <div className="flex flex-wrap gap-2">
                  {t.members.map(m => (
                    <div key={m.email} className="flex items-center gap-1.5 rounded-full px-2.5 py-1"
                         style={{ background: `${t.color}12`, border: `1px solid ${t.color}33` }}>
                      <span className="text-[10px] font-medium" style={{ color: t.color }}>{m.name}</span>
                      <button onClick={() => removeMember(t.id, m.email)}
                              className="text-[9px] opacity-50 hover:opacity-100" style={{ color: RED }}>✕</button>
                    </div>
                  ))}
                  {t.members.length === 0 && <p className="text-[10px] text-slate-700">Sin miembros aún.</p>}
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

                  {/* Assign team to challenge */}
                  <div className="space-y-2">
                    <p className="text-[9px] text-slate-600 uppercase tracking-wider font-bold">Asignar equipo a reto</p>
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
                      Asignar todo el equipo →
                    </button>
                  </div>
                </div>
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

function RetosTab({ challenges, datasets, users, token, onRefresh }: {
  challenges: Challenge[]; datasets: Dataset[]; users: User[]; token: string; onRefresh: () => void
}) {
  const [showForm,    setShowForm]    = useState(false)
  const [form, setForm] = useState({ title: '', description: '', objective: '', criteria: '', dataset_id: '' as string | number, deadline: '' })
  const [loading,     setLoading]     = useState(false)
  const [expanded,    setExpanded]    = useState<number | null>(null)
  const [assignments, setAssignments] = useState<Record<number, Assignment[]>>({})
  const [selUsers,    setSelUsers]    = useState<Record<number, string[]>>({})

  const loadAssignments = useCallback(async (cid: number) => {
    const data = await apiFetch(`/admin/challenges/${cid}/assignments`, token).catch(() => [])
    setAssignments(p => ({ ...p, [cid]: data }))
  }, [token])

  useEffect(() => {
    if (expanded !== null) loadAssignments(expanded)
  }, [expanded, loadAssignments])

  // Auto-refresh expanded challenge every 5s
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
        body: JSON.stringify({ ...form, dataset_id: form.dataset_id || null }),
      })
      setShowForm(false)
      setForm({ title: '', description: '', objective: '', criteria: '', dataset_id: '', deadline: '' })
      onRefresh()
    } catch (e) { alert(e) }
    finally { setLoading(false) }
  }

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

  const assign = async (cid: number) => {
    const emails = selUsers[cid] ?? []
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

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-xs text-slate-500">{challenges.length} retos creados</p>
        <button onClick={() => setShowForm(s => !s)}
                className="px-4 py-2 rounded-lg text-xs font-bold"
                style={{ background: 'rgba(167,139,250,0.12)', border: '1px solid rgba(167,139,250,0.3)', color: '#a78bfa' }}>
          {showForm ? 'Cancelar' : '+ Nuevo reto'}
        </button>
      </div>

      {showForm && (
        <div className="rounded-xl p-5 space-y-3" style={glass}>
          <p className="text-xs font-bold text-slate-300">Crear reto</p>
          {[
            { label: 'Título *', key: 'title', placeholder: 'Análisis de ataque Supply Chain XZ Utils' },
            { label: 'Descripción', key: 'description', placeholder: 'Contexto del reto...' },
            { label: 'Objetivo del estudiante', key: 'objective', placeholder: 'Identificar el vector de entrada y crear 2 visualizaciones' },
            { label: 'Criterios de evaluación', key: 'criteria', placeholder: 'Creatividad (40%) + Precisión del análisis (60%)' },
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
              <label className="text-[10px] text-slate-500">Fecha límite</label>
              <input type="datetime-local" value={form.deadline}
                     onChange={e => setForm(p => ({ ...p, deadline: e.target.value }))}
                     className="w-full rounded-lg px-3 py-2 text-xs text-slate-100 outline-none"
                     style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)' }} />
            </div>
          </div>
          <button onClick={create} disabled={loading}
                  className="px-5 py-2 rounded-lg text-xs font-bold disabled:opacity-40"
                  style={{ background: 'rgba(167,139,250,0.15)', border: '1px solid rgba(167,139,250,0.4)', color: '#a78bfa' }}>
            {loading ? 'Creando...' : 'Crear reto →'}
          </button>
        </div>
      )}

      <div className="space-y-3">
        {challenges.map(c => {
          const isOpen = expanded === c.id
          const asmts  = assignments[c.id] ?? []
          const notAssigned = students.filter(u => !asmts.find(a => a.email === u.email))

          return (
            <div key={c.id} className="rounded-xl overflow-hidden" style={glass}>
              {/* Challenge header */}
              <div className="flex items-center gap-4 px-5 py-4 cursor-pointer hover:bg-white/[0.02]"
                   onClick={() => setExpanded(isOpen ? null : c.id)}>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-0.5">
                    <p className="text-sm font-semibold text-slate-100 truncate">{c.title}</p>
                    <Badge label={c.status} color={c.status === 'active' ? '#4ade80' : '#475569'} />
                    {c.dataset_name && <Badge label={c.dataset_name} color="#f97316" />}
                  </div>
                  <div className="flex items-center gap-4 text-[10px] text-slate-600">
                    <span>{c.assigned_count} asignados</span>
                    <span>{c.submission_count} entregas</span>
                    {c.deadline && <span>Límite: {new Date(c.deadline).toLocaleDateString('es-MX')}</span>}
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

                  {/* Assignment board */}
                  <div>
                    <p className="text-[10px] font-bold text-slate-500 uppercase tracking-wider mb-2">
                      Asignación en tiempo real
                      <span className="ml-2 text-[8px] text-cyan-700 animate-pulse">● live</span>
                    </p>
                    <div className="grid grid-cols-2 gap-3">
                      {/* Assigned */}
                      <div className="rounded-lg p-3 space-y-2" style={{ background: 'rgba(74,222,128,0.04)', border: '1px solid rgba(74,222,128,0.1)' }}>
                        <p className="text-[9px] text-green-700 font-bold uppercase">Asignados ({asmts.length})</p>
                        {asmts.map(a => (
                          <div key={a.email} className="flex items-center justify-between gap-2">
                            <div>
                              <p className="text-xs text-slate-300">{a.name}</p>
                              <p className="text-[9px] text-slate-600 flex items-center gap-1">
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
                                     onChange={e => {
                                       setSelUsers(p => {
                                         const cur = p[c.id] ?? []
                                         return { ...p, [c.id]: e.target.checked ? [...cur, u.email] : cur.filter(x => x !== u.email) }
                                       })
                                     }}
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

function SubmissionsTab({ token }: { token: string }) {
  const [subs,     setSubs]     = useState<Submission[]>([])
  const [expanded, setExpanded] = useState<number | null>(null)
  const [scoring,  setScoring]  = useState<Record<number, { score: string; feedback: string }>>({})

  const load = useCallback(() => {
    apiFetch('/admin/submissions', token).then(setSubs).catch(() => {})
  }, [token])

  useEffect(() => { load(); const id = setInterval(load, 5000); return () => clearInterval(id) }, [load])

  const saveScore = async (id: number) => {
    const s = scoring[id]
    if (!s?.score) return
    await apiFetch(`/admin/submissions/${id}/score`, token, {
      method: 'PUT',
      body: JSON.stringify({ score: Number(s.score), feedback: s.feedback ?? '' }),
    }).catch(alert)
    load()
  }

  return (
    <div className="space-y-3">
      <p className="text-xs text-slate-500">{subs.length} entregas · <span className="text-yellow-700">{subs.filter(s => s.score == null).length} por calificar</span></p>
      {subs.map(s => {
        const plots: string[] = (() => { try { return JSON.parse(s.plots_json) } catch { return [] } })()
        const isOpen = expanded === s.id
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
                <p className="text-xs text-slate-500 truncate">{s.challenge_title}</p>
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
                  <p className="text-[10px] text-green-700 font-bold uppercase">Calificación</p>
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

// ── Main AdminPanel ───────────────────────────────────────────────────────────

const TABS: { id: Tab; label: string; icon: string; badge?: number }[] = [
  { id: 'dashboard',   label: 'Dashboard',  icon: 'M3 3h7v7H3zM14 3h7v7h-7zM3 14h7v7H3zM14 14h7v7h-7z' },
  { id: 'users',       label: 'Usuarios',   icon: 'M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM23 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75' },
  { id: 'teams',       label: 'Equipos',    icon: 'M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2zM9 22V12h6v10' },
  { id: 'badges',      label: 'Insignias',  icon: 'M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z' },
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

  const tk = token ?? ''

  const fetchAll = useCallback(() => {
    apiFetch('/admin/stats',           tk).then(setStats).catch(() => {})
    apiFetch('/admin/users',           tk).then(setUsers).catch(() => {})
    apiFetch('/admin/datasets',        tk).then(setDatasets).catch(() => {})
    apiFetch('/admin/challenges',      tk).then(setChallenges).catch(() => {})
    apiFetch('/admin/teams',           tk).then(setTeams).catch(() => {})
    apiFetch('/admin/badges',          tk).then(setAllBadges).catch(() => {})
    apiFetch('/admin/badges/awarded',  tk).then(setAwarded).catch(() => {})
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
          {tab === 'teams'       && <EquiposTab     teams={teams} users={users} challenges={challenges} token={tk} onRefresh={fetchAll} />}
          {tab === 'badges'      && <InsigniasTab   allBadges={allBadges} awarded={awarded} token={tk} onRefresh={fetchAll} />}
          {tab === 'datasets'    && <DatasetsTab    datasets={datasets} token={tk} onRefresh={fetchAll} />}
          {tab === 'retos'       && <RetosTab       challenges={challenges} datasets={datasets} users={users} token={tk} onRefresh={fetchAll} />}
          {tab === 'submissions' && <SubmissionsTab token={tk} />}
        </main>
      </div>
    </div>
  )
}

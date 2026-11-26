import { useCallback, useEffect, useState } from 'react'
import TeamChat from './TeamChat'

const API = import.meta.env.VITE_API_URL ?? 'http://127.0.0.1:8000'
const glass = { background: 'rgba(26,31,19,0.6)', border: '1px solid rgba(255,255,255,0.07)', borderRadius: 12 }
const GOLD = '#d4bd55'

interface Reto { id: number; title: string; description: string; objective: string; criteria: string; difficulty: string; status: string; stage: string; dataset_name?: string }
interface Member { name: string; email: string; joined_at: string; progress: Record<string, { submitted: boolean; score: number | null }> }
interface Overview { id: number; name: string; color: string; open_signup: number; chat_enabled: number; retos: Reto[]; members: Member[] }

const STATUS: Record<string, { label: string; color: string }> = {
  active: { label: 'Activo', color: '#4ade80' }, closed: { label: 'Cerrado', color: '#f87171' }, draft: { label: 'Borrador', color: '#a3a27c' },
}

/** Panel de un grupo (por defecto ORION): sus retos, el avance de cada integrante y el chat con el instructor. */
export default function GroupOverviewTab({ teams, token }: { teams: { id: number; name: string }[]; token: string }) {
  const def = teams.find(t => t.name.toUpperCase() === 'ORION') ?? teams[0]
  const [teamId, setTeamId] = useState<number | undefined>(def?.id)
  const [data, setData]     = useState<Overview | null>(null)
  const [open, setOpen]     = useState<number | null>(null)
  const [error, setError]   = useState('')
  const headers = { Authorization: `Bearer ${token}` }

  useEffect(() => { if (!teamId && def) setTeamId(def.id) }, [def, teamId])

  const load = useCallback(async () => {
    if (!teamId) return
    const r = await fetch(`${API}/admin/teams/${teamId}/overview`, { headers })
    if (r.ok) { setData(await r.json()); setError('') } else setError('No se pudo cargar el grupo')
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [teamId, token])

  useEffect(() => { load() }, [load])

  const toggle = async (what: 'chat' | 'signup', value: boolean) => {
    const url = what === 'chat' ? `${API}/admin/teams/${teamId}/chat-enabled` : `${API}/admin/teams/${teamId}/open-signup`
    await fetch(url, { method: 'PATCH', headers: { ...headers, 'Content-Type': 'application/json' },
                       body: JSON.stringify(what === 'chat' ? { enabled: value } : { open: value }) })
    load()
  }

  if (!teams.length) return <p className="text-sm text-slate-500">No hay grupos creados.</p>

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center gap-3">
        <h2 className="text-lg font-bold text-slate-100">🎖️ Grupo {data?.name ?? ''}</h2>
        <select value={teamId} onChange={e => setTeamId(Number(e.target.value))}
                className="rounded-lg px-3 py-1.5 text-xs text-slate-200"
                style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.1)' }}>
          {teams.map(t => <option key={t.id} value={t.id}>{t.name}</option>)}
        </select>
        {data && (
          <div className="flex gap-2 ml-auto">
            <button onClick={() => toggle('signup', !data.open_signup)} className="rounded-lg px-3 py-1.5 text-[11px]"
                    style={{ border: `1px solid ${data.open_signup ? '#4ade80' : 'rgba(255,255,255,0.12)'}`, color: data.open_signup ? '#4ade80' : '#a3a27c' }}>
              Registro {data.open_signup ? 'abierto' : 'cerrado'}
            </button>
            <button onClick={() => toggle('chat', !data.chat_enabled)} className="rounded-lg px-3 py-1.5 text-[11px]"
                    style={{ border: `1px solid ${data.chat_enabled ? GOLD : 'rgba(255,255,255,0.12)'}`, color: data.chat_enabled ? GOLD : '#a3a27c' }}>
              Chat {data.chat_enabled ? 'habilitado' : 'deshabilitado'}
            </button>
          </div>
        )}
      </div>
      {error && <p className="text-xs text-red-400">{error}</p>}

      {data && (
        <div className="grid gap-5 xl:grid-cols-[1fr_420px]">
          <div className="space-y-5 min-w-0">
            {/* Retos del grupo */}
            <div className="p-4 space-y-2" style={glass}>
              <p className="text-[10px] font-bold uppercase tracking-wider" style={{ color: GOLD }}>
                Retos del grupo · {data.retos.length}
              </p>
              {data.retos.length === 0 && <p className="text-xs text-slate-500">Este grupo no tiene retos propios asignados.</p>}
              {data.retos.map((r, i) => {
                const st = STATUS[r.status] ?? { label: r.status, color: '#a3a27c' }
                const done = data.members.filter(m => m.progress[String(r.id)]?.submitted).length
                return (
                  <div key={r.id} className="rounded-lg" style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)' }}>
                    <button onClick={() => setOpen(open === r.id ? null : r.id)} className="w-full flex items-center gap-3 px-3 py-2 text-left">
                      <span className="w-6 text-[11px] font-mono" style={{ color: GOLD }}>{String(i + 1).padStart(2, '0')}</span>
                      <span className="flex-1 text-xs text-slate-200">{r.title}</span>
                      <span className="text-[10px] text-slate-500">{r.difficulty}</span>
                      <span className="text-[10px]" style={{ color: st.color }}>{st.label}</span>
                      <span className="text-[10px] text-slate-500">{done}/{data.members.length} entregas</span>
                    </button>
                    {open === r.id && (
                      <div className="px-4 pb-3 space-y-2 text-xs text-slate-400 whitespace-pre-wrap">
                        {r.description && <p>{r.description}</p>}
                        {r.objective && <p><b className="text-slate-300">Objetivo:</b> {r.objective}</p>}
                        {r.criteria && <p><b className="text-slate-300">Criterios:</b> {r.criteria}</p>}
                        {r.dataset_name && <p><b className="text-slate-300">Dataset:</b> {r.dataset_name}</p>}
                      </div>
                    )}
                  </div>
                )
              })}
            </div>

            {/* Avance por integrante */}
            <div className="p-4" style={glass}>
              <p className="text-[10px] font-bold uppercase tracking-wider mb-3" style={{ color: GOLD }}>
                Integrantes · {data.members.length}
              </p>
              {data.members.length === 0 ? (
                <p className="text-xs text-slate-500">Aún no hay integrantes. Se suman al registrarse eligiendo este grupo.</p>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-[11px]">
                    <thead>
                      <tr className="text-slate-500">
                        <th className="text-left font-medium py-1 pr-3">Integrante</th>
                        {data.retos.map((r, i) => <th key={r.id} title={r.title} className="font-mono font-medium px-1">{String(i + 1).padStart(2, '0')}</th>)}
                      </tr>
                    </thead>
                    <tbody>
                      {data.members.map(m => (
                        <tr key={m.email} className="border-t" style={{ borderColor: 'rgba(255,255,255,0.05)' }}>
                          <td className="py-1.5 pr-3">
                            <p className="text-slate-200">{m.name}</p>
                            <p className="text-[10px] text-slate-600">{m.email}</p>
                          </td>
                          {data.retos.map(r => {
                            const p = m.progress[String(r.id)]
                            return (
                              <td key={r.id} className="text-center px-1">
                                {p?.submitted
                                  ? <span style={{ color: (p.score ?? 0) >= 50 ? '#4ade80' : '#facc15' }}>{p.score ?? '✓'}</span>
                                  : <span className="text-slate-700">·</span>}
                              </td>
                            )
                          })}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>

          {/* Chat */}
          <div>
            {data.chat_enabled
              ? <TeamChat teamId={data.id} teamName={data.name} height={460} />
              : <div className="p-4 text-xs text-slate-500" style={glass}>El chat está deshabilitado para este grupo. Actívalo con el botón “Chat”.</div>}
          </div>
        </div>
      )}
    </div>
  )
}

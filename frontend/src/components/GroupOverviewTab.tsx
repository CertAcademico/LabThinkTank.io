import { useCallback, useEffect, useState } from 'react'
import TeamChat from './TeamChat'
import OrionLogo, { GotecLogo } from './OrionLogo'
import TeacherDeck from './TeacherDeck'
import MissionBriefing, { DomainChips } from './MissionBriefing'
import { getBriefing, ROUTE } from '../data/orionBriefings'

const API = import.meta.env.VITE_API_URL ?? 'http://127.0.0.1:8000'
const glass = { background: 'rgba(26,31,19,0.6)', border: '1px solid rgba(255,255,255,0.07)', borderRadius: 12 }
const GOLD = '#d4bd55'

interface Reto { id: number; title: string; description: string; objective: string; criteria: string; difficulty: string; status: string; stage: string; dataset_name?: string; unlocked?: number }
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
  const [deck, setDeck]     = useState<{ id?: number; title?: string; criteria?: string } | null>(null)
  const headers = { Authorization: `Bearer ${token}` }

  useEffect(() => { if (!teamId && def) setTeamId(def.id) }, [def, teamId])

  const load = useCallback(async () => {
    if (!teamId) return
    const r = await fetch(`${API}/admin/teams/${teamId}/overview`, { headers })
    if (r.ok) { setData(await r.json()); setError('') } else setError('No se pudo cargar el grupo')
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [teamId, token])

  useEffect(() => { load() }, [load])

  const setUnlocked = async (challengeId: number, unlocked: boolean) => {
    await fetch(`${API}/admin/teams/${teamId}/challenges/${challengeId}/unlock`, {
      method: 'PATCH', headers: { ...headers, 'Content-Type': 'application/json' }, body: JSON.stringify({ unlocked }),
    })
    load()
  }

  // Orden de la ruta táctica (fases I→IV) cuando el grupo usa los retos ORION; si no, por id.
  const routeOrder = ROUTE.flatMap(r => r.ids)
  const orderedRetos = data ? [...data.retos].sort((a, b) => {
    const ia = routeOrder.indexOf(a.id), ib = routeOrder.indexOf(b.id)
    return (ia < 0 ? 99 + a.id : ia) - (ib < 0 ? 99 + b.id : ib)
  }) : []
  const unlockedCount = orderedRetos.filter(r => r.unlocked !== 0).length

  const toggle = async (what: 'chat' | 'signup', value: boolean) => {
    const url = what === 'chat' ? `${API}/admin/teams/${teamId}/chat-enabled` : `${API}/admin/teams/${teamId}/open-signup`
    await fetch(url, { method: 'PATCH', headers: { ...headers, 'Content-Type': 'application/json' },
                       body: JSON.stringify(what === 'chat' ? { enabled: value } : { open: value }) })
    load()
  }

  const deckView = deck && <TeacherDeck retoId={deck.id} title={deck.title} criteria={deck.criteria} onClose={() => setDeck(null)} />

  if (!teams.length) return <p className="text-sm text-slate-500">No hay grupos creados.</p>

  return (
    <div className="space-y-5">
      {deckView}
      <div className="flex flex-wrap items-center gap-3">
        <GotecLogo height={36} />
        <OrionLogo size={44} />
        <div>
          <h2 className="text-lg font-bold text-slate-100">Grupo {data?.name ?? ''}</h2>
          <p className="text-[10px] tracking-[0.2em] font-bold" style={{ color: GOLD }}>ENTRENAMIENTO TÁCTICO CTI · CCOCI</p>
        </div>
        <select value={teamId} onChange={e => setTeamId(Number(e.target.value))}
                className="rounded-lg px-3 py-1.5 text-xs text-slate-200"
                style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.1)' }}>
          {teams.map(t => <option key={t.id} value={t.id}>{t.name}</option>)}
        </select>
        {data && (
          <div className="flex gap-2 ml-auto">
            <button onClick={() => setDeck({})} className="rounded-lg px-3 py-1.5 text-[11px] font-semibold"
                    style={{ background: 'rgba(212,189,85,0.15)', border: '1px solid rgba(212,189,85,0.45)', color: '#e0cf74' }}>
              🎓 Presentación del programa
            </button>
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
                Retos del grupo · {unlockedCount}/{data.retos.length} habilitados
              </p>
              <p className="text-[10px] text-slate-500">Los integrantes solo pueden abrir los retos habilitados. Usa 🔒/🔓 para habilitarlos cuando corresponda.</p>
              {data.retos.length === 0 && <p className="text-xs text-slate-500">Este grupo no tiene retos propios asignados.</p>}
              {orderedRetos.map(r => {
                const st = STATUS[r.status] ?? { label: r.status, color: '#a3a27c' }
                const done = data.members.filter(m => m.progress[String(r.id)]?.submitted).length
                return (
                  <div key={r.id} className="rounded-lg" style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)' }}>
                    <button onClick={() => setOpen(open === r.id ? null : r.id)} className="w-full flex items-center gap-3 px-3 py-2 text-left">
                      <span className="w-6 text-[11px] font-mono" style={{ color: GOLD }}>{String(r.id).padStart(2, '0')}</span>
                      <span className="flex-1 min-w-0 space-y-1">
                        <span className="block text-xs text-slate-200">{r.title}</span>
                        {getBriefing(r.id) && <DomainChips id={r.id} />}
                      </span>
                      <span className="text-[10px] text-slate-500">{r.difficulty}</span>
                      <span className="text-[10px]" style={{ color: st.color }}>{st.label}</span>
                      <span className="text-[10px] text-slate-500">{done}/{data.members.length} entregas</span>
                    </button>
                    <div className="px-3 pb-2 -mt-1 flex justify-end">
                      <button onClick={() => setUnlocked(r.id, r.unlocked === 0)}
                              className="rounded-md px-2.5 py-1 text-[10px] font-semibold"
                              style={r.unlocked === 0
                                ? { color: '#f87171', border: '1px solid rgba(248,113,113,0.4)', background: 'rgba(248,113,113,0.06)' }
                                : { color: '#4ade80', border: '1px solid rgba(74,222,128,0.4)', background: 'rgba(74,222,128,0.06)' }}>
                        {r.unlocked === 0 ? '🔒 Bloqueado · clic para habilitar' : '🔓 Habilitado · clic para bloquear'}
                      </button>
                    </div>
                    {open === r.id && (
                      <div className="px-4 pb-3 space-y-3 text-xs text-slate-400 whitespace-pre-wrap">
                        {getBriefing(r.id) && (
                          <MissionBriefing id={r.id} onTeacherDeck={() => setDeck({ id: r.id, title: r.title, criteria: r.criteria })} />
                        )}
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
                        {orderedRetos.map(r => <th key={r.id} title={r.title} className="font-mono font-medium px-1">{String(r.id).padStart(2, '0')}{r.unlocked === 0 ? '🔒' : ''}</th>)}
                      </tr>
                    </thead>
                    <tbody>
                      {data.members.map(m => (
                        <tr key={m.email} className="border-t" style={{ borderColor: 'rgba(255,255,255,0.05)' }}>
                          <td className="py-1.5 pr-3">
                            <p className="text-slate-200">{m.name}</p>
                            <p className="text-[10px] text-slate-600">{m.email}</p>
                          </td>
                          {orderedRetos.map(r => {
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

import { useState } from 'react'
import { BRIEFINGS, DOMAINS, METHODS, PHASES } from '../data/orionBriefings'
import OrionLogo, { GotecLogo } from './OrionLogo'

const GOLD = '#d4bd55'
const box = { background: 'rgba(26,31,19,0.6)', border: '1px solid rgba(212,189,85,0.22)', borderRadius: 12 }

/** Etiquetas compactas de dominio para las tarjetas de la lista de retos. */
export function DomainChips({ id }: { id: number }) {
  const b = BRIEFINGS[id]
  if (!b) return null
  return (
    <div className="flex flex-wrap gap-1">
      {b.domains.map(d => (
        <span key={d} className="text-[9px] font-semibold px-1.5 py-0.5 rounded"
              style={{ color: DOMAINS[d].color, border: `1px solid ${DOMAINS[d].color}55`, background: `${DOMAINS[d].color}12` }}>
          {DOMAINS[d].icon} {DOMAINS[d].label}
        </span>
      ))}
    </div>
  )
}

/** Ficha táctica del reto: dominio, metodologías, actores, PIR y dossier del dataset. */
export default function MissionBriefing({ id, onTeacherDeck, deckLabel = '🎓 Presentación docente' }:
  { id: number; onTeacherDeck?: () => void; deckLabel?: string }) {
  const b = BRIEFINGS[id]
  const [tab, setTab] = useState<'mision' | 'metodo' | 'dataset'>('mision')
  if (!b) return null

  return (
    <div className="p-4 space-y-3" style={box}>
      <div className="flex items-center gap-3 flex-wrap">
        <OrionLogo size={36} />
        <div className="flex-1 min-w-0">
          <p className="text-[10px] font-mono tracking-widest" style={{ color: GOLD }}>
            {b.codename} · {PHASES[b.phase].name.toUpperCase()}
          </p>
          <DomainChips id={id} />
        </div>
        <GotecLogo height={22} />
        {onTeacherDeck && (
          <button onClick={onTeacherDeck} className="rounded-lg px-3 py-1.5 text-[11px] font-semibold"
                  style={{ background: 'rgba(212,189,85,0.15)', border: '1px solid rgba(212,189,85,0.45)', color: '#e0cf74' }}>
            {deckLabel}
          </button>
        )}
      </div>

      <div className="flex gap-1 border-b" style={{ borderColor: 'rgba(212,189,85,0.15)' }}>
        {([['mision', '🎯 Misión'], ['metodo', '🧭 Metodología'], ['dataset', '🗂️ Dossier del dataset']] as const).map(([k, l]) => (
          <button key={k} onClick={() => setTab(k)} className="px-3 py-1.5 text-[11px] font-semibold -mb-px"
                  style={{ color: tab === k ? GOLD : '#7f8360', borderBottom: `2px solid ${tab === k ? GOLD : 'transparent'}` }}>
            {l}
          </button>
        ))}
      </div>

      {tab === 'mision' && (
        <div className="grid gap-3 md:grid-cols-2 text-xs">
          <div className="md:col-span-2 rounded-lg p-3" style={{ background: 'rgba(212,189,85,0.07)', borderLeft: `3px solid ${GOLD}` }}>
            <p className="text-[9px] font-bold uppercase tracking-wider mb-1" style={{ color: GOLD }}>Situación</p>
            <p className="text-slate-300 leading-relaxed">{b.scenario}</p>
          </div>
          <div className="rounded-lg p-3" style={{ background: 'rgba(255,255,255,0.03)' }}>
            <p className="text-[9px] font-bold uppercase tracking-wider mb-1 text-cyan-600">Requerimiento (PIR)</p>
            <p className="text-slate-200 font-medium">{b.pir}</p>
            <p className="text-[9px] font-bold uppercase tracking-wider mt-3 mb-1 text-cyan-600">Producto esperado</p>
            <p className="text-slate-400">{b.product}</p>
          </div>
          <div className="rounded-lg p-3" style={{ background: 'rgba(249,115,22,0.05)', border: '1px solid rgba(249,115,22,0.18)' }}>
            <p className="text-[9px] font-bold uppercase tracking-wider mb-2" style={{ color: '#f97316' }}>🎯 Actores y amenazas en el objetivo</p>
            <div className="flex flex-wrap gap-1.5">
              {b.actors.map(a => (
                <span key={a} className="text-[10px] px-2 py-0.5 rounded-full text-slate-200"
                      style={{ background: 'rgba(249,115,22,0.1)', border: '1px solid rgba(249,115,22,0.3)' }}>{a}</span>
              ))}
            </div>
          </div>
        </div>
      )}

      {tab === 'metodo' && (
        <div className="grid gap-2 md:grid-cols-2">
          {b.methods.map(m => METHODS[m] && (
            <div key={m} className="rounded-lg p-3 text-xs" style={{ background: 'rgba(147,169,84,0.06)', border: '1px solid rgba(147,169,84,0.2)' }}>
              <p className="font-bold text-slate-100">{METHODS[m].name}</p>
              <p className="text-[10px] font-mono mt-0.5" style={{ color: '#aec174' }}>{METHODS[m].short}</p>
              <p className="text-slate-400 mt-1.5 leading-relaxed">{METHODS[m].detail}</p>
            </div>
          ))}
        </div>
      )}

      {tab === 'dataset' && (
        <div className="space-y-3 text-xs">
          <div className="flex flex-wrap gap-4 text-[11px]">
            <span className="text-slate-500">Origen: <span className="text-slate-300">{b.dataset.origin}</span></span>
            <span className="text-slate-500">Registros: <span className="text-slate-300">{b.dataset.rows}</span></span>
            <span className="text-slate-500">Cada fila es: <span className="text-slate-300">{b.dataset.grain}</span></span>
          </div>
          <div className="overflow-x-auto rounded-lg" style={{ border: '1px solid rgba(255,255,255,0.06)' }}>
            <table className="w-full text-[11px]">
              <thead><tr style={{ background: 'rgba(212,189,85,0.08)' }}>
                <th className="text-left px-3 py-1.5 font-semibold" style={{ color: GOLD }}>Columna</th>
                <th className="text-left px-3 py-1.5 font-semibold" style={{ color: GOLD }}>Qué significa para el analista</th>
              </tr></thead>
              <tbody>
                {Object.entries(b.dataset.columns).map(([k, v]) => (
                  <tr key={k} className="border-t" style={{ borderColor: 'rgba(255,255,255,0.05)' }}>
                    <td className="px-3 py-1.5 font-mono text-cyan-300 whitespace-nowrap align-top">{k}</td>
                    <td className="px-3 py-1.5 text-slate-400">{v}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="grid gap-3 md:grid-cols-2">
            <div className="rounded-lg p-3" style={{ background: 'rgba(74,222,128,0.05)', border: '1px solid rgba(74,222,128,0.18)' }}>
              <p className="text-[9px] font-bold uppercase tracking-wider mb-1.5 text-green-400">🔎 Qué buscar</p>
              <ul className="space-y-1 text-slate-300 list-disc pl-4">{b.dataset.lookFor.map(x => <li key={x}>{x}</li>)}</ul>
            </div>
            <div className="rounded-lg p-3" style={{ background: 'rgba(250,204,21,0.05)', border: '1px solid rgba(250,204,21,0.2)' }}>
              <p className="text-[9px] font-bold uppercase tracking-wider mb-1.5 text-yellow-400">⚠ Trampas del dataset</p>
              <ul className="space-y-1 text-slate-300 list-disc pl-4">{b.dataset.pitfalls.map(x => <li key={x}>{x}</li>)}</ul>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

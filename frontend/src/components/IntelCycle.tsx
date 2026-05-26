import { useEffect, useState } from 'react'

const API_URL = import.meta.env.VITE_API_URL ?? 'http://127.0.0.1:8000'

interface Campaign {
  name: string
  actor: string
  status: string
  kill_chain_phase: string
  ioc_count: number
  confirmed_victims: number
}

const PHASES = [
  {
    id: 1,
    label: 'DIRECCIÓN',
    sublabel: 'Definir RFI / PIR',
    description: 'Definir requerimientos de inteligencia (RFI/PIR). ¿Qué necesitamos saber y para quién?',
    color: '#22c55e',
    textColor: 'text-green-400',
    borderColor: 'border-green-600',
    bg: 'bg-green-950/40',
  },
  {
    id: 2,
    label: 'RECOLECCIÓN',
    sublabel: 'OSINT · feeds · sandboxes',
    description: 'Recolección de datos desde OSINT, threat feeds, sandboxes, honeypots y dark web.',
    color: '#06b6d4',
    textColor: 'text-cyan-400',
    borderColor: 'border-cyan-600',
    bg: 'bg-cyan-950/40',
  },
  {
    id: 3,
    label: 'PROCESAMIENTO',
    sublabel: 'Normalización · enriquecimiento',
    description: 'Normalización, deduplicación y enriquecimiento de IOCs. Structuring raw data.',
    color: '#a855f7',
    textColor: 'text-purple-400',
    borderColor: 'border-purple-600',
    bg: 'bg-purple-950/40',
  },
  {
    id: 4,
    label: 'ANÁLISIS',
    sublabel: 'Correlación · ATT&CK mapping',
    description: 'Correlación de indicadores, mapeo a MITRE ATT&CK y producción de informes.',
    color: '#ef4444',
    textColor: 'text-red-400',
    borderColor: 'border-red-600',
    bg: 'bg-red-950/40',
  },
  {
    id: 5,
    label: 'DIFUSIÓN',
    sublabel: 'TLP · STIX/TAXII · informes',
    description: 'Distribución de inteligencia via TLP, STIX/TAXII, informes ejecutivos y técnicos.',
    color: '#f97316',
    textColor: 'text-orange-400',
    borderColor: 'border-orange-600',
    bg: 'bg-orange-950/40',
  },
]

function killChainToPhase(killChainPhase: string): number {
  const map: Record<string, number> = {
    'Reconnaissance': 2,
    'Weaponization': 2,
    'Delivery': 2,
    'Exploitation': 3,
    'Installation': 3,
    'Command & Control': 3,
    'Credential Access': 4,
    'Exfiltration': 4,
    'Impact': 5,
  }
  return map[killChainPhase] ?? 3
}

function IntelCycle() {
  const [campaigns, setCampaigns] = useState<Campaign[]>([])
  const [activePhase, setActivePhase] = useState<number | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetch(`${API_URL}/campaigns`)
      .then(r => r.json())
      .then(setCampaigns)
      .finally(() => setLoading(false))
  }, [])

  const campaignsByPhase = (phaseId: number) =>
    campaigns.filter(c => killChainToPhase(c.kill_chain_phase) === phaseId)

  if (loading) return <div className="text-slate-400 text-sm p-4 animate-pulse">Cargando ciclo CTI...</div>

  return (
    <div className="bg-slate-900 rounded-xl p-6 border border-slate-800">
      <div className="mb-5">
        <h2 className="text-xl font-bold">Ciclo CTI</h2>
        <p className="text-slate-500 text-xs mt-0.5">
          Proceso continuo e iterativo de 5 fases · campañas activas mapeadas por fase
        </p>
      </div>

      <div className="grid grid-cols-5 gap-2 mb-4">
        {PHASES.map((phase, idx) => {
          const phaseCampaigns = campaignsByPhase(phase.id)
          const isActive = activePhase === phase.id
          return (
            <button
              key={phase.id}
              onClick={() => setActivePhase(isActive ? null : phase.id)}
              className={`rounded-xl p-4 border text-left transition-all hover:brightness-110 ${
                isActive ? `${phase.bg} ${phase.borderColor}` : 'bg-slate-800 border-slate-700'
              }`}
            >
              <div className="flex items-center justify-between mb-2">
                <span
                  className="text-2xl font-black"
                  style={{ color: phase.color, opacity: isActive ? 1 : 0.5 }}
                >
                  {String(idx + 1).padStart(2, '0')}
                </span>
                {phaseCampaigns.length > 0 && (
                  <span
                    className="text-xs font-bold px-1.5 py-0.5 rounded-full"
                    style={{ backgroundColor: phase.color + '33', color: phase.color }}
                  >
                    {phaseCampaigns.length}
                  </span>
                )}
              </div>
              <p className={`text-xs font-bold uppercase tracking-wider ${isActive ? phase.textColor : 'text-slate-400'}`}>
                {phase.label}
              </p>
              <p className="text-slate-600 text-[10px] mt-0.5 leading-tight">{phase.sublabel}</p>
            </button>
          )
        })}
      </div>

      {/* Connector arrows */}
      <div className="flex items-center justify-center gap-1 mb-4 px-4">
        {PHASES.map((phase, idx) => (
          <div key={phase.id} className="flex items-center flex-1">
            <div className="h-0.5 flex-1" style={{ backgroundColor: phase.color + '60' }} />
            {idx < PHASES.length - 1 && (
              <div className="text-slate-600 text-xs mx-1">→</div>
            )}
          </div>
        ))}
        <div className="text-slate-500 text-xs ml-2">↺</div>
      </div>

      {/* Phase detail */}
      {activePhase && (() => {
        const phase = PHASES[activePhase - 1]
        const phaseCampaigns = campaignsByPhase(activePhase)
        return (
          <div className={`rounded-xl border p-5 ${phase.bg} ${phase.borderColor}`}>
            <div className="flex items-start justify-between mb-3">
              <div>
                <p className={`text-xs font-bold uppercase tracking-widest ${phase.textColor} mb-1`}>
                  Fase {activePhase}
                </p>
                <h3 className="text-white font-bold text-lg">{phase.label}</h3>
                <p className="text-slate-300 text-sm mt-1">{phase.description}</p>
              </div>
              {phaseCampaigns.length > 0 && (
                <span className={`text-xs font-bold px-2 py-1 rounded ${phase.textColor} bg-black/30`}>
                  {phaseCampaigns.length} campaña{phaseCampaigns.length > 1 ? 's' : ''} activa{phaseCampaigns.length > 1 ? 's' : ''}
                </span>
              )}
            </div>

            {phaseCampaigns.length > 0 ? (
              <div className="space-y-2 mt-3">
                <p className="text-slate-500 text-xs uppercase tracking-wider">Campañas en esta fase</p>
                {phaseCampaigns.map(c => (
                  <div
                    key={c.name}
                    className="bg-black/30 rounded-lg px-4 py-3 flex items-center justify-between"
                  >
                    <div>
                      <p className="text-white font-semibold text-sm">{c.name}</p>
                      <p className="text-slate-400 text-xs">
                        {c.actor} · fase operacional: <span className="text-orange-400">{c.kill_chain_phase}</span>
                      </p>
                    </div>
                    <div className="flex gap-3 text-right">
                      <div>
                        <p className="text-white font-bold">{c.ioc_count}</p>
                        <p className="text-slate-500 text-[10px]">IOCs</p>
                      </div>
                      <div>
                        <p className="text-white font-bold">{c.confirmed_victims}</p>
                        <p className="text-slate-500 text-[10px]">Víctimas</p>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-slate-600 text-sm mt-3 italic">
                Sin campañas activas en esta fase del ciclo.
              </p>
            )}
          </div>
        )
      })()}
    </div>
  )
}

export default IntelCycle

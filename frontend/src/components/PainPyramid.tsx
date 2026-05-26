import { useEffect, useState } from 'react'

const API_URL = import.meta.env.VITE_API_URL ?? 'http://127.0.0.1:8000'

interface IOC { id: number; ioc: string; type: string; threat_actor: string; severity: string; mitre: string }
interface Actor { name: string; malware: string[]; ttps: string[] }

interface PyramidLevel {
  level: number
  label: string
  sublabel: string
  difficulty: string
  difficultyColor: string
  color: string
  borderColor: string
  items: string[]
  description: string
}

function buildPyramid(iocs: IOC[], actors: Actor[]): PyramidLevel[] {
  const hashes  = iocs.filter(i => i.type === 'HASH').map(i => i.ioc)
  const ips     = iocs.filter(i => i.type === 'IP').map(i => i.ioc)
  const domains = iocs.filter(i => i.type === 'DOMAIN').map(i => i.ioc)
  const tools   = [...new Set(actors.flatMap(a => a.malware))]
  const ttps    = [...new Set(actors.flatMap(a => a.ttps))]

  const hostArtifacts = [
    'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\ShadowSvc',
    'C:\\ProgramData\\ShadowLoader\\config.dat',
    'Mutex: Global\\NightBeacon_v2',
    'C:\\Users\\Public\\LynxStealer.dll',
    'HKLM\\SYSTEM\\CurrentControlSet\\Services\\LockBitSvc',
  ]

  return [
    {
      level: 5,
      label: 'TTPs',
      sublabel: 'Tactics, Techniques & Procedures',
      difficulty: 'DURO',
      difficultyColor: 'text-red-400',
      color: 'bg-red-950/60',
      borderColor: 'border-red-600',
      items: ttps,
      description: 'Obliga al atacante a reinventar su arquitectura operacional completa. Mayor impacto y mayor costo de defensa.',
    },
    {
      level: 4,
      label: 'Herramientas',
      sublabel: 'Malware & Tooling',
      difficulty: 'DIFÍCIL',
      difficultyColor: 'text-orange-400',
      color: 'bg-orange-950/60',
      borderColor: 'border-orange-600',
      items: tools,
      description: 'Cambiar herramientas requiere reentrenamiento del operador y redefinir la cadena de C2.',
    },
    {
      level: 3,
      label: 'Host Artifacts',
      sublabel: 'Registry / Files / Mutex',
      difficulty: 'MOLESTO',
      difficultyColor: 'text-yellow-400',
      color: 'bg-yellow-950/40',
      borderColor: 'border-yellow-600',
      items: hostArtifacts,
      description: 'Modificar artefactos en disco y registry keys requiere reempaquetar el implante.',
    },
    {
      level: 2,
      label: 'Dominios / IPs',
      sublabel: 'Network Infrastructure',
      difficulty: 'SIMPLE',
      difficultyColor: 'text-blue-400',
      color: 'bg-blue-950/40',
      borderColor: 'border-blue-600',
      items: [...ips, ...domains],
      description: 'Rotar infraestructura de red tarda minutos. El atacante puede obtener nuevas IPs/dominios casi instantáneamente.',
    },
    {
      level: 1,
      label: 'Hashes',
      sublabel: 'File Hashes (MD5 / SHA256)',
      difficulty: 'TRIVIAL',
      difficultyColor: 'text-green-400',
      color: 'bg-green-950/30',
      borderColor: 'border-green-700',
      items: hashes,
      description: 'Recompilar o mutar el binario en segundos invalida el hash. El IOC menos valioso operacionalmente.',
    },
  ]
}

function PainPyramid() {
  const [iocs, setIocs]       = useState<IOC[]>([])
  const [actors, setActors]   = useState<Actor[]>([])
  const [expanded, setExpanded] = useState<number | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    Promise.all([
      fetch(`${API_URL}/ioc-feed`).then(r => r.json()),
      fetch(`${API_URL}/threat-actors`).then(r => r.json()),
    ]).then(([i, a]) => { setIocs(i); setActors(a) })
      .finally(() => setLoading(false))
  }, [])

  if (loading) return <div className="text-slate-400 text-sm p-4 animate-pulse">Construyendo pirámide...</div>

  const levels = buildPyramid(iocs, actors)

  const WIDTHS = ['100%', '82%', '64%', '46%', '28%']

  return (
    <div className="bg-slate-900 rounded-xl p-6 border border-slate-800">
      <div className="mb-5">
        <h2 className="text-xl font-bold">Pirámide del Dolor</h2>
        <p className="text-slate-500 text-xs mt-0.5">Cuanto más alto, mayor impacto en el atacante al bloquear el indicador</p>
      </div>

      <div className="flex flex-col items-center gap-1 mb-4">
        {[...levels].reverse().map((lvl, idx) => {
          const isOpen = expanded === lvl.level
          const width = WIDTHS[idx]
          return (
            <div key={lvl.level} className="w-full flex flex-col items-center">
              <button
                style={{ width }}
                onClick={() => setExpanded(isOpen ? null : lvl.level)}
                className={`border rounded-lg px-4 py-2.5 transition-all text-left ${lvl.color} ${lvl.borderColor} hover:brightness-110`}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <span className={`text-xs font-bold uppercase tracking-widest ${lvl.difficultyColor}`}>
                      {lvl.difficulty}
                    </span>
                    <span className="text-white font-semibold text-sm">{lvl.label}</span>
                    <span className="text-slate-500 text-xs hidden sm:block">{lvl.sublabel}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-slate-400 text-xs">{lvl.items.length} items</span>
                    <span className="text-slate-500 text-xs">{isOpen ? '▲' : '▼'}</span>
                  </div>
                </div>
              </button>

              {isOpen && (
                <div
                  className={`border-x border-b rounded-b-lg p-4 ${lvl.color} ${lvl.borderColor}`}
                  style={{ width }}
                >
                  <p className="text-slate-300 text-xs mb-3 leading-relaxed">{lvl.description}</p>
                  <div className="flex flex-wrap gap-1.5">
                    {lvl.items.map(item => (
                      <code
                        key={item}
                        className="bg-black/40 text-slate-200 text-xs px-2 py-0.5 rounded font-mono border border-slate-700"
                      >
                        {item.length > 40 ? item.slice(0, 38) + '…' : item}
                      </code>
                    ))}
                    {lvl.items.length === 0 && (
                      <span className="text-slate-600 text-xs italic">Sin indicadores registrados en este nivel</span>
                    )}
                  </div>
                </div>
              )}
            </div>
          )
        })}
      </div>

      <div className="flex items-center justify-center gap-6 pt-3 border-t border-slate-800">
        {[
          { label: 'TTPs', color: 'bg-red-500' },
          { label: 'Tools', color: 'bg-orange-500' },
          { label: 'Host Artifacts', color: 'bg-yellow-500' },
          { label: 'IPs / Domains', color: 'bg-blue-500' },
          { label: 'Hashes', color: 'bg-green-500' },
        ].map(({ label, color }) => (
          <div key={label} className="flex items-center gap-1.5">
            <div className={`w-2 h-2 rounded-full ${color}`} />
            <span className="text-slate-400 text-xs">{label}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

export default PainPyramid

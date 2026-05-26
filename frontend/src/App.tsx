import { useState, useEffect } from 'react'
import GlobalOverview  from './components/GlobalOverview'
import ThreatGraphView from './components/ThreatGraphView'
import AICopilot       from './components/AICopilot'
import ATTCKMatrix     from './components/ATTCKMatrix'
import ThreatTimeline  from './components/ThreatTimeline'
import IOCIOABoard     from './components/IOCIOABoard'
import IntelFeed       from './components/IntelFeed'

type ViewId = 'overview' | 'graph' | 'copilot' | 'attack' | 'timeline' | 'ioc' | 'feeds'

const NAV: { id: ViewId; label: string; tag?: string; icon: string }[] = [
  { id: 'overview',  label: 'Threat Overview',  icon: 'M3 3h7v7H3zM14 3h7v7h-7zM3 14h7v7H3zM14 14h7v7h-7z' },
  { id: 'graph',     label: 'Threat Graph',     icon: 'M12 5a2 2 0 1 0 0-4 2 2 0 0 0 0 4zM5 19a2 2 0 1 0 0-4 2 2 0 0 0 0 4zM19 19a2 2 0 1 0 0-4 2 2 0 0 0 0 4zM12 5l-5.5 9.5M12 5l5.5 9.5' },
  { id: 'copilot',   label: 'AI Copilot',        icon: 'M9 3H5a2 2 0 0 0-2 2v4m6-6h10a2 2 0 0 1 2 2v4M9 3v18m0 0h10a2 2 0 0 0 2-2V9M9 21H5a2 2 0 0 1-2-2V9m0 0h18', tag: 'AI' },
  { id: 'attack',    label: 'ATT&CK Matrix',    icon: 'M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z' },
  { id: 'timeline',  label: 'Timeline',         icon: 'M3 12h18M3 6h18M3 18h18' },
  { id: 'ioc',       label: 'IOC / IOA Board',  icon: 'M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z' },
  { id: 'feeds',     label: 'Intel Feeds',      icon: 'M4 11a9 9 0 0 1 9 9M4 4a16 16 0 0 1 16 16M5 20a1 1 0 1 0 0-2 1 1 0 0 0 0 2z' },
]

function NavIcon({ d }: { d: string }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"
         strokeLinecap="round" strokeLinejoin="round" className="w-4 h-4 shrink-0">
      <path d={d} />
    </svg>
  )
}

function Clock() {
  const [t, setT] = useState(new Date())
  useEffect(() => {
    const id = setInterval(() => setT(new Date()), 1000)
    return () => clearInterval(id)
  }, [])
  return (
    <span className="font-mono text-xs tabular-nums text-slate-500">
      {t.toLocaleTimeString('es-MX', { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
    </span>
  )
}

export default function App() {
  const [view, setView] = useState<ViewId>('overview')

  const renderView = () => {
    switch (view) {
      case 'overview':  return <GlobalOverview />
      case 'graph':     return <ThreatGraphView />
      case 'copilot':   return <AICopilot />
      case 'attack':    return <ATTCKMatrix />
      case 'timeline':  return <ThreatTimeline />
      case 'ioc':       return <IOCIOABoard />
      case 'feeds':     return <IntelFeed />
    }
  }

  return (
    <div className="flex h-screen text-white overflow-hidden" style={{ background: '#030712' }}>

      {/* ══ Sidebar ══════════════════════════════════════════════════════════ */}
      <aside className="w-56 shrink-0 flex flex-col border-r"
             style={{ background: 'rgba(8, 12, 25, 0.97)', borderColor: 'rgba(255,255,255,0.05)' }}>

        {/* brand */}
        <div className="h-14 flex items-center gap-3 px-4 border-b" style={{ borderColor: 'rgba(255,255,255,0.05)' }}>
          <div className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0"
               style={{ background: 'rgba(34,211,238,0.12)', boxShadow: '0 0 16px rgba(34,211,238,0.25)' }}>
            <svg viewBox="0 0 24 24" className="w-4 h-4 text-cyan-400" fill="none"
                 stroke="currentColor" strokeWidth="2">
              <polygon points="12 2 2 7 12 12 22 7 12 2" />
              <polyline points="2 17 12 22 22 17" />
              <polyline points="2 12 12 17 22 12" />
            </svg>
          </div>
          <div className="min-w-0">
            <p className="text-sm font-bold text-white leading-none">CTI Nexus</p>
            <p className="text-[9px] font-mono text-slate-600 tracking-widest mt-0.5">INTELLIGENCE OS</p>
          </div>
        </div>

        {/* nav */}
        <nav className="flex-1 px-2 py-3 space-y-0.5 overflow-y-auto">
          <p className="text-[9px] font-bold text-slate-700 tracking-widest px-3 py-2 uppercase">Plataforma</p>
          {NAV.map(item => {
            const active = view === item.id
            return (
              <button key={item.id} onClick={() => setView(item.id)}
                      className="w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-xs transition-all group"
                      style={active ? {
                        background: 'rgba(34,211,238,0.08)',
                        borderLeft: '2px solid #22d3ee',
                        paddingLeft: '10px',
                        color: '#22d3ee',
                      } : {
                        color: '#475569',
                        borderLeft: '2px solid transparent',
                      }}>
                <span className={active ? 'text-cyan-400' : 'text-slate-700 group-hover:text-slate-500'}>
                  <NavIcon d={item.icon} />
                </span>
                <span className={`font-medium truncate ${active ? '' : 'group-hover:text-slate-300'}`}>
                  {item.label}
                </span>
                {item.tag && (
                  <span className="ml-auto text-[9px] font-bold px-1.5 py-0.5 rounded shrink-0"
                        style={{ background: 'rgba(167,139,250,0.15)', color: '#a78bfa' }}>
                    {item.tag}
                  </span>
                )}
              </button>
            )
          })}
        </nav>

        {/* status */}
        <div className="px-4 py-3 border-t space-y-2" style={{ borderColor: 'rgba(255,255,255,0.05)' }}>
          <div className="flex items-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-green-400 shrink-0 animate-pulse"
                  style={{ boxShadow: '0 0 6px #4ade80' }} />
            <span className="text-xs text-slate-500">Operativo · 3 fuentes</span>
          </div>
          <p className="text-[9px] font-mono text-slate-700">v3.0 · CTI Nexus Platform</p>
        </div>
      </aside>

      {/* ══ Main ═════════════════════════════════════════════════════════════ */}
      <div className="flex-1 flex flex-col overflow-hidden min-w-0">

        {/* top bar */}
        <header className="h-14 flex items-center justify-between px-6 border-b shrink-0"
                style={{ background: 'rgba(8,12,25,0.85)', backdropFilter: 'blur(20px)', borderColor: 'rgba(255,255,255,0.05)' }}>
          <div>
            <p className="text-sm font-semibold text-slate-200">
              {NAV.find(n => n.id === view)?.label}
            </p>
            <p className="text-[10px] text-slate-600 font-mono">CTI Nexus · Enterprise Cyber Intelligence</p>
          </div>
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2 rounded-lg border px-3 py-1.5 text-xs text-slate-500"
                 style={{ background: 'rgba(255,255,255,0.03)', borderColor: 'rgba(255,255,255,0.06)' }}>
              <svg viewBox="0 0 24 24" className="w-3.5 h-3.5" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="11" cy="11" r="8" /><path d="m21 21-4.35-4.35" />
              </svg>
              <span>Buscar IOC, actor, TTP...</span>
            </div>
            <button className="relative p-2 rounded-lg border"
                    style={{ background: 'rgba(255,255,255,0.03)', borderColor: 'rgba(255,255,255,0.06)' }}>
              <svg viewBox="0 0 24 24" className="w-4 h-4 text-slate-500" fill="none" stroke="currentColor" strokeWidth="1.5">
                <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9" />
                <path d="M13.73 21a2 2 0 0 1-3.46 0" />
              </svg>
              <span className="absolute top-1 right-1 w-1.5 h-1.5 bg-red-500 rounded-full" />
            </button>
            <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg border text-xs"
                 style={{ background: 'rgba(74,222,128,0.06)', borderColor: 'rgba(74,222,128,0.2)', color: '#4ade80' }}>
              <span className="w-1.5 h-1.5 bg-green-400 rounded-full animate-pulse" />
              Live
            </div>
            <Clock />
          </div>
        </header>

        {/* content */}
        <main className="flex-1 overflow-y-auto p-5">
          {renderView()}
        </main>
      </div>
    </div>
  )
}

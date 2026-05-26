import { useState } from 'react'

const glass = {
  background: 'rgba(15,23,42,0.55)',
  backdropFilter: 'blur(16px)',
  border: '1px solid rgba(255,255,255,0.07)',
  borderRadius: 12,
}

interface Technique {
  id: string
  name: string
  active?: boolean
  severity?: 'critical' | 'high' | 'medium' | 'low'
}

interface Tactic {
  id: string
  name: string
  color: string
  techniques: Technique[]
}

const TACTICS: Tactic[] = [
  { id: 'TA0001', name: 'Initial Access', color: '#ef4444', techniques: [
    { id: 'T1566', name: 'Phishing', active: true, severity: 'critical' },
    { id: 'T1190', name: 'Exploit Public App', active: true, severity: 'high' },
    { id: 'T1133', name: 'External Remote Services' },
    { id: 'T1078', name: 'Valid Accounts', active: true, severity: 'high' },
    { id: 'T1195', name: 'Supply Chain' },
  ]},
  { id: 'TA0002', name: 'Execution', color: '#f97316', techniques: [
    { id: 'T1059', name: 'Command & Scripting', active: true, severity: 'critical' },
    { id: 'T1203', name: 'Exploit Client Exec' },
    { id: 'T1569', name: 'System Services', active: true, severity: 'medium' },
    { id: 'T1106', name: 'Native API' },
    { id: 'T1047', name: 'WMI', active: true, severity: 'high' },
  ]},
  { id: 'TA0003', name: 'Persistence', color: '#facc15', techniques: [
    { id: 'T1053', name: 'Scheduled Task', active: true, severity: 'high' },
    { id: 'T1547', name: 'Boot Autostart' },
    { id: 'T1098', name: 'Account Manipulation', active: true, severity: 'medium' },
    { id: 'T1136', name: 'Create Account' },
    { id: 'T1505', name: 'Server Software' },
  ]},
  { id: 'TA0004', name: 'Privilege Escalation', color: '#fb923c', techniques: [
    { id: 'T1055', name: 'Process Injection', active: true, severity: 'critical' },
    { id: 'T1068', name: 'Exploit Vuln', active: true, severity: 'high' },
    { id: 'T1134', name: 'Access Token Manip' },
    { id: 'T1548', name: 'Abuse Elevation' },
    { id: 'T1611', name: 'Escape to Host' },
  ]},
  { id: 'TA0005', name: 'Defense Evasion', color: '#a3e635', techniques: [
    { id: 'T1036', name: 'Masquerading', active: true, severity: 'medium' },
    { id: 'T1562', name: 'Impair Defenses', active: true, severity: 'high' },
    { id: 'T1070', name: 'Indicator Removal', active: true, severity: 'critical' },
    { id: 'T1027', name: 'Obfuscation' },
    { id: 'T1553', name: 'Subvert Trust Ctrl' },
  ]},
  { id: 'TA0006', name: 'Credential Access', color: '#34d399', techniques: [
    { id: 'T1003', name: 'OS Cred Dumping', active: true, severity: 'critical' },
    { id: 'T1110', name: 'Brute Force', active: true, severity: 'high' },
    { id: 'T1555', name: 'Cred from Stores' },
    { id: 'T1056', name: 'Input Capture' },
    { id: 'T1558', name: 'Steal Kerberos Ticket', active: true, severity: 'high' },
  ]},
  { id: 'TA0007', name: 'Discovery', color: '#22d3ee', techniques: [
    { id: 'T1087', name: 'Account Discovery' },
    { id: 'T1083', name: 'File Discovery', active: true, severity: 'low' },
    { id: 'T1046', name: 'Network Scan', active: true, severity: 'medium' },
    { id: 'T1018', name: 'Remote System Disc' },
    { id: 'T1082', name: 'System Info Disc', active: true, severity: 'low' },
  ]},
  { id: 'TA0008', name: 'Lateral Movement', color: '#818cf8', techniques: [
    { id: 'T1021', name: 'Remote Services', active: true, severity: 'high' },
    { id: 'T1550', name: 'Use Alt Auth Material', active: true, severity: 'critical' },
    { id: 'T1534', name: 'Internal Spearphish' },
    { id: 'T1563', name: 'Remote Hijacking' },
    { id: 'T1570', name: 'Lateral Tool Transfer' },
  ]},
  { id: 'TA0009', name: 'Collection', color: '#c084fc', techniques: [
    { id: 'T1560', name: 'Archive Collected' },
    { id: 'T1213', name: 'Data from Info Repos', active: true, severity: 'medium' },
    { id: 'T1005', name: 'Data from Local', active: true, severity: 'high' },
    { id: 'T1114', name: 'Email Collection' },
    { id: 'T1557', name: 'Adversary-in-Middle', active: true, severity: 'high' },
  ]},
  { id: 'TA0010', name: 'Exfiltration', color: '#f472b6', techniques: [
    { id: 'T1041', name: 'Exfil over C2', active: true, severity: 'critical' },
    { id: 'T1048', name: 'Exfil Alt Protocol', active: true, severity: 'high' },
    { id: 'T1567', name: 'Exfil to Web Svc' },
    { id: 'T1030', name: 'Data Transfer Limits' },
    { id: 'T1020', name: 'Automated Exfil' },
  ]},
  { id: 'TA0011', name: 'Command & Control', color: '#fb7185', techniques: [
    { id: 'T1071', name: 'App Layer Protocol', active: true, severity: 'high' },
    { id: 'T1573', name: 'Encrypted Channel', active: true, severity: 'high' },
    { id: 'T1095', name: 'Non-App Layer Proto' },
    { id: 'T1572', name: 'Protocol Tunneling', active: true, severity: 'medium' },
    { id: 'T1105', name: 'Ingress Tool Transfer' },
  ]},
  { id: 'TA0040', name: 'Impact', color: '#fbbf24', techniques: [
    { id: 'T1486', name: 'Data Encrypted', active: true, severity: 'critical' },
    { id: 'T1489', name: 'Service Stop', active: true, severity: 'high' },
    { id: 'T1565', name: 'Data Manipulation' },
    { id: 'T1491', name: 'Defacement' },
    { id: 'T1498', name: 'DDoS' },
  ]},
]

const SEVERITY_STYLE: Record<string, { bg: string; border: string; text: string }> = {
  critical: { bg: 'rgba(239,68,68,0.2)',  border: 'rgba(239,68,68,0.5)',  text: '#ef4444' },
  high:     { bg: 'rgba(249,115,22,0.2)', border: 'rgba(249,115,22,0.5)', text: '#f97316' },
  medium:   { bg: 'rgba(250,204,21,0.15)',border: 'rgba(250,204,21,0.4)', text: '#facc15' },
  low:      { bg: 'rgba(74,222,128,0.1)', border: 'rgba(74,222,128,0.3)', text: '#4ade80' },
}

export default function ATTCKMatrix() {
  const [selected, setSelected] = useState<Technique | null>(null)
  const [hoveredTactic, setHoveredTactic] = useState<string | null>(null)

  const activeCount = TACTICS.flatMap(t => t.techniques).filter(t => t.active).length
  const criticalCount = TACTICS.flatMap(t => t.techniques).filter(t => t.severity === 'critical').length

  return (
    <div className="space-y-4">

      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-base font-semibold text-slate-100">MITRE ATT&CK® Matrix</h2>
          <p className="text-xs text-slate-500 mt-0.5">Enterprise techniques mapped to observed threat activity</p>
        </div>
        <div className="flex items-center gap-3">
          {[
            { label: 'Active TTPs', value: activeCount, color: '#ef4444' },
            { label: 'Critical', value: criticalCount, color: '#f97316' },
            { label: 'Tactics', value: 12, color: '#22d3ee' },
          ].map(s => (
            <div key={s.label} className="text-center px-3 py-2 rounded-lg"
                 style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.07)' }}>
              <div className="text-lg font-bold" style={{ color: s.color }}>{s.value}</div>
              <div className="text-[9px] text-slate-600 uppercase tracking-wide">{s.label}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Legend */}
      <div className="flex items-center gap-4 flex-wrap">
        {Object.entries(SEVERITY_STYLE).map(([sev, st]) => (
          <div key={sev} className="flex items-center gap-1.5">
            <span className="w-3 h-3 rounded-sm" style={{ background: st.bg, border: `1px solid ${st.border}` }} />
            <span className="text-xs capitalize" style={{ color: st.text }}>{sev}</span>
          </div>
        ))}
        <div className="flex items-center gap-1.5">
          <span className="w-3 h-3 rounded-sm" style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.1)' }} />
          <span className="text-xs text-slate-600">Inactive</span>
        </div>
      </div>

      {/* Matrix */}
      <div className="rounded-xl overflow-x-auto" style={glass}>
        <div className="min-w-max">
          {/* Tactic headers */}
          <div className="grid border-b" style={{ gridTemplateColumns: `repeat(${TACTICS.length}, 140px)`, borderColor: 'rgba(255,255,255,0.07)' }}>
            {TACTICS.map(t => (
              <div key={t.id}
                   className="px-3 py-3 border-r cursor-pointer transition-colors"
                   style={{ borderColor: 'rgba(255,255,255,0.07)', borderTop: `2px solid ${t.color}`, background: hoveredTactic === t.id ? 'rgba(255,255,255,0.06)' : 'transparent' }}
                   onMouseEnter={() => setHoveredTactic(t.id)}
                   onMouseLeave={() => setHoveredTactic(null)}>
                <div className="text-[9px] font-mono text-slate-600">{t.id}</div>
                <div className="text-xs font-semibold text-slate-200 mt-0.5 leading-tight">{t.name}</div>
                <div className="text-[9px] text-slate-600 mt-1">
                  {t.techniques.filter(x => x.active).length}/{t.techniques.length} active
                </div>
              </div>
            ))}
          </div>

          {/* Technique cells */}
          <div className="grid" style={{ gridTemplateColumns: `repeat(${TACTICS.length}, 140px)` }}>
            {TACTICS.map(t => (
              <div key={t.id} className="border-r py-2 px-1.5 space-y-1"
                   style={{ borderColor: 'rgba(255,255,255,0.07)', background: hoveredTactic === t.id ? 'rgba(255,255,255,0.02)' : 'transparent' }}>
                {t.techniques.map(tech => {
                  const st = tech.severity ? SEVERITY_STYLE[tech.severity] : null
                  return (
                    <button key={tech.id}
                            onClick={() => setSelected(selected?.id === tech.id ? null : tech)}
                            className="w-full text-left px-2 py-1.5 rounded text-[10px] leading-tight transition-all"
                            style={tech.active && st ? {
                              background: st.bg,
                              border: `1px solid ${st.border}`,
                              color: st.text,
                            } : {
                              background: 'rgba(255,255,255,0.03)',
                              border: '1px solid rgba(255,255,255,0.05)',
                              color: '#475569',
                            }}>
                      <div className="font-mono text-[8px] opacity-70">{tech.id}</div>
                      <div className="font-medium leading-tight">{tech.name}</div>
                    </button>
                  )
                })}
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Selected technique detail */}
      {selected && (
        <div className="rounded-xl p-4" style={{ ...glass, borderColor: 'rgba(34,211,238,0.3)', background: 'rgba(34,211,238,0.05)' }}>
          <div className="flex items-start justify-between">
            <div>
              <div className="flex items-center gap-2">
                <span className="font-mono text-xs text-cyan-400">{selected.id}</span>
                <h3 className="text-sm font-semibold text-slate-100">{selected.name}</h3>
                {selected.severity && (
                  <span className="text-[10px] font-bold px-2 py-0.5 rounded-full uppercase"
                        style={{ ...SEVERITY_STYLE[selected.severity], color: SEVERITY_STYLE[selected.severity].text }}>
                    {selected.severity}
                  </span>
                )}
              </div>
              <p className="text-xs text-slate-400 mt-1">
                {selected.active
                  ? `Técnica activa detectada en actividad reciente. Correlacionar con IOCs y actores en el panel de Threat Graph.`
                  : `Técnica registrada en la base de conocimiento. Sin actividad detectada en el período actual.`}
              </p>
            </div>
            <button onClick={() => setSelected(null)} className="text-slate-600 hover:text-slate-400 transition-colors ml-4">
              <svg viewBox="0 0 24 24" className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth="2">
                <line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" />
              </svg>
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

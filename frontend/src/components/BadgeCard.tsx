// Badge visual component for CertAcademico, redciber and LabThinkTank

export interface Badge {
  id:          number
  org:         string
  name:        string
  description: string
  tier:        'bronze' | 'silver' | 'gold' | 'platinum' | 'diamond'
  icon:        string
  awarded_at?: string
  awarded_by?: string
  badge_id?:   number
}

// ── Tier palette ──────────────────────────────────────────────────────────────

export const TIER: Record<string, { color: string; glow: string; label: string }> = {
  bronze:   { color: '#cd7f32', glow: 'rgba(205,127,50,0.4)',   label: 'Bronce'   },
  silver:   { color: '#c0c0c0', glow: 'rgba(192,192,192,0.4)',  label: 'Plata'    },
  gold:     { color: '#ffd700', glow: 'rgba(255,215,0,0.45)',   label: 'Oro'      },
  platinum: { color: '#e5e4e2', glow: 'rgba(229,228,226,0.5)',  label: 'Platino'  },
  diamond:  { color: '#b9f2ff', glow: 'rgba(185,242,255,0.55)', label: 'Diamante' },
}

// ── Org palette ───────────────────────────────────────────────────────────────

const ORG: Record<string, { bg: string; border: string; accent: string; abbr: string }> = {
  CertAcademico: { bg: 'rgba(59,130,246,0.08)',  border: 'rgba(59,130,246,0.3)',  accent: '#60a5fa', abbr: 'CA' },
  redciber:      { bg: 'rgba(239,68,68,0.08)',   border: 'rgba(239,68,68,0.3)',   accent: '#f87171', abbr: 'RC' },
  LabThinkTank:  { bg: 'rgba(34,211,238,0.08)',  border: 'rgba(34,211,238,0.3)',  accent: '#22d3ee', abbr: 'LT' },
}

// ── Icon SVG paths ────────────────────────────────────────────────────────────

const ICONS: Record<string, string> = {
  book:    'M4 19.5A2.5 2.5 0 0 1 6.5 17H20M4 19.5A2.5 2.5 0 0 0 6.5 22H20V2H6.5A2.5 2.5 0 0 0 4 4.5v15z',
  chart:   'M18 20V10M12 20V4M6 20v-6',
  flask:   'M9 3h6m-6 0v6l-4 9a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1L15 9V3M9 3H7m8 0h2',
  eye:     'M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8zM12 12a3 3 0 1 0 0-6 3 3 0 0 0 0 6z',
  cpu:     'M9 3H5a2 2 0 0 0-2 2v4m6-6h10a2 2 0 0 1 2 2v4M9 3v18m0 0h10a2 2 0 0 0 2-2V9M9 21H5a2 2 0 0 1-2-2V9m0 0h18',
  shield:  'M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z',
  lock:    'M19 11H5a2 2 0 0 0-2 2v7a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7a2 2 0 0 0-2-2zM7 11V7a5 5 0 0 1 10 0v4',
  search:  'M11 19a8 8 0 1 0 0-16 8 8 0 0 0 0 16zm10 2-4.35-4.35',
  radar:   'M12 12m-1 0a1 1 0 1 0 2 0 1 1 0 0 0-2 0M12 12m-5 0a5 5 0 1 0 10 0 5 5 0 0 0-10 0M12 12m-9 0a9 9 0 1 0 18 0 9 9 0 0 0-18 0',
  target:  'M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zM12 18a6 6 0 1 0 0-12 6 6 0 0 0 0 12zM12 14a2 2 0 1 0 0-4 2 2 0 0 0 0 4z',
  fire:    'M8.5 14.5A2.5 2.5 0 0 0 11 12c0-1.38-.5-2-1-3-1.072-2.143-.224-4.054 2-6 .5 2.5 2 4.9 4 6.5 2 1.6 3 3.5 3 5.5a7 7 0 1 1-14 0c0-1.153.433-2.294 1-3a2.5 2.5 0 0 0 2.5 2.5z',
  beaker:  'M9 3h6m-3 0v6m-5 3h10l2 9H5L7 12zM7 12l-1-3h12l-1 3',
  flow:    'M5 12h14M12 5l7 7-7 7',
  brain:   'M9.5 2A2.5 2.5 0 0 1 12 4.5v15a2.5 2.5 0 0 1-4.96.44A2.5 2.5 0 0 1 4.5 17a2.5 2.5 0 0 1 0-5 2.5 2.5 0 0 1 3.5-3.5A2.5 2.5 0 0 1 9.5 2zM14.5 2A2.5 2.5 0 0 0 12 4.5v15a2.5 2.5 0 0 0 4.96.44A2.5 2.5 0 0 0 19.5 17a2.5 2.5 0 0 0 0-5 2.5 2.5 0 0 0-3.5-3.5A2.5 2.5 0 0 0 14.5 2z',
  star:    'M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z',
  trophy:  'M6 9H4.5a2.5 2.5 0 0 1 0-5H6M18 9h1.5a2.5 2.5 0 0 0 0-5H18M4 22h16M10 14.66V17c0 .55-.47.98-.97 1.21C7.85 18.75 7 20.24 7 22M14 14.66V17c0 .55.47.98.97 1.21C16.15 18.75 17 20.24 17 22M18 2H6v7a6 6 0 0 0 12 0V2z',
}

// ── Badge SVG renderer ────────────────────────────────────────────────────────

function BadgeShape({ tier, org, icon, size = 64 }: {
  tier: string; org: string; icon: string; size?: number
}) {
  const t  = TIER[tier]  ?? TIER.bronze
  const o  = ORG[org]    ?? ORG.CertAcademico
  const cx = size / 2
  const r  = size * 0.42

  // Hexagon points
  const hex = Array.from({ length: 6 }, (_, i) => {
    const angle = (Math.PI / 180) * (60 * i - 30)
    return `${cx + r * Math.cos(angle)},${cx + r * Math.sin(angle)}`
  }).join(' ')

  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
      <defs>
        <filter id={`glow-${tier}`}>
          <feGaussianBlur stdDeviation="2" result="coloredBlur" />
          <feMerge><feMergeNode in="coloredBlur" /><feMergeNode in="SourceGraphic" /></feMerge>
        </filter>
        <linearGradient id={`grad-${tier}-${org}`} x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%"   stopColor={t.color} stopOpacity="0.25" />
          <stop offset="100%" stopColor={o.accent} stopOpacity="0.15" />
        </linearGradient>
      </defs>

      {/* Hex background */}
      <polygon points={hex}
               fill={`url(#grad-${tier}-${org})`}
               stroke={t.color} strokeWidth="1.5"
               filter={`url(#glow-${tier})`} />

      {/* Org abbr top-left */}
      <text x={cx} y={size * 0.28} textAnchor="middle" fill={o.accent}
            fontSize={size * 0.115} fontWeight="900" fontFamily="monospace">
        {ORG[org]?.abbr ?? org.slice(0, 2).toUpperCase()}
      </text>

      {/* Icon */}
      <g transform={`translate(${cx - size * 0.18}, ${size * 0.35}) scale(${size / 96})`}>
        <svg viewBox="0 0 24 24" width={size * 0.36} height={size * 0.36}
             fill="none" stroke={t.color} strokeWidth="1.5"
             strokeLinecap="round" strokeLinejoin="round">
          <path d={ICONS[icon] ?? ICONS.star} />
        </svg>
      </g>

      {/* Tier dots bottom */}
      {Object.keys(TIER).indexOf(tier) >= 0 && (
        Array.from({ length: Object.keys(TIER).indexOf(tier) + 1 }, (_, i) => (
          <circle key={i}
                  cx={cx - (Object.keys(TIER).indexOf(tier) * 4) + i * 8}
                  cy={size * 0.84}
                  r={2.5} fill={t.color} opacity="0.9" />
        ))
      )}
    </svg>
  )
}

// ── Badge Card ────────────────────────────────────────────────────────────────

export function BadgeCard({ badge, size = 'md', showOrg = true }: {
  badge: Badge; size?: 'sm' | 'md' | 'lg'; showOrg?: boolean
}) {
  const t = TIER[badge.tier] ?? TIER.bronze
  const o = ORG[badge.org]   ?? ORG.CertAcademico
  const px = size === 'sm' ? 48 : size === 'lg' ? 88 : 64

  return (
    <div className="flex flex-col items-center gap-1.5 group relative"
         title={`${badge.name} — ${badge.description}`}>
      <div className="transition-transform group-hover:scale-110" style={{ filter: `drop-shadow(0 0 8px ${t.glow})` }}>
        <BadgeShape tier={badge.tier} org={badge.org} icon={badge.icon} size={px} />
      </div>
      {size !== 'sm' && (
        <>
          <p className="text-[10px] font-bold text-center leading-tight" style={{ color: t.color }}
             title={badge.name}>
            {badge.name}
          </p>
          {showOrg && (
            <p className="text-[8px] font-mono font-bold px-1.5 py-0.5 rounded"
               style={{ background: o.bg, border: `1px solid ${o.border}`, color: o.accent }}>
              {badge.org}
            </p>
          )}
        </>
      )}
    </div>
  )
}

// ── Badge Row (compact for sidebar) ──────────────────────────────────────────

export function BadgeRow({ badges }: { badges: Badge[] }) {
  if (!badges.length) return null
  return (
    <div className="flex flex-wrap gap-1.5 justify-center">
      {badges.map(b => (
        <div key={b.id} title={`${b.org} · ${b.name}\n${b.description}`}
             style={{ filter: `drop-shadow(0 0 4px ${(TIER[b.tier] ?? TIER.bronze).glow})` }}>
          <BadgeShape tier={b.tier} org={b.org} icon={b.icon} size={32} />
        </div>
      ))}
    </div>
  )
}

// ── Badge Gallery (grid) ──────────────────────────────────────────────────────

export function BadgeGallery({ badges, title }: { badges: Badge[]; title?: string }) {
  const orgs = ['CertAcademico', 'redciber', 'LabThinkTank']
  return (
    <div className="space-y-5">
      {title && <p className="text-xs font-bold text-slate-400 uppercase tracking-wider">{title}</p>}
      {orgs.map(org => {
        const orgBadges = badges.filter(b => b.org === org)
        if (!orgBadges.length) return null
        const o = ORG[org]
        return (
          <div key={org}>
            <div className="flex items-center gap-2 mb-3">
              <span className="text-[9px] font-bold px-2 py-0.5 rounded font-mono"
                    style={{ background: o.bg, border: `1px solid ${o.border}`, color: o.accent }}>
                {org}
              </span>
              <div className="flex-1 h-px" style={{ background: o.border }} />
            </div>
            <div className="flex flex-wrap gap-4">
              {orgBadges.map(b => (
                <BadgeCard key={b.id} badge={b} size="md" showOrg={false} />
              ))}
            </div>
          </div>
        )
      })}
    </div>
  )
}

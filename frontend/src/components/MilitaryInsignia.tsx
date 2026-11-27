import { PHASE_COLOR, RANKS } from '../data/orionBriefings'

const GOLD = '#d4bd55'
const DIM = '#4a5236'

/** Insignia de grado: galones (suboficiales, 1–5) o estrellas (oficiales, 6–10). Nivel 0 = Recluta. */
export function RankInsignia({ level, size = 64 }: { level: number; size?: number }) {
  const lv = Math.max(0, Math.min(level, RANKS.length - 1))
  const officer = lv >= 6
  const n = officer ? lv - 5 : lv
  return (
    <svg width={size} height={size} viewBox="0 0 64 64" role="img" aria-label={RANKS[lv]}>
      <rect x="6" y="4" width="52" height="56" rx="8" fill="#1a1f13" stroke={lv ? GOLD : DIM} strokeWidth="2" />
      {lv === 0 && <circle cx="32" cy="32" r="6" fill="none" stroke={DIM} strokeWidth="2" />}
      {!officer && Array.from({ length: n }).map((_, i) => (
        <path key={i} d={`M16 ${16 + i * 7} L32 ${26 + i * 7} L48 ${16 + i * 7}`} fill="none" stroke={GOLD} strokeWidth="3.2" strokeLinejoin="round" />
      ))}
      {officer && Array.from({ length: n }).map((_, i) => {
        const cols = n <= 3 ? n : 3
        const row = i < cols ? 0 : 1
        const inRow = row === 0 ? cols : n - cols
        const k = row === 0 ? i : i - cols
        const cx = 32 + (k - (inRow - 1) / 2) * 14
        const cy = n <= 3 ? 32 : 24 + row * 16
        return <Star key={i} cx={cx} cy={cy} r={6} fill={GOLD} />
      })}
    </svg>
  )
}

function Star({ cx, cy, r, fill }: { cx: number; cy: number; r: number; fill: string }) {
  const pts = Array.from({ length: 10 }).map((_, i) => {
    const a = (Math.PI / 5) * i - Math.PI / 2
    const rr = i % 2 ? r * 0.45 : r
    return `${cx + rr * Math.cos(a)},${cy + rr * Math.sin(a)}`
  }).join(' ')
  return <polygon points={pts} fill={fill} />
}

/** Distintivo de reto: escudo con el número del reto, color por fase. Apagado si aún no se gana. */
export function Distintivo({ id, phase, earned, size = 40 }: { id: number; phase: number; earned: boolean; size?: number }) {
  const c = earned ? (PHASE_COLOR[phase] ?? GOLD) : DIM
  return (
    <svg width={size} height={size} viewBox="0 0 48 48" role="img" aria-label={`Distintivo reto ${id}`} className="shrink-0">
      <path d="M24 3 L43 10 V23 C43 34 35 42 24 45 C13 42 5 34 5 23 V10 Z" fill={earned ? '#1f2616' : '#151a0f'} stroke={c} strokeWidth="2.2" />
      <path d="M11 14 L24 9 L37 14" fill="none" stroke={c} strokeWidth="1.4" opacity="0.7" />
      <text x="24" y="31" textAnchor="middle" fontSize="15" fontWeight="700" fontFamily="Oswald, sans-serif" fill={c}>
        {String(id).padStart(2, '0')}
      </text>
      {earned && <Star cx={24} cy={39} r={3.2} fill={c} />}
    </svg>
  )
}

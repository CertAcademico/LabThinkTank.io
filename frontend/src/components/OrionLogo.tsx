/** Logo institucional de la plataforma (GoTec · Global Open Technologies). */
export const GOTEC_SRC = '/logos/gotec.jpg'

/** Logo GoTec sobre placa clara: el original tiene fondo blanco y debe verse bien sobre el tema oscuro. */
export function GotecLogo({ height = 32, className = '' }: { height?: number; className?: string }) {
  return (
    <span className={`inline-flex items-center justify-center rounded-md shrink-0 ${className}`}
          style={{ background: '#ffffff', padding: Math.max(2, Math.round(height / 10)), boxShadow: '0 0 0 1px rgba(212,189,85,0.35)' }}>
      <img src={GOTEC_SRC} alt="GoTec · Global Open Technologies" style={{ height, width: 'auto', display: 'block' }} />
    </span>
  )
}

/** Emblema del grupo ORION (CCOCI): escudo con el cinturón de Orión. */
export default function OrionLogo({ size = 40, className = '' }: { size?: number; className?: string }) {
  return (
    <svg width={size} height={size} viewBox="0 0 64 64" className={`shrink-0 ${className}`} role="img" aria-label="ORION · CCOCI">
      <path d="M32 3 L57 12 V30 C57 45 46 56 32 61 C18 56 7 45 7 30 V12 Z" fill="#1a1f13" stroke="#d4bd55" strokeWidth="2.5" />
      <path d="M32 9 L51 16 V30 C51 42 43 51 32 55 C21 51 13 42 13 30 V16 Z" fill="none" stroke="#93a954" strokeWidth="1" opacity="0.6" />
      <g fill="#e0cf74">
        <circle cx="22" cy="19" r="2.2" /><circle cx="43" cy="20" r="1.8" />
        <circle cx="26" cy="32" r="1.9" /><circle cx="32" cy="30.5" r="1.9" /><circle cx="38" cy="29" r="1.9" />
        <circle cx="23" cy="44" r="1.8" /><circle cx="42" cy="45" r="2.2" />
      </g>
      <path d="M22 19 L26 32 L23 44 M43 20 L38 29 L42 45 M26 32 L32 30.5 L38 29" stroke="#d4bd55" strokeWidth="0.8" opacity="0.55" fill="none" />
    </svg>
  )
}

import { AnnouncementBanner } from './CtfScoreboard'

// Avisos y recordatorios del docente: visibles en toda la plataforma (no solo en el Overview), con botón para cerrarlos.
export default function GlobalAnnouncements() {
  return <div className="px-5 pt-3 empty:hidden"><AnnouncementBanner /></div>
}

/**
 * reportPdf.ts — Generación de informes PDF con marca CTI Nexus Fusion Center / RedCiber.
 *
 * Todas las funciones usan jsPDF 2.5 + jspdf-autotable.
 * Los logos se dibujan vectorialmente (sin dependencias de imagen externas).
 */

// ── Constantes de marca ────────────────────────────────────────────────────────

const C = {
  dark:        [15,  23,  42]  as [number, number, number],
  darkMid:     [30,  41,  59]  as [number, number, number],
  darkBorder:  [51,  65,  85]  as [number, number, number],
  purple:      [134, 59,  255] as [number, number, number],
  purpleMid:   [168, 85,  247] as [number, number, number],
  purpleLight: [196, 143, 255] as [number, number, number],
  red:         [220, 38,  38]  as [number, number, number],
  redLight:    [239, 68,  68]  as [number, number, number],
  cyan:        [34,  211, 238] as [number, number, number],
  white:       [255, 255, 255] as [number, number, number],
  gray:        [100, 116, 139] as [number, number, number],
  grayLight:   [148, 163, 184] as [number, number, number],
  green:       [34,  197, 94]  as [number, number, number],
  orange:      [249, 115, 22]  as [number, number, number],
  yellow:      [234, 179, 8]   as [number, number, number],
}

const PAGE_W  = 210
const MARGIN  = 14
const HEADER_H = 30
const FOOTER_H = 12

// ── Helpers de color ───────────────────────────────────────────────────────────

function setFill(doc: any, color: [number, number, number]) {
  doc.setFillColor(color[0], color[1], color[2])
}
function setDraw(doc: any, color: [number, number, number]) {
  doc.setDrawColor(color[0], color[1], color[2])
}
function setTxt(doc: any, color: [number, number, number]) {
  doc.setTextColor(color[0], color[1], color[2])
}

// ── Logo RedCiber (vector) ─────────────────────────────────────────────────────

function drawRedCiberLogo(doc: any, x: number, y: number, scale = 1) {
  const s = scale
  // Escudo (shield)
  setFill(doc, C.red)
  setDraw(doc, C.red)
  // Rect superior del escudo
  doc.rect(x, y, 18 * s, 14 * s, 'F')
  // Triángulo inferior (punta)
  doc.triangle(x, y + 12 * s, x + 18 * s, y + 12 * s, x + 9 * s, y + 22 * s, 'F')
  // Letras RC en blanco
  setTxt(doc, C.white)
  doc.setFont('helvetica', 'bold')
  doc.setFontSize(9 * s)
  doc.text('RC', x + 2.5 * s, y + 11.5 * s)
  // Separador
  setDraw(doc, C.red)
  doc.setLineWidth(0.4)
  doc.line(x + 23 * s, y + 1 * s, x + 23 * s, y + 21 * s)
  // Wordmark
  setTxt(doc, C.red)
  doc.setFont('helvetica', 'bold')
  doc.setFontSize(11 * s)
  doc.text('RedCiber', x + 27 * s, y + 9 * s)
  // Tagline
  setTxt(doc, C.gray)
  doc.setFont('helvetica', 'normal')
  doc.setFontSize(6.5 * s)
  doc.text('CYBERSECURITY RESEARCH', x + 27 * s, y + 16 * s)
}

// ── Logo CTI Nexus Fusion Center (vector) ─────────────────────────────────────

function drawCtiNexusLogo(doc: any, x: number, y: number, scale = 1) {
  const s = scale
  // Hexágono exterior (ring)
  setDraw(doc, C.purpleMid)
  doc.setLineWidth(0.8)
  const hex = [
    [x + 11 * s, y],
    [x + 20 * s, y],
    [x + 24 * s, y + 7 * s],
    [x + 20 * s, y + 14 * s],
    [x + 11 * s, y + 14 * s],
    [x + 7 * s,  y + 7 * s],
  ]
  doc.lines(
    hex.slice(1).map((pt, i) => [pt[0] - hex[i][0], pt[1] - hex[i][1]]),
    hex[0][0], hex[0][1], [1, 1], 'S', true
  )
  // Rayo interior (lightning bolt)
  setFill(doc, C.purple)
  setDraw(doc, C.purple)
  doc.triangle(x + 17 * s, y + 2 * s, x + 9 * s,  y + 9 * s, x + 13 * s, y + 9 * s,  'F')
  doc.triangle(x + 12 * s, y + 6 * s, x + 19 * s, y + 6 * s, x + 11 * s, y + 14 * s, 'F')
  // Separador
  setDraw(doc, C.purpleMid)
  doc.setLineWidth(0.4)
  doc.line(x + 30 * s, y + 1 * s, x + 30 * s, y + 21 * s)
  // Wordmark
  setTxt(doc, C.purple)
  doc.setFont('helvetica', 'bold')
  doc.setFontSize(11 * s)
  doc.text('CTI Nexus', x + 34 * s, y + 8.5 * s)
  // Subtitle
  setTxt(doc, C.purpleMid)
  doc.setFont('helvetica', 'bold')
  doc.setFontSize(7.5 * s)
  doc.text('Fusion Center', x + 34 * s, y + 16 * s)
}

// ── Header de página ───────────────────────────────────────────────────────────

function drawHeader(doc: any, title: string, subtitle: string, classification = 'TLP:WHITE') {
  // Fondo oscuro
  setFill(doc, C.dark)
  doc.rect(0, 0, PAGE_W, HEADER_H, 'F')

  // Línea de acento
  setFill(doc, C.purple)
  doc.rect(0, HEADER_H - 2, PAGE_W, 2, 'F')

  // Logo RedCiber (izquierda)
  drawRedCiberLogo(doc, MARGIN, 4, 1)

  // Logo CTI Nexus (derecha)
  drawCtiNexusLogo(doc, PAGE_W - MARGIN - 88, 4, 1)

  // Título centrado
  setTxt(doc, C.white)
  doc.setFont('helvetica', 'bold')
  doc.setFontSize(9.5)
  doc.text(title, PAGE_W / 2, 12, { align: 'center' })
  setTxt(doc, C.grayLight)
  doc.setFont('helvetica', 'normal')
  doc.setFontSize(7)
  doc.text(subtitle, PAGE_W / 2, 18, { align: 'center' })

  // Clasificación TLP (esquina superior derecha — encima del logo)
  const tlpColor = classification.startsWith('TLP:RED')    ? C.red
                 : classification.startsWith('TLP:AMBER')  ? C.orange
                 : classification.startsWith('TLP:GREEN')  ? C.green
                 : C.grayLight
  setTxt(doc, tlpColor)
  doc.setFont('helvetica', 'bold')
  doc.setFontSize(6)
  doc.text(classification, PAGE_W - MARGIN, 5, { align: 'right' })
}

// ── Sub-header de metadatos ────────────────────────────────────────────────────

function drawMetaBar(doc: any, meta: { date: string; analyst?: string; events?: number; version?: string }) {
  const y = HEADER_H + 1
  setFill(doc, C.darkMid)
  doc.rect(0, y, PAGE_W, 8, 'F')
  setTxt(doc, C.grayLight)
  doc.setFont('helvetica', 'normal')
  doc.setFontSize(7)
  const parts = [
    `Fecha: ${meta.date}`,
    meta.analyst ? `Analista: ${meta.analyst}` : null,
    meta.events != null ? `Eventos: ${meta.events}` : null,
    meta.version ? `v${meta.version}` : null,
  ].filter(Boolean) as string[]
  doc.text(parts.join('   ·   '), MARGIN, y + 5.5)
  // Línea separadora
  setDraw(doc, C.darkBorder)
  doc.setLineWidth(0.3)
  doc.line(0, y + 8, PAGE_W, y + 8)
}

// ── Footer de página ───────────────────────────────────────────────────────────

function drawFooter(doc: any, pageNum: number, totalPages: number) {
  const y = 297 - FOOTER_H
  setFill(doc, C.dark)
  doc.rect(0, y, PAGE_W, FOOTER_H, 'F')
  setFill(doc, C.purple)
  doc.rect(0, y, PAGE_W, 1, 'F')

  setTxt(doc, C.gray)
  doc.setFont('helvetica', 'normal')
  doc.setFontSize(6.5)
  doc.text('RedCiber © 2024  ·  CTI Nexus Fusion Center', MARGIN, y + 7.5)
  doc.text(`Pág. ${pageNum} / ${totalPages}`, PAGE_W - MARGIN, y + 7.5, { align: 'right' })
  setTxt(doc, C.grayLight)
  doc.text('DOCUMENTO CONFIDENCIAL — Uso interno autorizado', PAGE_W / 2, y + 7.5, { align: 'center' })
}

// ── Área de contenido disponible ───────────────────────────────────────────────

export const CONTENT_TOP    = HEADER_H + 10   // y donde inicia el contenido
export const CONTENT_BOTTOM = 297 - FOOTER_H - 6
export const CONTENT_W      = PAGE_W - MARGIN * 2

// ── Inicialización del doc ─────────────────────────────────────────────────────

export function initDoc(jsPDFClass: any, title: string, subtitle: string, meta: {
  date: string; analyst?: string; events?: number; version?: string; classification?: string
}): { doc: any; y: number } {
  const doc = new jsPDFClass({ unit: 'mm', format: 'a4' })
  drawHeader(doc, title, subtitle, meta.classification ?? 'TLP:WHITE')
  drawMetaBar(doc, meta)
  return { doc, y: CONTENT_TOP + 2 }
}

// ── Paginación ─────────────────────────────────────────────────────────────────

export function addPageWithHeader(doc: any, title: string, subtitle: string, meta: {
  date: string; classification?: string
}): number {
  doc.addPage()
  drawHeader(doc, title, subtitle, meta.classification ?? 'TLP:WHITE')
  drawMetaBar(doc, { date: meta.date })
  return CONTENT_TOP + 2
}

export function finalizeDoc(doc: any, title: string, subtitle: string, meta: {
  date: string; events?: number; analyst?: string; classification?: string
}) {
  const total = doc.getNumberOfPages()
  for (let p = 1; p <= total; p++) {
    doc.setPage(p)
    drawFooter(doc, p, total)
    // Re-dibujar header en páginas 2+ (autotable puede no haberlo puesto)
    if (p > 1) {
      drawHeader(doc, title, subtitle, meta.classification ?? 'TLP:WHITE')
      drawMetaBar(doc, meta)
    }
  }
}

// ── Sección de título dentro del contenido ────────────────────────────────────

export function drawSectionTitle(doc: any, text: string, y: number): number {
  setFill(doc, C.darkMid)
  doc.rect(MARGIN, y, CONTENT_W, 7, 'F')
  setFill(doc, C.purple)
  doc.rect(MARGIN, y, 2, 7, 'F')
  setTxt(doc, C.white)
  doc.setFont('helvetica', 'bold')
  doc.setFontSize(9)
  doc.text(text, MARGIN + 5, y + 5)
  return y + 11
}

// ── Caja de texto con fondo ───────────────────────────────────────────────────

export function drawTextBox(doc: any, text: string, y: number, options?: {
  bgColor?: [number, number, number]; textColor?: [number, number, number]; fontSize?: number; maxWidth?: number
}): number {
  const opts = { bgColor: C.darkMid, textColor: C.grayLight, fontSize: 8, maxWidth: CONTENT_W, ...options }
  const lines = doc.splitTextToSize(text, opts.maxWidth - 8)
  const h     = lines.length * (opts.fontSize * 0.45) + 6
  setFill(doc, opts.bgColor)
  doc.rect(MARGIN, y, opts.maxWidth, h, 'F')
  setTxt(doc, opts.textColor)
  doc.setFont('helvetica', 'normal')
  doc.setFontSize(opts.fontSize)
  doc.text(lines, MARGIN + 4, y + 5)
  return y + h + 3
}

// ── Badges de severidad ────────────────────────────────────────────────────────

export function severityColor(sev: string): [number, number, number] {
  const s = (sev || '').toLowerCase()
  if (s === 'critical') return C.red
  if (s === 'high')     return C.orange
  if (s === 'medium')   return C.yellow
  return C.grayLight
}

// ── Exportación de informe de fusión ──────────────────────────────────────────

export interface FusionReportOptions {
  query: string
  events: Array<{
    severity: string; threatActor: string; mitreTactic?: string;
    ioc?: string; malware?: string; informationSource?: string; timestamp?: string
  }>
  weekly: Record<string, unknown> | null
  analyst?: string
}

export async function exportFusionReportPdf(opts: FusionReportOptions): Promise<void> {
  const mod = await import('jspdf')
  const jsPDFClass = (mod as any).jsPDF ?? (mod as any).default ?? mod

  const now = new Date()
  const dateStr = now.toLocaleDateString('es-CO', { year: 'numeric', month: 'long', day: 'numeric' })

  const title    = 'INFORME DE FUSIÓN CTI'
  const subtitle = `RedCiber × CTI Nexus Fusion Center`

  const { doc, y: y0 } = initDoc(jsPDFClass, title, subtitle, {
    date: dateStr, analyst: opts.analyst ?? 'CTI Nexus AI Engine',
    events: opts.events.length, version: '2.0', classification: 'TLP:WHITE',
  })

  let y = y0

  // ── Bloque de consulta ───────────────────────────────────────────────────────
  y = drawSectionTitle(doc, 'PARÁMETROS DEL ANÁLISIS', y)
  setTxt(doc, C.grayLight)
  doc.setFont('helvetica', 'normal')
  doc.setFontSize(8)
  doc.text(`Consulta: ${opts.query}`, MARGIN + 2, y)
  y += 6

  // ── Resumen ejecutivo (weekly flash) ─────────────────────────────────────────
  if (opts.weekly) {
    y = drawSectionTitle(doc, String(opts.weekly.reportTitle ?? 'INFORME FLASH SEMANAL'), y)

    const summary = String(opts.weekly.executiveSummary ?? '')
    if (summary) {
      y = drawTextBox(doc, summary, y, { textColor: C.white, fontSize: 8.5, maxWidth: CONTENT_W })
    }

    // Amenazas principales
    if (Array.isArray(opts.weekly.topThreats) && (opts.weekly.topThreats as any[]).length) {
      y = drawSectionTitle(doc, 'AMENAZAS PRINCIPALES', y)
      ;(opts.weekly.topThreats as string[]).forEach((threat, i) => {
        if (y > CONTENT_BOTTOM - 10) {
          y = addPageWithHeader(doc, title, subtitle, { date: dateStr })
        }
        setTxt(doc, C.cyan)
        doc.setFont('helvetica', 'bold')
        doc.setFontSize(8)
        doc.text(`${i + 1}.`, MARGIN + 2, y)
        setTxt(doc, C.grayLight)
        doc.setFont('helvetica', 'normal')
        const lines = doc.splitTextToSize(threat, CONTENT_W - 12)
        doc.text(lines, MARGIN + 8, y)
        y += lines.length * 4.5 + 2
      })
      y += 3
    }

    // Recomendaciones
    if (Array.isArray(opts.weekly.mitigationRecommendations)) {
      if (y > CONTENT_BOTTOM - 30) {
        y = addPageWithHeader(doc, title, subtitle, { date: dateStr })
      }
      y = drawSectionTitle(doc, 'RECOMENDACIONES DE MITIGACIÓN', y)
      ;(opts.weekly.mitigationRecommendations as string[]).forEach((rec, i) => {
        if (y > CONTENT_BOTTOM - 10) {
          y = addPageWithHeader(doc, title, subtitle, { date: dateStr })
        }
        setTxt(doc, C.green)
        doc.setFont('helvetica', 'bold')
        doc.setFontSize(8)
        doc.text(`→`, MARGIN + 2, y)
        setTxt(doc, C.white)
        doc.setFont('helvetica', 'normal')
        const lines = doc.splitTextToSize(`${i + 1}. ${rec}`, CONTENT_W - 10)
        doc.text(lines, MARGIN + 8, y)
        y += lines.length * 4.5 + 2
      })
      y += 3
    }

    // Indicadores MITRE
    if (Array.isArray(opts.weekly.mitreAttackCoverage)) {
      if (y > CONTENT_BOTTOM - 25) {
        y = addPageWithHeader(doc, title, subtitle, { date: dateStr })
      }
      y = drawSectionTitle(doc, 'COBERTURA MITRE ATT&CK', y)
      const row: string[] = (opts.weekly.mitreAttackCoverage as string[]).slice(0, 12)
      const cols = 3
      row.forEach((tactic, i) => {
        const col = i % cols
        const xPos = MARGIN + 2 + col * (CONTENT_W / cols)
        const rowOff = Math.floor(i / cols) * 7
        if (col === 0 && i > 0 && y + rowOff > CONTENT_BOTTOM - 10) {
          y = addPageWithHeader(doc, title, subtitle, { date: dateStr })
        }
        setFill(doc, C.darkBorder)
        doc.roundedRect(xPos - 1, y + rowOff - 4, CONTENT_W / cols - 4, 6, 1, 1, 'F')
        setTxt(doc, C.purpleLight)
        doc.setFont('helvetica', 'normal')
        doc.setFontSize(7)
        doc.text(tactic, xPos + 1, y + rowOff)
      })
      y += Math.ceil(row.length / cols) * 7 + 5
    }
  }

  // ── Tabla de eventos ──────────────────────────────────────────────────────────
  if (opts.events.length) {
    if (y > CONTENT_BOTTOM - 20) {
      y = addPageWithHeader(doc, title, subtitle, { date: dateStr })
    }
    y = drawSectionTitle(doc, `MUESTRA DE EVENTOS (${Math.min(30, opts.events.length)} de ${opts.events.length})`, y)

    try {
      const autoTable = (await import('jspdf-autotable')).default
      autoTable(doc, {
        startY: y,
        margin: { left: MARGIN, right: MARGIN },
        head: [['Sev.', 'Actor', 'Táctica', 'IOC / Malware', 'Fuente']],
        body: opts.events.slice(0, 30).map(ev => [
          ev.severity ?? '—',
          (ev.threatActor ?? '—').slice(0, 22),
          (ev.mitreTactic ?? '—').slice(0, 20),
          ((ev.ioc || ev.malware) ?? '—').slice(0, 28),
          (ev.informationSource ?? '—').slice(0, 15),
        ]),
        styles: {
          fontSize: 7, cellPadding: 2, overflow: 'ellipsize',
          textColor: [200, 210, 230], fillColor: [30, 41, 59],
          lineColor: [51, 65, 85], lineWidth: 0.2,
        },
        headStyles: {
          fillColor: [20, 28, 48], textColor: [168, 85, 247], fontStyle: 'bold', fontSize: 7.5,
        },
        alternateRowStyles: { fillColor: [22, 32, 52] },
        columnStyles: {
          0: { cellWidth: 16, halign: 'center' },
          1: { cellWidth: 38 },
          2: { cellWidth: 36 },
          3: { cellWidth: 48 },
          4: { cellWidth: 30 },
        },
        didParseCell: (data: any) => {
          if (data.section === 'body' && data.column.index === 0) {
            const sev = String(data.cell.raw ?? '')
            const [r, g, b] = severityColor(sev)
            data.cell.styles.textColor = [r, g, b]
            data.cell.styles.fontStyle = 'bold'
          }
        },
        showHead: 'everyPage',
        didDrawPage: () => {
          const p = doc.getCurrentPageInfo?.()?.pageNumber ?? doc.internal.pages.length - 1
          drawHeader(doc, title, subtitle, 'TLP:WHITE')
          drawMetaBar(doc, { date: dateStr, events: opts.events.length })
          drawFooter(doc, p, 999)
        },
      })
    } catch {
      // Fallback texto plano si autotable no carga
      opts.events.slice(0, 30).forEach(ev => {
        if (y > CONTENT_BOTTOM - 6) { y = addPageWithHeader(doc, title, subtitle, { date: dateStr }) }
        const [r, g, b] = severityColor(ev.severity)
        setTxt(doc, [r, g, b])
        doc.setFont('helvetica', 'bold')
        doc.setFontSize(7)
        doc.text(`[${ev.severity}]`, MARGIN + 2, y)
        setTxt(doc, C.grayLight)
        doc.setFont('helvetica', 'normal')
        const line = `${ev.threatActor ?? '—'} · ${ev.mitreTactic ?? '—'} · ${ev.ioc || ev.malware || '—'}`
        doc.text(line.slice(0, 105), MARGIN + 20, y)
        y += 4.5
      })
    }
  }

  finalizeDoc(doc, title, subtitle, { date: dateStr, events: opts.events.length })
  doc.save(`cti-nexus-fusion-report-${Date.now()}.pdf`)
}

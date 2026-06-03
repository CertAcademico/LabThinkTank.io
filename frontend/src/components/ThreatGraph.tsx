/**
 * CTI Threat Intelligence Graph — RedCiber × CTI-Lab
 * Diseño propio: SVG + foreignObject, sin dependencias de grafos externos.
 *
 * Arquitectura visual:
 *   ZONA 1 (izq)  — Actores / APTs  (enriquecidos con CISA)
 *   ZONA 2 (centro) — Campañas     (agrupadas por actor)
 *   ZONA 3 (der)  — IoCs           (coloreados por cluster K-Means)
 *
 * ML: K-Means puro TypeScript (k=5) sobre features de severidad/tipo/país/actor.
 */

import { useCallback, useEffect, useRef, useState, useMemo } from 'react'
import {
  Shield, ZoomIn, ZoomOut, Maximize2, RefreshCw,
  Activity, Layers, Filter, X, ChevronRight, Search,
} from 'lucide-react'
import { useAuth } from '../contexts/AuthContext'

const API = import.meta.env.VITE_API_URL ?? 'http://127.0.0.1:8000'

// ── Types ──────────────────────────────────────────────────────────────────────

interface CisaEntry {
  name: string; aliases: string[]; country: string; sponsor: string
  motivation: string; risk_level: string; target_sectors: string[]
  known_campaigns: string[]; cisa_advisories: string[]; description: string
}

interface RawIoc {
  id: number | string; ioc: string; type: string; threat_actor: string
  severity: string; mitre: string; country: string; source: string
}

interface RawActor {
  id: number; name: string; active_campaign: string
  country: string; motivation: string
}

interface GNode {
  id: string
  kind: 'actor' | 'campaign' | 'ioc'
  label: string
  fullLabel?: string
  x: number; y: number
  w: number; h: number
  // actor fields
  country?: string; riskLevel?: string; riskColor?: string
  cisaMatch?: boolean; cisaEntry?: CisaEntry; iocCount?: number
  // campaign fields
  actorName?: string; iocCount2?: number
  // ioc fields
  iocType?: string; severity?: string; sevColor?: string
  cluster?: number; clusterColor?: string; actor?: string
}

interface GEdge {
  id: string; source: string; target: string
  color: string; dashed: boolean; animated: boolean
}

// ── Paleta de colores ──────────────────────────────────────────────────────────

const RISK: Record<string, string> = {
  Critical: '#ef4444', High: '#f97316', Medium: '#facc15', Low: '#4ade80',
}
const SEV: Record<string, string> = {
  critical: '#ef4444', high: '#f97316', medium: '#facc15', low: '#4ade80',
}
const CLUSTER_COLORS = [
  '#22d3ee', '#a78bfa', '#f472b6', '#4ade80', '#fb923c',
]

// ── K-Means puro TypeScript ────────────────────────────────────────────────────

function encodeIoc(ioc: RawIoc): number[] {
  const typeMap: Record<string, number> = {
    IP: 0, Domain: 1, URL: 2, 'Hash-SHA256': 3, 'Hash-MD5': 4, Email: 5, CVE: 6,
  }
  const sevMap: Record<string, number> = { critical: 3, high: 2, medium: 1, low: 0 }
  return [
    (typeMap[ioc.type] ?? 7) / 7,
    (sevMap[(ioc.severity ?? '').toLowerCase()] ?? 1) / 3,
    (Math.abs(hashStr(ioc.country ?? '')) % 10) / 10,
    (Math.abs(hashStr(ioc.threat_actor ?? '')) % 15) / 15,
    (Math.abs(hashStr((ioc.mitre ?? '').slice(0, 5))) % 14) / 14,
  ]
}

function hashStr(s: string): number {
  let h = 0
  for (let i = 0; i < s.length; i++) h = (Math.imul(31, h) + s.charCodeAt(i)) | 0
  return h
}

function dist(a: number[], b: number[]): number {
  return Math.sqrt(a.reduce((s, v, i) => s + (v - b[i]) ** 2, 0))
}

function kMeans(iocs: RawIoc[], k = 5, iterations = 40): number[] {
  if (iocs.length === 0) return []
  const vecs = iocs.map(encodeIoc)
  const dim  = vecs[0].length

  // Seeded centroids (pick k evenly spaced samples)
  let centroids = Array.from({ length: k }, (_, i) =>
    vecs[Math.floor((i * vecs.length) / k)].slice()
  )

  let assignments = new Array(vecs.length).fill(0)
  for (let iter = 0; iter < iterations; iter++) {
    const newAssign = vecs.map(v => {
      let best = 0, bestD = Infinity
      centroids.forEach((c, ci) => { const d = dist(v, c); if (d < bestD) { bestD = d; best = ci } })
      return best
    })
    // Update centroids
    const sums   = Array.from({ length: k }, () => new Array(dim).fill(0))
    const counts = new Array(k).fill(0)
    newAssign.forEach((ci, vi) => { vecs[vi].forEach((v, d) => { sums[ci][d] += v }); counts[ci]++ })
    centroids = sums.map((s, ci) =>
      counts[ci] ? s.map(v => v / counts[ci]) : centroids[ci]
    )
    assignments = newAssign
  }
  return assignments
}

// ── Layout calculator ──────────────────────────────────────────────────────────

const NODE_W = { actor: 175, campaign: 155, ioc: 145 }
const NODE_H = { actor: 88,  campaign: 62,  ioc: 52  }
const GAP_V  = { actor: 24,  campaign: 18,  ioc: 14  }
const ZONE_X = { actor: 30,  campaign: 380, ioc: 720 }
const TOP_PAD = 50

function buildGraph(
  rawIocs: RawIoc[],
  rawActors: RawActor[],
  cisaDb: CisaEntry[],
  clusters: number[],
): { nodes: GNode[]; edges: GEdge[]; svgH: number } {
  const nodes: GNode[] = []
  const edges: GEdge[] = []

  function matchCisa(name: string): CisaEntry | undefined {
    const low = name.toLowerCase()
    return cisaDb.find(e =>
      e.name.toLowerCase() === low ||
      e.aliases.some(a => a.toLowerCase() === low) ||
      low.includes(e.name.toLowerCase()) ||
      e.name.toLowerCase().includes(low)
    )
  }

  // ── Actor nodes ──────────────────────────────────────────────────────────────
  const actorMap = new Map<string, GNode>()
  const uniqueActors = Array.from(new Set([
    ...rawActors.map(a => a.name),
    ...rawIocs.map(i => i.threat_actor).filter(Boolean),
  ])).filter(Boolean)

  uniqueActors.forEach((name, i) => {
    const cisa    = matchCisa(name)
    const risk    = cisa?.risk_level ?? 'Medium'
    const iocCount = rawIocs.filter(io => io.threat_actor === name).length
    const y = TOP_PAD + i * (NODE_H.actor + GAP_V.actor)
    const node: GNode = {
      id: `actor:${name}`, kind: 'actor', label: name,
      x: ZONE_X.actor, y,
      w: NODE_W.actor, h: NODE_H.actor,
      country: cisa?.country ?? rawActors.find(a => a.name === name)?.country ?? '—',
      riskLevel: risk, riskColor: RISK[risk] ?? '#94a3b8',
      cisaMatch: Boolean(cisa), cisaEntry: cisa,
      iocCount,
    }
    nodes.push(node)
    actorMap.set(name, node)
  })

  // ── Campaign nodes ───────────────────────────────────────────────────────────
  const campaignMap = new Map<string, GNode>()
  const campaigns: { name: string; actor: string }[] = []
  rawActors.forEach(a => {
    if (a.active_campaign && !campaignMap.has(a.active_campaign))
      campaigns.push({ name: a.active_campaign, actor: a.name })
  })
  // Add CISA campaigns for matched actors
  uniqueActors.forEach(name => {
    const cisa = matchCisa(name)
    cisa?.known_campaigns.forEach(c => {
      if (!campaignMap.has(c)) campaigns.push({ name: c, actor: name })
    })
  })

  campaigns.forEach(({ name, actor }, i) => {
    const actorIocs = rawIocs.filter(io => io.threat_actor === actor).length
    const y = TOP_PAD + i * (NODE_H.campaign + GAP_V.campaign)
    const node: GNode = {
      id: `camp:${name}`, kind: 'campaign', label: name,
      x: ZONE_X.campaign, y,
      w: NODE_W.campaign, h: NODE_H.campaign,
      actorName: actor, iocCount2: actorIocs,
    }
    nodes.push(node)
    campaignMap.set(name, node)

    // Edge: Actor → Campaign
    const src = actorMap.get(actor)
    if (src) {
      edges.push({
        id: `e-ac-${name}`, source: src.id, target: node.id,
        color: '#a78bfa', dashed: false, animated: true,
      })
    }
  })

  // ── IoC nodes ────────────────────────────────────────────────────────────────
  // Sort by cluster so same clusters are adjacent
  const iocWithCluster = rawIocs.map((ioc, i) => ({
    ioc, cluster: clusters[i] ?? 0,
  })).sort((a, b) => a.cluster - b.cluster)

  iocWithCluster.forEach(({ ioc, cluster }, i) => {
    const sev    = (ioc.severity ?? 'medium').toLowerCase()
    const y      = TOP_PAD + i * (NODE_H.ioc + GAP_V.ioc)
    const cColor = CLUSTER_COLORS[cluster % CLUSTER_COLORS.length]
    const node: GNode = {
      id: `ioc:${ioc.id}`, kind: 'ioc',
      label: ioc.ioc.length > 22 ? ioc.ioc.slice(0, 22) + '…' : ioc.ioc,
      fullLabel: ioc.ioc,
      x: ZONE_X.ioc, y,
      w: NODE_W.ioc, h: NODE_H.ioc,
      iocType: ioc.type, severity: sev, sevColor: SEV[sev] ?? '#94a3b8',
      cluster, clusterColor: cColor,
      actor: ioc.threat_actor,
    }
    nodes.push(node)

    // Edge: Actor → IoC
    const actorNode = actorMap.get(ioc.threat_actor)
    if (actorNode) {
      edges.push({
        id: `e-ai-${ioc.id}`, source: actorNode.id, target: node.id,
        color: cColor, dashed: true, animated: false,
      })
    }

    // Edge: Campaign → IoC (if campaign belongs to same actor)
    campaignMap.forEach((campNode, campName) => {
      if (campNode.actorName === ioc.threat_actor) {
        edges.push({
          id: `e-ci-${campName}-${ioc.id}`, source: campNode.id, target: node.id,
          color: '#4ade8040', dashed: true, animated: false,
        })
      }
    })
  })

  const allY = nodes.map(n => n.y + n.h)
  const svgH = Math.max(600, Math.max(...allY) + 60)
  return { nodes, edges, svgH }
}

// ── SVG bezier edge ────────────────────────────────────────────────────────────

function edgePath(src: GNode, tgt: GNode): string {
  const x1 = src.x + src.w
  const y1 = src.y + src.h / 2
  const x2 = tgt.x
  const y2 = tgt.y + tgt.h / 2
  const cx = (x1 + x2) / 2
  return `M ${x1} ${y1} C ${cx} ${y1} ${cx} ${y2} ${x2} ${y2}`
}

// ── Node card components (rendered inside SVG foreignObject) ───────────────────

function ActorCard({ node, selected, onClick }: {
  node: GNode; selected: boolean; onClick: () => void
}) {
  const c = node.riskColor!
  return (
    <div
      onClick={onClick}
      style={{
        width: node.w, height: node.h, cursor: 'pointer', userSelect: 'none',
        background: selected ? `${c}18` : 'rgba(15,10,30,0.96)',
        border: `${selected ? 2 : 1.5}px solid ${c}`,
        borderRadius: 10, padding: '7px 10px', boxSizing: 'border-box',
        boxShadow: selected ? `0 0 20px ${c}40` : `0 0 8px ${c}18`,
        transition: 'box-shadow 0.2s',
      }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 5, marginBottom: 3 }}>
        <span style={{
          fontSize: 7, fontWeight: 700, color: c,
          background: `${c}18`, border: `1px solid ${c}28`,
          borderRadius: 4, padding: '1px 5px',
        }}>{node.riskLevel}</span>
        {node.cisaMatch && (
          <span style={{
            fontSize: 7, fontWeight: 700, color: '#22d3ee',
            background: 'rgba(34,211,238,0.1)', border: '1px solid rgba(34,211,238,0.22)',
            borderRadius: 4, padding: '1px 5px',
          }}>✓ CISA</span>
        )}
      </div>
      <div style={{ fontSize: 12, fontWeight: 700, color: '#f1f5f9', marginBottom: 1,
                    overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
        {node.label}
      </div>
      <div style={{ fontSize: 9, color: '#64748b', marginBottom: 2 }}>
        {node.country}
        {node.cisaEntry?.sponsor ? ` · ${node.cisaEntry.sponsor.split(' ')[0]}` : ''}
      </div>
      {node.cisaEntry?.cisa_advisories?.length ? (
        <div style={{ fontSize: 7, color: '#0e7490', fontWeight: 600 }}>
          {node.cisaEntry.cisa_advisories.slice(0, 2).join(' · ')}
        </div>
      ) : null}
      <div style={{ marginTop: 3, fontSize: 8, color: '#475569' }}>
        {node.iocCount} IoC{node.iocCount !== 1 ? 's' : ''} detectados
      </div>
    </div>
  )
}

function CampaignCard({ node, selected, onClick }: {
  node: GNode; selected: boolean; onClick: () => void
}) {
  const truncated = node.label.length > 24 ? node.label.slice(0, 24) + '…' : node.label
  return (
    <div
      onClick={onClick}
      style={{
        width: node.w, height: node.h, cursor: 'pointer', userSelect: 'none',
        background: selected ? 'rgba(167,139,250,0.12)' : 'rgba(20,12,40,0.96)',
        border: `${selected ? 2 : 1}px solid rgba(167,139,250,${selected ? 0.6 : 0.35})`,
        borderRadius: 9, padding: '6px 10px', boxSizing: 'border-box',
        boxShadow: selected ? '0 0 18px rgba(167,139,250,0.3)' : '0 0 6px rgba(167,139,250,0.1)',
      }}>
      <div style={{ fontSize: 7, color: '#a78bfa', fontWeight: 700,
                    textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 3 }}>
        Campaña
      </div>
      <div style={{ fontSize: 11, fontWeight: 600, color: '#ddd6fe',
                    overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
        {truncated}
      </div>
      <div style={{ marginTop: 3, fontSize: 8, color: '#4c1d95' }}>
        {node.actorName} · {node.iocCount2} IoCs
      </div>
    </div>
  )
}

function IocCard({ node, selected, onClick }: {
  node: GNode; selected: boolean; onClick: () => void
}) {
  const cc = node.clusterColor!
  const sc = node.sevColor!
  return (
    <div
      onClick={onClick}
      style={{
        width: node.w, height: node.h, cursor: 'pointer', userSelect: 'none',
        background: selected ? `${cc}14` : 'rgba(5,18,42,0.96)',
        border: `${selected ? 2 : 1}px solid ${selected ? cc : `${cc}55`}`,
        borderRadius: 8, padding: '5px 9px', boxSizing: 'border-box',
        boxShadow: selected ? `0 0 16px ${cc}35` : 'none',
        borderLeft: `3px solid ${cc}`,
      }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 4, marginBottom: 2 }}>
        <span style={{ fontSize: 7, color: sc, fontWeight: 700 }}>{node.severity?.toUpperCase()}</span>
        <span style={{ fontSize: 7, color: '#334155' }}>·</span>
        <span style={{ fontSize: 7, color: '#475569' }}>{node.iocType}</span>
        <span style={{ marginLeft: 'auto', width: 7, height: 7, borderRadius: '50%',
                       background: cc, flexShrink: 0, boxShadow: `0 0 4px ${cc}` }} />
      </div>
      <div style={{ fontFamily: 'monospace', fontSize: 10, color: '#67e8f9', fontWeight: 600,
                    overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
        {node.label}
      </div>
      <div style={{ marginTop: 2, fontSize: 7, color: '#1e3a5f' }}>
        C{node.cluster} · {node.actor ?? '—'}
      </div>
    </div>
  )
}

// ── Detail side panel ──────────────────────────────────────────────────────────

function DetailPanel({ node, onClose }: { node: GNode; onClose: () => void }) {
  const cisa = node.cisaEntry
  return (
    <div style={{
      position: 'absolute', right: 0, top: 0, bottom: 0, width: 280, zIndex: 10,
      background: 'rgba(5,10,22,0.98)', backdropFilter: 'blur(12px)',
      borderLeft: '1px solid rgba(255,255,255,0.07)',
      overflowY: 'auto', padding: '16px 14px',
    }}>
      <button onClick={onClose}
        style={{ position: 'absolute', top: 10, right: 10, background: 'none',
                 border: 'none', color: '#64748b', cursor: 'pointer', padding: 4 }}>
        <X size={14} />
      </button>

      {node.kind === 'actor' && cisa && (
        <>
          <div style={{ fontSize: 8, color: node.riskColor, fontWeight: 700,
                        textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 6 }}>
            Actor de Amenaza
          </div>
          <div style={{ fontSize: 14, fontWeight: 700, color: '#f1f5f9', marginBottom: 4 }}>
            {node.label}
          </div>
          <div style={{ fontSize: 9, color: '#64748b', marginBottom: 10 }}>
            {cisa.aliases.slice(0, 4).join(' · ')}
          </div>

          {[
            { l: 'País',       v: cisa.country },
            { l: 'Sponsor',    v: cisa.sponsor },
            { l: 'Motivación', v: cisa.motivation },
            { l: 'Riesgo',     v: cisa.risk_level },
          ].map(({ l, v }) => (
            <div key={l} style={{ marginBottom: 6 }}>
              <div style={{ fontSize: 7, color: '#334155', textTransform: 'uppercase',
                            fontWeight: 700, marginBottom: 1 }}>{l}</div>
              <div style={{ fontSize: 10, color: '#cbd5e1' }}>{v}</div>
            </div>
          ))}

          {cisa.cisa_advisories.length > 0 && (
            <div style={{ marginBottom: 8 }}>
              <div style={{ fontSize: 7, color: '#334155', textTransform: 'uppercase',
                            fontWeight: 700, marginBottom: 4 }}>Advisories CISA</div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                {cisa.cisa_advisories.map(a => (
                  <span key={a} style={{ fontSize: 8, color: '#22d3ee',
                    background: 'rgba(34,211,238,0.08)', border: '1px solid rgba(34,211,238,0.2)',
                    borderRadius: 4, padding: '2px 6px', fontWeight: 600 }}>{a}</span>
                ))}
              </div>
            </div>
          )}

          <div style={{ marginBottom: 8 }}>
            <div style={{ fontSize: 7, color: '#334155', textTransform: 'uppercase',
                          fontWeight: 700, marginBottom: 4 }}>Campañas conocidas</div>
            {cisa.known_campaigns.slice(0, 4).map(c => (
              <div key={c} style={{ fontSize: 9, color: '#94a3b8', marginBottom: 2,
                                    display: 'flex', alignItems: 'center', gap: 4 }}>
                <ChevronRight size={8} style={{ color: '#a78bfa', flexShrink: 0 }} /> {c}
              </div>
            ))}
          </div>

          <div style={{ marginBottom: 8 }}>
            <div style={{ fontSize: 7, color: '#334155', textTransform: 'uppercase',
                          fontWeight: 700, marginBottom: 4 }}>Sectores objetivo</div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 3 }}>
              {cisa.target_sectors.slice(0, 6).map(s => (
                <span key={s} style={{ fontSize: 7, color: '#94a3b8',
                  background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)',
                  borderRadius: 3, padding: '2px 5px' }}>{s}</span>
              ))}
            </div>
          </div>

          <div style={{ fontSize: 9, color: '#475569', lineHeight: 1.5,
                        borderTop: '1px solid rgba(255,255,255,0.05)', paddingTop: 8 }}>
            {cisa.description}
          </div>
        </>
      )}

      {node.kind === 'campaign' && (
        <>
          <div style={{ fontSize: 8, color: '#a78bfa', fontWeight: 700,
                        textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 6 }}>
            Campaña
          </div>
          <div style={{ fontSize: 13, fontWeight: 700, color: '#ddd6fe', marginBottom: 8 }}>
            {node.label}
          </div>
          <div style={{ fontSize: 10, color: '#64748b' }}>Actor atribuido</div>
          <div style={{ fontSize: 11, color: '#f1f5f9', marginTop: 2 }}>{node.actorName}</div>
        </>
      )}

      {node.kind === 'ioc' && (
        <>
          <div style={{ fontSize: 8, color: node.sevColor, fontWeight: 700,
                        textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 6 }}>
            Indicador de Compromiso
          </div>
          <div style={{ fontFamily: 'monospace', fontSize: 11, color: '#67e8f9',
                        wordBreak: 'break-all', marginBottom: 10, fontWeight: 600 }}>
            {node.fullLabel ?? node.label}
          </div>
          {[
            { l: 'Tipo',    v: node.iocType },
            { l: 'Severidad', v: node.severity?.toUpperCase() },
            { l: 'Actor',   v: node.actor },
            { l: 'Cluster ML', v: `Cluster ${node.cluster} (${node.clusterColor})` },
          ].map(({ l, v }) => (
            <div key={l} style={{ marginBottom: 6 }}>
              <div style={{ fontSize: 7, color: '#334155', textTransform: 'uppercase',
                            fontWeight: 700, marginBottom: 1 }}>{l}</div>
              <div style={{ fontSize: 10, color: '#cbd5e1' }}>{v}</div>
            </div>
          ))}
          <div style={{ marginTop: 8, padding: '8px 10px', borderRadius: 8,
                        background: `${node.clusterColor}12`,
                        border: `1px solid ${node.clusterColor}30` }}>
            <div style={{ fontSize: 8, color: node.clusterColor, fontWeight: 700, marginBottom: 3 }}>
              Cluster {node.cluster} — K-Means (k=5)
            </div>
            <div style={{ fontSize: 9, color: '#475569' }}>
              Agrupado por similitud de tipo, severidad, país y actor.
            </div>
          </div>
        </>
      )}
    </div>
  )
}

// ── Stats bar ──────────────────────────────────────────────────────────────────

function StatsBar({
  actors, iocs, campaigns, cisaMatches, clusterDist, filterActor, setFilterActor,
}: {
  actors: number; iocs: number; campaigns: number; cisaMatches: number
  clusterDist: number[]; filterActor: string; setFilterActor: (s: string) => void
}) {
  return (
    <div style={{
      display: 'flex', alignItems: 'center', gap: 20, padding: '8px 16px',
      borderBottom: '1px solid rgba(255,255,255,0.06)', flexWrap: 'wrap',
    }}>
      {[
        { l: 'Actores', v: actors, c: '#a855f7' },
        { l: 'Campañas', v: campaigns, c: '#a78bfa' },
        { l: 'IoCs', v: iocs, c: '#22d3ee' },
        { l: '✓ CISA', v: cisaMatches, c: '#4ade80' },
      ].map(s => (
        <div key={s.l} style={{ textAlign: 'center', minWidth: 60 }}>
          <div style={{ fontSize: 18, fontWeight: 800, color: s.c, lineHeight: 1 }}>{s.v}</div>
          <div style={{ fontSize: 8, color: '#334155', textTransform: 'uppercase',
                        letterSpacing: '0.06em', marginTop: 2 }}>{s.l}</div>
        </div>
      ))}

      <div style={{ display: 'flex', gap: 4, alignItems: 'center', marginLeft: 8 }}>
        <Filter size={9} style={{ color: '#334155' }} />
        {clusterDist.map((count, ci) => (
          <div key={ci} title={`Cluster ${ci}: ${count} IoCs`}
            style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 2 }}>
            <div style={{ width: 8, height: 8, borderRadius: '50%',
                          background: CLUSTER_COLORS[ci % CLUSTER_COLORS.length] }} />
            <span style={{ fontSize: 7, color: '#334155' }}>{count}</span>
          </div>
        ))}
      </div>

      <div style={{ flex: 1 }} />
      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
        <Filter size={10} style={{ color: '#334155' }} />
        <input
          value={filterActor}
          onChange={e => setFilterActor(e.target.value)}
          placeholder="Filtrar actor…"
          style={{
            background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)',
            borderRadius: 6, padding: '3px 8px', fontSize: 10, color: '#cbd5e1', outline: 'none',
            width: 120,
          }}
        />
      </div>
      <div style={{ fontSize: 8, color: '#1e293b' }}>CISA · MITRE ATT&CK · K-Means</div>
    </div>
  )
}

// ── Main component ─────────────────────────────────────────────────────────────

export default function ThreatGraph() {
  const { token } = useAuth()
  const [rawIocs,   setRawIocs]   = useState<RawIoc[]>([])
  const [rawActors, setRawActors] = useState<RawActor[]>([])
  const [cisaDb,    setCisaDb]    = useState<CisaEntry[]>([])
  const [loading,   setLoading]   = useState(true)
  const [error,     setError]     = useState('')
  const [selected,  setSelected]  = useState<GNode | null>(null)
  const [filterActor, setFilterActor] = useState('')
  const [nodeQuery, setNodeQuery] = useState('')
  const [zoom,   setZoom]   = useState(1)
  const [pan,    setPan]    = useState({ x: 0, y: 0 })
  const [dragging, setDragging] = useState(false)
  const viewportRef = useRef<HTMLDivElement>(null)
  const dragStart = useRef({ mx: 0, my: 0, px: 0, py: 0 })

  // K-Means clusters
  const clusters = useMemo(() => kMeans(rawIocs, 5), [rawIocs])

  // Filter
  const filteredIocs = useMemo(() =>
    filterActor
      ? rawIocs.filter(io => io.threat_actor?.toLowerCase().includes(filterActor.toLowerCase()))
      : rawIocs,
    [rawIocs, filterActor]
  )

  // Build graph
  const { nodes, edges, svgH } = useMemo(() =>
    buildGraph(filteredIocs, rawActors, cisaDb, clusters),
    [filteredIocs, rawActors, cisaDb, clusters]
  )

  const nodeMap = useMemo(() => new Map(nodes.map(n => [n.id, n])), [nodes])
  const SVG_W = 960
  const VIEW_H = 640

  const graphBounds = useMemo(() => {
    if (!nodes.length) return { minX: 0, minY: 0, maxX: SVG_W, maxY: svgH }
    return nodes.reduce((b, n) => ({
      minX: Math.min(b.minX, n.x),
      minY: Math.min(b.minY, n.y),
      maxX: Math.max(b.maxX, n.x + n.w),
      maxY: Math.max(b.maxY, n.y + n.h),
    }), { minX: Infinity, minY: Infinity, maxX: -Infinity, maxY: -Infinity })
  }, [nodes, svgH])

  const visibleNodes = useMemo(() => {
    const q = nodeQuery.trim().toLowerCase()
    if (!q) return nodes.slice(0, 80)
    return nodes.filter(n =>
      n.label.toLowerCase().includes(q) ||
      n.fullLabel?.toLowerCase().includes(q) ||
      n.actor?.toLowerCase().includes(q) ||
      n.actorName?.toLowerCase().includes(q) ||
      n.iocType?.toLowerCase().includes(q) ||
      n.severity?.toLowerCase().includes(q)
    ).slice(0, 80)
  }, [nodes, nodeQuery])

  // CISA match count
  const cisaMatches = useMemo(() => {
    const actorNodes = nodes.filter(n => n.kind === 'actor')
    return actorNodes.filter(n => n.cisaMatch).length
  }, [nodes])

  // Cluster distribution
  const clusterDist = useMemo(() => {
    const dist = new Array(5).fill(0)
    clusters.forEach(c => { dist[c % 5]++ })
    return dist
  }, [clusters])

  // Load data
  const load = useCallback(() => {
    const headers: Record<string, string> = token ? { Authorization: `Bearer ${token}` } : {}
    setLoading(true); setError('')
    Promise.all([
      fetch(`${API}/ioc-feed`,      { headers }).then(r => r.ok ? r.json() : []).catch(() => []),
      fetch(`${API}/threat-actors`, { headers }).then(r => r.ok ? r.json() : []).catch(() => []),
      fetch(`${API}/apt-database`,  { headers }).then(r => r.ok ? r.json() : []).catch(() => []),
    ]).then(([iocs, actors, cisa]) => {
      setRawIocs(Array.isArray(iocs) ? iocs : [])
      setRawActors(Array.isArray(actors) ? actors : [])
      setCisaDb(Array.isArray(cisa) ? cisa : [])
    }).catch(() => setError('Error al cargar datos'))
    .finally(() => setLoading(false))
  }, [token])

  useEffect(() => { load() }, [load])

  const centerOnNode = useCallback((node: GNode, nextZoom = Math.max(zoom, 0.85)) => {
    setSelected(node)
    setZoom(nextZoom)
    setPan({
      x: SVG_W / 2 - (node.x + node.w / 2) * nextZoom,
      y: VIEW_H / 2 - (node.y + node.h / 2) * nextZoom,
    })
  }, [zoom])

  const fitGraph = useCallback(() => {
    const width = Math.max(1, graphBounds.maxX - graphBounds.minX + 120)
    const height = Math.max(1, graphBounds.maxY - graphBounds.minY + 120)
    const nextZoom = Math.max(0.18, Math.min(1.15, Math.min(SVG_W / width, VIEW_H / height)))
    setZoom(nextZoom)
    setPan({
      x: (SVG_W - (graphBounds.minX + graphBounds.maxX) * nextZoom) / 2,
      y: (VIEW_H - (graphBounds.minY + graphBounds.maxY) * nextZoom) / 2,
    })
  }, [graphBounds])

  const resetView = () => {
    setZoom(1)
    setPan({ x: 0, y: 0 })
    setSelected(null)
  }

  const jumpToKind = (kind: GNode['kind']) => {
    const node = nodes.find(n => n.kind === kind)
    if (node) centerOnNode(node)
  }

  // Pan / zoom handlers
  const onWheel = useCallback((e: React.WheelEvent) => {
    e.preventDefault()
    if (e.ctrlKey || e.metaKey || e.altKey) {
      const rect = viewportRef.current?.getBoundingClientRect()
      const mx = rect ? e.clientX - rect.left : SVG_W / 2
      const my = rect ? e.clientY - rect.top : VIEW_H / 2
      setZoom(prev => {
        const next = Math.max(0.18, Math.min(2.8, prev * (e.deltaY > 0 ? 0.9 : 1.1)))
        const graphX = (mx - pan.x) / prev
        const graphY = (my - pan.y) / prev
        setPan({ x: mx - graphX * next, y: my - graphY * next })
        return next
      })
      return
    }
    setPan(p => ({
      x: p.x - e.deltaX,
      y: p.y - e.deltaY,
    }))
  }, [pan])

  const onMouseDown = useCallback((e: React.MouseEvent) => {
    if (e.button !== 0) return
    setDragging(true)
    dragStart.current = { mx: e.clientX, my: e.clientY, px: pan.x, py: pan.y }
  }, [pan])

  const onMouseMove = useCallback((e: React.MouseEvent) => {
    if (!dragging) return
    const dx = e.clientX - dragStart.current.mx
    const dy = e.clientY - dragStart.current.my
    setPan({ x: dragStart.current.px + dx, y: dragStart.current.py + dy })
  }, [dragging])

  const onMouseUp = useCallback(() => setDragging(false), [])

  const onMiniMapClick = useCallback((e: React.MouseEvent<HTMLDivElement>) => {
    const rect = e.currentTarget.getBoundingClientRect()
    const graphX = ((e.clientX - rect.left) / rect.width) * SVG_W
    const graphY = ((e.clientY - rect.top) / rect.height) * svgH
    setPan({
      x: SVG_W / 2 - graphX * zoom,
      y: VIEW_H / 2 - graphY * zoom,
    })
  }, [svgH, zoom])

  if (loading) return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: 24,
                  color: '#475569', fontSize: 13 }}>
      <RefreshCw size={16} style={{ animation: 'spin 1s linear infinite', color: '#22d3ee' }} />
      Construyendo grafo de correlación…
    </div>
  )
  if (error) return (
    <div style={{ padding: 20, color: '#ef4444', fontSize: 13 }}>{error}</div>
  )

  const actorCount    = nodes.filter(n => n.kind === 'actor').length
  const campaignCount = nodes.filter(n => n.kind === 'campaign').length
  const iocCount      = nodes.filter(n => n.kind === 'ioc').length

  return (
    <div style={{
      background: 'rgba(5,8,20,0.98)', borderRadius: 14, overflow: 'hidden',
      border: '1px solid rgba(255,255,255,0.06)',
      boxShadow: '0 4px 40px rgba(0,0,0,0.4)',
      position: 'relative', userSelect: 'none',
    }}>
      {/* Header */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 10, padding: '10px 16px',
        borderBottom: '1px solid rgba(255,255,255,0.05)',
        background: 'rgba(0,0,0,0.3)',
      }}>
        <Shield size={14} style={{ color: '#a855f7' }} />
        <span style={{ fontSize: 12, fontWeight: 700, color: '#e2e8f0' }}>
          Grafo de Correlación CTI
        </span>
        <span style={{ fontSize: 9, color: '#334155', marginLeft: 4 }}>
          Actores → Campañas → IoCs · K-Means · CISA
        </span>
        <div style={{ flex: 1 }} />
        <div style={{ position: 'relative', width: 210 }}>
          <Search size={11} style={{
            position: 'absolute', left: 8, top: '50%', transform: 'translateY(-50%)',
            color: '#334155', pointerEvents: 'none',
          }} />
          <input
            value={nodeQuery}
            onChange={e => setNodeQuery(e.target.value)}
            placeholder="Saltar a actor, CVE, IOC…"
            style={{
              width: '100%', height: 26, background: 'rgba(255,255,255,0.04)',
              border: '1px solid rgba(255,255,255,0.08)', borderRadius: 7,
              color: '#cbd5e1', outline: 'none', fontSize: 10,
              padding: '0 8px 0 24px',
            }}
          />
          {nodeQuery.trim() && visibleNodes.length > 0 && (
            <div style={{
              position: 'absolute', right: 0, top: 30, width: 280, maxHeight: 260,
              overflowY: 'auto', zIndex: 30, background: 'rgba(5,10,22,0.98)',
              border: '1px solid rgba(255,255,255,0.08)', borderRadius: 8,
              boxShadow: '0 18px 36px rgba(0,0,0,0.4)', padding: 4,
            }}>
              {visibleNodes.map(node => (
                <button
                  key={node.id}
                  onClick={() => {
                    centerOnNode(node)
                    setNodeQuery('')
                  }}
                  style={{
                    width: '100%', display: 'grid', gridTemplateColumns: '54px 1fr',
                    gap: 8, alignItems: 'center', textAlign: 'left', padding: '6px 7px',
                    border: 0, borderRadius: 6, background: selected?.id === node.id ? 'rgba(34,211,238,0.1)' : 'transparent',
                    color: '#cbd5e1', cursor: 'pointer',
                  }}
                >
                  <span style={{
                    fontSize: 8, fontWeight: 800, textTransform: 'uppercase',
                    color: node.kind === 'ioc' ? '#22d3ee' : node.kind === 'actor' ? '#a855f7' : '#a78bfa',
                  }}>{node.kind}</span>
                  <span style={{
                    fontSize: 10, fontFamily: node.kind === 'ioc' ? 'monospace' : undefined,
                    overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                  }}>{node.fullLabel ?? node.label}</span>
                </button>
              ))}
            </div>
          )}
        </div>
        {/* Zoom controls */}
        <div style={{ display: 'flex', gap: 4 }}>
          {[
            { icon: <ZoomIn size={12} />,    action: () => setZoom(z => Math.min(2.5, z + 0.15)) },
            { icon: <ZoomOut size={12} />,   action: () => setZoom(z => Math.max(0.18, z - 0.15)) },
            { icon: <Maximize2 size={12} />, action: fitGraph },
            { icon: <RefreshCw size={12} />, action: load },
          ].map((btn, i) => (
            <button key={i} onClick={btn.action} style={{
              background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)',
              borderRadius: 6, padding: '4px 6px', color: '#64748b', cursor: 'pointer',
              display: 'flex', alignItems: 'center',
            }}>{btn.icon}</button>
          ))}
          <button onClick={resetView} style={{
            background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)',
            borderRadius: 6, padding: '4px 7px', color: '#64748b', cursor: 'pointer',
            fontSize: 9, fontWeight: 800,
          }}>1:1</button>
        </div>
      </div>

      {/* Stats bar */}
      <StatsBar
        actors={actorCount} iocs={iocCount} campaigns={campaignCount}
        cisaMatches={cisaMatches} clusterDist={clusterDist}
        filterActor={filterActor} setFilterActor={setFilterActor}
      />

      <div style={{
        display: 'flex', alignItems: 'center', gap: 6, padding: '6px 16px',
        borderBottom: '1px solid rgba(255,255,255,0.04)', background: 'rgba(0,0,0,0.16)',
      }}>
        {[
          { label: 'Actores', kind: 'actor' as const },
          { label: 'Campañas', kind: 'campaign' as const },
          { label: 'IoC / CVE', kind: 'ioc' as const },
        ].map(item => (
          <button key={item.kind} onClick={() => jumpToKind(item.kind)}
            style={{
              background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.07)',
              borderRadius: 6, color: '#64748b', cursor: 'pointer', fontSize: 9,
              fontWeight: 700, padding: '4px 8px',
            }}>
            {item.label}
          </button>
        ))}
        <span style={{ marginLeft: 'auto', fontSize: 8, color: '#334155' }}>
          Rueda: desplazar · Ctrl/⌘/Alt + rueda: zoom · arrastrar: mover
        </span>
      </div>

      {/* Zone labels row */}
      <div style={{
        display: 'grid', gridTemplateColumns: '1fr 1fr 1fr',
        padding: '6px 0', background: 'rgba(0,0,0,0.2)',
        borderBottom: '1px solid rgba(255,255,255,0.04)',
      }}>
        {[
          { label: 'Actores / APTs', icon: <Shield size={9} />, color: '#a855f7', desc: `${actorCount} actores · enriquecidos CISA` },
          { label: 'Campañas',       icon: <Layers size={9} />, color: '#a78bfa', desc: `${campaignCount} campañas atribuidas` },
          { label: 'Indicadores',    icon: <Activity size={9} />, color: '#22d3ee', desc: `${iocCount} IoCs · ${CLUSTER_COLORS.length} clusters K-Means` },
        ].map((z, i) => (
          <div key={i} style={{ textAlign: 'center', padding: '2px 8px' }}>
            <div style={{ display: 'inline-flex', alignItems: 'center', gap: 4,
                          color: z.color, fontSize: 9, fontWeight: 700 }}>
              {z.icon} {z.label}
            </div>
            <div style={{ fontSize: 7, color: '#1e3a5f', marginTop: 1 }}>{z.desc}</div>
          </div>
        ))}
      </div>

      {/* Graph canvas */}
      <div ref={viewportRef} style={{ position: 'relative', height: VIEW_H, overflow: 'hidden' }}>
        <svg
          width="100%" height="100%"
          viewBox={`0 0 ${SVG_W} ${VIEW_H}`}
          style={{ cursor: dragging ? 'grabbing' : 'grab' }}
          onWheel={onWheel}
          onMouseDown={onMouseDown}
          onMouseMove={onMouseMove}
          onMouseUp={onMouseUp}
          onMouseLeave={onMouseUp}
        >
          <defs>
            {/* Animated edge gradient */}
            <marker id="arr" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto">
              <path d="M0,0 L0,6 L6,3 z" fill="#334155" />
            </marker>
            {/* Zone gradients */}
            {ZONE_COLORS_DEF.map(([id, c1, c2]) => (
              <linearGradient key={id} id={id} x1="0%" y1="0%" x2="100%" y2="0%">
                <stop offset="0%" stopColor={c1} />
                <stop offset="100%" stopColor={c2} />
              </linearGradient>
            ))}
            <style>{`
              @keyframes dash { to { stroke-dashoffset: -20; } }
              .edge-animated { animation: dash 2s linear infinite; }
            `}</style>
          </defs>

          <g transform={`translate(${pan.x},${pan.y}) scale(${zoom})`}>
            {/* Zone backgrounds */}
            {[
              { x: ZONE_X.actor - 10,    w: NODE_W.actor + 20,    fill: 'rgba(167,139,250,0.025)' },
              { x: ZONE_X.campaign - 10, w: NODE_W.campaign + 20, fill: 'rgba(251,146,60,0.02)' },
              { x: ZONE_X.ioc - 10,      w: NODE_W.ioc + 20,      fill: 'rgba(34,211,238,0.02)' },
            ].map((z, i) => (
              <rect key={i} x={z.x} y={0} width={z.w} height={svgH} fill={z.fill}
                    rx={8} />
            ))}

            {/* Zone separator lines */}
            {[ZONE_X.campaign - 15, ZONE_X.ioc - 15].map((x, i) => (
              <line key={i} x1={x} y1={20} x2={x} y2={svgH - 20}
                    stroke="rgba(255,255,255,0.04)" strokeWidth={1} strokeDasharray="4 6" />
            ))}

            {/* Edges */}
            {edges.map(edge => {
              const src = nodeMap.get(edge.source)
              const tgt = nodeMap.get(edge.target)
              if (!src || !tgt) return null
              const d = edgePath(src, tgt)
              return (
                <path key={edge.id} d={d} fill="none"
                      stroke={edge.color} strokeWidth={1.2}
                      strokeDasharray={edge.dashed ? '5 4' : undefined}
                      strokeOpacity={0.55}
                      className={edge.animated ? 'edge-animated' : undefined}
                      markerEnd={edge.animated ? 'url(#arr)' : undefined}
                />
              )
            })}

            {/* Nodes via foreignObject */}
            {nodes.map(node => (
              <foreignObject
                key={node.id}
                x={node.x} y={node.y}
                width={node.w} height={node.h}
                overflow="visible"
              >
                <div style={{ width: node.w, height: node.h }}>
                  {node.kind === 'actor' && (
                    <ActorCard node={node} selected={selected?.id === node.id}
                      onClick={() => setSelected(prev => prev?.id === node.id ? null : node)} />
                  )}
                  {node.kind === 'campaign' && (
                    <CampaignCard node={node} selected={selected?.id === node.id}
                      onClick={() => setSelected(prev => prev?.id === node.id ? null : node)} />
                  )}
                  {node.kind === 'ioc' && (
                    <IocCard node={node} selected={selected?.id === node.id}
                      onClick={() => setSelected(prev => prev?.id === node.id ? null : node)} />
                  )}
                </div>
              </foreignObject>
            ))}
          </g>
        </svg>

        <div
          onClick={onMiniMapClick}
          style={{
            position: 'absolute', left: 12, bottom: 12, width: 168, height: 112,
            background: 'rgba(2,6,23,0.88)', border: '1px solid rgba(255,255,255,0.09)',
            borderRadius: 8, zIndex: 8, cursor: 'crosshair', overflow: 'hidden',
            boxShadow: '0 10px 24px rgba(0,0,0,0.35)',
          }}
        >
          <svg width="100%" height="100%" viewBox={`0 0 ${SVG_W} ${svgH}`} preserveAspectRatio="none">
            <rect x="0" y="0" width={SVG_W} height={svgH} fill="rgba(15,23,42,0.62)" />
            {nodes.map(node => (
              <rect
                key={node.id}
                x={node.x} y={node.y} width={node.w} height={node.h}
                rx={4}
                fill={node.kind === 'ioc' ? (node.clusterColor ?? '#22d3ee') : node.kind === 'actor' ? '#a855f7' : '#a78bfa'}
                opacity={node.kind === 'ioc' ? 0.58 : 0.85}
              />
            ))}
            <rect
              x={Math.max(0, -pan.x / zoom)}
              y={Math.max(0, -pan.y / zoom)}
              width={SVG_W / zoom}
              height={VIEW_H / zoom}
              fill="rgba(34,211,238,0.12)"
              stroke="#22d3ee"
              strokeWidth={8 / zoom}
            />
          </svg>
        </div>

        {/* Detail panel */}
        {selected && <DetailPanel node={selected} onClose={() => setSelected(null)} />}
      </div>

      {/* Legend footer */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 16, padding: '7px 16px', flexWrap: 'wrap',
        borderTop: '1px solid rgba(255,255,255,0.05)', background: 'rgba(0,0,0,0.2)',
      }}>
        {[
          { c: '#a855f7', l: 'Actor APT' },
          { c: '#a78bfa', l: 'Campaña' },
          { c: '#22d3ee', l: 'IoC' },
          { c: '#4ade80', l: '✓ Verificado CISA' },
        ].map(({ c, l }) => (
          <div key={l} style={{ display: 'flex', alignItems: 'center', gap: 5,
                                fontSize: 9, color: '#475569' }}>
            <span style={{ width: 8, height: 8, borderRadius: '50%', background: c }} />
            {l}
          </div>
        ))}
        <span style={{ fontSize: 8, color: '#0f172a', marginLeft: 'auto' }}>
          K-Means k=5 · 40 iteraciones · features: tipo · severidad · país · actor · MITRE
        </span>
      </div>
    </div>
  )
}

// helper constant (avoid object literal in JSX)
const ZONE_COLORS_DEF: [string, string, string][] = [
  ['zg-actor',    'rgba(167,139,250,0.05)', 'rgba(167,139,250,0)'],
  ['zg-campaign', 'rgba(251,146,60,0.04)',  'rgba(251,146,60,0)'],
  ['zg-ioc',      'rgba(34,211,238,0.04)',  'rgba(34,211,238,0)'],
]

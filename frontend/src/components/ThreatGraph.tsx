import { useEffect, useState } from 'react'
import ReactFlow, { Background, Controls } from 'reactflow'
import type { Node, Edge } from 'reactflow'
import 'reactflow/dist/style.css'

const API_URL = import.meta.env.VITE_API_URL ?? 'http://127.0.0.1:8000'

const SEVERITY_COLORS: Record<string, { bg: string; border: string }> = {
  critical: { bg: '#7f1d1d', border: '#ef4444' },
  high:     { bg: '#78350f', border: '#f97316' },
  medium:   { bg: '#1e3a5f', border: '#3b82f6' },
  low:      { bg: '#14532d', border: '#22c55e' },
}

const ACTOR_STYLE = { bg: '#3b0764', border: '#a855f7' }
const CAMPAIGN_STYLE = { bg: '#1c1917', border: '#78716c' }

function nodeStyle(bg: string, border: string) {
  return { background: bg, color: 'white', border: `1px solid ${border}`, borderRadius: 8, fontSize: 12 }
}

interface IOC {
  id: number
  ioc: string
  type: string
  threat_actor: string
  severity: string
  mitre: string
}

interface Actor {
  id: number
  name: string
  active_campaign: string
  country: string
  motivation: string
}

function buildGraph(iocs: IOC[], actors: Actor[]): { nodes: Node[]; edges: Edge[] } {
  const nodes: Node[] = []
  const edges: Edge[] = []
  const actorNodeIds = new Map<string, string>()
  const campaignNodeIds = new Map<string, string>()

  // Actor nodes
  actors.forEach((actor, i) => {
    const id = `actor-${actor.id}`
    actorNodeIds.set(actor.name, id)
    nodes.push({
      id,
      position: { x: 50, y: i * 160 + 50 },
      data: { label: `${actor.name}\n(${actor.country})` },
      style: nodeStyle(ACTOR_STYLE.bg, ACTOR_STYLE.border)
    })
  })

  // IOC nodes
  iocs.forEach((ioc, i) => {
    const id = `ioc-${ioc.id}`
    const colors = SEVERITY_COLORS[ioc.severity] ?? SEVERITY_COLORS.medium
    nodes.push({
      id,
      position: { x: 320, y: i * 140 + 30 },
      data: { label: `${ioc.ioc}\n[${ioc.type}] ${ioc.mitre}` },
      style: nodeStyle(colors.bg, colors.border)
    })

    const actorId = actorNodeIds.get(ioc.threat_actor)
    if (actorId) {
      edges.push({ id: `e-${actorId}-${id}`, source: actorId, target: id, animated: true })
    }
  })

  // Campaign nodes (unique)
  actors.forEach(actor => {
    if (!actor.active_campaign) return
    if (campaignNodeIds.has(actor.active_campaign)) return

    const id = `campaign-${campaignNodeIds.size}`
    campaignNodeIds.set(actor.active_campaign, id)
    nodes.push({
      id,
      position: { x: 620, y: campaignNodeIds.size * 160 + 30 },
      data: { label: actor.active_campaign },
      style: nodeStyle(CAMPAIGN_STYLE.bg, CAMPAIGN_STYLE.border)
    })

    const actorId = actorNodeIds.get(actor.name)
    if (actorId) {
      edges.push({ id: `e-${actorId}-${id}`, source: actorId, target: id, animated: false })
    }
  })

  return { nodes, edges }
}

function ThreatGraph() {
  const [nodes, setNodes] = useState<Node[]>([])
  const [edges, setEdges] = useState<Edge[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    Promise.all([
      fetch(`${API_URL}/ioc-feed`).then(r => r.json()),
      fetch(`${API_URL}/threat-actors`).then(r => r.json())
    ])
      .then(([iocs, actors]) => {
        const { nodes, edges } = buildGraph(iocs, actors)
        setNodes(nodes)
        setEdges(edges)
      })
      .catch(() => setError('Failed to load threat data'))
      .finally(() => setLoading(false))
  }, [])

  if (loading) return <div className="text-slate-400 text-sm p-4">Loading threat graph...</div>
  if (error) return <div className="text-red-400 text-sm p-4">{error}</div>

  return (
    <div style={{ width: '100%', height: '500px' }}>
      <ReactFlow nodes={nodes} edges={edges} fitView>
        <Background />
        <Controls />
      </ReactFlow>
    </div>
  )
}

export default ThreatGraph

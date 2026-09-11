"""
Shared graph-building utilities for the threat correlation graph.
Both claude_fusion_engine and gemini_engine use these helpers so neither
needs to import from the other.
"""
from __future__ import annotations

import json


def extract_graph_data(events: list[dict]) -> tuple[dict, dict, dict, list, list]:
    """
    Parse raw threat events into actor/IOC frequency maps.
    Returns (actor_counts, ioc_counts, tactic_by_actor, top_actors, top_iocs).
    """
    actor_counts: dict[str, int] = {}
    ioc_counts: dict[str, list[str]] = {}
    tactic_by_actor: dict[str, list[str]] = {}

    for ev in events:
        actor = (ev.get("threatActor") or "").strip()
        ioc = (ev.get("ioc") or "").strip()
        tactic = (ev.get("mitreTactic") or "").strip()
        if actor and actor not in ("Unknown", "N/A", ""):
            actor_counts[actor] = actor_counts.get(actor, 0) + 1
            if tactic:
                tactic_by_actor.setdefault(actor, [])
                if tactic not in tactic_by_actor[actor]:
                    tactic_by_actor[actor].append(tactic)
        if ioc and ioc not in ("N/A", "—", ""):
            ioc_counts.setdefault(ioc, [])
            if actor and actor not in ioc_counts[ioc]:
                ioc_counts[ioc].append(actor)

    top_actors = sorted(actor_counts, key=lambda a: actor_counts[a], reverse=True)[:8]
    top_iocs = sorted(ioc_counts, key=lambda i: len(ioc_counts[i]), reverse=True)[:12]
    return actor_counts, ioc_counts, tactic_by_actor, top_actors, top_iocs


def enrich_with_cisa(top_actors: list[str]) -> dict[str, dict]:
    """Match actors against the CISA APT database."""
    from intelligence.apt_database import match_actor_to_database
    return {
        actor: match
        for actor in top_actors
        if (match := match_actor_to_database(actor))
    }


def build_actor_profiles(
    top_actors: list[str],
    actor_counts: dict[str, int],
    tactic_by_actor: dict[str, list[str]],
    cisa_enrichment: dict[str, dict],
) -> list[dict]:
    """Build actor profile dicts used as AI prompt context."""
    profiles = []
    for actor in top_actors:
        cisa = cisa_enrichment.get(actor)
        profile: dict = {
            "name": actor,
            "events": actor_counts[actor],
            "tactics": tactic_by_actor.get(actor, []),
        }
        if cisa:
            profile["cisa_country"] = cisa["country"]
            profile["cisa_risk"] = cisa["risk_level"]
            profile["cisa_campaigns"] = cisa["known_campaigns"][:3]
            profile["cisa_advisory"] = cisa.get("cisa_advisories", [])[:2]
        profiles.append(profile)
    return profiles


def build_graph_nodes_edges(
    top_actors: list[str],
    top_iocs: list[str],
    campaigns: list[dict],
    correlations: list[dict],
    summary: str,
    actor_counts: dict[str, int],
    ioc_counts: dict[str, list[str]],
    tactic_by_actor: dict[str, list[str]],
    cisa_enrichment: dict[str, dict],
) -> dict:
    """Assemble the ReactFlow-compatible nodes + edges and return the full graph payload."""
    nodes: list[dict] = []
    edges: list[dict] = []
    edge_counter = 0

    def add_edge(src: str, tgt: str, label: str, animated: bool = False, color: str = "#475569"):
        nonlocal edge_counter
        edge_counter += 1
        edges.append({
            "id": f"e{edge_counter}",
            "source": src,
            "target": tgt,
            "label": label,
            "animated": animated,
            "style": {"stroke": color, "strokeWidth": 1.5},
            "labelStyle": {"fill": "#94a3b8", "fontSize": 9},
        })

    # Actor nodes — left column
    for i, actor in enumerate(top_actors):
        cisa = cisa_enrichment.get(actor)
        risk = cisa["risk_level"] if cisa else ("High" if actor_counts[actor] > 3 else "Medium")
        risk_color = {
            "Critical": "#ef4444",
            "High": "#f97316",
            "Medium": "#facc15",
            "Low": "#4ade80",
        }.get(risk, "#94a3b8")
        nodes.append({
            "id": f"actor:{actor}",
            "type": "actor",
            "position": {"x": 50, "y": i * 130 + 40},
            "data": {
                "label": actor,
                "nodeType": "actor",
                "country": cisa["country"] if cisa else "Desconocido",
                "motivation": cisa["motivation"] if cisa else "No atribuido",
                "risk": risk,
                "riskColor": risk_color,
                "eventCount": actor_counts[actor],
                "tactics": tactic_by_actor.get(actor, [])[:3],
                "cisaMatch": bool(cisa),
                "cisaAdvisories": cisa["cisa_advisories"][:2] if cisa else [],
                "cisaAliases": cisa["aliases"][:3] if cisa else [],
                "knownCampaigns": cisa["known_campaigns"][:3] if cisa else [],
                "sponsor": cisa.get("sponsor", "") if cisa else "",
            },
        })

    # Campaign nodes — center column
    for i, camp in enumerate(campaigns[:6]):
        camp_id = f"campaign:{camp['id']}"
        nodes.append({
            "id": camp_id,
            "type": "campaign",
            "position": {"x": 400, "y": i * 110 + 40},
            "data": {
                "label": camp["name"],
                "nodeType": "campaign",
                "description": camp.get("description", ""),
                "timeframe": camp.get("timeframe", ""),
                "attributedActors": camp.get("attributed_actors", []),
            },
        })
        for actor_name in camp.get("attributed_actors", []):
            if any(n["id"] == f"actor:{actor_name}" for n in nodes):
                add_edge(f"actor:{actor_name}", camp_id, "conducts", animated=True, color="#a78bfa")

    # IOC nodes — right column
    for i, ioc in enumerate(top_iocs[:10]):
        ioc_id = f"ioc:{ioc}"
        ioc_actors = ioc_counts.get(ioc, [])
        nodes.append({
            "id": ioc_id,
            "type": "ioc",
            "position": {"x": 750, "y": i * 80 + 40},
            "data": {
                "label": ioc[:35] + ("…" if len(ioc) > 35 else ""),
                "fullIoc": ioc,
                "nodeType": "ioc",
                "usedBy": ioc_actors,
            },
        })
        for actor_name in ioc_actors:
            if any(n["id"] == f"actor:{actor_name}" for n in nodes):
                add_edge(f"actor:{actor_name}", ioc_id, "usa", animated=False, color="#22d3ee")
        for camp in campaigns:
            if ioc in camp.get("iocs_generated", []):
                camp_id = f"campaign:{camp['id']}"
                if any(n["id"] == camp_id for n in nodes):
                    add_edge(camp_id, ioc_id, "genera", animated=False, color="#4ade80")

    return {
        "nodes": nodes,
        "edges": edges,
        "crossCorrelations": correlations,
        "summary": summary,
        "cisaMatchCount": len(cisa_enrichment),
        "totalActors": len(top_actors),
        "totalIocs": len(top_iocs),
        "totalCampaigns": len(campaigns),
    }

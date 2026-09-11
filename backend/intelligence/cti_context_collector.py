"""
CTI Lab Context Collector — agrega toda la inteligencia interna del lab
para que el motor de fusión opere sobre datos reales en lugar de solo
datos enviados por el frontend.

Funciones principales:
  collect_lab_context()   → snapshot completo del lab (IOCs, actores, campañas, IOAs)
  iocs_to_threat_events() → convierte IOC feed al formato de eventos del motor AI
  correlate_across_feeds()→ detecta IOCs que aparecen en múltiples fuentes
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Any


# ── Snapshot principal ─────────────────────────────────────────────────────────

def collect_lab_context(max_iocs: int = 150) -> dict:
    """
    Agrega todos los datos internos del CTI Lab en un snapshot estructurado.
    El motor de fusión usa esto para anclar el análisis AI en datos reales.
    """
    from db import get_conn
    from intelligence.threat_engine import get_threat_feed
    from intelligence.actor_engine import get_threat_actors
    from intelligence.campaign_engine import get_campaigns
    from intelligence.ioa_engine import get_ioas
    from services.live_service import live_service

    iocs      = get_threat_feed()
    actors    = get_threat_actors()
    campaigns = get_campaigns()
    ioas      = get_ioas()
    live_evts = live_service.get_history(200)

    # ── Estadísticas del feed de IOCs ─────────────────────────────────────────
    ioc_by_source   = Counter(i.get("source", "unknown") for i in iocs)
    ioc_by_type     = Counter(i.get("type", "unknown") for i in iocs)
    ioc_by_severity = Counter((i.get("severity") or "unknown").lower() for i in iocs)
    ioc_by_actor    = Counter(i.get("threat_actor", "Unknown") for i in iocs)
    ioc_by_mitre    = Counter(i.get("mitre", "") for i in iocs if i.get("mitre"))

    # ── Correlación multi-fuente: IOCs vistos en >1 feed ─────────────────────
    _ioc_sources: dict[str, set[str]] = {}
    for ioc in iocs:
        val = (ioc.get("ioc") or "").strip()
        src = ioc.get("source", "unknown")
        if val:
            _ioc_sources.setdefault(val, set()).add(src)

    cross_feed = sorted(
        [
            {"ioc": val, "sources": sorted(srcs), "feed_count": len(srcs)}
            for val, srcs in _ioc_sources.items()
            if len(srcs) > 1
        ],
        key=lambda x: x["feed_count"],
        reverse=True,
    )

    # ── Actores con recuento de IOCs ──────────────────────────────────────────
    actor_ioc_map = {
        actor: cnt
        for actor, cnt in ioc_by_actor.most_common(15)
        if actor not in ("Unknown", "N/A", "")
    }

    # ── Datos de log datasets y IOCs recientes (24h) ─────────────────────────
    with get_conn() as conn:
        log_ds_rows = conn.execute("""
            SELECT id, name, description, source, created_at
            FROM datasets
            WHERE source LIKE 'log_ingest:%' OR source LIKE 'log:%'
            ORDER BY created_at DESC
            LIMIT 15
        """).fetchall()

        recent_ioc_rows = conn.execute("""
            SELECT ioc, type, threat_actor, severity, mitre, source, created_at
            FROM iocs
            WHERE created_at >= datetime('now', '-24 hours')
            ORDER BY created_at DESC
            LIMIT 100
        """).fetchall()

        log_ds_count = conn.execute(
            "SELECT COUNT(*) FROM datasets WHERE source LIKE 'log_ingest:%'"
        ).fetchone()[0]

        # Tendencia: IOCs nuevos por fuente en las últimas 24h
        feed_trend_rows = conn.execute("""
            SELECT source, COUNT(*) as cnt
            FROM iocs
            WHERE created_at >= datetime('now', '-24 hours')
            GROUP BY source
            ORDER BY cnt DESC
            LIMIT 10
        """).fetchall()

    recent_iocs_24h = [dict(r) for r in recent_ioc_rows]
    feed_trend_24h  = {r["source"]: r["cnt"] for r in feed_trend_rows}

    return {
        "collected_at": datetime.utcnow().isoformat() + "Z",
        "summary": {
            "total_iocs":        len(iocs),
            "total_actors":      len(actors),
            "total_campaigns":   len(campaigns),
            "total_ioas":        len(ioas),
            "multi_feed_iocs":   len(cross_feed),
            "recent_iocs_24h":   len(recent_iocs_24h),
            "log_datasets":      log_ds_count,
            "live_events_buffered": len(live_evts),
        },
        "ioc_stats": {
            "by_source":       dict(ioc_by_source.most_common(20)),
            "by_type":         dict(ioc_by_type),
            "by_severity":     dict(ioc_by_severity),
            "top_actors":      dict(ioc_by_actor.most_common(10)),
            "top_mitre_ttps":  dict(ioc_by_mitre.most_common(15)),
            "feed_trend_24h":  feed_trend_24h,
        },
        "cross_feed_correlations": cross_feed[:40],
        "actor_ioc_map":           actor_ioc_map,
        "top_iocs_sample":         iocs[:max_iocs],
        "actors":                  actors[:25],
        "campaigns":               campaigns[:20],
        "ioas":                    ioas[:30],
        "recent_iocs_24h":         recent_iocs_24h,
        "log_datasets":            [dict(r) for r in log_ds_rows],
        "live_events_sample":      live_evts[-30:] if live_evts else [],
    }


# ── Adaptadores de formato ─────────────────────────────────────────────────────

def iocs_to_threat_events(iocs: list[dict]) -> list[dict]:
    """
    Convierte registros del IOC feed al formato de eventos que usan las
    funciones del motor de fusión (generate_fusion_report, generate_predictive_analysis, etc.).
    """
    _sev_map = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"}
    events: list[dict] = []
    for idx, ioc in enumerate(iocs):
        raw_sev = (ioc.get("severity") or "medium").strip().lower()
        severity = _sev_map.get(raw_sev, "Medium")
        actor = ioc.get("threat_actor") or "Unknown"
        ioc_val = ioc.get("ioc", "")
        ioc_type = ioc.get("type", "Unknown")
        events.append({
            "id":               str(idx + 1),
            "timestamp":        ioc.get("created_at", ""),
            "ioc":              ioc_val,
            "threatType":       ioc_type,
            "severity":         severity,
            "sourceCountry":    ioc.get("country", "Unknown"),
            "targetCountry":    "",
            "threatActor":      actor,
            "threatName":       ioc.get("family") or ioc.get("tags", "").split(",")[0] or actor,
            "mitreTactic":      "",
            "mitreTechniqueId": ioc.get("mitre", ""),
            "mitreTechniqueName": "",
            "informationSource": ioc.get("source", "cti-lab"),
            "description": (
                f"{ioc_type} · {ioc_val} · Actor: {actor}"
                + (f" · Tags: {ioc.get('tags','')}" if ioc.get("tags") else "")
            ),
            "confidenceScore":  float(ioc.get("confidence", 70)),
            "isFalsePositive":  False,
        })
    return events


def correlate_across_feeds(iocs: list[dict]) -> dict:
    """
    Analiza el feed de IOCs y detecta:
    - IOCs compartidos entre múltiples fuentes (alta confianza)
    - Actores que aparecen en más de un feed
    - Técnicas MITRE más frecuentes por fuente
    """
    ioc_source_map: dict[str, list[str]] = {}
    actor_source_map: dict[str, set[str]] = {}
    mitre_by_source: dict[str, Counter] = {}

    for ioc in iocs:
        val    = (ioc.get("ioc") or "").strip()
        src    = ioc.get("source", "unknown")
        actor  = ioc.get("threat_actor", "Unknown")
        mitre  = ioc.get("mitre", "")

        if val:
            ioc_source_map.setdefault(val, []).append(src)
        if actor and actor not in ("Unknown", "N/A"):
            actor_source_map.setdefault(actor, set()).add(src)
        if mitre and src:
            mitre_by_source.setdefault(src, Counter())[mitre] += 1

    shared_iocs = [
        {"ioc": val, "sources": srcs, "confidence_boost": len(srcs) * 15}
        for val, srcs in ioc_source_map.items()
        if len(srcs) > 1
    ]
    shared_iocs.sort(key=lambda x: len(x["sources"]), reverse=True)

    multi_feed_actors = [
        {"actor": actor, "feeds": sorted(feeds), "feed_count": len(feeds)}
        for actor, feeds in actor_source_map.items()
        if len(feeds) > 1
    ]
    multi_feed_actors.sort(key=lambda x: x["feed_count"], reverse=True)

    return {
        "shared_iocs":         shared_iocs[:50],
        "multi_feed_actors":   multi_feed_actors[:20],
        "mitre_by_source":     {src: dict(ctr.most_common(5)) for src, ctr in mitre_by_source.items()},
        "total_shared_iocs":   len(shared_iocs),
        "total_multi_actors":  len(multi_feed_actors),
    }

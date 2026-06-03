from __future__ import annotations

import asyncio
import csv
import io
import json
import os
import re
import uuid
import zipfile
from collections import Counter
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

import requests
import anthropic
from fastapi import Body, FastAPI, File, Form, Header, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse

from db import init_db, get_conn
from auth import register, login, verify_token
from intelligence.threat_engine import get_threat_feed, add_uploaded_iocs
from intelligence.actor_engine import get_threat_actors
from intelligence.campaign_engine import get_campaigns
from intelligence.misp_engine import fetch_misp_iocs, get_misp_status
from ai.ai_engine import analyze_ioc
from services.findings_service import get_findings, add_finding
from services.upload_service import parse_upload
from services.enrichment_service import enrich_ioc
from intelligence.ioa_engine import get_ioas, TTP_IOA_MAP
from intelligence.feeds_engine import FETCH_REGISTRY, PUBLIC_FEEDS
from intelligence.defend_engine import compute_depuration
from intelligence.log_engine import parse_logs, extract_iocs, detect_format
from services.live_service import live_service
from ai.gemini_engine import (
    GeminiNotConfiguredError,
    generate_threat_data as _gemini_threat_data,
    generate_quantum_threat_analysis as _gemini_quantum,
    generate_predictive_analysis as _gemini_predictive,
    generate_fusion_report as _gemini_fusion_report,
    generate_mitre_details as _gemini_mitre,
    generate_welcome_data as _gemini_welcome,
    query_ioc_context as _gemini_ioc_context,
    generate_weekly_flash_report as _gemini_weekly,
    extract_entities_from_text as _gemini_extract,
    assess_colombian_risk as _gemini_colombia,
    generate_crisis_map as _gemini_crisis,
    generate_team_scenarios as _gemini_scenarios,
    generate_behavioral_analysis as _gemini_behavioral,
    generate_playbook as _gemini_playbook,
    generate_ml_proposals as _gemini_ml,
    generate_geopolitical_analysis as _gemini_geo,
    generate_threat_graph as _gemini_graph,
)
from ai.claude_fusion_engine import (
    ClaudeNotConfiguredError,
    generate_threat_data as _claude_threat_data,
    generate_quantum_threat_analysis as _claude_quantum,
    generate_predictive_analysis as _claude_predictive,
    generate_fusion_report as _claude_fusion_report,
    generate_mitre_details as _claude_mitre,
    generate_welcome_data as _claude_welcome,
    query_ioc_context as _claude_ioc_context,
    generate_weekly_flash_report as _claude_weekly,
    extract_entities_from_text as _claude_extract,
    assess_colombian_risk as _claude_colombia,
    generate_crisis_map as _claude_crisis,
    generate_team_scenarios as _claude_scenarios,
    generate_behavioral_analysis as _claude_behavioral,
    generate_playbook as _claude_playbook,
    generate_ml_proposals as _claude_ml,
    generate_geopolitical_analysis as _claude_geo,
    generate_threat_graph as _claude_graph,
)


def _fusion_engine() -> str:
    """Returns 'gemini', 'claude', or 'none' depending on which key is set."""
    if os.getenv("GEMINI_API_KEY"):
        return "gemini"
    if os.getenv("ANTHROPIC_API_KEY"):
        return "claude"
    return "none"


def _fusion_fn(gemini_fn, claude_fn):
    """Return the correct function based on configured engine."""
    engine = _fusion_engine()
    if engine == "gemini":
        return gemini_fn
    if engine == "claude":
        return claude_fn
    raise HTTPException(
        status_code=503,
        detail="Motor de Fusión no configurado. Agrega GEMINI_API_KEY o ANTHROPIC_API_KEY al .env y reinicia el backend.",
    )


# Unified aliases used by all endpoints below
generate_threat_data           = lambda *a, **kw: _fusion_fn(_gemini_threat_data,    _claude_threat_data)(*a, **kw)
generate_quantum_threat_analysis = lambda *a, **kw: _fusion_fn(_gemini_quantum,      _claude_quantum)(*a, **kw)
generate_predictive_analysis   = lambda *a, **kw: _fusion_fn(_gemini_predictive,     _claude_predictive)(*a, **kw)
generate_fusion_report         = lambda *a, **kw: _fusion_fn(_gemini_fusion_report,  _claude_fusion_report)(*a, **kw)
generate_mitre_details         = lambda *a, **kw: _fusion_fn(_gemini_mitre,          _claude_mitre)(*a, **kw)
generate_welcome_data          = lambda *a, **kw: _fusion_fn(_gemini_welcome,        _claude_welcome)(*a, **kw)
query_ioc_context              = lambda *a, **kw: _fusion_fn(_gemini_ioc_context,    _claude_ioc_context)(*a, **kw)
generate_weekly_flash_report   = lambda *a, **kw: _fusion_fn(_gemini_weekly,         _claude_weekly)(*a, **kw)
extract_entities_from_text     = lambda *a, **kw: _fusion_fn(_gemini_extract,        _claude_extract)(*a, **kw)
assess_colombian_risk          = lambda *a, **kw: _fusion_fn(_gemini_colombia,       _claude_colombia)(*a, **kw)
generate_crisis_map            = lambda *a, **kw: _fusion_fn(_gemini_crisis,         _claude_crisis)(*a, **kw)
generate_team_scenarios        = lambda *a, **kw: _fusion_fn(_gemini_scenarios,      _claude_scenarios)(*a, **kw)
generate_behavioral_analysis   = lambda *a, **kw: _fusion_fn(_gemini_behavioral,     _claude_behavioral)(*a, **kw)
generate_playbook              = lambda *a, **kw: _fusion_fn(_gemini_playbook,       _claude_playbook)(*a, **kw)
generate_ml_proposals          = lambda *a, **kw: _fusion_fn(_gemini_ml,             _claude_ml)(*a, **kw)
generate_geopolitical_analysis = lambda *a, **kw: _fusion_fn(_gemini_geo,            _claude_geo)(*a, **kw)
generate_threat_graph          = lambda *a, **kw: _fusion_fn(_gemini_graph,           _claude_graph)(*a, **kw)

BOGOTA_TZ = ZoneInfo("America/Bogota")


def _parse_dt(value: str | None):
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value)
        return dt if dt.tzinfo else dt.replace(tzinfo=BOGOTA_TZ)
    except Exception:
        return None


def _now_bogota():
    return datetime.now(BOGOTA_TZ)


def _is_started(value: str | None) -> bool:
    dt = _parse_dt(value)
    return not dt or _now_bogota() >= dt


def _is_due(value: str | None) -> bool:
    dt = _parse_dt(value)
    return bool(dt and _now_bogota() >= dt)


PRIVILEGED_ROLES = {"admin", "instructor", "senior_analyst", "analyst"}


def _is_privileged(user: dict | None) -> bool:
    return bool(user and user.get("role") in PRIVILEGED_ROLES)


def _auth_user_or_raise(authorization: str | None) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="No autenticado")
    user = verify_token(authorization[7:])
    if not user:
        raise HTTPException(status_code=401, detail="Token inválido")
    return user


def _dataset_rows_for_user(user: dict) -> list[dict]:
    """Rows from datasets attached to challenges assigned to the student or their team."""
    if _is_privileged(user):
        return []
    email = user["email"]
    with get_conn() as conn:
        rows = conn.execute("""
            SELECT DISTINCT d.data_json
            FROM datasets d
            JOIN challenges c ON c.dataset_id = d.id
            JOIN challenge_assignments ca ON ca.challenge_id = c.id
            WHERE ca.user_email = ?

            UNION

            SELECT DISTINCT d.data_json
            FROM datasets d
            JOIN challenges c ON c.dataset_id = d.id
            JOIN team_challenge_assignments tca ON tca.challenge_id = c.id
            JOIN team_members tm ON tm.team_id = tca.team_id
            WHERE tm.user_email = ?

            UNION

            SELECT DISTINCT d.data_json
            FROM datasets d
            JOIN challenge_datasets cd ON cd.dataset_id = d.id
            JOIN challenge_assignments ca ON ca.challenge_id = cd.challenge_id
            WHERE ca.user_email = ?

            UNION

            SELECT DISTINCT d.data_json
            FROM datasets d
            JOIN challenge_datasets cd ON cd.dataset_id = d.id
            JOIN team_challenge_assignments tca ON tca.challenge_id = cd.challenge_id
            JOIN team_members tm ON tm.team_id = tca.team_id
            WHERE tm.user_email = ?
        """, (email, email, email, email)).fetchall()

    out: list[dict] = []
    for row in rows:
        try:
            parsed = json.loads(row["data_json"] or "[]")
        except Exception:
            parsed = []
        if isinstance(parsed, dict):
            parsed = parsed.get("rows") or parsed.get("data") or []
        if isinstance(parsed, list):
            out.extend([r for r in parsed if isinstance(r, dict)])
    return out


def _row_value(row: dict, *keys: str, default: str = "") -> str:
    for key in keys:
        value = row.get(key)
        if value not in (None, ""):
            return str(value)
    return default


def _scoped_ioc_feed(user: dict) -> list[dict]:
    if _is_privileged(user):
        return get_threat_feed()

    scoped: list[dict] = []
    seen: set[str] = set()
    for idx, row in enumerate(_dataset_rows_for_user(user), start=1):
        value = _row_value(row, "ioc", "indicator", "value", "domain", "ip", "url", "hash")
        if not value or value in seen:
            continue
        seen.add(value)
        scoped.append({
            "id": row.get("id", idx),
            "ioc": value,
            "type": _row_value(row, "type", "ioc_type", "kind", default="unknown"),
            "threat_actor": _row_value(row, "threat_actor", "actor", "apt", default="Reto asignado"),
            "severity": _row_value(row, "severity", "priority", default="medium").lower(),
            "mitre": _row_value(row, "mitre", "mitreTechniqueId", "ttp", "technique_id"),
            "country": _row_value(row, "country", "targetCountry", "sourceCountry", default=""),
            "source": "assigned-challenge",
            "scope": "assigned-challenge",
        })
    return scoped[:120]


def _scoped_actors(user: dict) -> list[dict]:
    actors = get_threat_actors()
    if _is_privileged(user):
        return actors

    allowed = {
        row.get("threat_actor", "").lower()
        for row in _scoped_ioc_feed(user)
        if row.get("threat_actor")
    }
    if not allowed:
        return []
    return [
        {
            "id": actor.get("id"),
            "name": actor.get("name"),
            "country": actor.get("country"),
            "severity": actor.get("severity", "medium"),
            "active_campaign": actor.get("active_campaign", ""),
            "motivation": actor.get("motivation", ""),
            "ttps": actor.get("ttps", [])[:4],
            "scope": "assigned-challenge",
        }
        for actor in actors
        if str(actor.get("name", "")).lower() in allowed
    ]


def _scoped_ioas(user: dict) -> list[dict]:
    ioas = get_ioas()
    if _is_privileged(user):
        return ioas

    feed = _scoped_ioc_feed(user)
    actors = {str(row.get("threat_actor", "")).lower() for row in feed}
    ttps = {str(row.get("mitre", "")).lower() for row in feed if row.get("mitre")}
    return [
        ioa for ioa in ioas
        if str(ioa.get("attributed_actor", "")).lower() in actors
        or str(ioa.get("ttp", "")).lower() in ttps
    ][:80]


def _scoped_campaigns(user: dict) -> list[dict]:
    camps = get_campaigns()
    if _is_privileged(user):
        return camps
    actors = {str(row.get("threat_actor", "")).lower() for row in _scoped_ioc_feed(user)}
    return [
        {
            "name": c.get("name"),
            "actor": c.get("actor"),
            "status": c.get("status"),
            "last_activity": c.get("last_activity"),
            "ioc_count": c.get("ioc_count", 0),
            "scope": "assigned-challenge",
        }
        for c in camps
        if str(c.get("actor", "")).lower() in actors
    ]


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="CTI-Lab API",
    description="AI Native Cyber Threat Intelligence Platform",
    version="1.1.0",
    lifespan=lifespan,
)

_CORS_ORIGINS = os.environ.get(
    "CORS_ORIGINS",
    "http://localhost:3000,http://localhost:5173,http://127.0.0.1:3000,http://127.0.0.1:5173",
).split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=_CORS_ORIGINS,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Auth ──────────────────────────────────────────────────────────────────────

@app.post("/auth/register")
def auth_register(payload: dict = Body(...)):
    try:
        return register(
            name=payload.get("name", ""),
            email=payload.get("email", ""),
            password=payload.get("password", ""),
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/auth/login")
def auth_login(payload: dict = Body(...)):
    try:
        token = login(
            email=payload.get("email", ""),
            password=payload.get("password", ""),
        )
        return {"token": token}
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))


@app.get("/auth/me")
def auth_me(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="No autenticado")
    user = verify_token(authorization[7:])
    if not user:
        raise HTTPException(status_code=401, detail="Token inválido o expirado")
    return user


# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/")
def home():
    return {"platform": "CTI-Lab", "status": "running", "version": "1.1.0"}


# ── Search ────────────────────────────────────────────────────────────────────

@app.get("/search")
def search(q: str = "", authorization: str = Header(None)):
    user = _auth_user_or_raise(authorization)
    q = q.strip().lower()
    if len(q) < 2:
        return {"iocs": [], "actors": [], "campaigns": [], "ttps": []}

    feed    = _scoped_ioc_feed(user)
    actors  = _scoped_actors(user)
    camps   = _scoped_campaigns(user)
    ioas    = _scoped_ioas(user)

    def _match(text: str) -> bool:
        return q in str(text).lower()

    ioc_results = [
        ioc for ioc in feed
        if _match(ioc.get("ioc","")) or _match(ioc.get("threat_actor",""))
        or _match(ioc.get("mitre","")) or _match(ioc.get("type",""))
        or _match(ioc.get("country",""))
    ][:10]

    actor_results = [
        {"name": a["name"], "country": a["country"], "severity": a["severity"],
         "active_campaign": a["active_campaign"], "motivation": a["motivation"],
         "ttps": a.get("ttps",[])}
        for a in actors
        if _match(a["name"]) or _match(str(a.get("aliases","")))
        or any(_match(t) for t in a.get("ttps",[]))
        or _match(a.get("active_campaign","")) or _match(a.get("motivation",""))
    ][:5]

    camp_results = [
        {"name": c["name"], "actor": c["actor"], "status": c["status"],
         "last_activity": c["last_activity"], "ioc_count": c.get("ioc_count",0)}
        for c in camps
        if _match(c["name"]) or _match(c.get("actor",""))
        or _match(c.get("description","")) or any(_match(m) for m in c.get("mitre",[]))
    ][:5]

    ttp_results = [
        {"ttp": i["ttp"], "ttp_name": i["ttp_name"], "tactic": i["tactic"],
         "priority": i["priority"], "attributed_actor": i["attributed_actor"],
         "ioa": i.get("ioa","")}
        for i in ioas
        if _match(i["ttp"]) or _match(i["ttp_name"])
        or _match(i["tactic"]) or _match(i.get("ioa",""))
        or _match(i.get("attributed_actor",""))
    ][:5]

    return {"iocs": ioc_results, "actors": actor_results,
            "campaigns": camp_results, "ttps": ttp_results}


# ── Missions ──────────────────────────────────────────────────────────────────

@app.get("/missions")
def missions():
    return [
        {"id": 1, "title": "Operacion Black Lynx",   "difficulty": "medium",   "type": "phishing",   "status": "active"},
        {"id": 2, "title": "Ransomware Universidad",  "difficulty": "critical", "type": "ransomware", "status": "active"},
    ]


# ── Threat Intelligence ───────────────────────────────────────────────────────

@app.get("/ioc-feed")
def ioc_feed(authorization: str = Header(None)):
    user = _auth_user_or_raise(authorization)
    return _scoped_ioc_feed(user)


def _csv_response(filename: str, rows: list[dict]):
    if rows:
        columns = list(dict.fromkeys(key for row in rows for key in row.keys()))
    else:
        columns = ["ioc", "type", "threat_actor", "severity", "mitre", "country", "source"]
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=columns, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


def _stix_pattern(ioc_type: str, value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace("'", "\\'")
    kind = (ioc_type or "").lower()
    if "domain" in kind:
        observable = "domain-name:value"
    elif "url" in kind:
        observable = "url:value"
    elif "hash" in kind or "sha256" in kind:
        observable = "file:hashes.'SHA-256'"
    else:
        observable = "ipv4-addr:value"
    return f"[{observable} = '{escaped}']"


def _stix_bundle(rows: list[dict]) -> dict:
    now = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    objects = []
    for idx, row in enumerate(rows):
        value = str(row.get("ioc") or "").strip()
        if not value:
            continue
        labels = [
            str(row.get("severity") or "medium").lower(),
            str(row.get("type") or "ioc").lower(),
            str(row.get("source") or "cti-lab").lower(),
        ]
        indicator = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid4()}",
            "created": now,
            "modified": now,
            "name": f"{row.get('type', 'IOC')} - {value}",
            "description": f"IOC consumido por CTI-Lab desde {row.get('source', 'feed')}.",
            "pattern": _stix_pattern(str(row.get("type") or ""), value),
            "pattern_type": "stix",
            "valid_from": now,
            "labels": labels,
        }
        if row.get("mitre"):
            indicator["external_references"] = [
                {"source_name": "mitre-attack", "external_id": row["mitre"]},
            ]
        objects.append(indicator)
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }


@app.get("/ioc-feed/export")
def ioc_feed_export(
    format: str = "csv",
    source: str | None = None,
    severity: str | None = None,
    type: str | None = None,
    limit: int = 1000,
    authorization: str = Header(None),
):
    """
    Export the consumed CTI feed for analysis or handoff.
    Supports csv, json, and stix. Optional filters: source, severity, type.
    """
    fmt = format.lower().strip()
    if fmt not in {"csv", "json", "stix"}:
        raise HTTPException(status_code=400, detail="format must be csv, json, or stix")

    user = _auth_user_or_raise(authorization)
    rows = _scoped_ioc_feed(user)
    if source:
        rows = [r for r in rows if str(r.get("source", "")).lower() == source.lower()]
    if severity:
        rows = [r for r in rows if str(r.get("severity", "")).lower() == severity.lower()]
    if type:
        rows = [r for r in rows if str(r.get("type", "")).lower() == type.lower()]

    rows = rows[: max(1, min(limit, 5000))]
    stamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    filename = f"cti-feed-consumo-{stamp}.{fmt if fmt != 'stix' else 'json'}"

    if fmt == "csv":
        return _csv_response(filename, rows)

    payload = _stix_bundle(rows) if fmt == "stix" else {
        "exported_at": datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
        "count": len(rows),
        "filters": {"source": source, "severity": severity, "type": type, "limit": limit},
        "data": rows,
    }
    return StreamingResponse(
        iter([json.dumps(payload, ensure_ascii=False, indent=2)]),
        media_type="application/json; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@app.get("/threat-actors")
def threat_actors(authorization: str = Header(None)):
    user = _auth_user_or_raise(authorization)
    return _scoped_actors(user)


@app.get("/campaigns")
def campaigns(authorization: str = Header(None)):
    user = _auth_user_or_raise(authorization)
    return _scoped_campaigns(user)


@app.get("/findings")
def findings():
    return get_findings()


@app.post("/findings")
def create_finding(payload: dict = Body(...)):
    return add_finding(
        severity    = payload.get("severity", "MEDIUM"),
        title       = payload.get("title", ""),
        description = payload.get("description", ""),
        mitre       = payload.get("mitre", ""),
        source      = payload.get("source", "manual"),
    )


@app.get("/ioas")
def ioas(authorization: str = Header(None)):
    user = _auth_user_or_raise(authorization)
    return _scoped_ioas(user)


# ── CTI Toolkit ───────────────────────────────────────────────────────────────

@app.get("/cti/sources")
def cti_sources(category: str = None, authorization: str = Header(None)):
    _require_user(authorization)
    with get_conn() as conn:
        if category:
            rows = conn.execute(
                """SELECT id, name, category, url, feed_type, requires_auth, description,
                          formats, group_label, status, last_fetched, last_count
                   FROM feed_sources
                   WHERE category = ?
                   ORDER BY group_label, name""",
                (category,),
            ).fetchall()
        else:
            rows = conn.execute(
                """SELECT id, name, category, url, feed_type, requires_auth, description,
                          formats, group_label, status, last_fetched, last_count
                   FROM feed_sources
                   ORDER BY category, group_label, name"""
            ).fetchall()
    return [dict(r) for r in rows]


# ── MISP ──────────────────────────────────────────────────────────────────────

@app.get("/misp/status")
def misp_status(authorization: str = Header(None)):
    _require_fusion_access(authorization)
    return get_misp_status()


@app.get("/misp/iocs")
def misp_iocs(limit: int = 50, authorization: str = Header(None)):
    _require_fusion_access(authorization)
    try:
        iocs = fetch_misp_iocs(limit=min(limit, 200))
        return {"count": len(iocs), "iocs": iocs}
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"MISP fetch failed: {e}")


@app.post("/misp/import")
def misp_import(limit: int = 50, authorization: str = Header(None)):
    """Pull IOCs from MISP and persist them into the local DB."""
    _require_fusion_access(authorization)
    try:
        iocs = fetch_misp_iocs(limit=min(limit, 200))
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"MISP fetch failed: {e}")
    added = add_uploaded_iocs(iocs)
    return {
        "fetched": len(iocs),
        "added":   len(added),
        "skipped": len(iocs) - len(added),
    }


# ── File Upload ───────────────────────────────────────────────────────────────

@app.post("/upload")
async def upload_export(file: UploadFile = File(...)):
    allowed = {".csv", ".json", ".txt", ".stix"}
    ext = "." + (file.filename or "").rsplit(".", 1)[-1].lower()
    if ext not in allowed:
        raise HTTPException(status_code=400, detail=f"Unsupported file type: {ext}. Allowed: {', '.join(allowed)}")

    raw = await file.read()
    if len(raw) > 5 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File too large. Maximum 5 MB.")

    try:
        parsed = parse_upload(file.filename or "", raw)
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Parse error: {e}")

    added = add_uploaded_iocs(parsed)
    return {"parsed": len(parsed), "added": len(added), "skipped": len(parsed) - len(added), "iocs": added}


# ── AI ────────────────────────────────────────────────────────────────────────

@app.get("/ai/analyze/{ioc}")
def ai_analysis(ioc: str):
    return analyze_ioc(ioc)


@app.get("/enrich/{ioc:path}")
def enrich(ioc: str):
    return enrich_ioc(ioc)


@app.post("/ai/chat")
def ai_chat(payload: dict = Body(...)):
    prompt = payload.get("message", "")

    iocs   = get_threat_feed()
    actors = get_threat_actors()

    ioc_summary = "\n".join(
        f"- {i['ioc']} ({i['type']}, {i['severity']}, actor: {i['threat_actor']}, MITRE: {i['mitre']})"
        for i in iocs
    )
    actor_summary = "\n".join(
        f"- {a['name']} ({a['country']}, motivation: {a['motivation']}, campaign: {a['active_campaign']})"
        for a in actors
    )

    system_context = f"""You are an advanced SOC and CTI analyst with access to the following live threat intelligence:

ACTIVE IOCs:
{ioc_summary}

TRACKED THREAT ACTORS:
{actor_summary}

Use this context when answering. Be concise and technical."""

    anthropic_key = os.environ.get("ANTHROPIC_API_KEY")
    if anthropic_key:
        client = anthropic.Anthropic(api_key=anthropic_key)
        message = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=1024,
            system=[{"type": "text", "text": system_context, "cache_control": {"type": "ephemeral"}}],
            messages=[{"role": "user", "content": prompt}],
        )
        return {"response": message.content[0].text}

    ollama_url = os.environ.get("OLLAMA_URL", "http://localhost:11434")
    response = requests.post(
        f"{ollama_url}/api/generate",
        json={"model": "llama3", "prompt": f"{system_context}\n\nUser query: {prompt}\n\nProvide a technical cybersecurity response.", "stream": False},
        timeout=60,
    )
    return {"response": response.json()["response"]}


# ── Admin helpers ─────────────────────────────────────────────────────────────

def _require_admin(authorization: str) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="No autenticado")
    user = verify_token(authorization[7:])
    if not user or user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Solo administradores")
    return user

def _require_user(authorization: str) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="No autenticado")
    user = verify_token(authorization[7:])
    if not user:
        raise HTTPException(status_code=401, detail="Token inválido")
    return user


# ── Admin: Users ──────────────────────────────────────────────────────────────

@app.get("/admin/users")
def admin_users(authorization: str = Header(None)):
    _require_admin(authorization)
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT id, name, email, role, created_at FROM users ORDER BY created_at DESC"
        ).fetchall()
    return [dict(r) for r in rows]


# ── Admin: Datasets ───────────────────────────────────────────────────────────

@app.get("/admin/datasets")
def admin_datasets(authorization: str = Header(None)):
    _require_admin(authorization)
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT id, name, description, source, schema_json, created_by, created_at FROM datasets ORDER BY created_at DESC"
        ).fetchall()
    return [dict(r) for r in rows]


@app.post("/admin/datasets")
def admin_create_dataset(payload: dict = Body(...), authorization: str = Header(None)):
    admin = _require_admin(authorization)
    name = payload.get("name", "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="Nombre requerido")

    raw = payload.get("data", "").strip()
    try:
        if raw.startswith("[") or raw.startswith("{"):
            parsed = json.loads(raw)
            rows = parsed if isinstance(parsed, list) else [parsed]
            data_json = json.dumps(rows)
        else:
            reader = csv.DictReader(io.StringIO(raw))
            rows = list(reader)
            data_json = json.dumps(rows)
        schema = {k: type(v).__name__ for k, v in rows[0].items()} if rows else {}
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Error al parsear datos: {exc}")

    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO datasets (name, description, source, data_json, schema_json, created_by) VALUES (?,?,?,?,?,?)",
            (name, payload.get("description", ""), payload.get("source", "manual"),
             data_json, json.dumps(schema), admin["email"]),
        )
    return {"id": cur.lastrowid, "name": name, "rows": len(rows)}


@app.get("/admin/datasets/{dataset_id}")
def admin_get_dataset(dataset_id: int, authorization: str = Header(None)):
    _require_admin(authorization)
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM datasets WHERE id = ?", (dataset_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404)
    return dict(row)


@app.delete("/admin/datasets/{dataset_id}")
def admin_delete_dataset(dataset_id: int, authorization: str = Header(None)):
    _require_admin(authorization)
    with get_conn() as conn:
        conn.execute("DELETE FROM datasets WHERE id = ?", (dataset_id,))
    return {"ok": True}


@app.post("/datasets/generate-synthetic")
def datasets_generate_synthetic(payload: dict = Body(...), authorization: str = Header(None)):
    """
    Genera un dataset sintético ML-ready basado en perfiles CISA.
    Si el usuario es admin, persiste en DB. Si no, devuelve los datos sin guardar.
    """
    from intelligence.dataset_generator import generate_synthetic_dataset

    n      = int(payload.get("n", 1000))
    focus  = payload.get("focus", "mixed")
    actors = payload.get("actors") or None
    seed   = payload.get("seed")
    save   = payload.get("save", False)

    result = generate_synthetic_dataset(n=n, actor_filter=actors, focus=focus,
                                        seed=int(seed) if seed is not None else None)

    dataset_id = None
    if save:
        try:
            user = _require_admin(authorization)
            created_by = user["email"]
        except Exception:
            created_by = "anonymous"
        with get_conn() as conn:
            cur = conn.execute(
                "INSERT INTO datasets (name, description, source, data_json, schema_json, created_by) VALUES (?,?,?,?,?,?)",
                (result["name"], result["description"], result["source"],
                 json.dumps(result["data"], ensure_ascii=False),
                 json.dumps(result["schema"], ensure_ascii=False),
                 created_by),
            )
            dataset_id = cur.lastrowid

    return {
        "dataset_id": dataset_id,
        "name":        result["name"],
        "rows":        len(result["data"]),
        "stats":       result["stats"],
        "schema":      result["schema"],
        "preview":     result["data"][:20],
        "saved":       dataset_id is not None,
    }


@app.post("/datasets/bulk-import-feeds")
def datasets_bulk_import_feeds(payload: dict = Body(default={}), authorization: str = Header(None)):
    """
    Importa todos los IoCs del feed actual como un dataset ML-ready.
    Añade columnas feat_* con encoding numérico listo para clustering.
    """
    from intelligence.dataset_generator import generate_feed_import_dataset

    try:
        user = _require_admin(authorization)
        created_by = user["email"]
    except Exception:
        created_by = "anonymous"

    iocs = get_threat_feed()
    if not iocs:
        raise HTTPException(status_code=404, detail="No hay IoCs en el feed actual.")

    result = generate_feed_import_dataset(iocs)

    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO datasets (name, description, source, data_json, schema_json, created_by) VALUES (?,?,?,?,?,?)",
            (result["name"], result["description"], result["source"],
             json.dumps(result["data"], ensure_ascii=False),
             json.dumps(result["schema"], ensure_ascii=False),
             created_by),
        )
        dataset_id = cur.lastrowid

    return {
        "dataset_id": dataset_id,
        "name":        result["name"],
        "rows":        len(result["data"]),
        "saved":       True,
    }


# ── Admin: Challenges ─────────────────────────────────────────────────────────

@app.get("/admin/challenges")
def admin_challenges(authorization: str = Header(None)):
    _require_admin(authorization)
    with get_conn() as conn:
        rows = conn.execute("""
            SELECT c.id, c.title, c.description, c.objective, c.criteria, c.hints_json,
                   c.deadline, c.status, c.created_at,
                   c.badge_id, c.min_score_badge, c.difficulty,
                   d.name AS dataset_name,
                   b.name AS badge_name, b.org AS badge_org, b.tier AS badge_tier, b.icon AS badge_icon,
                   (SELECT COUNT(*) FROM challenge_assignments ca WHERE ca.challenge_id = c.id) AS assigned_count,
                   (SELECT COUNT(*) FROM submissions s WHERE s.challenge_id = c.id) AS submission_count
            FROM challenges c
            LEFT JOIN datasets d ON c.dataset_id = d.id
            LEFT JOIN badges b ON c.badge_id = b.id
            ORDER BY c.created_at DESC
        """).fetchall()
    return [dict(r) for r in rows]


@app.post("/admin/challenges")
def admin_create_challenge(payload: dict = Body(...), authorization: str = Header(None)):
    admin = _require_admin(authorization)
    title = payload.get("title", "").strip()
    if not title:
        raise HTTPException(status_code=400, detail="Título requerido")
    with get_conn() as conn:
        cur = conn.execute(
            """INSERT INTO challenges
               (title, description, objective, dataset_id, criteria, deadline,
                badge_id, min_score_badge, difficulty, created_by)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (title, payload.get("description", ""), payload.get("objective", ""),
             payload.get("dataset_id") or None, payload.get("criteria", ""),
             payload.get("deadline") or None,
             payload.get("badge_id") or None,
             int(payload.get("min_score_badge") or 70),
             payload.get("difficulty", "medio"),
             admin["email"]),
        )
    return {"id": cur.lastrowid, "title": title}


@app.patch("/admin/challenges/{challenge_id}")
def admin_update_challenge(challenge_id: int, payload: dict = Body(...), authorization: str = Header(None)):
    _require_admin(authorization)
    updatable = ["status", "title", "description", "objective", "criteria", "hints_json", "deadline", "difficulty"]
    with get_conn() as conn:
        for field in updatable:
            if field in payload:
                conn.execute(f"UPDATE challenges SET {field} = ? WHERE id = ?", (payload[field], challenge_id))
        if "badge_id" in payload:
            conn.execute("UPDATE challenges SET badge_id = ? WHERE id = ?", (payload["badge_id"] or None, challenge_id))
        if "min_score_badge" in payload:
            conn.execute("UPDATE challenges SET min_score_badge = ? WHERE id = ?", (int(payload["min_score_badge"] or 70), challenge_id))
    return {"ok": True}


@app.delete("/admin/challenges/{challenge_id}")
def admin_delete_challenge(challenge_id: int, authorization: str = Header(None)):
    _require_admin(authorization)
    with get_conn() as conn:
        conn.execute("DELETE FROM challenge_assignments WHERE challenge_id = ?", (challenge_id,))
        conn.execute("DELETE FROM submissions WHERE challenge_id = ?", (challenge_id,))
        conn.execute("DELETE FROM challenges WHERE id = ?", (challenge_id,))
    return {"ok": True}


@app.get("/admin/challenges/{challenge_id}/assignments")
def admin_challenge_assignments(challenge_id: int, authorization: str = Header(None)):
    _require_admin(authorization)
    with get_conn() as conn:
        rows = conn.execute("""
            SELECT u.name, u.email, ca.assigned_at,
                   (SELECT COUNT(*) FROM submissions s
                    WHERE s.challenge_id = ? AND s.user_email = u.email) AS submitted
            FROM challenge_assignments ca
            JOIN users u ON ca.user_email = u.email
            WHERE ca.challenge_id = ?
        """, (challenge_id, challenge_id)).fetchall()
    return [dict(r) for r in rows]


@app.post("/admin/challenges/{challenge_id}/assign")
def admin_assign_users(challenge_id: int, payload: dict = Body(...), authorization: str = Header(None)):
    _require_admin(authorization)
    emails = payload.get("emails", [])
    assigned = []
    with get_conn() as conn:
        for email in emails:
            try:
                conn.execute(
                    "INSERT OR IGNORE INTO challenge_assignments (challenge_id, user_email) VALUES (?,?)",
                    (challenge_id, email),
                )
                assigned.append(email)
            except Exception:
                pass
    return {"assigned": assigned}


@app.delete("/admin/challenges/{challenge_id}/assign/{email}")
def admin_unassign_user(challenge_id: int, email: str, authorization: str = Header(None)):
    _require_admin(authorization)
    with get_conn() as conn:
        conn.execute(
            "DELETE FROM challenge_assignments WHERE challenge_id = ? AND user_email = ?",
            (challenge_id, email),
        )
    return {"ok": True}


# ── Admin: Submissions ────────────────────────────────────────────────────────

@app.get("/admin/submissions")
def admin_submissions(challenge_id: int = None, authorization: str = Header(None)):
    _require_admin(authorization)
    with get_conn() as conn:
        if challenge_id:
            rows = conn.execute("""
                SELECT s.*, c.title AS challenge_title
                FROM submissions s JOIN challenges c ON s.challenge_id = c.id
                WHERE s.challenge_id = ? ORDER BY s.submitted_at DESC
            """, (challenge_id,)).fetchall()
        else:
            rows = conn.execute("""
                SELECT s.*, c.title AS challenge_title
                FROM submissions s JOIN challenges c ON s.challenge_id = c.id
                ORDER BY s.submitted_at DESC
            """).fetchall()
    return [dict(r) for r in rows]


@app.put("/admin/submissions/{submission_id}/score")
def admin_score(submission_id: int, payload: dict = Body(...), authorization: str = Header(None)):
    admin = _require_admin(authorization)
    score = payload.get("score")
    feedback = payload.get("feedback", "")
    badge_awarded = None
    with get_conn() as conn:
        conn.execute(
            "UPDATE submissions SET score = ?, feedback = ? WHERE id = ?",
            (score, feedback, submission_id),
        )
        if score is not None:
            sub = conn.execute(
                "SELECT user_email, challenge_id FROM submissions WHERE id = ?", (submission_id,)
            ).fetchone()
            if sub:
                ch = conn.execute(
                    "SELECT badge_id, min_score_badge FROM challenges WHERE id = ?", (sub["challenge_id"],)
                ).fetchone()
                if ch and ch["badge_id"] and int(score) >= (ch["min_score_badge"] or 70):
                    already = conn.execute(
                        "SELECT 1 FROM user_badges WHERE user_email = ? AND badge_id = ?",
                        (sub["user_email"], ch["badge_id"]),
                    ).fetchone()
                    if not already:
                        conn.execute(
                            "INSERT INTO user_badges (user_email, badge_id, awarded_by) VALUES (?,?,?)",
                            (sub["user_email"], ch["badge_id"], admin["email"]),
                        )
                        b = conn.execute("SELECT name, org, tier FROM badges WHERE id = ?", (ch["badge_id"],)).fetchone()
                        badge_awarded = dict(b) if b else None
    return {"ok": True, "badge_awarded": badge_awarded}


# ── Admin: Seed demo data ─────────────────────────────────────────────────────

@app.post("/admin/seed-demo")
def admin_seed_demo(authorization: str = Header(None)):
    from db import _seed_demo_datasets, _seed_demo_challenges
    _require_admin(authorization)
    with get_conn() as conn:
        ds_before = conn.execute("SELECT COUNT(*) FROM datasets WHERE source LIKE 'CTI-Lab%'").fetchone()[0]
        ch_before = conn.execute("SELECT COUNT(*) FROM challenges WHERE created_by = 'system@cti-lab'").fetchone()[0]
        _seed_demo_datasets(conn)
        _seed_demo_challenges(conn)
        ds_after = conn.execute("SELECT COUNT(*) FROM datasets WHERE source LIKE 'CTI-Lab%'").fetchone()[0]
        ch_after = conn.execute("SELECT COUNT(*) FROM challenges WHERE created_by = 'system@cti-lab'").fetchone()[0]
    return {
        "datasets_added": ds_after - ds_before,
        "challenges_added": ch_after - ch_before,
        "total_datasets": ds_after,
        "total_challenges": ch_after,
    }


# ── Admin: Feed Sources ───────────────────────────────────────────────────────

@app.get("/admin/sources")
def admin_sources(category: str = None, authorization: str = Header(None)):
    _require_admin(authorization)
    with get_conn() as conn:
        if category:
            rows = conn.execute(
                "SELECT * FROM feed_sources WHERE category = ? ORDER BY group_label, name",
                (category,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM feed_sources ORDER BY category, group_label, name"
            ).fetchall()
    return [dict(r) for r in rows]


@app.post("/admin/sources/{source_id}/fetch")
def admin_fetch_source(source_id: int, authorization: str = Header(None)):
    _require_admin(authorization)
    with get_conn() as conn:
        src = conn.execute("SELECT * FROM feed_sources WHERE id = ?", (source_id,)).fetchone()
    if not src:
        raise HTTPException(status_code=404, detail="Fuente no encontrada")
    src = dict(src)
    fn = FETCH_REGISTRY.get(src["name"])
    if not fn:
        raise HTTPException(status_code=400, detail=f"Fetch no implementado para '{src['name']}'. Solo fuentes públicas (ThreatFox, FeodoTracker, OpenPhish, Ransomware.live).")
    data = fn(limit=50)
    if data and "error" in data[0]:
        raise HTTPException(status_code=502, detail=data[0]["error"])
    with get_conn() as conn:
        conn.execute(
            "UPDATE feed_sources SET last_fetched = datetime('now'), last_count = ?, status = 'active' WHERE id = ?",
            (len(data), source_id),
        )
    return {"source": src["name"], "count": len(data), "sample": data[:5], "data": data}


@app.get("/admin/sources/summary")
def admin_sources_summary(authorization: str = Header(None)):
    _require_admin(authorization)
    with get_conn() as conn:
        rows = conn.execute("""
            SELECT category,
                   COUNT(*) AS total,
                   SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) AS active,
                   SUM(CASE WHEN status = 'needs_key' THEN 1 ELSE 0 END) AS needs_key,
                   SUM(CASE WHEN status = 'manual' THEN 1 ELSE 0 END) AS manual
            FROM feed_sources GROUP BY category ORDER BY category
        """).fetchall()
    return [dict(r) for r in rows]


# ── Admin: Stats ──────────────────────────────────────────────────────────────

@app.get("/admin/stats")
def admin_stats(authorization: str = Header(None)):
    _require_admin(authorization)
    with get_conn() as conn:
        users      = conn.execute("SELECT COUNT(*) FROM users WHERE role = 'student'").fetchone()[0]
        total_users = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        admins     = conn.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'").fetchone()[0]
        challenges = conn.execute("SELECT COUNT(*) FROM challenges WHERE status = 'active'").fetchone()[0]
        datasets   = conn.execute("SELECT COUNT(*) FROM datasets").fetchone()[0]
        teams      = conn.execute("SELECT COUNT(*) FROM teams").fetchone()[0]
        team_members = conn.execute("SELECT COUNT(*) FROM team_members").fetchone()[0]
        total_submissions = conn.execute("SELECT COUNT(*) FROM submissions").fetchone()[0]
        graded_submissions = conn.execute("SELECT COUNT(*) FROM submissions WHERE score IS NOT NULL").fetchone()[0]
        ctf_solves = conn.execute("SELECT COUNT(*) FROM ctf_solves WHERE is_correct = 1").fetchone()[0]
        ctf_points = conn.execute("SELECT COALESCE(SUM(points_earned), 0) FROM ctf_solves WHERE is_correct = 1").fetchone()[0]
        active_students = conn.execute("""
            SELECT COUNT(DISTINCT email) FROM (
                SELECT user_email AS email FROM submissions
                UNION
                SELECT user_email AS email FROM ctf_solves WHERE is_correct = 1
                UNION
                SELECT user_email AS email FROM user_badges
            )
        """).fetchone()[0]
        log_datasets = conn.execute("SELECT COUNT(*) FROM datasets WHERE source LIKE 'log_ingest:%'").fetchone()[0]
        feed_iocs = conn.execute("SELECT COUNT(*) FROM iocs WHERE source != 'uploaded'").fetchone()[0]
        subs_today = conn.execute(
            "SELECT COUNT(*) FROM submissions WHERE date(submitted_at) = date('now')"
        ).fetchone()[0]
        pending    = conn.execute(
            "SELECT COUNT(*) FROM submissions WHERE score IS NULL"
        ).fetchone()[0]
        top_students = conn.execute("""
            SELECT u.name, u.email,
                   COUNT(DISTINCT s.id) AS submissions,
                   COUNT(DISTINCT cs.id) AS ctf_solves,
                   COALESCE(SUM(DISTINCT cs.points_earned), 0) AS ctf_points,
                   ROUND(AVG(s.score), 1) AS avg_score
            FROM users u
            LEFT JOIN submissions s ON s.user_email = u.email
            LEFT JOIN ctf_solves cs ON cs.user_email = u.email AND cs.is_correct = 1
            WHERE u.role = 'student'
            GROUP BY u.email
            ORDER BY ctf_points DESC, ctf_solves DESC, submissions DESC, u.name
            LIMIT 5
        """).fetchall()
        team_progress = conn.execute("""
            SELECT t.id, t.name, t.color,
                   COUNT(DISTINCT tm.user_email) AS members,
                   COUNT(DISTINCT tca.challenge_id) AS assigned_challenges,
                   COUNT(DISTINCT tb.badge_id) AS badges
            FROM teams t
            LEFT JOIN team_members tm ON tm.team_id = t.id
            LEFT JOIN team_challenge_assignments tca ON tca.team_id = t.id
            LEFT JOIN team_badges tb ON tb.team_id = t.id
            GROUP BY t.id
            ORDER BY badges DESC, assigned_challenges DESC, t.name
        """).fetchall()
        recent_subs = conn.execute("""
            SELECT s.user_name, s.user_email, c.title AS challenge, s.submitted_at, s.score
            FROM submissions s JOIN challenges c ON s.challenge_id = c.id
            ORDER BY s.submitted_at DESC LIMIT 5
        """).fetchall()
    return {
        "students": users, "total_users": total_users, "admins": admins,
        "active_challenges": challenges, "datasets": datasets,
        "teams": teams, "team_members": team_members,
        "submissions_today": subs_today, "total_submissions": total_submissions,
        "graded_submissions": graded_submissions, "pending_scoring": pending,
        "ctf_solves": ctf_solves, "ctf_points": ctf_points,
        "active_students": active_students, "log_datasets": log_datasets,
        "feed_iocs": feed_iocs,
        "live_events": len(live_service.get_history(300)),
        "live_clients": live_service.client_count(),
        "top_students": [dict(r) for r in top_students],
        "team_progress": [dict(r) for r in team_progress],
        "recent_submissions": [dict(r) for r in recent_subs],
    }


# ── Student: Challenges ───────────────────────────────────────────────────────

@app.get("/student/challenges")
def student_challenges(authorization: str = Header(None)):
    user = _require_user(authorization)
    with get_conn() as conn:
        rows = conn.execute("""
            SELECT c.id, c.title, c.description, c.objective, c.criteria, c.hints_json,
                   c.starts_at, c.deadline, c.stage, c.status, c.difficulty,
                   c.badge_id, c.min_score_badge,
                   b.name AS badge_name, b.org AS badge_org, b.tier AS badge_tier, b.icon AS badge_icon,
                   d.name AS dataset_name, d.schema_json,
                   (SELECT COUNT(*) FROM submissions s
                    WHERE s.challenge_id = c.id AND s.user_email = ?) AS submitted,
                   (SELECT score FROM submissions s
                    WHERE s.challenge_id = c.id AND s.user_email = ?
                    LIMIT 1) AS my_score,
                   (SELECT 1 FROM user_badges ub
                    WHERE ub.user_email = ? AND ub.badge_id = c.badge_id) AS badge_earned
            FROM challenges c
            JOIN challenge_assignments ca ON c.id = ca.challenge_id
            LEFT JOIN datasets d ON c.dataset_id = d.id
            LEFT JOIN badges b ON c.badge_id = b.id
            WHERE ca.user_email = ?
            ORDER BY c.created_at DESC
        """, (user["email"], user["email"], user["email"], user["email"])).fetchall()
    return [dict(r) for r in rows if _is_started(r["starts_at"])]


@app.get("/student/solved-challenges")
def student_solved_challenges(authorization: str = Header(None)):
    user = _require_user(authorization)
    with get_conn() as conn:
        rows = conn.execute("""
            SELECT c.id, c.title, c.stage, c.difficulty, s.score, s.feedback, s.submitted_at,
                   b.name AS badge_name, b.tier AS badge_tier
            FROM submissions s
            JOIN challenges c ON c.id = s.challenge_id
            LEFT JOIN badges b ON b.id = c.badge_id
            WHERE s.user_email = ?
            ORDER BY s.submitted_at DESC
        """, (user["email"],)).fetchall()
    return [dict(r) for r in rows]


@app.get("/student/challenges/{challenge_id}/dataset")
def student_challenge_dataset(challenge_id: int, authorization: str = Header(None)):
    user = _require_user(authorization)
    with get_conn() as conn:
        ok = _has_challenge_access(conn, challenge_id, user["email"])
        if not ok:
            raise HTTPException(status_code=403, detail="No tienes acceso a este reto")
        row = conn.execute("""
            SELECT d.name, d.description, d.data_json, d.schema_json, d.source
            FROM challenges c JOIN datasets d ON c.dataset_id = d.id
            WHERE c.id = ?
        """, (challenge_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Dataset no encontrado")
    return dict(row)


@app.post("/student/challenges/{challenge_id}/submit")
def student_submit(challenge_id: int, payload: dict = Body(...), authorization: str = Header(None)):
    user = _require_user(authorization)
    with get_conn() as conn:
        ok = _has_challenge_access(conn, challenge_id, user["email"])
        if not ok:
            raise HTTPException(status_code=403)
        existing = conn.execute(
            "SELECT id FROM submissions WHERE challenge_id = ? AND user_email = ?",
            (challenge_id, user["email"]),
        ).fetchone()
        plots = json.dumps(payload.get("plots", []))
        if existing:
            conn.execute(
                "UPDATE submissions SET code=?, output=?, plots_json=?, notes=?, submitted_at=datetime('now') WHERE id=?",
                (payload.get("code",""), payload.get("output",""), plots, payload.get("notes",""), existing["id"]),
            )
            return {"id": existing["id"], "updated": True}
        cur = conn.execute(
            "INSERT INTO submissions (challenge_id, user_email, user_name, code, output, plots_json, notes) VALUES (?,?,?,?,?,?,?)",
            (challenge_id, user["email"], user.get("name",""),
             payload.get("code",""), payload.get("output",""), plots, payload.get("notes","")),
        )
    return {"id": cur.lastrowid, "created": True}


def _has_challenge_access(conn, challenge_id: int, user_email: str):
    direct = conn.execute(
        "SELECT 1 FROM challenge_assignments WHERE challenge_id = ? AND user_email = ?",
        (challenge_id, user_email),
    ).fetchone()
    if direct:
        return direct
    return conn.execute("""
        SELECT 1
        FROM team_challenge_assignments tca
        JOIN team_members tm ON tm.team_id = tca.team_id
        WHERE tca.challenge_id = ? AND tm.user_email = ?
        LIMIT 1
    """, (challenge_id, user_email)).fetchone()


DOCS_DIR = Path(os.getenv("DOCS_DIR", "/data/documents"))
ALLOWED_TYPES = {
    "application/pdf":                                                    "pdf",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "docx",
    "application/msword":                                                 "doc",
}
MAX_PAGES   = 4
MAX_SIZE_MB = 10


def _count_pdf_pages(data: bytes) -> int:
    return len(re.findall(rb"/Type\s*/Page[^s]", data))


def _count_docx_pages(data: bytes) -> int | None:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            if "docProps/app.xml" in z.namelist():
                import xml.etree.ElementTree as ET
                tree = ET.fromstring(z.read("docProps/app.xml"))
                ns   = "{http://schemas.openxmlformats.org/officeDocument/2006/extended-properties}"
                el   = tree.find(f"{ns}Pages")
                if el is not None and el.text:
                    return int(el.text)
    except Exception:
        pass
    return None


@app.post("/student/challenges/{challenge_id}/upload-document")
async def student_upload_document(
    challenge_id: int,
    file: UploadFile = File(...),
    authorization: str = Header(None),
):
    user = _require_user(authorization)
    email = user["email"]

    # ── Validate type ──────────────────────────────────────────────────────
    ct = (file.content_type or "").split(";")[0].strip()
    if ct not in ALLOWED_TYPES:
        raise HTTPException(status_code=415, detail="Solo se aceptan archivos PDF, DOCX o DOC.")

    data = await file.read()

    # ── Validate size ──────────────────────────────────────────────────────
    if len(data) > MAX_SIZE_MB * 1024 * 1024:
        raise HTTPException(status_code=413, detail=f"El archivo supera el límite de {MAX_SIZE_MB} MB.")

    # ── Count pages ────────────────────────────────────────────────────────
    ext = ALLOWED_TYPES[ct]
    if ext == "pdf":
        pages = _count_pdf_pages(data)
    elif ext == "docx":
        pages = _count_docx_pages(data)
    else:
        pages = None  # .doc binario — no podemos contar páginas sin LibreOffice

    if pages is not None and pages > MAX_PAGES:
        raise HTTPException(
            status_code=422,
            detail=f"El documento tiene {pages} páginas. El máximo permitido es {MAX_PAGES}.",
        )

    # ── Access check ───────────────────────────────────────────────────────
    with get_conn() as conn:
        if not _has_challenge_access(conn, challenge_id, email):
            raise HTTPException(status_code=403, detail="Sin acceso a este reto.")

    # ── Save file ──────────────────────────────────────────────────────────
    safe_email = re.sub(r"[^\w@.]", "_", email)
    dest_dir   = DOCS_DIR / str(challenge_id) / safe_email
    dest_dir.mkdir(parents=True, exist_ok=True)

    safe_name = re.sub(r"[^\w.\-]", "_", file.filename or f"document.{ext}")
    dest_path = dest_dir / safe_name
    dest_path.write_bytes(data)

    # ── Update/create submission record ───────────────────────────────────
    with get_conn() as conn:
        existing = conn.execute(
            "SELECT id FROM submissions WHERE challenge_id=? AND user_email=?",
            (challenge_id, email),
        ).fetchone()
        if existing:
            conn.execute(
                "UPDATE submissions SET document_path=?, document_filename=?, document_pages=? WHERE id=?",
                (str(dest_path), safe_name, pages, existing["id"]),
            )
            sub_id = existing["id"]
        else:
            cur = conn.execute(
                """INSERT INTO submissions (challenge_id, user_email, user_name, code, output,
                   plots_json, notes, document_path, document_filename, document_pages)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (challenge_id, email, user.get("name",""), "", "", "[]", "",
                 str(dest_path), safe_name, pages),
            )
            sub_id = cur.lastrowid

    return {
        "ok": True,
        "submission_id": sub_id,
        "filename": safe_name,
        "pages": pages,
        "size_kb": round(len(data) / 1024, 1),
    }


@app.get("/admin/submissions/{submission_id}/document")
def admin_download_document(submission_id: int, authorization: str = Header(None)):
    _require_admin(authorization)
    with get_conn() as conn:
        row = conn.execute(
            "SELECT document_path, document_filename FROM submissions WHERE id=?",
            (submission_id,),
        ).fetchone()
    if not row or not row["document_path"]:
        raise HTTPException(status_code=404, detail="No hay documento adjunto en esta entrega.")
    path = Path(row["document_path"])
    if not path.exists():
        raise HTTPException(status_code=404, detail="Archivo no encontrado en el servidor.")
    media = "application/pdf" if row["document_filename"].endswith(".pdf") else \
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    return FileResponse(str(path), filename=row["document_filename"], media_type=media)


@app.get("/student/challenges/{challenge_id}/document-status")
def student_document_status(challenge_id: int, authorization: str = Header(None)):
    user = _require_user(authorization)
    with get_conn() as conn:
        row = conn.execute(
            "SELECT document_filename, document_pages FROM submissions WHERE challenge_id=? AND user_email=?",
            (challenge_id, user["email"]),
        ).fetchone()
    if not row or not row["document_filename"]:
        return {"uploaded": False}
    return {
        "uploaded":  True,
        "filename":  row["document_filename"],
        "pages":     row["document_pages"],
    }


def _auto_award_due_team_badges(conn) -> None:
    rows = conn.execute("""
        SELECT tca.team_id, c.id AS challenge_id, c.badge_id, c.deadline
        FROM team_challenge_assignments tca
        JOIN challenges c ON c.id = tca.challenge_id
        WHERE c.badge_id IS NOT NULL
    """).fetchall()
    for row in rows:
        if not _is_due(row["deadline"]):
            continue
        submitted = conn.execute("""
            SELECT 1
            FROM submissions s
            JOIN team_members tm ON tm.user_email = s.user_email
            WHERE tm.team_id = ? AND s.challenge_id = ?
            LIMIT 1
        """, (row["team_id"], row["challenge_id"])).fetchone()
        if not submitted:
            continue
        conn.execute(
            "INSERT OR IGNORE INTO team_badges (team_id, badge_id, awarded_by) VALUES (?,?,?)",
            (row["team_id"], row["badge_id"], "auto@cti-range"),
        )


# ── Admin: User roles ─────────────────────────────────────────────────────────

ALLOWED_ROLES = {"student", "analyst", "senior_analyst", "instructor", "admin"}

@app.patch("/admin/users/{email}/role")
def admin_set_role(email: str, payload: dict = Body(...), authorization: str = Header(None)):
    _require_admin(authorization)
    role = payload.get("role", "")
    if role not in ALLOWED_ROLES:
        raise HTTPException(status_code=400, detail=f"Rol inválido. Opciones: {', '.join(ALLOWED_ROLES)}")
    with get_conn() as conn:
        conn.execute("UPDATE users SET role = ? WHERE email = ?", (role, email))
    return {"ok": True, "email": email, "role": role}


@app.delete("/admin/users/{email}")
def admin_delete_user(email: str, authorization: str = Header(None)):
    _require_admin(authorization)
    with get_conn() as conn:
        user = conn.execute("SELECT role FROM users WHERE email = ?", (email,)).fetchone()
        if not user:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")
        if user["role"] == "admin":
            raise HTTPException(status_code=403, detail="No se puede eliminar un administrador")
        conn.execute("DELETE FROM submissions WHERE user_email = ?", (email,))
        conn.execute("DELETE FROM challenge_assignments WHERE user_email = ?", (email,))
        conn.execute("DELETE FROM user_badges WHERE user_email = ?", (email,))
        conn.execute("DELETE FROM team_members WHERE user_email = ?", (email,))
        conn.execute("DELETE FROM ctf_solves WHERE user_email = ?", (email,))
        conn.execute("DELETE FROM users WHERE email = ?", (email,))
    return {"ok": True, "email": email}


# ── Admin: Teams ──────────────────────────────────────────────────────────────

@app.get("/admin/teams")
def admin_teams(authorization: str = Header(None)):
    _require_admin(authorization)
    with get_conn() as conn:
        teams = conn.execute(
            "SELECT id, name, color, created_by, created_at FROM teams ORDER BY created_at"
        ).fetchall()
        result = []
        for t in teams:
            members = conn.execute("""
                SELECT u.name, u.email, tm.role, tm.joined_at
                FROM team_members tm JOIN users u ON tm.user_email = u.email
                WHERE tm.team_id = ?
            """, (t["id"],)).fetchall()
            result.append({**dict(t), "members": [dict(m) for m in members]})
    return result


@app.post("/admin/teams")
def admin_create_team(payload: dict = Body(...), authorization: str = Header(None)):
    admin = _require_admin(authorization)
    name = payload.get("name", "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="Nombre requerido")
    with get_conn() as conn:
        try:
            cur = conn.execute(
                "INSERT INTO teams (name, color, created_by) VALUES (?,?,?)",
                (name, payload.get("color", "#22d3ee"), admin["email"]),
            )
        except Exception:
            raise HTTPException(status_code=409, detail="Ya existe un equipo con ese nombre")
    return {"id": cur.lastrowid, "name": name}


@app.delete("/admin/teams/{team_id}")
def admin_delete_team(team_id: int, authorization: str = Header(None)):
    _require_admin(authorization)
    with get_conn() as conn:
        conn.execute("DELETE FROM team_members WHERE team_id = ?", (team_id,))
        conn.execute("DELETE FROM teams WHERE id = ?", (team_id,))
    return {"ok": True}


@app.post("/admin/teams/{team_id}/members")
def admin_add_team_member(team_id: int, payload: dict = Body(...), authorization: str = Header(None)):
    _require_admin(authorization)
    emails = payload.get("emails", [])
    with get_conn() as conn:
        for email in emails:
            conn.execute(
                "INSERT OR IGNORE INTO team_members (team_id, user_email) VALUES (?,?)",
                (team_id, email),
            )
    return {"ok": True}


@app.delete("/admin/teams/{team_id}/members/{email}")
def admin_remove_team_member(team_id: int, email: str, authorization: str = Header(None)):
    _require_admin(authorization)
    with get_conn() as conn:
        conn.execute(
            "DELETE FROM team_members WHERE team_id = ? AND user_email = ?", (team_id, email)
        )
    return {"ok": True}


# ── Admin: Badges ─────────────────────────────────────────────────────────────

@app.get("/admin/badges")
def admin_badges(authorization: str = Header(None)):
    _require_admin(authorization)
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM badges ORDER BY org, tier").fetchall()
    return [dict(r) for r in rows]


@app.post("/admin/badges/award")
def admin_award_badge(payload: dict = Body(...), authorization: str = Header(None)):
    admin = _require_admin(authorization)
    email    = payload.get("user_email", "")
    badge_id = payload.get("badge_id")
    if not email or not badge_id:
        raise HTTPException(status_code=400, detail="user_email y badge_id son requeridos")
    with get_conn() as conn:
        try:
            conn.execute(
                "INSERT INTO user_badges (user_email, badge_id, awarded_by) VALUES (?,?,?)",
                (email, badge_id, admin["email"]),
            )
        except Exception:
            raise HTTPException(status_code=409, detail="El usuario ya tiene esta insignia")
    return {"ok": True}


@app.delete("/admin/badges/revoke")
def admin_revoke_badge(payload: dict = Body(...), authorization: str = Header(None)):
    _require_admin(authorization)
    with get_conn() as conn:
        conn.execute(
            "DELETE FROM user_badges WHERE user_email = ? AND badge_id = ?",
            (payload.get("user_email"), payload.get("badge_id")),
        )
    return {"ok": True}


@app.get("/admin/badges/awarded")
def admin_badges_awarded(authorization: str = Header(None)):
    _require_admin(authorization)
    with get_conn() as conn:
        rows = conn.execute("""
            SELECT ub.user_email, u.name AS user_name, b.org, b.name AS badge_name,
                   b.tier, b.icon, ub.awarded_by, ub.awarded_at, ub.badge_id
            FROM user_badges ub
            JOIN badges b ON ub.badge_id = b.id
            JOIN users u ON ub.user_email = u.email
            ORDER BY ub.awarded_at DESC
        """).fetchall()
    return [dict(r) for r in rows]


# ── Student: Badges ───────────────────────────────────────────────────────────

@app.get("/student/badges")
def student_badges(authorization: str = Header(None)):
    user = _require_user(authorization)
    with get_conn() as conn:
        rows = conn.execute("""
            SELECT b.id, b.org, b.name, b.description, b.tier, b.icon,
                   ub.awarded_at, ub.awarded_by,
                   u.name AS owner_name,
                   COALESCE(
                     (SELECT c.title
                      FROM submissions s
                      JOIN challenges c ON c.id = s.challenge_id
                      WHERE s.user_email = ub.user_email AND c.badge_id = b.id
                      ORDER BY s.submitted_at DESC LIMIT 1),
                     (SELECT c.title
                      FROM submissions s
                      JOIN challenges c ON c.id = s.challenge_id
                      WHERE s.user_email = ub.user_email
                      ORDER BY s.submitted_at ASC LIMIT 1),
                     'CTI-Lab'
                   ) AS challenge_title
            FROM user_badges ub
            JOIN badges b ON ub.badge_id = b.id
            JOIN users u ON u.email = ub.user_email
            WHERE ub.user_email = ?
            ORDER BY ub.awarded_at DESC
        """, (user["email"],)).fetchall()
    return [dict(r) for r in rows]


@app.get("/student/team-badges")
def student_team_badges(authorization: str = Header(None)):
    user = _require_user(authorization)
    with get_conn() as conn:
        _auto_award_due_team_badges(conn)
        rows = conn.execute("""
            SELECT b.id, b.org, b.name, b.description, b.tier, b.icon,
                   tb.awarded_at, tb.awarded_by,
                   t.id AS team_id, t.name AS team_name, t.color AS team_color,
                   u.name AS owner_name,
                   COALESCE(
                     (SELECT c.title
                      FROM team_challenge_assignments tca
                      JOIN challenges c ON c.id = tca.challenge_id
                      WHERE tca.team_id = t.id AND c.badge_id = b.id
                      LIMIT 1),
                     'Reto grupal CTI-Lab'
                   ) AS challenge_title
            FROM team_members tm
            JOIN teams t ON t.id = tm.team_id
            JOIN team_badges tb ON tb.team_id = t.id
            JOIN badges b ON b.id = tb.badge_id
            JOIN users u ON u.email = tm.user_email
            WHERE tm.user_email = ?
            ORDER BY tb.awarded_at DESC
        """, (user["email"],)).fetchall()
    return [dict(r) for r in rows]


# ── Student: Team ─────────────────────────────────────────────────────────────

@app.get("/student/team")
def student_team(authorization: str = Header(None)):
    user = _require_user(authorization)
    with get_conn() as conn:
        row = conn.execute("""
            SELECT t.id, t.name, t.color,
                   (SELECT COUNT(*) FROM team_members WHERE team_id = t.id) AS member_count
            FROM team_members tm JOIN teams t ON tm.team_id = t.id
            WHERE tm.user_email = ?
            LIMIT 1
        """, (user["email"],)).fetchone()
    return dict(row) if row else None


# ── Student: Team challenge notification ─────────────────────────────────────

@app.get("/student/team-challenge")
def student_team_challenge(authorization: str = Header(None)):
    user = _require_user(authorization)
    with get_conn() as conn:
        _auto_award_due_team_badges(conn)
        team = conn.execute("""
            SELECT t.id, t.name, t.color
            FROM team_members tm JOIN teams t ON tm.team_id = t.id
            WHERE tm.user_email = ? LIMIT 1
        """, (user["email"],)).fetchone()
        if not team:
            return None
        challenges = conn.execute("""
            SELECT c.id, c.title, c.description, c.objective, c.criteria, c.hints_json,
                   c.difficulty, c.starts_at, c.deadline, c.stage, c.status,
                   c.badge_id, c.min_score_badge,
                   b.name AS badge_name, b.org AS badge_org, b.tier AS badge_tier,
                   d.name AS dataset_name, tca.assigned_at,
                   (SELECT COUNT(*) FROM submissions s
                    WHERE s.challenge_id = c.id AND s.user_email = ?) AS submitted,
                   (SELECT score FROM submissions s
                    WHERE s.challenge_id = c.id AND s.user_email = ?
                    LIMIT 1) AS my_score,
                   (SELECT 1 FROM team_badges tb WHERE tb.team_id=? AND tb.badge_id=c.badge_id) AS badge_earned
            FROM team_challenge_assignments tca
            JOIN challenges c ON tca.challenge_id = c.id
            LEFT JOIN badges b ON c.badge_id = b.id
            LEFT JOIN datasets d ON c.dataset_id = d.id
            WHERE tca.team_id = ?
            ORDER BY tca.assigned_at DESC
        """, (user["email"], user["email"], team["id"], team["id"])).fetchall()
        members = conn.execute("""
            SELECT u.name, u.email, tm.role
            FROM team_members tm JOIN users u ON tm.user_email = u.email
            WHERE tm.team_id = ?
        """, (team["id"],)).fetchall()
        team_badge_rows = conn.execute("""
            SELECT b.id, b.name, b.org, b.tier, b.icon, tb.awarded_at
            FROM team_badges tb JOIN badges b ON tb.badge_id = b.id
            WHERE tb.team_id = ?
        """, (team["id"],)).fetchall()
    return {
        "team": dict(team),
        "challenges": [dict(r) for r in challenges],
        "members": [dict(r) for r in members],
        "team_badges": [dict(r) for r in team_badge_rows],
    }


# ── Admin: Team group challenges ─────────────────────────────────────────────

@app.get("/admin/teams/{team_id}/group-challenges")
def admin_team_group_challenges(team_id: int, authorization: str = Header(None)):
    _require_admin(authorization)
    with get_conn() as conn:
        rows = conn.execute("""
            SELECT c.id, c.title, c.difficulty, c.status, c.badge_id,
                   b.name AS badge_name, tca.assigned_at,
                   (SELECT 1 FROM team_badges tb WHERE tb.team_id=? AND tb.badge_id=c.badge_id) AS badge_earned
            FROM team_challenge_assignments tca
            JOIN challenges c ON tca.challenge_id = c.id
            LEFT JOIN badges b ON c.badge_id = b.id
            WHERE tca.team_id = ?
        """, (team_id, team_id)).fetchall()
    return [dict(r) for r in rows]


@app.post("/admin/teams/{team_id}/group-challenges")
def admin_assign_team_challenge(team_id: int, payload: dict = Body(...), authorization: str = Header(None)):
    _require_admin(authorization)
    cid = payload.get("challenge_id")
    if not cid:
        raise HTTPException(status_code=400, detail="challenge_id requerido")
    with get_conn() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO team_challenge_assignments (team_id, challenge_id) VALUES (?,?)",
            (team_id, cid),
        )
    return {"ok": True}


@app.delete("/admin/teams/{team_id}/group-challenges/{challenge_id}")
def admin_remove_team_challenge(team_id: int, challenge_id: int, authorization: str = Header(None)):
    _require_admin(authorization)
    with get_conn() as conn:
        conn.execute(
            "DELETE FROM team_challenge_assignments WHERE team_id=? AND challenge_id=?",
            (team_id, challenge_id),
        )
    return {"ok": True}


# ── Admin: Team badges (separate from individual badges) ─────────────────────

@app.get("/admin/team-badges/awarded")
def admin_team_badges_awarded(authorization: str = Header(None)):
    _require_admin(authorization)
    with get_conn() as conn:
        rows = conn.execute("""
            SELECT t.id AS team_id, t.name AS team_name, t.color AS team_color,
                   b.id AS badge_id, b.name AS badge_name, b.org, b.tier, b.icon,
                   tb.awarded_by, tb.awarded_at
            FROM team_badges tb
            JOIN teams t ON tb.team_id = t.id
            JOIN badges b ON tb.badge_id = b.id
            ORDER BY tb.awarded_at DESC
        """).fetchall()
    return [dict(r) for r in rows]


@app.post("/admin/team-badges/award")
def admin_award_team_badge(payload: dict = Body(...), authorization: str = Header(None)):
    admin = _require_admin(authorization)
    team_id  = payload.get("team_id")
    badge_id = payload.get("badge_id")
    if not team_id or not badge_id:
        raise HTTPException(status_code=400, detail="team_id y badge_id requeridos")
    with get_conn() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO team_badges (team_id, badge_id, awarded_by) VALUES (?,?,?)",
            (team_id, badge_id, admin["email"]),
        )
    return {"ok": True}


@app.delete("/admin/team-badges/revoke")
def admin_revoke_team_badge(payload: dict = Body(...), authorization: str = Header(None)):
    _require_admin(authorization)
    with get_conn() as conn:
        conn.execute(
            "DELETE FROM team_badges WHERE team_id=? AND badge_id=?",
            (payload.get("team_id"), payload.get("badge_id")),
        )
    return {"ok": True}


# ── CTF Phases (Admin) ────────────────────────────────────────────────────────

@app.get("/admin/ctf-phases")
def admin_ctf_phases(authorization: str = Header(None)):
    _require_admin(authorization)
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM ctf_phases ORDER BY order_idx"
        ).fetchall()
    return [dict(r) for r in rows]


@app.post("/admin/ctf-phases")
def admin_create_ctf_phase(payload: dict = Body(...), authorization: str = Header(None)):
    _require_admin(authorization)
    with get_conn() as conn:
        max_order = conn.execute("SELECT COALESCE(MAX(order_idx),0) FROM ctf_phases").fetchone()[0]
        cur = conn.execute(
            "INSERT INTO ctf_phases (order_idx, name, category, reto_count, group_label, emoji) VALUES (?,?,?,?,?,?)",
            (max_order + 1, payload.get("name","Nueva fase"), payload.get("category",""),
             payload.get("reto_count", 0), payload.get("group_label",""), payload.get("emoji","📅")),
        )
    return {"id": cur.lastrowid}


@app.patch("/admin/ctf-phases/{phase_id}")
def admin_update_ctf_phase(phase_id: int, payload: dict = Body(...), authorization: str = Header(None)):
    _require_admin(authorization)
    with get_conn() as conn:
        if "status" in payload:
            if payload["status"] not in ("active", "inactive"):
                raise HTTPException(status_code=400, detail="status debe ser 'active' o 'inactive'")
            conn.execute("UPDATE ctf_phases SET status = ? WHERE id = ?", (payload["status"], phase_id))
        if "solves" in payload:
            conn.execute("UPDATE ctf_phases SET solves = ? WHERE id = ?", (payload["solves"], phase_id))
        if "name" in payload:
            conn.execute("UPDATE ctf_phases SET name = ? WHERE id = ?", (payload["name"], phase_id))
        if "reto_count" in payload:
            conn.execute("UPDATE ctf_phases SET reto_count = ? WHERE id = ?", (payload["reto_count"], phase_id))
        if "emoji" in payload:
            conn.execute("UPDATE ctf_phases SET emoji = ? WHERE id = ?", (payload["emoji"], phase_id))
    return {"ok": True}


@app.delete("/admin/ctf-phases/{phase_id}")
def admin_delete_ctf_phase(phase_id: int, authorization: str = Header(None)):
    _require_admin(authorization)
    with get_conn() as conn:
        conn.execute("DELETE FROM ctf_phases WHERE id = ?", (phase_id,))
    return {"ok": True}


# ── CTF Phases (Student) ──────────────────────────────────────────────────────

@app.get("/student/ctf-phases")
def student_ctf_phases(authorization: str = Header(None)):
    _require_user(authorization)
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT id, order_idx, name, category, reto_count, group_label, emoji, status, solves FROM ctf_phases ORDER BY order_idx"
        ).fetchall()
    return [dict(r) for r in rows]


# ── Admin: CTF Challenges ─────────────────────────────────────────────────────

@app.get("/admin/ctf-challenges")
def admin_ctf_challenges(phase_id: int = None, authorization: str = Header(None)):
    _require_admin(authorization)
    with get_conn() as conn:
        if phase_id:
            rows = conn.execute("""
                SELECT c.*, d.name AS dataset_name,
                       (SELECT COUNT(*) FROM ctf_solves s WHERE s.challenge_id = c.id AND s.is_correct = 1) AS solve_count
                FROM ctf_challenges c
                LEFT JOIN datasets d ON c.dataset_id = d.id
                WHERE c.phase_id = ?
                ORDER BY c.order_idx
            """, (phase_id,)).fetchall()
        else:
            rows = conn.execute("""
                SELECT c.*, d.name AS dataset_name, p.name AS phase_name,
                       (SELECT COUNT(*) FROM ctf_solves s WHERE s.challenge_id = c.id AND s.is_correct = 1) AS solve_count
                FROM ctf_challenges c
                LEFT JOIN datasets d ON c.dataset_id = d.id
                LEFT JOIN ctf_phases p ON c.phase_id = p.id
                ORDER BY p.order_idx, c.order_idx
            """).fetchall()
    return [dict(r) for r in rows]


@app.post("/admin/ctf-challenges")
def admin_create_ctf_challenge(payload: dict = Body(...), authorization: str = Header(None)):
    admin = _require_admin(authorization)
    if not payload.get("title"):
        raise HTTPException(status_code=400, detail="Título requerido")
    import json as _json
    with get_conn() as conn:
        cur = conn.execute(
            """INSERT INTO ctf_challenges
               (phase_id, order_idx, title, description, flag, flag_format,
                hints_json, category, difficulty, points, docker_image, docker_port,
                tools_json, roles_json, dataset_id, is_team, created_by)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                payload.get("phase_id"),
                payload.get("order_idx", 0),
                payload["title"],
                payload.get("description", ""),
                payload.get("flag", ""),
                payload.get("flag_format", "CTI{...}"),
                _json.dumps(payload.get("hints", [])),
                payload.get("category", "CTI"),
                payload.get("difficulty", "fácil"),
                int(payload.get("points", 100)),
                payload.get("docker_image", ""),
                payload.get("docker_port", "8080"),
                _json.dumps(payload.get("tools", [])),
                _json.dumps(payload.get("roles", [])),
                payload.get("dataset_id") or None,
                1 if payload.get("is_team") else 0,
                admin["email"],
            ),
        )
    return {"id": cur.lastrowid}


@app.patch("/admin/ctf-challenges/{challenge_id}")
def admin_update_ctf_challenge(challenge_id: int, payload: dict = Body(...), authorization: str = Header(None)):
    _require_admin(authorization)
    updatable = ["title", "description", "flag", "flag_format", "category", "difficulty",
                 "points", "docker_image", "docker_port", "status", "order_idx"]
    with get_conn() as conn:
        for field in updatable:
            if field in payload:
                conn.execute(f"UPDATE ctf_challenges SET {field} = ? WHERE id = ?", (payload[field], challenge_id))
        if "phase_id" in payload:
            conn.execute("UPDATE ctf_challenges SET phase_id = ? WHERE id = ?", (payload["phase_id"], challenge_id))
        if "dataset_id" in payload:
            conn.execute("UPDATE ctf_challenges SET dataset_id = ? WHERE id = ?", (payload.get("dataset_id") or None, challenge_id))
    return {"ok": True}


@app.delete("/admin/ctf-challenges/{challenge_id}")
def admin_delete_ctf_challenge(challenge_id: int, authorization: str = Header(None)):
    _require_admin(authorization)
    with get_conn() as conn:
        conn.execute("DELETE FROM ctf_solves WHERE challenge_id = ?", (challenge_id,))
        conn.execute("DELETE FROM ctf_challenges WHERE id = ?", (challenge_id,))
    return {"ok": True}


@app.get("/admin/ctf-leaderboard")
def admin_ctf_leaderboard(authorization: str = Header(None)):
    _require_admin(authorization)
    with get_conn() as conn:
        rows = conn.execute("""
            SELECT u.name, u.email, u.role,
                   COUNT(s.id) AS solves,
                   COALESCE(SUM(s.points_earned), 0) AS total_points,
                   MAX(s.solved_at) AS last_solve
            FROM users u
            LEFT JOIN ctf_solves s ON u.email = s.user_email AND s.is_correct = 1
            GROUP BY u.email
            ORDER BY total_points DESC, solves DESC
        """).fetchall()
        badges_map = {}
        for r in conn.execute("SELECT user_email, COUNT(*) c FROM user_badges GROUP BY user_email").fetchall():
            badges_map[r["user_email"]] = r["c"]
    result = []
    for i, r in enumerate(rows):
        d = dict(r)
        d["rank"] = i + 1
        d["badges"] = badges_map.get(r["email"], 0)
        result.append(d)
    return result


# ── Admin: CTF Challenge flag submit (admin test) ─────────────────────────────

@app.post("/admin/ctf-challenges/{challenge_id}/test-flag")
def admin_test_flag(challenge_id: int, payload: dict = Body(...), authorization: str = Header(None)):
    _require_admin(authorization)
    with get_conn() as conn:
        ch = conn.execute("SELECT flag FROM ctf_challenges WHERE id = ?", (challenge_id,)).fetchone()
    if not ch:
        raise HTTPException(status_code=404, detail="Reto no encontrado")
    return {"correct": payload.get("flag", "").strip() == ch["flag"].strip()}


# ── Student: CTF Challenges ───────────────────────────────────────────────────

@app.get("/student/ctf-challenges")
def student_ctf_challenges(authorization: str = Header(None)):
    user = _require_user(authorization)
    with get_conn() as conn:
        rows = conn.execute("""
            SELECT c.id, c.phase_id, c.order_idx, c.title, c.description,
                   c.flag_format, c.hints_json, c.category, c.difficulty,
                   c.points, c.docker_image, c.docker_port,
                   c.tools_json, c.roles_json, c.is_team, c.status,
                   d.name AS dataset_name,
                   p.name AS phase_name, p.status AS phase_status,
                   (SELECT is_correct FROM ctf_solves s
                    WHERE s.challenge_id = c.id AND s.user_email = ? LIMIT 1) AS solved,
                   (SELECT COUNT(*) FROM ctf_solves s
                    WHERE s.challenge_id = c.id AND s.is_correct = 1) AS total_solves
            FROM ctf_challenges c
            LEFT JOIN datasets d ON c.dataset_id = d.id
            LEFT JOIN ctf_phases p ON c.phase_id = p.id
            WHERE c.status = 'active'
            ORDER BY p.order_idx, c.order_idx
        """, (user["email"],)).fetchall()
    return [dict(r) for r in rows]


@app.post("/student/ctf-challenges/{challenge_id}/submit")
def student_ctf_submit(challenge_id: int, payload: dict = Body(...), authorization: str = Header(None)):
    user = _require_user(authorization)
    submitted = payload.get("flag", "").strip()
    with get_conn() as conn:
        ch = conn.execute("SELECT flag, points, phase_id FROM ctf_challenges WHERE id = ? AND status = 'active'", (challenge_id,)).fetchone()
        if not ch:
            raise HTTPException(status_code=404, detail="Reto no encontrado o inactivo")
        already = conn.execute(
            "SELECT is_correct FROM ctf_solves WHERE challenge_id = ? AND user_email = ?",
            (challenge_id, user["email"]),
        ).fetchone()
        if already and already["is_correct"]:
            return {"correct": True, "message": "Ya resolviste este reto anteriormente", "already_solved": True}
        is_correct = submitted == ch["flag"].strip()
        points_earned = ch["points"] if is_correct else 0
        if already:
            conn.execute(
                "UPDATE ctf_solves SET submitted_flag=?, is_correct=?, points_earned=?, solved_at=datetime('now') WHERE challenge_id=? AND user_email=?",
                (submitted, is_correct, points_earned, challenge_id, user["email"]),
            )
        else:
            conn.execute(
                "INSERT INTO ctf_solves (challenge_id, user_email, submitted_flag, is_correct, points_earned) VALUES (?,?,?,?,?)",
                (challenge_id, user["email"], submitted, is_correct, points_earned),
            )
        if is_correct:
            conn.execute(
                "UPDATE ctf_phases SET solves = solves + 1 WHERE id = ?", (ch["phase_id"],)
            )
    return {"correct": is_correct, "points": points_earned if is_correct else 0}


# ── Admin: Multi-dataset for challenges ──────────────────────────────────────

@app.get("/admin/challenges/{challenge_id}/datasets")
def admin_challenge_datasets(challenge_id: int, authorization: str = Header(None)):
    _require_admin(authorization)
    with get_conn() as conn:
        rows = conn.execute("""
            SELECT d.id, d.name, d.description, d.source
            FROM challenge_datasets cd JOIN datasets d ON cd.dataset_id = d.id
            WHERE cd.challenge_id = ?
        """, (challenge_id,)).fetchall()
    return [dict(r) for r in rows]


@app.post("/admin/challenges/{challenge_id}/datasets")
def admin_add_challenge_dataset(challenge_id: int, payload: dict = Body(...), authorization: str = Header(None)):
    _require_admin(authorization)
    dataset_id = payload.get("dataset_id")
    if not dataset_id:
        raise HTTPException(status_code=400, detail="dataset_id requerido")
    with get_conn() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO challenge_datasets (challenge_id, dataset_id) VALUES (?,?)",
            (challenge_id, dataset_id),
        )
    return {"ok": True}


@app.delete("/admin/challenges/{challenge_id}/datasets/{dataset_id}")
def admin_remove_challenge_dataset(challenge_id: int, dataset_id: int, authorization: str = Header(None)):
    _require_admin(authorization)
    with get_conn() as conn:
        conn.execute(
            "DELETE FROM challenge_datasets WHERE challenge_id = ? AND dataset_id = ?",
            (challenge_id, dataset_id),
        )
    return {"ok": True}


# ── Admin: Badge Progress ─────────────────────────────────────────────────────

@app.get("/admin/badge-progress")
def admin_badge_progress(authorization: str = Header(None)):
    _require_admin(authorization)
    with get_conn() as conn:
        users = conn.execute(
            "SELECT id, name, email, role FROM users ORDER BY name"
        ).fetchall()
        badges = conn.execute(
            "SELECT id, name, org, tier FROM badges ORDER BY org, tier"
        ).fetchall()
        earned = conn.execute(
            "SELECT user_email, badge_id, awarded_at FROM user_badges"
        ).fetchall()
        ctf_scores = conn.execute("""
            SELECT user_email, COUNT(*) AS solves, COALESCE(SUM(points_earned),0) AS points
            FROM ctf_solves WHERE is_correct = 1 GROUP BY user_email
        """).fetchall()
        sub_scores = conn.execute("""
            SELECT user_email, COUNT(*) AS submissions, AVG(score) AS avg_score
            FROM submissions WHERE score IS NOT NULL GROUP BY user_email
        """).fetchall()
    earned_map: dict[str, set] = {}
    earned_dates: dict[tuple, str] = {}
    for e in earned:
        earned_map.setdefault(e["user_email"], set()).add(e["badge_id"])
        earned_dates[(e["user_email"], e["badge_id"])] = e["awarded_at"]
    ctf_map = {r["user_email"]: dict(r) for r in ctf_scores}
    sub_map = {r["user_email"]: dict(r) for r in sub_scores}
    result = []
    for u in users:
        earned_ids = earned_map.get(u["email"], set())
        result.append({
            "name":        u["name"],
            "email":       u["email"],
            "role":        u["role"],
            "badges":      [{"id": b["id"], "name": b["name"], "org": b["org"], "tier": b["tier"],
                             "earned": b["id"] in earned_ids,
                             "earned_at": earned_dates.get((u["email"], b["id"]), None)}
                            for b in badges],
            "badge_count": len(earned_ids),
            "ctf_solves":  ctf_map.get(u["email"], {}).get("solves", 0),
            "ctf_points":  ctf_map.get(u["email"], {}).get("points", 0),
            "avg_score":   round(sub_map.get(u["email"], {}).get("avg_score", 0) or 0, 1),
            "submissions": sub_map.get(u["email"], {}).get("submissions", 0),
        })
    return result


# ── Admin: Team member role ───────────────────────────────────────────────────

@app.patch("/admin/teams/{team_id}/members/{email}/role")
def admin_set_member_role(team_id: int, email: str, payload: dict = Body(...), authorization: str = Header(None)):
    _require_admin(authorization)
    role = payload.get("role", "analista_datos")
    valid = {"analista_datos", "ciberseguridad", "ciencia_datos", "machine_learning"}
    if role not in valid:
        raise HTTPException(status_code=400, detail=f"Rol inválido. Válidos: {valid}")
    with get_conn() as conn:
        conn.execute(
            "UPDATE team_members SET role = ? WHERE team_id = ? AND user_email = ?",
            (role, team_id, email),
        )
    return {"ok": True}


@app.get("/admin/teams/{team_id}/members")
def admin_team_members(team_id: int, authorization: str = Header(None)):
    _require_admin(authorization)
    with get_conn() as conn:
        rows = conn.execute("""
            SELECT tm.user_email, tm.role, tm.joined_at, u.name
            FROM team_members tm JOIN users u ON tm.user_email = u.email
            WHERE tm.team_id = ?
        """, (team_id,)).fetchall()
    return [dict(r) for r in rows]


# ── Rule Depuration Pipeline ───────────────────────────────────────────────────

@app.post("/rules/depurate")
def rules_depurate(payload: dict = Body(...), authorization: str = Header(None)):
    """
    Validates an IOA/IOC through the CTI depuration pipeline before rule deployment.
    Checks: CTI context → IoC lifecycle → IoA lifecycle → MITRE D3FEND mapping.
    """
    _auth_user_or_raise(authorization)
    ttp          = payload.get("ttp", "").upper()
    ioc_value    = payload.get("ioc_value", "")
    ioc_type     = payload.get("ioc_type", "ip")
    severity     = payload.get("severity", "medium")
    ioa_priority = payload.get("ioa_priority", "medium")

    # Fetch detection rule and IoA context from TTP map
    ttp_meta = TTP_IOA_MAP.get(ttp, {})
    detection_rule = ttp_meta.get("detection_rule", "")
    ioa_description = ttp_meta.get("ioa", "")
    tactic = ttp_meta.get("tactic", "")

    # Try to find IoC creation date from DB
    ioc_created_at = None
    if ioc_value:
        with get_conn() as conn:
            row = conn.execute(
                "SELECT created_at FROM iocs WHERE ioc = ?", (ioc_value,)
            ).fetchone()
            if row:
                ioc_created_at = row["created_at"]

    result = compute_depuration(
        ttp=ttp,
        ioc_type=ioc_type,
        severity=severity,
        ioc_created_at=ioc_created_at,
        ioa_priority=ioa_priority,
    )

    return {
        **result,
        "ttp":             ttp,
        "tactic":          tactic,
        "ioa_description": ioa_description,
        "detection_rule":  detection_rule,
        "ioc_value":       ioc_value,
    }


@app.get("/rules/ioa-catalog")
def rules_ioa_catalog(authorization: str = Header(None)):
    """Returns all available TTPs with their IoA metadata for the depuration selector."""
    user = _auth_user_or_raise(authorization)
    scoped = _scoped_ioas(user)
    allowed_ttps = {str(ioa.get("ttp", "")).upper() for ioa in scoped}
    return [
        {
            "ttp":            ttp,
            "name":           meta["name"],
            "tactic":         meta["tactic"],
            "ioa":            meta["ioa"],
            "detection_rule": meta["detection_rule"],
            "priority":       meta["priority"],
        }
        for ttp, meta in TTP_IOA_MAP.items()
        if _is_privileged(user) or ttp.upper() in allowed_ttps
    ]


# ── Log Ingestion ─────────────────────────────────────────────────────────────

@app.post("/logs/ingest")
async def logs_ingest(
    file: UploadFile | None = File(None),
    raw_text: str | None = Form(None),
    format_hint: str | None = Form(None),
    save_dataset: str = Form("false"),
    dataset_name: str = Form(""),
    authorization: str | None = Header(None),
):
    """
    Parse and optionally persist log data.

    Accepts either:
    - multipart file upload (any text format)
    - raw_text form field (paste logs directly)

    Returns parsed rows, detected format, and extracted IOCs.
    If save_dataset=true and the caller is authenticated, the parsed
    rows are stored as a dataset accessible to students.
    """
    user = _auth_user_or_raise(authorization)
    if file:
        raw = (await file.read()).decode("utf-8", errors="replace")
        name = file.filename or "upload"
    elif raw_text:
        raw = raw_text
        name = "paste"
    else:
        raise HTTPException(status_code=400, detail="Provide 'file' or 'raw_text'.")

    if len(raw) > 8 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Input too large. Maximum 8 MB.")

    result = parse_logs(raw, hint=format_hint or None)

    # Persist extracted IOCs into the iocs table
    ioc_records = [
        {"ioc": i["ioc"], "type": i["type"], "threat_actor": "log_ingest",
         "severity": "medium", "mitre": "", "country": "", "source": f"log:{name}"}
        for i in result["iocs"]
    ]
    added_iocs = add_uploaded_iocs(ioc_records) if ioc_records else []

    # Optionally save as a student-accessible dataset
    dataset_id = None
    if save_dataset.lower() == "true" and result["rows"]:
        ds_name = (dataset_name.strip() or f"Log Ingest — {name}").strip()[:120]
        with get_conn() as conn:
            cur = conn.execute(
                "INSERT INTO datasets (name, description, source, data_json, schema_json, created_by) VALUES (?,?,?,?,?,?)",
                (
                    ds_name,
                    f"Logs ingestados desde {name} · formato {result['format']} · {result['line_count']} entradas",
                    f"log_ingest:{name}",
                    json.dumps(result["rows"], ensure_ascii=False),
                    json.dumps(result["schema"], ensure_ascii=False),
                    user["email"],
                ),
            )
            dataset_id = cur.lastrowid

    # Broadcast to SSE clients
    live_service.publish("log_ingested", {
        "source": name,
        "format": result["format"],
        "line_count": result["line_count"],
        "ioc_count": len(result["iocs"]),
        "dataset_id": dataset_id,
    })

    return {
        "format":     result["format"],
        "line_count": result["line_count"],
        "rows":       result["rows"][:500],   # first 500 rows for the response
        "schema":     result["schema"],
        "iocs":       result["iocs"],
        "iocs_added": len(added_iocs),
        "dataset_id": dataset_id,
    }


@app.post("/logs/extract-iocs")
async def logs_extract_iocs(payload: dict = Body(...), authorization: str = Header(None)):
    """
    Extract IOCs from arbitrary text without storing anything.
    Body: {"text": "..."}
    """
    _auth_user_or_raise(authorization)
    text = payload.get("text", "")
    if not text:
        return {"iocs": []}
    if len(text) > 2 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Text too large. Maximum 2 MB.")
    return {"iocs": extract_iocs(text), "format": detect_format(text)}


# ── SSE Live Feed ─────────────────────────────────────────────────────────────

@app.get("/live/feed")
async def live_feed(request: Request):
    """
    Server-Sent Events stream.  Each event is a JSON object with at minimum:
      {"type": "...", "ts": "ISO-8601", ...payload...}

    Event types:
      - ioc_added       — new IOC persisted (from feed sync or log ingest)
      - log_ingested    — log batch processed
      - feed_synced     — a feed source was refreshed
      - heartbeat       — keepalive (comment line, no data)

    The first batch of events replays the last 100 from history so
    freshly-connected clients are not starting cold.
    """
    token = request.query_params.get("token", "")
    if not verify_token(token):
        raise HTTPException(status_code=401, detail="No autenticado")
    queue = live_service.subscribe()

    async def generator():
        for ev in live_service.get_history(100):
            yield f"data: {json.dumps(ev)}\n\n"
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    ev = await asyncio.wait_for(queue.get(), timeout=20)
                    yield f"data: {json.dumps(ev)}\n\n"
                except asyncio.TimeoutError:
                    yield ": heartbeat\n\n"
        finally:
            live_service.unsubscribe(queue)

    return StreamingResponse(
        generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/live/status")
def live_status(authorization: str = Header(None)):
    """Returns current SSE subscriber count and recent event count."""
    _auth_user_or_raise(authorization)
    return {
        "clients":       live_service.client_count(),
        "history_count": len(live_service.get_history(300)),
    }


@app.get("/live/export")
def live_export(format: str = "csv", limit: int = 300):
    """
    Export recent SSE history for evidence, audit, or offline analysis.
    Supports csv and json.
    """
    fmt = format.lower().strip()
    if fmt not in {"csv", "json"}:
        raise HTTPException(status_code=400, detail="format must be csv or json")

    events = live_service.get_history(max(1, min(limit, 300)))
    stamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    if fmt == "csv":
        return _csv_response(f"cti-live-feed-{stamp}.csv", events)

    payload = {
        "exported_at": datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
        "count": len(events),
        "limit": limit,
        "events": events,
    }
    return StreamingResponse(
        iter([json.dumps(payload, ensure_ascii=False, indent=2)]),
        media_type="application/json; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename=cti-live-feed-{stamp}.json"},
    )


# ── Feed Sync ─────────────────────────────────────────────────────────────────

@app.post("/admin/feeds/sync")
def admin_feeds_sync(payload: dict = Body(...), authorization: str = Header(None)):
    """
    Trigger a manual sync of one or more public feeds.
    Body: {"feeds": ["ThreatFox", "URLhaus", ...]}  or {"feeds": "all"}
    Returns per-feed results.
    """
    _require_admin(authorization)
    requested = payload.get("feeds", "all")
    names = PUBLIC_FEEDS if requested == "all" else (
        [n for n in requested if n in FETCH_REGISTRY] if isinstance(requested, list) else []
    )
    if not names:
        raise HTTPException(status_code=400, detail="No valid feed names provided.")

    results = {}
    total_added = 0
    for name in names:
        fetcher = FETCH_REGISTRY[name]
        try:
            raw_iocs = fetcher(limit=100)
            # Filter out error entries
            good = [i for i in raw_iocs if "error" not in i and i.get("ioc")]
            added = add_uploaded_iocs(good)
            total_added += len(added)
            results[name] = {"fetched": len(good), "added": len(added), "ok": True}

            # Update feed_sources stats
            with get_conn() as conn:
                conn.execute(
                    """UPDATE feed_sources SET last_fetched = datetime('now'), last_count = ?
                       WHERE name = ?""",
                    (len(good), name),
                )

            # Broadcast each added IOC to SSE (batch as one event)
            if added:
                live_service.publish("feed_synced", {
                    "feed": name,
                    "fetched": len(good),
                    "added": len(added),
                    "sample": added[:3],
                })
        except Exception as exc:
            results[name] = {"ok": False, "error": str(exc)}

    return {"results": results, "total_added": total_added}


# ── Student: Logs / Datasets ──────────────────────────────────────────────────

@app.get("/student/logs")
def student_logs(
    format: str | None = None,
    authorization: str = Header(None),
):
    """
    List datasets available to a student, optionally filtered by log source.
    format query param filters by source prefix: "log_ingest", "CTI-Lab", etc.
    """
    _require_user(authorization)
    with get_conn() as conn:
        if format:
            rows = conn.execute(
                """SELECT id, name, description, source, schema_json, created_at
                   FROM datasets WHERE source LIKE ? ORDER BY created_at DESC""",
                (f"%{format}%",),
            ).fetchall()
        else:
            rows = conn.execute(
                """SELECT id, name, description, source, schema_json, created_at
                   FROM datasets ORDER BY created_at DESC"""
            ).fetchall()
    return [dict(r) for r in rows]


@app.get("/student/logs/{dataset_id}/raw")
def student_log_raw(dataset_id: int, authorization: str = Header(None)):
    """
    Return the raw data_json of a dataset so students can download
    unparsed / structured logs for their own analysis.
    """
    _require_user(authorization)
    with get_conn() as conn:
        row = conn.execute(
            "SELECT name, description, source, data_json, schema_json, created_at FROM datasets WHERE id = ?",
            (dataset_id,),
        ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Dataset not found.")
    return {
        "id":          dataset_id,
        "name":        row["name"],
        "description": row["description"],
        "source":      row["source"],
        "schema":      json.loads(row["schema_json"] or "{}"),
        "data":        json.loads(row["data_json"] or "[]"),
        "created_at":  row["created_at"],
    }


@app.get("/student/logs/{dataset_id}/iocs")
def student_log_iocs(dataset_id: int, authorization: str = Header(None)):
    """
    Re-run IOC extraction on a stored dataset and return the results.
    This lets students discover IOCs from any lab dataset on demand.
    """
    _require_user(authorization)
    with get_conn() as conn:
        row = conn.execute(
            "SELECT name, data_json FROM datasets WHERE id = ?", (dataset_id,)
        ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Dataset not found.")
    try:
        rows = json.loads(row["data_json"] or "[]")
        blob = " ".join(json.dumps(r) for r in rows)
        iocs = extract_iocs(blob)
    except Exception:
        iocs = []
    return {"dataset": row["name"], "iocs": iocs, "count": len(iocs)}


# ── RedCiber Fusion Engine — Gemini endpoints ─────────────────────────────────
#
# All calls are proxied through the backend so GEMINI_API_KEY never reaches
# the browser.  Every endpoint returns HTTP 503 if the key is not configured,
# which the frontend can handle gracefully.
#

def _gemini_wrap(fn, *args, **kwargs):
    """Call a fusion engine function and surface errors cleanly."""
    try:
        return fn(*args, **kwargs)
    except (GeminiNotConfiguredError, ClaudeNotConfiguredError) as e:
        raise HTTPException(status_code=503, detail=str(e))
    except Exception as e:
        msg = str(e)
        # Detect Anthropic credit exhaustion and surface a clear message
        if "credit balance is too low" in msg or "Your credit balance" in msg:
            raise HTTPException(
                status_code=402,
                detail="Créditos de Anthropic agotados. Ve a console.anthropic.com → Plans & Billing y agrega créditos.",
            )
        engine = _fusion_engine()
        raise HTTPException(status_code=502, detail=f"Error del motor CTI ({engine}): {msg}")


def _norm_severity(value: str | None) -> str:
    sev = (value or "medium").strip().lower()
    if sev == "critical":
        return "Critical"
    if sev == "high":
        return "High"
    return "Medium"


def _fallback_predictive_analysis(threats: list[dict], query: str, reason: str = "") -> dict:
    """Deterministic predictive analysis used when the external LLM fails."""
    events = threats or []
    severities = [_norm_severity(str(e.get("severity", ""))) for e in events]
    actors = [str(e.get("threatActor") or e.get("threat_actor") or "Unknown") for e in events]
    tactics = [
        str(e.get("mitreTactic") or e.get("mitre_tactic") or e.get("mitre") or "")
        for e in events
        if e.get("mitreTactic") or e.get("mitre_tactic") or e.get("mitre")
    ]
    countries = [
        str(e.get("targetCountry") or e.get("country") or "")
        for e in events
        if e.get("targetCountry") or e.get("country")
    ]

    sev_counts = Counter(severities)
    actor_counts = Counter(a for a in actors if a and a != "Unknown")
    tactic_counts = Counter(t for t in tactics if t)
    country_counts = Counter(c for c in countries if c)

    top_actor = actor_counts.most_common(1)[0][0] if actor_counts else (query or "Actor no determinado")
    top_tactic = tactic_counts.most_common(1)[0][0] if tactic_counts else "Initial Access"
    top_country = country_counts.most_common(1)[0][0] if country_counts else "objetivos mixtos"

    critical = sev_counts.get("Critical", 0)
    high = sev_counts.get("High", 0)
    total = max(len(events), 1)
    risk_ratio = (critical * 1.0 + high * 0.65) / total
    if critical or risk_ratio >= 0.55:
        severity = "Critical"
    elif high or risk_ratio >= 0.25:
        severity = "High"
    else:
        severity = "Medium"
    probability = round(min(0.92, max(0.45, 0.42 + risk_ratio + min(len(actor_counts), 5) * 0.035)), 2)

    next_tactic_map = {
        "Initial Access": "Execution",
        "Execution": "Persistence",
        "Persistence": "Privilege Escalation",
        "Privilege Escalation": "Defense Evasion",
        "Defense Evasion": "Credential Access",
        "Credential Access": "Discovery",
        "Discovery": "Lateral Movement",
        "Lateral Movement": "Collection",
        "Collection": "Exfiltration",
        "Command and Control": "Actions on Objectives",
    }
    next_tactic = next_tactic_map.get(top_tactic, "Command and Control")

    historical = []
    for actor, count in actor_counts.most_common(5):
        actor_tactics = [
            str(e.get("mitreTactic") or e.get("mitre_tactic") or e.get("mitre") or "")
            for e in events
            if str(e.get("threatActor") or e.get("threat_actor") or "Unknown") == actor
        ]
        actor_tactic_counts = Counter(t for t in actor_tactics if t)
        historical.append({
            "actor": actor,
            "consistencyScore": round(min(0.95, 0.58 + count / total * 0.35), 2),
            "anomalousActions": [
                "Revisar eventos con severidad alta fuera de la táctica dominante",
                "Validar infraestructura compartida antes de atribución definitiva",
            ],
            "confirmedPatterns": [
                f"{count} eventos asociados al actor",
                f"Táctica dominante: {actor_tactic_counts.most_common(1)[0][0] if actor_tactic_counts else top_tactic}",
            ],
        })

    cross_actor = []
    if len(actor_counts) > 1 and tactic_counts:
        actors_top = [a for a, _ in actor_counts.most_common(3)]
        cross_actor.append({
            "actors": actors_top,
            "sharedTtp": top_tactic,
            "sharedInfrastructure": "Coincidencia operativa inferida por táctica, severidad y ventana de eventos; requiere validación con IOC/ASN/WHOIS.",
            "targetOverlapScore": round(min(0.9, 0.35 + len(actors_top) * 0.12 + risk_ratio * 0.35), 2),
        })

    fallback_note = " Análisis generado en modo heurístico local por indisponibilidad temporal del motor IA." if reason else ""
    return {
        "potentialImpact": {
            "severity": severity,
            "probability": probability,
            "reasoning": (
                f"Se analizaron {len(events)} eventos para '{query}'. Predominan {top_actor}, "
                f"{top_tactic} y objetivos en {top_country}. La ponderación de severidad "
                f"({critical} críticos, {high} altos) sugiere impacto {severity}."
                f"{fallback_note}"
            ),
        },
        "predictedNextTactic": {
            "tactic": next_tactic,
            "reasoning": f"Después de {top_tactic}, la progresión ATT&CK más probable es {next_tactic}, especialmente si existen eventos de severidad alta o crítica.",
        },
        "recalculatedAttribution": {
            "actor": top_actor,
            "confidence": round(min(0.9, 0.48 + (actor_counts.get(top_actor, 1) / total) * 0.38 + risk_ratio * 0.12), 2),
            "reasoning": "La atribución se recalcula por frecuencia del actor, severidad, táctica dominante y solapamiento de objetivos. Requiere enriquecimiento externo para confirmación final.",
        },
        "multiActorCorrelation": (
            f"Se observan {len(actor_counts)} actores con posible solapamiento táctico en {top_tactic}."
            if len(actor_counts) > 1 else "No hay suficientes actores distintos para inferir correlación multi-actor robusta."
        ),
        "historicalValidation": historical,
        "crossActorNexus": cross_actor,
        "analysisMode": "heuristic-fallback" if reason else "heuristic",
        "engineWarning": reason,
    }


def _fallback_ml_proposals(events: list[dict], reason: str = "") -> dict:
    rows = events or []
    actor_counts = Counter(str(e.get("threatActor") or e.get("threat_actor") or "Unknown") for e in rows)
    sev_counts = Counter(_norm_severity(str(e.get("severity", ""))) for e in rows)
    proposals = []
    for actor, count in actor_counts.most_common(6):
        high_signal = sev_counts.get("Critical", 0) + sev_counts.get("High", 0)
        model = "Random Forest" if count >= 3 else "Isolation Forest"
        if high_signal >= max(3, len(rows) // 3):
            model = "Gradient Boosted Trees"
        proposals.append({
            "actor": actor,
            "suggestedModel": model,
            "reasoning": f"Modelo recomendado por volumen relativo ({count} eventos), severidad y mezcla de TTP/IOC disponible.",
            "featuresToUse": ["severity_score", "mitre_tactic", "ioc_type", "source_country", "target_country", "confidence_score"],
            "labelStrategy": "Clasificación supervisada si hay etiquetas históricas; anomalía no supervisada si el dataset es nuevo.",
            "validationMetric": "F1 macro + matriz de confusión por severidad",
        })
    return {
        "summary": f"Propuestas ML generadas para {len(rows)} eventos. " + ("Modo heurístico local por fallo temporal del motor IA." if reason else ""),
        "proposals": proposals,
        "analysisMode": "heuristic-fallback" if reason else "heuristic",
        "engineWarning": reason,
    }


def _require_fusion_access(authorization: str | None) -> dict:
    user = _auth_user_or_raise(authorization)
    if not _is_privileged(user):
        raise HTTPException(
            status_code=403,
            detail="El Motor de Fusión completo está reservado para roles de análisis/instrucción. Los estudiantes acceden a inteligencia limitada por reto asignado.",
        )
    return user


@app.get("/ai/gemini/status")
def gemini_status(authorization: str = Header(None)):
    """Check which fusion engine is active (Gemini, Claude, or none)."""
    _require_fusion_access(authorization)
    engine = _fusion_engine()
    if engine == "gemini":
        return {"configured": True, "engine": "gemini", "model_fast": os.getenv("GEMINI_MODEL_FAST", "gemini-2.0-flash")}
    if engine == "claude":
        from ai.claude_fusion_engine import _MODEL as claude_model
        return {"configured": True, "engine": "claude", "model_fast": claude_model}
    return {"configured": False, "engine": "none", "model_fast": "—"}


@app.post("/ai/gemini/threat-data")
def gemini_threat_data(payload: dict = Body(...), authorization: str = Header(None)):
    """
    Generate 60 (operativo) or 500 (annual) structured threat events via Gemini.
    Body: { "topic": str, "is_annual": bool }
    """
    _require_fusion_access(authorization)
    return _gemini_wrap(
        generate_threat_data,
        payload.get("topic", ""),
        bool(payload.get("is_annual", False)),
    )


@app.post("/ai/gemini/quantum")
def gemini_quantum(payload: dict = Body(...), authorization: str = Header(None)):
    """Quantum / PQC risk analysis for a threat actor."""
    _require_fusion_access(authorization)
    return _gemini_wrap(
        generate_quantum_threat_analysis,
        payload.get("actor", ""),
        payload.get("events", []),
    )


@app.post("/ai/gemini/predictive")
def gemini_predictive(payload: dict = Body(...), authorization: str = Header(None)):
    """Predictive analysis: next tactic, attribution, multi-actor correlation."""
    _require_fusion_access(authorization)
    threats = payload.get("threats", [])
    query = payload.get("query", "")
    try:
        return _gemini_wrap(generate_predictive_analysis, threats, query)
    except HTTPException as e:
        return _fallback_predictive_analysis(threats, query, str(e.detail))


@app.post("/ai/gemini/fusion-report")
def gemini_fusion_report(payload: dict = Body(...), authorization: str = Header(None)):
    """Executive intelligence fusion report with Google Search grounding."""
    _require_fusion_access(authorization)
    return _gemini_wrap(
        generate_fusion_report,
        payload.get("query", ""),
        payload.get("threats", []),
    )


@app.post("/ai/gemini/mitre-details")
def gemini_mitre_details(payload: dict = Body(...), authorization: str = Header(None)):
    """MITRE ATT&CK technique deep-dive for a specific actor."""
    _require_fusion_access(authorization)
    return _gemini_wrap(
        generate_mitre_details,
        payload.get("actor", ""),
        payload.get("technique_ids", []),
    )


@app.get("/ai/gemini/welcome")
def gemini_welcome(authorization: str = Header(None)):
    """Welcome panel: 5 recent APTs + 5 CVEs + 5 LATAM incidents."""
    _require_fusion_access(authorization)
    return _gemini_wrap(generate_welcome_data)


@app.post("/ai/gemini/ioc-context")
def gemini_ioc_context(payload: dict = Body(...), authorization: str = Header(None)):
    """IOC context with Google Search grounding (actor, malware, campaigns)."""
    _require_fusion_access(authorization)
    ioc = payload.get("ioc", "").strip()
    if not ioc:
        raise HTTPException(status_code=400, detail="'ioc' field required.")
    return _gemini_wrap(query_ioc_context, ioc)


@app.post("/ai/gemini/weekly-report")
def gemini_weekly_report(payload: dict = Body(...), authorization: str = Header(None)):
    """Weekly flash report: TTPs, IOCs, hunting queries (Sigma/KQL/Splunk/YARA/PS)."""
    _require_fusion_access(authorization)
    return _gemini_wrap(
        generate_weekly_flash_report,
        payload.get("query", ""),
        payload.get("events", []),
    )


@app.post("/ai/gemini/extract-entities")
def gemini_extract_entities(payload: dict = Body(...), authorization: str = Header(None)):
    """Extract IOCs, actors, malware, CVEs from unstructured text."""
    _require_fusion_access(authorization)
    text = payload.get("text", "")
    if not text:
        raise HTTPException(status_code=400, detail="'text' field required.")
    return _gemini_wrap(extract_entities_from_text, text)


@app.post("/ai/gemini/colombia-risk")
def gemini_colombia_risk(payload: dict = Body(...), authorization: str = Header(None)):
    """Colombian critical infrastructure risk assessment (Decreto 338/2022)."""
    _require_fusion_access(authorization)
    return _gemini_wrap(
        assess_colombian_risk,
        payload.get("actor", ""),
        payload.get("events", []),
    )


@app.post("/ai/gemini/crisis-map")
def gemini_crisis_map(payload: dict = Body(...), authorization: str = Header(None)):
    """Cyber crisis map: attack phases + strategic responses."""
    _require_fusion_access(authorization)
    return _gemini_wrap(
        generate_crisis_map,
        payload.get("actor", ""),
        payload.get("ttps", []),
    )


@app.post("/ai/gemini/team-scenarios")
def gemini_team_scenarios(payload: dict = Body(...), authorization: str = Header(None)):
    """Red / Blue / Purple / White Team simulation scenarios."""
    _require_fusion_access(authorization)
    return _gemini_wrap(
        generate_team_scenarios,
        payload.get("actor", ""),
        payload.get("ttps", []),
    )


@app.post("/ai/gemini/behavioral")
def gemini_behavioral(payload: dict = Body(...), authorization: str = Header(None)):
    """Behavioral analysis: threat behavior + historical event explanations."""
    _require_fusion_access(authorization)
    return _gemini_wrap(
        generate_behavioral_analysis,
        payload.get("topic", ""),
        payload.get("threats", []),
    )


@app.post("/ai/gemini/playbook")
def gemini_playbook(payload: dict = Body(...), authorization: str = Header(None)):
    """Incident response playbook for a given threat."""
    _require_fusion_access(authorization)
    return _gemini_wrap(
        generate_playbook,
        payload.get("threat_name", ""),
        payload.get("threat_type", "Malware"),
    )


@app.post("/ai/gemini/ml-proposals")
def gemini_ml_proposals(payload: dict = Body(...), authorization: str = Header(None)):
    """ML model proposals (Random Forest / LSTM / SVM / Clustering) per event."""
    _require_fusion_access(authorization)
    events = payload.get("events", [])
    try:
        return _gemini_wrap(generate_ml_proposals, events)
    except HTTPException as e:
        return _fallback_ml_proposals(events, str(e.detail))


@app.post("/ai/gemini/geopolitical")
def gemini_geopolitical(payload: dict = Body(...), authorization: str = Header(None)):
    """Geopolitical deep-dive with anticipatory threats and stability score."""
    _require_fusion_access(authorization)
    return _gemini_wrap(
        generate_geopolitical_analysis,
        payload.get("query", ""),
    )


@app.post("/ai/gemini/threat-graph")
def gemini_threat_graph(payload: dict = Body(...), authorization: str = Header(None)):
    """Actor → IOC → Campaign correlation graph enriched with CISA APT database."""
    _require_fusion_access(authorization)
    return _gemini_wrap(
        generate_threat_graph,
        payload.get("events", []),
        payload.get("query", ""),
    )


@app.get("/apt-database")
def apt_database_endpoint(authorization: str = Header(None)):
    """Returns the full CISA-sourced APT database for frontend enrichment."""
    from intelligence.apt_database import get_full_database
    user = _auth_user_or_raise(authorization)
    rows = get_full_database()
    if _is_privileged(user):
        return rows
    allowed = {str(actor.get("name", "")).lower() for actor in _scoped_actors(user)}
    return [
        {
            "name": row.get("name"),
            "aliases": row.get("aliases", [])[:3],
            "country": row.get("country", ""),
            "risk_level": row.get("risk_level", "Medium"),
            "known_campaigns": row.get("known_campaigns", [])[:3],
            "cisa_advisories": row.get("cisa_advisories", [])[:3],
            "scope": "assigned-challenge",
        }
        for row in rows
        if str(row.get("name", "")).lower() in allowed
    ]

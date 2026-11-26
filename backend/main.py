from __future__ import annotations

import asyncio
import csv
import io
import json
import logging
import os
import re
import time as _time
import uuid
import zipfile
from collections import Counter
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

# Load .env from project root (two levels up from backend/) — no-op if missing
try:
    from dotenv import load_dotenv
    _env_path = Path(__file__).parent.parent / ".env"
    load_dotenv(_env_path, override=False)
except ImportError:
    pass

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
)
_logger = logging.getLogger("cti")

import requests
import anthropic
from fastapi import Body, FastAPI, File, Form, Header, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse

from db import init_db, get_conn
from auth import register, login, verify_token, ensure_admin, domain_allowed, open_domains_active, open_signup_until, ALLOWED_DOMAIN
import grading
import hints as hints_mod
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
from ai.ml_engine import (
    score_log_batch, get_model_status, retrain_model, reset_model,
    save_fusion_events_to_corpus, get_supervised_model_status,
    retrain_supervised_model, predict_false_positive, batch_predict_false_positives,
)
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


_ENGINE: str | None = None


def _fusion_engine() -> str:
    """Returns 'gemini', 'claude', or 'none'. Result is cached after first call."""
    global _ENGINE
    if _ENGINE is None:
        if os.getenv("GEMINI_API_KEY"):
            _ENGINE = "gemini"
        elif os.getenv("ANTHROPIC_API_KEY"):
            _ENGINE = "claude"
        else:
            _ENGINE = "none"
        _logger.info("Motor de fusión activo: %s", _ENGINE)
    return _ENGINE


def _fusion_fn(gemini_fn, claude_fn):
    """Return the correct function. Gemini calls fall back to Claude on transient errors."""
    engine = _fusion_engine()
    if engine == "gemini":
        def _gemini_with_fallback(*args, **kwargs):
            try:
                return gemini_fn(*args, **kwargs)
            except GeminiNotConfiguredError:
                raise
            except Exception as exc:
                if not os.getenv("ANTHROPIC_API_KEY"):
                    raise
                _logger.warning(
                    "Gemini falló (%s: %s) — reintentando con Claude como fallback",
                    type(exc).__name__, exc,
                )
                return claude_fn(*args, **kwargs)
        return _gemini_with_fallback
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


def _is_started_until(deadline: str | None) -> bool:
    """True si el plazo AÚN no ha vencido (o no hay plazo)."""
    dt = _parse_dt(deadline)
    return not dt or _now_bogota() < dt


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
    ensure_admin()
    yield


app = FastAPI(
    title="CTI-Lab API",
    description="AI Native Cyber Threat Intelligence Platform",
    version="1.1.0",
    lifespan=lifespan,
)

_CORS_ORIGINS = os.environ.get(
    "CORS_ORIGINS",
    "http://localhost:3000,http://localhost:5173,http://localhost:5174,http://localhost:5175,http://127.0.0.1:3000,http://127.0.0.1:5173,http://127.0.0.1:5174,http://127.0.0.1:5175",
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
    team_id = payload.get("team_id")
    if team_id:
        with get_conn() as conn:
            if not conn.execute("SELECT 1 FROM teams WHERE id = ? AND open_signup = 1", (team_id,)).fetchone():
                raise HTTPException(status_code=400, detail="El grupo elegido no está habilitado para registro")
    try:
        user = register(
            name=payload.get("name", ""),
            email=payload.get("email", ""),
            password=payload.get("password", ""),
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    with get_conn() as conn:
        from db import enroll_individual_path
        enroll_individual_path(conn, user["email"])       # ruta individual solo para cuentas nuevas
        if team_id:
            conn.execute("INSERT OR IGNORE INTO team_members (team_id, user_email) VALUES (?,?)", (team_id, user["email"]))
    return user


@app.get("/auth/open-groups")
def auth_open_groups():
    """Grupos habilitados para que estudiantes nuevos se unan al registrarse (público)."""
    with get_conn() as conn:
        rows = conn.execute("""
            SELECT t.id, t.name, t.color,
                   (SELECT COUNT(*) FROM team_members tm WHERE tm.team_id = t.id) AS members
            FROM teams t WHERE t.open_signup = 1 ORDER BY t.name""").fetchall()
    return [dict(r) for r in rows]


@app.patch("/admin/teams/{team_id}/open-signup")
def admin_team_open_signup(team_id: int, payload: dict = Body(...), authorization: str = Header(None)):
    _require_admin(authorization)
    with get_conn() as conn:
        conn.execute("UPDATE teams SET open_signup = ? WHERE id = ?", (1 if payload.get("open") else 0, team_id))
    return {"ok": True}


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


@app.get("/auth/signup-policy")
def auth_signup_policy():
    until = open_signup_until()
    return {
        "domain": ALLOWED_DOMAIN,
        "open_domains": open_domains_active(),
        "until": until.isoformat() if until else None,
    }


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
        try:
            from ai.claude_fusion_engine import _MODEL as _CLAUDE_MODEL
            from ai.claude_fusion_engine import _get_client as _claude_client
            message = _claude_client().messages.create(
                model=_CLAUDE_MODEL,
                max_tokens=1024,
                system=[{"type": "text", "text": system_context, "cache_control": {"type": "ephemeral"}}],
                messages=[{"role": "user", "content": prompt}],
            )
            return {"response": message.content[0].text}
        except Exception as exc:                       # saldo agotado, límite de uso o caída del proveedor
            logging.getLogger("ai.chat").warning("Asistente de IA no disponible: %s", str(exc)[:200])
            return {"response": _AI_UNAVAILABLE, "degraded": True}

    ollama_url = os.environ.get("OLLAMA_URL", "http://localhost:11434")
    try:
        response = requests.post(
            f"{ollama_url}/api/generate",
            json={"model": "llama3", "prompt": f"{system_context}\n\nUser query: {prompt}\n\nProvide a technical cybersecurity response.", "stream": False},
            timeout=8,
        )
        return {"response": response.json()["response"]}
    except Exception:
        return {"response": _AI_UNAVAILABLE, "degraded": True}


_AI_UNAVAILABLE = (
    "El asistente de IA no está disponible en este momento. No es un error tuyo ni de tu código.\n\n"
    "Mientras se restablece puedes avanzar así:\n"
    "1) Usa las pistas graduales del reto (botón «Pedir pista»): van de lo general a lo concreto.\n"
    "2) Abre «Antes de empezar» y el glosario del capítulo.\n"
    "3) Mira «Mi Tablero» para explorar tus datos y ver qué datasets se pueden cruzar.\n"
    "4) Si sigues atascado, escribe tu duda puntual al docente."
)


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


@app.get("/admin/users/auth-audit")
def admin_users_auth_audit(authorization: str = Header(None)):
    _require_admin(authorization)
    allowed_roles = {"student", "analyst", "senior_analyst", "instructor", "admin"}

    with get_conn() as conn:
        rows = conn.execute("""
            SELECT id, name, email, role, created_at, password_hash, password_expires_at
            FROM users
            ORDER BY created_at DESC
        """).fetchall()

    items = []
    status_counts = Counter()
    for row in rows:
        email = (row["email"] or "").strip()
        role = row["role"] or ""
        password_hash = row["password_hash"] or ""
        expires_at = row["password_expires_at"] or ""
        issues: list[dict[str, str]] = []

        if not (row["name"] or "").strip():
            issues.append({"severity": "error", "code": "missing_name", "detail": "El nombre está vacío."})
        if not email:
            issues.append({"severity": "error", "code": "missing_email", "detail": "El email está vacío."})
        elif not re.match(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$", email):
            issues.append({"severity": "error", "code": "invalid_email", "detail": "El formato del email no es válido."})
        else:
            if email != email.lower():
                issues.append({"severity": "warning", "code": "email_not_normalized", "detail": "El email contiene mayúsculas."})
            if not domain_allowed(email):
                issues.append({"severity": "error", "code": "invalid_domain", "detail": "El dominio no está permitido para login."})

        if role not in allowed_roles:
            issues.append({"severity": "error", "code": "invalid_role", "detail": "El rol no existe en la plataforma."})
        if not password_hash:
            issues.append({"severity": "error", "code": "missing_password_hash", "detail": "No hay hash de contraseña."})
        elif not password_hash.startswith("$2"):
            issues.append({"severity": "error", "code": "invalid_password_hash", "detail": "El hash no usa bcrypt."})
        elif len(password_hash) != 60:
            issues.append({"severity": "warning", "code": "unexpected_hash_length", "detail": "El hash bcrypt tiene longitud inesperada."})

        password_status = "permanent"
        if expires_at:
            exp_dt = _parse_dt(expires_at)
            if not exp_dt:
                password_status = "invalid_expiry"
                issues.append({"severity": "error", "code": "invalid_password_expiry", "detail": "La fecha de expiración no se puede interpretar."})
            elif _is_due(expires_at):
                password_status = "expired"
                issues.append({"severity": "error", "code": "password_expired", "detail": "La contraseña temporal está vencida."})
            else:
                password_status = "temporary_active"

        severity = "ok"
        if any(issue["severity"] == "error" for issue in issues):
            severity = "error"
        elif issues:
            severity = "warning"
        status_counts[severity] += 1

        items.append({
            "id": row["id"],
            "name": row["name"],
            "email": email,
            "role": role,
            "created_at": row["created_at"],
            "password_status": password_status,
            "status": severity,
            "issues": issues,
        })

    return {
        "total": len(items),
        "ok": status_counts["ok"],
        "warnings": status_counts["warning"],
        "errors": status_counts["error"],
        "items": items,
    }


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
                   c.deadline, c.starts_at, c.status, c.created_at, c.stage, c.case_key, c.case_chapter,
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


@app.get("/admin/challenges/{challenge_id}/solution")
def admin_challenge_solution(challenge_id: int, email: str = "", authorization: str = Header(None)):
    """Rúbrica con la respuesta esperada y código de referencia. Para casos con datos por estudiante, usa su variante."""
    admin = _require_admin(authorization)
    with get_conn() as conn:
        ch = conn.execute("""SELECT c.title, c.case_key, c.case_chapter, d.data_json FROM challenges c
                             LEFT JOIN datasets d ON d.id = c.dataset_id WHERE c.id = ?""", (challenge_id,)).fetchone()
    if not ch:
        raise HTTPException(status_code=404)
    from aurora import solutions as sol
    if ch["case_key"] == "aurora":
        from aurora.generator import build_case
        from aurora.chapters import rubric as aurora_rubric
        who = (email or admin["email"]).strip().lower()
        case = build_case(who)
        rub = aurora_rubric(ch["case_chapter"], case["facts"], {"has_wall_report": True})
        exp = sol.expected(ch["case_chapter"], case["facts"])
        code = sol.REFERENCE_CODE.get(ch["case_chapter"], "")
        if ch["case_chapter"] == 8:
            code = sol.reference_note(case["facts"])
        return {"title": ch["title"], "variant": case["code"], "variant_email": who, "reference_code": code,
                "criteria": [{"label": r[0], "weight": r[1], "hint": r[3], "expected": exp[i] if i < len(exp) else ""} for i, r in enumerate(rub)]}
    rub = grading.rubric_for(ch["title"]) or []
    rows = grading.rows_of(ch["data_json"])
    exp = sol.practice_expected(ch["title"], rows)
    return {"title": ch["title"], "variant": None, "variant_email": None, "reference_code": sol.PRACTICE_CODE.get(ch["title"], ""),
            "criteria": [{"label": r[0], "weight": r[1], "hint": r[3], "expected": exp[i] if i < len(exp) else "Se calcula sobre el dataset del reto"} for i, r in enumerate(rub)]}


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
    updatable = ["status", "title", "description", "objective", "criteria", "hints_json", "deadline", "difficulty", "starts_at"]
    if payload.get("status") not in (None, "draft", "active", "closed"):
        raise HTTPException(status_code=400, detail="status debe ser draft, active o closed")
    with get_conn() as conn:
        for field in updatable:
            if field in payload:
                val = payload[field]
                if field in ("starts_at", "deadline") and not val:
                    val = None
                conn.execute(f"UPDATE challenges SET {field} = ? WHERE id = ?", (val, challenge_id))
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
    out = []
    for r in rows:
        d = dict(r)
        d["auto_feedback"], d["teacher_note"] = _split_feedback(d.get("feedback"), d.get("auto_graded", 0))
        out.append(d)
    return out


_NOTE_MARK = "\n\n✉ Docente: "


def _split_feedback(feedback: str | None, auto_graded: int) -> tuple[str, str]:
    """(parte automática, nota del docente). Las notas manuales antiguas, sin marca, son enteramente del docente."""
    fb = feedback or ""
    if _NOTE_MARK in fb:
        a, n = fb.split(_NOTE_MARK, 1)
        return a, n
    return ("", fb) if not auto_graded and fb else (fb, "")


@app.put("/admin/submissions/{submission_id}/score")
def admin_score(submission_id: int, payload: dict = Body(...), authorization: str = Header(None)):
    """Ajusta la nota y/o la retroalimentación del docente. Cada campo es opcional: lo que no se envía no se toca.
    La retroalimentación automática se conserva; la del docente se guarda aparte y se muestra al estudiante."""
    admin = _require_admin(authorization)
    badge_awarded = None
    with get_conn() as conn:
        cur = conn.execute("SELECT user_email, challenge_id, score, feedback, auto_graded FROM submissions WHERE id = ?", (submission_id,)).fetchone()
        if not cur:
            raise HTTPException(status_code=404, detail="Entrega no encontrada")
        new_score, score_changed = cur["score"], False
        if payload.get("score") not in (None, ""):
            try:
                new_score = int(float(payload["score"]))
            except (TypeError, ValueError):
                raise HTTPException(status_code=400, detail="La nota debe ser un número entre 0 y 100")
            if not 0 <= new_score <= 100:
                raise HTTPException(status_code=400, detail="La nota debe estar entre 0 y 100")
            score_changed = new_score != cur["score"]
        auto_part, note = _split_feedback(cur["feedback"], cur["auto_graded"])
        if "feedback" in payload:
            note = str(payload.get("feedback") or "").strip()[:4000]
        new_fb = auto_part + (_NOTE_MARK + note if note else "")
        # Solo pasa a «calificada por el docente» si realmente cambió la nota: así un comentario no frena la autocalificación al reentregar.
        auto_flag = 0 if score_changed else cur["auto_graded"]
        conn.execute("UPDATE submissions SET score = ?, feedback = ?, auto_graded = ? WHERE id = ?", (new_score, new_fb, auto_flag, submission_id))
        if new_score is not None:
            ch = conn.execute("SELECT badge_id, min_score_badge FROM challenges WHERE id = ?", (cur["challenge_id"],)).fetchone()
            if ch and ch["badge_id"] and new_score >= (ch["min_score_badge"] or 70):
                if not conn.execute("SELECT 1 FROM user_badges WHERE user_email = ? AND badge_id = ?", (cur["user_email"], ch["badge_id"])).fetchone():
                    conn.execute("INSERT INTO user_badges (user_email, badge_id, awarded_by) VALUES (?,?,?)", (cur["user_email"], ch["badge_id"], admin["email"]))
                    b = conn.execute("SELECT name, org, tier FROM badges WHERE id = ?", (ch["badge_id"],)).fetchone()
                    badge_awarded = dict(b) if b else None
    return {"ok": True, "score": new_score, "teacher_note": note, "score_changed": score_changed, "badge_awarded": badge_awarded}


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
                   (SELECT COUNT(*) FROM submissions s WHERE s.user_email = u.email) AS submissions,
                   (SELECT COUNT(*) FROM ctf_solves cs
                     WHERE cs.user_email = u.email AND cs.is_correct = 1) AS ctf_solves,
                   (SELECT COALESCE(SUM(cs.points_earned), 0) FROM ctf_solves cs
                     WHERE cs.user_email = u.email AND cs.is_correct = 1) AS ctf_points,
                   (SELECT ROUND(AVG(s.score), 1) FROM submissions s WHERE s.user_email = u.email) AS avg_score
            FROM users u
            WHERE u.role = 'student'
            ORDER BY ctf_points DESC, ctf_solves DESC, submissions DESC, u.name
            LIMIT 5
        """).fetchall()
        team_progress = conn.execute("""
            SELECT t.id, t.name, t.color,
                   (SELECT COUNT(*) FROM team_members tm WHERE tm.team_id = t.id) AS members,
                   (SELECT COUNT(*) FROM team_challenge_assignments tca WHERE tca.team_id = t.id) AS assigned_challenges,
                   (SELECT COUNT(*) FROM team_badges tb WHERE tb.team_id = t.id) AS badges,
                   (SELECT COALESCE(SUM(cs.points_earned), 0) FROM ctf_solves cs
                     WHERE cs.is_correct = 1
                       AND cs.user_email IN (SELECT tm.user_email FROM team_members tm WHERE tm.team_id = t.id)) AS points,
                   (SELECT COUNT(*) FROM ctf_solves cs
                     WHERE cs.is_correct = 1
                       AND cs.user_email IN (SELECT tm.user_email FROM team_members tm WHERE tm.team_id = t.id)) AS solves
            FROM teams t
            ORDER BY points DESC, solves DESC, badges DESC, t.name
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
    is_admin = user.get("role") == "admin"   # vista de admin: todos los retos diseñados, para explicarlos
    with get_conn() as conn:                       # cuentas nuevas: asegurar los capítulos de la ruta antes de listar
        flag = conn.execute("SELECT onboarding_path FROM users WHERE email = ?", (user["email"],)).fetchone()
        if flag and flag["onboarding_path"]:
            from db import ensure_path_assignments, badge_flow_active, sync_chapter_badges
            ensure_path_assignments(conn, user["email"])
            if badge_flow_active(conn):
                sync_chapter_badges(conn, user["email"])
    with get_conn() as conn:
        rows = conn.execute("""
            SELECT c.id, c.title, c.description, c.objective, c.criteria, c.hints_json,
                   c.starts_at, c.deadline, c.stage, c.status, c.difficulty,
                   c.case_key, c.case_chapter,
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
            LEFT JOIN datasets d ON c.dataset_id = d.id
            LEFT JOIN badges b ON c.badge_id = b.id
            WHERE (? = 1 OR (c.status != 'draft' AND EXISTS (
                     SELECT 1 FROM challenge_assignments ca
                     WHERE ca.challenge_id = c.id AND ca.user_email = ?)))
            ORDER BY c.created_at DESC
        """, (user["email"], user["email"], user["email"],
              1 if is_admin else 0, user["email"])).fetchall()
        from db import path_status, PATH_PASS_SCORE
        pstat = path_status(conn, user["email"])

    out = []
    for r in rows:
        if not is_admin and not _is_started(r["starts_at"]):
            continue
        d = dict(r)
        if is_admin:
            d["admin_preview"] = True
        if d.get("case_key") == "aurora":
            from aurora.generator import case_code, DATASETS
            from aurora.chapters import CHAPTER_DATASET
            d["case_code"] = case_code(user["email"])
            d["no_code"] = d["case_chapter"] == 8
            from aurora.learn import LEARN, CICLO
            d["learn"] = {**LEARN.get(d["case_chapter"], {}), "ciclo": CICLO}
            k = CHAPTER_DATASET[d["case_chapter"] - 1]
            d["dataset_name"] = DATASETS[k] if k else "todos los datasets del caso"
        if hints_mod.levels_for(d["title"]):
            d["hints_json"] = "[]"            # las pistas se piden de a una vía /hints
            d["hint_levels"] = len(hints_mod.levels_for(d["title"]))
        st = None if is_admin else pstat.get(d["id"])
        if st:
            d.update(path_order=st["order"], path_total=st["total"], locked=st["locked"],
                     locked_by=st["requires"], path_pass_score=PATH_PASS_SCORE)
            if st["locked"]:      # no filtrar enunciado, pistas ni dataset de un reto aún cerrado
                d.update(objective="", criteria="", hints_json="[]", schema_json=None, dataset_name=None)
                d.pop("learn", None)
        out.append(d)
    out.sort(key=lambda d: (d.get("path_order") is None, d.get("path_order") or 0))
    return out


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
        case = conn.execute("SELECT case_key, case_chapter FROM challenges WHERE id = ?", (challenge_id,)).fetchone()
        if case and case["case_key"] == "aurora":
            return _aurora_dataset_payload(user, case["case_chapter"])
        row = conn.execute("""
            SELECT d.name, d.description, d.data_json, d.schema_json, d.source
            FROM challenges c JOIN datasets d ON c.dataset_id = d.id
            WHERE c.id = ?
        """, (challenge_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Dataset no encontrado")
    return dict(row)


def _aurora_dataset_payload(user: dict, chapter: int) -> dict:
    """Datos del Caso Aurora de ESTE estudiante: dataset del capítulo + los de capítulos anteriores para cruzar."""
    from aurora.generator import build_case, DATASETS
    from aurora.chapters import CHAPTER_DATASET
    case = build_case(user["email"])
    keys = [k for k in CHAPTER_DATASET[:chapter] if k]
    main_key = CHAPTER_DATASET[chapter - 1] or keys[-1]
    rows = case["datasets"][main_key]
    return {"name": DATASETS[main_key], "description": f"Caso Aurora · tu variante {case['code']}", "source": "Caso Aurora (ficticio)",
            "data_json": json.dumps(rows, ensure_ascii=False),
            "schema_json": json.dumps({k: type(v).__name__ for k, v in rows[0].items()}),
            "case_code": case["code"],
            "extras": {DATASETS[k]: case["datasets"][k] for k in keys}}


@app.post("/student/challenges/{challenge_id}/submit")
def student_submit(challenge_id: int, payload: dict = Body(...), authorization: str = Header(None)):
    user = _require_user(authorization)
    _require_not_admin_preview(user)
    with get_conn() as conn:
        ok = _has_challenge_access(conn, challenge_id, user["email"])
        if not ok:
            raise HTTPException(status_code=403)
        ch = conn.execute("SELECT case_key, deadline FROM challenges WHERE id = ?", (challenge_id,)).fetchone()
        if ch and ch["case_key"] == "aurora" and ch["deadline"] and not _is_started_until(ch["deadline"]):
            raise HTTPException(status_code=403, detail="El plazo de este capítulo ya terminó.")
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
            sub_id, created = existing["id"], False
        else:
            cur = conn.execute(
                "INSERT INTO submissions (challenge_id, user_email, user_name, code, output, plots_json, notes) VALUES (?,?,?,?,?,?,?)",
                (challenge_id, user["email"], user.get("name",""),
                 payload.get("code",""), payload.get("output",""), plots, payload.get("notes","")),
            )
            sub_id, created = cur.lastrowid, True
        result = _auto_grade(conn, sub_id, challenge_id, payload)
    out = {"id": sub_id, "created": created, "updated": not created}
    if result:
        out["grading"] = result
        out["score"] = result["score"]
    return out


def _auto_grade(conn, sub_id: int, challenge_id: int, payload: dict) -> dict | None:
    """Califica con la rúbrica del reto. No pisa una nota puesta a mano por el docente."""
    row = conn.execute(
        "SELECT c.title, c.case_key, c.case_chapter, d.data_json FROM challenges c LEFT JOIN datasets d ON d.id = c.dataset_id WHERE c.id = ?",
        (challenge_id,)).fetchone()
    if not row:
        return None
    if row["case_key"] == "aurora":
        from aurora.generator import build_case
        from aurora.chapters import rubric as aurora_rubric
        email = conn.execute("SELECT user_email FROM submissions WHERE id = ?", (sub_id,)).fetchone()["user_email"]
        has_wall = bool(conn.execute("SELECT 1 FROM intel_reports WHERE user_email = ? AND length(title) > 0", (email,)).fetchone())
        case_ = build_case(email)
        facts = case_["facts"]
        result = grading.grade(row["title"], [], payload.get("code", ""), payload.get("output", ""),
                               payload.get("notes", ""), payload.get("plots", []),
                               rubric=aurora_rubric(row["case_chapter"], facts, {"has_wall_report": has_wall}))
    else:
        result = grading.grade(row["title"], grading.rows_of(row["data_json"]),
                               payload.get("code", ""), payload.get("output", ""),
                               payload.get("notes", ""), payload.get("plots", []))
    if not result:
        return None
    manual = conn.execute("SELECT score, auto_graded FROM submissions WHERE id = ?", (sub_id,)).fetchone()
    if manual["score"] is not None and not manual["auto_graded"]:
        result["manual_override"] = True      # el docente ya calificó: se conserva su nota
        return result
    lines = ["Calificación automática (provisional; el docente puede ajustarla)"]
    for it in result["items"]:
        mark = "✓" if it["ok"] else ("◐" if it["partial"] else "✗")
        lines.append(f"{mark} {it['label']} ({it['earned']}/{it['weight']})" + (f" → {it['hint']}" if it["hint"] else ""))
    conn.execute("UPDATE submissions SET score = ?, feedback = ?, auto_graded = 1 WHERE id = ?",
                 (result["score"], "\n".join(lines), sub_id))
    if row["case_key"] == "aurora" and row["case_chapter"] != 8:
        from aurora.review import has_analysis
        if not has_analysis(payload.get("code", "")) and result["score"] > 20:
            # Sin análisis propio (p. ej. solo la plantilla que imprime el dataset) los números impresos coinciden por casualidad: no es mérito.
            result["score"] = min(result["score"], 20)
            result["capped"] = "Tu código no hace ningún análisis propio (solo imprime datos). La nota se limita a 20 hasta que calcules tú los resultados."
            conn.execute("UPDATE submissions SET score = ?, feedback = ? WHERE id = ?",
                         (result["score"], "\n".join(lines) + "\n⚠ " + result["capped"], sub_id))
    if row["case_key"] == "aurora":
        from db import BASE_SCORE
        from aurora.review import has_analysis as _has_an
        out_txt, code_txt, notes_txt = payload.get("output", ""), payload.get("code", ""), payload.get("notes", "")
        crashed = out_txt.startswith("Error:") or "Traceback" in out_txt
        if row["case_chapter"] == 8:
            minimum = len(notes_txt.strip()) >= 250
            why = "un informe propio de al menos ~250 caracteres"
        else:
            minimum = _has_an(code_txt) and bool(out_txt.strip()) and not crashed
            why = "código con análisis propio, que se ejecuta sin errores e imprime resultados"
        if minimum:
            raw = result["score"]
            result["raw_score"] = raw
            result["score"] = round(BASE_SCORE + (100 - BASE_SCORE) * raw / 100)       # parte de 50 y suma por cada criterio logrado
            result["base_applied"] = (f"Reconocemos tu entrega: cumpliste los requisitos mínimos ({why}). Tu nota parte de {BASE_SCORE} "
                                      f"y suma por cada criterio que logres (criterios logrados: {raw}/100).")
            conn.execute("UPDATE submissions SET score = ?, feedback = ? WHERE id = ?",
                         (result["score"], "\n".join(lines) + "\n✓ " + result["base_applied"], sub_id))
    if row["case_key"] == "aurora":
        from aurora.review import review as _review
        from aurora.chapters import CHAPTER_DATASET
        data = {k: case_["datasets"][k] for k in CHAPTER_DATASET[:row["case_chapter"]] if k}
        result["review"] = _review(row["case_chapter"], payload.get("code", ""), payload.get("output", ""), payload.get("notes", ""), data, facts)
        scale = (100 - BASE_SCORE) / 100 if "raw_score" in result else 1.0           # cuánto sube la nota real por cada punto de criterio
        missing = sorted(({"label": it["label"], "points": round((it["weight"] - it["earned"]) * scale), "tip": it["hint"], "partial": it["partial"]}
                          for it in result["items"] if not it["ok"]), key=lambda x: -x["points"])[:3]
        result["review"]["improve"] = missing
        result["review"]["max_gain"] = max(0, 100 - result["score"])
        conn.execute("UPDATE submissions SET review_json = ? WHERE id = ?", (json.dumps(result["review"], ensure_ascii=False), sub_id))
        from db import badge_flow_active, award_chapter_badge, _path_challenges, PATH_PASS_SCORE
        result["pass_score"] = PATH_PASS_SCORE
        result["passed"] = result["score"] >= PATH_PASS_SCORE
        if badge_flow_active(conn) and result["passed"]:
            email = conn.execute("SELECT user_email FROM submissions WHERE id = ?", (sub_id,)).fetchone()["user_email"]
            new_badge = award_chapter_badge(conn, email, challenge_id)
            if new_badge:
                result["badge"] = new_badge
            chs = _path_challenges(conn)
            nxt = next((c for i, c in enumerate(chs[:-1]) if c["id"] == challenge_id), None)
            if nxt:
                following = chs[[c["id"] for c in chs].index(challenge_id) + 1]
                result["next_chapter"] = following["title"]
    return result


def _hint_payload(conn, challenge_id: int, email: str, title: str) -> dict:
    levels = hints_mod.levels_for(title)
    used = {r["level"] for r in conn.execute(
        "SELECT level FROM hint_usage WHERE challenge_id = ? AND user_email = ?", (challenge_id, email)).fetchall()}
    n = len(levels)
    labels = hints_mod.labels_for(title)
    revealed = [{"level": i, "label": labels[i - 1], "text": levels[i - 1]}
                for i in range(1, n + 1) if i in used]
    nxt = len(revealed) + 1
    return {"total": n, "revealed": revealed,
            "next_label": labels[nxt - 1] if nxt <= n else None}


@app.get("/student/challenges/{challenge_id}/hints")
def student_hints(challenge_id: int, authorization: str = Header(None)):
    user = _require_user(authorization)
    with get_conn() as conn:
        if not _has_challenge_access(conn, challenge_id, user["email"]):
            raise HTTPException(status_code=403, detail="No tienes acceso a este reto")
        ch = conn.execute("SELECT title FROM challenges WHERE id = ?", (challenge_id,)).fetchone()
        if not ch:
            raise HTTPException(status_code=404)
        return _hint_payload(conn, challenge_id, user["email"], ch["title"])


@app.post("/student/challenges/{challenge_id}/hints/next")
def student_hint_next(challenge_id: int, authorization: str = Header(None)):
    """Revela la siguiente pista (orden fijo, una por llamada)."""
    user = _require_user(authorization)
    with get_conn() as conn:
        if not _has_challenge_access(conn, challenge_id, user["email"]):
            raise HTTPException(status_code=403, detail="No tienes acceso a este reto")
        ch = conn.execute("SELECT title FROM challenges WHERE id = ?", (challenge_id,)).fetchone()
        if not ch or not hints_mod.levels_for(ch["title"]):
            raise HTTPException(status_code=404, detail="Este reto no tiene pistas")
        cur = _hint_payload(conn, challenge_id, user["email"], ch["title"])
        if cur["next_label"]:
            conn.execute("INSERT OR IGNORE INTO hint_usage (challenge_id, user_email, level) VALUES (?,?,?)",
                         (challenge_id, user["email"], len(cur["revealed"]) + 1))
            cur = _hint_payload(conn, challenge_id, user["email"], ch["title"])
        return cur


@app.get("/admin/hint-usage")
def admin_hint_usage(authorization: str = Header(None)):
    _require_admin(authorization)
    with get_conn() as conn:
        rows = conn.execute("""
            SELECT c.id AS challenge_id, c.title, COUNT(DISTINCT h.user_email) AS students, COUNT(*) AS hints_revealed
            FROM hint_usage h JOIN challenges c ON c.id = h.challenge_id GROUP BY c.id ORDER BY c.id""").fetchall()
        out = []
        for r in rows:
            total = len(hints_mod.levels_for(r["title"]))
            last = conn.execute("SELECT COUNT(*) n FROM hint_usage WHERE challenge_id = ? AND level = ?", (r["challenge_id"], total)).fetchone()["n"]
            out.append({**dict(r), "reached_skeleton": last, "levels": total})
    return out


def _is_admin_email(conn, user_email: str) -> bool:
    r = conn.execute("SELECT role FROM users WHERE email = ?", (user_email,)).fetchone()
    return bool(r and r["role"] == "admin")


def _require_not_admin_preview(user: dict) -> None:
    if user.get("role") == "admin":
        raise HTTPException(status_code=403, detail="Vista de admin: los retos se pueden revisar, pero no enviar ni subir archivos.")


def _has_challenge_access(conn, challenge_id: int, user_email: str):
    from db import path_status
    if _is_admin_email(conn, user_email):
        return (1,)                           # el admin puede abrir cualquier reto para explicarlo
    st0 = conn.execute("SELECT status, starts_at FROM challenges WHERE id = ?", (challenge_id,)).fetchone()
    if st0 and st0["status"] == "draft":
        return None                           # borrador: solo el admin decide cuándo se activa
    if st0 and not _is_started(st0["starts_at"]):
        return None                           # programado: no se puede usar antes de su hora de inicio
    st = path_status(conn, user_email).get(challenge_id)
    if st and st["locked"]:
        return None
    return _has_challenge_access_raw(conn, challenge_id, user_email)


def _has_challenge_access_raw(conn, challenge_id: int, user_email: str):
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
    _require_not_admin_preview(user)
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


# ── Student: raw (dirty) dataset upload ──────────────────────────────────────

RAW_DATASETS_DIR = Path(os.getenv("RAW_DATASETS_DIR", "/data/raw_datasets"))
MAX_RAW_MB = 5


@app.post("/student/challenges/{challenge_id}/upload-raw-dataset")
async def student_upload_raw_dataset(
    challenge_id: int,
    file: UploadFile = File(...),
    authorization: str = Header(None),
):
    user = _require_user(authorization)
    _require_not_admin_preview(user)
    email = user["email"]

    with get_conn() as conn:
        if not _has_challenge_access(conn, challenge_id, email):
            raise HTTPException(status_code=403, detail="Sin acceso a este reto.")

    data = await file.read()
    if len(data) > MAX_RAW_MB * 1024 * 1024:
        raise HTTPException(status_code=413, detail=f"El archivo supera el límite de {MAX_RAW_MB} MB.")

    filename = file.filename or "dataset.csv"
    ext = Path(filename).suffix.lower()
    if ext not in {".csv", ".json", ".tsv", ".txt"}:
        raise HTTPException(status_code=415, detail="Solo se aceptan archivos CSV, JSON, TSV o TXT.")

    text = data.decode("utf-8-sig", errors="replace")
    rows: list[dict] = []
    parse_error: str | None = None

    try:
        if ext == ".json":
            parsed = json.loads(text)
            rows = parsed if isinstance(parsed, list) else [parsed]
        else:
            import csv as _csv
            try:
                dialect = _csv.Sniffer().sniff(text[:4096], delimiters=",;\t|")
            except _csv.Error:
                dialect = _csv.excel  # type: ignore[assignment]
            reader = _csv.DictReader(io.StringIO(text), dialect=dialect)
            rows = [dict(r) for r in reader]
    except Exception as exc:
        parse_error = str(exc)

    if not rows:
        raise HTTPException(
            status_code=422,
            detail=f"No se pudo parsear el archivo. {parse_error or 'Archivo vacío o sin estructura tabular.'}",
        )

    safe_email = re.sub(r"[^\w@.]", "_", email)
    dest_dir = RAW_DATASETS_DIR / str(challenge_id) / safe_email
    dest_dir.mkdir(parents=True, exist_ok=True)
    (dest_dir / "raw.json").write_text(json.dumps(rows, ensure_ascii=False), encoding="utf-8")
    (dest_dir / "filename.txt").write_text(filename, encoding="utf-8")

    columns = list(rows[0].keys()) if rows else []
    return {
        "ok": True,
        "filename": filename,
        "rows": len(rows),
        "columns": columns,
        "preview": rows[:5],
        "data": rows,
        "size_kb": round(len(data) / 1024, 1),
    }


@app.get("/student/challenges/{challenge_id}/raw-dataset")
def student_get_raw_dataset(challenge_id: int, authorization: str = Header(None)):
    user = _require_user(authorization)
    email = user["email"]

    with get_conn() as conn:
        if not _has_challenge_access(conn, challenge_id, email):
            raise HTTPException(status_code=403, detail="Sin acceso a este reto.")

    safe_email = re.sub(r"[^\w@.]", "_", email)
    raw_path  = RAW_DATASETS_DIR / str(challenge_id) / safe_email / "raw.json"
    name_path = RAW_DATASETS_DIR / str(challenge_id) / safe_email / "filename.txt"

    if not raw_path.exists():
        return {"exists": False, "rows": [], "columns": [], "count": 0}

    try:
        rows    = json.loads(raw_path.read_text(encoding="utf-8"))
        columns = list(rows[0].keys()) if rows else []
        fname   = name_path.read_text(encoding="utf-8") if name_path.exists() else "dataset.csv"
        return {"exists": True, "rows": rows, "columns": columns, "count": len(rows), "filename": fname}
    except Exception:
        return {"exists": False, "rows": [], "columns": [], "count": 0}


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
            "SELECT id, name, color, created_by, created_at, open_signup FROM teams ORDER BY created_at"
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
                "INSERT INTO teams (name, color, created_by, open_signup) VALUES (?,?,?,?)",
                (name, payload.get("color", "#22d3ee"), admin["email"], 1 if payload.get("open_signup") else 0),
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
        if "opens_at" in payload:
            conn.execute("UPDATE ctf_phases SET opens_at = ? WHERE id = ?", (payload["opens_at"] or None, phase_id))
    return {"ok": True}


@app.delete("/admin/ctf-phases/{phase_id}")
def admin_delete_ctf_phase(phase_id: int, authorization: str = Header(None)):
    _require_admin(authorization)
    with get_conn() as conn:
        conn.execute("DELETE FROM ctf_phases WHERE id = ?", (phase_id,))
    return {"ok": True}


# ── CTF Phases (Student) ──────────────────────────────────────────────────────

def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _parse_iso(v: str | None) -> datetime | None:
    if not v:
        return None
    try:
        d = datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def _apply_phase_schedule(conn) -> None:
    """Activa fases cuya fecha opens_at ya pasó."""
    for r in conn.execute("SELECT id, opens_at FROM ctf_phases WHERE status = 'inactive' AND opens_at IS NOT NULL").fetchall():
        d = _parse_iso(r["opens_at"])
        if d and d <= _now_utc():
            conn.execute("UPDATE ctf_phases SET status = 'active' WHERE id = ?", (r["id"],))


def _user_team_ids(conn, email: str) -> list[int]:
    return [r["team_id"] for r in conn.execute("SELECT team_id FROM team_members WHERE user_email = ?", (email,)).fetchall()]


@app.get("/student/ctf-phases")
def student_ctf_phases(authorization: str = Header(None)):
    _require_user(authorization)
    with get_conn() as conn:
        _apply_phase_schedule(conn)
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
                 "points", "docker_image", "docker_port", "status", "order_idx", "team_color"]
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
        _apply_phase_schedule(conn)
        rows = conn.execute("""
            SELECT c.id, c.phase_id, c.order_idx, c.title, c.description,
                   c.flag_format, c.hints_json, c.category, c.difficulty,
                   c.team_color, c.points, c.docker_image, c.docker_port,
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
        # Retos con color: solo los asignados al grupo del estudiante (admin ve todos)
        if user.get("role") != "admin":
            teams = _user_team_ids(conn, user["email"])
            mine = {r["challenge_id"] for t in teams for r in conn.execute(
                "SELECT challenge_id FROM team_ctf_assignments WHERE team_id = ?", (t,)).fetchall()}
            rows = [r for r in rows if not r["team_color"] or r["id"] in mine]
    return [dict(r) for r in rows]


@app.post("/student/ctf-challenges/{challenge_id}/submit")
def student_ctf_submit(challenge_id: int, payload: dict = Body(...), authorization: str = Header(None)):
    user = _require_user(authorization)
    submitted = payload.get("flag", "").strip()
    with get_conn() as conn:
        _apply_phase_schedule(conn)
        ch = conn.execute("""SELECT c.flag, c.points, c.phase_id, c.team_color, p.status AS phase_status
                             FROM ctf_challenges c LEFT JOIN ctf_phases p ON p.id = c.phase_id
                             WHERE c.id = ? AND c.status = 'active'""", (challenge_id,)).fetchone()
        if not ch:
            raise HTTPException(status_code=404, detail="Reto no encontrado o inactivo")
        if ch["phase_status"] != "active":
            raise HTTPException(status_code=403, detail="La fase de este reto aún no está habilitada")
        teams = _user_team_ids(conn, user["email"])
        if ch["team_color"] and user.get("role") != "admin":
            ok = conn.execute(
                f"SELECT 1 FROM team_ctf_assignments WHERE challenge_id = ? AND team_id IN ({','.join('?'*len(teams)) or 'NULL'})",
                (challenge_id, *teams)).fetchone()
            if not ok:
                raise HTTPException(status_code=403, detail="Este reto no está asignado a tu grupo")
        team_id = teams[0] if teams else None
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
                "UPDATE ctf_solves SET submitted_flag=?, is_correct=?, points_earned=?, team_id=?, solved_at=datetime('now') WHERE challenge_id=? AND user_email=?",
                (submitted, is_correct, points_earned, team_id, challenge_id, user["email"]),
            )
        else:
            conn.execute(
                "INSERT INTO ctf_solves (challenge_id, user_email, team_id, submitted_flag, is_correct, points_earned) VALUES (?,?,?,?,?,?)",
                (challenge_id, user["email"], team_id, submitted, is_correct, points_earned),
            )
        if is_correct:
            conn.execute(
                "UPDATE ctf_phases SET solves = solves + 1 WHERE id = ?", (ch["phase_id"],)
            )
    return {"correct": is_correct, "points": points_earned if is_correct else 0}


# ── CTF por color: balanceo, asignación aleatoria, scoreboard, anuncios ───────

@app.post("/admin/ctf-phases/{phase_id}/balance")
def admin_balance_phase(phase_id: int, payload: dict = Body(default={}), authorization: str = Header(None)):
    """Asigna color a los retos conocidos, baja un nivel de dificultad y nivela puntos."""
    _require_admin(authorization)
    from db import balance_phase_challenges
    with get_conn() as conn:
        n = balance_phase_challenges(conn, phase_id, int(payload.get("points", 150)))
    return {"ok": True, "updated": n}


@app.post("/admin/ctf-phases/{phase_id}/assign-random")
def admin_assign_random(phase_id: int, payload: dict = Body(default={}), authorization: str = Header(None)):
    """Asigna N retos de color al azar a cada grupo. Sin reset no toca grupos que ya tienen asignación."""
    import random
    _require_admin(authorization)
    per_team = int(payload.get("per_team", 3))
    reset = bool(payload.get("reset"))
    out = []
    with get_conn() as conn:
        pool = [r["id"] for r in conn.execute(
            "SELECT id FROM ctf_challenges WHERE phase_id = ? AND team_color != '' AND status = 'active'", (phase_id,)).fetchall()]
        if len(pool) < per_team:
            raise HTTPException(status_code=400, detail=f"Solo hay {len(pool)} retos con color en esta fase; ejecuta /balance primero")
        pool_set = set(pool)
        for t in conn.execute("SELECT id, name FROM teams ORDER BY id").fetchall():
            have = [r["challenge_id"] for r in conn.execute(
                "SELECT challenge_id FROM team_ctf_assignments WHERE team_id = ?", (t["id"],)).fetchall() if r["challenge_id"] in pool_set]
            if have and not reset:
                out.append({"team": t["name"], "challenges": have, "kept": True}); continue
            if reset:
                conn.execute(f"DELETE FROM team_ctf_assignments WHERE team_id = ? AND challenge_id IN ({','.join('?'*len(pool))})", (t["id"], *pool))
            picked = random.sample(pool, per_team)
            for cid in picked:
                conn.execute("INSERT OR IGNORE INTO team_ctf_assignments (team_id, challenge_id) VALUES (?,?)", (t["id"], cid))
            out.append({"team": t["name"], "challenges": picked, "kept": False})
    return {"ok": True, "teams": out}


def _build_scoreboard(conn) -> list[dict]:
    teams = conn.execute("SELECT id, name, color FROM teams ORDER BY name").fetchall()
    board = []
    for t in teams:
        members = conn.execute(
            "SELECT u.name, u.email FROM team_members tm JOIN users u ON u.email = tm.user_email WHERE tm.team_id = ? ORDER BY u.name",
            (t["id"],)).fetchall()
        emails = [m["email"] for m in members]
        assigned = conn.execute("""
            SELECT c.id, c.title, c.team_color, c.points, c.difficulty
            FROM team_ctf_assignments a JOIN ctf_challenges c ON c.id = a.challenge_id
            WHERE a.team_id = ? ORDER BY c.order_idx""", (t["id"],)).fetchall()
        solves = conn.execute(f"""
            SELECT s.user_email, s.challenge_id, s.points_earned, s.solved_at, c.title, c.team_color
            FROM ctf_solves s JOIN ctf_challenges c ON c.id = s.challenge_id
            WHERE s.is_correct = 1 AND s.user_email IN ({','.join('?'*len(emails)) or 'NULL'})
            ORDER BY s.solved_at""", emails).fetchall()
        name_of = {m["email"]: m["name"] for m in members}
        solved_ids = {r["challenge_id"] for r in solves}
        board.append({
            "team_id": t["id"], "team": t["name"], "color": t["color"],
            "points": sum(r["points_earned"] for r in solves),
            "solves": len(solves),
            "members": [{"name": m["name"], "email": m["email"],
                         "points": sum(r["points_earned"] for r in solves if r["user_email"] == m["email"]),
                         "solves": sum(1 for r in solves if r["user_email"] == m["email"])} for m in members],
            "assigned": [{**dict(a), "solved": a["id"] in solved_ids} for a in assigned],
            "solved": [{"challenge": r["title"], "team_color": r["team_color"], "points": r["points_earned"],
                        "solved_by": name_of.get(r["user_email"], r["user_email"]), "solved_at": r["solved_at"]} for r in solves],
        })
    board.sort(key=lambda b: (-b["points"], -b["solves"], b["team"]))
    for i, b in enumerate(board):
        b["rank"] = i + 1
    return board


@app.get("/student/scoreboard")
def student_scoreboard(authorization: str = Header(None)):
    _require_user(authorization)
    with get_conn() as conn:
        return _build_scoreboard(conn)


@app.get("/admin/scoreboard")
def admin_scoreboard(authorization: str = Header(None)):
    _require_admin(authorization)
    with get_conn() as conn:
        return _build_scoreboard(conn)


@app.get("/student/announcements")
def student_announcements(authorization: str = Header(None)):
    _require_user(authorization)
    now = _now_utc()
    with get_conn() as conn:
        rows = conn.execute("SELECT id, title, body, publish_at, expires_at FROM announcements ORDER BY publish_at DESC").fetchall()
    return [dict(r) for r in rows
            if (_parse_iso(r["publish_at"]) or now) <= now and (not r["expires_at"] or (_parse_iso(r["expires_at"]) or now) > now)]


@app.get("/admin/announcements")
def admin_announcements(authorization: str = Header(None)):
    _require_admin(authorization)
    with get_conn() as conn:
        return [dict(r) for r in conn.execute("SELECT * FROM announcements ORDER BY publish_at DESC").fetchall()]


@app.post("/admin/announcements")
def admin_create_announcement(payload: dict = Body(...), authorization: str = Header(None)):
    admin = _require_admin(authorization)
    if not payload.get("title") or not payload.get("body") or not _parse_iso(payload.get("publish_at")):
        raise HTTPException(status_code=400, detail="title, body y publish_at (ISO 8601 con zona) requeridos")
    with get_conn() as conn:
        cur = conn.execute("INSERT INTO announcements (title, body, publish_at, expires_at, created_by) VALUES (?,?,?,?,?)",
                           (payload["title"], payload["body"], payload["publish_at"], payload.get("expires_at") or None, admin["email"]))
    return {"ok": True, "id": cur.lastrowid}


@app.delete("/admin/announcements/{ann_id}")
def admin_delete_announcement(ann_id: int, authorization: str = Header(None)):
    _require_admin(authorization)
    with get_conn() as conn:
        conn.execute("DELETE FROM announcements WHERE id = ?", (ann_id,))
    return {"ok": True}


# ── Muro de resultados de inteligencia ────────────────────────────────────────
# Cada estudiante redacta su reporte final. Mientras el admin no abra el muro,
# cada quien ve solo el suyo (evita copiar); al abrirlo, todos ven todos.

def _wall_opens_at(conn) -> str | None:
    r = conn.execute("SELECT value FROM app_settings WHERE key = 'wall_open_at'").fetchone()
    return r["value"] if r and r["value"] else None


def _wall_open(conn) -> bool:
    """Abierto si el admin lo abrió a mano o si ya llegó la hora programada."""
    r = conn.execute("SELECT value FROM app_settings WHERE key = 'intel_wall_open'").fetchone()
    if r and r["value"] == "1":
        return True
    at = _parse_iso(_wall_opens_at(conn))
    return bool(at and datetime.now(timezone.utc) >= at)


_WALL_LIMITS = {"title": 140, "summary": 1500, "evidence": 3000, "recommendations": 2000}


@app.get("/intel-wall")
def intel_wall(authorization: str = Header(None)):
    user = _require_user(authorization)
    admin = user.get("role") == "admin"
    with get_conn() as conn:
        is_open = _wall_open(conn)
        opens_at = _wall_opens_at(conn)
        rows = conn.execute("""SELECT id, user_email, user_name, title, summary, evidence, confidence,
                                      recommendations, pinned, updated_at FROM intel_reports
                               ORDER BY pinned DESC, updated_at DESC""").fetchall()
    reports = [dict(r) for r in rows]
    mine = next((r for r in reports if r["user_email"] == user["email"]), None)
    visible = reports if (is_open or admin) else ([mine] if mine else [])
    return {"open": is_open, "opens_at": opens_at, "mine": mine, "reports": visible, "total": len(reports)}


@app.put("/intel-wall/mine")
def intel_wall_save(payload: dict = Body(...), authorization: str = Header(None)):
    user = _require_user(authorization)
    vals = {k: str(payload.get(k, "")).strip()[:n] for k, n in _WALL_LIMITS.items()}
    conf = payload.get("confidence", "media")
    conf = conf if conf in ("baja", "media", "alta") else "media"
    if not vals["title"] or not vals["summary"]:
        raise HTTPException(status_code=400, detail="El título y el resumen son obligatorios")
    with get_conn() as conn:
        conn.execute("""
            INSERT INTO intel_reports (user_email, user_name, title, summary, evidence, confidence, recommendations)
            VALUES (?,?,?,?,?,?,?)
            ON CONFLICT(user_email) DO UPDATE SET user_name=excluded.user_name, title=excluded.title,
              summary=excluded.summary, evidence=excluded.evidence, confidence=excluded.confidence,
              recommendations=excluded.recommendations, updated_at=datetime('now')""",
            (user["email"], user.get("name", ""), vals["title"], vals["summary"], vals["evidence"], conf, vals["recommendations"]))
    return {"ok": True}


@app.post("/admin/intel-wall/open")
def admin_intel_wall_open(payload: dict = Body(...), authorization: str = Header(None)):
    _require_admin(authorization)
    with get_conn() as conn:
        conn.execute("INSERT INTO app_settings (key, value) VALUES ('intel_wall_open', ?) "
                     "ON CONFLICT(key) DO UPDATE SET value = excluded.value", ("1" if payload.get("open") else "0",))
    return {"ok": True, "open": bool(payload.get("open"))}


@app.patch("/admin/intel-wall/{report_id}/pin")
def admin_intel_wall_pin(report_id: int, payload: dict = Body(...), authorization: str = Header(None)):
    _require_admin(authorization)
    with get_conn() as conn:
        conn.execute("UPDATE intel_reports SET pinned = ? WHERE id = ?", (1 if payload.get("pinned") else 0, report_id))
    return {"ok": True}


@app.delete("/admin/intel-wall/{report_id}")
def admin_intel_wall_delete(report_id: int, authorization: str = Header(None)):
    _require_admin(authorization)
    with get_conn() as conn:
        conn.execute("DELETE FROM intel_reports WHERE id = ?", (report_id,))
    return {"ok": True}


@app.get("/admin/intel-wall/export")
def admin_intel_wall_export(authorization: str = Header(None)):
    """CSV de todos los reportes (para el diálogo y para evidencia de la clase)."""
    _require_admin(authorization)
    with get_conn() as conn:
        rows = conn.execute("""SELECT user_name, user_email, title, summary, evidence, confidence, recommendations, updated_at
                               FROM intel_reports ORDER BY user_name""").fetchall()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["estudiante", "email", "titulo", "resumen", "evidencia", "confianza", "recomendaciones", "actualizado"])
    for r in rows:
        w.writerow([r[k] for k in r.keys()])
    from fastapi.responses import Response
    return Response(buf.getvalue(), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": "attachment; filename=muro_inteligencia.csv"})


# ── Guía del docente: el Caso Aurora completo + avance de los estudiantes (solo admin) ──

@app.get("/admin/case/aurora/guide")
def admin_aurora_guide(email: str = "", authorization: str = Header(None)):
    """Todo el caso para el docente: expediente, datos de la variante, pistas, rúbrica con respuesta esperada y solución."""
    admin = _require_admin(authorization)
    from aurora.generator import build_case, DATASETS
    from aurora.chapters import CHAPTERS, PATH_TITLES, CHAPTER_DATASET, rubric as aurora_rubric
    from aurora import solutions as sol
    who = (email or admin["email"]).strip().lower()
    case = build_case(who)
    f = case["facts"]
    cycle = {1: "Recolección", 2: "Procesamiento", 3: "Análisis", 4: "Análisis", 5: "Procesamiento", 6: "Análisis predictivo", 7: "Análisis predictivo", 8: "Diseminación"}
    with get_conn() as conn:
        status = {r["case_chapter"]: dict(r) for r in conn.execute(
            "SELECT case_chapter, id, status, starts_at, deadline FROM challenges WHERE case_key = 'aurora'").fetchall()}
    chapters = []
    for i, (title, ch) in enumerate(zip(PATH_TITLES, CHAPTERS), start=1):
        key = CHAPTER_DATASET[i - 1]
        rub = aurora_rubric(i, f, {"has_wall_report": True})
        exp = sol.expected(i, f)
        rows = case["datasets"][key] if key else []
        chapters.append({
            "chapter": i, "title": title, "cycle": cycle[i], "difficulty": ch["difficulty"],
            "challenge": status.get(i), "briefing": ch["description"], "objective": ch["objective"], "criteria_text": ch["criteria"],
            "hints": hints_mod.levels_for(title), "hint_labels": hints_mod.labels_for(title), "dataset": ({"name": DATASETS[key], "rows": len(rows), "columns": list(rows[0].keys()) if rows else [], "preview": rows[:8]} if key else None),
            "rubric": [{"label": r[0], "weight": r[1], "hint": r[3], "expected": exp[j] if j < len(exp) else ""} for j, r in enumerate(rub)],
            "reference_code": sol.reference_note(f) if i == 8 else sol.REFERENCE_CODE.get(i, ""),
        })
    truth = [{"timestamp": r["timestamp"], "host": r["host"], "usuario": r["usuario"], "fase": r["fase"], "detalle": r["detalle"]}
             for r in case["datasets"]["siem"] if r["severidad"] in ("high", "critical")]
    facts_view = {k: v for k, v in f.items() if k not in ("legit_candidates",)}
    return {"variant": case["code"], "variant_email": who, "facts": facts_view, "truth": truth, "chapters": chapters}


@app.get("/admin/case/aurora/progress")
def admin_aurora_progress(authorization: str = Header(None)):
    """Matriz de avance: cada estudiante del caso, su variante y su resultado en cada capítulo."""
    _require_admin(authorization)
    from aurora.generator import case_code
    with get_conn() as conn:
        chs = [dict(r) for r in conn.execute(
            "SELECT id, case_chapter, title, status, starts_at, deadline FROM challenges WHERE case_key = 'aurora' ORDER BY case_chapter").fetchall()]
        ids = [c["id"] for c in chs]
        marks = ",".join("?" * len(ids)) or "NULL"
        users = conn.execute(f"""SELECT DISTINCT u.email, u.name FROM challenge_assignments a JOIN users u ON u.email = a.user_email
                                 WHERE a.challenge_id IN ({marks}) ORDER BY u.name""", ids).fetchall()
        subs = {(r["user_email"], r["challenge_id"]): dict(r) for r in conn.execute(
            f"SELECT user_email, challenge_id, score, submitted_at, auto_graded FROM submissions WHERE challenge_id IN ({marks})", ids).fetchall()}
        hints = {(r["user_email"], r["challenge_id"]): r["n"] for r in conn.execute(
            f"SELECT user_email, challenge_id, COUNT(*) n FROM hint_usage WHERE challenge_id IN ({marks}) GROUP BY user_email, challenge_id", ids).fetchall()}
        wall = {r["user_email"] for r in conn.execute("SELECT user_email FROM intel_reports").fetchall()}
    rows = []
    for u in users:
        per = []
        for c in chs:
            sb = subs.get((u["email"], c["id"]))
            per.append({"chapter": c["case_chapter"], "score": sb["score"] if sb else None, "submitted_at": sb["submitted_at"] if sb else None,
                        "hints_used": hints.get((u["email"], c["id"]), 0)})
        rows.append({"name": u["name"], "email": u["email"], "variant": case_code(u["email"]), "chapters": per, "wall": u["email"] in wall,
                     "passed": sum(1 for p in per if p["score"] is not None and p["score"] >= _PASS())})
    return {"pass_score": _PASS(), "chapters": [{"chapter": c["case_chapter"], "title": c["title"], "status": c["status"], "starts_at": c["starts_at"], "deadline": c["deadline"]} for c in chs], "students": rows}


# ── Mis datasets: biblioteca personal del estudiante, disponible en todos los capítulos ──
MY_DS_DIR = RAW_DATASETS_DIR / "_mine"
MAX_MY_DATASETS = 8


def _my_ds_dir(email: str) -> Path:
    return MY_DS_DIR / re.sub(r"[^\w@.]", "_", email)


def _slug(name: str) -> str:
    base = Path(name).stem.lower()
    base = re.sub(r"[^a-z0-9]+", "_", base.encode("ascii", "ignore").decode()).strip("_") or "datos"
    return base[:40]


def _parse_upload_rows(filename: str, data: bytes) -> list[dict]:
    """CSV/TSV/JSON/JSONL/TXT/LOG -> filas. El texto libre (informes, logs sin columnas) pasa a una fila por línea."""
    ext = Path(filename).suffix.lower()
    text = data.decode("utf-8-sig", errors="replace")
    if ext == ".json":
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            lists = [v for v in parsed.values() if isinstance(v, list) and v and isinstance(v[0], dict)]
            parsed = lists[0] if len(lists) == 1 else [parsed]
        return [r if isinstance(r, dict) else {"valor": r} for r in parsed]
    if ext in (".jsonl", ".ndjson"):
        return [json.loads(l) for l in text.splitlines() if l.strip()]
    import csv as _csv
    try:
        dialect = _csv.Sniffer().sniff(text[:4096], delimiters=",;\t|")
        rows = [dict(r) for r in _csv.DictReader(io.StringIO(text), dialect=dialect)]
        if rows and len(rows[0]) >= 2:
            return rows
    except _csv.Error:
        pass
    if ext in (".txt", ".log"):
        return [{"linea": l} for l in text.splitlines() if l.strip()]
    return [dict(r) for r in _csv.DictReader(io.StringIO(text))]


@app.post("/student/my-datasets")
async def student_upload_my_dataset(file: UploadFile = File(...), authorization: str = Header(None)):
    user = _require_user(authorization)
    data = await file.read()
    if len(data) > MAX_RAW_MB * 1024 * 1024:
        raise HTTPException(status_code=413, detail=f"El archivo supera el límite de {MAX_RAW_MB} MB.")
    filename = file.filename or "datos.csv"
    if Path(filename).suffix.lower() not in {".csv", ".tsv", ".json", ".jsonl", ".ndjson", ".txt", ".log"}:
        raise HTTPException(status_code=415, detail="Formatos permitidos: CSV, TSV, JSON, JSONL, TXT y LOG. Si tienes Excel, expórtalo a CSV.")
    try:
        rows = _parse_upload_rows(filename, data)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"No se pudo leer el archivo: {exc}")
    if not rows:
        raise HTTPException(status_code=422, detail="El archivo está vacío o no tiene estructura legible.")
    d = _my_ds_dir(user["email"])
    d.mkdir(parents=True, exist_ok=True)
    slug = _slug(filename)
    if not (d / f"{slug}.json").exists() and len(list(d.glob("*.json"))) >= MAX_MY_DATASETS:
        raise HTTPException(status_code=409, detail=f"Máximo {MAX_MY_DATASETS} datasets. Elimina alguno para subir otro.")
    (d / f"{slug}.json").write_text(json.dumps({"filename": filename, "rows": rows}, ensure_ascii=False), encoding="utf-8")
    cols = list(rows[0].keys())
    return {"name": slug, "var": f"up_{slug}", "filename": filename, "rows": len(rows), "columns": cols, "preview": rows[:5], "data": rows}


@app.get("/student/my-datasets")
def student_list_my_datasets(authorization: str = Header(None)):
    user = _require_user(authorization)
    d = _my_ds_dir(user["email"])
    out = []
    for f in sorted(d.glob("*.json")) if d.exists() else []:
        try:
            j = json.loads(f.read_text(encoding="utf-8"))
            out.append({"name": f.stem, "var": f"up_{f.stem}", "filename": j.get("filename", f.name), "rows": len(j["rows"]),
                        "columns": list(j["rows"][0].keys()) if j["rows"] else []})
        except Exception:
            continue
    return out


@app.get("/student/my-datasets/{name}")
def student_get_my_dataset(name: str, authorization: str = Header(None)):
    user = _require_user(authorization)
    if not re.fullmatch(r"[a-z0-9_]{1,40}", name):
        raise HTTPException(status_code=400)
    f = _my_ds_dir(user["email"]) / f"{name}.json"
    if not f.exists():
        raise HTTPException(status_code=404)
    j = json.loads(f.read_text(encoding="utf-8"))
    return {"name": name, "var": f"up_{name}", "filename": j.get("filename"), "rows": j["rows"]}


@app.delete("/student/my-datasets/{name}")
def student_delete_my_dataset(name: str, authorization: str = Header(None)):
    user = _require_user(authorization)
    if not re.fullmatch(r"[a-z0-9_]{1,40}", name):
        raise HTTPException(status_code=400)
    f = _my_ds_dir(user["email"]) / f"{name}.json"
    if f.exists():
        f.unlink()
    return {"ok": True}


@app.get("/admin/my-datasets")
def admin_student_datasets(email: str, authorization: str = Header(None)):
    """El docente ve qué datasets propios subió un estudiante (para acompañar su análisis)."""
    _require_admin(authorization)
    d = _my_ds_dir(email.strip().lower())
    out = []
    for f in sorted(d.glob("*.json")) if d.exists() else []:
        j = json.loads(f.read_text(encoding="utf-8"))
        out.append({"name": f.stem, "filename": j.get("filename"), "rows": len(j["rows"]), "preview": j["rows"][:5]})
    return out


@app.get("/student/case/board")
def student_case_board(authorization: str = Header(None)):
    """Tablero del estudiante: su progreso en el caso, el perfil de SUS datos y los cruces posibles (sin dar respuestas)."""
    user = _require_user(authorization)
    from aurora.generator import build_case, DATASETS
    from aurora.chapters import CHAPTER_DATASET
    from aurora.board import profile, relations
    from db import path_status
    email = user["email"]
    with get_conn() as conn:
        pstat = path_status(conn, email)
        rows = conn.execute("""
            SELECT c.id, c.case_chapter, c.title, c.status, c.starts_at, c.deadline,
                   (SELECT score FROM submissions s WHERE s.challenge_id = c.id AND s.user_email = ?) AS score,
                   (SELECT feedback FROM submissions s WHERE s.challenge_id = c.id AND s.user_email = ?) AS feedback,
                   (SELECT auto_graded FROM submissions s WHERE s.challenge_id = c.id AND s.user_email = ?) AS auto_graded,
                   (SELECT COUNT(*) FROM hint_usage h WHERE h.challenge_id = c.id AND h.user_email = ?) AS hints_used,
                   b.name AS badge_name, b.tier AS badge_tier, b.icon AS badge_icon,
                   (SELECT 1 FROM user_badges ub WHERE ub.user_email = ? AND ub.badge_id = c.badge_id) AS badge_earned
            FROM challenges c JOIN challenge_assignments a ON a.challenge_id = c.id LEFT JOIN badges b ON b.id = c.badge_id
            WHERE a.user_email = ? AND c.case_key = 'aurora' AND c.status != 'draft' ORDER BY c.case_chapter""",
            (email, email, email, email, email, email)).fetchall()
    chapters, unlocked = [], 0
    for r in rows:
        if not _is_started(r["starts_at"]):
            continue
        st = pstat.get(r["id"])
        locked = bool(st and st["locked"])
        if not locked:
            unlocked = max(unlocked, r["case_chapter"])
        auto_fb, teacher_fb = _split_feedback(r["feedback"], r["auto_graded"] or 0)
        lines = [l for l in auto_fb.splitlines()[1:]] if r["score"] is not None else []
        chapters.append({"chapter": r["case_chapter"], "title": r["title"], "status": r["status"], "locked": locked,
                         "locked_by": st["requires"] if st else None, "score": r["score"], "hints_used": r["hints_used"],
                         "deadline": r["deadline"], "checks": lines if not locked else [], "teacher_feedback": teacher_fb if not locked else "",
                         "badge": {"name": r["badge_name"], "tier": r["badge_tier"], "earned": bool(r["badge_earned"])} if r["badge_name"] else None})
    case = build_case(email)
    keys = [k for k in CHAPTER_DATASET[:unlocked] if k]
    data = {DATASETS[k]: case["datasets"][k] for k in keys}
    return {"variant": case["code"], "pass_score": _PASS(), "chapters": chapters,
            "datasets": [{"name": n, **profile(v)} for n, v in data.items()], "relations": relations(data)}


@app.get("/admin/badge-flow")
def admin_badge_flow(authorization: str = Header(None)):
    _require_admin(authorization)
    from db import badge_flow_start, badge_flow_active, AURORA_BADGES
    with get_conn() as conn:
        return {"start": badge_flow_start(conn), "active": badge_flow_active(conn),
                "badges": [{"chapter": i + 1, "name": b[0], "tier": b[2]} for i, b in enumerate(AURORA_BADGES)]}


@app.post("/admin/badge-flow")
def admin_set_badge_flow(payload: dict = Body(...), authorization: str = Header(None)):
    """Fija desde cuándo cada capítulo superado entrega su insignia y habilita el siguiente."""
    _require_admin(authorization)
    start = payload.get("start")
    if not start or not _parse_iso(start):
        raise HTTPException(status_code=400, detail="start (ISO 8601 con zona horaria) requerido")
    with get_conn() as conn:
        conn.execute("INSERT INTO app_settings (key, value) VALUES ('badge_flow_start', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", (start,))
    return {"ok": True, "start": start}


@app.get("/student/challenges/{challenge_id}/review")
def student_review(challenge_id: int, authorization: str = Header(None)):
    """La revisión de la última entrega del estudiante (qué hace su código, qué reportó y qué dicen sus datos)."""
    user = _require_user(authorization)
    with get_conn() as conn:
        r = conn.execute("SELECT review_json FROM submissions WHERE challenge_id = ? AND user_email = ?", (challenge_id, user["email"])).fetchone()
    with get_conn() as conn:
        f = conn.execute("SELECT feedback, auto_graded FROM submissions WHERE challenge_id = ? AND user_email = ?", (challenge_id, user["email"])).fetchone()
    note = _split_feedback(f["feedback"], f["auto_graded"])[1] if f else ""
    rv = json.loads(r["review_json"]) if r and r["review_json"] else {}
    return {**rv, "teacher_feedback": note} if (rv or note) else None


def _weak_by_challenge(fb_rows: list[dict]) -> dict:
    """Por capítulo, los criterios que menos estudiantes logran (a partir del feedback guardado: ✓ logrado, ◐ parcial, ✗ por mejorar)."""
    import re as _re
    agg: dict[int, dict[str, list[int]]] = {}
    for r in fb_rows:
        for line in (r["feedback"] or "").splitlines():
            m = _re.match(r"^([✓◐✗])\s+(.*?)\s+\((\d+)/(\d+)\)", line.strip())
            if not m:
                continue
            a = agg.setdefault(r["challenge_id"], {}).setdefault(m.group(2), [0, 0, 0])
            a[0 if m.group(1) == "✓" else 1 if m.group(1) == "◐" else 2] += 1
    out = {}
    for cid, d in agg.items():
        rows = [{"label": k, "ok": v[0], "partial": v[1], "missed": v[2], "n": sum(v)} for k, v in d.items()]
        out[cid] = sorted((r for r in rows if r["missed"] + r["partial"] > 0), key=lambda r: (-(r["missed"] + 0.5 * r["partial"]) / r["n"], r["label"]))[:3]
    return out


def _PASS() -> int:
    from db import PATH_PASS_SCORE
    return PATH_PASS_SCORE


@app.get("/admin/case/aurora/dashboard")
def admin_aurora_dashboard(authorization: str = Header(None)):
    """Tablero del docente: visión de conjunto del caso (embudo por capítulo, atascados, actividad). Solo admin."""
    _require_admin(authorization)
    from datetime import datetime, timedelta
    from aurora.generator import case_code
    from aurora.chapters import PATH_TITLES
    with get_conn() as conn:
        chs = [dict(r) for r in conn.execute(
            "SELECT id, case_chapter, title, status, starts_at, deadline, badge_id FROM challenges WHERE case_key = 'aurora' ORDER BY case_chapter").fetchall()]
        ids = [c["id"] for c in chs]
        mk = ",".join("?" * len(ids)) or "NULL"
        students = {r["email"]: r["name"] for r in conn.execute(
            f"SELECT DISTINCT u.email, u.name FROM challenge_assignments a JOIN users u ON u.email = a.user_email WHERE a.challenge_id IN ({mk})", ids).fetchall()}
        subs = [dict(r) for r in conn.execute(
            f"SELECT challenge_id, user_email, score, submitted_at FROM submissions WHERE challenge_id IN ({mk})", ids).fetchall()]
        hints = [dict(r) for r in conn.execute(
            f"SELECT challenge_id, user_email, level, used_at FROM hint_usage WHERE challenge_id IN ({mk})", ids).fetchall()]
        badges = [dict(r) for r in conn.execute(
            """SELECT ub.user_email, ub.awarded_at, b.name FROM user_badges ub JOIN badges b ON b.id = ub.badge_id
               WHERE ub.badge_id IN (SELECT badge_id FROM challenges WHERE case_key = 'aurora' AND badge_id IS NOT NULL)""").fetchall()]
        wall = {r["user_email"] for r in conn.execute("SELECT user_email FROM intel_reports").fetchall()}
        fb_rows = [dict(r) for r in conn.execute(f"SELECT challenge_id, feedback FROM submissions WHERE auto_graded = 1 AND challenge_id IN ({mk})", ids).fetchall()]
        from db import badge_flow_start, badge_flow_active
        flow = {"start": badge_flow_start(conn), "active": badge_flow_active(conn)}
    chapters = []
    weak = _weak_by_challenge(fb_rows)
    for c in chs:
        cs = [x for x in subs if x["challenge_id"] == c["id"]]
        ch_hints = [h for h in hints if h["challenge_id"] == c["id"]]
        scores = [x["score"] for x in cs if x["score"] is not None]
        chapters.append({
            "chapter": c["case_chapter"], "title": c["title"], "status": c["status"], "starts_at": c["starts_at"], "deadline": c["deadline"],
            "assigned": len(students), "worked": len({x["user_email"] for x in cs} | {h["user_email"] for h in ch_hints}),
            "submitted": len({x["user_email"] for x in cs}), "passed": len({x["user_email"] for x in cs if (x["score"] or 0) >= _PASS()}),
            "avg_score": round(sum(scores) / len(scores)) if scores else None,
            "dist": [sum(1 for v in scores if 0 <= v < 40), sum(1 for v in scores if 40 <= v < _PASS()), sum(1 for v in scores if _PASS() <= v < 80), sum(1 for v in scores if v >= 80)],
            "hint_students": len({h["user_email"] for h in ch_hints}), "hints_total": len(ch_hints),
            "weak": weak.get(c["id"], []),
        })
    active_ids = {c["id"]: c for c in chs if c["status"] == "active"}
    now = datetime.utcnow()
    stuck, rows = [], []
    for email, name in students.items():
        my = [x for x in subs if x["user_email"] == email]
        passed_ids = {x["challenge_id"] for x in my if (x["score"] or 0) >= _PASS()}
        last = max([x["submitted_at"] for x in my if x["submitted_at"]] + [h["used_at"] for h in hints if h["user_email"] == email and h["used_at"]] + [""]) or None
        open_chs = [c for c in chs if c["id"] in active_ids and c["id"] not in passed_ids]
        cur = open_chs[0] if open_chs else None
        n_hints = len([h for h in hints if h["user_email"] == email and cur and h["challenge_id"] == cur["id"]])
        has_sub = any(x["challenge_id"] == cur["id"] for x in my) if cur else False
        best = max([x["score"] for x in my if cur and x["challenge_id"] == cur["id"] and x["score"] is not None] + [-1]) if cur else -1
        reason = None
        if cur and not has_sub and n_hints >= 3:
            reason = f"Usó {n_hints} pistas en el capítulo {cur['case_chapter']} y no ha entregado"
        elif cur and has_sub and best < _PASS():
            reason = f"Entregó el capítulo {cur['case_chapter']} pero no supera {_PASS()} (mejor nota {best})"
        elif cur and not has_sub and not my and not any(h["user_email"] == email for h in hints):
            reason = "Aún no ha empezado"
        status = "sin_empezar" if not my and not any(h["user_email"] == email for h in hints) else ("completo" if not open_chs else "en_curso")
        row = {"name": name, "email": email, "variant": case_code(email), "passed": len(passed_ids), "current": cur["case_chapter"] if cur else None,
               "current_hints": n_hints, "best": best if best >= 0 else None, "last_activity": last, "status": status, "wall": email in wall}
        rows.append(row)
        if reason:
            stuck.append({**row, "reason": reason})
    events = []
    for x in subs:
        if x["submitted_at"]:
            events.append({"t": x["submitted_at"], "who": students.get(x["user_email"], x["user_email"]), "what": f"entregó el capítulo {next((c['case_chapter'] for c in chs if c['id'] == x['challenge_id']), '?')} · nota {x['score']}"})
    for b in badges:
        events.append({"t": b["awarded_at"], "who": students.get(b["user_email"], b["user_email"]), "what": f"ganó la insignia «{b['name']}»"})
    events.sort(key=lambda e: e["t"] or "", reverse=True)
    return {
        "kpis": {"students": len(students), "working": sum(1 for r in rows if r["status"] != "sin_empezar"), "not_started": sum(1 for r in rows if r["status"] == "sin_empezar"),
                 "submissions": len(subs), "passed_any": sum(1 for r in rows if r["passed"] > 0), "completed": sum(1 for r in rows if r["status"] == "completo" and r["passed"] > 0),
                 "badges": len(badges), "wall": len(wall), "hints": len(hints)},
        "pass_score": _PASS(), "chapters": chapters, "stuck": stuck, "students": sorted(rows, key=lambda r: (-r["passed"], r["name"])), "events": events[:12], "flow": flow,
        "server_time": datetime.utcnow().isoformat() + "Z",
    }


# ── Mensajes del docente a un estudiante (ayuda personalizada) ────────────────

@app.post("/admin/teacher-notes")
def admin_add_teacher_note(payload: dict = Body(...), authorization: str = Header(None)):
    admin = _require_admin(authorization)
    email, body = str(payload.get("email", "")).strip().lower(), str(payload.get("body", "")).strip()
    if not email or not body:
        raise HTTPException(status_code=400, detail="email y body requeridos")
    with get_conn() as conn:
        if not conn.execute("SELECT 1 FROM users WHERE email = ?", (email,)).fetchone():
            raise HTTPException(status_code=404, detail="Estudiante no encontrado")
        cur = conn.execute("INSERT INTO teacher_notes (user_email, challenge_id, body, created_by) VALUES (?,?,?,?)",
                           (email, payload.get("challenge_id"), body[:4000], admin["email"]))
    return {"ok": True, "id": cur.lastrowid}


@app.get("/student/teacher-notes")
def student_teacher_notes(authorization: str = Header(None)):
    user = _require_user(authorization)
    with get_conn() as conn:
        rows = conn.execute("SELECT id, challenge_id, body, created_at FROM teacher_notes WHERE user_email = ? ORDER BY id DESC", (user["email"],)).fetchall()
    return [dict(r) for r in rows]


@app.get("/admin/path-open")
def admin_path_open(authorization: str = Header(None)):
    _require_admin(authorization)
    with get_conn() as conn:
        r = conn.execute("SELECT value FROM app_settings WHERE key = 'path_open_up_to'").fetchone()
    return {"open_up_to": int(r["value"]) if r and str(r["value"]).isdigit() else 0}


@app.post("/admin/path-open")
def admin_set_path_open(payload: dict = Body(...), authorization: str = Header(None)):
    """Abre los capítulos hasta el N para TODOS, sin exigir superar el anterior. 0 = vuelve al desbloqueo secuencial."""
    _require_admin(authorization)
    n = int(payload.get("open_up_to", 0))
    if not 0 <= n <= 8:
        raise HTTPException(status_code=400, detail="open_up_to debe estar entre 0 y 8")
    with get_conn() as conn:
        conn.execute("INSERT INTO app_settings (key, value) VALUES ('path_open_up_to', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", (str(n),))
    return {"ok": True, "open_up_to": n}


@app.post("/admin/case/aurora/regrade")
def admin_aurora_regrade(authorization: str = Header(None)):
    """Vuelve a calificar las entregas automáticas del caso con las reglas actuales (umbral y piso). No toca las notas puestas a mano."""
    _require_admin(authorization)
    changes = []
    with get_conn() as conn:
        rows = conn.execute("""SELECT s.id, s.challenge_id, s.user_email, s.code, s.output, s.notes, s.plots_json, s.score, s.auto_graded, u.name, c.case_chapter
                               FROM submissions s JOIN challenges c ON c.id = s.challenge_id JOIN users u ON u.email = s.user_email
                               WHERE c.case_key = 'aurora'""").fetchall()
        for r in rows:
            if r["score"] is not None and not r["auto_graded"]:
                changes.append({"name": r["name"], "chapter": r["case_chapter"], "before": r["score"], "after": r["score"], "kept": "nota del docente"})
                continue
            try:
                plots = json.loads(r["plots_json"] or "[]")
            except Exception:
                plots = []
            res = _auto_grade(conn, r["id"], r["challenge_id"], {"code": r["code"], "output": r["output"], "notes": r["notes"], "plots": plots})
            after = conn.execute("SELECT score FROM submissions WHERE id = ?", (r["id"],)).fetchone()["score"]
            changes.append({"name": r["name"], "chapter": r["case_chapter"], "before": r["score"], "after": after,
                            "badge": (res or {}).get("badge", {}).get("name") if res else None})
        from db import sync_chapter_badges
        for email in {r["user_email"] for r in rows}:
            sync_chapter_badges(conn, email)
    return {"ok": True, "pass_score": _PASS(), "changes": changes}


# ── Hito con reloj para los estudiantes (p. ej. «validación del Muro a las 3:30 pm») ──

@app.get("/student/milestone")
def student_milestone(authorization: str = Header(None)):
    _require_user(authorization)
    with get_conn() as conn:
        r = conn.execute("SELECT value FROM app_settings WHERE key = 'milestone_json'").fetchone()
        wall_at = _wall_opens_at(conn)
        wall_open = _wall_open(conn)
    ms = None
    try:
        ms = json.loads(r["value"]) if r and r["value"] else None
    except Exception:
        ms = None
    return {"milestone": ms, "wall_open_at": wall_at, "wall_open": wall_open, "server_time": datetime.now(timezone.utc).isoformat()}


@app.post("/admin/milestone")
def admin_set_milestone(payload: dict = Body(...), authorization: str = Header(None)):
    """{at, title, message} muestra un reloj con cuenta regresiva a todos; {} lo quita."""
    _require_admin(authorization)
    if payload.get("at") and not _parse_iso(payload["at"]):
        raise HTTPException(status_code=400, detail="at debe ser ISO 8601 con zona horaria")
    value = json.dumps({"at": payload["at"], "title": str(payload.get("title", ""))[:140], "message": str(payload.get("message", ""))[:600]}, ensure_ascii=False) if payload.get("at") else ""
    with get_conn() as conn:
        conn.execute("INSERT INTO app_settings (key, value) VALUES ('milestone_json', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", (value,))
    return {"ok": True}


@app.post("/admin/intel-wall/schedule")
def admin_wall_schedule(payload: dict = Body(...), authorization: str = Header(None)):
    """Programa la hora en que el Muro se abre solo para todos. open_at nulo la cancela."""
    _require_admin(authorization)
    at = payload.get("open_at")
    if at and not _parse_iso(at):
        raise HTTPException(status_code=400, detail="open_at debe ser ISO 8601 con zona horaria")
    with get_conn() as conn:
        conn.execute("INSERT INTO app_settings (key, value) VALUES ('wall_open_at', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", (at or "",))
    return {"ok": True, "open_at": at}


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

    if len(raw) > 20 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Input too large. Maximum 20 MB.")

    result = parse_logs(raw, hint=format_hint or None, max_rows=10_000)

    # ── Correlacionar IOCs extraídos contra el feed existente ─────────────────
    existing_feed = {i["ioc"] for i in get_threat_feed()}
    ioc_records = []
    ioc_matches: list[dict] = []
    for i in result["iocs"]:
        ioc_val = i["ioc"]
        if ioc_val in existing_feed:
            ioc_matches.append(ioc_val)
        ioc_records.append({
            "ioc":          ioc_val,
            "type":         i["type"],
            "threat_actor": "log_ingest",
            "severity":     "medium",
            "mitre":        "",
            "country":      "",
            "source":       f"log:{name}",
        })
    added_iocs = add_uploaded_iocs(ioc_records) if ioc_records else []

    # ── Guardar como dataset (opcional) ──────────────────────────────────────
    dataset_id = None
    if save_dataset.lower() == "true" and result["rows"]:
        vol = result["volumetry"]
        vol_desc = (
            f" · {vol['events_per_minute']} eventos/min" if vol.get("events_per_minute") else ""
        )
        ds_name = (dataset_name.strip() or f"Log Ingest — {name}").strip()[:120]
        with get_conn() as conn:
            cur = conn.execute(
                "INSERT INTO datasets (name, description, source, data_json, schema_json, created_by) VALUES (?,?,?,?,?,?)",
                (
                    ds_name,
                    f"Logs ingestados desde {name} · formato {result['format']} · {result['line_count']} eventos{vol_desc}",
                    f"log_ingest:{name}",
                    json.dumps(result["rows"], ensure_ascii=False),
                    json.dumps(result["schema"], ensure_ascii=False),
                    user["email"],
                ),
            )
            dataset_id = cur.lastrowid

    vol = result["volumetry"]

    # ── ML Anomaly Scoring ────────────────────────────────────────────────────
    anomaly = score_log_batch(
        n_rows=result["line_count"],
        n_iocs=len(result["iocs"]),
        n_feed_matches=len(ioc_matches),
        events_per_minute=vol.get("events_per_minute"),
        log_format=result["format"],
        volumetry=vol,
    )

    # ── Broadcast a clientes SSE ──────────────────────────────────────────────
    sse_payload = {
        "source":            name,
        "format":            result["format"],
        "line_count":        result["line_count"],
        "ioc_count":         len(result["iocs"]),
        "ioc_matches":       len(ioc_matches),
        "events_per_minute": vol.get("events_per_minute"),
        "dataset_id":        dataset_id,
        "anomaly_score":     anomaly.get("anomaly_score", 0.0),
        "is_anomaly":        anomaly.get("is_anomaly", False),
        "anomaly_reason":    anomaly.get("reason", ""),
    }
    live_service.publish("log_ingested", sse_payload)

    if anomaly.get("is_anomaly"):
        live_service.publish("anomaly_detected", {
            "source":        name,
            "anomaly_score": anomaly["anomaly_score"],
            "reason":        anomaly.get("reason", ""),
            "ioc_count":     len(result["iocs"]),
            "feed_matches":  len(ioc_matches),
        })

    return {
        "format":            result["format"],
        "line_count":        result["line_count"],
        "rows":              result["rows"][:2_000],
        "schema":            result["schema"],
        "iocs":              result["iocs"],
        "iocs_added":        len(added_iocs),
        "ioc_feed_matches":  ioc_matches,
        "dataset_id":        dataset_id,
        "volumetry":         vol,
        "anomaly":           anomaly,
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


@app.post("/logs/analyze")
def logs_analyze(payload: dict = Body(...), authorization: str = Header(None)):
    """
    AI analysis of an ingested log batch.

    Expects the same shape returned by /logs/ingest:
      { format, line_count, schema, iocs, rows }

    Returns { analysis: str, engine: "claude" | "ollama" | "unavailable" }
    """
    _auth_user_or_raise(authorization)

    fmt        = payload.get("format", "desconocido")
    line_count = payload.get("line_count", 0)
    iocs       = payload.get("iocs", [])
    schema     = payload.get("schema", {})
    rows       = payload.get("rows", [])

    ioc_lines   = "\n".join(f"  • {i['type']}: {i['ioc']}" for i in iocs[:40])
    schema_text = ", ".join(f"{k} ({v})" for k, v in schema.items())
    sample_json = json.dumps(rows[:8], indent=2, ensure_ascii=False)

    prompt = f"""Eres un analista senior de SOC/CTI. Se acaban de ingestar los siguientes logs de seguridad.

Formato detectado: {fmt}
Total de líneas/registros: {line_count}
Campos del schema: {schema_text or "no detectado"}

IOCs extraídos ({len(iocs)} total):
{ioc_lines if iocs else "  — ninguno detectado —"}

Muestra de registros (primeros 8):
{sample_json}

Proporciona un análisis técnico estructurado:
1. Resumen ejecutivo de la actividad observada
2. Indicadores de compromiso más relevantes y su contexto
3. Patrones de ataque o comportamiento anómalo detectado
4. Técnicas MITRE ATT&CK aplicables (IDs + nombres)
5. Recomendaciones de respuesta inmediata (prioridad alta → baja)

Sé conciso y usa formato Markdown."""

    anthropic_key = os.environ.get("ANTHROPIC_API_KEY")
    if anthropic_key:
        try:
            from ai.claude_fusion_engine import _get_client as _claude_client, _MODEL as _CLAUDE_MODEL
            msg = _claude_client().messages.create(
                model=_CLAUDE_MODEL,
                max_tokens=2048,
                messages=[{"role": "user", "content": prompt}],
            )
            return {"analysis": msg.content[0].text, "engine": "claude"}
        except Exception as exc:
            raise HTTPException(status_code=502, detail=f"Claude error: {exc}") from exc

    ollama_url = os.environ.get("OLLAMA_URL", "http://localhost:11434")
    try:
        r = requests.post(
            f"{ollama_url}/api/generate",
            json={"model": "llama3", "prompt": prompt, "stream": False},
            timeout=120,
        )
        r.raise_for_status()
        return {"analysis": r.json().get("response", ""), "engine": "ollama"}
    except Exception:
        pass

    return {
        "analysis": "No hay motor AI disponible. Configura `ANTHROPIC_API_KEY` o Ollama.",
        "engine": "unavailable",
    }


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


def _student_fusion_daily_limit() -> int:
    try:
        return max(0, int(os.getenv("STUDENT_FUSION_DAILY_LIMIT", "3")))
    except ValueError:
        return 3


def _fusion_usage_date() -> str:
    return _now_bogota().date().isoformat()


def _fusion_allowed(user: dict) -> bool:
    """El Motor de Fusión lo habilita el admin: roles privilegiados siempre; estudiantes solo si fueron autorizados."""
    if _is_privileged(user):
        return True
    with get_conn() as conn:
        return bool(conn.execute("SELECT 1 FROM fusion_access WHERE user_email = ?", (user["email"],)).fetchone())


def _fusion_quota_for_user(user: dict) -> dict:
    if _is_privileged(user):
        return {"limited": False, "limit": None, "used": 0, "remaining": None, "usage_date": _fusion_usage_date()}

    usage_date = _fusion_usage_date()
    limit = _student_fusion_daily_limit()
    with get_conn() as conn:
        row = conn.execute(
            "SELECT request_count FROM fusion_usage WHERE user_email = ? AND usage_date = ?",
            (user["email"], usage_date),
        ).fetchone()
    used = int(row["request_count"]) if row else 0
    return {
        "limited": True,
        "limit": limit,
        "used": used,
        "remaining": max(0, limit - used),
        "usage_date": usage_date,
    }


def _consume_student_fusion_quota(user: dict, endpoint: str) -> dict:
    if _is_privileged(user):
        return _fusion_quota_for_user(user)

    usage_date = _fusion_usage_date()
    limit = _student_fusion_daily_limit()
    if limit <= 0:
        raise HTTPException(
            status_code=429,
            detail={
                "message": "El Motor de Fusión está deshabilitado para estudiantes.",
                "limit": limit,
                "used": 0,
                "remaining": 0,
                "usage_date": usage_date,
            },
        )

    with get_conn() as conn:
        row = conn.execute(
            "SELECT request_count FROM fusion_usage WHERE user_email = ? AND usage_date = ?",
            (user["email"], usage_date),
        ).fetchone()
        used = int(row["request_count"]) if row else 0
        if used >= limit:
            raise HTTPException(
                status_code=429,
                detail={
                    "message": "Límite diario de consultas del Motor de Fusión alcanzado para estudiantes.",
                    "limit": limit,
                    "used": used,
                    "remaining": 0,
                    "usage_date": usage_date,
                },
            )

        if row:
            conn.execute(
                """
                UPDATE fusion_usage
                SET request_count = request_count + 1,
                    last_endpoint = ?,
                    updated_at = datetime('now')
                WHERE user_email = ? AND usage_date = ?
                """,
                (endpoint, user["email"], usage_date),
            )
        else:
            conn.execute(
                """
                INSERT INTO fusion_usage (user_email, usage_date, request_count, last_endpoint)
                VALUES (?, ?, 1, ?)
                """,
                (user["email"], usage_date, endpoint),
            )

    used += 1
    return {
        "limited": True,
        "limit": limit,
        "used": used,
        "remaining": max(0, limit - used),
        "usage_date": usage_date,
    }


def _require_fusion_access(authorization: str | None, *, consume: bool = False, endpoint: str = "fusion") -> dict:
    user = _auth_user_or_raise(authorization)
    if not _fusion_allowed(user):
        raise HTTPException(status_code=403, detail={
            "message": "El Motor de Fusión no está habilitado para tu cuenta. Lo activa el administrador.",
            "enabled": False,
        })
    user["fusion_quota"] = _consume_student_fusion_quota(user, endpoint) if consume else _fusion_quota_for_user(user)
    return user


@app.get("/student/fusion-access")
def student_fusion_access(authorization: str = Header(None)):
    user = _require_user(authorization)
    return {"enabled": _fusion_allowed(user)}


@app.get("/admin/fusion-access")
def admin_fusion_access(authorization: str = Header(None)):
    _require_admin(authorization)
    with get_conn() as conn:
        return {"emails": [r["user_email"] for r in conn.execute("SELECT user_email FROM fusion_access").fetchall()]}


@app.post("/admin/fusion-access")
def admin_set_fusion_access(payload: dict = Body(...), authorization: str = Header(None)):
    """{emails:[...], enabled:bool} o {all_students:true, enabled:bool}."""
    admin = _require_admin(authorization)
    enabled = bool(payload.get("enabled"))
    with get_conn() as conn:
        emails = payload.get("emails") or []
        if payload.get("all_students"):
            emails = [r["email"] for r in conn.execute("SELECT email FROM users WHERE role = 'student'").fetchall()]
        for e in emails:
            if enabled:
                conn.execute("INSERT OR IGNORE INTO fusion_access (user_email, granted_by) VALUES (?,?)", (e, admin["email"]))
            else:
                conn.execute("DELETE FROM fusion_access WHERE user_email = ?", (e,))
    return {"ok": True, "count": len(emails)}


@app.get("/ai/gemini/lab-context")
def gemini_lab_context(authorization: str = Header(None)):
    """
    Snapshot completo del CTI Lab para el motor de fusión:
    IOC feed, actores, campañas, IOAs, correlaciones multi-fuente, tendencia 24h.
    No consume cuota — es una consulta de contexto, no de generación AI.
    """
    user = _require_fusion_access(authorization)
    from intelligence.cti_context_collector import collect_lab_context
    context = collect_lab_context()
    return {**context, "fusion_quota": user["fusion_quota"]}


@app.post("/ai/gemini/fuse-with-lab")
def gemini_fuse_with_lab(payload: dict = Body(...), authorization: str = Header(None)):
    """
    Análisis de fusión anclado en los datos reales del CTI Lab.

    A diferencia de los otros endpoints (que reciben eventos del frontend),
    este endpoint recolecta automáticamente todos los IOCs, actores, campañas
    y correlaciones del lab, luego ejecuta el análisis AI sobre datos reales.

    Body:
      {
        "query":         str,                             # tema o actor de interés
        "analysis_type": "fusion-report|predictive|behavioral|geopolitical|threat-graph",
        "max_iocs":      int (default 100)                # IOCs reales a incluir
      }
    """
    _require_fusion_access(authorization, consume=True, endpoint="fuse-with-lab")
    from intelligence.cti_context_collector import collect_lab_context, iocs_to_threat_events, correlate_across_feeds

    query         = (payload.get("query") or "").strip()
    analysis_type = payload.get("analysis_type", "fusion-report")
    max_iocs      = min(int(payload.get("max_iocs", 100)), 300)

    if not query:
        raise HTTPException(status_code=400, detail="'query' es obligatorio.")

    # 1. Recolectar contexto real del lab
    context = collect_lab_context(max_iocs=max_iocs)
    lab_iocs = context["top_iocs_sample"]

    # 2. Correlación multi-fuente (enriquece confianza)
    correlations = correlate_across_feeds(lab_iocs)

    # 3. Convertir IOCs al formato de eventos del motor
    events = iocs_to_threat_events(lab_iocs)

    # 4. Inyectar metadatos del lab en el query para anclar el análisis
    enriched_query = (
        f"{query} | Contexto CTI Lab: {context['summary']['total_iocs']} IOCs "
        f"({context['summary']['multi_feed_iocs']} en múltiples fuentes), "
        f"{context['summary']['total_actors']} actores, "
        f"{context['summary']['recent_iocs_24h']} IOCs nuevos en 24h. "
        f"Fuentes activas: {', '.join(list(context['ioc_stats']['by_source'].keys())[:6])}."
    )

    # 5. Ejecutar el análisis AI correspondiente
    if analysis_type == "predictive":
        result = _gemini_wrap(generate_predictive_analysis, events, enriched_query)
    elif analysis_type == "behavioral":
        result = _gemini_wrap(generate_behavioral_analysis, enriched_query, events)
    elif analysis_type == "geopolitical":
        result = _gemini_wrap(generate_geopolitical_analysis, enriched_query)
    elif analysis_type == "threat-graph":
        result = _gemini_wrap(generate_threat_graph, events, enriched_query)
    else:  # fusion-report (default)
        result = _gemini_wrap(generate_fusion_report, enriched_query, events)

    # 6. Adjuntar metadatos del lab al resultado
    if isinstance(result, dict):
        result["_lab_context"] = {
            "iocs_used":           len(events),
            "actors_in_scope":     context["summary"]["total_actors"],
            "campaigns_in_scope":  context["summary"]["total_campaigns"],
            "cross_feed_iocs":     correlations["total_shared_iocs"],
            "multi_feed_actors":   correlations["total_multi_actors"],
            "feed_sources":        list(context["ioc_stats"]["by_source"].keys()),
            "collected_at":        context["collected_at"],
        }
    return result


@app.get("/ai/gemini/feed-correlations")
def gemini_feed_correlations(authorization: str = Header(None)):
    """
    Correlaciones entre fuentes de feeds: IOCs compartidos, actores
    vistos en múltiples feeds, técnicas MITRE por fuente.
    No consume cuota AI — análisis puramente local sobre el feed DB.
    """
    user = _require_fusion_access(authorization)
    from intelligence.threat_engine import get_threat_feed
    from intelligence.cti_context_collector import correlate_across_feeds
    iocs = get_threat_feed()
    result = correlate_across_feeds(iocs)
    return {**result, "total_iocs_analyzed": len(iocs), "fusion_quota": user["fusion_quota"]}


@app.get("/ai/gemini/status")
def gemini_status(authorization: str = Header(None)):
    """Check which fusion engine is active (Gemini, Claude, or none)."""
    user = _require_fusion_access(authorization)
    engine = _fusion_engine()
    if engine == "gemini":
        return {"configured": True, "engine": "gemini", "model_fast": os.getenv("GEMINI_MODEL_FAST", "gemini-2.0-flash"), "quota": user["fusion_quota"]}
    if engine == "claude":
        from ai.claude_fusion_engine import _MODEL as claude_model
        return {"configured": True, "engine": "claude", "model_fast": claude_model, "quota": user["fusion_quota"]}
    return {"configured": False, "engine": "none", "model_fast": "—", "quota": user["fusion_quota"]}


@app.get("/ai/gemini/quota")
def gemini_quota(authorization: str = Header(None)):
    """Current Motor de Fusion quota for the authenticated user."""
    user = _require_fusion_access(authorization)
    return user["fusion_quota"]


@app.post("/ai/gemini/threat-data")
def gemini_threat_data(payload: dict = Body(...), authorization: str = Header(None)):
    """
    Generate 150 (operativo) or 1000 (annual) structured threat events and persist to ML corpus.
    Body: { "topic": str, "is_annual": bool }
    """
    user = _require_fusion_access(authorization)
    is_annual = bool(payload.get("is_annual", False))
    if not _is_privileged(user) and is_annual:
        raise HTTPException(status_code=403, detail="Las consultas anuales del Motor de Fusión están reservadas para analistas e instructores.")
    _require_fusion_access(authorization, consume=True, endpoint="threat-data")
    topic = payload.get("topic", "")
    result = _gemini_wrap(generate_threat_data, topic, is_annual)
    # Persist events to ML corpus in background (non-blocking)
    threats = result.get("threats", []) if isinstance(result, dict) else []
    if threats:
        try:
            corpus_info = save_fusion_events_to_corpus(
                threats, query=topic, created_by=user.get("email", "unknown"), is_annual=is_annual
            )
            result["corpus_update"] = corpus_info
        except Exception as exc:
            _logger.warning("No se pudo guardar corpus ML: %s", exc)
    return result


@app.post("/ai/gemini/quantum")
def gemini_quantum(payload: dict = Body(...), authorization: str = Header(None)):
    """Quantum / PQC risk analysis for a threat actor."""
    _require_fusion_access(authorization, consume=True, endpoint="quantum")
    return _gemini_wrap(
        generate_quantum_threat_analysis,
        payload.get("actor", ""),
        payload.get("events", []),
    )


@app.post("/ai/gemini/predictive")
def gemini_predictive(payload: dict = Body(...), authorization: str = Header(None)):
    """Predictive analysis: next tactic, attribution, multi-actor correlation."""
    _require_fusion_access(authorization, consume=True, endpoint="predictive")
    threats = payload.get("threats", [])
    query = payload.get("query", "")
    try:
        return _gemini_wrap(generate_predictive_analysis, threats, query)
    except HTTPException as e:
        return _fallback_predictive_analysis(threats, query, str(e.detail))


@app.post("/ai/gemini/fusion-report")
def gemini_fusion_report(payload: dict = Body(...), authorization: str = Header(None)):
    """Executive intelligence fusion report with Google Search grounding."""
    _require_fusion_access(authorization, consume=True, endpoint="fusion-report")
    return _gemini_wrap(
        generate_fusion_report,
        payload.get("query", ""),
        payload.get("threats", []),
    )


@app.post("/ai/gemini/mitre-details")
def gemini_mitre_details(payload: dict = Body(...), authorization: str = Header(None)):
    """MITRE ATT&CK technique deep-dive for a specific actor."""
    _require_fusion_access(authorization, consume=True, endpoint="mitre-details")
    return _gemini_wrap(
        generate_mitre_details,
        payload.get("actor", ""),
        payload.get("technique_ids", []),
    )


_welcome_cache: dict = {}
_welcome_cache_ts: float = 0.0
_WELCOME_CACHE_TTL = 600  # 10 minutos


@app.get("/ai/gemini/welcome")
def gemini_welcome(authorization: str = Header(None)):
    """Welcome panel: 5 recent APTs + 5 CVEs + 5 LATAM incidents (cached 10 min)."""
    global _welcome_cache, _welcome_cache_ts
    user = _require_fusion_access(authorization)  # auth sin consumir cuota
    if _welcome_cache and _time.monotonic() - _welcome_cache_ts < _WELCOME_CACHE_TTL:
        _logger.debug("Welcome data servido desde caché")
        return {**_welcome_cache, "fusion_quota": user["fusion_quota"]}
    # Cache miss → consumir cuota y llamar al motor
    user = _require_fusion_access(authorization, consume=True, endpoint="welcome")
    result = _gemini_wrap(generate_welcome_data)
    _welcome_cache = result
    _welcome_cache_ts = _time.monotonic()
    return result


@app.post("/ai/gemini/ioc-context")
def gemini_ioc_context(payload: dict = Body(...), authorization: str = Header(None)):
    """IOC context with Google Search grounding (actor, malware, campaigns)."""
    _require_fusion_access(authorization, consume=True, endpoint="ioc-context")
    ioc = payload.get("ioc", "").strip()
    if not ioc:
        raise HTTPException(status_code=400, detail="'ioc' field required.")
    return _gemini_wrap(query_ioc_context, ioc)


@app.post("/ai/gemini/weekly-report")
def gemini_weekly_report(payload: dict = Body(...), authorization: str = Header(None)):
    """Weekly flash report: TTPs, IOCs, hunting queries (Sigma/KQL/Splunk/YARA/PS)."""
    _require_fusion_access(authorization, consume=True, endpoint="weekly-report")
    return _gemini_wrap(
        generate_weekly_flash_report,
        payload.get("query", ""),
        payload.get("events", []),
    )


@app.post("/ai/gemini/extract-entities")
def gemini_extract_entities(payload: dict = Body(...), authorization: str = Header(None)):
    """Extract IOCs, actors, malware, CVEs from unstructured text."""
    _require_fusion_access(authorization, consume=True, endpoint="extract-entities")
    text = payload.get("text", "")
    if not text:
        raise HTTPException(status_code=400, detail="'text' field required.")
    return _gemini_wrap(extract_entities_from_text, text)


@app.post("/ai/gemini/colombia-risk")
def gemini_colombia_risk(payload: dict = Body(...), authorization: str = Header(None)):
    """Colombian critical infrastructure risk assessment (Decreto 338/2022)."""
    _require_fusion_access(authorization, consume=True, endpoint="colombia-risk")
    return _gemini_wrap(
        assess_colombian_risk,
        payload.get("actor", ""),
        payload.get("events", []),
    )


@app.post("/ai/gemini/crisis-map")
def gemini_crisis_map(payload: dict = Body(...), authorization: str = Header(None)):
    """Cyber crisis map: attack phases + strategic responses."""
    _require_fusion_access(authorization, consume=True, endpoint="crisis-map")
    return _gemini_wrap(
        generate_crisis_map,
        payload.get("actor", ""),
        payload.get("ttps", []),
    )


@app.post("/ai/gemini/team-scenarios")
def gemini_team_scenarios(payload: dict = Body(...), authorization: str = Header(None)):
    """Red / Blue / Purple / White Team simulation scenarios."""
    _require_fusion_access(authorization, consume=True, endpoint="team-scenarios")
    return _gemini_wrap(
        generate_team_scenarios,
        payload.get("actor", ""),
        payload.get("ttps", []),
    )


@app.post("/ai/gemini/behavioral")
def gemini_behavioral(payload: dict = Body(...), authorization: str = Header(None)):
    """Behavioral analysis: threat behavior + historical event explanations."""
    _require_fusion_access(authorization, consume=True, endpoint="behavioral")
    return _gemini_wrap(
        generate_behavioral_analysis,
        payload.get("topic", ""),
        payload.get("threats", []),
    )


@app.post("/ai/gemini/playbook")
def gemini_playbook(payload: dict = Body(...), authorization: str = Header(None)):
    """Incident response playbook for a given threat."""
    _require_fusion_access(authorization, consume=True, endpoint="playbook")
    return _gemini_wrap(
        generate_playbook,
        payload.get("threat_name", ""),
        payload.get("threat_type", "Malware"),
    )


@app.post("/ai/gemini/ml-proposals")
def gemini_ml_proposals(payload: dict = Body(...), authorization: str = Header(None)):
    """ML model proposals (Random Forest / LSTM / SVM / Clustering) per event."""
    _require_fusion_access(authorization, consume=True, endpoint="ml-proposals")
    events = payload.get("events", [])
    try:
        return _gemini_wrap(generate_ml_proposals, events)
    except HTTPException as e:
        return _fallback_ml_proposals(events, str(e.detail))


@app.post("/ai/gemini/geopolitical")
def gemini_geopolitical(payload: dict = Body(...), authorization: str = Header(None)):
    """Geopolitical deep-dive with anticipatory threats and stability score."""
    _require_fusion_access(authorization, consume=True, endpoint="geopolitical")
    return _gemini_wrap(
        generate_geopolitical_analysis,
        payload.get("query", ""),
    )


@app.post("/ai/gemini/threat-graph")
def gemini_threat_graph(payload: dict = Body(...), authorization: str = Header(None)):
    """Actor → IOC → Campaign correlation graph enriched with CISA APT database."""
    _require_fusion_access(authorization, consume=True, endpoint="threat-graph")
    return _gemini_wrap(
        generate_threat_graph,
        payload.get("events", []),
        payload.get("query", ""),
    )


# ── ML Anomaly Detection endpoints ────────────────────────────────────────────

@app.get("/ml/anomaly/status")
def ml_anomaly_status(authorization: str = Header(None)):
    """Returns the current state of the Isolation Forest anomaly model."""
    _auth_user_or_raise(authorization)
    return get_model_status()


@app.post("/ml/anomaly/train")
def ml_anomaly_train(authorization: str = Header(None)):
    """Manually trigger model retraining on all collected samples."""
    user = _auth_user_or_raise(authorization)
    if not _is_privileged(user):
        raise HTTPException(status_code=403, detail="Admin access required.")
    return retrain_model()


@app.post("/ml/anomaly/reset")
def ml_anomaly_reset(authorization: str = Header(None)):
    """Reset model and clear all training samples. Admin only."""
    user = _auth_user_or_raise(authorization)
    if not _is_privileged(user):
        raise HTTPException(status_code=403, detail="Admin access required.")
    return reset_model()


# ── Supervised RF model endpoints (fusion events → FP classifier) ─────────────

@app.get("/ml/supervised/status")
def ml_supervised_status(authorization: str = Header(None)):
    """
    Estado del modelo RF supervisado: corpus acumulado, etiquetas,
    importancia de features e indicador de entrenamiento.
    """
    _auth_user_or_raise(authorization)
    return get_supervised_model_status()


@app.post("/ml/supervised/train")
def ml_supervised_train(authorization: str = Header(None)):
    """
    Reentrena el clasificador RF de falsos positivos con todo el corpus
    acumulado. Requiere ≥50 eventos etiquetados. Admin/analista únicamente.
    """
    user = _auth_user_or_raise(authorization)
    if not _is_privileged(user):
        raise HTTPException(status_code=403, detail="Requiere rol privilegiado.")
    return retrain_supervised_model()


@app.post("/ml/supervised/predict")
def ml_supervised_predict(payload: dict = Body(...), authorization: str = Header(None)):
    """
    Predice probabilidad de falso positivo para un evento de fusión.
    Body: { "event": { ...campos del evento... } }
    """
    _auth_user_or_raise(authorization)
    event = payload.get("event", {})
    if not event:
        raise HTTPException(status_code=400, detail="Se requiere 'event' en el body.")
    return predict_false_positive(event)


@app.post("/ml/supervised/predict-batch")
def ml_supervised_predict_batch(payload: dict = Body(...), authorization: str = Header(None)):
    """
    Predice probabilidad de FP para un lote de eventos de fusión.
    Body: { "events": [ ...lista de eventos... ] }
    Devuelve la lista de eventos enriquecidos con el campo 'fp_prediction'.
    """
    _auth_user_or_raise(authorization)
    events = payload.get("events", [])
    if not isinstance(events, list) or not events:
        raise HTTPException(status_code=400, detail="Se requiere 'events' (lista no vacía).")
    predictions = batch_predict_false_positives(events)
    enriched = [
        {**ev, "fp_prediction": pred}
        for ev, pred in zip(events, predictions)
    ]
    active = sum(1 for p in predictions if p.get("status") == "active")
    likely_fp = sum(1 for p in predictions if p.get("is_likely_fp"))
    return {
        "events": enriched,
        "summary": {
            "total": len(enriched),
            "model_active": active > 0,
            "likely_false_positives": likely_fp,
            "fp_rate": round(likely_fp / max(len(enriched), 1), 3),
        },
    }


@app.get("/ml/corpus/stats")
def ml_corpus_stats(authorization: str = Header(None)):
    """
    Estadísticas del corpus de fusión acumulado para entrenamiento ML.
    Incluye distribución por actor, severidad y conteo temporal.
    """
    _auth_user_or_raise(authorization)
    try:
        import sqlite3 as _sqlite3
        db_path = os.getenv("DB_PATH", "/data/cti.db")
        conn = _sqlite3.connect(db_path)
        conn.row_factory = _sqlite3.Row
        rows = conn.execute(
            "SELECT actor, event_count, is_annual, created_at FROM fusion_corpus ORDER BY created_at DESC"
        ).fetchall()
        conn.close()

        total_events = sum(r["event_count"] for r in rows)
        by_actor: dict[str, int] = {}
        for r in rows:
            a = r["actor"] or "Unknown"
            by_actor[a] = by_actor.get(a, 0) + r["event_count"]

        return {
            "total_batches": len(rows),
            "total_events": total_events,
            "by_actor": dict(sorted(by_actor.items(), key=lambda x: x[1], reverse=True)[:20]),
            "latest_batch": rows[0]["created_at"] if rows else None,
            "annual_batches": sum(1 for r in rows if r["is_annual"]),
            "operative_batches": sum(1 for r in rows if not r["is_annual"]),
            "supervised_model": get_supervised_model_status(),
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


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

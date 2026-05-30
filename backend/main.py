import csv
import io
import json
import os
from contextlib import asynccontextmanager
from datetime import datetime
from zoneinfo import ZoneInfo

import requests
import anthropic
from fastapi import Body, FastAPI, File, Header, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware

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
from intelligence.feeds_engine import FETCH_REGISTRY
from intelligence.defend_engine import compute_depuration

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
    _require_user(authorization)
    q = q.strip().lower()
    if len(q) < 2:
        return {"iocs": [], "actors": [], "campaigns": [], "ttps": []}

    feed    = get_threat_feed()
    actors  = get_threat_actors()
    camps   = get_campaigns()
    ioas    = get_ioas()

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
def ioc_feed():
    return get_threat_feed()


@app.get("/threat-actors")
def threat_actors():
    return get_threat_actors()


@app.get("/campaigns")
def campaigns():
    return get_campaigns()


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
def ioas():
    return get_ioas()


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
def misp_status():
    return get_misp_status()


@app.get("/misp/iocs")
def misp_iocs(limit: int = 50):
    try:
        iocs = fetch_misp_iocs(limit=min(limit, 200))
        return {"count": len(iocs), "iocs": iocs}
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"MISP fetch failed: {e}")


@app.post("/misp/import")
def misp_import(limit: int = 50):
    """Pull IOCs from MISP and persist them into the local DB."""
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
        challenges = conn.execute("SELECT COUNT(*) FROM challenges WHERE status = 'active'").fetchone()[0]
        datasets   = conn.execute("SELECT COUNT(*) FROM datasets").fetchone()[0]
        subs_today = conn.execute(
            "SELECT COUNT(*) FROM submissions WHERE date(submitted_at) = date('now')"
        ).fetchone()[0]
        pending    = conn.execute(
            "SELECT COUNT(*) FROM submissions WHERE score IS NULL"
        ).fetchone()[0]
        recent_subs = conn.execute("""
            SELECT s.user_name, s.user_email, c.title AS challenge, s.submitted_at, s.score
            FROM submissions s JOIN challenges c ON s.challenge_id = c.id
            ORDER BY s.submitted_at DESC LIMIT 5
        """).fetchall()
    return {
        "students": users, "active_challenges": challenges,
        "datasets": datasets, "submissions_today": subs_today,
        "pending_scoring": pending,
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
def rules_depurate(payload: dict = Body(...)):
    """
    Validates an IOA/IOC through the CTI depuration pipeline before rule deployment.
    Checks: CTI context → IoC lifecycle → IoA lifecycle → MITRE D3FEND mapping.
    """
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
def rules_ioa_catalog():
    """Returns all available TTPs with their IoA metadata for the depuration selector."""
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
    ]

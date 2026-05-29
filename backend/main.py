import csv
import io
import json
import os
from contextlib import asynccontextmanager

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
from intelligence.ioa_engine import get_ioas


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
            SELECT c.id, c.title, c.description, c.objective, c.criteria,
                   c.deadline, c.status, c.created_at,
                   d.name AS dataset_name,
                   (SELECT COUNT(*) FROM challenge_assignments ca WHERE ca.challenge_id = c.id) AS assigned_count,
                   (SELECT COUNT(*) FROM submissions s WHERE s.challenge_id = c.id) AS submission_count
            FROM challenges c
            LEFT JOIN datasets d ON c.dataset_id = d.id
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
            "INSERT INTO challenges (title, description, objective, dataset_id, criteria, deadline, created_by) VALUES (?,?,?,?,?,?,?)",
            (title, payload.get("description", ""), payload.get("objective", ""),
             payload.get("dataset_id"), payload.get("criteria", ""),
             payload.get("deadline"), admin["email"]),
        )
    return {"id": cur.lastrowid, "title": title}


@app.patch("/admin/challenges/{challenge_id}")
def admin_update_challenge(challenge_id: int, payload: dict = Body(...), authorization: str = Header(None)):
    _require_admin(authorization)
    with get_conn() as conn:
        if "status" in payload:
            conn.execute("UPDATE challenges SET status = ? WHERE id = ?", (payload["status"], challenge_id))
        if "title" in payload:
            conn.execute("UPDATE challenges SET title = ? WHERE id = ?", (payload["title"], challenge_id))
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
    _require_admin(authorization)
    with get_conn() as conn:
        conn.execute(
            "UPDATE submissions SET score = ?, feedback = ? WHERE id = ?",
            (payload.get("score"), payload.get("feedback", ""), submission_id),
        )
    return {"ok": True}


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
            SELECT c.id, c.title, c.description, c.objective, c.criteria,
                   c.deadline, c.status, d.name AS dataset_name, d.schema_json,
                   (SELECT COUNT(*) FROM submissions s
                    WHERE s.challenge_id = c.id AND s.user_email = ?) AS submitted,
                   (SELECT score FROM submissions s
                    WHERE s.challenge_id = c.id AND s.user_email = ?
                    LIMIT 1) AS my_score
            FROM challenges c
            JOIN challenge_assignments ca ON c.id = ca.challenge_id
            LEFT JOIN datasets d ON c.dataset_id = d.id
            WHERE ca.user_email = ?
            ORDER BY c.created_at DESC
        """, (user["email"], user["email"], user["email"])).fetchall()
    return [dict(r) for r in rows]


@app.get("/student/challenges/{challenge_id}/dataset")
def student_challenge_dataset(challenge_id: int, authorization: str = Header(None)):
    user = _require_user(authorization)
    with get_conn() as conn:
        ok = conn.execute(
            "SELECT 1 FROM challenge_assignments WHERE challenge_id = ? AND user_email = ?",
            (challenge_id, user["email"]),
        ).fetchone()
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
        ok = conn.execute(
            "SELECT 1 FROM challenge_assignments WHERE challenge_id = ? AND user_email = ?",
            (challenge_id, user["email"]),
        ).fetchone()
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
                SELECT u.name, u.email, u.role
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
                   ub.awarded_at, ub.awarded_by
            FROM user_badges ub JOIN badges b ON ub.badge_id = b.id
            WHERE ub.user_email = ?
            ORDER BY ub.awarded_at DESC
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

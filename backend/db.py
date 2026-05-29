import os
import sqlite3
from contextlib import contextmanager

DB_PATH = os.getenv("DB_PATH", "/data/cti.db")


def init_db() -> None:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with get_conn() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS iocs (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                ioc           TEXT    NOT NULL UNIQUE,
                type          TEXT    NOT NULL DEFAULT 'UNKNOWN',
                threat_actor  TEXT    NOT NULL DEFAULT 'Unknown',
                severity      TEXT    NOT NULL DEFAULT 'medium',
                mitre         TEXT    NOT NULL DEFAULT '',
                country       TEXT    NOT NULL DEFAULT 'Unknown',
                source        TEXT    NOT NULL DEFAULT 'uploaded',
                created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS findings (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                severity      TEXT    NOT NULL,
                title         TEXT    NOT NULL,
                description   TEXT    NOT NULL DEFAULT '',
                mitre         TEXT    NOT NULL DEFAULT '',
                source        TEXT    NOT NULL DEFAULT 'manual',
                created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                name          TEXT    NOT NULL,
                email         TEXT    NOT NULL UNIQUE,
                password_hash TEXT    NOT NULL,
                role          TEXT    NOT NULL DEFAULT 'student',
                created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS datasets (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                name        TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                source      TEXT NOT NULL DEFAULT 'manual',
                data_json   TEXT NOT NULL DEFAULT '[]',
                schema_json TEXT NOT NULL DEFAULT '{}',
                created_by  TEXT NOT NULL,
                created_at  TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS challenges (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                title       TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                objective   TEXT NOT NULL DEFAULT '',
                dataset_id  INTEGER REFERENCES datasets(id),
                criteria    TEXT NOT NULL DEFAULT '',
                deadline    TEXT,
                status      TEXT NOT NULL DEFAULT 'active',
                created_by  TEXT NOT NULL,
                created_at  TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS challenge_assignments (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                challenge_id INTEGER NOT NULL REFERENCES challenges(id),
                user_email   TEXT    NOT NULL,
                assigned_at  TEXT    NOT NULL DEFAULT (datetime('now')),
                UNIQUE(challenge_id, user_email)
            );

            CREATE TABLE IF NOT EXISTS submissions (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                challenge_id INTEGER NOT NULL REFERENCES challenges(id),
                user_email   TEXT NOT NULL,
                user_name    TEXT NOT NULL DEFAULT '',
                code         TEXT NOT NULL DEFAULT '',
                output       TEXT NOT NULL DEFAULT '',
                plots_json   TEXT NOT NULL DEFAULT '[]',
                notes        TEXT NOT NULL DEFAULT '',
                score        INTEGER,
                feedback     TEXT NOT NULL DEFAULT '',
                submitted_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS teams (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                name       TEXT NOT NULL UNIQUE,
                color      TEXT NOT NULL DEFAULT '#22d3ee',
                created_by TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS team_members (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                team_id    INTEGER NOT NULL REFERENCES teams(id),
                user_email TEXT    NOT NULL,
                joined_at  TEXT    NOT NULL DEFAULT (datetime('now')),
                UNIQUE(team_id, user_email)
            );

            CREATE TABLE IF NOT EXISTS badges (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                org         TEXT NOT NULL,
                name        TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                tier        TEXT NOT NULL DEFAULT 'bronze',
                icon        TEXT NOT NULL DEFAULT 'star',
                created_at  TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS user_badges (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                user_email TEXT    NOT NULL,
                badge_id   INTEGER NOT NULL REFERENCES badges(id),
                awarded_by TEXT    NOT NULL,
                awarded_at TEXT    NOT NULL DEFAULT (datetime('now')),
                UNIQUE(user_email, badge_id)
            );

            CREATE TABLE IF NOT EXISTS ctf_phases (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                order_idx   INTEGER NOT NULL DEFAULT 0,
                name        TEXT    NOT NULL,
                category    TEXT    NOT NULL DEFAULT '',
                reto_count  INTEGER NOT NULL DEFAULT 0,
                group_label TEXT    NOT NULL DEFAULT '',
                emoji       TEXT    NOT NULL DEFAULT '📅',
                status      TEXT    NOT NULL DEFAULT 'inactive',
                solves      INTEGER NOT NULL DEFAULT 0,
                created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_iocs_ioc ON iocs(ioc);
            CREATE INDEX IF NOT EXISTS idx_iocs_source ON iocs(source);
            CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
            CREATE INDEX IF NOT EXISTS idx_assign_challenge ON challenge_assignments(challenge_id);
            CREATE INDEX IF NOT EXISTS idx_assign_user ON challenge_assignments(user_email);
            CREATE INDEX IF NOT EXISTS idx_submissions_challenge ON submissions(challenge_id);
            CREATE INDEX IF NOT EXISTS idx_user_badges ON user_badges(user_email);
        """)
        _seed_badges(conn)
        _seed_ctf_phases(conn)


CTF_PHASE_SEEDS = [
    # (order_idx, name, category, reto_count, group_label, emoji, status, solves)
    (1, 'Día 1',        'Fundamentos',   13, '',           '📅', 'inactive', 54),
    (2, 'Día 2',        'Explotación',   13, '',           '📅', 'inactive', 30),
    (3, 'Día 3',        'Encadenamiento', 5, '',           '🔥', 'inactive',  2),
    (4, 'Día 4 — Fase 3', 'Avanzada',   50, 'G1 / G2 / G3', '☠️', 'inactive', 0),
    (5, 'Fase 4',       'Muerte Letal',   0, '',           '☠️', 'inactive',  0),
]


def _seed_ctf_phases(conn) -> None:
    existing = conn.execute("SELECT COUNT(*) FROM ctf_phases").fetchone()[0]
    if existing:
        return
    conn.executemany(
        "INSERT INTO ctf_phases (order_idx, name, category, reto_count, group_label, emoji, status, solves) VALUES (?,?,?,?,?,?,?,?)",
        CTF_PHASE_SEEDS,
    )


BADGE_SEEDS = [
    # ── CertAcademico ────────────────────────────────────────────────────────
    ("CertAcademico", "Explorador de Datos",       "Completó su primer ejercicio en el Sandbox Lab",          "bronze",   "book"),
    ("CertAcademico", "Analista Junior",            "Dominó el track CTI & pandas",                            "silver",   "chart"),
    ("CertAcademico", "Científico de Datos",        "Completó el track ETL & Limpieza de Datos",               "gold",     "flask"),
    ("CertAcademico", "Maestro de Visualización",   "Completó el track de Visualización con Matplotlib",       "gold",     "eye"),
    ("CertAcademico", "Ingeniero ML",               "Completó el track de Machine Learning con scikit-learn",  "platinum", "cpu"),
    ("CertAcademico", "Experto CTI",                "Completó todos los tracks del Sandbox Lab",               "diamond",  "shield"),
    # ── redciber ─────────────────────────────────────────────────────────────
    ("redciber",      "Ciberdefensor",              "Realizó su primera entrega de reto de ciberseguridad",    "bronze",   "lock"),
    ("redciber",      "Threat Hunter",              "Obtuvo 70 o más en un reto de análisis de amenazas",      "silver",   "search"),
    ("redciber",      "SOC Analyst",                "Obtuvo 85 o más en un reto de operaciones de seguridad",  "gold",     "radar"),
    ("redciber",      "Analista de Amenazas",       "Completó 3 retos con score ≥ 80",                        "platinum", "target"),
    ("redciber",      "Red Team Ready",             "Análisis excepcional — reto completado con 100 puntos",   "diamond",  "fire"),
    # ── LabThinkTank ─────────────────────────────────────────────────────────
    ("LabThinkTank",  "Lab Explorer",               "Primera sesión activa en el laboratorio Python",          "bronze",   "beaker"),
    ("LabThinkTank",  "Data Engineer",              "Pipeline ETL funcional y documentado",                    "silver",   "flow"),
    ("LabThinkTank",  "ML Practitioner",            "Modelo de Machine Learning entrenado y evaluado",         "gold",     "brain"),
    ("LabThinkTank",  "Innovation Award",           "Mejor visualización del reto — elegido por el docente",   "diamond",  "star"),
    ("LabThinkTank",  "Campeón del Reto",           "Primer lugar en el ranking de un reto grupal",            "diamond",  "trophy"),
]


def _seed_badges(conn) -> None:
    existing = conn.execute("SELECT COUNT(*) FROM badges").fetchone()[0]
    if existing:
        return
    conn.executemany(
        "INSERT INTO badges (org, name, description, tier, icon) VALUES (?,?,?,?,?)",
        BADGE_SEEDS,
    )


@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def row_to_dict(row: sqlite3.Row) -> dict:
    return dict(row)

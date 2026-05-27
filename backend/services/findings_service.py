from db import get_conn, row_to_dict

_SEED = [
    {"severity": "HIGH",   "title": "Exposed Admin Panel",     "description": "Public login interface discovered", "mitre": "T1190", "source": "static"},
    {"severity": "MEDIUM", "title": "Missing Security Headers", "description": "CSP header not configured",        "mitre": "T1595", "source": "static"},
]


def _seed_if_empty(conn) -> None:
    count = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
    if count == 0:
        conn.executemany(
            "INSERT INTO findings (severity, title, description, mitre, source) VALUES (:severity, :title, :description, :mitre, :source)",
            _SEED,
        )


def get_findings() -> list[dict]:
    with get_conn() as conn:
        _seed_if_empty(conn)
        rows = conn.execute("SELECT * FROM findings ORDER BY created_at DESC").fetchall()
    return [row_to_dict(r) for r in rows]


def add_finding(severity: str, title: str, description: str = "", mitre: str = "", source: str = "manual") -> dict:
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO findings (severity, title, description, mitre, source) VALUES (?,?,?,?,?)",
            (severity.upper(), title, description, mitre, source),
        )
        row = conn.execute("SELECT * FROM findings WHERE id = ?", (cur.lastrowid,)).fetchone()
    return row_to_dict(row)

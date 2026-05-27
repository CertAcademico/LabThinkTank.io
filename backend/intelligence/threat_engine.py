from db import get_conn, row_to_dict

_STATIC_FEED = [
    {"id": 1, "ioc": "185.220.101.1",                    "type": "IP",     "threat_actor": "APT-Shadow", "severity": "high",     "mitre": "T1071", "country": "RU",      "source": "static"},
    {"id": 2, "ioc": "evil-login-security.com",           "type": "DOMAIN", "threat_actor": "Black Lynx", "severity": "critical", "mitre": "T1566", "country": "CN",      "source": "static"},
    {"id": 3, "ioc": "7f4d2f9c8ab2f1e3d4c5b6a7890abcde", "type": "HASH",   "threat_actor": "LockBit",    "severity": "critical", "mitre": "T1486", "country": "Unknown", "source": "static"},
]
_STATIC_IOCS = {e["ioc"] for e in _STATIC_FEED}


def get_threat_feed() -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM iocs ORDER BY created_at DESC").fetchall()
    return _STATIC_FEED + [row_to_dict(r) for r in rows]


def add_uploaded_iocs(iocs: list[dict]) -> list[dict]:
    added = []
    with get_conn() as conn:
        existing_db = {r[0] for r in conn.execute("SELECT ioc FROM iocs").fetchall()}
        for ioc in iocs:
            val = ioc["ioc"]
            if val in _STATIC_IOCS or val in existing_db:
                continue
            conn.execute(
                """INSERT INTO iocs (ioc, type, threat_actor, severity, mitre, country, source)
                   VALUES (:ioc, :type, :threat_actor, :severity, :mitre, :country, :source)""",
                {
                    "ioc":          val,
                    "type":         ioc.get("type", "UNKNOWN"),
                    "threat_actor": ioc.get("threat_actor", "Unknown"),
                    "severity":     ioc.get("severity", "medium"),
                    "mitre":        ioc.get("mitre", ""),
                    "country":      ioc.get("country", "Unknown"),
                    "source":       ioc.get("source", "uploaded"),
                },
            )
            existing_db.add(val)
            added.append(ioc)
    return added


def get_ioc_count() -> int:
    with get_conn() as conn:
        row = conn.execute("SELECT COUNT(*) FROM iocs").fetchone()
    return (row[0] if row else 0) + len(_STATIC_FEED)

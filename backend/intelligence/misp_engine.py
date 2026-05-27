"""
MISP integration — two modes:
  1. Private MISP API : set MISP_URL + MISP_KEY in .env
  2. Public feeds     : MalwareBazaar (hashes) + URLhaus (URLs) — no auth needed
"""
import csv
import io
import os
import requests

MISP_URL  = os.getenv("MISP_URL", "").rstrip("/")
MISP_KEY  = os.getenv("MISP_KEY", "")
_TIMEOUT  = 15

_BAZAAR_CSV   = "https://bazaar.abuse.ch/export/csv/recent/"
_URLHAUS_TEXT = "https://urlhaus.abuse.ch/downloads/text/"

_ATTR_TYPES_IOC = {
    "ip-dst", "ip-src", "ip-dst|port",
    "domain", "hostname", "domain|ip",
    "url", "uri",
    "md5", "sha1", "sha256", "sha512",
    "filename|md5", "filename|sha256",
}

_SEVERITY_MAP = {1: "critical", 2: "high", 3: "medium", 4: "low"}


def _headers() -> dict:
    return {
        "Authorization": MISP_KEY,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def _ioc_value(attr_type: str, value: str) -> str:
    if "|" in attr_type and "|" in value:
        return value.split("|", 1)[1]
    return value


def _detect_type(attr_type: str) -> str:
    if "ip" in attr_type:
        return "IP"
    if attr_type in ("domain", "hostname"):
        return "DOMAIN"
    if attr_type in ("url", "uri"):
        return "URL"
    if any(h in attr_type for h in ("md5", "sha1", "sha256", "sha512")):
        return "HASH"
    return "UNKNOWN"


def _parse_event(event: dict) -> list[dict]:
    iocs = []
    ev = event.get("Event", event)
    threat_level = int(ev.get("threat_level_id", 3))
    severity = _SEVERITY_MAP.get(threat_level, "medium")
    actor = ev.get("Orgc", {}).get("name", "") or ev.get("info", "MISP")

    for attr in [*ev.get("Attribute", []), *[a for o in ev.get("Object", []) for a in o.get("Attribute", [])]]:
        atype = attr.get("type", "")
        if atype not in _ATTR_TYPES_IOC:
            continue
        val = _ioc_value(atype, attr.get("value", "").strip())
        if val:
            iocs.append({
                "ioc": val, "type": _detect_type(atype),
                "threat_actor": actor, "severity": severity,
                "mitre": "", "country": "", "source": "misp",
                "event_id": ev.get("uuid", ""),
            })
    return iocs


# ── Private MISP API ──────────────────────────────────────────────────────────

def _fetch_private(limit: int = 50) -> list[dict]:
    r = requests.post(
        f"{MISP_URL}/attributes/restSearch",
        headers=_headers(),
        json={"returnFormat": "json", "limit": limit, "enforceWarninglist": True},
        timeout=_TIMEOUT,
        verify=False,
    )
    r.raise_for_status()
    iocs = []
    for attr in r.json().get("response", {}).get("Attribute", []):
        atype = attr.get("type", "")
        if atype not in _ATTR_TYPES_IOC:
            continue
        val = _ioc_value(atype, attr.get("value", "").strip())
        if not val:
            continue
        threat_level = int(attr.get("Event", {}).get("threat_level_id", 3))
        iocs.append({
            "ioc": val, "type": _detect_type(atype),
            "threat_actor": attr.get("Event", {}).get("Orgc", {}).get("name", "MISP"),
            "severity": _SEVERITY_MAP.get(threat_level, "medium"),
            "mitre": "", "country": "", "source": "misp",
            "event_id": attr.get("event_uuid", ""),
        })
    return iocs


# ── Public feeds (no auth) ────────────────────────────────────────────────────

def _fetch_malwarebazaar(limit: int = 30) -> list[dict]:
    """Recent malware hashes from MalwareBazaar (abuse.ch)."""
    r = requests.get(_BAZAAR_CSV, timeout=_TIMEOUT)
    r.raise_for_status()
    iocs = []
    reader = csv.reader(io.StringIO(r.text))
    for row in reader:
        if not row or row[0].startswith("#"):
            continue
        # cols: first_seen, sha256, md5, sha1, reporter, filename, mime, type, signature, ...
        if len(row) < 9:
            continue
        sha256    = row[1].strip().strip('"')
        signature = row[8].strip().strip('"') or "Unknown"
        severity  = "critical" if signature.lower() not in ("n/a", "", "unknown") else "high"
        iocs.append({
            "ioc": sha256, "type": "HASH",
            "threat_actor": signature,
            "severity": severity,
            "mitre": "T1105", "country": "Unknown", "source": "malwarebazaar",
        })
        if len(iocs) >= limit:
            break
    return iocs


def _fetch_urlhaus(limit: int = 20) -> list[dict]:
    """Recent malicious URLs from URLhaus (abuse.ch)."""
    r = requests.get(_URLHAUS_TEXT, timeout=_TIMEOUT)
    r.raise_for_status()
    iocs = []
    for line in r.text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        iocs.append({
            "ioc": line, "type": "URL",
            "threat_actor": "URLhaus",
            "severity": "high",
            "mitre": "T1566", "country": "Unknown", "source": "urlhaus",
        })
        if len(iocs) >= limit:
            break
    return iocs


def _fetch_public(limit: int = 50) -> list[dict]:
    iocs: list[dict] = []
    hash_limit = min(limit * 3 // 4, 40)
    url_limit  = limit - hash_limit
    try:
        iocs.extend(_fetch_malwarebazaar(hash_limit))
    except Exception:
        pass
    try:
        iocs.extend(_fetch_urlhaus(url_limit))
    except Exception:
        pass
    return iocs[:limit]


# ── Public entrypoints ────────────────────────────────────────────────────────

def fetch_misp_iocs(limit: int = 50) -> list[dict]:
    if MISP_URL and MISP_KEY:
        return _fetch_private(limit)
    return _fetch_public(limit)


def get_misp_status() -> dict:
    if MISP_URL and MISP_KEY:
        return {"mode": "private", "url": MISP_URL, "configured": True}
    return {
        "mode": "public",
        "sources": ["malwarebazaar", "urlhaus"],
        "configured": False,
        "note": "Set MISP_URL + MISP_KEY in .env for a private MISP instance (e.g. CIRCL)",
    }

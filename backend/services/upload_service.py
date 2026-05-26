import csv
import io
import json
import re
from typing import Any

from ai.ai_engine import _detect_type


# ── Column aliases for CSV auto-mapping ──────────────────────────────────────

_COL_IOC       = {"ioc", "indicator", "value", "observable", "ip", "domain", "hash", "url", "artifact"}
_COL_TYPE      = {"type", "ioc_type", "indicator_type", "observable_type"}
_COL_SEVERITY  = {"severity", "risk", "risk_level", "confidence", "priority", "tlp"}
_COL_ACTOR     = {"threat_actor", "actor", "source", "group", "attribution"}
_COL_MITRE     = {"mitre", "mitre_id", "mitre_technique", "technique", "attack_id", "ttp"}
_COL_COUNTRY   = {"country", "geo", "origin", "cc"}


def parse_upload(filename: str, raw: bytes) -> list[dict]:
    fname = filename.lower()
    text = raw.decode("utf-8", errors="replace")

    if fname.endswith(".csv"):
        return _parse_csv(text)
    if fname.endswith(".json"):
        data = json.loads(text)
        # STIX bundle detection
        if isinstance(data, dict) and data.get("type") == "bundle":
            return _parse_stix(data)
        return _parse_json(data)
    # Plain text: one IOC per line
    return _parse_plaintext(text)


# ── CSV ───────────────────────────────────────────────────────────────────────

def _parse_csv(text: str) -> list[dict]:
    reader = csv.DictReader(io.StringIO(text))
    mapping = _build_column_map(reader.fieldnames or [])
    results = []
    for row in reader:
        ioc_val = _pick(row, mapping.get("ioc", ""))
        if not ioc_val:
            continue
        results.append(_normalize(
            ioc=ioc_val,
            ioc_type=_pick(row, mapping.get("type", "")),
            severity=_pick(row, mapping.get("severity", "")),
            actor=_pick(row, mapping.get("actor", "")),
            mitre=_pick(row, mapping.get("mitre", "")),
            country=_pick(row, mapping.get("country", "")),
        ))
    return results


def _build_column_map(fields: list[str]) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for f in fields:
        fl = f.lower().strip()
        if fl in _COL_IOC and "ioc" not in mapping:
            mapping["ioc"] = f
        elif fl in _COL_TYPE and "type" not in mapping:
            mapping["type"] = f
        elif fl in _COL_SEVERITY and "severity" not in mapping:
            mapping["severity"] = f
        elif fl in _COL_ACTOR and "actor" not in mapping:
            mapping["actor"] = f
        elif fl in _COL_MITRE and "mitre" not in mapping:
            mapping["mitre"] = f
        elif fl in _COL_COUNTRY and "country" not in mapping:
            mapping["country"] = f
    return mapping


# ── JSON (plain array or object with indicators key) ────────────────────────

def _parse_json(data: Any) -> list[dict]:
    rows: list[Any] = []
    if isinstance(data, list):
        rows = data
    elif isinstance(data, dict):
        for key in ("indicators", "iocs", "objects", "items", "data"):
            if isinstance(data.get(key), list):
                rows = data[key]
                break

    results = []
    for item in rows:
        if not isinstance(item, dict):
            continue
        ioc_val = (
            item.get("ioc") or item.get("indicator") or item.get("value")
            or item.get("observable") or item.get("ip") or item.get("domain")
            or item.get("hash") or item.get("url")
        )
        if not ioc_val:
            continue
        results.append(_normalize(
            ioc=str(ioc_val),
            ioc_type=str(item.get("type", "")),
            severity=str(item.get("severity") or item.get("risk") or ""),
            actor=str(item.get("threat_actor") or item.get("actor") or item.get("source") or ""),
            mitre=str(item.get("mitre") or item.get("technique") or ""),
            country=str(item.get("country") or item.get("geo") or ""),
        ))
    return results


# ── STIX 2.x bundle ──────────────────────────────────────────────────────────

# Extracts value from STIX pattern like: [domain-name:value = 'evil.com']
_STIX_PATTERN = re.compile(r"=\s*'([^']+)'")

def _parse_stix(bundle: dict) -> list[dict]:
    results = []
    objects = bundle.get("objects", [])

    # Build a name map from threat-actor/intrusion-set objects for relationship resolution
    name_map: dict[str, str] = {}
    for obj in objects:
        if obj.get("type") in ("threat-actor", "intrusion-set", "malware", "tool"):
            name_map[obj.get("id", "")] = obj.get("name", "")

    # Build actor relationship map: indicator_id → actor_name
    rel_map: dict[str, str] = {}
    for obj in objects:
        if obj.get("type") == "relationship":
            src = obj.get("source_ref", "")
            tgt = obj.get("target_ref", "")
            if src.startswith("indicator--") and tgt in name_map:
                rel_map[src] = name_map[tgt]

    for obj in objects:
        if obj.get("type") != "indicator":
            continue

        pattern = obj.get("pattern", "")
        match = _STIX_PATTERN.search(pattern)
        if not match:
            continue

        ioc_val = match.group(1)
        labels = obj.get("labels", [])
        severity = "high" if "malicious-activity" in labels else "medium"
        mitre_refs = [
            ref.get("external_id", "")
            for ref in obj.get("external_references", [])
            if ref.get("source_name") == "mitre-attack"
        ]

        results.append(_normalize(
            ioc=ioc_val,
            ioc_type="",
            severity=severity,
            actor=rel_map.get(obj.get("id", ""), "Unknown"),
            mitre=mitre_refs[0] if mitre_refs else "",
            country="",
        ))

    return results


# ── Plain text ────────────────────────────────────────────────────────────────

def _parse_plaintext(text: str) -> list[dict]:
    results = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        results.append(_normalize(ioc=line))
    return results


# ── Normalizer ────────────────────────────────────────────────────────────────

_SEVERITY_ALIASES = {
    "critical": "critical", "crit": "critical",
    "high": "high", "h": "high",
    "medium": "medium", "med": "medium", "moderate": "medium",
    "low": "low", "l": "low", "info": "low",
}

def _normalize(
    ioc: str,
    ioc_type: str = "",
    severity: str = "",
    actor: str = "",
    mitre: str = "",
    country: str = "",
) -> dict:
    ioc = ioc.strip()
    detected_type = _detect_type(ioc)
    final_type = ioc_type.upper() if ioc_type.strip() else detected_type
    final_severity = _SEVERITY_ALIASES.get(severity.lower().strip(), "medium")

    return {
        "ioc": ioc,
        "type": final_type,
        "threat_actor": actor.strip() or "Unknown",
        "severity": final_severity,
        "mitre": mitre.strip() or "—",
        "country": country.strip() or "Unknown",
        "source": "upload",
    }


def _pick(row: dict, col: str) -> str:
    return str(row.get(col, "") or "").strip()

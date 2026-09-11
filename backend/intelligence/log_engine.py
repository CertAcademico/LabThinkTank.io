from __future__ import annotations

"""
Multi-format log parser, IOC extractor and volumetry analyzer for CTI-Lab.

Supported input formats (auto-detected):
  - JSON / JSON Lines
  - CSV / TSV
  - Syslog (RFC 3164 / RFC 5424)
  - CEF (Common Event Format — ArcSight)
  - LEEF (Log Event Extended Format — IBM)
  - Zeek/Bro TSV logs
  - W3C Extended Log Format (IIS / Apache)
  - key=value pairs (Splunk-style)
  - Plain text (free-form, IOC extraction only)

IOC types extracted from any format:
  - IPv4 public addresses
  - URLs (http/https)
  - Domain names
  - SHA-256 / SHA-1 / MD5 hashes
  - Email addresses
  - CVE identifiers
"""
import csv
import io
import ipaddress
import json
import re
from collections import Counter
from datetime import datetime, timezone
from typing import Any

# ── IOC extraction ─────────────────────────────────────────────────────────────

_RE_URL    = re.compile(r'https?://[^\s"\'<>\]]+', re.IGNORECASE)
_RE_IPV4   = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b')
_RE_DOMAIN = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
    r'+(?:com|net|org|edu|gov|io|co|info|xyz|ru|cn|de|uk|fr|br|onion|tk|ml|ga|cf|gq|cc|biz)\b',
    re.IGNORECASE,
)
_RE_SHA256 = re.compile(r'\b[a-fA-F0-9]{64}\b')
_RE_SHA1   = re.compile(r'\b[a-fA-F0-9]{40}\b')
_RE_MD5    = re.compile(r'\b[a-fA-F0-9]{32}\b')
_RE_EMAIL  = re.compile(r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b')
_RE_CVE    = re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.IGNORECASE)

_PRIVATE = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('0.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16'),
    ipaddress.ip_network('100.64.0.0/10'),
    ipaddress.ip_network('224.0.0.0/4'),
    ipaddress.ip_network('240.0.0.0/4'),
]
_SKIP_DOMAINS = {"example.com", "test.com", "localhost.com", "domain.com"}


def _is_public(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return not any(a in n for n in _PRIVATE)
    except ValueError:
        return False


def extract_iocs(text: str) -> list[dict]:
    """Return a deduplicated list of {ioc, type} dicts found in *text*."""
    seen: set[str] = set()
    result: list[dict] = []

    def _add(value: str, ioc_type: str) -> None:
        if value and value not in seen:
            seen.add(value)
            result.append({"ioc": value, "type": ioc_type})

    for m in _RE_URL.finditer(text):
        _add(m.group().rstrip(").,;"), "URL")

    for m in _RE_IPV4.finditer(text):
        if _is_public(m.group()):
            _add(m.group(), "IP")

    # domains — skip anything already covered by a URL match
    url_blob = " ".join(m.group() for m in _RE_URL.finditer(text))
    for m in _RE_DOMAIN.finditer(text):
        dom = m.group().lower()
        if dom not in seen and dom not in _SKIP_DOMAINS and dom not in url_blob:
            _add(dom, "Domain")

    for m in _RE_SHA256.finditer(text):
        _add(m.group().lower(), "Hash-SHA256")
    for m in _RE_SHA1.finditer(text):
        if m.group().lower() not in seen:
            _add(m.group().lower(), "Hash-SHA1")
    for m in _RE_MD5.finditer(text):
        if m.group().lower() not in seen:
            _add(m.group().lower(), "Hash-MD5")

    for m in _RE_EMAIL.finditer(text):
        _add(m.group().lower(), "Email")

    for m in _RE_CVE.finditer(text):
        _add(m.group().upper(), "CVE")

    return result


# ── Format detection ───────────────────────────────────────────────────────────

_MONTHS = r'(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)'

def detect_format(raw: str) -> str:
    """
    Return one of:
      json | jsonl | csv | syslog | cef | leef | zeek | w3c | kvpairs | text
    """
    stripped = raw.lstrip()
    lines = [l for l in raw.splitlines() if l.strip()]
    if not lines:
        return "text"

    first = lines[0]

    if stripped.startswith(("{", "[")):
        return "json"

    # JSON Lines — first two lines are both valid JSON objects
    try:
        json.loads(first)
        if len(lines) > 1:
            json.loads(lines[1])
        return "jsonl"
    except Exception:
        pass

    if first.startswith("CEF:"):
        return "cef"
    if first.startswith("LEEF:"):
        return "leef"
    if first.startswith("#fields"):
        return "zeek"
    if first.startswith("#Version:") or first.startswith("#Fields:"):
        return "w3c"

    if re.match(r'^<\d+>', first) or re.match(rf'^{_MONTHS}\s+\d', first):
        return "syslog"

    # CSV: consistent delimiter
    if "\t" in first and all("\t" in l for l in lines[:3]):
        return "csv"
    cc = [l.count(",") for l in lines[:5]]
    if cc and min(cc) >= 2 and (max(cc) - min(cc)) <= 2:
        return "csv"

    # key=value
    kv_re = re.compile(r'\w+=\S+')
    avg = sum(len(kv_re.findall(l)) for l in lines[:5]) / max(len(lines[:5]), 1)
    if avg >= 2:
        return "kvpairs"

    return "text"


# ── Parsers ────────────────────────────────────────────────────────────────────

def _parse_json(raw: str) -> list[dict]:
    data = json.loads(raw.strip())
    if isinstance(data, list):
        return [r if isinstance(r, dict) else {"value": r} for r in data]
    if isinstance(data, dict):
        for key in ("logs", "data", "events", "records", "hits", "results"):
            if isinstance(data.get(key), list):
                return [r if isinstance(r, dict) else {"value": r} for r in data[key]]
        return [data]
    return []


def _parse_jsonl(raw: str) -> list[dict]:
    rows: list[dict] = []
    for line in raw.splitlines():
        line = line.strip()
        if line:
            try:
                rows.append(json.loads(line))
            except Exception:
                pass
    return rows


def _parse_csv(raw: str) -> list[dict]:
    try:
        sample = raw[:4000]
        dialect = csv.Sniffer().sniff(sample, delimiters=",\t|;")
    except csv.Error:
        dialect = None  # type: ignore[assignment]
    try:
        reader = csv.DictReader(io.StringIO(raw), dialect=dialect)
        return [dict(r) for r in reader]
    except Exception:
        return []


def _parse_syslog(raw: str) -> list[dict]:
    pat3164 = re.compile(
        r'^(?:<(?P<priority>\d+)>)?'
        rf'(?P<timestamp>{_MONTHS}\s+\d{{1,2}}\s+\d{{2}}:\d{{2}}:\d{{2}})\s+'
        r'(?P<hostname>\S+)\s+'
        r'(?P<process>[^\[\s:]+)(?:\[(?P<pid>\d+)\])?:\s*'
        r'(?P<message>.*)$'
    )
    pat5424 = re.compile(
        r'^<(?P<priority>\d+)>(?P<version>\d)\s+'
        r'(?P<timestamp>\S+)\s+(?P<hostname>\S+)\s+'
        r'(?P<app>\S+)\s+(?P<procid>\S+)\s+(?P<msgid>\S+)\s+'
        r'(?P<sd>\S+)\s+(?P<message>.*)$'
    )
    rows: list[dict] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        m = pat5424.match(line) or pat3164.match(line)
        if m:
            d = m.groupdict()
            pri = int(d.get("priority") or 0)
            d["facility"]      = pri >> 3
            d["severity_code"] = pri & 0x7
            d["raw"] = line
            rows.append(d)
        else:
            rows.append({"raw": line, "message": line})
    return rows


def _parse_cef(raw: str) -> list[dict]:
    rows: list[dict] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line.startswith("CEF:"):
            continue
        try:
            parts = line[4:].split("|", 7)
            if len(parts) < 7:
                rows.append({"raw": line}); continue
            row: dict[str, Any] = {
                "cef_version":    parts[0], "device_vendor": parts[1],
                "device_product": parts[2], "device_version": parts[3],
                "signature_id":   parts[4], "name":           parts[5],
                "severity":       parts[6], "raw":            line,
            }
            if len(parts) == 8:
                for kv in re.finditer(r'(\w+)=((?:[^=\\]|\\.)*?)(?=\s+\w+=|$)', parts[7]):
                    row[kv.group(1)] = kv.group(2)
            rows.append(row)
        except Exception:
            rows.append({"raw": line})
    return rows


def _parse_leef(raw: str) -> list[dict]:
    rows: list[dict] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line.startswith("LEEF:"):
            continue
        try:
            sep  = "\t" if "\t" in line else "|"
            hdr, _, attrs = line.partition(sep if sep == "\t" else "|")
            hp = hdr.split("|")
            row: dict[str, Any] = {
                "leef_version": hp[0][5:] if hp else "",
                "vendor": hp[1] if len(hp) > 1 else "",
                "product": hp[2] if len(hp) > 2 else "",
                "version": hp[3] if len(hp) > 3 else "",
                "event_id": hp[4] if len(hp) > 4 else "",
                "raw": line,
            }
            for kv in attrs.split(sep):
                if "=" in kv:
                    k, _, v = kv.partition("=")
                    row[k.strip()] = v.strip()
            rows.append(row)
        except Exception:
            rows.append({"raw": line})
    return rows


def _parse_zeek(raw: str) -> list[dict]:
    fields: list[str] = []
    rows: list[dict] = []
    for line in raw.splitlines():
        if line.startswith("#fields"):
            fields = line.split("\t")[1:]
        elif not line.startswith("#") and fields:
            rows.append(dict(zip(fields, line.split("\t"))))
    return rows


def _parse_w3c(raw: str) -> list[dict]:
    fields: list[str] = []
    rows: list[dict] = []
    for line in raw.splitlines():
        if line.startswith("#Fields:"):
            fields = line[8:].strip().split()
        elif not line.startswith("#") and fields:
            rows.append(dict(zip(fields, line.split())))
    return rows


def _parse_kv(raw: str) -> list[dict]:
    kv_re = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|\S+)')
    rows: list[dict] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        row: dict[str, Any] = {"raw": line}
        for m in kv_re.finditer(line):
            row[m.group(1)] = m.group(2).strip('"')
        rows.append(row)
    return rows


_PARSERS = {
    "json":    _parse_json,
    "jsonl":   _parse_jsonl,
    "csv":     _parse_csv,
    "syslog":  _parse_syslog,
    "cef":     _parse_cef,
    "leef":    _parse_leef,
    "zeek":    _parse_zeek,
    "w3c":     _parse_w3c,
    "kvpairs": _parse_kv,
    "text":    lambda r: [{"raw": l} for l in r.splitlines() if l.strip()],
}


# ── Volumetry analysis ────────────────────────────────────────────────────────

_TS_PATTERNS = [
    # ISO 8601
    re.compile(r'\b(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})'),
    # Common log format: 01/Jan/2024:12:34:56
    re.compile(r'(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})'),
    # Syslog: Jan 01 12:34:56
    re.compile(r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})'),
]

_TS_FMTS = [
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
    "%d/%b/%Y:%H:%M:%S",
    "%b %d %H:%M:%S",
    "%b  %d %H:%M:%S",
]


def _try_parse_ts(value: str) -> datetime | None:
    for fmt in _TS_FMTS:
        try:
            return datetime.strptime(value.strip(), fmt)
        except ValueError:
            pass
    return None


def _extract_ts_from_row(row: dict) -> datetime | None:
    """Try to find a timestamp in common log field names."""
    for key in ("timestamp", "time", "date", "@timestamp", "datetime",
                "event_time", "created_at", "ts", "log_time", "start_time"):
        val = row.get(key) or row.get(key.upper())
        if val:
            parsed = _try_parse_ts(str(val))
            if parsed:
                return parsed
    # Last resort: scan raw field
    raw = str(row.get("raw", ""))
    for pat in _TS_PATTERNS:
        m = pat.search(raw)
        if m:
            parsed = _try_parse_ts(m.group(1))
            if parsed:
                return parsed
    return None


def compute_volumetry(rows: list[dict], raw: str = "") -> dict:
    """
    Compute event volumetry metrics from parsed log rows.

    Returns:
        {
          "total_events":      int,
          "events_with_ts":    int,
          "timespan_seconds":  float | None,
          "events_per_minute": float | None,
          "events_per_hour":   float | None,
          "by_hour":           {hour_str: count},   # e.g. "2024-01-15T14": 42
          "by_severity":       {severity: count},
          "by_source":         {source: count},
          "by_type":           {type: count},
          "by_action":         {action: count},
          "peak_hour":         str | None,
          "peak_count":        int,
        }
    """
    total = len(rows)
    if total == 0:
        return {
            "total_events": 0, "events_with_ts": 0,
            "timespan_seconds": None, "events_per_minute": None, "events_per_hour": None,
            "by_hour": {}, "by_severity": {}, "by_source": {}, "by_type": {},
            "by_action": {}, "peak_hour": None, "peak_count": 0,
        }

    timestamps: list[datetime] = []
    by_hour:     Counter = Counter()
    by_severity: Counter = Counter()
    by_source:   Counter = Counter()
    by_type:     Counter = Counter()
    by_action:   Counter = Counter()

    _sev_fields  = ("severity", "level", "priority", "log_level", "sev")
    _src_fields  = ("source", "src", "hostname", "host", "origin", "device_vendor")
    _type_fields = ("type", "event_type", "category", "threatType", "ioc_type")
    _act_fields  = ("action", "event_id", "signature_id", "name", "msg")

    for row in rows:
        # timestamp
        ts = _extract_ts_from_row(row)
        if ts:
            timestamps.append(ts)
            by_hour[ts.strftime("%Y-%m-%dT%H")] += 1

        # categorical fields
        for f in _sev_fields:
            v = row.get(f) or row.get(f.upper())
            if v:
                by_severity[str(v).lower()[:20]] += 1
                break
        for f in _src_fields:
            v = row.get(f) or row.get(f.upper())
            if v:
                by_source[str(v)[:40]] += 1
                break
        for f in _type_fields:
            v = row.get(f) or row.get(f.upper())
            if v:
                by_type[str(v)[:30]] += 1
                break
        for f in _act_fields:
            v = row.get(f) or row.get(f.upper())
            if v:
                by_action[str(v)[:40]] += 1
                break

    timespan = events_per_min = events_per_hour = None
    if len(timestamps) >= 2:
        ts_sorted = sorted(timestamps)
        delta = (ts_sorted[-1] - ts_sorted[0]).total_seconds()
        if delta > 0:
            timespan       = round(delta, 1)
            events_per_min = round(total / (delta / 60), 2)
            events_per_hour = round(total / (delta / 3600), 2)

    peak_hour  = by_hour.most_common(1)[0][0] if by_hour else None
    peak_count = by_hour.most_common(1)[0][1] if by_hour else 0

    return {
        "total_events":      total,
        "events_with_ts":    len(timestamps),
        "timespan_seconds":  timespan,
        "events_per_minute": events_per_min,
        "events_per_hour":   events_per_hour,
        "by_hour":           dict(sorted(by_hour.items())[-48:]),  # last 48h buckets
        "by_severity":       dict(by_severity.most_common(10)),
        "by_source":         dict(by_source.most_common(15)),
        "by_type":           dict(by_type.most_common(15)),
        "by_action":         dict(by_action.most_common(20)),
        "peak_hour":         peak_hour,
        "peak_count":        peak_count,
    }


# ── Public API ─────────────────────────────────────────────────────────────────

def parse_logs(raw: str, hint: str | None = None, max_rows: int = 10_000) -> dict:
    """
    Parse *raw* log content, extract IOC candidates and compute volumetry.

    Returns::

        {
            "format":     str,
            "rows":       list[dict],   # up to max_rows parsed rows
            "iocs":       list[dict],   # [{ioc, type}, ...]
            "schema":     dict,
            "line_count": int,          # total parsed (may exceed max_rows)
            "volumetry":  dict,         # event rate and breakdown metrics
            "error":      str | None,
        }
    """
    if not raw or not raw.strip():
        return {
            "format": "empty", "rows": [], "iocs": [], "schema": {},
            "line_count": 0, "volumetry": compute_volumetry([]), "error": None,
        }

    fmt = hint or detect_format(raw)
    parser = _PARSERS.get(fmt, _PARSERS["text"])

    try:
        rows = parser(raw)
    except Exception:
        rows = [{"raw": l} for l in raw.splitlines() if l.strip()]
        fmt  = "text"

    total_rows = len(rows)
    iocs = extract_iocs(raw)
    volumetry = compute_volumetry(rows, raw)

    schema: dict[str, str] = {}
    for row in rows:
        if row:
            schema = {k: type(v).__name__ for k, v in row.items()}
            break

    return {
        "format":     fmt,
        "rows":       rows[:max_rows],
        "iocs":       iocs,
        "schema":     schema,
        "line_count": total_rows,
        "volumetry":  volumetry,
        "error":      None,
    }

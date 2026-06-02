from __future__ import annotations

"""
Public CTI feed integrations — no API key required (unless noted).

Original feeds:
  - ThreatFox (abuse.ch)       — IOCs of active malware
  - FeodoTracker (abuse.ch)    — Botnet C2 IP blocklist
  - OpenPhish                  — Phishing URLs
  - Ransomware.live            — Recent ransomware victims

New feeds added:
  - URLhaus (abuse.ch)         — Malware distribution URLs
  - MalwareBazaar (abuse.ch)   — Recent malware samples with hashes
  - CISA KEV                   — CISA Known Exploited Vulnerabilities
  - DShield / SANS Top-20      — Top attacking subnets
  - Cybercrime Tracker         — C2 panels (botnet trackers)
  - Botvrij.eu Domains         — Domain blocklist from Botvrij.eu
  - CI Army / Collective Intel — IP blocklist (collective intelligence)
  - Emerging Threats IPs       — Proofpoint Emerging Threats blocklist (free)
"""
import re
import requests

_TIMEOUT = 18
_UA = "CTI-Lab/2.0 (educational; contact: ctilab@redciber.com)"


# ── Helpers ────────────────────────────────────────────────────────────────────

def _severity(score: int | float | None) -> str:
    if score is None:
        return "medium"
    s = int(score)
    if s >= 90:
        return "critical"
    if s >= 70:
        return "high"
    if s >= 40:
        return "medium"
    return "low"


# ── Original feeds ─────────────────────────────────────────────────────────────

def fetch_threatfox(limit: int = 50) -> list[dict]:
    """Recent IOCs from ThreatFox — malware C2, payloads, domains."""
    try:
        r = requests.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "get_iocs", "days": 3},
            timeout=_TIMEOUT,
        )
        r.raise_for_status()
        data = r.json()
        iocs = []
        for item in (data.get("data") or [])[:limit]:
            iocs.append({
                "ioc":          item.get("ioc_value", ""),
                "type":         item.get("ioc_type", ""),
                "threat_actor": item.get("malware_printable", "Unknown"),
                "severity":     _severity(item.get("confidence_level")),
                "mitre":        "",
                "country":      "",
                "source":       "threatfox",
                "confidence":   item.get("confidence_level", 0),
                "tags":         ",".join(item.get("tags") or []),
            })
        return iocs
    except Exception as e:
        return [{"error": str(e)}]


def fetch_feodotracker(limit: int = 50) -> list[dict]:
    """Active botnet C2 IPs from Feodo Tracker (Emotet, TrickBot, Dridex, QakBot)."""
    try:
        r = requests.get(
            "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
            timeout=_TIMEOUT,
        )
        r.raise_for_status()
        iocs = []
        for item in r.json()[:limit]:
            iocs.append({
                "ioc":          item.get("ip_address", ""),
                "type":         "IP",
                "threat_actor": item.get("malware", "Unknown"),
                "severity":     "critical" if item.get("level") == "Tier1" else "high",
                "mitre":        "T1071",
                "country":      item.get("country", ""),
                "source":       "feodotracker",
                "port":         item.get("port", 0),
                "last_online":  item.get("last_online", ""),
                "first_seen":   item.get("first_seen", ""),
            })
        return iocs
    except Exception as e:
        return [{"error": str(e)}]


def fetch_openphish(limit: int = 50) -> list[dict]:
    """Active phishing URLs from OpenPhish community feed."""
    try:
        r = requests.get("https://openphish.com/feed.txt", timeout=_TIMEOUT)
        r.raise_for_status()
        urls = [l.strip() for l in r.text.splitlines() if l.strip().startswith("http")]
        iocs = []
        for url in urls[:limit]:
            domain = url.split("/")[2] if "/" in url else url
            iocs.append({
                "ioc":          url,
                "type":         "URL",
                "threat_actor": "Unknown",
                "severity":     "high",
                "mitre":        "T1566.002",
                "country":      "",
                "source":       "openphish",
                "domain":       domain,
            })
        return iocs
    except Exception as e:
        return [{"error": str(e)}]


def fetch_ransomware_live(limit: int = 30) -> list[dict]:
    """Recent ransomware victims from Ransomware.live public API."""
    try:
        r = requests.get(
            "https://api.ransomware.live/v2/recentvictims",
            timeout=_TIMEOUT,
            headers={"User-Agent": _UA},
        )
        r.raise_for_status()
        victims = r.json()
        result = []
        for v in (victims if isinstance(victims, list) else victims.get("data", []))[:limit]:
            result.append({
                "victim":    v.get("name") or v.get("victim", ""),
                "group":     v.get("group") or v.get("gangname", ""),
                "sector":    v.get("activity", "") or v.get("sector", ""),
                "country":   v.get("country", ""),
                "published": v.get("published") or v.get("date", ""),
                "url_leak":  v.get("website") or v.get("url", ""),
                "source":    "ransomware.live",
            })
        return result
    except Exception as e:
        return [{"error": str(e)}]


# ── New feeds ──────────────────────────────────────────────────────────────────

def fetch_urlhaus(limit: int = 50) -> list[dict]:
    """
    Recent malware distribution URLs from URLhaus (abuse.ch).
    Returns URLs with malware family, hosting country, tags.
    """
    try:
        r = requests.post(
            "https://urlhaus-api.abuse.ch/v1/urls/recent/",
            data={"limit": min(limit, 1000)},
            timeout=_TIMEOUT,
            headers={"User-Agent": _UA},
        )
        r.raise_for_status()
        data = r.json()
        iocs = []
        for item in (data.get("urls") or [])[:limit]:
            if item.get("url_status") not in ("online", "unknown"):
                continue
            url = item.get("url", "")
            domain = url.split("/")[2] if len(url.split("/")) > 2 else url
            tags = ",".join(item.get("tags") or [])
            iocs.append({
                "ioc":          url,
                "type":         "URL",
                "threat_actor": (item.get("threat") or "Unknown").replace("_", " "),
                "severity":     "high",
                "mitre":        "T1105",
                "country":      item.get("country", ""),
                "source":       "urlhaus",
                "domain":       domain,
                "tags":         tags,
                "first_seen":   item.get("date_added", ""),
            })
        return iocs
    except Exception as e:
        return [{"error": str(e)}]


def fetch_malwarebazaar(limit: int = 50) -> list[dict]:
    """
    Recent malware samples from MalwareBazaar (abuse.ch).
    Returns SHA-256 hashes, malware families, MIME types, tags.
    """
    try:
        r = requests.post(
            "https://mb-api.abuse.ch/api/v1/",
            data={"query": "get_recent", "selector": "100"},
            timeout=_TIMEOUT,
            headers={"User-Agent": _UA},
        )
        r.raise_for_status()
        data = r.json()
        iocs = []
        for item in (data.get("data") or [])[:limit]:
            iocs.append({
                "ioc":          item.get("sha256_hash", ""),
                "type":         "Hash-SHA256",
                "threat_actor": item.get("signature") or item.get("tags", ["Unknown"])[0] if item.get("tags") else "Unknown",
                "severity":     "high",
                "mitre":        "T1204.002",
                "country":      "",
                "source":       "malwarebazaar",
                "md5":          item.get("md5_hash", ""),
                "sha1":         item.get("sha1_hash", ""),
                "family":       item.get("signature", ""),
                "file_type":    item.get("file_type", ""),
                "file_name":    item.get("file_name", ""),
                "tags":         ",".join(item.get("tags") or []),
                "first_seen":   item.get("first_seen", ""),
            })
        return iocs
    except Exception as e:
        return [{"error": str(e)}]


def fetch_cisa_kev(limit: int = 50) -> list[dict]:
    """
    CISA Known Exploited Vulnerabilities (KEV) catalog.
    Public JSON feed — no auth required.
    Great for educational context: CVEs being actively exploited in the wild.
    """
    try:
        r = requests.get(
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            timeout=_TIMEOUT,
            headers={"User-Agent": _UA},
        )
        r.raise_for_status()
        data = r.json()
        vulns = sorted(
            data.get("vulnerabilities", []),
            key=lambda v: v.get("dateAdded", ""),
            reverse=True,
        )[:limit]
        result = []
        for v in vulns:
            result.append({
                "ioc":              v.get("cveID", ""),
                "type":             "CVE",
                "vendor":           v.get("vendorProject", ""),
                "product":          v.get("product", ""),
                "vulnerability":    v.get("vulnerabilityName", ""),
                "description":      v.get("shortDescription", ""),
                "required_action":  v.get("requiredAction", ""),
                "due_date":         v.get("dueDate", ""),
                "date_added":       v.get("dateAdded", ""),
                "ransomware_use":   v.get("knownRansomwareCampaignUse", "Unknown"),
                "severity":         "critical",
                "source":           "cisa_kev",
                "threat_actor":     "Multiple",
                "mitre":            "",
                "country":          "",
            })
        return result
    except Exception as e:
        return [{"error": str(e)}]


def fetch_dshield_top20(limit: int = 20) -> list[dict]:
    """
    SANS DShield / Internet Storm Center — Top attacking IPs (JSON API).
    Lists the most active scanners/attackers in the last 24h.
    """
    try:
        r = requests.get(
            "https://isc.sans.edu/api/sources/attacks/20/json",
            timeout=_TIMEOUT,
            headers={"User-Agent": _UA},
        )
        r.raise_for_status()
        data = r.json()
        items = data if isinstance(data, list) else data.get("sources", [])
        iocs = []
        for item in items[:limit]:
            iocs.append({
                "ioc":          item.get("ip", item.get("ipv4", "")),
                "type":         "IP",
                "threat_actor": "Unknown Scanner",
                "severity":     "medium",
                "mitre":        "T1595",
                "country":      item.get("country", ""),
                "source":       "dshield",
                "attacks":      item.get("attacks", 0),
                "targets":      item.get("targets", 0),
                "first_seen":   item.get("mindate", ""),
                "last_seen":    item.get("maxdate", ""),
            })
        return iocs
    except Exception as e:
        return [{"error": str(e)}]


def fetch_cybercrime_tracker(limit: int = 40) -> list[dict]:
    """
    Cybercrime Tracker — active C2 panels (CyberCriminalIP, ZeuS, SpyEye, etc.).
    RSS-based, returns URL + malware family.
    """
    try:
        r = requests.get(
            "https://cybercrime-tracker.net/rss.xml",
            timeout=_TIMEOUT,
            headers={"User-Agent": _UA},
        )
        r.raise_for_status()
        # Simple XML parsing without lxml
        urls  = re.findall(r'<link>([^<]+)</link>', r.text)
        titles = re.findall(r'<title>([^<]+)</title>', r.text)
        iocs = []
        for url, title in zip(urls[2:limit + 2], titles[2:]):   # skip channel-level links
            if not url.startswith("http"):
                continue
            domain = url.split("/")[2] if len(url.split("/")) > 2 else url
            iocs.append({
                "ioc":          url,
                "type":         "URL",
                "threat_actor": title.strip(),
                "severity":     "high",
                "mitre":        "T1071.001",
                "country":      "",
                "source":       "cybercrime-tracker",
                "domain":       domain,
            })
        return iocs
    except Exception as e:
        return [{"error": str(e)}]


def fetch_botvrij_domains(limit: int = 100) -> list[dict]:
    """
    Botvrij.eu — malicious domain blocklist (free, community-sourced).
    Plain text, one domain per line.
    """
    try:
        r = requests.get(
            "https://www.botvrij.eu/data/ioclist.domain.raw",
            timeout=_TIMEOUT,
            headers={"User-Agent": _UA},
        )
        r.raise_for_status()
        iocs = []
        for line in r.text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            iocs.append({
                "ioc":          line.lower(),
                "type":         "Domain",
                "threat_actor": "Unknown",
                "severity":     "medium",
                "mitre":        "T1071",
                "country":      "",
                "source":       "botvrij",
            })
            if len(iocs) >= limit:
                break
        return iocs
    except Exception as e:
        return [{"error": str(e)}]


def fetch_emerging_threats_ips(limit: int = 100) -> list[dict]:
    """
    Proofpoint Emerging Threats — compromised / attacking IP list (free tier).
    Plain text, one IP per line.
    """
    try:
        r = requests.get(
            "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
            timeout=_TIMEOUT,
            headers={"User-Agent": _UA},
        )
        r.raise_for_status()
        iocs = []
        for line in r.text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            iocs.append({
                "ioc":          line,
                "type":         "IP",
                "threat_actor": "Compromised Host",
                "severity":     "medium",
                "mitre":        "T1078.004",
                "country":      "",
                "source":       "emergingthreats",
            })
            if len(iocs) >= limit:
                break
        return iocs
    except Exception as e:
        return [{"error": str(e)}]


# ── Registry ───────────────────────────────────────────────────────────────────

FETCH_REGISTRY: dict[str, callable] = {
    # Original
    "ThreatFox":              fetch_threatfox,
    "ThreatFox (Ransom)":     fetch_threatfox,
    "FeodoTracker":           fetch_feodotracker,
    "Feodo Tracker C2":       fetch_feodotracker,
    "OpenPhish":              fetch_openphish,
    "Ransomware.live":        fetch_ransomware_live,
    # New
    "URLhaus":                fetch_urlhaus,
    "MalwareBazaar":          fetch_malwarebazaar,
    "CISA KEV":               fetch_cisa_kev,
    "DShield Top-20":         fetch_dshield_top20,
    "Cybercrime Tracker":     fetch_cybercrime_tracker,
    "Botvrij Domains":        fetch_botvrij_domains,
    "Emerging Threats IPs":   fetch_emerging_threats_ips,
}

# Feeds that are safe to sync-all without overloading (public, no auth)
PUBLIC_FEEDS = [
    "ThreatFox", "FeodoTracker", "URLhaus", "MalwareBazaar",
    "CISA KEV", "DShield Top-20", "Botvrij Domains", "Emerging Threats IPs",
]

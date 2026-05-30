"""
Public CTI feed integrations — no API key required.

Supported:
  - ThreatFox (abuse.ch)    — IOCs of active malware
  - FeodoTracker (abuse.ch) — Botnet C2 IP blocklist
  - OpenPhish               — Phishing URLs feed
  - Ransomware.live         — Recent ransomware victims
  - (MalwareBazaar + URLhaus are handled by misp_engine.py)
"""
import requests

_TIMEOUT = 15


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
                "severity":     "high" if item.get("confidence_level", 0) >= 75 else "medium",
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
        data = r.json()
        iocs = []
        for item in data[:limit]:
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
        r = requests.get(
            "https://openphish.com/feed.txt",
            timeout=_TIMEOUT,
        )
        r.raise_for_status()
        urls = [line.strip() for line in r.text.splitlines() if line.strip().startswith("http")]
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
            headers={"User-Agent": "CTI-Lab/1.0 (educational)"},
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


FETCH_REGISTRY: dict[str, callable] = {
    "ThreatFox":        fetch_threatfox,
    "ThreatFox (Ransom)": fetch_threatfox,
    "FeodoTracker":     fetch_feodotracker,
    "Feodo Tracker C2": fetch_feodotracker,
    "OpenPhish":        fetch_openphish,
    "Ransomware.live":  fetch_ransomware_live,
}

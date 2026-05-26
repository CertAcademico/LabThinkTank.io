import os
import re
import requests

VT_KEY       = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSE_KEY    = os.getenv("ABUSEIPDB_API_KEY", "")
SHODAN_KEY   = os.getenv("SHODAN_API_KEY", "")

_TIMEOUT = 10


def detect_ioc_type(ioc: str) -> str:
    ioc = ioc.strip()
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ioc):
        return "IP"
    if re.match(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$", ioc):
        return "HASH"
    if re.match(r"^https?://", ioc):
        return "URL"
    if "." in ioc:
        return "DOMAIN"
    return "UNKNOWN"


def _vt_ip(ip: str) -> dict:
    r = requests.get(
        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
        headers={"x-apikey": VT_KEY},
        timeout=_TIMEOUT,
    )
    if r.status_code != 200:
        return {"error": f"VT returned {r.status_code}"}
    attr = r.json().get("data", {}).get("attributes", {})
    stats = attr.get("last_analysis_stats", {})
    return {
        "malicious":   stats.get("malicious", 0),
        "suspicious":  stats.get("suspicious", 0),
        "harmless":    stats.get("harmless", 0),
        "undetected":  stats.get("undetected", 0),
        "reputation":  attr.get("reputation", 0),
        "country":     attr.get("country", ""),
        "asn":         attr.get("asn", ""),
        "as_owner":    attr.get("as_owner", ""),
        "network":     attr.get("network", ""),
    }


def _vt_domain(domain: str) -> dict:
    r = requests.get(
        f"https://www.virustotal.com/api/v3/domains/{domain}",
        headers={"x-apikey": VT_KEY},
        timeout=_TIMEOUT,
    )
    if r.status_code != 200:
        return {"error": f"VT returned {r.status_code}"}
    attr = r.json().get("data", {}).get("attributes", {})
    stats = attr.get("last_analysis_stats", {})
    return {
        "malicious":    stats.get("malicious", 0),
        "suspicious":   stats.get("suspicious", 0),
        "harmless":     stats.get("harmless", 0),
        "undetected":   stats.get("undetected", 0),
        "reputation":   attr.get("reputation", 0),
        "registrar":    attr.get("registrar", ""),
        "creation_date": attr.get("creation_date", ""),
        "categories":   attr.get("categories", {}),
    }


def _vt_hash(h: str) -> dict:
    r = requests.get(
        f"https://www.virustotal.com/api/v3/files/{h}",
        headers={"x-apikey": VT_KEY},
        timeout=_TIMEOUT,
    )
    if r.status_code != 200:
        return {"error": f"VT returned {r.status_code}"}
    attr = r.json().get("data", {}).get("attributes", {})
    stats = attr.get("last_analysis_stats", {})
    return {
        "malicious":      stats.get("malicious", 0),
        "suspicious":     stats.get("suspicious", 0),
        "harmless":       stats.get("harmless", 0),
        "undetected":     stats.get("undetected", 0),
        "type_description": attr.get("type_description", ""),
        "size":           attr.get("size", 0),
        "magic":          attr.get("magic", ""),
        "meaningful_name": attr.get("meaningful_name", ""),
        "tags":           attr.get("tags", []),
    }


def _vt_url(url: str) -> dict:
    import base64
    url_id = base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()
    r = requests.get(
        f"https://www.virustotal.com/api/v3/urls/{url_id}",
        headers={"x-apikey": VT_KEY},
        timeout=_TIMEOUT,
    )
    if r.status_code != 200:
        return {"error": f"VT returned {r.status_code}"}
    attr = r.json().get("data", {}).get("attributes", {})
    stats = attr.get("last_analysis_stats", {})
    return {
        "malicious":  stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless":   stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "final_url":  attr.get("last_final_url", url),
        "title":      attr.get("title", ""),
    }


def _abuseipdb(ip: str) -> dict:
    r = requests.get(
        "https://api.abuseipdb.com/api/v2/check",
        headers={"Key": ABUSE_KEY, "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": 90},
        timeout=_TIMEOUT,
    )
    if r.status_code != 200:
        return {"error": f"AbuseIPDB returned {r.status_code}"}
    d = r.json().get("data", {})
    return {
        "abuse_confidence_score": d.get("abuseConfidenceScore", 0),
        "total_reports":          d.get("totalReports", 0),
        "distinct_users":         d.get("numDistinctUsers", 0),
        "country":                d.get("countryCode", ""),
        "isp":                    d.get("isp", ""),
        "domain":                 d.get("domain", ""),
        "is_tor":                 d.get("isTor", False),
        "usage_type":             d.get("usageType", ""),
        "last_reported":          d.get("lastReportedAt", ""),
    }


def _shodan(ip: str) -> dict:
    r = requests.get(
        f"https://api.shodan.io/shodan/host/{ip}",
        params={"key": SHODAN_KEY},
        timeout=_TIMEOUT,
    )
    if r.status_code == 404:
        return {"error": "No information available for this IP"}
    if r.status_code != 200:
        return {"error": f"Shodan returned {r.status_code}"}
    d = r.json()
    return {
        "ports":        d.get("ports", []),
        "country_name": d.get("country_name", ""),
        "org":          d.get("org", ""),
        "isp":          d.get("isp", ""),
        "os":           d.get("os", ""),
        "hostnames":    d.get("hostnames", []),
        "vulns":        list(d.get("vulns", {}).keys()),
        "tags":         d.get("tags", []),
        "last_update":  d.get("last_update", ""),
    }


def enrich_ioc(ioc: str) -> dict:
    ioc = ioc.strip()
    ioc_type = detect_ioc_type(ioc)
    result: dict = {"ioc": ioc, "type": ioc_type, "sources": {}}

    # VirusTotal — supports all types
    if VT_KEY:
        try:
            if ioc_type == "IP":
                result["sources"]["virustotal"] = _vt_ip(ioc)
            elif ioc_type == "DOMAIN":
                result["sources"]["virustotal"] = _vt_domain(ioc)
            elif ioc_type == "HASH":
                result["sources"]["virustotal"] = _vt_hash(ioc)
            elif ioc_type == "URL":
                result["sources"]["virustotal"] = _vt_url(ioc)
        except Exception as e:
            result["sources"]["virustotal"] = {"error": str(e)}
    else:
        result["sources"]["virustotal"] = {"error": "API key not configured"}

    # AbuseIPDB — IP only
    if ioc_type == "IP":
        if ABUSE_KEY:
            try:
                result["sources"]["abuseipdb"] = _abuseipdb(ioc)
            except Exception as e:
                result["sources"]["abuseipdb"] = {"error": str(e)}
        else:
            result["sources"]["abuseipdb"] = {"error": "API key not configured"}

        # Shodan — IP only
        if SHODAN_KEY:
            try:
                result["sources"]["shodan"] = _shodan(ioc)
            except Exception as e:
                result["sources"]["shodan"] = {"error": str(e)}
        else:
            result["sources"]["shodan"] = {"error": "API key not configured"}

    return result

import re


def analyze_ioc(ioc: str) -> dict:
    ioc_lower = ioc.lower().strip()

    ioc_type = _detect_type(ioc)
    risk, confidence, summary, action = _evaluate(ioc_lower, ioc_type)

    return {
        "ioc": ioc,
        "type": ioc_type,
        "risk": risk,
        "confidence": confidence,
        "summary": summary,
        "recommended_action": action
    }


def _detect_type(ioc: str) -> str:
    ip_pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
    hash_pattern = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
    url_pattern = re.compile(r"^https?://")

    if ip_pattern.match(ioc):
        return "IP"
    if hash_pattern.match(ioc):
        return "HASH"
    if url_pattern.match(ioc):
        return "URL"
    if "." in ioc and not ioc.startswith("/"):
        return "DOMAIN"
    return "UNKNOWN"


def _evaluate(ioc: str, ioc_type: str) -> tuple:
    # Known malicious IP ranges (Tor exit nodes, common C2 ranges)
    HIGH_RISK_IP_PREFIXES = ("185.220.", "185.199.", "198.51.", "192.42.", "176.10.")
    # Phishing/credential-harvesting keywords in domains/URLs
    PHISHING_KEYWORDS = ("login", "secure", "account", "verify", "signin", "banking", "update", "paypal", "microsoft")
    # Suspicious TLDs
    SUSPICIOUS_TLDS = (".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click")
    # Ransomware/malware hash signatures (simulated known-bad hashes)
    KNOWN_BAD_HASHES = {
        "7f4d2f9c8ab2f1e3d4c5b6a7890abcde",
        "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
    }

    if ioc_type == "IP":
        if any(ioc.startswith(prefix) for prefix in HIGH_RISK_IP_PREFIXES):
            return ("high", 91, "IP associated with Tor exit nodes or known C2 infrastructure", "Block at perimeter firewall and investigate traffic")
        octets = ioc.split(".")
        if octets[0] in ("10", "172", "192"):
            return ("low", 40, "Private/RFC1918 address range", "No action required")
        return ("medium", 60, "Public IP with no known threat association", "Monitor for anomalous traffic patterns")

    if ioc_type == "DOMAIN":
        if any(kw in ioc for kw in PHISHING_KEYWORDS):
            return ("critical", 95, "Domain contains credential-harvesting keywords — likely phishing infrastructure", "Isolate affected users, block domain, notify security team")
        if any(ioc.endswith(tld) for tld in SUSPICIOUS_TLDS):
            return ("high", 80, "Domain uses free/abused TLD commonly associated with malware distribution", "Block domain and investigate DNS logs")
        return ("medium", 55, "Domain has no direct threat match — further OSINT recommended", "Investigate WHOIS, passive DNS, and certificate history")

    if ioc_type == "HASH":
        if ioc in KNOWN_BAD_HASHES:
            return ("critical", 99, "Hash matches known ransomware/malware sample", "Quarantine host immediately and initiate IR process")
        return ("medium", 50, "Hash not in local threat database — submit to VirusTotal for analysis", "Submit to external threat intel platforms")

    if ioc_type == "URL":
        if any(kw in ioc for kw in PHISHING_KEYWORDS):
            return ("critical", 93, "URL path contains phishing indicators", "Block URL, notify affected users, preserve logs")
        return ("medium", 55, "URL with no direct threat match", "Analyze in sandbox environment")

    return ("unknown", 30, "IOC type could not be determined", "Manual triage required")

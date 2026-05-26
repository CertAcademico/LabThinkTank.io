_static_feed = [
    {
        "id": 1,
        "ioc": "185.220.101.1",
        "type": "IP",
        "threat_actor": "APT-Shadow",
        "severity": "high",
        "mitre": "T1071",
        "country": "RU",
        "source": "static"
    },
    {
        "id": 2,
        "ioc": "evil-login-security.com",
        "type": "DOMAIN",
        "threat_actor": "Black Lynx",
        "severity": "critical",
        "mitre": "T1566",
        "country": "CN",
        "source": "static"
    },
    {
        "id": 3,
        "ioc": "7f4d2f9c8ab2f1e3d4c5b6a7890abcde",
        "type": "HASH",
        "threat_actor": "LockBit",
        "severity": "critical",
        "mitre": "T1486",
        "country": "Unknown",
        "source": "static"
    }
]

_uploaded_iocs: list[dict] = []
_next_id: int = len(_static_feed) + 1


def get_threat_feed() -> list[dict]:
    return _static_feed + _uploaded_iocs


def add_uploaded_iocs(iocs: list[dict]) -> list[dict]:
    global _next_id
    added = []
    existing = {entry["ioc"] for entry in get_threat_feed()}

    for ioc in iocs:
        if ioc["ioc"] in existing:
            continue
        ioc["id"] = _next_id
        _next_id += 1
        _uploaded_iocs.append(ioc)
        existing.add(ioc["ioc"])
        added.append(ioc)

    return added


def get_uploaded_iocs() -> list[dict]:
    return list(_uploaded_iocs)

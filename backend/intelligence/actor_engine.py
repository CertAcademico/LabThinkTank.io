threat_actors = [

    {
        "id": 1,
        "name": "APT-Shadow",
        "aliases": ["Shadow Bear", "UNC-2891"],
        "country": "RU",
        "motivation": "Cyber Espionage",
        "severity": "high",
        "active_campaign": "Operation Silent Night",
        "malware": ["ShadowLoader", "NightBeacon"],
        "ttps": ["T1071", "T1059", "T1003", "T1055", "T1566"],
        "targeted_sectors": ["Government", "Defense", "Energy"],
        "first_seen": "2019-03-12",
        "last_seen": "2026-05-18",
        "description": (
            "State-sponsored threat actor attributed to Russian intelligence services. "
            "Specializes in long-term stealthy intrusions targeting government and defense networks. "
            "Known for living-off-the-land techniques and custom implant deployment."
        ),
        "infrastructure": ["185.220.101.0/24", "176.10.99.0/24"],
        "ioc_count": 47,
    },

    {
        "id": 2,
        "name": "Black Lynx",
        "aliases": ["APT-41 Splinter", "Lynx-7"],
        "country": "CN",
        "motivation": "Credential Theft",
        "severity": "critical",
        "active_campaign": "Phantom Harvest",
        "malware": ["LynxStealer", "GhostDropper"],
        "ttps": ["T1566", "T1078", "T1110", "T1539", "T1056"],
        "targeted_sectors": ["Finance", "Healthcare", "Telecommunications"],
        "first_seen": "2021-07-04",
        "last_seen": "2026-05-22",
        "description": (
            "Financially motivated group with ties to Chinese state interests. "
            "Primary focus on harvesting credentials from high-value targets across the financial sector. "
            "Uses spear-phishing lures crafted with regional language and brand impersonation."
        ),
        "infrastructure": ["evil-login-security.com", "103.224.182.0/24"],
        "ioc_count": 83,
    },

    {
        "id": 3,
        "name": "LockBit",
        "aliases": ["LockBit 3.0", "ABCD Ransomware"],
        "country": "Unknown",
        "motivation": "Ransomware / Financial",
        "severity": "critical",
        "active_campaign": "University Strike",
        "malware": ["LockBit3", "StealBit"],
        "ttps": ["T1486", "T1027", "T1490", "T1489", "T1082"],
        "targeted_sectors": ["Education", "Healthcare", "Manufacturing"],
        "first_seen": "2019-09-01",
        "last_seen": "2026-05-25",
        "description": (
            "Prolific ransomware-as-a-service (RaaS) operation. "
            "Operates an affiliate model responsible for hundreds of confirmed attacks globally. "
            "Known for double extortion: encrypting data and threatening to publish exfiltrated files."
        ),
        "infrastructure": ["7f4d2f9c8ab2f1e3d4c5b6a7890abcde"],
        "ioc_count": 212,
    },

]


def get_threat_actors():
    return threat_actors

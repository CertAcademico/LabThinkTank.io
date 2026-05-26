campaigns = [

    {
        "id": 1,
        "name": "Operation Silent Night",
        "actor": "APT-Shadow",
        "target_sectors": ["Government", "Defense"],
        "affected_countries": ["UA", "PL", "DE", "US"],
        "status": "active",
        "start_date": "2025-11-03",
        "last_activity": "2026-05-18",
        "mitre": ["T1071", "T1059", "T1003", "T1055"],
        "ioc_count": 31,
        "confirmed_victims": 7,
        "description": (
            "Long-running espionage campaign targeting Eastern European government ministries "
            "and NATO-aligned defense contractors. Initial access via spear-phishing emails "
            "impersonating official diplomatic correspondence. Post-compromise activity includes "
            "credential dumping and lateral movement through WMI/PowerShell."
        ),
        "kill_chain_phase": "Exfiltration",
    },

    {
        "id": 2,
        "name": "University Strike",
        "actor": "LockBit",
        "target_sectors": ["Education"],
        "affected_countries": ["MX", "ES", "AR", "CO"],
        "status": "critical",
        "start_date": "2026-03-15",
        "last_activity": "2026-05-25",
        "mitre": ["T1486", "T1027", "T1490", "T1489"],
        "ioc_count": 18,
        "confirmed_victims": 4,
        "description": (
            "Ransomware campaign systematically targeting university networks across Latin America "
            "and Spain. Attackers exploit unpatched VPN appliances for initial access, followed "
            "by rapid lateral movement and deployment of LockBit3. Demands range from $500K to $2M USD. "
            "StealBit used for data exfiltration prior to encryption."
        ),
        "kill_chain_phase": "Impact",
    },

    {
        "id": 3,
        "name": "Phantom Harvest",
        "actor": "Black Lynx",
        "target_sectors": ["Finance", "Healthcare"],
        "affected_countries": ["US", "GB", "SG", "JP"],
        "status": "active",
        "start_date": "2026-01-20",
        "last_activity": "2026-05-22",
        "mitre": ["T1566", "T1078", "T1539", "T1056"],
        "ioc_count": 54,
        "confirmed_victims": 12,
        "description": (
            "Credential-harvesting campaign targeting financial institutions and healthcare providers. "
            "Deploys realistic phishing pages mimicking banking portals and internal SSO systems. "
            "LynxStealer captures session cookies enabling MFA bypass. Harvested credentials "
            "are subsequently used for business email compromise and fraudulent wire transfers."
        ),
        "kill_chain_phase": "Credential Access",
    },

]


def get_campaigns():
    return campaigns

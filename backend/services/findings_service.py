findings = [
    {
        "severity": "HIGH",
        "title": "Exposed Admin Panel",
        "description": "Public login interface discovered",
        "mitre": "T1190"
    },
    {
        "severity": "MEDIUM",
        "title": "Missing Security Headers",
        "description": "CSP header not configured",
        "mitre": "T1595"
    }
]

def get_findings():
    return findings

"""
CTI Synthetic Dataset Generator
Genera datasets realistas para entrenamiento de modelos ML,
basados en perfiles de actores CISA y distribuciones estadísticas reales.
"""
from __future__ import annotations

import random
import hashlib
import json
from datetime import datetime, timedelta
from intelligence.apt_database import CISA_APT_DATABASE

# ── Tablas de distribución ──────────────────────────────────────────────────────

_IOC_TYPE_DIST = [
    ("IP",         0.28),
    ("Domain",     0.24),
    ("URL",        0.18),
    ("Hash-SHA256",0.14),
    ("Hash-MD5",   0.08),
    ("Email",      0.05),
    ("CVE",        0.03),
]

_SEVERITY_DIST = [
    ("critical", 0.15),
    ("high",     0.30),
    ("medium",   0.35),
    ("low",      0.20),
]

_MITRE_BY_TACTIC = {
    "Initial Access":        ["T1566.001","T1566.002","T1190","T1133","T1199","T1078"],
    "Execution":             ["T1059.001","T1059.003","T1059.005","T1204.002","T1106"],
    "Persistence":           ["T1547.001","T1543.003","T1098","T1136.001","T1505.003"],
    "Defense Evasion":       ["T1027","T1036","T1562.001","T1070.004","T1218.011"],
    "Credential Access":     ["T1003.001","T1555","T1539","T1621","T1056.001"],
    "Discovery":             ["T1046","T1018","T1083","T1082","T1057"],
    "Lateral Movement":      ["T1021.001","T1021.002","T1021.006","T1550.002","T1080"],
    "Collection":            ["T1113","T1125","T1119","T1005","T1560"],
    "Command and Control":   ["T1071.001","T1071.004","T1090","T1102","T1573"],
    "Exfiltration":          ["T1041","T1048","T1567.002","T1020","T1030"],
    "Impact":                ["T1486","T1490","T1485","T1489","T1491.001"],
}

_COUNTRIES = {
    "Russia":       ["RU"],
    "China":        ["CN"],
    "Iran":         ["IR"],
    "North Korea":  ["KP"],
    "Colombia":     ["CO"],
    "Sur América":  ["CO","EC","CL","PE","AR","BR","VE"],
    "Internacional":["RU","CN","IR","UA","US","NL","DE","FR","GB"],
    "Rusia/Internacional":["RU","UA","MD","BY"],
    "Ucrania/Rusia":["UA","RU"],
    "EEUU/Reino Unido (jóvenes angloparlantes)":["US","GB","CA"],
}

# Rangos de IPs asociados a países maliciosos (educacional)
_IP_RANGES = {
    "RU": [("45.142.212",20),("185.220.101",100),("91.108.4",50),("194.165.16",30)],
    "CN": [("116.31.116",50),("36.99.136",20),("103.248.11",40),("175.6.14",30)],
    "IR": [("5.61.38",30),("185.51.201",20),("94.182.128",40)],
    "KP": [("175.45.176",10),("210.52.109",5)],
    "UA": [("91.212.150",30),("194.67.215",20)],
    "NL": [("185.220.100",50),("193.239.147",20)],
    "US": [("198.51.100",30),("203.0.113",20)],
}

_DOMAIN_PATTERNS = [
    "{brand}-security-{word}.{tld}",
    "{word}-{brand}-login.{tld}",
    "secure-{brand}-{word}.{tld}",
    "{brand}-{word}-verify.{tld}",
    "{word}-{brand}-update.{tld}",
    "cdn-{word}-{brand}.{tld}",
    "{brand}-{word}-alert.{tld}",
    "update-{brand}-{word}.{tld}",
    "download-{word}-{brand}.{tld}",
    "{word}.{brand}-{tld2}.{tld}",
]

_BRANDS = ["microsoft","google","amazon","paypal","apple","linkedin",
           "zoom","office365","github","dhl","fedex","bankofamerica",
           "oracle","adobe","dropbox","onedrive","teams","sharepoint"]
_WORDS  = ["cdn","secure","login","auth","update","verify","support",
           "portal","service","account","notification","delivery","alert",
           "access","help","download","api","cloud","sync"]
_TLDS   = ["com","net","info","xyz","biz","io","cloud","online","site","top"]
_TLDS2  = ["security","auth","verify","login","secure","cdn","update"]

_MALWARE_FAMILIES = {
    "APT28":       ["X-Agent","Zebrocy","LoJax","Sofacy","Drovorub"],
    "APT29":       ["SUNBURST","TEARDROP","MiniDuke","WellMess","CosmicDuke"],
    "Sandworm":    ["NotPetya","Industroyer","BlackEnergy","CaddyWiper","Cyclops Blink"],
    "Lazarus Group":["ELECTRICFISH","AppleJeus","DTrack","BLINDINGCAN","HOPLIGHT"],
    "LockBit":     ["LockBit 3.0","StealBit","LockBit Black"],
    "ALPHV/BlackCat":["BlackCat","ExMatter"],
    "Cl0p":        ["Cl0p","DEWMODE","FlawedAmmyy"],
    "Blind Eagle": ["AsyncRAT","BitRAT","Remcos RAT","njRAT","QuasarRAT"],
    "APT34":       ["POWRUNER","BONDUPDATER","RDAT","Saitama"],
    "Kimsuky":     ["BabyShark","ReconShark","AppleSeed","RandomQuery"],
}

_CAMPAIGNS_BY_ACTOR = {
    "APT28":        ["Operation Pawn Storm","Sednit Campaign","Olympic Destroyer 2018"],
    "APT29":        ["SolarWinds SUNBURST","COVID-19 Vaccine Theft","TeamViewer Breach"],
    "Sandworm":     ["NotPetya 2017","Ukraine Power Grid 2022","Viasat Hack 2022"],
    "Lazarus Group":["WannaCry 2017","Bangladesh Bank Heist","Bybit Hack 2025"],
    "LockBit":      ["ICBC Attack 2023","Boeing Breach 2023","Royal Mail UK"],
    "ALPHV/BlackCat":["Change Healthcare 2024","MGM Resorts 2023","Caesars 2023"],
    "Cl0p":         ["MOVEit Zero-Day 2023","GoAnywhere Zero-Day 2023"],
    "Blind Eagle":  ["Operation Blind Eagle","Ataque PONAL Colombia 2023"],
    "APT34":        ["DNSpionage 2018","Operation OilRig","SideTwist Campaign"],
    "Kimsuky":      ["Operation Kimsuky","STOLEN PENCIL","ReconShark 2023"],
}

_SOURCES = [
    "threatfox","malwarebazaar","feodotracker","urlhaus",
    "cisa-kev","dshield","emerging-threats","cti-lab-feed",
    "osint-manual","virustotal","shodan","alienvault-otx",
]


# ── Helpers ────────────────────────────────────────────────────────────────────

def _weighted_choice(dist: list[tuple]) -> str:
    r = random.random()
    acc = 0.0
    for val, prob in dist:
        acc += prob
        if r <= acc:
            return val
    return dist[-1][0]


def _fake_ip(country_code: str) -> str:
    ranges = _IP_RANGES.get(country_code)
    if ranges:
        prefix, limit = random.choice(ranges)
        return f"{prefix}.{random.randint(1, limit)}"
    return f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"


def _fake_domain() -> str:
    pattern = random.choice(_DOMAIN_PATTERNS)
    return pattern.format(
        brand=random.choice(_BRANDS),
        word=random.choice(_WORDS),
        tld=random.choice(_TLDS),
        tld2=random.choice(_TLDS2),
    )


def _fake_url(domain: str) -> str:
    paths = ["/login","/auth","/verify","/download","/api/v1/data",
             "/secure/signin","/update/install","/oauth/callback",
             "/user/account","/portal/access"]
    return f"https://{domain}{random.choice(paths)}"


def _fake_hash(length: int = 64) -> str:
    seed = random.randbytes(32)
    h = hashlib.sha256(seed).hexdigest()
    return h if length == 64 else h[:length]


def _fake_email(actor: str) -> str:
    words = ["noreply","admin","security","support","info","contact","billing"]
    tlds  = ["ru","cn","ir","kp","ua","com","net"]
    domain_words = [actor.lower().replace(" ","").replace("/","")[:8],
                    random.choice(_WORDS), "secure", "mail"]
    return f"{random.choice(words)}@{random.choice(domain_words)}.{random.choice(tlds)}"


def _fake_cve() -> str:
    year = random.randint(2020, 2025)
    num  = random.randint(1000, 50000)
    return f"CVE-{year}-{num}"


def _rand_date(days_back: int = 730) -> str:
    base = datetime(2024, 1, 1)
    delta = timedelta(days=random.randint(0, days_back))
    return (base + delta).strftime("%Y-%m-%dT%H:%M:%SZ")


def _pick_mitre() -> str:
    tactic = random.choice(list(_MITRE_BY_TACTIC.keys()))
    return random.choice(_MITRE_BY_TACTIC[tactic])


def _country_for_actor(actor_entry: dict) -> str:
    codes = _COUNTRIES.get(actor_entry["country"], ["XX"])
    return random.choice(codes)


# ── Core generator ─────────────────────────────────────────────────────────────

def generate_ioc_record(actor_entry: dict, idx: int) -> dict:
    """Generate one synthetic IoC record from a CISA actor profile."""
    ioc_type = _weighted_choice(_IOC_TYPE_DIST)
    severity  = _weighted_choice(_SEVERITY_DIST)
    country   = _country_for_actor(actor_entry)
    mitre     = _pick_mitre()
    campaign  = random.choice(_CAMPAIGNS_BY_ACTOR.get(actor_entry["name"], ["Unknown Campaign"]))
    malware   = random.choice(_MALWARE_FAMILIES.get(actor_entry["name"], ["Unknown"]))
    source    = random.choice(_SOURCES)
    confidence = random.randint(55, 99)
    tags_pool = ["C2","phishing","ransomware","spear","dropper","exfil","proxy",
                 "scanner","botnet","lateral","stealer","wiper","backdoor","exploit"]
    tags = ",".join(random.sample(tags_pool, k=random.randint(1, 3)))

    # Generate IoC value based on type
    if ioc_type == "IP":
        ioc_value = _fake_ip(country)
    elif ioc_type == "Domain":
        ioc_value = _fake_domain()
    elif ioc_type == "URL":
        ioc_value = _fake_url(_fake_domain())
    elif ioc_type in ("Hash-SHA256", "Hash-MD5"):
        length = 64 if ioc_type == "Hash-SHA256" else 32
        ioc_value = _fake_hash(length)
    elif ioc_type == "Email":
        ioc_value = _fake_email(actor_entry["name"])
    else:  # CVE
        ioc_value = _fake_cve()

    # Feature vector for ML clustering (numeric encoding)
    type_code = ["IP","Domain","URL","Hash-SHA256","Hash-MD5","Email","CVE"].index(ioc_type)
    sev_code  = {"critical":3,"high":2,"medium":1,"low":0}[severity]
    country_code = abs(hash(country)) % 20
    actor_code   = abs(hash(actor_entry["name"])) % 30

    return {
        # Identity
        "id":           f"syn_{idx:05d}",
        "ioc":          ioc_value,
        "type":         ioc_type,
        # Attribution
        "threat_actor": actor_entry["name"],
        "actor_country":actor_entry["country"],
        "actor_sponsor":actor_entry.get("sponsor",""),
        "campaign":     campaign,
        "malware":      malware,
        # Classification
        "severity":     severity,
        "mitre":        mitre,
        "country":      country,
        "source":       source,
        "confidence":   confidence,
        "tags":         tags,
        # Temporal
        "first_seen":   _rand_date(730),
        "last_seen":    _rand_date(90),
        # ML features (pre-computed numeric)
        "feat_type_code":    type_code,
        "feat_severity_code":sev_code,
        "feat_confidence":   confidence,
        "feat_country_code": country_code,
        "feat_actor_code":   actor_code,
        "feat_mitre_tactic": abs(hash(mitre[:5])) % 14,
        # CISA metadata
        "cisa_risk":         actor_entry.get("risk_level","Medium"),
        "cisa_advisories":   ",".join(actor_entry.get("cisa_advisories",[])[:2]),
        "target_sectors":    ",".join(actor_entry.get("target_sectors",[])[:3]),
    }


def generate_synthetic_dataset(
    n: int = 1000,
    actor_filter: list[str] | None = None,
    focus: str = "mixed",
    seed: int | None = None,
) -> dict:
    """
    Generate n synthetic IoC records for ML training.

    Args:
        n:            Number of records to generate (50 – 5000)
        actor_filter: Optional list of actor names to include (None = all)
        focus:        'apt' | 'criminal' | 'latam' | 'mixed'
        seed:         Random seed for reproducibility

    Returns:
        {
          "name": str,
          "description": str,
          "schema": dict,
          "data": list[dict],
          "stats": dict
        }
    """
    if seed is not None:
        random.seed(seed)

    n = max(50, min(5000, n))

    # Filter actor pool
    pool = CISA_APT_DATABASE
    if actor_filter:
        lower = [a.lower() for a in actor_filter]
        pool = [a for a in pool if a["name"].lower() in lower]
    if focus == "apt":
        pool = [a for a in pool if a.get("motivation","").startswith("Espionaje")]
    elif focus == "criminal":
        pool = [a for a in pool if "Criminal" in a.get("sponsor","") or "RaaS" in a.get("sponsor","")]
    elif focus == "latam":
        pool = [a for a in pool if any(r in a.get("target_regions",[]) for r in
                ["Colombia","LATAM","Sur América","Ecuador","Chile","México"])]
    if not pool:
        pool = CISA_APT_DATABASE

    records = []
    for i in range(n):
        actor = pool[i % len(pool)]
        rec   = generate_ioc_record(actor, i + 1)
        records.append(rec)

    # Shuffle to avoid ordering bias
    random.shuffle(records)

    # Stats summary
    from collections import Counter
    stats = {
        "total":         n,
        "by_type":       dict(Counter(r["type"] for r in records)),
        "by_severity":   dict(Counter(r["severity"] for r in records)),
        "by_actor":      dict(Counter(r["threat_actor"] for r in records).most_common(10)),
        "by_country":    dict(Counter(r["country"] for r in records).most_common(10)),
        "actors_count":  len({r["threat_actor"] for r in records}),
        "campaigns":     len({r["campaign"] for r in records}),
    }

    schema = {
        "id":                "str",
        "ioc":               "str",
        "type":              "str",
        "threat_actor":      "str",
        "actor_country":     "str",
        "actor_sponsor":     "str",
        "campaign":          "str",
        "malware":           "str",
        "severity":          "str",
        "mitre":             "str",
        "country":           "str",
        "source":            "str",
        "confidence":        "int",
        "tags":              "str",
        "first_seen":        "str",
        "last_seen":         "str",
        "feat_type_code":    "int",
        "feat_severity_code":"int",
        "feat_confidence":   "int",
        "feat_country_code": "int",
        "feat_actor_code":   "int",
        "feat_mitre_tactic": "int",
        "cisa_risk":         "str",
        "cisa_advisories":   "str",
        "target_sectors":    "str",
    }

    focus_label = {"apt":"APT Nations","criminal":"Criminal RaaS",
                   "latam":"LATAM","mixed":"Global Mix"}.get(focus, focus)
    actor_label = f"{len(pool)} actores"

    return {
        "name":        f"CTI Dataset Sintético — {focus_label} ({n} registros)",
        "description": (
            f"Dataset generado automáticamente para entrenamiento de modelos ML. "
            f"Contiene {n} IoCs sintéticos realistas basados en perfiles CISA de {actor_label}. "
            f"Incluye features pre-computados (feat_*) listos para K-Means, Random Forest e Isolation Forest."
        ),
        "source":      "cti-lab/synthetic-generator",
        "schema":      schema,
        "data":        records,
        "stats":       stats,
    }


def generate_feed_import_dataset(ioc_rows: list[dict]) -> dict:
    """
    Convert live feed IoC rows into a ML-ready dataset.
    Adds numeric feature columns needed for clustering.
    """
    records = []
    for i, row in enumerate(ioc_rows):
        ioc_type  = row.get("type","UNKNOWN")
        severity  = row.get("severity","medium")
        country   = row.get("country","Unknown")
        actor     = row.get("threat_actor","Unknown")
        mitre     = row.get("mitre","")
        confidence= int(row.get("confidence", 50) or 50)

        type_list = ["IP","Domain","URL","Hash-SHA256","Hash-MD5","Email","CVE","UNKNOWN"]
        type_code = type_list.index(ioc_type) if ioc_type in type_list else 7
        sev_code  = {"critical":3,"high":2,"medium":1,"low":0}.get(severity.lower(), 1)

        enriched = dict(row)
        enriched.update({
            "feat_type_code":    type_code,
            "feat_severity_code":sev_code,
            "feat_confidence":   confidence,
            "feat_country_code": abs(hash(country)) % 20,
            "feat_actor_code":   abs(hash(actor)) % 30,
            "feat_mitre_tactic": abs(hash(mitre[:5])) % 14 if mitre else 0,
        })
        records.append(enriched)

    schema = {k: ("int" if isinstance(v, int) else "str")
              for k, v in (records[0] if records else {}).items()}

    return {
        "name":        f"CTI Feed Import — {len(records)} IoCs",
        "description": (
            f"Dataset importado desde feeds públicos CTI. {len(records)} IoCs con "
            f"features ML pre-computados para clustering y clasificación."
        ),
        "source":      "cti-lab/feed-import",
        "schema":      schema,
        "data":        records,
    }

import json
import os
import sqlite3
from contextlib import contextmanager

DB_PATH = os.getenv("DB_PATH", "/data/cti.db")


def init_db() -> None:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with get_conn() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS iocs (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                ioc           TEXT    NOT NULL UNIQUE,
                type          TEXT    NOT NULL DEFAULT 'UNKNOWN',
                threat_actor  TEXT    NOT NULL DEFAULT 'Unknown',
                severity      TEXT    NOT NULL DEFAULT 'medium',
                mitre         TEXT    NOT NULL DEFAULT '',
                country       TEXT    NOT NULL DEFAULT 'Unknown',
                source        TEXT    NOT NULL DEFAULT 'uploaded',
                created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS findings (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                severity      TEXT    NOT NULL,
                title         TEXT    NOT NULL,
                description   TEXT    NOT NULL DEFAULT '',
                mitre         TEXT    NOT NULL DEFAULT '',
                source        TEXT    NOT NULL DEFAULT 'manual',
                created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                name          TEXT    NOT NULL,
                email         TEXT    NOT NULL UNIQUE,
                password_hash TEXT    NOT NULL,
                role          TEXT    NOT NULL DEFAULT 'student',
                created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS datasets (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                name        TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                source      TEXT NOT NULL DEFAULT 'manual',
                data_json   TEXT NOT NULL DEFAULT '[]',
                schema_json TEXT NOT NULL DEFAULT '{}',
                created_by  TEXT NOT NULL,
                created_at  TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS challenges (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                title           TEXT    NOT NULL,
                description     TEXT    NOT NULL DEFAULT '',
                objective       TEXT    NOT NULL DEFAULT '',
                dataset_id      INTEGER REFERENCES datasets(id),
                criteria        TEXT    NOT NULL DEFAULT '',
                deadline        TEXT,
                status          TEXT    NOT NULL DEFAULT 'active',
                badge_id        INTEGER REFERENCES badges(id),
                min_score_badge INTEGER NOT NULL DEFAULT 70,
                difficulty      TEXT    NOT NULL DEFAULT 'medio',
                created_by      TEXT    NOT NULL,
                created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS challenge_assignments (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                challenge_id INTEGER NOT NULL REFERENCES challenges(id),
                user_email   TEXT    NOT NULL,
                assigned_at  TEXT    NOT NULL DEFAULT (datetime('now')),
                UNIQUE(challenge_id, user_email)
            );

            CREATE TABLE IF NOT EXISTS submissions (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                challenge_id INTEGER NOT NULL REFERENCES challenges(id),
                user_email   TEXT NOT NULL,
                user_name    TEXT NOT NULL DEFAULT '',
                code         TEXT NOT NULL DEFAULT '',
                output       TEXT NOT NULL DEFAULT '',
                plots_json   TEXT NOT NULL DEFAULT '[]',
                notes        TEXT NOT NULL DEFAULT '',
                score        INTEGER,
                feedback     TEXT NOT NULL DEFAULT '',
                submitted_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS teams (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                name       TEXT NOT NULL UNIQUE,
                color      TEXT NOT NULL DEFAULT '#22d3ee',
                created_by TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS team_members (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                team_id    INTEGER NOT NULL REFERENCES teams(id),
                user_email TEXT    NOT NULL,
                joined_at  TEXT    NOT NULL DEFAULT (datetime('now')),
                UNIQUE(team_id, user_email)
            );

            CREATE TABLE IF NOT EXISTS badges (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                org         TEXT NOT NULL,
                name        TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                tier        TEXT NOT NULL DEFAULT 'bronze',
                icon        TEXT NOT NULL DEFAULT 'star',
                created_at  TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS user_badges (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                user_email TEXT    NOT NULL,
                badge_id   INTEGER NOT NULL REFERENCES badges(id),
                awarded_by TEXT    NOT NULL,
                awarded_at TEXT    NOT NULL DEFAULT (datetime('now')),
                UNIQUE(user_email, badge_id)
            );

            CREATE TABLE IF NOT EXISTS ctf_phases (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                order_idx   INTEGER NOT NULL DEFAULT 0,
                name        TEXT    NOT NULL,
                category    TEXT    NOT NULL DEFAULT '',
                reto_count  INTEGER NOT NULL DEFAULT 0,
                group_label TEXT    NOT NULL DEFAULT '',
                emoji       TEXT    NOT NULL DEFAULT '📅',
                status      TEXT    NOT NULL DEFAULT 'inactive',
                solves      INTEGER NOT NULL DEFAULT 0,
                created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS feed_sources (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                name          TEXT    NOT NULL,
                category      TEXT    NOT NULL DEFAULT 'IOC',
                url           TEXT    NOT NULL DEFAULT '',
                feed_type     TEXT    NOT NULL DEFAULT 'API',
                requires_auth INTEGER NOT NULL DEFAULT 0,
                api_key_env   TEXT    NOT NULL DEFAULT '',
                description   TEXT    NOT NULL DEFAULT '',
                formats       TEXT    NOT NULL DEFAULT '',
                group_label   TEXT    NOT NULL DEFAULT '',
                status        TEXT    NOT NULL DEFAULT 'available',
                last_fetched  TEXT,
                last_count    INTEGER NOT NULL DEFAULT 0,
                created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS ctf_challenges (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                phase_id        INTEGER REFERENCES ctf_phases(id),
                order_idx       INTEGER NOT NULL DEFAULT 0,
                title           TEXT    NOT NULL,
                description     TEXT    NOT NULL DEFAULT '',
                flag            TEXT    NOT NULL DEFAULT '',
                flag_format     TEXT    NOT NULL DEFAULT 'CTI{...}',
                hints_json      TEXT    NOT NULL DEFAULT '[]',
                category        TEXT    NOT NULL DEFAULT 'CTI',
                difficulty      TEXT    NOT NULL DEFAULT 'fácil',
                points          INTEGER NOT NULL DEFAULT 100,
                docker_image    TEXT    NOT NULL DEFAULT '',
                docker_port     TEXT    NOT NULL DEFAULT '8080',
                tools_json      TEXT    NOT NULL DEFAULT '[]',
                roles_json      TEXT    NOT NULL DEFAULT '[]',
                dataset_id      INTEGER REFERENCES datasets(id),
                is_team         INTEGER NOT NULL DEFAULT 0,
                status          TEXT    NOT NULL DEFAULT 'active',
                created_by      TEXT    NOT NULL DEFAULT 'system',
                created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS ctf_solves (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                challenge_id    INTEGER NOT NULL REFERENCES ctf_challenges(id),
                user_email      TEXT    NOT NULL,
                team_id         INTEGER REFERENCES teams(id),
                submitted_flag  TEXT    NOT NULL DEFAULT '',
                is_correct      INTEGER NOT NULL DEFAULT 0,
                points_earned   INTEGER NOT NULL DEFAULT 0,
                solved_at       TEXT    NOT NULL DEFAULT (datetime('now')),
                UNIQUE(challenge_id, user_email)
            );

            CREATE TABLE IF NOT EXISTS challenge_datasets (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                challenge_id INTEGER NOT NULL REFERENCES challenges(id),
                dataset_id   INTEGER NOT NULL REFERENCES datasets(id),
                UNIQUE(challenge_id, dataset_id)
            );

            CREATE INDEX IF NOT EXISTS idx_iocs_ioc ON iocs(ioc);
            CREATE INDEX IF NOT EXISTS idx_iocs_source ON iocs(source);
            CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
            CREATE INDEX IF NOT EXISTS idx_assign_challenge ON challenge_assignments(challenge_id);
            CREATE INDEX IF NOT EXISTS idx_assign_user ON challenge_assignments(user_email);
            CREATE INDEX IF NOT EXISTS idx_submissions_challenge ON submissions(challenge_id);
            CREATE INDEX IF NOT EXISTS idx_user_badges ON user_badges(user_email);
        """)
        _migrate(conn)
        _seed_badges(conn)
        _seed_ctf_phases(conn)
        _seed_feed_sources(conn)
        _seed_demo_datasets(conn)
        _seed_demo_challenges(conn)
        _seed_group_datasets(conn)
        _seed_group_challenges(conn)
        _seed_ctf_challenges(conn)


def _migrate(conn) -> None:
    """Add columns that may not exist in databases created before this version."""
    cols = {r[1] for r in conn.execute("PRAGMA table_info(challenges)").fetchall()}
    if "badge_id" not in cols:
        conn.execute("ALTER TABLE challenges ADD COLUMN badge_id INTEGER REFERENCES badges(id)")
    if "min_score_badge" not in cols:
        conn.execute("ALTER TABLE challenges ADD COLUMN min_score_badge INTEGER NOT NULL DEFAULT 70")
    if "difficulty" not in cols:
        conn.execute("ALTER TABLE challenges ADD COLUMN difficulty TEXT NOT NULL DEFAULT 'medio'")
    tm_cols = {r[1] for r in conn.execute("PRAGMA table_info(team_members)").fetchall()}
    if "role" not in tm_cols:
        conn.execute("ALTER TABLE team_members ADD COLUMN role TEXT NOT NULL DEFAULT 'analista_datos'")


# ── CTF Phase seeds ────────────────────────────────────────────────────────────

CTF_PHASE_SEEDS = [
    # (order_idx, name, category, reto_count, group_label, emoji, status, solves)
    (1, 'Día 1',          'Fundamentos',    13, '',             '📅', 'inactive', 54),
    (2, 'Día 2',          'Explotación',    13, '',             '📅', 'inactive', 30),
    (3, 'Día 3',          'Encadenamiento',  5, '',             '🔥', 'inactive',  2),
    (4, 'Día 4 — Fase 3', 'Avanzada',       50, 'G1 / G2 / G3', '☠️', 'inactive',  0),
    (5, 'Fase 4',         'Muerte Letal',    0, '',             '☠️', 'inactive',  0),
]


def _seed_ctf_phases(conn) -> None:
    if conn.execute("SELECT COUNT(*) FROM ctf_phases").fetchone()[0]:
        return
    conn.executemany(
        "INSERT INTO ctf_phases (order_idx, name, category, reto_count, group_label, emoji, status, solves) VALUES (?,?,?,?,?,?,?,?)",
        CTF_PHASE_SEEDS,
    )


# ── Badge seeds ────────────────────────────────────────────────────────────────

BADGE_SEEDS = [
    # ── CertAcademico ────────────────────────────────────────────────────────
    ("CertAcademico", "Explorador de Datos",      "Completó su primer ejercicio en el Sandbox Lab",         "bronze",   "book"),
    ("CertAcademico", "Analista Junior",           "Dominó el track CTI & pandas",                           "silver",   "chart"),
    ("CertAcademico", "Científico de Datos",       "Completó el track ETL & Limpieza de Datos",              "gold",     "flask"),
    ("CertAcademico", "Maestro de Visualización",  "Completó el track de Visualización con Matplotlib",      "gold",     "eye"),
    ("CertAcademico", "Ingeniero ML",              "Completó el track de Machine Learning con scikit-learn", "platinum", "cpu"),
    ("CertAcademico", "Experto CTI",               "Completó todos los tracks del Sandbox Lab",              "diamond",  "shield"),
    # ── redciber ─────────────────────────────────────────────────────────────
    ("redciber",      "Ciberdefensor",             "Realizó su primera entrega de reto de ciberseguridad",   "bronze",   "lock"),
    ("redciber",      "Threat Hunter",             "Obtuvo 70 o más en un reto de análisis de amenazas",     "silver",   "search"),
    ("redciber",      "SOC Analyst",               "Obtuvo 85 o más en un reto de operaciones de seguridad", "gold",     "radar"),
    ("redciber",      "Analista de Amenazas",      "Completó 3 retos con score ≥ 80",                        "platinum", "target"),
    ("redciber",      "Red Team Ready",            "Análisis excepcional — reto completado con 100 puntos",  "diamond",  "fire"),
    # ── LabThinkTank ─────────────────────────────────────────────────────────
    ("LabThinkTank",  "Lab Explorer",              "Primera sesión activa en el laboratorio Python",         "bronze",   "beaker"),
    ("LabThinkTank",  "Data Engineer",             "Pipeline ETL funcional y documentado",                   "silver",   "flow"),
    ("LabThinkTank",  "ML Practitioner",           "Modelo de Machine Learning entrenado y evaluado",        "gold",     "brain"),
    ("LabThinkTank",  "Innovation Award",          "Mejor visualización del reto — elegido por el docente",  "diamond",  "star"),
    ("LabThinkTank",  "Campeón del Reto",          "Primer lugar en el ranking de un reto grupal",           "diamond",  "trophy"),
]


def _seed_badges(conn) -> None:
    if conn.execute("SELECT COUNT(*) FROM badges").fetchone()[0]:
        return
    conn.executemany(
        "INSERT INTO badges (org, name, description, tier, icon) VALUES (?,?,?,?,?)",
        BADGE_SEEDS,
    )


# ── Demo CTI datasets ──────────────────────────────────────────────────────────

_DATASETS = [
    {
        "name": "Logs de Red — APT28 Fancy Bear",
        "description": "Tráfico de red capturado durante actividad atribuida a APT28. Contiene comunicaciones C2, movimiento lateral y exfiltración.",
        "source": "CTI-Lab / PCAP simulado",
        "schema": {"timestamp": "str", "src_ip": "str", "dst_ip": "str", "port": "int", "proto": "str", "bytes": "int", "action": "str", "country": "str", "threat_actor": "str", "mitre": "str"},
        "data": [
            {"timestamp": "2024-03-15 02:14:33", "src_ip": "185.220.101.47", "dst_ip": "10.0.0.24", "port": 443,  "proto": "HTTPS", "bytes": 4820,  "action": "ALLOW",  "country": "RU", "threat_actor": "APT28", "mitre": "T1071.001"},
            {"timestamp": "2024-03-15 02:15:01", "src_ip": "185.220.101.47", "dst_ip": "10.0.0.24", "port": 443,  "proto": "HTTPS", "bytes": 128,   "action": "ALLOW",  "country": "RU", "threat_actor": "APT28", "mitre": "T1071.001"},
            {"timestamp": "2024-03-15 02:17:45", "src_ip": "10.0.0.24",      "dst_ip": "10.0.0.12", "port": 445,  "proto": "SMB",   "bytes": 38400, "action": "ALLOW",  "country": "LAN", "threat_actor": "APT28", "mitre": "T1021.002"},
            {"timestamp": "2024-03-15 02:18:12", "src_ip": "10.0.0.24",      "dst_ip": "10.0.0.31", "port": 445,  "proto": "SMB",   "bytes": 41200, "action": "ALLOW",  "country": "LAN", "threat_actor": "APT28", "mitre": "T1021.002"},
            {"timestamp": "2024-03-15 02:22:09", "src_ip": "10.0.0.31",      "dst_ip": "91.108.4.11","port": 80,  "proto": "HTTP",  "bytes": 2240,  "action": "ALLOW",  "country": "NL",  "threat_actor": "APT28", "mitre": "T1041"},
            {"timestamp": "2024-03-15 02:22:44", "src_ip": "10.0.0.31",      "dst_ip": "91.108.4.11","port": 80,  "proto": "HTTP",  "bytes": 891200,"action": "ALLOW",  "country": "NL",  "threat_actor": "APT28", "mitre": "T1041"},
            {"timestamp": "2024-03-15 02:25:30", "src_ip": "185.220.101.47", "dst_ip": "10.0.0.24", "port": 4444, "proto": "TCP",  "bytes": 6144,  "action": "BLOCK",  "country": "RU",  "threat_actor": "APT28", "mitre": "T1071"},
            {"timestamp": "2024-03-15 02:26:18", "src_ip": "10.0.0.55",      "dst_ip": "8.8.8.8",   "port": 53,  "proto": "DNS",   "bytes": 512,   "action": "ALLOW",  "country": "US",  "threat_actor": "Unknown", "mitre": ""},
            {"timestamp": "2024-03-15 02:27:00", "src_ip": "10.0.0.24",      "dst_ip": "192.168.1.1","port": 22,  "proto": "SSH",   "bytes": 3200,  "action": "ALLOW",  "country": "LAN", "threat_actor": "APT28", "mitre": "T1021.004"},
            {"timestamp": "2024-03-15 02:30:15", "src_ip": "91.108.4.11",    "dst_ip": "10.0.0.31",  "port": 443, "proto": "HTTPS", "bytes": 1024,  "action": "ALLOW",  "country": "NL",  "threat_actor": "APT28", "mitre": "T1105"},
            {"timestamp": "2024-03-15 02:31:44", "src_ip": "10.0.0.24",      "dst_ip": "10.0.0.100","port": 3389, "proto": "RDP",   "bytes": 72000, "action": "ALLOW",  "country": "LAN", "threat_actor": "APT28", "mitre": "T1021.001"},
            {"timestamp": "2024-03-15 02:35:02", "src_ip": "10.0.0.100",     "dst_ip": "91.108.4.11","port": 80,  "proto": "HTTP",  "bytes": 1536000,"action": "ALLOW", "country": "NL",  "threat_actor": "APT28", "mitre": "T1041"},
            {"timestamp": "2024-03-15 02:40:55", "src_ip": "185.220.101.47", "dst_ip": "10.0.0.24", "port": 443,  "proto": "HTTPS", "bytes": 256,   "action": "ALLOW",  "country": "RU",  "threat_actor": "APT28", "mitre": "T1071.001"},
            {"timestamp": "2024-03-15 02:45:20", "src_ip": "10.0.0.24",      "dst_ip": "10.0.0.24", "port": 0,   "proto": "ICMP",  "bytes": 64,    "action": "ALLOW",  "country": "LAN", "threat_actor": "APT28", "mitre": "T1018"},
            {"timestamp": "2024-03-15 02:50:00", "src_ip": "10.0.0.24",      "dst_ip": "10.0.0.200","port": 5985, "proto": "WinRM", "bytes": 28160, "action": "ALLOW",  "country": "LAN", "threat_actor": "APT28", "mitre": "T1021.006"},
        ],
    },
    {
        "name": "Feed IOC Enriquecido — CTI-Lab",
        "description": "Indicadores de compromiso recopilados de múltiples fuentes: AlienVault OTX, AbuseIPDB, Threat Fox. Incluye IPs C2, dominios maliciosos y hashes de malware.",
        "source": "CTI-Lab / OTX + AbuseIPDB",
        "schema": {"ioc": "str", "type": "str", "threat_actor": "str", "severity": "str", "mitre": "str", "country": "str", "first_seen": "str", "confidence": "int", "tags": "str"},
        "data": [
            {"ioc": "185.220.101.47",              "type": "IP",     "threat_actor": "APT28",         "severity": "critical", "mitre": "T1071.001", "country": "RU", "first_seen": "2024-01-10", "confidence": 95, "tags": "C2,proxy"},
            {"ioc": "91.108.4.11",                 "type": "IP",     "threat_actor": "APT28",         "severity": "high",     "mitre": "T1041",     "country": "NL", "first_seen": "2024-02-03", "confidence": 87, "tags": "exfil,C2"},
            {"ioc": "update-microsoft-cdn.com",    "type": "domain", "threat_actor": "Lazarus Group", "severity": "critical", "mitre": "T1566.002", "country": "KP", "first_seen": "2024-02-14", "confidence": 92, "tags": "phishing,spear"},
            {"ioc": "secure-paypal-login.info",    "type": "domain", "threat_actor": "FIN7",          "severity": "high",     "mitre": "T1566.001", "country": "UA", "first_seen": "2024-03-01", "confidence": 83, "tags": "phishing,credential"},
            {"ioc": "cdn-fonts-google.net",        "type": "domain", "threat_actor": "APT29",         "severity": "medium",   "mitre": "T1583.001", "country": "RU", "first_seen": "2024-01-28", "confidence": 74, "tags": "C2,domain-fronting"},
            {"ioc": "44a8-bd6f-209b1a51c8e0",      "type": "hash",   "threat_actor": "LockBit",       "severity": "critical", "mitre": "T1486",     "country": "RU", "first_seen": "2024-03-10", "confidence": 99, "tags": "ransomware,LockBit3"},
            {"ioc": "e3b0c44298fc1c149afbf4c8",    "type": "hash",   "threat_actor": "AgentTesla",    "severity": "high",     "mitre": "T1555",     "country": "TR", "first_seen": "2024-02-20", "confidence": 91, "tags": "stealer,keylogger"},
            {"ioc": "203.0.113.45",                "type": "IP",     "threat_actor": "BlackCat",      "severity": "critical", "mitre": "T1486",     "country": "CN", "first_seen": "2024-03-05", "confidence": 88, "tags": "ransomware,C2"},
            {"ioc": "invoice-march2024.exe.doc",   "type": "domain", "threat_actor": "FIN7",          "severity": "high",     "mitre": "T1204.002", "country": "UA", "first_seen": "2024-03-08", "confidence": 85, "tags": "spear-phishing,lure"},
            {"ioc": "172.16.254.1",                "type": "IP",     "threat_actor": "Turla",         "severity": "medium",   "mitre": "T1090",     "country": "RU", "first_seen": "2024-01-15", "confidence": 70, "tags": "proxy,C2"},
            {"ioc": "office365-auth.xyz",          "type": "domain", "threat_actor": "APT29",         "severity": "high",     "mitre": "T1566.002", "country": "RU", "first_seen": "2024-02-28", "confidence": 90, "tags": "phishing,O365"},
            {"ioc": "198.51.100.22",               "type": "IP",     "threat_actor": "Cobalt Strike",  "severity": "critical", "mitre": "T1071",     "country": "US", "first_seen": "2024-03-12", "confidence": 93, "tags": "C2,beacon"},
            {"ioc": "a1b2c3d4e5f6a1b2c3d4e5f6",   "type": "hash",   "threat_actor": "Emotet",        "severity": "critical", "mitre": "T1204.002", "country": "Unknown", "first_seen": "2024-02-10", "confidence": 97, "tags": "dropper,botnet"},
            {"ioc": "download-java-update.biz",    "type": "domain", "threat_actor": "Lazarus Group", "severity": "high",     "mitre": "T1189",     "country": "KP", "first_seen": "2024-03-15", "confidence": 81, "tags": "drive-by,watering-hole"},
            {"ioc": "192.0.2.100",                 "type": "IP",     "threat_actor": "Unknown",       "severity": "low",      "mitre": "",          "country": "CN", "first_seen": "2024-03-18", "confidence": 45, "tags": "scanner"},
        ],
    },
    {
        "name": "Campaña Ransomware — LockBit 3.0",
        "description": "Registro de actividad de la campaña LockBit 3.0 contra infraestructura crítica. Incluye TTPs, movimiento lateral, encriptación y C2.",
        "source": "CTI-Lab / IR Report simulado",
        "schema": {"host": "str", "ip": "str", "timestamp": "str", "phase": "str", "technique": "str", "mitre": "str", "severity": "str", "ioc": "str", "details": "str"},
        "data": [
            {"host": "WEB-SRV-01",  "ip": "10.1.0.5",   "timestamp": "2024-03-20 08:12:00", "phase": "Initial Access",    "technique": "Phishing con enlace malicioso", "mitre": "T1566.002", "severity": "high",     "ioc": "secure-paypal-login.info", "details": "Usuario descargó archivo ZIP desde enlace de phishing"},
            {"host": "WEB-SRV-01",  "ip": "10.1.0.5",   "timestamp": "2024-03-20 08:15:33", "phase": "Execution",         "technique": "Macro maliciosa en Excel",      "mitre": "T1204.002", "severity": "critical", "ioc": "invoice-march2024.exe",    "details": "Macro ejecutó PowerShell codificado en Base64"},
            {"host": "WEB-SRV-01",  "ip": "10.1.0.5",   "timestamp": "2024-03-20 08:16:01", "phase": "Defense Evasion",   "technique": "Bypass de AMSI",                "mitre": "T1562.001", "severity": "high",     "ioc": "",                         "details": "Patch en memoria para evadir AMSI y Windows Defender"},
            {"host": "WEB-SRV-01",  "ip": "10.1.0.5",   "timestamp": "2024-03-20 08:18:45", "phase": "C2",                "technique": "HTTPS a servidor C2",           "mitre": "T1071.001", "severity": "critical", "ioc": "203.0.113.45",             "details": "Beacon HTTPS cada 60s a IP de LockBit"},
            {"host": "DC-01",       "ip": "10.1.0.1",   "timestamp": "2024-03-20 09:02:11", "phase": "Privilege Escalation", "technique": "PrintNightmare CVE-2021-34527", "mitre": "T1068",  "severity": "critical", "ioc": "",                         "details": "Explotación del servicio de cola de impresión para escalar a SYSTEM"},
            {"host": "DC-01",       "ip": "10.1.0.1",   "timestamp": "2024-03-20 09:10:30", "phase": "Credential Access", "technique": "LSASS dump con Mimikatz",       "mitre": "T1003.001", "severity": "critical", "ioc": "mimi64.exe",               "details": "Credenciales del dominio extraídas de memoria LSASS"},
            {"host": "FILE-SRV-02", "ip": "10.1.0.8",   "timestamp": "2024-03-20 09:25:00", "phase": "Lateral Movement",  "technique": "Pass the Hash por SMB",         "mitre": "T1550.002", "severity": "high",     "ioc": "",                         "details": "Movimiento lateral usando hash NTLM capturado"},
            {"host": "FILE-SRV-02", "ip": "10.1.0.8",   "timestamp": "2024-03-20 09:40:15", "phase": "Discovery",         "technique": "Enumeración de red",            "mitre": "T1046",     "severity": "medium",   "ioc": "",                         "details": "Escaneo interno con netscan para mapear infraestructura"},
            {"host": "BACKUP-SRV",  "ip": "10.1.0.20",  "timestamp": "2024-03-20 10:05:22", "phase": "Impact",            "technique": "Eliminación de backups VSS",    "mitre": "T1490",     "severity": "critical", "ioc": "",                         "details": "vssadmin delete shadows /all /quiet"},
            {"host": "FILE-SRV-02", "ip": "10.1.0.8",   "timestamp": "2024-03-20 10:15:00", "phase": "Exfiltration",      "technique": "Exfiltración por SFTP",         "mitre": "T1048",     "severity": "critical", "ioc": "91.108.4.11",              "details": "3.2 GB de datos enviados antes del cifrado"},
            {"host": "FILE-SRV-02", "ip": "10.1.0.8",   "timestamp": "2024-03-20 10:45:00", "phase": "Impact",            "technique": "Cifrado de archivos .lockbit3", "mitre": "T1486",     "severity": "critical", "ioc": "44a8-bd6f-209b1a51c8e0",   "details": "Extensión .lockbit3 en 18,432 archivos"},
            {"host": "WEB-SRV-01",  "ip": "10.1.0.5",   "timestamp": "2024-03-20 10:46:00", "phase": "Impact",            "technique": "Wallpaper y nota de rescate",   "mitre": "T1491.001", "severity": "high",     "ioc": "",                         "details": "Nota de rescate en cada directorio, exige 200,000 USD en BTC"},
            {"host": "DC-01",       "ip": "10.1.0.1",   "timestamp": "2024-03-20 11:00:00", "phase": "Impact",            "technique": "Cifrado de controlador de dominio", "mitre": "T1486", "severity": "critical", "ioc": "",                         "details": "AD completamente cifrado, sin posibilidad de recuperación sin backup"},
        ],
    },
    {
        "name": "Campaña Phishing — Credential Harvesting FIN7",
        "description": "Dominios y URLs registrados por FIN7 para robo de credenciales. Incluye typosquatting, lookalike domains y análisis de infraestructura.",
        "source": "CTI-Lab / OSINT + DomainTools",
        "schema": {"domain": "str", "url": "str", "target_org": "str", "registrar": "str", "registered": "str", "ip_hosting": "str", "technique": "str", "threat_actor": "str", "status": "str", "confidence": "int"},
        "data": [
            {"domain": "secure-paypal-login.info",     "url": "https://secure-paypal-login.info/signin",      "target_org": "PayPal",       "registrar": "Namecheap",   "registered": "2024-02-28", "ip_hosting": "91.108.4.11", "technique": "Typosquatting",       "threat_actor": "FIN7", "status": "active",   "confidence": 92},
            {"domain": "office365-auth.xyz",           "url": "https://office365-auth.xyz/login",             "target_org": "Microsoft",    "registrar": "Porkbun",     "registered": "2024-02-25", "ip_hosting": "185.220.101.47", "technique": "Lookalike domain",  "threat_actor": "APT29","status": "active",   "confidence": 89},
            {"domain": "login-bankofamerica-verify.com","url": "https://login-bankofamerica-verify.com/auth", "target_org": "Bank of America","registrar": "GoDaddy",   "registered": "2024-03-01", "ip_hosting": "203.0.113.45", "technique": "Homoglyph",           "threat_actor": "FIN7", "status": "sinkholed","confidence": 95},
            {"domain": "amazon-security-alert.net",    "url": "https://amazon-security-alert.net/verify",    "target_org": "Amazon",       "registrar": "Namecheap",   "registered": "2024-03-05", "ip_hosting": "198.51.100.22", "technique": "Brand impersonation","threat_actor": "FIN7", "status": "active",   "confidence": 87},
            {"domain": "update-microsoft-cdn.com",     "url": "https://update-microsoft-cdn.com/kb4056894",  "target_org": "Microsoft",    "registrar": "PublicDomain", "registered": "2024-02-10", "ip_hosting": "172.16.254.1", "technique": "Subdomain abuse",    "threat_actor": "Lazarus","status": "active",  "confidence": 91},
            {"domain": "linkedin-recruiter-verify.biz","url": "https://linkedin-recruiter-verify.biz/auth",  "target_org": "LinkedIn",     "registrar": "Porkbun",     "registered": "2024-03-08", "ip_hosting": "91.108.4.11", "technique": "Spear phishing",      "threat_actor": "Lazarus","status": "active",  "confidence": 84},
            {"domain": "dhl-delivery-notification.info","url": "https://dhl-delivery-notification.info/track","target_org": "DHL",          "registrar": "Namecheap",  "registered": "2024-03-10", "ip_hosting": "203.0.113.45", "technique": "Brand impersonation","threat_actor": "FIN7", "status": "active",   "confidence": 88},
            {"domain": "cdn-fonts-google.net",         "url": "https://cdn-fonts-google.net/api/fonts",       "target_org": "Google",       "registrar": "eNom",        "registered": "2024-01-28", "ip_hosting": "185.220.101.47","technique": "Domain fronting",   "threat_actor": "APT29","status": "active",   "confidence": 76},
            {"domain": "download-java-update.biz",     "url": "https://download-java-update.biz/jre-8u391",  "target_org": "Oracle",       "registrar": "Namecheap",   "registered": "2024-03-15", "ip_hosting": "192.0.2.100", "technique": "Watering hole",       "threat_actor": "Lazarus","status": "inactive","confidence": 81},
            {"domain": "zoom-meeting-secure.cloud",    "url": "https://zoom-meeting-secure.cloud/j/meeting",  "target_org": "Zoom",         "registrar": "Porkbun",     "registered": "2024-03-12", "ip_hosting": "198.51.100.22","technique": "Typosquatting",       "threat_actor": "APT28","status": "active",   "confidence": 79},
            {"domain": "github-actions-token.com",     "url": "https://github-actions-token.com/oauth",       "target_org": "GitHub",       "registrar": "GoDaddy",     "registered": "2024-03-18", "ip_hosting": "172.16.254.1", "technique": "Token harvesting",    "threat_actor": "APT29","status": "active",   "confidence": 94},
            {"domain": "fedex-shipment-update.xyz",    "url": "https://fedex-shipment-update.xyz/tracking",   "target_org": "FedEx",        "registrar": "Namecheap",   "registered": "2024-03-20", "ip_hosting": "203.0.113.45", "technique": "Brand impersonation","threat_actor": "FIN7", "status": "active",   "confidence": 82},
        ],
    },
    {
        "name": "Análisis Malware — AgentTesla & Emotet",
        "description": "Muestras de malware analizadas en sandbox. Incluye IOCs de red, persistencia, evasión y técnicas de credential stealing.",
        "source": "CTI-Lab / Any.run + VirusTotal sandbox",
        "schema": {"filename": "str", "md5": "str", "sha256": "str", "size_kb": "int", "family": "str", "type": "str", "mitre": "str", "c2_domain": "str", "c2_ip": "str", "persistence": "str", "evasion": "str", "capability": "str"},
        "data": [
            {"filename": "invoice_march2024.exe",   "md5": "a1b2c3d4e5f6a1b2c3d4e5f6", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size_kb": 420,  "family": "AgentTesla", "type": "exe",  "mitre": "T1555,T1056.001", "c2_domain": "update-microsoft-cdn.com", "c2_ip": "185.220.101.47", "persistence": "HKCU\\Run,Task Scheduler",       "evasion": "Process Hollowing,AMSI bypass",        "capability": "Keylogger,credential stealer,screenshot"},
            {"filename": "document_Q1_2024.doc",    "md5": "f1e2d3c4b5a6f1e2d3c4b5a6", "sha256": "2c624232cdd221771294dfbb310acbc8d21cadf2e9a9e2b5cdba3d3bcb9da53", "size_kb": 185,  "family": "Emotet",     "type": "doc",  "mitre": "T1204.002,T1059.005", "c2_domain": "cdn-fonts-google.net",     "c2_ip": "203.0.113.45",   "persistence": "HKCU\\Run,Startup Folder",          "evasion": "Macro obfuscation,VBA stomping",       "capability": "Dropper,botnet loader,spam module"},
            {"filename": "svchost32.exe",           "md5": "deadbeef01234567deadbeef", "sha256": "4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865", "size_kb": 892,  "family": "Cobalt Strike","type": "exe", "mitre": "T1071.001,T1055", "c2_domain": "office365-auth.xyz",       "c2_ip": "198.51.100.22",  "persistence": "Service Install,Scheduled Task",    "evasion": "Process injection,Sleep masking",      "capability": "RAT,C2 beacon,lateral movement"},
            {"filename": "updater.dll",             "md5": "0123456789abcdef01234567", "sha256": "1121cfccd5913f0a63fec40a6ffd44ea64f9dc135c66634ba001d10bcf4302a2", "size_kb": 512,  "family": "AgentTesla", "type": "dll",  "mitre": "T1056.001,T1113", "c2_domain": "secure-paypal-login.info", "c2_ip": "91.108.4.11",    "persistence": "DLL hijacking,COM object hijacking","evasion": "Reflective DLL injection,Timestomping", "capability": "Screen capture,FTP exfil,credential stealer"},
            {"filename": "powershell_stage2.ps1",   "md5": "abcdef0123456789abcdef01", "sha256": "7de9f8742b905ae6c02c4f6041fef37ab9b45a76a3dc1a6ad1fb6a6f3d3a5e1c", "size_kb": 28,   "family": "LockBit",    "type": "ps1",  "mitre": "T1059.001,T1562", "c2_domain": "",                         "c2_ip": "203.0.113.45",   "persistence": "",                                  "evasion": "AMSI bypass,event log clearing",       "capability": "Ransomware dropper,UAC bypass"},
            {"filename": "crypter_v3.exe",          "md5": "fedcba9876543210fedcba98", "sha256": "32096c2e0eff33d844ee6d675407ace18289357d3790c16e6ee2a8b8281f6c39", "size_kb": 1240, "family": "LockBit",    "type": "exe",  "mitre": "T1486,T1490",    "c2_domain": "",                         "c2_ip": "",               "persistence": "",                                  "evasion": "Anti-debugging,VM detection",          "capability": "File encryptor (.lockbit3),VSS deletion"},
            {"filename": "mimi64.exe",              "md5": "1234567890abcdef12345678", "sha256": "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b", "size_kb": 1408, "family": "Mimikatz",   "type": "exe",  "mitre": "T1003.001,T1550","c2_domain": "",                         "c2_ip": "",               "persistence": "",                                  "evasion": "Rename to legit process",              "capability": "LSASS dump,Pass-the-Hash,Kerberoasting"},
            {"filename": "remote_access.bat",       "md5": "98765432101234567890abcd", "sha256": "d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35", "size_kb": 4,    "family": "AgentTesla", "type": "bat",  "mitre": "T1059.003",      "c2_domain": "linkedin-recruiter-verify.biz","c2_ip": "91.108.4.11", "persistence": "Startup Folder",                    "evasion": "Base64 obfuscation",                   "capability": "Persistence,C2 connection setup"},
            {"filename": "macro_loader.xlsm",       "md5": "aabbccddeeff00112233aabb", "sha256": "4a44dc15364204a80fe80e9039455cc1608281820fe2b24f1e5233ade6af1dd5", "size_kb": 95,   "family": "Emotet",     "type": "xlsm", "mitre": "T1204.002,T1547","c2_domain": "dhl-delivery-notification.info","c2_ip": "203.0.113.45","persistence": "Registry Run Key",                  "evasion": "Macro sheet obfuscation",              "capability": "Dropper,network propagation"},
            {"filename": "teams_update.exe",        "md5": "112233445566778899aabb00", "sha256": "ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d", "size_kb": 756,  "family": "Cobalt Strike","type": "exe", "mitre": "T1218.011,T1055","c2_domain": "zoom-meeting-secure.cloud", "c2_ip": "198.51.100.22",  "persistence": "DLL side-loading",                  "evasion": "LOLBins,Signed binary proxy",           "capability": "Beacon,lateral movement,privilege escalation"},
        ],
    },
]

# ── Challenge seeds linked to badges ──────────────────────────────────────────
# badge_name must match an entry in BADGE_SEEDS exactly
_CHALLENGE_SEEDS = [
    {
        "title": "Caza de IOCs — APT28 Fancy Bear",
        "description": "Analiza el dataset de tráfico de red capturado durante actividad de APT28. Identifica todos los indicadores de compromiso (IOCs), mapea las técnicas MITRE ATT&CK usadas y construye un timeline del ataque.",
        "objective": "1) Filtra eventos con threat_actor='APT28'. 2) Identifica IPs únicas de C2. 3) Calcula bytes totales exfiltrados. 4) Crea gráfica de técnicas MITRE ATT&CK por frecuencia. 5) Construye un timeline de fases del ataque.",
        "criteria": "Análisis técnico (40%) + Visualizaciones (30%) + Mapeo MITRE correcto (30%)",
        "difficulty": "básico",
        "badge_name": "Threat Hunter",
        "min_score_badge": 70,
    },
    {
        "title": "Análisis de Campaña Ransomware LockBit 3.0",
        "description": "Reconstruye el kill chain completo de la campaña LockBit 3.0 usando los logs de respuesta a incidentes. Identifica el vector de entrada, movimiento lateral, técnicas de evasión y el impacto final.",
        "objective": "1) Ordena los eventos por timestamp y agrupa por fase del ataque. 2) Identifica el host de entrada inicial (Patient Zero). 3) Mapea el Lateral Movement path. 4) Crea diagrama de Kill Chain con Cyber Kill Chain o ATT&CK. 5) Calcula el tiempo total desde intrusión hasta cifrado.",
        "criteria": "Kill chain completo (35%) + Identificación Patient Zero (25%) + Visualizaciones (25%) + Recomendaciones de mitigación (15%)",
        "difficulty": "intermedio",
        "badge_name": "SOC Analyst",
        "min_score_badge": 85,
    },
    {
        "title": "Detección de Phishing con Machine Learning",
        "description": "Entrena un modelo para clasificar dominios como legítimos o maliciosos usando el dataset de campaña de phishing. Aplica feature engineering con características OSINT del dominio.",
        "objective": "1) Crea features: longitud del dominio, número de guiones, TLD sospechoso, antigüedad (registered date), confidence score. 2) Entrena un clasificador (Random Forest o Logistic Regression). 3) Evalúa con accuracy, precision, recall y F1. 4) Identifica los 3 features más importantes. 5) Visualiza la matriz de confusión.",
        "criteria": "Feature engineering (30%) + Accuracy del modelo ≥75% (30%) + Visualizaciones (20%) + Código limpio y comentado (20%)",
        "difficulty": "avanzado",
        "badge_name": "ML Practitioner",
        "min_score_badge": 75,
    },
    {
        "title": "Enriquecimiento y Priorización de IOC Feed",
        "description": "Procesa el feed IOC del CTI-Lab, limpia los datos, prioriza los IOCs por criticidad y genera un reporte ejecutivo. El objetivo es simular el workflow de un analista de threat intelligence.",
        "objective": "1) Limpia el dataset (maneja valores nulos, normaliza tipos de IOC). 2) Crea una puntuación de riesgo combinando severity + confidence. 3) Clasifica IOCs en Crítico/Alto/Medio/Bajo. 4) Agrupa por threat_actor y calcula distribución. 5) Genera gráficas: Top 5 threat actors, distribución por país, IOCs por tipo.",
        "criteria": "Limpieza de datos (20%) + Score de riesgo correcto (30%) + Visualizaciones informativas (30%) + Reporte ejecutivo en notas (20%)",
        "difficulty": "básico",
        "badge_name": "Analista Junior",
        "min_score_badge": 70,
    },
    {
        "title": "Perfilado de Malware con Pandas — AgentTesla & Emotet",
        "description": "Analiza el dataset de muestras de malware para crear perfiles de familias, extraer patrones de comportamiento y correlacionar indicadores de red.",
        "objective": "1) Agrupa muestras por familia de malware. 2) Extrae todas las IPs C2 y dominios únicos. 3) Mapea técnicas MITRE por familia. 4) Crea un heatmap de capabilities vs families. 5) Identifica patrones comunes de persistencia y evasión. 6) Calcula tamaño promedio por tipo de archivo.",
        "criteria": "Agrupación correcta (20%) + Extracción de IOCs (20%) + Heatmap MITRE (25%) + Insights de comportamiento (20%) + Código reproducible (15%)",
        "difficulty": "intermedio",
        "badge_name": "Analista de Amenazas",
        "min_score_badge": 80,
    },
]


def _seed_demo_datasets(conn) -> None:
    if conn.execute("SELECT COUNT(*) FROM datasets WHERE source LIKE 'CTI-Lab%'").fetchone()[0]:
        return
    for ds in _DATASETS:
        conn.execute(
            "INSERT INTO datasets (name, description, source, data_json, schema_json, created_by) VALUES (?,?,?,?,?,?)",
            (
                ds["name"], ds["description"], ds["source"],
                json.dumps(ds["data"], ensure_ascii=False),
                json.dumps(ds["schema"], ensure_ascii=False),
                "system@cti-lab",
            ),
        )


def _seed_demo_challenges(conn) -> None:
    if conn.execute("SELECT COUNT(*) FROM challenges WHERE created_by = 'system@cti-lab'").fetchone()[0]:
        return
    dataset_names = [r[0] for r in conn.execute("SELECT name FROM datasets WHERE source LIKE 'CTI-Lab%' ORDER BY id").fetchall()]
    for i, ch in enumerate(_CHALLENGE_SEEDS):
        dataset_id = None
        if i < len(dataset_names):
            row = conn.execute("SELECT id FROM datasets WHERE name = ?", (dataset_names[i],)).fetchone()
            if row:
                dataset_id = row[0]
        badge_row = conn.execute("SELECT id FROM badges WHERE name = ?", (ch["badge_name"],)).fetchone()
        badge_id = badge_row[0] if badge_row else None
        conn.execute(
            """INSERT INTO challenges
               (title, description, objective, dataset_id, criteria, status, badge_id, min_score_badge, difficulty, created_by)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (
                ch["title"], ch["description"], ch["objective"],
                dataset_id, ch["criteria"], "active",
                badge_id, ch["min_score_badge"], ch["difficulty"],
                "system@cti-lab",
            ),
        )


# ── Feed sources seed ─────────────────────────────────────────────────────────
# (name, category, url, feed_type, requires_auth, api_key_env, description, formats, group_label, status)
_FEED_SOURCES = [
    # ── IOC (10) ──────────────────────────────────────────────────────────────
    ("AlienVault OTX",     "IOC",       "https://otx.alienvault.com",                 "API",     1, "OTX_API_KEY",        "Plataforma colaborativa de IOCs — pulsos con IPs, dominios, hashes",             "JSON,STIX",       "Grupo IOC",       "needs_key"),
    ("ThreatFox",          "IOC",       "https://threatfox.abuse.ch",                 "API",     0, "",                   "IOCs de malware activo — gratis sin auth para consultas básicas",                 "JSON",            "Grupo IOC",       "active"),
    ("URLhaus",            "IOC",       "https://urlhaus.abuse.ch",                   "Feed",    0, "",                   "URLs maliciosas en tiempo real — feed público sin auth",                          "CSV,JSON",        "Grupo IOC",       "active"),
    ("AbuseIPDB",          "IOC",       "https://abuseipdb.com",                      "API",     1, "ABUSEIPDB_API_KEY",  "Reputación de IPs reportadas por abuso — requiere API key gratuita",             "JSON",            "Grupo IOC",       "needs_key"),
    ("OpenPhish",          "IOC",       "https://openphish.com",                      "Feed",    0, "",                   "Feed de URLs de phishing activas — público",                                      "TXT",             "Grupo IOC",       "active"),
    ("PhishTank",          "IOC",       "https://phishtank.org",                      "Feed",    1, "PHISHTANK_API_KEY",  "Base de datos colaborativa de phishing — API key gratuita",                      "JSON,CSV",        "Grupo IOC",       "needs_key"),
    ("FeodoTracker",       "IOC",       "https://feodotracker.abuse.ch",              "Feed",    0, "",                   "IPs C2 de botnets Feodo/Emotet/TrickBot — JSON público sin auth",                "JSON,CSV",        "Grupo IOC",       "active"),
    ("MISP Feeds",         "IOC",       "https://www.misp-project.org",               "TAXII",   1, "MISP_KEY",           "Plataforma de intercambio de inteligencia — instancia propia o feeds públicos",  "STIX,TAXII",      "Grupo IOC",       "needs_key"),
    ("IBM X-Force",        "IOC",       "https://exchange.xforce.ibmcloud.com",       "API",     1, "XFORCE_API_KEY",     "Inteligencia sobre amenazas y vulnerabilidades — API de pago/freemium",          "JSON",            "Grupo IOC",       "needs_key"),
    ("Pulsedive",          "IOC",       "https://pulsedive.com",                      "API",     1, "PULSEDIVE_API_KEY",  "Enriquecimiento de IOCs con contexto y scoring — plan gratuito disponible",      "JSON",            "Grupo IOC",       "needs_key"),
    # ── IoA (5) ───────────────────────────────────────────────────────────────
    ("MITRE ATT&CK",       "IoA",       "https://attack.mitre.org",                   "API",     0, "",                   "Framework de TTPs adversarias — API REST pública con datos STIX",                "STIX,JSON",       "Grupo IoA",       "active"),
    ("ATTACKCTI",          "IoA",       "https://github.com/OTRF/ATTACK-Python-Client","Dataset", 0, "",                   "Cliente Python para ATT&CK en STIX — librería open source",                      "STIX,Python",     "Grupo IoA",       "active"),
    ("MITRE D3FEND",       "IoA",       "https://d3fend.mitre.org",                   "API",     0, "",                   "Ontología de contramedidas de ciberseguridad — mapeadas a ATT&CK",               "JSON,OWL",        "Grupo IoA",       "active"),
    ("Atomic Red Team",    "IoA",       "https://github.com/redcanaryco/atomic-red-team","Dataset",0,"",                   "Tests de simulación de ataques basados en ATT&CK — YAML/PowerShell",            "YAML,JSON",       "Grupo IoA",       "active"),
    ("SigmaHQ",            "IoA",       "https://github.com/SigmaHQ/sigma",            "Dataset", 0, "",                   "Reglas de detección SIEM en formato Sigma — más de 3000 reglas",                 "YAML,JSON",       "Grupo IoA",       "active"),
    # ── Botnet (4) ────────────────────────────────────────────────────────────
    ("CTU-13 Dataset",     "Botnet",    "https://www.stratosphereips.org/datasets-ctu13","Dataset",0,"",                   "Tráfico de red con botnets reales capturado por CTU Prague — 13 escenarios",    "PCAP,CSV,Binetflow","Grupo Botnet",  "active"),
    ("Bot-IoT Dataset",    "Botnet",    "https://research.unsw.edu.au/projects/bot-iot-dataset","Dataset",0,"",            "Tráfico botnet en dispositivos IoT — dataset UNSW Sydney",                       "CSV,PCAP",        "Grupo Botnet",    "active"),
    ("Feodo Tracker C2",   "Botnet",    "https://feodotracker.abuse.ch",              "Feed",    0, "",                   "IPs C2 de botnets activas (Emotet, TrickBot, Dridex) — JSON en tiempo real",    "JSON,CSV",        "Grupo Botnet",    "active"),
    ("Stratosphere IPS",   "Botnet",    "https://www.stratosphereips.org",            "Dataset", 0, "",                   "Capturas de tráfico de malware y botnet del laboratorio Stratosphere",           "PCAP,Binetflow",  "Grupo Botnet",    "active"),
    # ── Ransomware (10) ───────────────────────────────────────────────────────
    ("Ransomware.live",    "Ransomware","https://ransomware.live",                    "API",     0, "",                   "Víctimas de ransomware en tiempo real — API pública con grupos activos",          "JSON",            "Grupo Ransomware","active"),
    ("MalwareBazaar",      "Ransomware","https://bazaar.abuse.ch",                   "API",     0, "",                   "Repositorio de muestras de malware con hashes y metadata — público",             "JSON,CSV",        "Grupo Ransomware","active"),
    ("Malpedia",           "Ransomware","https://malpedia.caad.fkie.fraunhofer.de",  "API",     1, "MALPEDIA_API_KEY",   "Base de conocimiento de familias de malware — API con auth gratuita",            "JSON",            "Grupo Ransomware","needs_key"),
    ("ThreatFox (Ransom)", "Ransomware","https://threatfox.abuse.ch",                "API",     0, "",                   "IOCs específicos de ransomware — mismo endpoint que ThreatFox IOC",              "JSON",            "Grupo Ransomware","active"),
    ("VX Underground",     "Ransomware","https://vx-underground.org",                "Dataset", 0, "",                   "Colección de muestras de malware — acceso manual/torrent",                       "EXE,ZIP",         "Grupo Ransomware","manual"),
    ("ID Ransomware",      "Ransomware","https://id-ransomware.malwarehunterteam.com","API",     0, "",                   "Identificación de familias por nota de rescate o sample — web API",             "JSON",            "Grupo Ransomware","active"),
    ("NoMoreRansom",       "Ransomware","https://www.nomoreransom.org",              "Dataset", 0, "",                   "Decryptors y familias de ransomware — base de conocimiento pública",             "JSON",            "Grupo Ransomware","active"),
    ("VirusTotal",         "Ransomware","https://virustotal.com",                    "API",     1, "VIRUSTOTAL_API_KEY", "Análisis de muestras de ransomware — ya integrado en la plataforma",            "JSON",            "Grupo Ransomware","needs_key"),
    ("Ransomware Tracker", "Ransomware","https://github.com/fwhibbit/Ransomware-Tracker","Dataset",0,"",                  "Histórico de campañas de ransomware — datos en CSV/JSON",                       "CSV,JSON",        "Grupo Ransomware","active"),
    ("YARAify",            "Ransomware","https://yaraify.abuse.ch",                  "API",     0, "",                   "Escaneo de muestras con reglas YARA públicas — abuse.ch",                        "JSON",            "Grupo Ransomware","active"),
    # ── Malware (5) ───────────────────────────────────────────────────────────
    ("MalwareBazaar (M)",  "Malware",   "https://bazaar.abuse.ch",                   "API",     0, "",                   "Muestras de malware con metadata — ya integrado via MISP engine",                "JSON,CSV",        "Grupo Malware",   "active"),
    ("Malpedia (M)",       "Malware",   "https://malpedia.caad.fkie.fraunhofer.de",  "API",     1, "MALPEDIA_API_KEY",   "Familias de malware con análisis técnico — API gratuita con registro",           "JSON",            "Grupo Malware",   "needs_key"),
    ("VirusShare",         "Malware",   "https://virusshare.com",                    "Dataset", 1, "",                   "Colección de muestras de malware — requiere cuenta para acceso",                 "ZIP,Hash",        "Grupo Malware",   "manual"),
    ("VX Underground (M)", "Malware",   "https://vx-underground.org",                "Dataset", 0, "",                   "Colección masiva de malware + papers de investigación",                          "EXE,ZIP,PDF",     "Grupo Malware",   "manual"),
    ("TheZoo",             "Malware",   "https://github.com/ytisf/theZoo",            "Dataset", 0, "",                   "Repositorio de malware live en GitHub — solo entorno seguro/aislado",           "ZIP,EXE",         "Grupo Malware",   "manual"),
]


def _seed_feed_sources(conn) -> None:
    if conn.execute("SELECT COUNT(*) FROM feed_sources").fetchone()[0]:
        return
    conn.executemany(
        """INSERT INTO feed_sources
           (name, category, url, feed_type, requires_auth, api_key_env, description, formats, group_label, status)
           VALUES (?,?,?,?,?,?,?,?,?,?)""",
        _FEED_SOURCES,
    )


# ── Group datasets (IoA, Botnet, Ransomware) ───────────────────────────────────

_GROUP_DATASETS = [
    {
        "name": "MITRE ATT&CK — TTPs por Grupo APT",
        "description": "Técnicas y tácticas adversarias (TTPs) de 12 grupos APT mapeadas a MITRE ATT&CK v14. Datos derivados de ATT&CK STIX para análisis de comportamiento adversario.",
        "source": "CTI-Lab / MITRE ATT&CK v14",
        "schema": {"group": "str", "group_id": "str", "technique": "str", "technique_id": "str", "tactic": "str", "platform": "str", "data_source": "str", "mitigations": "str", "detection": "str"},
        "data": [
            {"group": "APT28", "group_id": "G0007", "technique": "Spearphishing Attachment", "technique_id": "T1566.001", "tactic": "Initial Access", "platform": "Windows,Linux", "data_source": "Email,Network", "mitigations": "M1049,M1031", "detection": "Monitor email attachments with macro content"},
            {"group": "APT28", "group_id": "G0007", "technique": "LSASS Memory", "technique_id": "T1003.001", "tactic": "Credential Access", "platform": "Windows", "data_source": "Process,Windows Event Logs", "mitigations": "M1043,M1028", "detection": "Monitor access to lsass.exe process"},
            {"group": "APT28", "group_id": "G0007", "technique": "Scheduled Task", "technique_id": "T1053.005", "tactic": "Persistence", "platform": "Windows", "data_source": "Scheduled Job,Process", "mitigations": "M1026", "detection": "Monitor schtasks.exe execution"},
            {"group": "APT29", "group_id": "G0016", "technique": "Domain Fronting", "technique_id": "T1090.004", "tactic": "Command and Control", "platform": "Windows,Linux,macOS", "data_source": "Network Traffic", "mitigations": "M1020", "detection": "Inspect TLS SNI vs Host header mismatch"},
            {"group": "APT29", "group_id": "G0016", "technique": "Valid Accounts", "technique_id": "T1078", "tactic": "Defense Evasion", "platform": "Windows,Cloud,SaaS", "data_source": "Authentication,User Account", "mitigations": "M1036,M1032", "detection": "Monitor for anomalous account usage"},
            {"group": "Lazarus", "group_id": "G0032", "technique": "Supply Chain Compromise", "technique_id": "T1195.002", "tactic": "Initial Access", "platform": "Windows,Linux,macOS", "data_source": "File,Network", "mitigations": "M1051,M1016", "detection": "Hash verification of software packages"},
            {"group": "Lazarus", "group_id": "G0032", "technique": "Remote Service Session Hijacking", "technique_id": "T1563", "tactic": "Lateral Movement", "platform": "Windows,Linux", "data_source": "Network,Logon Session", "mitigations": "M1026,M1018", "detection": "Monitor for unusual SSH/RDP sessions"},
            {"group": "FIN7",   "group_id": "G0046", "technique": "Spearphishing Link", "technique_id": "T1566.002", "tactic": "Initial Access", "platform": "Windows", "data_source": "Email,Network,File", "mitigations": "M1049,M1031", "detection": "URL sandboxing, user training"},
            {"group": "FIN7",   "group_id": "G0046", "technique": "Mshta", "technique_id": "T1218.005", "tactic": "Defense Evasion", "platform": "Windows", "data_source": "Process,Command", "mitigations": "M1038", "detection": "Monitor mshta.exe with network connections"},
            {"group": "LockBit","group_id": "G1006", "technique": "Inhibit System Recovery", "technique_id": "T1490", "tactic": "Impact", "platform": "Windows,Linux", "data_source": "Process,Command,Windows Registry", "mitigations": "M1053", "detection": "Monitor vssadmin delete shadows"},
            {"group": "LockBit","group_id": "G1006", "technique": "Data Encrypted for Impact", "technique_id": "T1486", "tactic": "Impact", "platform": "Windows,Linux,macOS", "data_source": "File,Process", "mitigations": "M1053,M1040", "detection": "Bulk file modification with new extensions"},
            {"group": "BlackCat","group_id": "G1013","technique": "Exfiltration Over Web Service","technique_id": "T1567","tactic": "Exfiltration", "platform": "Windows,Linux", "data_source": "Network,File", "mitigations": "M1021,M1057", "detection": "Large data transfers to cloud storage"},
            {"group": "Turla",  "group_id": "G0010", "technique": "Rootkit", "technique_id": "T1014", "tactic": "Defense Evasion", "platform": "Windows,Linux", "data_source": "Drive,Firmware", "mitigations": "M1046", "detection": "Unexpected kernel module loading"},
            {"group": "Turla",  "group_id": "G0010", "technique": "DNS Communication", "technique_id": "T1071.004", "tactic": "Command and Control", "platform": "Windows,Linux", "data_source": "Network,DNS", "mitigations": "M1037", "detection": "High volume DNS TXT record queries"},
            {"group": "Emotet", "group_id": "G0080", "technique": "Malicious File", "technique_id": "T1204.002", "tactic": "Execution", "platform": "Windows", "data_source": "File,Process,Email", "mitigations": "M1049,M1038", "detection": "Word documents with suspicious macro code"},
        ],
    },
    {
        "name": "Botnet Traffic — CTU-13 Network Flows",
        "description": "Flujos de red de 8 escenarios del dataset CTU-13 (Stratosphere IPS). Contiene tráfico benigno, botnet Neris, Rbot y Virut con etiquetas de clasificación.",
        "source": "CTI-Lab / CTU-13 Dataset (Stratosphere IPS)",
        "schema": {"timestamp": "str", "duration": "float", "src_ip": "str", "src_port": "int", "dst_ip": "str", "dst_port": "int", "protocol": "str", "flags": "str", "packets": "int", "bytes": "int", "label": "str", "botnet": "str"},
        "data": [
            {"timestamp": "2011-08-10 09:46:53", "duration": 0.002, "src_ip": "147.32.84.165", "src_port": 1432, "dst_ip": "147.32.80.9",  "dst_port": 53,    "protocol": "UDP",  "flags": "", "packets": 1, "bytes": 82,    "label": "Botnet", "botnet": "Neris"},
            {"timestamp": "2011-08-10 09:46:54", "duration": 0.005, "src_ip": "147.32.84.165", "src_port": 2049, "dst_ip": "87.98.250.107","dst_port": 6667,  "protocol": "TCP",  "flags": "S", "packets": 3, "bytes": 180,   "label": "Botnet", "botnet": "Neris"},
            {"timestamp": "2011-08-10 09:47:01", "duration": 120.3, "src_ip": "147.32.84.165", "src_port": 2050, "dst_ip": "87.98.250.107","dst_port": 6667,  "protocol": "TCP",  "flags": "FA","packets": 142,"bytes": 48300, "label": "Botnet", "botnet": "Neris"},
            {"timestamp": "2011-08-10 09:47:10", "duration": 0.001, "src_ip": "147.32.84.165", "src_port": 1050, "dst_ip": "147.32.80.9",  "dst_port": 53,    "protocol": "UDP",  "flags": "", "packets": 1, "bytes": 78,    "label": "Botnet", "botnet": "Neris"},
            {"timestamp": "2011-08-10 09:48:00", "duration": 0.003, "src_ip": "147.32.84.168", "src_port": 4501, "dst_ip": "195.54.162.205","dst_port": 443,  "protocol": "TCP",  "flags": "S", "packets": 2, "bytes": 120,   "label": "Botnet", "botnet": "Rbot"},
            {"timestamp": "2011-08-10 09:48:05", "duration": 45.2,  "src_ip": "147.32.84.168", "src_port": 4502, "dst_ip": "195.54.162.205","dst_port": 443,  "protocol": "TCP",  "flags": "FA","packets": 63, "bytes": 32100, "label": "Botnet", "botnet": "Rbot"},
            {"timestamp": "2011-08-10 09:49:00", "duration": 0.002, "src_ip": "147.32.84.170", "src_port": 80,   "dst_ip": "147.32.80.230","dst_port": 1032,  "protocol": "TCP",  "flags": "S", "packets": 1, "bytes": 64,    "label": "Botnet", "botnet": "Virut"},
            {"timestamp": "2011-08-10 09:49:02", "duration": 30.1,  "src_ip": "147.32.84.170", "src_port": 80,   "dst_ip": "147.32.80.230","dst_port": 1032,  "protocol": "TCP",  "flags": "FA","packets": 88, "bytes": 44000, "label": "Botnet", "botnet": "Virut"},
            {"timestamp": "2011-08-10 09:50:00", "duration": 0.5,   "src_ip": "147.32.84.50",  "src_port": 1234, "dst_ip": "8.8.8.8",      "dst_port": 53,    "protocol": "UDP",  "flags": "", "packets": 2, "bytes": 160,   "label": "Benign", "botnet": ""},
            {"timestamp": "2011-08-10 09:50:05", "duration": 1.2,   "src_ip": "147.32.84.50",  "src_port": 49201,"dst_ip": "93.184.216.34","dst_port": 80,    "protocol": "TCP",  "flags": "FA","packets": 12, "bytes": 8200,  "label": "Benign", "botnet": ""},
            {"timestamp": "2011-08-10 09:51:00", "duration": 0.001, "src_ip": "147.32.84.171", "src_port": 3232, "dst_ip": "77.75.78.95",  "dst_port": 80,    "protocol": "TCP",  "flags": "S", "packets": 1, "bytes": 64,    "label": "Botnet", "botnet": "Neris"},
            {"timestamp": "2011-08-10 09:51:01", "duration": 600.0, "src_ip": "147.32.84.171", "src_port": 3233, "dst_ip": "77.75.78.95",  "dst_port": 80,    "protocol": "TCP",  "flags": "FA","packets": 820,"bytes": 420000,"label": "Botnet", "botnet": "Neris"},
            {"timestamp": "2011-08-10 09:52:00", "duration": 0.9,   "src_ip": "147.32.84.55",  "src_port": 49300,"dst_ip": "172.217.16.46","dst_port": 443,   "protocol": "TCP",  "flags": "FA","packets": 18, "bytes": 14000, "label": "Benign", "botnet": ""},
            {"timestamp": "2011-08-10 09:53:00", "duration": 0.001, "src_ip": "147.32.84.172", "src_port": 5544, "dst_ip": "193.109.69.72","dst_port": 4444,  "protocol": "TCP",  "flags": "S", "packets": 1, "bytes": 60,    "label": "Botnet", "botnet": "Rbot"},
            {"timestamp": "2011-08-10 09:53:02", "duration": 180.5, "src_ip": "147.32.84.172", "src_port": 5545, "dst_ip": "193.109.69.72","dst_port": 4444,  "protocol": "TCP",  "flags": "FA","packets": 240,"bytes": 95000, "label": "Botnet", "botnet": "Rbot"},
        ],
    },
    {
        "name": "Ransomware.live — Víctimas y Grupos Activos",
        "description": "Datos de víctimas publicadas por grupos de ransomware en sus sitios de leak. Incluye grupo, sector, país, fecha y descripción. Fuente: Ransomware.live API.",
        "source": "CTI-Lab / Ransomware.live API",
        "schema": {"victim": "str", "group": "str", "sector": "str", "country": "str", "published": "str", "description": "str", "employees": "str", "revenue": "str", "url_leak": "str", "ransom_usd": "int"},
        "data": [
            {"victim": "MedCare Solutions",      "group": "LockBit 3.0",  "sector": "Healthcare",       "country": "US",  "published": "2024-03-01", "description": "Hospital network — 180K patient records exfiltrated", "employees": "2,400",  "revenue": "$320M", "url_leak": "lockbit3xyz.onion/medcare",     "ransom_usd": 500000},
            {"victim": "ConstructBuild SA",      "group": "BlackCat",     "sector": "Construction",     "country": "ES",  "published": "2024-03-03", "description": "Engineering firm — CAD files and contracts stolen",   "employees": "850",    "revenue": "$95M",  "url_leak": "alphvmmm.onion/constructbuild", "ransom_usd": 200000},
            {"victim": "LegalPartners LLP",      "group": "Cl0p",         "sector": "Legal",            "country": "UK",  "published": "2024-03-05", "description": "Law firm — client case files and M&A documents",      "employees": "320",    "revenue": "$45M",  "url_leak": "clop2xtgu.onion/legalpartners", "ransom_usd": 350000},
            {"victim": "AutoManufacturer GmbH",  "group": "Play",         "sector": "Manufacturing",    "country": "DE",  "published": "2024-03-07", "description": "Auto parts manufacturer — production plans exfil",   "employees": "4,100",  "revenue": "$780M", "url_leak": "paymenthacks.onion/automanuf",  "ransom_usd": 1200000},
            {"victim": "FinGroup Bank",          "group": "LockBit 3.0",  "sector": "Finance",          "country": "MX",  "published": "2024-03-09", "description": "Regional bank — transaction records and PII",         "employees": "1,200",  "revenue": "$2.1B", "url_leak": "lockbit3xyz.onion/fingroup",    "ransom_usd": 800000},
            {"victim": "EduTech University",     "group": "Akira",        "sector": "Education",        "country": "AU",  "published": "2024-03-11", "description": "University — student records and research data",      "employees": "6,500",  "revenue": "$180M", "url_leak": "akira2.onion/edutech",          "ransom_usd": 150000},
            {"victim": "LogiChain Corp",         "group": "BlackCat",     "sector": "Transportation",   "country": "US",  "published": "2024-03-12", "description": "Logistics company — route and cargo manifests",       "employees": "9,800",  "revenue": "$1.4B", "url_leak": "alphvmmm.onion/logichain",      "ransom_usd": 2000000},
            {"victim": "MunicipalGov City X",    "group": "Medusa",       "sector": "Government",       "country": "BR",  "published": "2024-03-14", "description": "City government — citizen data and financial records","employees": "3,200",  "revenue": "N/A",   "url_leak": "medusaxxx.onion/municgov",      "ransom_usd": 300000},
            {"victim": "PharmaDistrib Inc",      "group": "Cl0p",         "sector": "Pharmaceutical",   "country": "CA",  "published": "2024-03-15", "description": "Pharma distributor — drug supply chain data",         "employees": "1,800",  "revenue": "$890M", "url_leak": "clop2xtgu.onion/pharmadistrib", "ransom_usd": 600000},
            {"victim": "EnergyGrid SA",          "group": "Trigona",      "sector": "Energy",           "country": "FR",  "published": "2024-03-16", "description": "Energy provider — SCADA config and employee data",    "employees": "5,400",  "revenue": "$3.2B", "url_leak": "trigona.onion/energygrid",      "ransom_usd": 4000000},
            {"victim": "RetailChain Group",      "group": "Akira",        "sector": "Retail",           "country": "AR",  "published": "2024-03-18", "description": "Retail group — POS data and customer PII",           "employees": "12,000", "revenue": "$620M", "url_leak": "akira2.onion/retailchain",      "ransom_usd": 250000},
            {"victim": "TechStartup Ventures",   "group": "LockBit 3.0",  "sector": "Technology",       "country": "SG",  "published": "2024-03-20", "description": "VC-backed startup — source code and investor data",  "employees": "280",    "revenue": "$28M",  "url_leak": "lockbit3xyz.onion/techstartup", "ransom_usd": 180000},
        ],
    },
]


def _seed_group_datasets(conn) -> None:
    if conn.execute("SELECT COUNT(*) FROM datasets WHERE source LIKE 'CTI-Lab / MITRE%' OR source LIKE 'CTI-Lab / CTU%' OR source LIKE 'CTI-Lab / Ransomware%'").fetchone()[0]:
        return
    for ds in _GROUP_DATASETS:
        conn.execute(
            "INSERT INTO datasets (name, description, source, data_json, schema_json, created_by) VALUES (?,?,?,?,?,?)",
            (
                ds["name"], ds["description"], ds["source"],
                json.dumps(ds["data"], ensure_ascii=False),
                json.dumps(ds["schema"], ensure_ascii=False),
                "system@cti-lab",
            ),
        )


# ── Group challenges seed ──────────────────────────────────────────────────────

_GROUP_CHALLENGES = [
    {
        "title": "Grupo Malware — Perfilado Avanzado de Familias",
        "description": "Usando el dataset de muestras de malware (AgentTesla, Emotet, Cobalt Strike), construye un sistema de perfilado automático que clasifique muestras desconocidas por familia basándose en sus comportamientos y metadatos.\n\nFuentes de referencia: MalwareBazaar · Malpedia · VX Underground · VirusShare · TheZoo",
        "objective": "1) Carga y limpia el dataset de malware. 2) Crea features basados en TTPs (capabilities, evasion, persistence). 3) Entrena un clasificador para identificar la familia. 4) Extrae reglas YARA conceptuales basadas en strings/hashes. 5) Visualiza similitudes entre familias con clustering. 6) Entrega: dataset original + script de ingestión + mapa de TTPs + visualización.",
        "criteria": "Clasificador funcional (30%) + Feature engineering de TTPs (25%) + Visualizaciones (20%) + Reporte técnico 2-3 páginas (25%)",
        "difficulty": "avanzado",
        "badge_name": "ML Practitioner",
        "min_score_badge": 75,
        "dataset_name": "Análisis Malware — AgentTesla & Emotet",
    },
    {
        "title": "Grupo IOC — Inteligencia y Enriquecimiento de Feeds",
        "description": "Integra y enriquece datos de 3 fuentes IOC distintas: ThreatFox (IOCs activos), FeodoTracker (C2 botnets) y URLhaus (URLs maliciosas). Construye un pipeline de enriquecimiento con deduplicación, scoring y correlación cruzada.\n\nFuentes: OTX · ThreatFox · URLhaus · AbuseIPDB · OpenPhish · PhishTank · FeodoTracker · MISP · IBM X-Force · Pulsedive",
        "objective": "1) Carga datos del feed IOC enriquecido del CTI-Lab. 2) Normaliza tipos de IOC (IP/domain/hash/URL). 3) Crea score de riesgo combinando severity + confidence + sources. 4) Detecta IOCs compartidos entre múltiples threat actors. 5) Visualiza red de correlaciones IOC↔Threat Actor. 6) Genera reporte ejecutivo priorizando los 10 IOCs más críticos.",
        "criteria": "Pipeline de normalización (20%) + Score de riesgo (25%) + Correlación cruzada (20%) + Red de relaciones (20%) + Reporte ejecutivo (15%)",
        "difficulty": "intermedio",
        "badge_name": "Threat Hunter",
        "min_score_badge": 70,
        "dataset_name": "Feed IOC Enriquecido — CTI-Lab",
    },
    {
        "title": "Grupo IoA — Mapeo de TTPs y Detección de Comportamiento",
        "description": "Analiza el dataset de TTPs de grupos APT (MITRE ATT&CK v14). Identifica patrones de comportamiento, construye mapas de calor de tácticas y propone reglas de detección en formato Sigma.\n\nFuentes: MITRE ATT&CK · ATTACKCTI · D3FEND · Atomic Red Team · SigmaHQ",
        "objective": "1) Carga el dataset ATT&CK y agrupa por táctica y técnica. 2) Identifica los grupos APT con más overlap de TTPs. 3) Crea heatmap de técnicas por táctica ATT&CK. 4) Propone 3 reglas de detección conceptuales en formato Sigma. 5) Mapea las TTPs del dataset a contramedidas D3FEND. 6) Identifica qué grupo APT es más difícil de detectar y por qué.",
        "criteria": "Agrupación y análisis (25%) + Heatmap de TTPs (25%) + Reglas Sigma (25%) + Análisis de detectabilidad (25%)",
        "difficulty": "avanzado",
        "badge_name": "SOC Analyst",
        "min_score_badge": 80,
        "dataset_name": "MITRE ATT&CK — TTPs por Grupo APT",
    },
    {
        "title": "Grupo Botnet — Clasificación de Tráfico de Red",
        "description": "Usando los flujos de red del dataset CTU-13 (Stratosphere IPS), construye un clasificador para distinguir tráfico benigno de botnet. Identifica las botnets presentes (Neris, Rbot, Virut) por sus patrones de comunicación.\n\nFuentes: CTU-13 Dataset · Bot-IoT · Feodo Tracker · Stratosphere IPS",
        "objective": "1) Explora la distribución benigno vs botnet en el dataset. 2) Crea features de red: bytes/pkt ratio, duración, puertos destino, protocolos. 3) Entrena un clasificador (Random Forest o Decision Tree). 4) Evalúa con métricas: precision, recall, F1 por clase. 5) Visualiza patrones de comportamiento por botnet. 6) Identifica las características más discriminantes entre Neris, Rbot y Virut.",
        "criteria": "Feature engineering de red (25%) + Clasificador con F1 ≥ 0.80 (30%) + Análisis por familia (25%) + Visualizaciones (20%)",
        "difficulty": "avanzado",
        "badge_name": "Analista de Amenazas",
        "min_score_badge": 80,
        "dataset_name": "Botnet Traffic — CTU-13 Network Flows",
    },
    {
        "title": "Grupo Ransomware — Inteligencia de Amenazas y Análisis de Campañas",
        "description": "Analiza el dataset de víctimas de ransomware (Ransomware.live) para identificar tendencias, grupos más activos y sectores más afectados. Combina con IOCs de LockBit del dataset de campaña.\n\nFuentes: Ransomware.live · MalwareBazaar · Malpedia · ThreatFox · VX Underground · ID Ransomware · NoMoreRansom · VirusTotal · Ransomware Tracker · YARAify",
        "objective": "1) Analiza distribución de víctimas por grupo, sector y país. 2) Identifica el grupo más activo y sus sectores favoritos. 3) Correlaciona grupos de ransomware con TTPs de la campaña LockBit 3.0. 4) Estima el impacto económico total del dataset. 5) Crea gráfica de línea temporal de ataques. 6) Recomienda los 3 controles de seguridad más efectivos basado en los TTPs identificados.",
        "criteria": "Análisis estadístico (25%) + Correlación con TTPs (25%) + Visualizaciones (25%) + Recomendaciones de mitigación (25%)",
        "difficulty": "intermedio",
        "badge_name": "SOC Analyst",
        "min_score_badge": 75,
        "dataset_name": "Ransomware.live — Víctimas y Grupos Activos",
    },
]


def _seed_group_challenges(conn) -> None:
    if conn.execute("SELECT COUNT(*) FROM challenges WHERE created_by = 'system@cti-lab-groups'").fetchone()[0]:
        return
    for ch in _GROUP_CHALLENGES:
        ds_row = conn.execute("SELECT id FROM datasets WHERE name = ?", (ch["dataset_name"],)).fetchone()
        dataset_id = ds_row[0] if ds_row else None
        badge_row = conn.execute("SELECT id FROM badges WHERE name = ?", (ch["badge_name"],)).fetchone()
        badge_id = badge_row[0] if badge_row else None
        conn.execute(
            """INSERT INTO challenges
               (title, description, objective, dataset_id, criteria, status, badge_id, min_score_badge, difficulty, created_by)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (
                ch["title"], ch["description"], ch["objective"],
                dataset_id, ch["criteria"], "active",
                badge_id, ch["min_score_badge"], ch["difficulty"],
                "system@cti-lab-groups",
            ),
        )


# ── CTF Challenges Día 1 & Día 2 ──────────────────────────────────────────────
# Each entry: (order_idx, phase_name, title, description, flag, flag_format,
#              hints_json, category, difficulty, points, docker_image, docker_port,
#              tools_json, roles_json, dataset_name_or_None, is_team)

_CTF_CHALLENGES = [
    # ── DÍA 1 — Fundamentos CTI (13 retos) ───────────────────────────────────
    (1,  "Día 1", "Bienvenido al Lab",
     "El servidor CTI-Lab tiene una bandera oculta. Accede al servicio en el puerto 80 y búscala en el código fuente o en /robots.txt.",
     "CTI{bienvenido_al_lab_2024}",
     "CTI{...}",
     json.dumps(["Visita http://localhost con tu navegador", "Revisa el código fuente (Ctrl+U)", "Busca el archivo /robots.txt"]),
     "Intro", "fácil", 50,
     "ctinexus/intro:latest", "80",
     json.dumps(["Browser", "curl"]),
     json.dumps(["Todos"]),
     None, 0),

    (2,  "Día 1", "Reputación de IP",
     "La IP `185.220.101.47` fue detectada en los logs. Usa el módulo de Enriquecimiento de IOCs de la plataforma para obtener: país de origen, severidad y threat actor. Construye la bandera.",
     "CTI{RU_CRITICAL_APT28}",
     "CTI{PAÍS_SEVERIDAD_ACTOR}",
     json.dumps(["Usa /enrich/185.220.101.47 en la plataforma", "La IP tiene severidad máxima", "Formato: país(2 letras)_severidad(en mayúsculas)_actor(sin espacios)"]),
     "IOC", "fácil", 75,
     "ctinexus/ioc-hunter:latest", "8080",
     json.dumps(["CTI-Lab IOC Enrichment", "curl", "Python"]),
     json.dumps(["Ciberseguridad", "Analista de Datos"]),
     "Feed IOC Enriquecido — CTI-Lab", 0),

    (3,  "Día 1", "Hash de Malware",
     "Se encontró un archivo con hash SHA256 `e3b0c44298fc1c149afbf4c8`. Búscalo en el dataset de análisis de malware del lab. Construye la bandera con: familia_tipo_primera_capacidad.",
     "CTI{AgentTesla_stealer_keylogger}",
     "CTI{familia_tipo_capacidad}",
     json.dumps(["Carga el dataset de malware con pandas", "Filtra por la columna md5 o sha256", "Usa las columnas 'family', 'type', 'capability'"]),
     "Malware", "fácil", 75,
     "ctinexus/malware-lab:latest", "8888",
     json.dumps(["Python", "pandas", "Jupyter"]),
     json.dumps(["Ciberseguridad", "Analista de Datos"]),
     "Análisis Malware — AgentTesla & Emotet", 0),

    (4,  "Día 1", "Dominio Sospechoso",
     "El dominio `update-microsoft-cdn.com` está en el feed IOC del lab. Analiza quién lo registró, qué técnica usa y el grupo amenaza detrás. Bandera: actor_país_técnica_abreviada.",
     "CTI{Lazarus_KP_watering-hole}",
     "CTI{actor_país_técnica}",
     json.dumps(["Carga el IOC feed con pandas", "Filtra por la columna ioc == 'update-microsoft-cdn.com'", "Usa las columnas threat_actor, country, technique"]),
     "OSINT", "fácil", 100,
     "ctinexus/osint-box:latest", "80",
     json.dumps(["Python", "pandas", "CTI-Lab IOC Feed"]),
     json.dumps(["Analista de Datos", "Ciberseguridad"]),
     "Feed IOC Enriquecido — CTI-Lab", 0),

    (5,  "Día 1", "Logs de Red — Exfiltración",
     "Analiza los logs de red del dataset APT28. Calcula el total de bytes exfiltrados hacia IPs externas (country != 'LAN'). La bandera es ese número.",
     "CTI{1536000_bytes_exfil}",
     "CTI{número_bytes_exfil}",
     json.dumps(["Filtra por country != 'LAN' y action == 'ALLOW'", "Suma la columna 'bytes'", "El número exacto (sin puntos) es la bandera"]),
     "Network", "fácil", 100,
     "ctinexus/network-logs:latest", "8888",
     json.dumps(["Python", "pandas", "Jupyter"]),
     json.dumps(["Analista de Datos", "Ciencia de Datos"]),
     "Logs de Red — APT28 Fancy Bear", 0),

    (6,  "Día 1", "Decodificación Base64",
     "En los logs del servidor encontramos este payload: `Q1RJe2Jhc2U2NF9wb3dlcnNoZWxsX2V2YXNpb259`. Decodifícalo en Python para obtener la bandera directamente.",
     "CTI{base64_powershell_evasion}",
     "CTI{...}",
     json.dumps(["Importa la librería base64 en Python", "Usa base64.b64decode('payload').decode()", "El resultado ya es la bandera"]),
     "Crypto", "fácil", 100,
     "ctinexus/crypto-lab:latest", "80",
     json.dumps(["Python", "base64", "terminal"]),
     json.dumps(["Ciberseguridad"]),
     None, 0),

    (7,  "Día 1", "Primera Técnica ATT&CK",
     "LockBit 3.0 eliminó los backups antes de cifrar. Busca en el dataset de campaña la técnica MITRE usada en la fase 'Impact' con la herramienta vssadmin. Bandera: ID_actor_táctica_herramienta.",
     "CTI{T1490_LockBit_Impact_vssadmin}",
     "CTI{TID_actor_táctica_herramienta}",
     json.dumps(["Filtra el dataset LockBit por phase='Impact'", "Busca el campo details que menciona vssadmin", "El ID de técnica está en la columna 'mitre'"]),
     "ATT&CK", "medio", 125,
     "ctinexus/attck-mapper:latest", "8080",
     json.dumps(["Python", "pandas", "dataset LockBit"]),
     json.dumps(["Ciberseguridad", "Analista de Datos"]),
     "Campaña Ransomware — LockBit 3.0", 0),

    (8,  "Día 1", "Pandas IOC Hunt",
     "Usa pandas para cargar el Feed IOC del lab. ¿Cuántos IOCs tienen severity='critical' Y confidence>=90? La bandera incluye ese número.",
     "CTI{4_critical_iocs_high_confidence}",
     "CTI{número_critical_iocs_high_confidence}",
     json.dumps(["df = pd.DataFrame(data) donde data son los registros del IOC feed", "Filtra: df[(df['severity']=='critical') & (df['confidence']>=90)]", "Cuenta las filas con len() o .shape[0]"]),
     "Data", "medio", 125,
     "ctinexus/pandas-lab:latest", "8888",
     json.dumps(["Python", "pandas", "Jupyter"]),
     json.dumps(["Ciencia de Datos", "Analista de Datos"]),
     "Feed IOC Enriquecido — CTI-Lab", 0),

    (9,  "Día 1", "Phishing — Header Analysis",
     "El servidor de email tiene cabeceras sospechosas almacenadas en el dataset de phishing. Busca el dominio con threat_actor='APT29' que usa technique='Lookalike domain'. Bandera: dominio_técnica.",
     "CTI{office365-auth.xyz_lookalike}",
     "CTI{dominio_técnica_resumida}",
     json.dumps(["Filtra el dataset phishing por threat_actor='APT29'", "Busca la técnica 'Lookalike domain'", "Formato: dominio_técnica(sin espacios, en minúsculas)"]),
     "OSINT", "medio", 125,
     "ctinexus/email-forensics:latest", "80",
     json.dumps(["Python", "pandas", "dataset phishing"]),
     json.dumps(["Ciberseguridad"]),
     "Campaña Phishing — Credential Harvesting FIN7", 0),

    (10, "Día 1", "Perfil de Threat Actor",
     "Analiza el IOC feed para determinar qué threat actor tiene el mayor número de IOCs en total. La bandera incluye el actor y su conteo total.",
     "CTI{APT28_top_actor_4_iocs}",
     "CTI{actor_top_actor_count_iocs}",
     json.dumps(["Agrupa el dataset IOC por threat_actor", "Usa .value_counts() o groupby().count()", "El actor con más IOCs gana"]),
     "OSINT", "medio", 150,
     "ctinexus/ta-profiler:latest", "8080",
     json.dumps(["Python", "pandas", "IOC feed"]),
     json.dumps(["Analista de Datos", "Ciberseguridad"]),
     "Feed IOC Enriquecido — CTI-Lab", 0),

    (11, "Día 1", "Visualización de Amenazas",
     "Crea un gráfico de barras con matplotlib mostrando la distribución de técnicas MITRE en el dataset APT28. ¿Cuántas técnicas únicas aparecen? La bandera incluye ese número.",
     "CTI{distribucion_mitre_apt28_7_tecnicas}",
     "CTI{distribucion_mitre_actor_número_tecnicas}",
     json.dumps(["Filtra el dataset APT28 por threat_actor='APT28'", "Cuenta valores únicos en la columna 'mitre' (excluye vacíos)", "Crea el gráfico y cuenta las barras"]),
     "Data", "medio", 150,
     "ctinexus/viz-lab:latest", "8888",
     json.dumps(["Python", "pandas", "matplotlib", "Jupyter"]),
     json.dumps(["Ciencia de Datos", "Analista de Datos"]),
     "Logs de Red — APT28 Fancy Bear", 0),

    (12, "Día 1", "Kill Chain Básico",
     "Usando el dataset de campaña LockBit, identifica la fase del Kill Chain con más eventos registrados. La bandera incluye el nombre de la fase y su count.",
     "CTI{Impact_3_eventos_maximos}",
     "CTI{fase_count_eventos_maximos}",
     json.dumps(["Agrupa el dataset LockBit por columna 'phase'", "Usa .value_counts() para contar eventos por fase", "La fase con mayor count es la respuesta"]),
     "CTI", "medio", 175,
     "ctinexus/killchain:latest", "8080",
     json.dumps(["Python", "pandas", "dataset LockBit"]),
     json.dumps(["Ciberseguridad", "Analista de Datos"]),
     "Campaña Ransomware — LockBit 3.0", 0),

    (13, "Día 1", "Reto de Equipo — Día 1",
     "RETO DE EQUIPO (todos los roles). El equipo analiza el dataset APT28 en conjunto:\n• Analista de Datos: ¿Cuántas IPs src únicas externas (country!='LAN') hay?\n• Ciberseguridad: ¿Cuál es el max bytes en un solo evento?\n• Ciencia de Datos: ¿Cuántas técnicas MITRE únicas hay?\n• Machine Learning: ¿Cuál es la IP dst externa más frecuente?\nBandera: CTI{D1_IPs_BYTES_TÉCNICAS_IP_C2}",
     "CTI{D1_3_891200_7_91.108.4.11}",
     "CTI{D1_ips_bytes_técnicas_ip_C2}",
     json.dumps(["Analista: filtra country!='LAN', cuenta src_ip únicas", "Ciber: max de la columna bytes", "DS: mitre.nunique() excluyendo vacíos; ML: dst_ip más frecuente en country!='LAN'"]),
     "Team", "difícil", 300,
     "ctinexus/team-d1:latest", "8080,8888",
     json.dumps(["Python", "pandas", "matplotlib", "sklearn", "Jupyter"]),
     json.dumps(["Analista de Datos", "Ciberseguridad", "Ciencia de Datos", "Machine Learning"]),
     "Logs de Red — APT28 Fancy Bear", 1),

    # ── DÍA 2 — Explotación CTI (13 retos) ───────────────────────────────────
    (1,  "Día 2", "APT28 — Timeline del Ataque",
     "Reconstruye el timeline del ataque APT28. Calcula cuántos minutos transcurrieron entre el primer y último evento registrado en el dataset.",
     "CTI{35_minutos_attack_window}",
     "CTI{minutos_attack_window}",
     json.dumps(["Usa pd.to_datetime() en la columna timestamp", "max_time - min_time convierte a timedelta", "int(delta.total_seconds() / 60) da los minutos"]),
     "Network", "medio", 150,
     "ctinexus/apt28-timeline:latest", "8888",
     json.dumps(["Python", "pandas", "datetime"]),
     json.dumps(["Analista de Datos", "Ciberseguridad"]),
     "Logs de Red — APT28 Fancy Bear", 0),

    (2,  "Día 2", "LockBit — Patient Zero",
     "Identifica el 'Patient Zero' en el dataset de campaña LockBit: el primer host comprometido. Bandera: hostname_ip_fase.",
     "CTI{WEB-SRV-01_10.1.0.5_Initial_Access}",
     "CTI{hostname_ip_fase}",
     json.dumps(["Ordena el dataset por timestamp ascendente", "El primer registro es el Patient Zero", "Formato: hostname_ip_phase(sin espacios)"]),
     "Ransomware", "medio", 175,
     "ctinexus/lockbit-ir:latest", "8888",
     json.dumps(["Python", "pandas", "dataset LockBit"]),
     json.dumps(["Ciberseguridad", "Analista de Datos"]),
     "Campaña Ransomware — LockBit 3.0", 0),

    (3,  "Día 2", "Clasificación de Malware con ML",
     "Entrena un RandomForestClassifier para predecir la familia de malware. Features: size_kb (numérico) + type (LabelEncoded). Evalúa en 30% de test set. ¿Cuál es el accuracy? Bandera con el accuracy redondeado a 2 decimales.",
     "CTI{RandomForest_accuracy_1.00}",
     "CTI{algoritmo_accuracy_valor}",
     json.dumps(["from sklearn.ensemble import RandomForestClassifier", "Codifica la columna 'type' con LabelEncoder", "train_test_split(test_size=0.3, random_state=42)"]),
     "Machine Learning", "difícil", 200,
     "ctinexus/ml-malware:latest", "8888",
     json.dumps(["Python", "sklearn", "pandas", "Jupyter"]),
     json.dumps(["Machine Learning", "Ciencia de Datos"]),
     "Análisis Malware — AgentTesla & Emotet", 0),

    (4,  "Día 2", "Pipeline de Enriquecimiento IOC",
     "Construye un pipeline que calcule un risk_score para cada IOC: severity_num * 25 * 0.6 + confidence * 0.4 (donde critical=4, high=3, medium=2, low=1). ¿Cuál es el score máximo?",
     "CTI{pipeline_top_score_96.4}",
     "CTI{pipeline_top_score_valor}",
     json.dumps(["Mapea severity: critical=4, high=3, medium=2, low=1", "score = severity_num * 25 * 0.6 + confidence * 0.4", "El IOC con confidence=99 y critical tiene el máximo"]),
     "Data Engineering", "difícil", 200,
     "ctinexus/pipeline-lab:latest", "8888",
     json.dumps(["Python", "pandas", "Jupyter"]),
     json.dumps(["Ciencia de Datos", "Analista de Datos"]),
     "Feed IOC Enriquecido — CTI-Lab", 0),

    (5,  "Día 2", "Botnet C2 — Detección",
     "Usando el dataset CTU-13, identifica cuántas IPs de destino únicas tienen la botnet Neris (label='Botnet', botnet='Neris'). Esas son las IPs C2.",
     "CTI{Neris_3_C2_IPs_detected}",
     "CTI{botnet_count_C2_IPs_detected}",
     json.dumps(["Filtra el dataset CTU-13 por botnet='Neris' AND label='Botnet'", "Agrupa por dst_ip", "Cuenta IPs de destino únicas"]),
     "Network", "difícil", 200,
     "ctinexus/botnet-hunter:latest", "8888",
     json.dumps(["Python", "pandas", "dataset CTU-13"]),
     json.dumps(["Ciberseguridad", "Machine Learning"]),
     "Botnet Traffic — CTU-13 Network Flows", 0),

    (6,  "Día 2", "Phishing Domain — Clasificador ML",
     "Entrena un clasificador para detectar dominios de phishing. Feature: longitud del dominio + número de guiones. Usa como target: 'active' vs otros del dataset phishing. Reporta el F1-score.",
     "CTI{LogReg_phish_F1_0.83}",
     "CTI{algoritmo_task_F1_valor}",
     json.dumps(["Crea features: len(domain), domain.count('-')", "Target: 1 si status='active', 0 si status='sinkholed' o 'inactive'", "from sklearn.linear_model import LogisticRegression + classification_report"]),
     "Machine Learning", "difícil", 225,
     "ctinexus/phish-ml:latest", "8888",
     json.dumps(["Python", "sklearn", "pandas", "re"]),
     json.dumps(["Machine Learning", "Ciencia de Datos"]),
     "Campaña Phishing — Credential Harvesting FIN7", 0),

    (7,  "Día 2", "YARA — Regla Básica",
     "Extrae los dominios C2 únicos de la familia AgentTesla del dataset de malware. ¿Cuántos dominios C2 únicos tiene? La bandera incluye ese número y la familia.",
     "CTI{AgentTesla_3_unique_C2_domains}",
     "CTI{familia_count_unique_C2_domains}",
     json.dumps(["Filtra el dataset malware por family='AgentTesla'", "Cuenta valores únicos en la columna 'c2_domain' (excluye vacíos)", "Cada dominio único sería una string en tu regla YARA"]),
     "Malware", "difícil", 225,
     "ctinexus/yara-lab:latest", "80",
     json.dumps(["Python", "pandas", "yara-python (opcional)"]),
     json.dumps(["Ciberseguridad"]),
     "Análisis Malware — AgentTesla & Emotet", 0),

    (8,  "Día 2", "Movimiento Lateral — Cadena",
     "En el dataset APT28, identifica los eventos de movimiento lateral (proto='SMB' o proto='RDP') entre IPs LAN. ¿Cuántos hosts destino únicos fueron alcanzados?",
     "CTI{lateral_movement_3_targets_SMB_RDP}",
     "CTI{lateral_count_targets_protocolos}",
     json.dumps(["Filtra por proto en ['SMB','RDP'] y country=='LAN'", "Cuenta dst_ip únicas en esos eventos", "Los protocolos usados son la parte final de la bandera"]),
     "Network", "difícil", 250,
     "ctinexus/lateral-hunter:latest", "8888",
     json.dumps(["Python", "pandas", "networkx (opcional)"]),
     json.dumps(["Ciberseguridad", "Analista de Datos"]),
     "Logs de Red — APT28 Fancy Bear", 0),

    (9,  "Día 2", "DNS Tunneling — Detección",
     "En el dataset APT28 hay eventos DNS (proto='DNS'). ¿Cuántos eventos DNS hay en total y cuál es la IP origen? Esto podría ser DNS tunneling.",
     "CTI{1_DNS_event_10.0.0.55_suspicious}",
     "CTI{count_DNS_events_ip_origen_label}",
     json.dumps(["Filtra por proto='DNS'", "Cuenta los eventos y extrae la src_ip", "Formato: count_ip_suspicious"]),
     "Network", "difícil", 250,
     "ctinexus/dns-tunnel:latest", "8888",
     json.dumps(["Python", "pandas"]),
     json.dumps(["Ciberseguridad"]),
     "Logs de Red — APT28 Fancy Bear", 0),

    (10, "Día 2", "Anomaly Detection — Isolation Forest",
     "Aplica IsolationForest al dataset CTU-13 usando features: bytes, packets, duration. Con contamination=0.4 y random_state=42, ¿cuántos flujos son clasificados como anomalía (-1)?",
     "CTI{IsolationForest_6_anomalies_detected}",
     "CTI{algoritmo_count_anomalies_detected}",
     json.dumps(["from sklearn.ensemble import IsolationForest", "X = df[['bytes','packets','duration']].fillna(0)", "model.fit_predict(X) → cuenta los -1"]),
     "Machine Learning", "experto", 275,
     "ctinexus/anomaly-lab:latest", "8888",
     json.dumps(["Python", "sklearn", "pandas"]),
     json.dumps(["Machine Learning", "Ciencia de Datos"]),
     "Botnet Traffic — CTU-13 Network Flows", 0),

    (11, "Día 2", "Informe de Inteligencia — LockBit",
     "Analiza el dataset LockBit para construir un informe. Encuentra: (1) el CVE explotado, (2) el número de hosts únicos comprometidos, (3) minutos totales del ataque. Bandera: CVE_hosts_minutos.",
     "CTI{CVE-2021-34527_4_hosts_48_min}",
     "CTI{CVE_hosts_minutos}",
     json.dumps(["El CVE está en la columna 'details' del dataset", "Cuenta hosts únicos en la columna 'host'", "Minutos = (max_timestamp - min_timestamp) en minutos"]),
     "CTI", "difícil", 250,
     "ctinexus/intel-report:latest", "80",
     json.dumps(["Python", "pandas", "datetime"]),
     json.dumps(["Analista de Datos", "Ciberseguridad"]),
     "Campaña Ransomware — LockBit 3.0", 0),

    (12, "Día 2", "Supply Chain Hunt — IOC Cruzado",
     "Correlaciona el IOC feed con el dataset de malware: busca un dominio C2 que aparezca en AMBOS datasets con threat actors DISTINTOS. Bandera: dominio_actor1_actor2.",
     "CTI{update-microsoft-cdn.com_Lazarus_AgentTesla}",
     "CTI{dominio_actor1_actor2}",
     json.dumps(["Extrae los dominios del IOC feed (columna 'ioc' donde type='domain')", "Extrae los dominios C2 del dataset malware (columna 'c2_domain')", "Busca la intersección con un set o merge de pandas"]),
     "IOC", "experto", 300,
     "ctinexus/supply-chain:latest", "8888",
     json.dumps(["Python", "pandas", "sets"]),
     json.dumps(["Todos"]),
     "Feed IOC Enriquecido — CTI-Lab", 0),

    (13, "Día 2", "Reto Final — Equipo Completo",
     "RETO FINAL DE EQUIPO. Integran los 5 datasets CTI-Lab:\n• Analista: Fusiona todos los datasets en un DataFrame maestro (campo: source_dataset)\n• Ciber: Identifica todos los TTPs únicos (todas las columnas mitre)\n• DS: Calcula el risk_score promedio del IOC feed enriquecido\n• ML: Entrena un clasificador binario (botnet vs benign) con CTU-13, reporta accuracy\nBandera: CTI{FINAL_filas_TTPs_score_accuracy}",
     "CTI{FINAL_75_11_60.5_1.00}",
     "CTI{FINAL_filas_TTPs_score_avg_accuracy}",
     json.dumps(["Analista: suma len() de los 5 datasets para el total de filas", "Ciber: combina todas las columnas mitre de los 5 datasets y cuenta únicos", "DS: risk_score promedio del IOC feed; ML: IsolationForest o RandomForest en CTU-13"]),
     "Team", "experto", 500,
     "ctinexus/final-challenge:latest", "8080,8888,9090",
     json.dumps(["Python", "pandas", "sklearn", "matplotlib", "todos los datasets"]),
     json.dumps(["Analista de Datos", "Ciberseguridad", "Ciencia de Datos", "Machine Learning"]),
     None, 1),
]


def _seed_ctf_challenges(conn) -> None:
    if conn.execute("SELECT COUNT(*) FROM ctf_challenges").fetchone()[0]:
        return
    for ch in _CTF_CHALLENGES:
        (order_idx, phase_name, title, description, flag, flag_format,
         hints_json, category, difficulty, points, docker_image, docker_port,
         tools_json, roles_json, dataset_name, is_team) = ch
        phase_row = conn.execute("SELECT id FROM ctf_phases WHERE name = ?", (phase_name,)).fetchone()
        phase_id  = phase_row[0] if phase_row else None
        ds_id     = None
        if dataset_name:
            ds_row = conn.execute("SELECT id FROM datasets WHERE name = ?", (dataset_name,)).fetchone()
            ds_id  = ds_row[0] if ds_row else None
        conn.execute(
            """INSERT INTO ctf_challenges
               (phase_id, order_idx, title, description, flag, flag_format,
                hints_json, category, difficulty, points, docker_image, docker_port,
                tools_json, roles_json, dataset_id, is_team, created_by)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (phase_id, order_idx, title, description, flag, flag_format,
             hints_json, category, difficulty, points, docker_image, docker_port,
             tools_json, roles_json, ds_id, is_team, "system@ctf"),
        )


@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def row_to_dict(row: sqlite3.Row) -> dict:
    return dict(row)

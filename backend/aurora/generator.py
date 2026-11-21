"""Generador del Caso Aurora: datos 100 % ficticios y distintos por estudiante.

La semilla sale del correo del estudiante, así que cada quien ve el mismo incidente
con hechos distintos (IP del C2, host del Paciente Cero, bytes exfiltrados, tiempos,
vector de entrada...). Es determinista: el mismo estudiante siempre recibe los mismos datos.

Convenciones de seguridad: IPs de rangos de documentación (RFC 5737), dominios .example
y red interna 10.20.0.0/16. No hay ningún indicador real.
"""
from __future__ import annotations

import hashlib
import random
from datetime import datetime, timedelta

DATASETS = {
    "telemetria": "aurora_telemetria_sesiones",
    "netflow":  "aurora_netflow",
    "ioc":      "aurora_ioc_feed",
    "malware":  "aurora_malware_lab",
    "siem":     "aurora_siem_events",
    "reportes": "aurora_reportes_texto",
    "dominios": "aurora_dominios",
}

_PZ_HOSTS = ["WKS-FIN-07", "WKS-FIN-12", "WKS-RH-03", "WKS-LEG-05", "WKS-TES-09"]
_VICTIMS = {"WKS-FIN-07": "mparra", "WKS-FIN-12": "lcastillo", "WKS-RH-03": "jrivera", "WKS-LEG-05": "agomez", "WKS-TES-09": "dortega"}
_MID_HOSTS = ["DC-AUR-01", "APP-SRV-04", "SQL-SRV-02"]
_SVC = ["svc_backup", "svc_sql", "svc_print", "svc_report"]
_VECTORS = [
    ("adjunto", "un adjunto de Excel con macro enviado como «factura pendiente»"),
    ("enlace", "un enlace a un portal falso de Aurora que pedía iniciar sesión"),
    ("credencial", "una credencial de un proveedor reutilizada en la VPN de Aurora"),
]
_FAMILIES = ["Brisa", "Cuervo", "Sombra", "Marejada"]
_PERSIST = ["Tarea programada", "Clave Run del registro", "Servicio falso de Windows", "Carpeta de inicio"]
_EVASION = ["Ofuscación de PowerShell", "Inyección en proceso legítimo", "Desactivación del antivirus", "Empaquetado con cifrado"]
_WORDS = ["seguro", "acceso", "clientes", "portal", "soporte", "validar", "token", "banca"]
_REGISTRARS = ["NombreRapido", "DominiosSur", "RegistroGlobal", "HostMarea"]
_BENIGN_DOMAINS = ["mail.proveedor-uno.example", "cdn.contenidos.example", "actualizaciones.so-oficial.example",
                   "api.pasarela-pagos.example", "intranet.aurora.example", "correo.aurora.example"]


def case_code(email: str) -> str:
    return "AUR-" + hashlib.sha256(f"aurora:{email.lower()}".encode()).hexdigest()[:4].upper()


def _rng(email: str) -> random.Random:
    return random.Random(int(hashlib.sha256(f"aurora-seed:{email.lower()}".encode()).hexdigest(), 16))


def _fmt(d: datetime) -> str:
    return d.strftime("%Y-%m-%d %H:%M:%S")


def build_case(email: str) -> dict:
    """Devuelve {code, facts, datasets:{clave: [filas]}} para el estudiante."""
    r = _rng(email)
    code = case_code(email)

    # ── Hechos de la variante (la «verdad» del caso para este estudiante) ──────
    pz = r.choice(_PZ_HOSTS)
    mid = r.choice(_MID_HOSTS)
    host_ip = {pz: f"10.20.{r.randint(10, 19)}.{r.randint(20, 90)}", "DC-AUR-01": "10.20.1.10", "APP-SRV-04": "10.20.2.14",
               "SQL-SRV-02": "10.20.2.22", "FILE-SRV-02": "10.20.3.8", "BACKUP-SRV": "10.20.3.20", "WEB-PORTAL-01": "10.20.0.5"}
    vec_key, vec_text = r.choice(_VECTORS)
    fam = r.choice(_FAMILIES)
    svc = r.choice(_SVC)
    c2_ip = f"203.0.113.{r.randint(20, 240)}"
    exfil_ip = f"198.51.100.{r.randint(20, 240)}"
    word = r.choice(_WORDS)
    phish = f"aurora-{word}-login.example"
    alias_word = r.choice([w for w in _WORDS if w != word])
    alias = f"aurora-{alias_word}-pagos.example"
    c2_domain = f"cdn-{r.choice(['nube', 'borde', 'sync'])}-{r.randint(10, 99)}.example"
    persist, evasion = r.choice(_PERSIST), r.choice(_EVASION)
    d0 = datetime(2026, 10, r.randint(6, 12), r.randint(8, 10), r.randint(0, 59), r.randint(0, 59))   # primer acceso
    t_lat = d0 + timedelta(hours=r.randint(30, 60), minutes=r.randint(0, 59))
    t_backup = t_lat + timedelta(hours=r.randint(20, 40))
    t_exfil = t_backup + timedelta(hours=r.randint(10, 22))
    t_enc = t_exfil + timedelta(hours=r.randint(8, 20), minutes=r.randint(0, 59))
    minutes_to_encrypt = int((t_enc - (d0 - timedelta(minutes=18))).total_seconds() // 60)   # desde la primera alerta del incidente
    minutes_from_exec = int((t_enc - d0).total_seconds() // 60)

    # ── 1. NetFlow ─────────────────────────────────────────────────────────────
    nf = []
    pz_ip = host_ip[pz]
    beacons = r.randint(14, 22)
    for i in range(beacons):                       # beacon al C2 cada ~60 s
        nf.append((d0 + timedelta(minutes=6, seconds=60 * i + r.randint(-3, 3)), pz_ip, c2_ip, 443, "HTTPS", r.randint(180, 520), "ALLOW", pz))
    nf.append((d0 + timedelta(minutes=30), pz_ip, c2_ip, 4444, "TCP", 6144, "BLOCK", pz))            # intento bloqueado
    for h in (mid, "FILE-SRV-02"):                  # movimiento lateral SMB/RDP
        for _ in range(r.randint(2, 4)):
            nf.append((t_lat + timedelta(minutes=r.randint(0, 50)), pz_ip if h == mid else host_ip[mid], host_ip[h],
                       r.choice([445, 3389, 5985]), "TCP", r.randint(18_000, 90_000), "ALLOW", pz if h == mid else mid))
    exfil_total = 0
    for i in range(r.randint(4, 7)):                # exfiltración
        b = r.randint(250, 520) * 1_000_000
        exfil_total += b
        nf.append((t_exfil + timedelta(minutes=12 * i + r.randint(0, 8)), host_ip["FILE-SRV-02"], exfil_ip, 443, "HTTPS", b, "ALLOW", "FILE-SRV-02"))
    nf.append((t_exfil + timedelta(minutes=2), host_ip["FILE-SRV-02"], exfil_ip, 21, "FTP", 8192, "BLOCK", "FILE-SRV-02"))
    names = list(host_ip)
    pool = ["8.8.8.8", "1.1.1.1", host_ip["WEB-PORTAL-01"], host_ip["DC-AUR-01"]] + [f"192.0.2.{r.randint(1, 250)}" for _ in range(10)]
    for _ in range(r.randint(38, 55)):              # tráfico normal (ruido): muchos destinos, pocas repeticiones cada uno
        s = r.choice(names)
        dst = r.choice(pool)
        nf.append((d0 - timedelta(hours=r.randint(0, 60), minutes=r.randint(0, 59)), host_ip[s], dst, r.choice([53, 80, 443, 389, 445]),
                   r.choice(["DNS", "HTTPS", "HTTP", "LDAP"]), r.randint(60, 90_000), "ALLOW", s))
    nf.sort(key=lambda x: x[0])
    netflow = [dict(zip(("timestamp", "src_ip", "dst_ip", "port", "proto", "bytes", "action", "host"),
                        (_fmt(t), a, b, p, pr, by, ac, h))) for t, a, b, p, pr, by, ac, h in nf]
    exfil_allowed = sum(x["bytes"] for x in netflow if x["dst_ip"] == exfil_ip and x["action"] == "ALLOW")

    # ── 2. Feed IOC (con ruido, duplicados y nulos) ────────────────────────────
    feed = [
        {"ioc": c2_ip, "tipo": "ip", "severidad": "critical", "confianza": r.randint(88, 97), "fuente": "ISAC-Financiero", "first_seen": _fmt(d0 - timedelta(days=3))[:10], "campana": "Marea Gris"},
        {"ioc": exfil_ip, "tipo": "ip", "severidad": "low", "confianza": r.randint(22, 38), "fuente": "Feed-Comunitario", "first_seen": _fmt(d0 - timedelta(days=9))[:10], "campana": "sin asignar"},  # trampa: parece inofensiva
        {"ioc": phish, "tipo": "dominio", "severidad": "high", "confianza": r.randint(75, 90), "fuente": "ISAC-Financiero", "first_seen": _fmt(d0 - timedelta(days=14))[:10], "campana": "Marea Gris"},
        {"ioc": c2_domain, "tipo": "dominio", "severidad": "high", "confianza": r.randint(70, 85), "fuente": "Sandbox-Interno", "first_seen": _fmt(d0)[:10], "campana": "Marea Gris"},
    ]
    for i in range(r.randint(48, 60)):
        t = r.choice(["ip", "dominio", "hash"])
        val = (f"203.0.113.{r.randint(1, 254)}" if t == "ip" else f"{r.choice(['promo', 'envios', 'tienda', 'ofertas'])}-{r.randint(100, 999)}.example"
               if t == "dominio" else hashlib.sha256(f"{email}{i}".encode()).hexdigest()[:32])
        if val in (c2_ip, exfil_ip):
            continue
        feed.append({"ioc": val, "tipo": t, "severidad": r.choice(["low", "medium", "medium", "high", "critical"]),
                     "confianza": r.choice([None, r.randint(20, 95), r.randint(20, 95)]),
                     "fuente": r.choice(["Feed-Comunitario", "ISAC-Financiero", "Sandbox-Interno", "OSINT"]),
                     "first_seen": _fmt(d0 - timedelta(days=r.randint(1, 90)))[:10],
                     "campana": r.choice(["Zorro Azul", "Luna Roja", "Nube Negra", "sin asignar", None])})
    for dup in r.sample(feed[4:], 5):               # duplicados y mayúsculas inconsistentes
        feed.append({**dup, "tipo": dup["tipo"].upper(), "severidad": dup["severidad"].capitalize()})
    r.shuffle(feed)

    # ── 3. Laboratorio de malware ──────────────────────────────────────────────
    def sample(name, family, c2i, c2d, per, ev, cap, mitre, size):
        return {"archivo": name, "sha256": hashlib.sha256(f"{email}{name}".encode()).hexdigest(), "familia": family, "tipo": name.rsplit(".", 1)[-1],
                "tamano_kb": size, "c2_ip": c2i, "c2_dominio": c2d, "persistencia": per, "evasion": ev, "capacidad": cap, "mitre": mitre}
    malware = [
        sample("factura_pendiente.xlsm" if vec_key == "adjunto" else "actualizador.exe", fam, c2_ip, c2_domain, persist, evasion, "Robo de credenciales", "T1204.002,T1003.001,T1071.001", r.randint(300, 520)),
        sample("svchost_upd.dll", fam, c2_ip, c2_domain, persist, evasion, "Movimiento lateral", "T1021.002,T1550.002,T1071.001", r.randint(150, 260)),
        sample("sync_tool.exe", fam, c2_ip, c2_domain, persist, "Eliminación de respaldos", "Impacto", "T1490,T1486,T1041", r.randint(700, 980)),
    ]
    otras = [("Pirata", "keylogger", "Clave Run del registro", "Empaquetado con cifrado", "Captura de teclado", "T1056.001"),
             ("Lince", "minero", "Tarea programada", "Inyección en proceso legítimo", "Minería de criptomonedas", "T1496"),
             ("Nodo", "botnet", "Servicio falso de Windows", "Ofuscación de PowerShell", "DDoS", "T1498"),
             ("Faro", "troyano", "Carpeta de inicio", "Desactivación del antivirus", "Acceso remoto", "T1219")]
    for i, (f, tp, pe, ev, cap, mi) in enumerate(otras * 2):
        malware.append(sample(f"{f.lower()}_{i}.exe", f, f"203.0.113.{r.randint(1, 254)}", f"{f.lower()}-{r.randint(10, 99)}.example", pe, ev, cap, mi, r.randint(100, 900)))
    r.shuffle(malware)

    # ── 4. Eventos SIEM ────────────────────────────────────────────────────────
    victim = _VICTIMS[pz]
    ev = [
        (d0 - timedelta(minutes=18), pz, victim, "Initial Access", f"Entrada por {vec_key}", "T1566.001" if vec_key != "credencial" else "T1078", "high", f"El usuario {victim} interactuó con {vec_text}"),
        (d0, pz, victim, "Execution", "Ejecución de script", "T1204.002", "critical", f"Se ejecutó un proceso hijo sospechoso en {pz}"),
        (d0 + timedelta(minutes=6), pz, victim, "Command and Control", "Beacon HTTPS", "T1071.001", "critical", f"Conexiones periódicas a {c2_ip}"),
        (d0 + timedelta(hours=r.randint(2, 6)), pz, victim, "Credential Access", "Volcado de memoria", "T1003.001", "critical", "Acceso a la memoria del proceso de autenticación"),
        (t_lat, mid, svc, "Lateral Movement", "Inicio de sesión remoto", "T1021.002", "high", f"Sesión SMB desde {pz} con la cuenta {svc}"),
        (t_lat + timedelta(hours=2), "FILE-SRV-02", svc, "Lateral Movement", "Inicio de sesión remoto", "T1021.002", "high", f"Acceso a recursos compartidos con {svc}"),
        (t_backup, "BACKUP-SRV", svc, "Impact", "Eliminación de respaldos", "T1490", "critical", "Se borraron las copias de volumen"),
        (t_exfil, "FILE-SRV-02", svc, "Exfiltration", "Transferencia hacia el exterior", "T1041", "critical", f"Subida masiva de datos hacia {exfil_ip}"),
        (t_enc, "FILE-SRV-02", svc, "Impact", "Cifrado de archivos", "T1486", "critical", "Extensión .aurora-lock en miles de archivos"),
        (t_enc + timedelta(minutes=1), mid, svc, "Impact", "Nota de rescate", "T1491.001", "high", "Nota de rescate en cada directorio compartido"),
    ]
    for _ in range(r.randint(34, 42)):              # alertas normales / falsos positivos
        h = r.choice(names)
        ev.append((d0 - timedelta(hours=r.randint(0, 70), minutes=r.randint(0, 59)), h, r.choice(["admin_ti", "mgarcia", "jlopez", "sistema"]),
                   r.choice(["Discovery", "Execution", "Initial Access", "Defense Evasion"]), r.choice(["Escaneo interno", "Script de mantenimiento", "Inicio de sesión inusual", "Software no firmado"]),
                   r.choice(["T1046", "T1059", "T1078", "T1036"]), r.choice(["low", "low", "medium"]), "Evento revisado: sin relación con el incidente"))
    ev.sort(key=lambda x: x[0])
    siem = [dict(zip(("timestamp", "host", "usuario", "fase", "tecnica", "mitre", "severidad", "detalle"), (_fmt(t), *rest))) for t, *rest in ev]

    # ── 5. Reportes en texto (con un alias que hay que resolver) ───────────────
    texts = [
        ("correo", f"Asunto: URGENTE. Recibí {vec_text} y lo abrí desde {pz}. Después el equipo se puso lento. — {victim}"),
        ("ticket", f"Mesa de ayuda: {pz} presenta conexiones salientes constantes hacia {c2_ip} a cualquier hora. Se escala al SOC."),
        ("chat_soc", f"Analista 1: veo la IP {exfil_ip} con mucho tráfico saliente desde FILE-SRV-02. Analista 2: en el feed figura con baja confianza, ¿la ignoramos?"),
        ("informe_forense", f"Se identificó la familia {fam}. Su servidor de mando usa {c2_domain}. Persiste mediante: {persist}."),
        ("informe_forense", f"El actor abusó de la cuenta {svc} para pasar de {pz} a {mid} y luego a FILE-SRV-02."),
        ("correo", f"Del proveedor: nuestro dominio de pagos es {alias} (antes {phish}). Disculpen la confusión con el portal."),
        ("ticket", f"Seguridad: {phish} y {alias} se registraron el mismo día y comparten la IP de alojamiento. Se tratan como el mismo actor."),
        ("chat_soc", f"Analista 2: el cifrado empezó en FILE-SRV-02 y la nota apareció en {mid}. Backup ya estaba borrado desde antes."),
        ("informe_forense", "El actor se autodenomina «Marea Gris». Busca extorsión económica, no espionaje."),
        ("correo", "Gerencia: necesitamos saber si hay datos de clientes expuestos antes del comité del lunes."),
        ("ticket", "RRHH: ningún empleado reporta haber compartido su contraseña por teléfono."),
        ("chat_soc", "Analista 1: el servidor de correo no muestra más adjuntos similares esta semana."),
    ]
    reportes = [{"id": i + 1, "fuente": s, "fecha": _fmt(d0 + timedelta(hours=r.randint(1, 140)))[:16], "texto": t} for i, (s, t) in enumerate(texts)]
    r.shuffle(reportes)
    for i, row in enumerate(reportes):
        row["id"] = i + 1

    # ── 6. Dominios (etiquetados + candidatos sin etiqueta a evaluar) ──────────
    dominios, hermanos = [], []
    def dom(name, reg, days_old, ip, label):
        base = name.split(".")[0]
        return {"dominio": name, "registrador": reg, "dias_desde_registro": days_old, "ip": ip, "longitud": len(base),
                "guiones": base.count("-"), "tld": name.rsplit(".", 1)[-1], "etiqueta": label}
    ip_pool = f"198.51.100.{r.randint(1, 254)}"
    for i in range(14):                              # maliciosos etiquetados
        dominios.append(dom(f"aurora-{r.choice(_WORDS)}-{r.choice(['login', 'pagos', 'clave', 'token'])}-{r.randint(1, 99)}.example",
                            r.choice(_REGISTRARS[:2]), r.randint(1, 20), ip_pool if r.random() < .6 else f"198.51.100.{r.randint(1, 254)}", "malicioso"))
    for i in range(18):                              # benignos etiquetados
        dominios.append(dom(f"{r.choice(['tienda', 'noticias', 'banco', 'seguros', 'viajes', 'cocina'])}{r.choice(['', '-', ''])}{r.choice(['norte', 'sur', 'plus', 'digital'])}{r.randint(1, 999)}.example",
                            r.choice(_REGISTRARS), r.randint(200, 3000), f"192.0.2.{r.randint(1, 254)}", "benigno"))
    for i in range(6):                               # candidatos: hermanos de Marea Gris (sin etiqueta)
        n = f"aurora-{r.choice(_WORDS)}-{r.choice(['login', 'pagos', 'clave'])}-{r.randint(100, 199)}.example"
        hermanos.append(n)
        dominios.append(dom(n, r.choice(_REGISTRARS[:2]), r.randint(1, 8), ip_pool, None))
    for i in range(4):                               # candidatos legítimos sin etiqueta
        dominios.append(dom(f"{r.choice(['mercado', 'clinica', 'colegio', 'taller'])}{r.randint(1, 99)}.example", r.choice(_REGISTRARS), r.randint(400, 2500), f"192.0.2.{r.randint(1, 254)}", None))
    r.shuffle(dominios)

    # ── 7. Telemetría de sesiones: ¿operador humano, automatización legítima o agente autónomo con IA? ──
    # Se genera AL FINAL para no alterar ningún dato anterior de las variantes ya entregadas.
    cuentas = ["mparra", "lcastillo", "jrivera", "agomez", "dortega", "ncardenas", "psuarez", "fbernal", "tmora", "rvalencia", "ihenao", "cgil"]
    ses = []
    def _row(kind, cuenta, ppm, desv_f, cmds, err, retry, hora, pags, tool, dur):
        inter = 60.0 / ppm
        return {"kind": kind, "cuenta": cuenta, "hora": hora, "duracion_min": dur, "peticiones_por_min": round(ppm, 1),
                "intervalo_medio_s": round(inter, 2), "intervalo_desv_s": round(inter * desv_f, 2), "comandos_distintos": cmds,
                "errores_pct": round(err, 1), "reintento_tras_error_s": round(retry, 1), "paginas_distintas": pags, "herramienta": tool}
    for _ in range(r.randint(96, 106)):                                   # operadores humanos
        ses.append(_row("humano", r.choice(cuentas), r.uniform(2, 11), r.uniform(0.5, 1.1), r.randint(3, 14), r.uniform(0, 9),
                        r.uniform(25, 120), r.choice(list(range(8, 19)) * 9 + [19, 20, 21]), r.randint(4, 34),
                        r.choice(["navegador"] * 4 + ["cliente-cli"]), r.randint(5, 90)))
    for tool in ("monitoreo", "respaldo", "reportes", "monitoreo"):       # automatización legítima (rápida y regular, pero rígida)
        ses.append(_row("legitimo", f"svc_{tool}", r.uniform(24, 48), r.uniform(0.03, 0.2), r.randint(1, 3), r.uniform(0, 1.2),
                        r.uniform(60, 300), r.choice([1, 2, 3, 4, 5, 22, 23]), r.randint(2, 6), "agente-" + tool, r.randint(20, 180)))
    for _ in range(8):                                                    # agente autónomo con IA (LLM + herramientas)
        ses.append(_row("agente", r.choice([victim, svc, r.choice(cuentas)]), r.uniform(17, 46), r.uniform(0.25, 0.55), r.randint(26, 60),
                        r.uniform(9, 22), r.uniform(1, 6), r.choice([0, 1, 2, 3, 4, 5, 23]), r.randint(90, 260),
                        r.choice(["python-requests", "httpx", "automatizacion"]), r.randint(10, 70)))
    r.shuffle(ses)
    telemetria, agent_sessions, legit_bots = [], [], []
    t_base = d0 + timedelta(days=1)
    for i, x in enumerate(ses, start=1):
        sid = f"S-{i:04d}"
        if x["kind"] == "agente":
            agent_sessions.append(sid)
        elif x["kind"] == "legitimo":
            legit_bots.append(sid)
        row = {"sesion": sid, "cuenta": x["cuenta"], "inicio": _fmt(t_base.replace(hour=x["hora"], minute=0, second=0) + timedelta(minutes=r.randint(0, 59), days=(i % 5)))}
        row.update({k: v for k, v in x.items() if k not in ("kind", "cuenta")})
        telemetria.append(row)

    facts = {
        "pz": pz, "pz_ip": pz_ip, "mid": mid, "svc": svc, "vector": vec_key, "vector_text": vec_text, "family": fam,
        "c2_ip": c2_ip, "exfil_ip": exfil_ip, "phish": phish, "alias": alias, "c2_domain": c2_domain, "persistence": persist, "evasion": evasion,
        "beacons": beacons, "exfil_bytes": exfil_allowed, "minutes_to_encrypt": minutes_to_encrypt, "minutes_from_exec": minutes_from_exec, "lateral_path": [pz, mid, "FILE-SRV-02"],
        "siblings": hermanos, "victim": victim,
        "agent_sessions": agent_sessions, "legit_bots": legit_bots,
        "legit_candidates": [d["dominio"] for d in dominios if d["etiqueta"] is None and d["dominio"] not in hermanos],
    }
    return {"code": code, "facts": facts,
            "datasets": {"netflow": netflow, "ioc": feed, "malware": malware, "siem": siem, "reportes": reportes, "dominios": dominios, "telemetria": telemetria}}

from __future__ import annotations

from datetime import datetime, timezone

# ── MITRE D3FEND countermeasures per ATT&CK technique ────────────────────────

DEFEND_MAP: dict[str, list[dict]] = {
    "T1071": [
        {"id": "D3-NTF",   "name": "Network Traffic Filtering",      "type": "Aislar",   "desc": "Filtrar tráfico C2 saliente a IPs no autorizadas mediante reglas de firewall"},
        {"id": "D3-DNSDL", "name": "DNS Denylisting",                "type": "Aislar",   "desc": "Bloquear resolución DNS de dominios C2 conocidos en el resolver corporativo"},
        {"id": "D3-NTA",   "name": "Network Traffic Analysis",       "type": "Detectar", "desc": "Analizar patrones de beaconing en flujos de red salientes"},
    ],
    "T1059": [
        {"id": "D3-SCA",   "name": "Script Code Analysis",           "type": "Detectar", "desc": "Inspeccionar argumentos de PowerShell/CMD antes de ejecución"},
        {"id": "D3-EAL",   "name": "Executable Allowlisting",        "type": "Endurecer","desc": "Restringir ejecución de intérpretes de scripts no autorizados (AppLocker/WDAC)"},
        {"id": "D3-PAT",   "name": "Process Argument Analysis",      "type": "Detectar", "desc": "Detectar flags sospechosos como -EncodedCommand o -WindowStyle Hidden"},
    ],
    "T1003": [
        {"id": "D3-PA",    "name": "Process Analysis",               "type": "Detectar", "desc": "Detectar acceso anómalo al proceso LSASS por procesos no del sistema"},
        {"id": "D3-CIL",   "name": "Credential Isolation",           "type": "Aislar",   "desc": "Proteger credenciales en enclave seguro (Windows Credential Guard / LSA PPL)"},
        {"id": "D3-UAP",   "name": "User Account Permissions",       "type": "Endurecer","desc": "Limitar privilegios de procesos con acceso a memoria de LSASS"},
    ],
    "T1055": [
        {"id": "D3-PA",    "name": "Process Analysis",               "type": "Detectar", "desc": "Detectar CreateRemoteThread/VirtualAllocEx en procesos legítimos"},
        {"id": "D3-DQSA",  "name": "Dynamic Analysis",               "type": "Detectar", "desc": "Análisis de comportamiento dinámico en sandbox antes de ejecución"},
        {"id": "D3-EAL",   "name": "Executable Allowlisting",        "type": "Endurecer","desc": "Restringir qué procesos pueden realizar llamadas de inyección"},
    ],
    "T1566": [
        {"id": "D3-SFV",   "name": "Sender Filter Verification",     "type": "Detectar", "desc": "Validar dominio del remitente: SPF, DKIM, DMARC y reputación"},
        {"id": "D3-URLF",  "name": "URL File Verification",          "type": "Detectar", "desc": "Analizar URLs y adjuntos con sandbox antes de entrega al usuario"},
        {"id": "D3-MEF",   "name": "Message Filter",                 "type": "Aislar",   "desc": "Bloquear adjuntos con extensiones peligrosas: exe, iso, vbs, js, lnk"},
    ],
    "T1486": [
        {"id": "D3-FBA",   "name": "File Backup",                    "type": "Endurecer","desc": "Copias de seguridad inmutables offline, probadas semanalmente"},
        {"id": "D3-FCA",   "name": "File Content Analysis",          "type": "Detectar", "desc": "Detectar cifrado masivo de archivos por extensión/entropía desconocida"},
        {"id": "D3-HBPI",  "name": "Honey Object",                   "type": "Detectar", "desc": "Archivos honeypot cuyo acceso indica actividad de ransomware activa"},
    ],
    "T1027": [
        {"id": "D3-OAM",   "name": "Obfuscation Analysis",           "type": "Detectar", "desc": "Decodificar y analizar payloads base64/ofuscados en tiempo de ejecución"},
        {"id": "D3-SCA",   "name": "Script Code Analysis",           "type": "Detectar", "desc": "Inspeccionar código desofuscado antes de ejecución por el intérprete"},
    ],
    "T1078": [
        {"id": "D3-UAL",   "name": "User Account Behavior Analysis", "type": "Detectar", "desc": "Detectar uso de cuentas fuera de horario o desde geolocalización anómala"},
        {"id": "D3-MFA",   "name": "Multi-Factor Authentication",    "type": "Endurecer","desc": "Requerir segundo factor para todas las cuentas con acceso privilegiado"},
    ],
    "T1190": [
        {"id": "D3-AVF",   "name": "Application Vulnerability Filter","type": "Endurecer","desc": "WAF con firmas para exploits públicos conocidos (virtual patching)"},
        {"id": "D3-NTF",   "name": "Network Traffic Filtering",      "type": "Aislar",   "desc": "Aislar servicios expuestos detrás de proxy inverso con inspección profunda"},
    ],
    "T1110": [
        {"id": "D3-AL",    "name": "Account Locking",                "type": "Endurecer","desc": "Bloquear cuenta tras N intentos fallidos consecutivos de autenticación"},
        {"id": "D3-MFA",   "name": "Multi-Factor Authentication",    "type": "Endurecer","desc": "MFA frustra fuerza bruta aunque las credenciales sean correctas"},
        {"id": "D3-UAL",   "name": "User Account Behavior Analysis", "type": "Detectar", "desc": "Alertar sobre patrones de login fallido ≥ X intentos/minuto por IP origen"},
    ],
    "T1562": [
        {"id": "D3-AM",    "name": "Audit Log Monitoring",           "type": "Detectar", "desc": "Alertar cuando se deshabiliten servicios de auditoría o EDR"},
        {"id": "D3-UBA",   "name": "User Behavior Analysis",         "type": "Detectar", "desc": "Detectar comandos que manipulan servicios de seguridad por usuarios no admin"},
    ],
}

# TTL en días por tipo de IoC — cuánto tiempo un indicador sigue siendo accionable
IOC_TTL_DAYS: dict[str, int] = {
    "ip":     14,
    "domain": 30,
    "url":    7,
    "hash":   90,
    "email":  60,
}

# Etapa de ciclo de vida del IoA según prioridad de la regla de detección
IOA_STAGE_MAP: dict[str, dict] = {
    "critical": {"stage": "respuesta",  "coverage": "alta",  "desc": "Patrón confirmado en campañas activas — despliegue inmediato"},
    "high":     {"stage": "triaje",     "coverage": "alta",  "desc": "Patrón validado — requiere calibración de umbrales antes de producción"},
    "medium":   {"stage": "detección",  "coverage": "media", "desc": "Patrón emergente — observado en inteligencia, pendiente validación en entorno"},
    "low":      {"stage": "detección",  "coverage": "baja",  "desc": "Señal débil — investigación adicional requerida antes de cualquier despliegue"},
}


def get_defend_countermeasures(ttp: str) -> list[dict]:
    return DEFEND_MAP.get(ttp.upper(), [])


def get_ioc_lifecycle(ioc_type: str, created_at: str | None, severity: str) -> dict:
    ttl = IOC_TTL_DAYS.get(ioc_type.lower(), 30)
    sev_boost = {"critical": 20, "high": 10, "medium": 0, "low": -10}.get(severity.lower(), 0)

    if not created_at:
        # IoC estático sin fecha — asumimos activo reciente
        confidence = min(99, 88 + sev_boost)
        return {
            "stage": "activo", "days_active": 0,
            "ttl_days": ttl, "confidence": confidence, "score": confidence,
            "note": "Sin fecha de primera observación — tratado como activo",
        }

    try:
        created = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        days = max(0, (now - created).days)
    except Exception:
        days = 0

    ratio = days / ttl if ttl else 1.0

    if ratio <= 0.3:
        stage, base_conf, note = "activo",       95, "Dentro del periodo de alta confianza"
    elif ratio <= 0.7:
        stage, base_conf, note = "envejeciendo", 70, "Confianza en descenso — verificar con fuente original"
    elif ratio <= 1.0:
        stage, base_conf, note = "estale",        45, "Próximo a expirar — validar si sigue activo"
    else:
        stage, base_conf, note = "deprecado",     15, "TTL superado — retirar de bloqueos activos"

    confidence = max(5, min(99, base_conf + sev_boost))
    return {
        "stage": stage, "days_active": days,
        "ttl_days": ttl, "confidence": confidence, "score": confidence, "note": note,
    }


def get_ioa_lifecycle(priority: str) -> dict:
    return IOA_STAGE_MAP.get(priority.lower(), IOA_STAGE_MAP["medium"])


def compute_depuration(
    ttp: str,
    ioc_type: str,
    severity: str,
    ioc_created_at: str | None,
    ioa_priority: str,
) -> dict:
    defend   = get_defend_countermeasures(ttp)
    ioc_lc   = get_ioc_lifecycle(ioc_type, ioc_created_at, severity)
    ioa_lc   = get_ioa_lifecycle(ioa_priority)

    blockers: list[str] = []
    warnings: list[str] = []

    if ioc_lc["stage"] == "deprecado":
        blockers.append(f"IoC deprecado: {ioc_lc['days_active']}d activo supera TTL de {ioc_lc['ttl_days']}d para tipo '{ioc_type}'")
    elif ioc_lc["stage"] == "estale":
        warnings.append(f"IoC próximo a expirar ({ioc_lc['days_active']}d / TTL {ioc_lc['ttl_days']}d) — confirmar vigencia")

    if ioc_lc["confidence"] < 40:
        blockers.append(f"Confianza del IoC insuficiente ({ioc_lc['confidence']}% < umbral 40%)")

    if not defend:
        blockers.append(f"Sin contramedidas D3FEND mapeadas para {ttp} — cobertura defensiva no verificada")

    if ioa_lc["stage"] == "detección" and ioa_priority in ("medium", "low"):
        warnings.append("IoA en etapa de detección — validar tasa de falsos positivos antes de despliegue")

    cti_stage = (
        "activo"       if ioc_lc["confidence"] >= 70 else
        "envejeciendo" if ioc_lc["confidence"] >= 40 else
        "inactivo"
    )

    approved = len(blockers) == 0

    if approved and not warnings:
        recommendation = "Regla aprobada. Despliega en modo monitoreo 48h antes de bloqueo activo. Revisa umbrales D3FEND para tu entorno."
    elif approved:
        recommendation = f"Regla condicionalmente aprobada. Advertencias: {'; '.join(warnings)}"
    else:
        recommendation = f"Regla BLOQUEADA. Corrige: {'; '.join(blockers)}"

    return {
        "cti_stage":      cti_stage,
        "cti_confidence": ioc_lc["confidence"],
        "ioc_lifecycle":  ioc_lc,
        "ioa_lifecycle":  ioa_lc,
        "defend":         defend,
        "rule_approved":  approved,
        "blockers":       blockers,
        "warnings":       warnings,
        "recommendation": recommendation,
    }

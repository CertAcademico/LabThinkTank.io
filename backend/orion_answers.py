"""Respuestas esperadas de los retos ORION (1–10), calculadas sobre los datasets reales.
Solo se entregan al admin: GET /admin/orion/answers/{id}. No mover al frontend."""

ORION_ANSWERS: dict[int, list[str]] = {
    1: [
        "C2 entrante: 185.220.101.47 (RU) hacia 10.0.0.24 por 443; intento por 4444 bloqueado.",
        "Paciente cero: 10.0.0.24 (recibe C2 y luego pivota por SMB, SSH, RDP y WinRM).",
        "Exfiltración (T1041) hacia 91.108.4.11 (NL): 2 429 440 bytes (~2,3 MB) desde 10.0.0.31 y 10.0.0.100.",
        "Ventana de la intrusión: 02:14:33 → 02:50:00 (≈36 min)."
    ],
    2: [
        "Paciente cero: WEB-SRV-01, phishing con enlace (T1566.002) a las 08:12:00.",
        "Ruta: WEB-SRV-01 → DC-01 (PrintNightmare T1068, LSASS T1003.001) → FILE-SRV-02 (Pass-the-Hash T1550.002) → BACKUP-SRV (T1490).",
        "Exfiltración por SFTP (T1048) a las 10:15, antes del cifrado (10:45).",
        "Tiempo total intrusión → cifrado del DC: 2 h 48 min (08:12 → 11:00)."
    ],
    3: [
        "FIN7 es el actor con más dominios (5); APT29 y Lazarus con 3 cada uno.",
        "secure-paypal-login.info se aloja en 91.108.4.11, la misma IP de exfiltración del Reto 01.",
        "Features más útiles esperadas: TLD sospechoso, palabras clave de urgencia y antigüedad del registro."
    ],
    4: [
        "15 IOC: 6 IP, 6 dominios, 3 hashes; 6 critical, 6 high, 2 medium, 1 low.",
        "RU concentra la infraestructura (5 IOC).",
        "185.220.101.47 (APT28, critical, 95) debe estar en el top: es el C2 del Reto 01."
    ],
    5: [
        "Familias: AgentTesla 3, Emotet 2, Cobalt Strike 2, LockBit 2, Mimikatz 1.",
        "C2 únicos: 185.220.101.47, 91.108.4.11, 203.0.113.45, 198.51.100.22.",
        "203.0.113.45 es compartida por Emotet y el dropper de LockBit; 185.220.101.47 ya apareció como C2 de APT28 (Reto 01)."
    ],
    6: [
        "Clases desbalanceadas: AgentTesla 3 vs. Mimikatz 1.",
        "Cobalt Strike y Emotet comparten conducta de movimiento/propagación; es esperable que se confundan.",
        "Strings YARA razonables: update-microsoft-cdn.com, office365-auth.xyz, extensión .lockbit3."
    ],
    7: [
        "T1566.002, T1486 y T1204.002 aparecen 2 veces cada una: enlazan actores distintos por conducta.",
        "Pivote cruzado: 185.220.101.47 vincula APT28 (Reto 01/04) con AgentTesla (Reto 05)."
    ],
    8: [
        "Initial Access y Defense Evasion concentran 3 técnicas cada una.",
        "APT28 es el grupo con más técnicas en la muestra (3)."
    ],
    9: [
        "12 flujos Botnet (Neris 6, Rbot 4, Virut 2) y 3 benignos.",
        "Neris usa 6667/TCP (IRC), además de 53 y 80; Rbot usa 443 y 4444; Virut usa 1032.",
        "Cada familia muestra un par \"beacon corto + sesión larga\" (p. ej. Neris 80/TCP: 64 B → 420 000 B en 600 s)."
    ],
    10: [
        "LockBit 3.0 es el grupo con más víctimas (3; 1,48 M USD en total).",
        "Mayor rescate individual: Trigona, Energy (FR), 4 M USD; BlackCat suma 2,2 M en 2 víctimas.",
        "Ventana analizada: 1–20 de marzo de 2024, ~1 publicación cada 1,7 días."
    ]
}

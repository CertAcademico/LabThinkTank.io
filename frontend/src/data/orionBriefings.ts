/**
 * Fichas tácticas ORION (CCOCI) para los retos 1–10.
 * - Presentación al estudiante: dominio, metodologías, actores, escenario, PIR y dossier del dataset.
 * - Presentación docente: tema, conceptos, guion de clase, preguntas, respuestas esperadas y errores comunes.
 * Las "respuestas esperadas" se calcularon sobre los datasets reales de la plataforma.
 */

export type Domain = 'ciberdefensa' | 'ciberinteligencia' | 'actores'

export const DOMAINS: Record<Domain, { label: string; icon: string; color: string; desc: string }> = {
  ciberinteligencia: { label: 'Ciberinteligencia', icon: '🛰️', color: '#d4bd55',
    desc: 'Convertir datos técnicos en conocimiento evaluado que responde a un requerimiento (PIR) del mando.' },
  ciberdefensa: { label: 'Ciberdefensa', icon: '🛡️', color: '#4ade80',
    desc: 'Detectar, contener y mitigar: reglas, bloqueos, priorización y recomendaciones operativas.' },
  actores: { label: 'Descubrimiento de actores', icon: '🎯', color: '#f97316',
    desc: 'Atribuir y perfilar al adversario: infraestructura, herramientas, TTP y patrones que lo delatan.' },
}

export interface Method { name: string; short: string; detail: string }

export const METHODS: Record<string, Method> = {
  ciclo:     { name: 'Ciclo de inteligencia', short: 'Planear → Recolectar → Procesar → Analizar → Difundir → Retroalimentar',
               detail: 'Todo reto empieza con una pregunta (PIR) y termina con un producto difundido. El código es la fase de procesamiento; el informe es la difusión.' },
  attack:    { name: 'MITRE ATT&CK', short: 'Táctica (el porqué) → Técnica (el cómo) → Procedimiento',
               detail: 'Lenguaje común para describir el comportamiento adversario. Las columnas "mitre" de los datasets usan identificadores T####.' },
  killchain: { name: 'Cyber Kill Chain', short: 'Reconocimiento → Armado → Entrega → Explotación → Instalación → C2 → Acciones',
               detail: 'Ordena una intrusión en fases. Cortar una fase temprana rompe toda la cadena: es la base de la defensa en profundidad.' },
  diamond:   { name: 'Modelo de Diamante', short: 'Adversario · Capacidad · Infraestructura · Víctima',
               detail: 'Cada evento conecta cuatro vértices. Pivotar desde uno (p. ej. una IP de infraestructura) permite descubrir los demás.' },
  piramide:  { name: 'Pirámide del Dolor', short: 'Hash < IP < Dominio < Artefactos < Herramientas < TTP',
               detail: 'Bloquear un hash no le cuesta nada al adversario; detectar sus TTP lo obliga a cambiar su forma de operar.' },
  admiralty: { name: 'Código Admiralty (STANAG 2511)', short: 'Fiabilidad de la fuente A–F · Credibilidad del dato 1–6',
               detail: 'Separa quién lo dice de qué tan creíble es lo dicho. Base para ponderar la columna confidence.' },
  f3ead:     { name: 'F3EAD', short: 'Find · Fix · Finish · Exploit · Analyze · Disseminate',
               detail: 'Ciclo de operaciones dirigido por inteligencia: lo que se explota de una operación alimenta el siguiente blanco.' },
  ach:       { name: 'Análisis de Hipótesis en Competencia (ACH)', short: 'Matriz hipótesis × evidencias',
               detail: 'Técnica estructurada para evitar el sesgo de confirmación en la atribución: se busca la evidencia que descarta, no la que confirma.' },
  d3fend:    { name: 'MITRE D3FEND + Sigma', short: 'Contramedida defensiva ↔ técnica ofensiva · regla de detección portable',
               detail: 'Por cada técnica ATT&CK se propone una contramedida D3FEND y una regla Sigma (logsource, detection, condition).' },
  crispdm:   { name: 'CRISP-DM aplicado a CTI', short: 'Entender → Preparar → Modelar → Evaluar → Desplegar',
               detail: 'Disciplina de ciencia de datos para que un modelo de ML sea un sensor confiable y explicable, no una caja negra.' },
  riesgo:    { name: 'Priorización por riesgo', short: 'Riesgo = Severidad × Confianza × Relevancia',
               detail: 'Un analista no puede bloquear todo: ordena por impacto potencial y calidad del dato, y justifica la escala.' },
}

export interface DatasetDossier {
  origin: string
  rows: number
  grain: string                 // qué representa una fila
  columns: Record<string, string>
  lookFor: string[]             // qué buscar
  pitfalls: string[]            // trampas del dataset
}

export interface TeacherNotes {
  tema: string
  concepts: { t: string; d: string }[]
  flow: { min: number; step: string }[]
  questions: string[]
  expected: string[]
  errors: string[]
}

export interface Briefing {
  phase: 1 | 2 | 3 | 4
  codename: string
  domains: Domain[]
  methods: string[]
  actors: string[]
  scenario: string
  pir: string
  product: string
  dataset: DatasetDossier
  teacher: TeacherNotes
}

export const PHASES: Record<number, { name: string; focus: string }> = {
  1: { name: 'Fase I · Fundamentos', focus: 'Depuración de datos, IOC y priorización' },
  2: { name: 'Fase II · Análisis de campañas', focus: 'Kill chain, malware y ransomware' },
  3: { name: 'Fase III · Comportamiento adversario', focus: 'Correlación de fuentes, TTP y detección' },
  4: { name: 'Fase IV · Analítica avanzada', focus: 'Machine Learning aplicado a CTI' },
}

/** Pivotes de infraestructura compartida entre datasets: material para el descubrimiento de actores. */
export const CROSS_PIVOTS = [
  { ioc: '185.220.101.47', where: 'Reto 01 (C2 de APT28, RU) · Reto 04/07 (feed: APT28, crítico) · Reto 05/06 (C2 de AgentTesla)',
    lesson: 'Una misma IP aparece con dos actores distintos: puede ser infraestructura compartida (nodo Tor/proxy) y no prueba atribución por sí sola.' },
  { ioc: '91.108.4.11', where: 'Reto 01 (destino de exfiltración, NL) · Reto 03 (hosting de phishing FIN7) · Reto 05/06 (C2 de AgentTesla)',
    lesson: 'Servidor de hosting reutilizado por varias operaciones: pivotar por él conecta phishing, malware y exfiltración.' },
  { ioc: '203.0.113.45', where: 'Reto 05/06 (C2 de Emotet y dropper de LockBit)',
    lesson: 'Emotet como "loader" que entrega ransomware: relación entre actores de acceso inicial y operadores de ransomware.' },
]

export const BRIEFINGS: Record<number, Briefing> = {
  1: {
    phase: 1, codename: 'OP. OSO DE FUEGO',
    domains: ['ciberinteligencia', 'actores', 'ciberdefensa'],
    methods: ['diamond', 'attack', 'piramide'],
    actors: ['APT28 · Fancy Bear (GRU, G0007)'],
    scenario: 'El CSIRT de una unidad reporta tráfico anómalo nocturno (02:14–02:50). Se sospecha de un actor estatal. Su sección debe confirmar la intrusión, extraer indicadores y reconstruir la secuencia en menos de una hora.',
    pir: 'PIR-1: ¿Existe una intrusión activa atribuible a APT28 y qué activos propios están comprometidos?',
    product: 'Informe de situación (SITREP) con lista de IOC, línea de tiempo y técnicas ATT&CK.',
    dataset: {
      origin: 'PCAP simulado convertido a registros de flujo (CTI-Lab).', rows: 15,
      grain: 'Una conexión de red observada en el perímetro o en la LAN.',
      columns: {
        timestamp: 'Momento de la conexión (orden cronológico = línea de tiempo).',
        src_ip: 'Origen. IP 10.x = red propia; IP pública = externa.',
        dst_ip: 'Destino. Si es pública y recibe bytes, posible exfiltración o C2.',
        port: 'Puerto destino: 443/80 web, 445 SMB, 3389 RDP, 22 SSH, 5985 WinRM, 4444 típico de shells.',
        proto: 'Protocolo de aplicación.',
        bytes: 'Volumen transferido: clave para cuantificar exfiltración.',
        action: 'Decisión del firewall (ALLOW/BLOCK).',
        country: 'Geolocalización del extremo externo (LAN = interno).',
        threat_actor: 'Atribución preliminar del sensor (¡evalúela, no la acepte a ciegas!).',
        mitre: 'Técnica ATT&CK asignada al evento.',
      },
      lookFor: [
        'IP externa que inicia conexiones hacia la red (C2 entrante).',
        'Host interno que, tras ser contactado, se mueve lateralmente (SMB, RDP, SSH, WinRM).',
        'Conexiones salientes con muchos bytes hacia un mismo destino (T1041).',
        'El único evento bloqueado: ¿por qué el firewall solo detuvo el puerto 4444?',
      ],
      pitfalls: [
        'Un evento tiene mitre vacío y actor "Unknown" (consulta DNS a 8.8.8.8): es ruido, no lo cuente como IOC.',
        'dst_ip 10.0.0.24 aparece como "externo" si filtra solo por country ≠ RU; use el prefijo 10. para separar interno/externo.',
      ],
    },
    teacher: {
      tema: 'Del indicador al adversario: caza de IOC y Modelo de Diamante.',
      concepts: [
        { t: 'IOC vs. IoA', d: 'El IOC es un rastro (IP, hash, dominio); el IoA es una conducta (moverse por SMB a las 2 a. m.).' },
        { t: 'Modelo de Diamante', d: 'Adversario APT28 · Infraestructura 185.220.101.47 / 91.108.4.11 · Capacidad (C2 HTTPS, SMB) · Víctima 10.0.0.24.' },
        { t: 'Pirámide del Dolor', d: 'Las IP se cambian en minutos; las TTP de movimiento lateral se mantienen. Prioricemos detectar conducta.' },
      ],
      flow: [
        { min: 10, step: 'Briefing: escenario, PIR-1 y Modelo de Diamante en el tablero.' },
        { min: 10, step: 'Demostración: cargar challenge_df, ordenar por timestamp, separar interno/externo.' },
        { min: 25, step: 'Trabajo individual: IOC, bytes exfiltrados, gráfica de técnicas, timeline.' },
        { min: 10, step: 'Puesta en común: cada analista lee su SITREP en formato BLUF.' },
      ],
      questions: [
        '¿Cuál fue el "paciente cero" y cómo lo sabe?',
        '¿Por qué la atribución del sensor no basta para afirmar que es APT28?',
        'Si solo pudiera bloquear una cosa, ¿qué bloquearía y por qué?',
      ],
      expected: [
        'C2 entrante: 185.220.101.47 (RU) hacia 10.0.0.24 por 443; intento por 4444 bloqueado.',
        'Paciente cero: 10.0.0.24 (recibe C2 y luego pivota por SMB, SSH, RDP y WinRM).',
        'Exfiltración (T1041) hacia 91.108.4.11 (NL): 2 429 440 bytes (~2,3 MB) desde 10.0.0.31 y 10.0.0.100.',
        'Ventana de la intrusión: 02:14:33 → 02:50:00 (≈36 min).',
      ],
      errors: [
        'Contar 8.8.8.8 como C2.',
        'Sumar todos los bytes en lugar de solo los eventos de exfiltración.',
        'Entregar gráficas sin conclusión operativa.',
      ],
    },
  },

  2: {
    phase: 2, codename: 'OP. CANDADO NEGRO',
    domains: ['ciberdefensa', 'ciberinteligencia'],
    methods: ['killchain', 'attack', 'd3fend'],
    actors: ['LockBit 3.0 (RaaS) y sus afiliados'],
    scenario: 'Una entidad de infraestructura crítica amaneció con servidores cifrados y nota de rescate. El equipo de respuesta entregó su registro de actividad. El mando necesita saber cómo entraron, cuánto tardaron y dónde se pudo haber cortado la cadena.',
    pir: 'PIR-2: ¿Cuál fue el vector de entrada, la ruta del atacante y el punto más temprano donde la defensa pudo romper la cadena?',
    product: 'Reconstrucción de kill chain + recomendaciones de mitigación priorizadas.',
    dataset: {
      origin: 'Informe de respuesta a incidentes simulado (CTI-Lab).', rows: 13,
      grain: 'Una acción del atacante sobre un host, con su fase y técnica.',
      columns: {
        host: 'Servidor afectado (WEB-SRV-01, DC-01, FILE-SRV-02, BACKUP-SRV).',
        ip: 'IP del host afectado.',
        timestamp: 'Momento de la acción: permite medir el tiempo de permanencia (dwell time).',
        phase: 'Fase ATT&CK (Initial Access, Execution, … Impact).',
        technique: 'Descripción humana de la técnica.',
        mitre: 'Identificador ATT&CK.',
        severity: 'Gravedad asignada por el equipo de respuesta.',
        ioc: 'Indicador asociado a la acción.',
        details: 'Contexto adicional del analista.',
      },
      lookFor: [
        'El primer evento cronológico y su host: es el paciente cero.',
        'El salto entre hosts: WEB → DC → FILE → BACKUP.',
        'Acciones previas al cifrado que debieron disparar alertas (AMSI bypass, LSASS dump, borrado de VSS).',
        'Exfiltración antes del cifrado: doble extorsión.',
      ],
      pitfalls: [
        'La fase "Impact" aparece 4 veces: no es una sola acción, es borrado de backups, cifrado y nota de rescate.',
        'Ordenar por fase alfabéticamente rompe la secuencia; ordene por timestamp.',
      ],
    },
    teacher: {
      tema: 'Ransomware como operación: Cyber Kill Chain y puntos de ruptura.',
      concepts: [
        { t: 'Ransomware-as-a-Service', d: 'Desarrolladores alquilan el malware a afiliados que ejecutan la intrusión: cambian los operadores, se repiten las TTP.' },
        { t: 'Doble extorsión', d: 'Exfiltrar (T1048) antes de cifrar (T1486) para presionar con la publicación.' },
        { t: 'Punto de ruptura', d: 'Cada fase es una oportunidad: filtrado de correo, bloqueo de macros, protección de LSASS, backups inmutables.' },
      ],
      flow: [
        { min: 10, step: 'Briefing con la nota de rescate: ¿qué preguntas haría el comandante?' },
        { min: 10, step: 'Dibujar en el tablero las 7 fases de la Kill Chain vacías.' },
        { min: 25, step: 'Los analistas ordenan los eventos y llenan cada fase con evidencia del dataset.' },
        { min: 15, step: 'Debate: ¿en qué fase se debió cortar? Cada equipo defiende un control.' },
      ],
      questions: [
        '¿Cuánto tiempo tuvo la defensa para reaccionar antes del cifrado?',
        '¿Qué evento debió activar la alarma más temprana?',
        '¿Por qué atacar BACKUP-SRV antes de cifrar?',
      ],
      expected: [
        'Paciente cero: WEB-SRV-01, phishing con enlace (T1566.002) a las 08:12:00.',
        'Ruta: WEB-SRV-01 → DC-01 (PrintNightmare T1068, LSASS T1003.001) → FILE-SRV-02 (Pass-the-Hash T1550.002) → BACKUP-SRV (T1490).',
        'Exfiltración por SFTP (T1048) a las 10:15, antes del cifrado (10:45).',
        'Tiempo total intrusión → cifrado del DC: 2 h 48 min (08:12 → 11:00).',
      ],
      errors: [
        'Confundir la fecha del cifrado con la de la intrusión.',
        'Recomendaciones genéricas ("tener antivirus") sin vincularlas a una técnica concreta.',
      ],
    },
  },

  3: {
    phase: 4, codename: 'OP. ANZUELO',
    domains: ['ciberdefensa', 'actores'],
    methods: ['crispdm', 'piramide', 'diamond'],
    actors: ['FIN7 (Carbanak)', 'APT29 · Cozy Bear', 'Lazarus Group', 'APT28'],
    scenario: 'El correo institucional recibe cientos de enlaces sospechosos al día. El mando ordena un sensor automático que clasifique dominios y explique por qué uno es malicioso, para reducir la carga del analista.',
    pir: 'PIR-3: ¿Qué características de un dominio permiten anticipar que es infraestructura de phishing de un actor hostil?',
    product: 'Modelo clasificador evaluado + las 3 características más explicativas + matriz de confusión.',
    dataset: {
      origin: 'OSINT + DomainTools simulado (CTI-Lab).', rows: 12,
      grain: 'Un dominio registrado para campañas de suplantación.',
      columns: {
        domain: 'Dominio: fuente de las features (longitud, guiones, TLD).',
        url: 'URL completa del señuelo.',
        target_org: 'Marca suplantada (Microsoft, PayPal, DHL…).',
        registrar: 'Registrador: algunos son preferidos por los actores.',
        registered: 'Fecha de registro: dominios recientes = más sospechosos.',
        ip_hosting: 'IP del servidor: pivote para descubrir más infraestructura.',
        technique: 'Técnica de engaño (typosquatting, homoglyph, lookalike…).',
        threat_actor: 'Actor atribuido.',
        status: 'active / inactive / sinkholed.',
        confidence: 'Confianza de la atribución (0–100).',
      },
      lookFor: [
        'Palabras de urgencia o seguridad: secure, login, verify, update, alert.',
        'TLD poco comunes: .xyz, .info, .biz, .cloud.',
        'IP de hosting repetidas entre dominios de un mismo actor (pivote del Diamante).',
      ],
      pitfalls: [
        'Solo 12 filas y todas maliciosas: para entrenar hay que construir la clase "legítima" (p. ej. microsoft.com, paypal.com) o usar status/confidence como etiqueta; documente la decisión.',
        'Con tan pocos datos un accuracy del 100 % es sobreajuste; use validación cruzada y explíquelo.',
      ],
    },
    teacher: {
      tema: 'El ML como sensor de ciberdefensa: features explicables sobre infraestructura adversaria.',
      concepts: [
        { t: 'Feature engineering', d: 'Traducir intuiciones del analista ("parece falso") a números: longitud, guiones, TLD, antigüedad.' },
        { t: 'Precisión vs. exhaustividad', d: 'Un falso negativo deja pasar un phishing; un falso positivo bloquea un correo legítimo. ¿Cuál cuesta más al mando?' },
        { t: 'Pivote por hosting', d: 'Dominios distintos en la misma IP delatan a un mismo operador.' },
      ],
      flow: [
        { min: 10, step: 'Mostrar 5 dominios y pedir al grupo que vote "legítimo/malicioso" y explique por qué.' },
        { min: 10, step: 'Convertir esas razones en features en pandas.' },
        { min: 30, step: 'Entrenar, evaluar y graficar la matriz de confusión.' },
        { min: 10, step: 'Discusión sobre sesgo de datos y explicabilidad.' },
      ],
      questions: [
        '¿Cómo construyeron la clase negativa y qué sesgo introduce?',
        '¿Qué feature confiarían a un sensor en producción y cuál no?',
        '¿Qué dominios comparten IP y qué dice eso del actor?',
      ],
      expected: [
        'FIN7 es el actor con más dominios (5); APT29 y Lazarus con 3 cada uno.',
        'secure-paypal-login.info se aloja en 91.108.4.11, la misma IP de exfiltración del Reto 01.',
        'Features más útiles esperadas: TLD sospechoso, palabras clave de urgencia y antigüedad del registro.',
      ],
      errors: [
        'Reportar accuracy sin precision/recall.',
        'No declarar cómo se generó la clase legítima.',
      ],
    },
  },

  4: {
    phase: 1, codename: 'OP. TAMIZ',
    domains: ['ciberinteligencia', 'ciberdefensa'],
    methods: ['ciclo', 'admiralty', 'riesgo', 'piramide'],
    actors: ['APT28', 'APT29', 'Lazarus Group', 'FIN7', 'Turla', 'LockBit', 'BlackCat'],
    scenario: 'Llega un feed de indicadores de varias fuentes abiertas. El centro de operaciones solo puede cargar 5 reglas de bloqueo esta noche. Su sección debe depurar el feed y decidir qué entra primero.',
    pir: 'PIR-1: ¿Qué indicadores representan el mayor riesgo inmediato para la red propia y deben bloquearse hoy?',
    product: 'Lista priorizada de IOC con puntaje de riesgo explicado + reporte ejecutivo BLUF.',
    dataset: {
      origin: 'Feed agregado OTX + AbuseIPDB + ThreatFox (CTI-Lab).', rows: 15,
      grain: 'Un indicador de compromiso con su contexto.',
      columns: {
        ioc: 'Valor del indicador (IP, dominio o hash).',
        type: 'Tipo: IP, domain, hash.',
        threat_actor: 'Actor asociado.',
        severity: 'critical / high / medium / low: conviértala a número.',
        mitre: 'Técnica ATT&CK relacionada.',
        country: 'País asociado a la infraestructura.',
        first_seen: 'Primera observación: indicadores viejos pierden valor.',
        confidence: 'Confianza 0–100 (equivalente a la credibilidad del Admiralty).',
        tags: 'Etiquetas libres (C2, proxy, phishing…).',
      },
      lookFor: [
        'IOC críticos con confianza ≥ 80: candidatos a bloqueo inmediato.',
        'Actores con varios indicadores: campaña activa.',
        'Tipo de IOC vs. Pirámide del Dolor: un hash vale menos que un dominio de C2 reutilizado.',
      ],
      pitfalls: [
        'severity es texto: ordenar alfabéticamente pone "critical" < "high" < "low" < "medium".',
        'country "Unknown" no es un país: trátelo como dato faltante.',
      ],
    },
    teacher: {
      tema: 'El analista como filtro: calidad de la fuente y priorización por riesgo.',
      concepts: [
        { t: 'Admiralty aplicado', d: 'confidence ≈ credibilidad del dato; la fuente (OTX, AbuseIPDB) ≈ fiabilidad.' },
        { t: 'Puntaje de riesgo', d: 'Ejemplo: severidad(1–4) × confianza/100. Lo importante es justificar la escala.' },
        { t: 'Vida útil del IOC', d: 'Una IP de hace un año probablemente ya cambió de dueño.' },
      ],
      flow: [
        { min: 10, step: 'Pregunta disparadora: "solo puede bloquear 5, ¿cuáles?"' },
        { min: 30, step: 'Limpieza, conversión de severidad, puntaje y gráficas.' },
        { min: 15, step: 'Cada equipo presenta su top 5 y defiende la fórmula.' },
      ],
      questions: [
        '¿Su fórmula premia la severidad o la confianza? ¿Por qué?',
        '¿Qué IOC descartaría aunque sea "critical"?',
        '¿Qué indicador también aparece en otros retos?',
      ],
      expected: [
        '15 IOC: 6 IP, 6 dominios, 3 hashes; 6 critical, 6 high, 2 medium, 1 low.',
        'RU concentra la infraestructura (5 IOC).',
        '185.220.101.47 (APT28, critical, 95) debe estar en el top: es el C2 del Reto 01.',
      ],
      errors: ['Ordenar severity como texto.', 'No explicar la fórmula del puntaje.'],
    },
  },

  5: {
    phase: 2, codename: 'OP. DISECCIÓN',
    domains: ['ciberinteligencia', 'actores', 'ciberdefensa'],
    methods: ['attack', 'diamond', 'piramide'],
    actors: ['AgentTesla (infostealer)', 'Emotet (loader, TA542)', 'Cobalt Strike (post-explotación)', 'LockBit', 'Mimikatz'],
    scenario: 'El laboratorio forense recuperó 10 muestras de equipos comprometidos. El mando quiere saber qué familias operan, qué infraestructura comparten y qué capacidades tienen contra la unidad.',
    pir: 'PIR-2: ¿Qué familias de malware están presentes, qué infraestructura de C2 usan y qué capacidad representa mayor amenaza?',
    product: 'Perfil por familia + lista de C2 + heatmap capacidad × familia.',
    dataset: {
      origin: 'Análisis de sandbox Any.run + VirusTotal (CTI-Lab).', rows: 10,
      grain: 'Una muestra de malware analizada.',
      columns: {
        filename: 'Nombre del archivo (señuelo).', md5: 'Hash MD5.', sha256: 'Hash SHA-256.',
        size_kb: 'Tamaño en KB.', family: 'Familia de malware.', type: 'Extensión (exe, dll, ps1, xlsm…).',
        mitre: 'Técnicas ATT&CK separadas por coma: use str.split(",") y explode().',
        c2_domain: 'Dominio de C2 (vacío si la muestra no se comunica).',
        c2_ip: 'IP de C2.',
        persistence: 'Mecanismos de persistencia (registro, tareas, servicios).',
        evasion: 'Técnicas de evasión.',
        capability: 'Capacidades separadas por coma.',
      },
      lookFor: [
        'IP de C2 compartidas entre familias distintas.',
        'Dominios de C2 que imitan marcas (update-microsoft-cdn.com).',
        'Familias sin C2: herramientas locales (Mimikatz, cifrador LockBit).',
      ],
      pitfalls: [
        'Columnas multivalor (mitre, capability, persistence): sin explode() el conteo sale mal.',
        'persistence vacía en 3 muestras: no significa "sin persistencia" sino "no observada".',
      ],
    },
    teacher: {
      tema: 'Perfilado de capacidades del adversario a partir de artefactos.',
      concepts: [
        { t: 'Familia vs. actor', d: 'AgentTesla es una herramienta que usan muchos actores; Emotet era operado por TA542. No confundir arma con operador.' },
        { t: 'Ecosistema criminal', d: 'Emotet entrega → Cobalt Strike se mueve → LockBit cifra. Las familias forman una cadena de suministro.' },
        { t: 'Datos multivalor', d: 'Normalizar listas en una celda es la habilidad de pandas clave de este reto.' },
      ],
      flow: [
        { min: 10, step: 'Explicar la diferencia familia/actor con el ejemplo Emotet → LockBit.' },
        { min: 10, step: 'Demostrar explode() sobre la columna mitre.' },
        { min: 30, step: 'Perfiles, extracción de C2 y heatmap.' },
        { min: 10, step: 'Conclusión: ¿qué capacidad amenaza más a la unidad?' },
      ],
      questions: ['¿Qué IP conecta familias distintas?', '¿Qué familia elegiría para una regla YARA y por qué?', '¿Qué capacidad cambia la prioridad de respuesta?'],
      expected: [
        'Familias: AgentTesla 3, Emotet 2, Cobalt Strike 2, LockBit 2, Mimikatz 1.',
        'C2 únicos: 185.220.101.47, 91.108.4.11, 203.0.113.45, 198.51.100.22.',
        '203.0.113.45 es compartida por Emotet y el dropper de LockBit; 185.220.101.47 ya apareció como C2 de APT28 (Reto 01).',
      ],
      errors: ['Contar técnicas sin separar la lista.', 'Atribuir AgentTesla a un único actor estatal.'],
    },
  },

  6: {
    phase: 4, codename: 'OP. GENOMA',
    domains: ['actores', 'ciberdefensa'],
    methods: ['crispdm', 'attack', 'ach'],
    actors: ['AgentTesla', 'Emotet', 'Cobalt Strike', 'LockBit', 'Mimikatz'],
    scenario: 'Aparecen muestras nuevas sin etiquetar. El equipo de malware debe construir un clasificador que proponga la familia por su comportamiento y redactar reglas YARA para el sensor de endpoints.',
    pir: 'PIR-3: Dada una muestra desconocida, ¿a qué familia pertenece y con qué certeza?',
    product: 'Dataset limpio + mapa de TTP + modelo entrenado + reglas YARA conceptuales + reporte técnico (trabajo por roles AD/CS/ML/CD).',
    dataset: {
      origin: 'Mismo dataset del Reto 05 (sandbox Any.run + VirusTotal).', rows: 10,
      grain: 'Una muestra de malware analizada.',
      columns: {
        family: 'Etiqueta objetivo del clasificador.',
        mitre: 'Técnicas (multivalor) → features binarias con get_dummies.',
        capability: 'Capacidades (multivalor) → features binarias.',
        type: 'Extensión del archivo (categórica).',
        size_kb: 'Tamaño (numérica).',
        persistence: 'Persistencia (multivalor, con vacíos).',
        evasion: 'Evasión (multivalor).',
        c2_domain: 'Candidato a string para YARA.',
      },
      lookFor: [
        'Técnicas exclusivas de una familia: son las features más discriminantes.',
        'Familias que quedan cerca en PCA: comparten comportamiento.',
        'Strings repetidos (dominios C2) para las reglas YARA.',
      ],
      pitfalls: [
        'Con 10 muestras y 5 clases, varias clases tienen 1–2 ejemplos: no hay test fiable; use leave-one-out y reconózcalo.',
        'Incluir md5/sha256 como features es fuga de información: cada hash es único.',
      ],
    },
    teacher: {
      tema: 'Atribución técnica de muestras: clasificar por comportamiento, no por firma.',
      concepts: [
        { t: 'Clasificación por TTP', d: 'Escala la Pirámide del Dolor: el hash cambia, el comportamiento persiste.' },
        { t: 'ACH en la atribución', d: 'Para cada muestra, ¿qué evidencia descarta las demás familias?' },
        { t: 'YARA', d: 'Regla con strings + condition; aquí conceptual: justificar el criterio importa más que la sintaxis.' },
      ],
      flow: [
        { min: 10, step: 'Asignar roles AD / CS / ML / CD y entregables.' },
        { min: 40, step: 'Trabajo por roles con sincronización a mitad de tiempo.' },
        { min: 15, step: 'Exposición del reporte técnico y defensa de las reglas YARA.' },
      ],
      questions: ['¿Qué features eliminaron por fuga de información?', '¿Qué familias confunde el modelo y por qué tiene sentido?', '¿Su regla YARA detectaría una variante nueva?'],
      expected: [
        'Clases desbalanceadas: AgentTesla 3 vs. Mimikatz 1.',
        'Cobalt Strike y Emotet comparten conducta de movimiento/propagación; es esperable que se confundan.',
        'Strings YARA razonables: update-microsoft-cdn.com, office365-auth.xyz, extensión .lockbit3.',
      ],
      errors: ['Usar los hashes como features.', 'Presentar 100 % de accuracy sin advertir el tamaño de muestra.'],
    },
  },

  7: {
    phase: 3, codename: 'OP. TELARAÑA',
    domains: ['ciberinteligencia', 'actores'],
    methods: ['ciclo', 'admiralty', 'diamond', 'riesgo'],
    actors: ['APT28', 'APT29', 'Lazarus Group', 'FIN7', 'Turla', 'LockBit', 'BlackCat'],
    scenario: 'Tres fuentes abiertas reportan indicadores superpuestos. La célula de fusión debe unificarlas, eliminar duplicados y descubrir qué actores comparten infraestructura.',
    pir: 'PIR-1: ¿Qué actores están conectados por infraestructura común y cuáles exigen bloqueo inmediato?',
    product: 'Top 10 IOC críticos + red IOC ↔ actor + explicación del puntaje + reporte ejecutivo (roles AD/CD/CS).',
    dataset: {
      origin: 'Feed IOC del Reto 04, con referencia a ThreatFox, FeodoTracker y URLhaus.', rows: 15,
      grain: 'Un indicador de compromiso con su contexto.',
      columns: {
        ioc: 'Indicador: nodo de la red de correlación.',
        threat_actor: 'Actor: el otro tipo de nodo.',
        type: 'Tipo de IOC.',
        severity: 'Severidad textual → numérica.',
        confidence: 'Confianza de la fuente.',
        mitre: 'Técnica: permite enlazar actores por conducta.',
        first_seen: 'Fecha de primera observación.',
        tags: 'Etiquetas para segmentar.',
      },
      lookFor: [
        'Actores enlazados por la misma técnica (T1566.002, T1486, T1204.002).',
        'IOC que reaparecen en otros datasets (pivote entre retos).',
        'Grado de cada nodo en la red: actores más conectados.',
      ],
      pitfalls: [
        'El dataset no repite IOC textualmente: los vínculos aparecen por técnica o al cruzar con los datasets de los retos 01 y 05.',
        'Una red sin leyenda (qué es nodo, qué es arista) no comunica nada.',
      ],
    },
    teacher: {
      tema: 'Fusión de fuentes: del feed a la red de relaciones adversarias.',
      concepts: [
        { t: 'Deduplicación y normalización', d: 'La misma IP puede llegar con formato distinto de cada fuente.' },
        { t: 'Grafo bipartito', d: 'Nodos IOC y nodos actor; las aristas muestran uso. El grado revela centralidad.' },
        { t: 'Correlación ≠ atribución', d: 'Compartir infraestructura puede ser alquiler (bulletproof hosting), no colaboración.' },
      ],
      flow: [
        { min: 10, step: 'Mostrar los pivotes cruzados (185.220.101.47, 91.108.4.11) entre retos.' },
        { min: 40, step: 'Trabajo por roles: normalizar, puntuar, correlacionar, graficar.' },
        { min: 10, step: 'Lectura del reporte ejecutivo.' },
      ],
      questions: ['¿Qué actor es el más conectado de la red?', '¿Qué evidencia necesitaría para afirmar que dos actores cooperan?', '¿Cómo cambia su top 10 si sube el peso de confidence?'],
      expected: [
        'T1566.002, T1486 y T1204.002 aparecen 2 veces cada una: enlazan actores distintos por conducta.',
        'Pivote cruzado: 185.220.101.47 vincula APT28 (Reto 01/04) con AgentTesla (Reto 05).',
      ],
      errors: ['Concluir colaboración entre actores solo por compartir IP.', 'Red ilegible sin colores por tipo de nodo.'],
    },
  },

  8: {
    phase: 3, codename: 'OP. HUELLA',
    domains: ['actores', 'ciberdefensa'],
    methods: ['attack', 'd3fend', 'piramide', 'ach'],
    actors: ['APT28', 'APT29', 'Lazarus', 'FIN7', 'Turla', 'LockBit', 'BlackCat', 'Emotet'],
    scenario: 'El mando pide anticipar: no qué IOC tendrá el próximo ataque, sino qué comportamiento. La sección debe mapear las TTP de los grupos de interés y entregar reglas de detección listas para el SIEM.',
    pir: 'PIR-3: ¿Qué conductas comparten los actores de interés y qué detecciones cubren el mayor riesgo con el menor esfuerzo?',
    product: 'Heatmap táctica × grupo + 3 reglas Sigma + mapeo D3FEND + conclusión de detectabilidad (roles AD/CS/CD).',
    dataset: {
      origin: 'MITRE ATT&CK v14 (derivado de STIX).', rows: 15,
      grain: 'Una técnica usada por un grupo.',
      columns: {
        group: 'Nombre del grupo.', group_id: 'ID ATT&CK del grupo (G####).',
        technique: 'Nombre de la técnica.', technique_id: 'ID ATT&CK (T####).',
        tactic: 'Táctica (objetivo táctico del adversario).',
        platform: 'Plataformas afectadas.', data_source: 'Fuente de datos necesaria para detectar.',
        mitigations: 'Mitigaciones ATT&CK (M####).',
        detection: 'Guía de detección: base para redactar la regla Sigma.',
      },
      lookFor: [
        'Táctica con más técnicas: dónde invertir en detección.',
        'Grupo con mayor diversidad de técnicas.',
        'data_source más repetida: qué telemetría habilita más detecciones.',
      ],
      pitfalls: [
        'Es una muestra de 15 relaciones, no ATT&CK completo: concluya sobre la muestra.',
        'Las reglas Sigma deben tener title, logsource, detection y condition aunque sean conceptuales.',
      ],
    },
    teacher: {
      tema: 'Del perfil de actor a la detección: ATT&CK → Sigma → D3FEND.',
      concepts: [
        { t: 'IoA', d: 'Detectar la conducta (p. ej. volcado de LSASS) funciona aunque cambie toda la infraestructura.' },
        { t: 'Sigma', d: 'Formato de regla independiente del SIEM; se traduce a Splunk, Elastic o Sentinel.' },
        { t: 'D3FEND', d: 'Contramedida defensiva por técnica: cierra el ciclo análisis → acción.' },
      ],
      flow: [
        { min: 10, step: 'Mostrar una regla Sigma real y desarmarla en sus partes.' },
        { min: 10, step: 'Construir juntos la tabla pivote táctica × grupo.' },
        { min: 30, step: 'Heatmap, reglas y mapeo D3FEND por roles.' },
        { min: 10, step: 'Cada equipo "despliega" una regla y la defiende ante el grupo.' },
      ],
      questions: ['¿Qué técnica detectarían primero y por qué?', '¿Qué telemetría falta en la unidad para esas reglas?', '¿Qué técnicas compartidas generan riesgo de atribución errónea?'],
      expected: [
        'Initial Access y Defense Evasion concentran 3 técnicas cada una.',
        'APT28 es el grupo con más técnicas en la muestra (3).',
      ],
      errors: ['Reglas Sigma sin logsource.', 'Heatmap sin conclusión operativa.'],
    },
  },

  9: {
    phase: 4, codename: 'OP. ENJAMBRE',
    domains: ['ciberdefensa', 'actores'],
    methods: ['crispdm', 'killchain', 'attack'],
    actors: ['Neris', 'Rbot', 'Virut'],
    scenario: 'Los sensores de red detectan equipos que "hablan" con servidores externos a intervalos regulares. Se sospecha una botnet. La sección debe separar tráfico legítimo del malicioso e identificar qué botnet opera.',
    pir: 'PIR-2: ¿Qué flujos corresponden a C2 de botnet y qué familia los genera?',
    product: 'Análisis exploratorio + features de red + comparación RF vs. árbol (F1 ≥ 0,80) + visualizaciones por familia.',
    dataset: {
      origin: 'CTU-13, Stratosphere IPS (Universidad Técnica Checa).', rows: 15,
      grain: 'Un flujo de red (NetFlow) etiquetado.',
      columns: {
        timestamp: 'Inicio del flujo.', duration: 'Duración en segundos.',
        src_ip: 'Origen.', src_port: 'Puerto origen.', dst_ip: 'Destino.',
        dst_port: 'Puerto destino: 6667 IRC (Neris), 4444, 1032 (Virut).',
        protocol: 'TCP/UDP.', flags: 'Banderas TCP.',
        packets: 'Paquetes: cuidado al dividir si es 0.', bytes: 'Bytes transferidos.',
        label: 'Etiqueta objetivo: Botnet / Benign.', botnet: 'Familia (vacío si es benigno).',
      },
      lookFor: [
        'Puertos no estándar (6667, 4444, 1032): canal C2 típico de botnet.',
        'Pares de flujos: un "beacon" corto seguido de una sesión larga con muchos bytes.',
        'Features derivadas: bytes/packet, bytes/segundo.',
      ],
      pitfalls: [
        '12 de 15 flujos son botnet: un modelo que siempre diga "Botnet" logra 80 % de accuracy. Use F1 y estratificación.',
        'botnet vacío en flujos benignos: rellénelo con "Benign" antes de agrupar.',
      ],
    },
    teacher: {
      tema: 'Detección de C2 por comportamiento de red con aprendizaje supervisado.',
      concepts: [
        { t: 'Beaconing', d: 'Conexiones cortas y regulares para pedir órdenes: patrón clásico de C2 (fase 6 de la Kill Chain).' },
        { t: 'Desbalance de clases', d: 'Accuracy engaña; F1 y la matriz de confusión dicen la verdad.' },
        { t: 'Features de flujo', d: 'Las proporciones (bytes/packet, duración) generalizan mejor que IP o puerto concretos.' },
      ],
      flow: [
        { min: 10, step: 'Explicar CTU-13 y cómo se etiquetó.' },
        { min: 40, step: 'EDA, features y dos modelos por roles AD / CD / ML.' },
        { min: 10, step: 'Comparar modelos y discutir la clase que más se confunde.' },
      ],
      questions: ['¿Su modelo supera al clasificador trivial "todo es botnet"?', '¿Qué familia es más fácil de reconocer y por qué?', '¿Usar dst_port como feature es trampa?'],
      expected: [
        '12 flujos Botnet (Neris 6, Rbot 4, Virut 2) y 3 benignos.',
        'Neris usa 6667/TCP (IRC), además de 53 y 80; Rbot usa 443 y 4444; Virut usa 1032.',
        'Cada familia muestra un par "beacon corto + sesión larga" (p. ej. Neris 80/TCP: 64 B → 420 000 B en 600 s).',
      ],
      errors: ['Reportar accuracy del 80 % como éxito.', 'Dividir por packets sin manejar ceros.'],
    },
  },

  10: {
    phase: 2, codename: 'OP. RESCATE',
    domains: ['ciberinteligencia', 'actores', 'ciberdefensa'],
    methods: ['ciclo', 'attack', 'f3ead', 'd3fend'],
    actors: ['LockBit 3.0', 'BlackCat/ALPHV', 'Cl0p', 'Akira', 'Play', 'Medusa', 'Trigona'],
    scenario: 'El mando debe decidir a qué grupo de ransomware dedicar la vigilancia del próximo trimestre. La sección analiza los sitios de filtración y cruza con la campaña LockBit del Reto 02.',
    pir: 'PIR-1: ¿Qué grupo de ransomware representa la amenaza prioritaria para sectores de interés nacional y con qué controles se mitiga?',
    product: 'Tendencias + actor prioritario + TTP + recomendaciones defensivas (roles AD/CS/CD).',
    dataset: {
      origin: 'Ransomware.live (sitios de filtración de grupos de ransomware).', rows: 12,
      grain: 'Una víctima publicada por un grupo.',
      columns: {
        victim: 'Organización víctima (ficticia).', group: 'Grupo de ransomware.',
        sector: 'Sector económico.', country: 'País de la víctima.',
        published: 'Fecha de publicación en el sitio de filtración.',
        description: 'Descripción de la víctima.', employees: 'Tamaño de la organización.',
        revenue: 'Ingresos estimados.', url_leak: 'URL del sitio de filtración (no visitar).',
        ransom_usd: 'Rescate exigido en USD.',
      },
      lookFor: [
        'Grupo con más víctimas y con mayor rescate total.',
        'Sectores críticos (salud, energía, gobierno, transporte).',
        'Ritmo de publicación por fecha: ¿hay aceleración?',
      ],
      pitfalls: [
        'Cada sector aparece una sola vez: el conteo por sector no muestra tendencia; analice por grupo y por monto.',
        'url_leak es contexto: nunca se navega a sitios de filtración desde la red institucional.',
      ],
    },
    teacher: {
      tema: 'Inteligencia estratégica de ransomware: del dato de víctimas a la decisión del mando.',
      concepts: [
        { t: 'Niveles de inteligencia', d: 'Táctica (IOC), operacional (campaña) y estratégica (tendencias para decidir). Este reto es estratégico.' },
        { t: 'Victimología', d: 'Sector, país y tamaño revelan la selección de blancos del grupo.' },
        { t: 'F3EAD', d: 'Lo explotado en el Reto 02 (TTP de LockBit) alimenta la priorización de hoy.' },
      ],
      flow: [
        { min: 10, step: 'Recordar el Reto 02 y plantear la decisión del trimestre.' },
        { min: 35, step: 'Análisis por grupo, monto y línea temporal; cruce con TTP.' },
        { min: 15, step: 'Briefing al "comandante" (docente) con recomendación única.' },
      ],
      questions: ['¿Prioriza por número de víctimas o por rescate exigido?', '¿Qué controles del Reto 02 aplican a este grupo?', '¿Qué limita la confianza en estos datos?'],
      expected: [
        'LockBit 3.0 es el grupo con más víctimas (3; 1,48 M USD en total).',
        'Mayor rescate individual: Trigona, Energy (FR), 4 M USD; BlackCat suma 2,2 M en 2 víctimas.',
        'Ventana analizada: 1–20 de marzo de 2024, ~1 publicación cada 1,7 días.',
      ],
      errors: ['Concluir tendencias sectoriales con una víctima por sector.', 'Recomendaciones sin vincular a TTP.'],
    },
  },
}

/** Presentación general para el docente: cómo encuadrar el programa ORION. */
export const ORION_INTRO = [
  { title: 'Programa ORION', subtitle: 'Entrenamiento táctico en Ciberinteligencia · CCOCI',
    bullets: ['10 retos sobre datos reales simulados', 'Tres dominios: Ciberinteligencia, Ciberdefensa y Descubrimiento de actores', 'Ruta en 4 fases, de fundamentos a analítica avanzada'] },
  { title: 'Los tres dominios', subtitle: 'Qué entrena cada reto',
    bullets: Object.values(DOMAINS).map(d => `${d.icon} ${d.label}: ${d.desc}`) },
  { title: 'Ciclo de inteligencia', subtitle: 'El hilo conductor de todos los retos',
    bullets: ['Planeación: PIR del mando', 'Recolección: el dataset del reto', 'Procesamiento: Python/pandas en el sandbox', 'Análisis: evaluar, correlacionar, atribuir', 'Difusión: informe BLUF con TLP', 'Retroalimentación: nota y comentarios del instructor'] },
  { title: 'Marcos metodológicos', subtitle: 'Se repiten a lo largo de la ruta',
    bullets: ['MITRE ATT&CK · Cyber Kill Chain · Modelo de Diamante', 'Pirámide del Dolor · Código Admiralty · ACH', 'D3FEND + Sigma · F3EAD · CRISP-DM'] },
  { title: 'Descubrimiento de actores', subtitle: 'Pivotes que cruzan los datasets',
    bullets: CROSS_PIVOTS.map(p => `${p.ioc} — ${p.lesson}`) },
  { title: 'Evaluación', subtitle: 'Qué se califica',
    bullets: ['Nota mínima aprobatoria: 50/100', 'Código reproducible + visualizaciones + conclusiones operativas', 'El informe responde al PIR en la primera línea (BLUF)', 'Retroalimentación por el canal del grupo'] },
]

export function getBriefing(id: number): Briefing | undefined { return BRIEFINGS[id] }

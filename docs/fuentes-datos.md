# Fuentes de datos gratuitas para enriquecer el Caso Aurora y los retos

> Para el docente/admin. Revisado el 21-nov-2026. Las condiciones de acceso y las licencias cambian: **confirma cada una en la página oficial antes de integrarla** (no verifiqué que todos los enlaces sigan vivos ni la licencia exacta de cada conjunto).

## Principio de uso

- **El Caso Aurora es 100 % ficticio** a propósito. Las fuentes reales no reemplazan el caso: sirven para (a) que el estudiante practique con datos reales **en paralelo** y (b) para que el admin construya datasets de práctica nuevos.
- **Se descargan en el servidor o en tu equipo, no desde el navegador del estudiante.** Muchas APIs bloquean peticiones del navegador (CORS) y piden clave. Lo recomendado: tú descargas un recorte, lo limpias y lo subes como dataset (Admin → Datasets), o el estudiante lo sube en "Mis datasets".
- **Nunca pongas indicadores reales en el caso ficticio.** Si los mezclas con los inventados (rangos `203.0.113.x`, `.example`), el estudiante no podrá distinguir ficción de realidad, y alguien podría bloquear un indicador real por error.

## Indicadores y campañas (capítulos 1, 2, 3 y 6)

| Fuente | Qué da | Acceso | Úsala para |
|---|---|---|---|
| [abuse.ch — ThreatFox / URLhaus / MalwareBazaar](https://abuse.ch/blog/community-first/) | IOC, URLs maliciosas y muestras de malware | Las APIs piden una **Auth-Key gratuita** del portal de abuse.ch; hay descargas/exportaciones públicas ([ThreatFox](https://threatfox.abuse.ch/export/), [MalwareBazaar](https://bazaar.abuse.ch/export/)) | Cap. 2 (limpiar y priorizar un feed real) y cap. 3 (familias) |
| [Feodo Tracker](https://abuse.ch/terms-of-use/) | IPs de servidores de mando de botnets | Descarga de la lista sin clave; según los términos, uso libre (CC0) | Cap. 1 y 2 (beacons y C2 reales) |
| AlienVault OTX | Pulsos de inteligencia con IOC y contexto | Cuenta y clave API gratuitas | Cap. 2 y 5 (contexto narrativo de una campaña) |
| CISA KEV | Vulnerabilidades explotadas activamente | JSON/CSV público | Priorizar por riesgo real: «¿qué parchear primero?» |
| FIRST EPSS | Probabilidad de explotación por CVE | Descarga diaria pública | Cap. 2 y 7 (priorización con datos) |
| OpenPhish (feed comunitario) / PhishTank | URLs de phishing | OpenPhish: lista pública limitada; PhishTank: registro | Cap. 6 (clasificador de dominios con datos reales) |
| ransomware.live | Víctimas y grupos de ransomware | Datos públicos / API | Cap. 4 y 7 (impacto y diseminación) |

## Comportamiento y técnicas (capítulos 3, 4 y 5)

| Fuente | Qué da | Úsala para |
|---|---|---|
| [MITRE ATT&CK (STIX en GitHub)](https://attack.mitre.org/) | Técnicas, grupos y software en STIX 2.1 | Cap. 3 y 4: mapear técnicas; cap. 5: normalizar nombres de actores |
| SigmaHQ | Reglas de detección abiertas | Cap. 4: «¿qué regla habría detectado este paso?» |
| Atomic Red Team | Pruebas de técnicas ATT&CK reproducibles | Práctica guiada de detección |

## Tráfico de red y detección de anomalías (capítulo 1 y el nuevo capítulo del agente con IA)

| Conjunto | Notas |
|---|---|
| [CTU-13 (Stratosphere)](https://www.stratosphereips.org/datasets-ctu13) | Tráfico con botnets, normal y de fondo, etiquetado. Ya está referenciado en la plataforma. |
| [UNSW-NB15](https://research.unsw.edu.au/projects/unsw-nb15-dataset) y su versión [NetFlow](https://staff.itee.uq.edu.au/marius/NIDS_datasets/) | Ataques modernos etiquetados; la versión NetFlow es más ligera para un navegador. |
| [CIC-IDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) | Muy usado, pero **tiene problemas conocidos** de etiquetado por la herramienta que lo generó: úsalo con cautela o junto a uno más limpio. |
| [Catálogo de datasets NIDS (Würzburg)](https://www.informatik.uni-wuerzburg.de/datascience/research/datasets/nids-ds/) | Para elegir otros según el objetivo didáctico. |

**Tamaño:** son de gigabytes. El navegador del estudiante (Pyodide) y el límite de 5 MB de "Mis datasets" obligan a **recortar** (por ejemplo, 5.000 filas) antes de subirlos.

## Recomendación para empezar (poco esfuerzo, mucho valor)

1. **Feodo Tracker + ThreatFox** (un recorte de unos cientos de IOC reales) como dataset de práctica de limpieza y priorización, paralelo al capítulo 2.
2. **CISA KEV + EPSS** para un reto corto de «qué parchear primero» (nuevo, encaja en el capítulo 7).
3. **Un recorte de UNSW-NB15 NetFlow** para el capítulo de detección de anomalías.
4. **MITRE ATT&CK** como diccionario de consulta del estudiante (lo puede subir en "Mis datasets").

## Qué falta construir en la plataforma

- Un botón en el admin para **importar un recorte** desde una URL pública a un dataset (hoy se sube a mano).
- Un campo de **licencia y procedencia** en cada dataset, visible al estudiante, para trabajar la ética del dato.

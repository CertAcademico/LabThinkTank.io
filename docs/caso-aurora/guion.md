# Caso Aurora — guion del hilo conductor

> Documento para aprobación del docente/admin. Aún no se ha construido ningún dato ni reto: al aprobarlo se genera todo desde un script reproducible.

## 1. Idea en una línea

Seis retos individuales que dejan de ser ejercicios sueltos y pasan a ser **seis capítulos de un mismo incidente** en una empresa ficticia. Los mismos hosts, IPs, dominios y cuentas aparecen en varios datasets, así que el estudiante **cruza datos para entender qué pasó** y termina escribiendo sus propias conclusiones.

## 2. El escenario (ficticio)

**Aurora Financiera S.A.** — banco regional ficticio, ~1.200 empleados, sedes en Bogotá y Medellín, banca móvil y portal web.

**Atacante:** grupo ficticio **"Marea Gris"** (motivación económica). No se usan nombres de grupos reales: los datos son inventados de punta a punta, para que el estudiante se involucre sin asociarlo a casos reales.

**Convenciones para que sea claramente ficticio y seguro:**
- IPs de los rangos de documentación (RFC 5737): `203.0.113.0/24`, `198.51.100.0/24`, `192.0.2.0/24`.
- Dominios del TLD reservado `.example` (por ejemplo `aurora-seguro-login.example`).
- Red interna `10.20.0.0/16`.

**Activos de Aurora que aparecen en los datos**

| Host | Rol |
|---|---|
| `WEB-PORTAL-01` | Portal de clientes (punto de entrada) |
| `WKS-FIN-07` | Estación de una analista de finanzas (Paciente Cero) |
| `DC-AUR-01` | Controlador de dominio |
| `FILE-SRV-02` | Servidor de archivos (datos de clientes) |
| `BACKUP-SRV` | Respaldos |
| `svc_backup` | Cuenta de servicio comprometida |

## 3. Cronología real del incidente (la "verdad" que el estudiante reconstruye)

| Día / hora | Evento |
|---|---|
| D-14 | Marea Gris registra `aurora-seguro-login.example` y 7 dominios parecidos. |
| D-10 | Campaña de phishing a 40 empleados de finanzas. |
| D-9 08:12 | La analista de `WKS-FIN-07` abre un adjunto y ejecuta una macro. |
| D-9 08:18 | Primera conexión a C2 (`203.0.113.45`), con beacon cada 60 s. |
| D-9 a D-7 | Reconocimiento y robo de credenciales (volcado de memoria). |
| D-6 | Movimiento lateral a `DC-AUR-01` y `FILE-SRV-02` con la cuenta `svc_backup`. |
| D-4 | Se borran las copias de respaldo en `BACKUP-SRV`. |
| D-3 | Exfiltración de ~2,4 GB a `198.51.100.77`. |
| D-2 03:10 | Cifrado de archivos y nota de rescate. |
| D | El equipo de seguridad detecta el incidente y abre el caso. |

El estudiante **no recibe esta tabla**: la reconstruye capítulo a capítulo.

## 4. Los seis capítulos (mapa de retos)

Cada capítulo reemplaza a uno de los retos actuales conservando sus habilidades y su rúbrica de autocalificación.

| # | Capítulo | Habilidad que ya evalúa | Pregunta central para el estudiante |
|---|---|---|---|
| 1 | **La alerta** | Filtrar logs, IPs externas, bytes exfiltrados, gráfica MITRE | ¿Qué está hablando con el exterior y cuánto salió? |
| 2 | **¿Quién nos ataca?** | Limpiar y priorizar un feed IOC, score de riesgo | ¿Qué indicadores del feed corresponden a esta campaña y cuáles son ruido? |
| 3 | **La muestra** | Perfilar malware, C2, heatmap de capacidades | ¿Qué hace el programa que se ejecutó y a dónde llama? |
| 4 | **La línea de tiempo** | Kill chain, Paciente Cero, tiempo hasta el cifrado | ¿Cómo entró, por dónde se movió y cuánto tardó? |
| 5 | **Lo que dicen los informes** | NLP / extracción de entidades, grafo de relaciones | ¿Qué conexiones aparecen en los reportes que los logs no muestran? |
| 6 | **El próximo golpe** | Clasificador de dominios (ML) | ¿Qué otros dominios de Marea Gris deberíamos bloquear antes de que ataquen? |
| 7 | **Informe al comité** | Síntesis (nota ejecutiva en el campo de notas) | ¿Qué concluyes y qué debe hacer Aurora el lunes? |

El capítulo 7 es nuevo: no tiene código obligatorio, se evalúa con criterios sobre las conclusiones (cita al menos tres evidencias de capítulos distintos, nombra el vector inicial, propone mitigaciones priorizadas).

## 5. Datasets y cómo se conectan

Cada dataset tendrá **60 a 150 filas** (hoy tienen 10 a 15), con ruido realista: tráfico benigno, falsos positivos, duplicados, mayúsculas inconsistentes y algunos nulos para limpiar.

| Dataset | Cap. | Columnas clave |
|---|---|---|
| `aurora_netflow` | 1 | timestamp, src_ip, dst_ip, port, proto, bytes, action, host |
| `aurora_ioc_feed` | 2 | ioc, tipo, severidad, confianza, fuente, first_seen |
| `aurora_malware_lab` | 3 | archivo, hash, familia, c2_ip, c2_dominio, persistencia, evasión, mitre |
| `aurora_siem_events` | 4 | timestamp, host, usuario, fase, técnica, mitre, detalle |
| `aurora_reportes_texto` | 5 | id, texto (correos, tickets, informe forense), entidades |
| `aurora_dominios` | 6 | dominio, registrador, fecha_registro, ip, tld, etiqueta de ejemplo |

**Llaves compartidas (lo que permite asociar datos):**

- `203.0.113.45` (C2) aparece en `aurora_netflow` (dst_ip), `aurora_ioc_feed` (ioc), `aurora_malware_lab` (c2_ip) y `aurora_reportes_texto`.
- `198.51.100.77` (destino de exfiltración) enlaza netflow con los informes y el feed.
- `aurora-seguro-login.example` enlaza el phishing (capítulo 5) con el malware (capítulo 3) y los dominios del capítulo 6.
- `WKS-FIN-07` y `svc_backup` enlazan netflow, SIEM y los informes.

**Pistas escondidas que solo se ven cruzando datasets** (premian explorar):
- El feed marca la IP de exfiltración como "baja confianza", pero el netflow muestra 2,4 GB hacia ella: el estudiante debe reclasificarla.
- Un dominio del malware aparece en los informes con otro nombre (alias): se descubre cruzando texto y malware.
- Una IP "interna" del netflow es en realidad la estación del Paciente Cero.

## 5b. Datos distintos para cada estudiante

Para que cada quien llegue a **hallazgos propios** y el diálogo final tenga qué comparar, el caso se genera **por estudiante**, con una semilla derivada de su correo:

- **Misma historia, distintos hechos.** Todos viven el mismo incidente en Aurora, pero cambian los valores clave: la IP del C2, el volumen exfiltrado, qué host fue el Paciente Cero, cuánto tardó el cifrado, qué cuenta de servicio se abusó y qué dominios son alias de cuál.
- **Mismo mecanismo, distinta variante.** La estructura de cada capítulo es igual (el autocalificador funciona igual), pero el valor esperado se calcula sobre **el dataset de ese estudiante**. Copiar la respuesta del compañero no sirve.
- **Los datos de cada quien son estables:** si vuelve a abrir el reto, ve los mismos datos.
- **Variantes etiquetadas:** cada estudiante tiene un código de caso (por ejemplo `AUR-07`), que aparece en su reporte. Así, en el diálogo se puede comparar "mi variante AUR-07 entró por finanzas, la tuya por el portal: ¿qué patrón común hay?".
- **Hallazgos cualitativos distintos** (no solo números): cambian el vector inicial (adjunto, enlace, credencial reutilizada), qué defensa falló y cuál fue el punto ciego del equipo de seguridad. Eso da conclusiones y recomendaciones distintas.

## 5c. Muro de resultados de inteligencia

Cada estudiante cierra el caso publicando su reporte final en el **Muro de resultados de inteligencia** (ya construido): título del hallazgo, resumen ejecutivo, evidencia, nivel de confianza y recomendaciones priorizadas.

- El reporte es **privado hasta que el docente abre el muro**, para evitar copias mientras trabajan.
- Al abrirlo, todos ven todos y se hace el diálogo. El docente puede destacar reportes y exportar todo a CSV.
- En el capítulo 7 el reporte del muro reemplaza al campo de notas como entregable final.

## 6. Cómo es cada capítulo para el estudiante

Estructura fija, pensada para que el docente solo atienda preguntas puntuales:

1. **Expediente** (1 página): contexto del caso, qué se sabe hasta ahora, rol del estudiante ("analista de CTI de Aurora").
2. **Diccionario de datos:** significado de cada columna y qué datasets se pueden cruzar con cuál.
3. **Tu misión:** 3 a 5 preguntas guiadas + 1 pregunta abierta ("¿qué más te llama la atención?").
4. **Espacio libre:** el estudiante puede explorar, graficar y unir datasets sin límite (en el sandbox ya existente).
5. **Pistas en 3 niveles** (ya implementadas): orientación → método → esqueleto de código.
6. **Entrega con autocalificación:** puntaje por criterio, con retroalimentación inmediata y reentrega.
7. **Desbloqueo del siguiente capítulo** al sacar 60 o más (ya implementado).

## 7. Autocalificación y respuestas

- Los valores esperados **se calculan desde los datasets** con la misma técnica ya usada; no hay respuestas escritas a mano.
- Los datasets los genera un script con semilla fija, así son reproducibles y se pueden regenerar o ampliar.
- La retroalimentación nunca muestra la respuesta, solo qué criterio se cumplió y qué falta.

## 8. Qué se construye y en qué orden

1. Script generador de los 6 datasets (con la cronología y las llaves compartidas).
2. Capítulos 1 a 7 como retos nuevos con su expediente, diccionario, rúbrica y pistas.
3. Prueba: ejecutar la solución de referencia de cada capítulo contra la rúbrica (como hicimos con las pistas) para comprobar que da buena nota.
4. Publicarlos **como ruta nueva**, sin tocar los 6 retos actuales.

**Fuera del alcance de esta primera entrega** (siguiente etapa, ya conversada): la biblioteca de datasets por estudiante, las herramientas del admin para enriquecer datasets y la relación formal entre datasets en la interfaz.

## 9. Decisiones (estado)

**Confirmadas por el docente:** los 6 retos actuales quedan como práctica; las cuentas nuevas empiezan por el Caso Aurora; los textos van en español. Nombre del banco y del atacante: se asumen aprobados.

**Construido:** generador de datos por estudiante, 7 capítulos con expediente, pistas en 3 niveles y autocalificación, datasets cruzables en el sandbox, desbloqueo secuencial y Muro de Inteligencia.

### Preguntas originales (referencia)

1. **Nombre y sector:** ¿"Aurora Financiera" y banca están bien?
2. **Atacante ficticio:** ¿"Marea Gris" te sirve o prefieres otro nombre?
3. **Retos actuales:** ¿se mantienen como material de práctica o se retiran cuando salga el caso?
4. **Ruta para cuentas nuevas:** ¿pasan a empezar por el Caso Aurora en vez de los 6 retos actuales?
5. **Idioma de los textos del capítulo 5:** español (recomendado), o mezcla con inglés para parecerse a informes reales.

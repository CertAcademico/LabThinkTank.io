# Guía de uso — Plataforma CTI-Lab y Operación ORION

**Retos tácticos de Ciberinteligencia (CTI) · Grupo ORION · CCOCI**

> **SIN CLASIFICAR // USO EDUCATIVO.** Los escenarios, datasets y la Operación ORION son ejercicios de entrenamiento. Los datos son públicos o sintéticos y no corresponden a operaciones reales.

---

## 1. Propósito

Esta guía orienta a los integrantes del **grupo ORION** en el uso del **SandBox de Entrenamiento CTI**. El objetivo del entrenamiento es convertir información cruda de amenazas en **inteligencia evaluada y accionable**, siguiendo un método de análisis de tipo militar:

1. Recolectar y depurar la información.
2. Evaluar la fuente y la credibilidad (código Admiralty, OTAN).
3. Responder a los **Requerimientos Prioritarios de Inteligencia (PIR)** del mando.
4. Mapear la actividad adversaria a **MITRE ATT&CK**.
5. Definir la difusión con **TLP** y producir un informe para la toma de decisiones.

---

## 2. Acceso a la plataforma

| Elemento | Detalle |
|---|---|
| Dirección | **https://frontend-woad-one-20.vercel.app/** |
| Navegador recomendado | Chrome, Edge, Brave o Firefox actualizados (de escritorio) |
| Requisitos | Conexión a internet. No hay que instalar nada: Python se ejecuta en el navegador. |

### 2.1 Registro (primera vez)

1. Abre la dirección de la plataforma y pulsa **Registrarse**.
2. Escribe tu **nombre completo** y tu **correo electrónico**.
3. En **Grupo**, verifica que esté seleccionado **ORION**.
4. Crea una **contraseña de al menos 10 caracteres que combine letras y números** (no puede contener tu usuario de correo) y confírmala. Puedes cambiarla después con **🔑 Cambiar contraseña**, en el menú lateral.
5. Pulsa **Crear cuenta →** y luego inicia sesión con tu correo y tu contraseña.

Al registrarte en ORION recibes automáticamente los **10 retos tácticos** del grupo y el acceso al **Canal del grupo**.

> El registro con correos personales (Gmail, Hotmail u otros) estuvo habilitado solo durante la jornada de inscripción. Si no alcanzaste a registrarte, solicita tu alta al instructor.

### 2.2 Inicio de sesión

1. En la pantalla principal, pulsa **Iniciar sesión**.
2. Escribe tu correo y tu contraseña y pulsa **Entrar al Lab →**.

**Buenas prácticas:**
- No compartas tu cuenta ni tu contraseña. Cada entrega se califica de forma individual.
- Cierra la sesión en equipos compartidos.
- Si ves una versión antigua de la página, recarga con **Ctrl+Shift+R** (Windows) o **Cmd+Shift+R** (Mac).

---

## 3. Recorrido por la plataforma

El menú lateral agrupa los módulos. Los más usados en el entrenamiento ORION son:

| Módulo | Para qué sirve |
|---|---|
| **Threat Overview** | Panorama general de amenazas: indicadores, actores y actividad reciente. |
| **Threat Graph** | Grafo de relaciones entre actores, infraestructura, malware y víctimas. |
| **AI Copilot** | Asistente de análisis: explica conceptos, TTPs y resultados. Úsalo como apoyo, no como respuesta final. |
| **ATT&CK Matrix** | Matriz MITRE ATT&CK para ubicar tácticas y técnicas. |
| **Timeline** | Línea de tiempo de eventos para reconstruir una intrusión. |
| **IOC / IOA Board** | Tablero de indicadores de compromiso (IOC) y de ataque (IOA). |
| **Intel Feeds** | Fuentes de inteligencia abiertas (OSINT) integradas. |
| **CTI Toolkit** | Utilidades de analista: genera paquetes de indicadores para compartir (TAXII, MISP, OpenCTI). |
| **Sandbox Lab** | Laboratorio guiado de Python. Incluye el track **🎖️ Militar · ORION**. |
| **Mis Retos** | Tus 10 retos tácticos y el **Canal del grupo ORION**. |
| **Mi Tablero** | Tu avance, calificaciones e insignias. |
| **Muro de Inteligencia** | Publicación de hallazgos para compartirlos con el grupo, cuando el instructor lo habilite. |

---

## 4. Entrenamiento previo: Sandbox Lab · Militar · ORION

Antes del primer reto, completa la lección **"Instrucciones para analizar información de Ciberinteligencia ORION"**:

1. Abre **Sandbox Lab** en el menú.
2. Selecciona la pestaña **🎖️ Militar · ORION**.
3. Lee la explicación, pulsa **▶ Ejecutar** y analiza el resultado.

La lección simula un centro de ciberdefensa que recibe 10 reportes sobre una campaña contra el sector defensa. Aprenderás a:

### 4.1 Evaluar la fuente (código Admiralty — STANAG 2511)

| Confiabilidad de la fuente | | Credibilidad de la información | |
|---|---|---|---|
| **A** | Totalmente confiable | **1** | Confirmada por otras fuentes |
| **B** | Usualmente confiable | **2** | Probablemente cierta |
| **C** | Medianamente confiable | **3** | Posiblemente cierta |
| **D** | Usualmente no confiable | **4** | Dudosa |
| **E** | No confiable | **5** | Improbable |
| **F** | No se puede juzgar | **6** | No se puede juzgar |

**Regla del ejercicio:** solo es utilizable la información con fuente **A–C** y credibilidad **1–3**. El resto se descarta o se marca para más recolección.

### 4.2 Alinear con los PIR

Cada reporte debe responder a una necesidad del mando. Por ejemplo:

- **PIR-1:** ¿Quién apunta al personal y a la cadena logística?
- **PIR-2:** ¿Qué vulnerabilidades perimetrales están explotando?
- **PIR-3:** ¿Hay actividad activa dentro de la red propia?

### 4.3 Clasificar la difusión (TLP)

| TLP | Difusión |
|---|---|
| **TLP:RED** | Solo para los destinatarios nombrados. Ejemplo: actividad dentro de la red propia. |
| **TLP:AMBER** | La organización del destinatario, según necesidad de conocer. |
| **TLP:GREEN** | La comunidad o el sector, sin publicación abierta. |
| **TLP:CLEAR** | Sin restricción. |

### 4.4 Producto de inteligencia

Para cada PIR redacta: **hallazgo → evaluación (p. ej. A1, B2) → TTP (ATT&CK) → TLP → acción recomendada** (bloquear, cazar, alertar o requerir más recolección).

---

## 5. Cómo resolver un reto

1. Entra a **Mis Retos** y abre un reto.
2. Lee el **Objetivo** (los pasos numerados) y los **Criterios** (la ponderación de la nota).
3. Espera el mensaje *"Cargando entorno Python + dataset del reto..."*. Cuando termine, tendrás disponibles:
   - `challenge_df`: el dataset del reto (DataFrame de pandas).
   - `ioc_df`: el feed de indicadores de la plataforma.
   - `uploaded_df`: un dataset propio, si subes uno con **Subir un dataset** (CSV, JSON o TSV, máx. 5 MB).
4. Escribe tu código y pulsa **▶ Ejecutar** (o **Ctrl+Enter**). Las gráficas que generes con `plt.show()` se muestran en el panel de salida y se adjuntan a la entrega.
5. Si te bloqueas, usa **Pedir pista**. Las pistas son graduales: la primera orienta y la última muestra el mínimo para aprobar. Se registra cuántas pistas usaste.
6. Completa **Notas para el docente**: metodología usada, hallazgos clave, evaluación de fuentes y recomendaciones.
7. Si el reto lo pide, adjunta tu informe en **Documento adjunto** (PDF o DOCX).
8. Pulsa **Entregar análisis**. Verás el resultado y la retroalimentación de tu entrega.

**Calificación**
- La **nota mínima para aprobar es 50/100**.
- Puedes **volver a entregar** para mejorar. Si el instructor ya calificó el reto, su nota se conserva.
- Cada reto otorga una **insignia** al alcanzar el puntaje indicado.

---

## 6. Los 10 retos tácticos ORION

Resuélvelos en orden: la dificultad crece de **básico** a **avanzado**. En los retos 6 a 10, los objetivos están marcados por rol (**[AD]** Analista de Datos, **[CS]** Ciberseguridad, **[CD]** Ciencia de Datos, **[ML]** Machine Learning). En ORION **cada integrante resuelve todos los roles** de forma individual.

### Reto 01 — Caza de IOCs: APT28 Fancy Bear
- **Nivel:** Básico · **Insignia:** Threat Hunter (70 pts)
- **Dataset:** Logs de red — APT28 Fancy Bear
- **Misión:** identificar los indicadores de compromiso de un actor estatal, mapear sus técnicas y reconstruir el ataque.
- **Tareas:** filtrar eventos de APT28; identificar las IP únicas de C2; calcular los bytes exfiltrados; graficar las técnicas ATT&CK por frecuencia; construir el timeline de fases.
- **Criterios:** análisis técnico 40 % · visualizaciones 30 % · mapeo MITRE 30 %.

### Reto 02 — Campaña Ransomware LockBit 3.0
- **Nivel:** Intermedio · **Insignia:** SOC Analyst (85 pts)
- **Dataset:** Campaña Ransomware — LockBit 3.0
- **Misión:** reconstruir la cadena de ataque (kill chain) completa, desde la intrusión hasta el cifrado.
- **Tareas:** ordenar los eventos por fase; identificar el *Patient Zero*; mapear el movimiento lateral; diagramar la kill chain (Cyber Kill Chain o ATT&CK); calcular el tiempo desde la intrusión hasta el cifrado.
- **Criterios:** kill chain 35 % · Patient Zero 25 % · visualizaciones 25 % · mitigación 15 %.

### Reto 03 — Detección de phishing con Machine Learning
- **Nivel:** Avanzado · **Insignia:** ML Practitioner (75 pts)
- **Dataset:** Campaña de phishing — Credential Harvesting FIN7
- **Misión:** clasificar dominios legítimos y maliciosos para anticipar campañas de suplantación.
- **Tareas:** crear variables OSINT del dominio (longitud, guiones, TLD, antigüedad, confianza); entrenar un clasificador (Random Forest o regresión logística); evaluar con accuracy, precision, recall y F1; identificar las 3 variables más importantes; graficar la matriz de confusión.
- **Criterios:** feature engineering 30 % · accuracy ≥ 75 % 30 % · visualizaciones 20 % · código limpio 20 %.

### Reto 04 — Enriquecimiento y priorización del feed de IOC
- **Nivel:** Básico · **Insignia:** Analista Junior (70 pts)
- **Dataset:** Feed IOC enriquecido — CTI-Lab
- **Misión:** simular el flujo de trabajo de un analista: depurar, priorizar e informar al mando.
- **Tareas:** limpiar nulos y normalizar tipos; crear un puntaje de riesgo (severidad + confianza); clasificar en Crítico, Alto, Medio y Bajo; agrupar por actor; graficar el Top 5 de actores, la distribución por país y los IOC por tipo.
- **Criterios:** limpieza 20 % · puntaje de riesgo 30 % · visualizaciones 30 % · reporte ejecutivo 20 %.

### Reto 05 — Perfilado de malware: AgentTesla y Emotet
- **Nivel:** Intermedio · **Insignia:** Analista de Amenazas (80 pts)
- **Dataset:** Análisis de malware — AgentTesla y Emotet
- **Misión:** perfilar familias de malware y correlacionar su infraestructura de red.
- **Tareas:** agrupar las muestras por familia; extraer las IP de C2 y los dominios únicos; mapear técnicas MITRE por familia; construir un heatmap de capacidades por familia; identificar patrones de persistencia y evasión.
- **Criterios:** agrupación 20 % · IOC 20 % · heatmap MITRE 25 % · hallazgos de comportamiento 20 % · reproducibilidad 15 %.

### Reto 06 — Perfilado avanzado de familias de malware
- **Nivel:** Avanzado · **Insignia:** ML Practitioner (75 pts)
- **Dataset:** Análisis de malware (AgentTesla, Emotet, Cobalt Strike)
- **Misión:** construir un sistema que clasifique muestras desconocidas por familia según su comportamiento.
- **Tareas:** perfilar y depurar el dataset **[AD]**; mapear las TTP que diferencian cada familia y la capacidad de mayor riesgo operativo **[CS]**; entrenar y comparar clasificadores **[ML]**.
- **Fuentes de referencia:** MalwareBazaar, Malpedia, VX Underground, VirusShare, theZoo.
- **Criterios:** clasificador 30 % · features de TTP 25 % · visualizaciones 20 % · informe técnico de 2 a 3 páginas 25 %.

### Reto 07 — Inteligencia y enriquecimiento de feeds
- **Nivel:** Intermedio · **Insignia:** Threat Hunter (70 pts)
- **Dataset:** Feed IOC enriquecido — CTI-Lab
- **Misión:** integrar varias fuentes de IOC en un pipeline con deduplicación, puntaje y correlación cruzada.
- **Tareas:** deduplicar, normalizar y bloquear registros de baja calidad **[AD]**; diseñar el puntaje de riesgo y la red de relaciones IOC↔actor **[CD]**; correlacionar con actores y MITRE **[CS]**.
- **Fuentes de referencia:** OTX, ThreatFox, URLhaus, AbuseIPDB, OpenPhish, PhishTank, FeodoTracker, MISP, IBM X-Force, Pulsedive.
- **Criterios:** normalización 20 % · puntaje 25 % · correlación 20 % · red de relaciones 20 % · reporte 15 %.

### Reto 08 — Mapeo de TTP y detección de comportamiento (IoA)
- **Nivel:** Avanzado · **Insignia:** SOC Analyst (80 pts)
- **Dataset:** MITRE ATT&CK — TTP por grupo APT
- **Misión:** identificar patrones de comportamiento adversario y proponer detecciones.
- **Tareas:** calcular la frecuencia por táctica y técnica, y la diversidad por APT **[AD]**; analizar el solapamiento entre APT y proponer reglas **Sigma** y contramedidas **D3FEND** **[CS]**; construir un heatmap de TTP **[CD]**.
- **Fuentes de referencia:** MITRE ATT&CK, D3FEND, Atomic Red Team, SigmaHQ.
- **Criterios:** análisis 25 % · heatmap 25 % · reglas Sigma 25 % · detectabilidad 25 %.

### Reto 09 — Clasificación de tráfico de botnet
- **Nivel:** Avanzado · **Insignia:** Analista de Amenazas (80 pts)
- **Dataset:** Botnet Traffic — flujos de red CTU-13
- **Misión:** distinguir tráfico benigno de tráfico de botnet e identificar las familias Neris, Rbot y Virut.
- **Tareas:** explorar la distribución por clase y familia **[AD]**; crear variables de red (puertos, protocolos, duración, ratios) **[CD]**; entrenar Random Forest y Decision Tree con **F1 ≥ 0,80** **[ML]**.
- **Fuentes de referencia:** CTU-13, Bot-IoT, Feodo Tracker, Stratosphere IPS.
- **Criterios:** features 25 % · clasificador F1 ≥ 0,80 30 % · análisis por familia 25 % · visualizaciones 20 %.

### Reto 10 — Inteligencia de amenazas ransomware y análisis de campañas
- **Nivel:** Intermedio · **Insignia:** SOC Analyst (75 pts)
- **Dataset:** Ransomware.live — víctimas y grupos activos
- **Misión:** identificar tendencias, grupos más activos y sectores más afectados, y recomendar controles.
- **Tareas:** analizar las víctimas por grupo, sector y país **[AD]**; correlacionar con TTP e IOC de LockBit **[CS]**; construir la línea temporal de actividad **[CD]**.
- **Fuentes de referencia:** Ransomware.live, MalwareBazaar, Malpedia, ThreatFox, ID Ransomware, NoMoreRansom, VirusTotal, YARAify.
- **Criterios:** análisis estadístico 25 % · correlación con TTP 25 % · visualizaciones 25 % · mitigación 25 %.

### Ruta sugerida

| Fase | Retos | Enfoque |
|---|---|---|
| **I. Fundamentos** | 01, 04 | Depuración de datos, IOC y priorización |
| **II. Análisis de campañas** | 02, 05, 10 | Kill chain, malware y ransomware |
| **III. Comportamiento adversario** | 07, 08 | Correlación de fuentes, TTP y detección |
| **IV. Analítica avanzada** | 03, 06, 09 | Machine Learning aplicado a CTI |

En **Mis Retos** los retos aparecen ordenados por estas fases. Cada uno trae su ficha táctica (misión, metodología y dossier del dataset), la presentación del reto, pistas en 5 niveles, el asistente y el canal con el instructor.

### Escalafón e insignias militares

- **Grado:** se sube un grado por cada reto aprobado (50/100 o más): Recluta → Soldado → Cabo Tercero → Cabo Segundo → Sargento Segundo → Sargento Viceprimero → Subteniente → Teniente → Capitán → Mayor → Coronel.
- **Distintivo del reto:** cada reto otorga un distintivo con el nombre de su operación (por ejemplo, Distintivo «Oso de Fuego» en el Reto 01) al alcanzar la nota indicada en su tarjeta (entre 70 y 85 puntos).
- Puedes volver a entregar un reto para subir tu nota, tu grado y ganar el distintivo.

---

## 7. Canal del grupo ORION (chat con el instructor)

En **Mis Retos**, arriba, encontrarás el **💬 Canal del grupo ORION**. Lo comparten el instructor y todos los integrantes del grupo.

- Escribe tu mensaje y pulsa **Enviar** (o **Enter**). Con **Shift+Enter** haces un salto de línea.
- Los mensajes del instructor aparecen resaltados como **🎖️ Instructor**.
- El canal se actualiza solo cada pocos segundos.
- Máximo 2.000 caracteres por mensaje.

**Normas del canal**
- Úsalo para dudas de método, del enunciado o de la plataforma. **No publiques soluciones completas ni flags.**
- Mantén un lenguaje profesional. El instructor puede moderar y borrar mensajes.
- Trata lo que se comparte en el canal como **TLP:AMBER**: queda dentro del grupo.
- No compartas datos personales, credenciales ni información institucional real.

---

## 8. Formato recomendado del informe

Usa esta estructura en tus **Notas para el docente** o en el documento adjunto:

```
1. RESUMEN EJECUTIVO (BLUF)   — 3 a 5 líneas con la conclusión principal.
2. PIR QUE RESPONDE            — qué pregunta del mando atiende el análisis.
3. FUENTES Y EVALUACIÓN        — fuente, código Admiralty (p. ej. B2) y justificación.
4. HALLAZGOS                   — datos clave, IOC, TTP (ATT&CK) y gráficas.
5. EVALUACIÓN DE AMENAZA       — actor, capacidad, intención e impacto.
6. RECOMENDACIONES             — bloquear / cazar / alertar / más recolección.
7. DIFUSIÓN                    — TLP asignado y destinatarios.
```

---

## 9. Problemas frecuentes

| Situación | Solución |
|---|---|
| "Error cargando Python" | Verifica tu conexión y recarga la página. La primera carga puede tardar unos segundos. |
| No veo mis retos | Confirma que te registraste en el grupo ORION. Si no, avisa por el canal o al instructor. |
| La página se ve antigua | Recarga con Ctrl+Shift+R (Cmd+Shift+R en Mac). |
| Olvidé mi contraseña | Solicita al instructor el restablecimiento. |
| La entrega no se envía | Revisa que el código se haya ejecutado sin errores y vuelve a intentarlo. |

---

## 10. Glosario

| Término | Significado |
|---|---|
| **CTI** | Cyber Threat Intelligence: inteligencia de amenazas cibernéticas. |
| **IOC** | Indicador de compromiso: IP, dominio, hash o URL asociado a actividad maliciosa. |
| **IoA** | Indicador de ataque: comportamiento que revela una intrusión en curso. |
| **TTP** | Tácticas, técnicas y procedimientos del adversario. |
| **MITRE ATT&CK** | Marco de referencia de las técnicas adversarias. |
| **C2** | Infraestructura de comando y control del adversario. |
| **PIR** | Requerimiento Prioritario de Inteligencia. |
| **Código Admiralty** | Sistema OTAN (STANAG 2511) para evaluar la fuente (A–F) y la información (1–6). |
| **TLP** | Traffic Light Protocol: control de la difusión de la información. |
| **Kill chain** | Fases de una intrusión, desde el reconocimiento hasta la acción sobre el objetivo. |
| **Sigma** | Formato abierto de reglas de detección para SIEM. |
| **D3FEND** | Marco MITRE de contramedidas defensivas. |
| **BLUF** | *Bottom Line Up Front*: la conclusión va primero. |

---

*SandBox de Entrenamiento CTI · Operación ORION · Uso exclusivamente educativo.*

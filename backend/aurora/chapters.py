"""Capítulos del Caso Aurora: expediente, pistas y rúbrica (calculada sobre los datos de cada estudiante)."""
from __future__ import annotations

import re

import grading as g

PATH_TITLES = [
    "Caso Aurora 1 — La alerta",
    "Caso Aurora 2 — ¿Quién nos ataca?",
    "Caso Aurora 3 — La muestra",
    "Caso Aurora 4 — La línea de tiempo",
    "Caso Aurora 5 — Lo que dicen los informes",
    "Caso Aurora 6 — El próximo golpe",
    "Caso Aurora 7 — El agente autónomo",
    "Caso Aurora 8 — Informe al comité",
]
# Datasets visibles acumulativamente: el capítulo n puede cruzar los de los capítulos ≤ n.
CHAPTER_DATASET = ["netflow", "ioc", "malware", "siem", "reportes", "dominios", "telemetria", None]

INTRO = (
    "Eres analista de inteligencia de amenazas (CTI) en Aurora Financiera, un banco regional ficticio. "
    "Hace unos días el banco sufrió un incidente y el comité directivo se reúne el lunes. "
    "Todos los datos del caso son ficticios y son solo tuyos: tu variante es distinta a la de tus compañeros, "
    "así que tus conclusiones también lo serán. Cruza las fuentes; ninguna cuenta la historia completa."
)

CHAPTERS = [
    dict(
        description=INTRO + "\n\nCAPÍTULO 1 · La alerta. El SOC detectó tráfico anómalo saliendo de la red de Aurora. "
        "Tienes el registro de flujos de red (aurora_netflow). Aún no sabemos quién es el atacante ni qué se llevó.",
        objective="1) Encuentra la IP externa con la que un equipo interno se comunica con una periodicidad sospechosa (beacon) y cuenta cuántas conexiones permitidas hubo. "
                  "2) Identifica la IP externa hacia la que salió una cantidad enorme de datos y calcula el total de bytes que salieron con acción ALLOW. "
                  "3) Ordena los eventos en el tiempo y grafica el volumen de bytes por hora o por destino. "
                  "4) Pregunta abierta: ¿qué más te llama la atención en el tráfico?",
        criteria="IP del C2 (20%) + Conteo de beacons (20%) + Bytes exfiltrados (20%) + IP de exfiltración (20%) + Gráfica (10%) + Línea de tiempo (10%)",
        difficulty="básico",
        hints=[
            "Un beacon es una conexión que se repite cada pocos segundos hacia el mismo destino externo. Cuenta los destinos fuera de 10.20.x.x y fíjate en cuáles se repiten decenas de veces con pocos bytes. "
            "La exfiltración es lo contrario: pocas conexiones pero con muchísimos bytes.",
            "Beacons: aurora_netflow.groupby('dst_ip').size().sort_values(ascending=False). Filtra action == 'ALLOW' para no contar los bloqueos. "
            "Exfiltración: groupby('dst_ip')['bytes'].sum() solo con ALLOW y quédate con el destino externo de mayor volumen. Ordena con pd.to_datetime(timestamp).",
            "import matplotlib.pyplot as plt\ndf = aurora_netflow.copy()\ndf['t'] = pd.to_datetime(df['___'])\npermitidos = df[df['action'] == '___']\n"
            "print(permitidos.groupby('dst_ip').size().sort_values(ascending=False).head())\n"
            "print(permitidos.groupby('dst_ip')['bytes'].___().sort_values(ascending=False).head())\n"
            "permitidos.groupby('dst_ip')['bytes'].sum().sort_values().tail(5).plot(kind='barh'); plt.show()",
        ],
    ),
    dict(
        description="CAPÍTULO 2 · ¿Quién nos ataca? Con las dos IPs del capítulo anterior, consulta el feed de indicadores (aurora_ioc_feed). "
        "El feed es ruidoso: tiene duplicados, mayúsculas inconsistentes, confianzas vacías y miles de indicadores que no tienen que ver con nuestro caso. "
        "Cuidado: un feed comunitario puede estar equivocado.",
        objective="1) Limpia el feed (duplicados, tipos y nulos). 2) Crea una puntuación de riesgo con severidad y confianza y clasifícala en Crítico, Alto, Medio y Bajo. "
                  "3) Localiza los indicadores de TU campaña: el feed tiene una columna campana y la IP del C2 que ya conoces te dice cuál buscar (aparecerán también un dominio de phishing y un dominio del C2). "
                  "4) Revisa cómo el feed califica la IP de exfiltración y decide si su clasificación es correcta; justifícalo. 5) Grafica la distribución por nivel y por tipo.",
        criteria="Limpieza (15%) + Indicadores de la campaña (20%) + Reclasificación justificada (25%) + Score de riesgo (15%) + Niveles (10%) + Gráficas (15%)",
        difficulty="intermedio",
        hints=[
            "Primero limpia: unifica mayúsculas en tipo y severidad, elimina duplicados y decide qué hacer con las confianzas vacías. "
            "Después mira los indicadores que ya conoces por el capítulo 1: ¿cómo los describe el feed? Si algo no cuadra con lo que viste en la red, confía en tus datos propios.",
            "Busca primero tu IP del C2 en el feed y mira su valor en la columna campana: todos los indicadores con esa misma campaña son tuyos. Compara además qué dice el feed de tu IP de exfiltración. Para el riesgo, mapea severidad a número (critical=4 … low=1) y multiplica por confianza/100. "
            "Clasifica con pd.cut. Un indicador de 'baja confianza' que mueve gigas hacia afuera merece subir de nivel.",
            "import matplotlib.pyplot as plt\nf = aurora_ioc_feed.copy()\nf['tipo'] = f['tipo'].str.___()\nf['severidad'] = f['severidad'].str.lower()\nf = f.drop_duplicates()\n"
            "f['confianza'] = f['confianza'].fillna(f['confianza'].median())\nsev = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}\n"
            "f['riesgo'] = f['severidad'].map(sev) * f['confianza'] / 100\nf['nivel'] = pd.cut(f['riesgo'], bins=[0, ___, ___, ___, 5], labels=['Bajo', 'Medio', 'Alto', 'Crítico'])\n"
            "print(f['nivel'].value_counts())\n# Ahora cruza con TUS indicadores: f[f['ioc'].isin([...])]\nf['nivel'].value_counts().plot(kind='bar'); plt.show()\nf['tipo'].value_counts().plot(kind='bar'); plt.show()",
        ],
    ),
    dict(
        description="CAPÍTULO 3 · La muestra. El equipo forense recuperó varios archivos sospechosos del equipo donde empezó todo y los analizó en un sandbox (aurora_malware_lab). "
        "No todos pertenecen a nuestro incidente: hay familias de otros casos mezcladas.",
        objective="1) Agrupa las muestras por familia e identifica cuáles pertenecen a TU campaña (pista: su servidor de mando coincide con lo que viste en la red). "
                  "2) Extrae el servidor de mando (IP y dominio) y el mecanismo de persistencia y de evasión de tu familia. "
                  "3) Mapea las técnicas MITRE de tu familia. 4) Cruza con aurora_netflow: ¿la IP del C2 de la muestra es la misma que viste comunicándose en la red?",
        criteria="Familia identificada (20%) + Servidor de mando (20%) + Persistencia (15%) + Evasión (10%) + Técnicas MITRE (15%) + Cruce con NetFlow (20%)",
        difficulty="intermedio",
        hints=[
            "Muchas muestras, una sola campaña. Busca las que llaman a la misma IP que viste en el capítulo 1. Las demás son de otros incidentes y no deben entrar a tu conclusión.",
            "aurora_malware_lab[aurora_malware_lab['c2_ip'] == ip_c2] te deja solo tus muestras. La columna mitre guarda códigos separados por coma: .str.split(',').explode(). "
            "El cruce con la red es un merge o un isin entre c2_ip de malware y dst_ip de netflow.",
            "m = aurora_malware_lab\nmias = m[m['c2_ip'] == '___']\nprint(mias[['archivo', 'familia', 'c2_dominio', 'persistencia', 'evasion']])\n"
            "print(mias.assign(mitre=mias['mitre'].str.split(',')).explode('mitre')['mitre'].unique())\n"
            "en_red = aurora_netflow[aurora_netflow['dst_ip'].isin(mias['c2_ip'])]\nprint('conexiones en la red al C2 de la muestra:', len(en_red))",
        ],
    ),
    dict(
        description="CAPÍTULO 4 · La línea de tiempo. El SIEM (aurora_siem_events) registra decenas de alertas, casi todas inofensivas. "
        "Las del incidente son de severidad alta o crítica. Reconstruye cómo entró el atacante, por dónde se movió y cuánto tardó en cifrar.",
        objective="1) Filtra las alertas high y critical y ordénalas en el tiempo. 2) Identifica el Paciente Cero (host del primer evento del incidente) y por qué vector entró. "
                  "3) Mapea la ruta de movimiento lateral (hosts en orden) y la cuenta de servicio abusada. "
                  "4) Calcula cuántos minutos pasaron desde la primera alerta hasta el cifrado de archivos. 5) Agrupa por fase y arma tu kill chain.",
        criteria="Paciente Cero (20%) + Tiempo hasta el cifrado (20%) + Ruta lateral (20%) + Cuenta abusada (15%) + Vector de entrada (15%) + Agrupación por fase (10%)",
        difficulty="intermedio",
        hints=[
            "Quédate solo con severidad alta o crítica: ahí está el incidente; el resto es ruido. Ordena por tiempo: el primer evento es la puerta de entrada y el de cifrado (T1486) es el final.",
            "ev = aurora_siem_events[aurora_siem_events['severidad'].isin(['high', 'critical'])] con pd.to_datetime y sort_values. "
            "Camino de hosts: ev['host'].drop_duplicates().tolist(). Tiempo: resta el ts del evento con mitre T1486 menos el primer ts. El vector sale del campo detalle del primer evento.",
            "ev = aurora_siem_events.copy()\nev['ts'] = pd.to_datetime(ev['___'])\nev = ev[ev['severidad'].isin(['high', 'critical'])].sort_values('ts')\n"
            "print('Paciente Cero:', ev.iloc[0]['___'])\nprint(ev.iloc[0]['detalle'])\nprint('Ruta:', ' -> '.join(ev['host'].drop_duplicates()))\n"
            "print('Cuenta usada:', ev[ev['fase'] == 'Lateral Movement']['usuario'].unique())\ncifrado = ev[ev['mitre'] == '___']['ts'].iloc[0]\n"
            "print('Minutos hasta el cifrado:', (cifrado - ev['ts'].min()).total_seconds() / 60)\nprint(ev.groupby('fase', sort=False).size())",
        ],
    ),
    dict(
        description="CAPÍTULO 5 · Lo que dicen los informes. Los correos, tickets, chats del SOC e informes forenses (aurora_reportes_texto) mencionan datos que los logs no muestran. "
        "Ahí aparece un dominio con otro nombre y una duda sobre una IP. Extrae las entidades y relaciónalas.",
        objective="1) Extrae del texto las entidades clave (IPs, hosts, dominios, cuentas, familia de malware). 2) Resuelve el alias: dos dominios distintos pueden ser el mismo actor; demuéstralo con los textos. "
                  "3) Construye las relaciones entre entidades (por ejemplo, un grafo) y señala qué dato de los informes contradice o completa el feed. "
                  "4) Escribe en las notas tu hallazgo principal de este capítulo.",
        criteria="Entidades extraídas (25%) + Alias resuelto (25%) + Relaciones o grafo (15%) + Contradicción del feed (15%) + Reporte en notas (20%)",
        difficulty="avanzado",
        hints=[
            "Las entidades siguen patrones: IPs (números con puntos), hosts (MAYÚSCULAS con guiones), dominios que terminan en .example y cuentas que empiezan con svc_. Las expresiones regulares son tu mejor herramienta.",
            "import re; re.findall(r'\\b\\d{1,3}(?:\\.\\d{1,3}){3}\\b', texto) para IPs; r'[a-z0-9-]+\\.example' para dominios; r'svc_\\w+' para cuentas. "
            "Aplica .apply sobre aurora_reportes_texto['texto']. Para el alias, busca los textos donde aparecen dos dominios juntos. Para el grafo: networkx con una arista por cada par de entidades que comparten un texto.",
            "import re, networkx as nx\nt = aurora_reportes_texto['texto']\nips = sorted(set(sum(t.apply(lambda s: re.findall(r'\\b\\d{1,3}(?:\\.\\d{1,3}){3}\\b', s)).tolist(), [])))\n"
            "doms = sorted(set(sum(t.apply(lambda s: re.findall(r'[a-z0-9-]+\\.___', s)).tolist(), [])))\ncuentas = sorted(set(sum(t.apply(lambda s: re.findall(r'svc_\\w+', s)).tolist(), [])))\n"
            "print(ips, doms, cuentas)\nG = nx.Graph()\nfor s in t:\n    ents = re.findall(r'\\b\\d{1,3}(?:\\.\\d{1,3}){3}\\b|[a-z0-9-]+\\.example|svc_\\w+|[A-Z]{2,}-[A-Z0-9-]+', s)\n"
            "    for a in ents:\n        for b in ents:\n            if a < b: G.add_edge(a, b)\nprint(G.number_of_nodes(), G.number_of_edges())",
        ],
    ),
    dict(
        description="CAPÍTULO 6 · El próximo golpe. Marea Gris registra dominios nuevos continuamente. En aurora_dominios hay dominios etiquetados (malicioso o benigno) y otros candidatos sin etiqueta. "
        "Si entrenas bien un clasificador, podrás decirle al banco qué dominios bloquear antes de que ataquen.",
        objective="1) Crea features del dominio (longitud, guiones, tld, días desde el registro, registrador). 2) Entrena un clasificador con los dominios etiquetados y evalúalo (accuracy, precision, recall, F1). "
                  "3) Aplica el modelo a los candidatos sin etiqueta y entrega la lista de dominios que recomiendas bloquear (y por qué los demás no). 4) Visualiza la matriz de confusión.",
        criteria="Clasificador (20%) + Features (15%) + Métricas (10%) + Accuracy ≥ 75% (10%) + Candidatos a bloquear (30%) + Matriz de confusión (10%) + Notas (5%)",
        difficulty="avanzado",
        hints=[
            "Entrena solo con las filas que tienen etiqueta; las que no la tienen son justo las que debes predecir. Una señal fuerte es que varios dominios maliciosos comparten la misma IP de alojamiento y se registraron hace muy pocos días.",
            "lab = aurora_dominios[aurora_dominios['etiqueta'].notna()]; cand = aurora_dominios[aurora_dominios['etiqueta'].isna()]. "
            "X con longitud, guiones, dias_desde_registro y tld (astype('category').cat.codes). Entrena RandomForestClassifier, valida con train_test_split y predice sobre cand.",
            "import matplotlib.pyplot as plt\nfrom sklearn.ensemble import RandomForestClassifier\nfrom sklearn.model_selection import train_test_split\n"
            "from sklearn.metrics import classification_report, confusion_matrix, accuracy_score\nd = aurora_dominios.copy()\nd['tld'] = d['tld'].astype('category').cat.codes\n"
            "cols = ['longitud', 'guiones', 'dias_desde_registro', 'tld']\nlab, cand = d[d['etiqueta'].notna()], d[d['etiqueta'].isna()]\n"
            "Xtr, Xte, ytr, yte = train_test_split(lab[cols], lab['etiqueta'] == '___', test_size=0.3, random_state=42)\nm = RandomForestClassifier(random_state=42).fit(Xtr, ytr)\n"
            "p = m.predict(Xte)\nprint('accuracy', accuracy_score(yte, p)); print(classification_report(yte, p, zero_division=0))\n"
            "cm = confusion_matrix(yte, p); plt.imshow(cm); plt.colorbar(); plt.show()\n"
            "print('BLOQUEAR:', aurora_dominios.loc[cand.index[m.predict(cand[cols])], 'dominio'].tolist())",
        ],
    ),
    dict(
        description="CAPÍTULO 7 · El agente autónomo. La revisión forense encontró algo inquietante: parte del reconocimiento fue demasiado rápido, demasiado sistemático y a horas absurdas para un operador humano. "
        "Hoy los atacantes usan agentes autónomos con IA (modelos de lenguaje con herramientas): planifican, ejecutan, leen el error y se corrigen solos, sin cansarse ni dormir. "
        "Tienes la telemetría de sesiones del banco (aurora_telemetria_sesiones). Hay tres tipos de sesión: personas, automatización legítima del banco (monitoreo, respaldos, reportes) y agentes de IA. "
        "Ningún campo te dice cuál es cuál: tendrás que descubrirlo con detección de anomalías.",
        objective="1) Explora la línea base: ¿cómo se comporta una sesión humana normal (ritmo, errores, horario, variedad de acciones)? "
                  "2) Construye un detector de anomalías sin etiquetas (Isolation Forest, LOF u otra técnica) sobre variables de comportamiento y marca las sesiones sospechosas. "
                  "3) Revisa lo marcado: no toda anomalía es un atacante. Separa la automatización legítima de los agentes de IA y justifícalo con las señales de comportamiento. "
                  "4) Entrega la lista de sesiones que recomiendas aislar y explica en las notas qué distingue a un agente de IA de una persona y de un script rígido.",
        criteria="Método de detección (15%) + Preparación de variables (10%) + Agentes encontrados (30%) + Precisión de la lista (15%) + Automatización legítima distinguida (15%) + Señales explicadas (15%)",
        difficulty="avanzado",
        hints=[
            "Piensa en cómo trabaja un agente de IA: actúa muy rápido, prueba muchas cosas distintas, se equivoca y corrige en segundos, y no respeta el horario de oficina. "
            "Una persona es más lenta, más irregular y se queda en lo conocido. Un script clásico es rápido y regular, pero repite siempre lo mismo.",
            "Escala las variables numéricas (StandardScaler) antes de comparar. IsolationForest(contamination=0.12) devuelve -1 para las sesiones anómalas. "
            "Usa variables de comportamiento: peticiones_por_min, intervalo_desv_s, comandos_distintos, errores_pct, reintento_tras_error_s, hora y paginas_distintas. No uses sesion ni cuenta.",
            "import pandas as pd\nfrom sklearn.ensemble import IsolationForest\nfrom sklearn.preprocessing import StandardScaler\nt = aurora_telemetria_sesiones.copy()\n"
            "cols = ['peticiones_por_min', 'intervalo_desv_s', 'comandos_distintos', 'errores_pct', 'reintento_tras_error_s', 'hora', 'paginas_distintas']\n"
            "X = StandardScaler().fit_transform(t[cols])\nt['anomala'] = IsolationForest(contamination=___, random_state=42).fit_predict(X) == -1\n"
            "marcadas = t[t['anomala']]\nprint(len(marcadas), 'sesiones marcadas')\nprint(marcadas[['sesion', 'cuenta', 'herramienta'] + cols].to_string())",
        ],
    ),
    dict(
        description="CAPÍTULO 8 · Informe al comité. Es el cierre. No hay que programar: usa lo que descubriste en los siete capítulos para escribir tu informe de inteligencia y publícalo en el "
        "Muro de resultados de inteligencia. Mañana el comité decide qué hacer, y tu variante del caso (código AUR-xxxx) será la base del diálogo con tus compañeros.",
        objective="En el campo de notas escribe un informe ejecutivo con: 1) cómo entró el atacante (vector), 2) qué hizo y por dónde se movió, 3) cuánto tardó y cuánto robó, "
                  "4) los indicadores clave (IPs, dominios, host, cuenta), 5) tu nivel de confianza y 6) al menos tres mitigaciones priorizadas. "
                  "Después publica el reporte en el Muro de Inteligencia.",
        criteria="Evidencias de varios capítulos (30%) + Vector de entrada (15%) + Cifras y tiempos (10%) + Mitigaciones (20%) + Extensión y claridad (10%) + Publicado en el muro (15%)",
        difficulty="avanzado",
        hints=[
            "Escribe para alguien que no es técnico: primero la conclusión, después la evidencia. Cada afirmación debe apoyarse en un dato concreto de tus capítulos (una IP, un host, una cifra).",
            "Estructura sugerida: Resumen (2 frases) · Cómo entraron · Qué hicieron (en orden) · Impacto (tiempo y datos) · Indicadores de compromiso · Confianza y límites · Recomendaciones priorizadas.",
            "Recomendaciones típicas, ordénalas por urgencia: bloquear los IOC del caso, aislar y reconstruir los equipos afectados, rotar credenciales y la cuenta de servicio abusada, "
            "restringir el movimiento lateral con segmentación, respaldos fuera de línea, autenticación multifactor y capacitación contra phishing.",
        ],
    ),
]


# ── Rúbricas ──────────────────────────────────────────────────────────────────

def _t(*vals):
    return g.has_terms(lambda r: [str(v) for v in vals])


def _bytes_forms(b: int):
    return (b, round(b / 1e6), round(b / 1e9, 1), round(b / 1e9, 2), round(b / 1e9, 3), round(b / 2**30, 2), round(b / 2**20))


def rubric(chapter: int, facts: dict, ctx: dict | None = None) -> list:
    f, ctx = facts, ctx or {}
    if chapter == 1:
        return [
            ("Identificaste la IP del servidor de mando (C2)", 20, _t(f["c2_ip"]), "Busca el destino externo al que un equipo se conecta con una periodicidad sospechosa."),
            ("Contaste las conexiones periódicas (beacons) permitidas", 20, g.has_num(f["beacons"], f["beacons"] + 1), "Cuenta las conexiones ALLOW hacia esa IP; ignora los bloqueos."),
            ("Calculaste los bytes que salieron hacia el exterior", 20, g.has_num(*_bytes_forms(f["exfil_bytes"])), "Suma los bytes con acción ALLOW del destino externo con mayor volumen."),
            ("Identificaste la IP de exfiltración", 20, _t(f["exfil_ip"]), "No es la del beacon: es el destino que recibió gigas de datos."),
            ("Graficaste el tráfico", 10, g.plots_at_least(1), "Genera una gráfica de bytes por destino o por hora."),
            ("Ordenaste los eventos en el tiempo", 10, g.code_matches(r"sort_values|sorted\(|to_datetime|resample|groupby\(.*(hour|date)"), "Usa pd.to_datetime y ordena por timestamp."),
        ]
    if chapter == 2:
        return [
            ("Limpiaste el feed (duplicados, mayúsculas, nulos)", 15, g.code_matches(r"drop_duplicates"), "Elimina duplicados y unifica mayúsculas de tipo y severidad."),
            ("Localizaste los indicadores de tu campaña", 20, g.has_terms(lambda r: [f["c2_ip"], f["phish"], f["c2_domain"]], minimum=3), "Cruza con lo que viste en la red: C2, dominio de phishing y dominio del C2."),
            ("Reclasificaste la IP de exfiltración con justificación", 25,
             lambda s, r: min(_t(f["exfil_ip"])(s, r), g.text_matches(r"reclasific|subir|subí|elev|cr[ií]tic|alta\b|contradic|baja confianza|no coincide|enga[ñn]")(s, r)),
             "La IP de exfiltración figura con baja severidad. Menciónala y explica por qué debe subir de nivel."),
            ("Creaste un score de riesgo con severidad y confianza", 15, lambda s, r: 1.0 if all(re.search(k, s.code, re.I) for k in ("severidad", "confianza", r"riesgo|risk|score")) else 0.0, "Combina severidad y confianza en una columna de riesgo."),
            ("Clasificaste en Crítico, Alto, Medio y Bajo", 10, lambda s, r: min(1.0, sum(1 for k in (("crítico", "critico", "critical"), ("alto", "high"), ("medio", "medium"), ("bajo", "low")) if any(x in s.low for x in k)) / 4), "Imprime cuántos indicadores hay en cada nivel."),
            ("Graficaste la distribución", 15, g.plots_at_least(2), "Dos gráficas: por nivel y por tipo de indicador."),
        ]
    if chapter == 3:
        return [
            ("Identificaste la familia de tu campaña", 20, _t(f["family"]), "Filtra las muestras que llaman a la IP del C2 que ya conoces."),
            ("Extrajiste el servidor de mando (IP y dominio)", 20, _t(f["c2_ip"], f["c2_domain"]), "Imprime c2_ip y c2_dominio de tus muestras."),
            ("Identificaste la persistencia", 15, _t(f["persistence"]), "Mira la columna persistencia de tus muestras."),
            ("Identificaste la evasión", 10, _t(f["evasion"]), "Mira la columna evasion de tus muestras."),
            ("Mapeaste técnicas MITRE", 15, lambda s, r: min(1.0, len(set(re.findall(r"T\d{4}(?:\.\d{3})?", s.text))) / 4), "Separa y lista los códigos T#### de tu familia."),
            ("Cruzaste con el NetFlow", 20, lambda s, r: 1.0 if (re.search(r"aurora_netflow", s.code) and re.search(r"merge|isin|==", s.code)) else 0.0, "Relaciona c2_ip de la muestra con dst_ip del NetFlow."),
        ]
    if chapter == 4:
        mins = f["minutes_to_encrypt"]
        return [
            ("Identificaste el Paciente Cero", 20, _t(f["pz"]), "Es el host del primer evento de severidad alta o crítica."),
            ("Calculaste el tiempo hasta el cifrado", 20, g.has_num(mins, f["minutes_from_exec"], round(mins / 60, 1), round(mins / 60, 2), round(f["minutes_from_exec"] / 60, 1), round(f["minutes_from_exec"] / 60, 2), round(mins / 1440, 1)), "Resta el primer evento al evento de cifrado (T1486) en minutos."),
            ("Mapeaste la ruta de movimiento lateral", 20, g.has_terms(lambda r: f["lateral_path"]), "Lista los hosts por los que pasó el atacante, en orden."),
            ("Identificaste la cuenta de servicio abusada", 15, _t(f["svc"]), "Mira la columna usuario de los eventos de Lateral Movement."),
            ("Identificaste el vector de entrada", 15, g.text_matches({"adjunto": r"adjunto|macro|excel|factura", "enlace": r"enlace|link|portal|url", "credencial": r"credencial|vpn|contrase[ñn]a|proveedor"}[f["vector"]]), "Lee el detalle del primer evento y descríbelo en tus notas."),
            ("Agrupaste por fase y ordenaste", 10, g.code_matches(r"groupby\(['\"]fase|sort_values"), "Agrupa por fase conservando el orden cronológico."),
        ]
    if chapter == 5:
        ents = [f["c2_ip"], f["exfil_ip"], f["pz"], f["svc"], f["phish"], f["alias"], f["c2_domain"], f["family"]]
        return [
            ("Extrajiste las entidades clave de los textos", 25, g.has_terms(lambda r: ents, minimum=6), "Imprime las IPs, hosts, dominios, cuentas y la familia que aparecen en los textos."),
            ("Resolviste el alias entre dominios", 25, lambda s, r: min(_t(f["phish"], f["alias"])(s, r), g.text_matches(r"alias|mismo actor|mismo dominio|antes|se renombr|misma ip|mismo d[ií]a|compart")(s, r)), "Dos dominios distintos aparecen juntos en un texto: explica por qué son el mismo actor."),
            ("Construiste relaciones entre entidades", 15, g.code_matches(r"networkx|add_edge|findall|re\.search"), "Extrae con expresiones regulares y relaciona entidades (grafo)."),
            ("Señalaste qué contradice o completa el feed", 15, lambda s, r: min(_t(f["exfil_ip"])(s, r), g.text_matches(r"feed|baja confianza|contradic|ignor|reclasific|subir|elev")(s, r)), "El chat del SOC duda de una IP que el feed minimiza. Dilo."),
            ("Escribiste tu hallazgo en las notas", 20, g.notes_min(300), "Resume tu hallazgo del capítulo (al menos ~300 caracteres)."),
        ]
    if chapter == 6:
        sibs, legit = f["siblings"], f["legit_candidates"]
        return [
            ("Entrenaste un clasificador", 20, g.code_matches(r"RandomForest|LogisticRegression|DecisionTree|GradientBoosting"), "Usa scikit-learn con los dominios etiquetados."),
            ("Creaste features del dominio", 15, lambda s, r: min(1.0, sum(1 for k in ("longitud", "guiones", "dias_desde_registro", "tld") if k in s.code) / 3), "Usa longitud, guiones, días desde el registro y tld."),
            ("Reportaste las métricas", 10, lambda s, r: sum(1 for k in ("accuracy", "precision", "recall", "f1") if k in s.low) / 4, "Imprime accuracy, precision, recall y F1."),
            ("Alcanzaste accuracy ≥ 75%", 10, g.metric_min(r"accuracy", 0.75), "Revisa features y el split."),
            ("Recomendaste bloquear los dominios hermanos", 30,
             lambda s, r: (min(1.0, sum(1 for d in sibs if d in s.low) / max(1, len(sibs) - 2)) if sum(1 for d in legit if d in s.low) <= 1 else 0.0),
             "Predice sobre los candidatos sin etiqueta y entrega solo los que el modelo marca como maliciosos."),
            ("Graficaste la matriz de confusión", 10, lambda s, r: g.plots_at_least(1)(s, r) if re.search("confusion", s.code, re.I) else 0.0, "Dibuja confusion_matrix."),
            ("Anotaste tu conclusión", 5, g.notes_min(100), "Explica en las notas por qué recomiendas bloquear esos dominios."),
        ]
    if chapter == 7:
        ag, bots = f["agent_sessions"], f["legit_bots"]
        def ids(sub):
            return set(re.findall(r"S-\d{4}", sub.output))
        def shrink(sub):
            """Una lista inflada (marcar casi todo) no demuestra detección: el crédito baja con el tamaño de la lista."""
            n = len(ids(sub))
            return 0.0 if n == 0 else min(1.0, 25 / n)
        def found(sub, _r):
            hit = len(ids(sub) & set(ag))
            return min(1.0, hit / 6) * shrink(sub)                      # con 6 de 8 ya es puntaje completo
        def precision(sub, _r):
            listed = ids(sub)
            if not listed or len(listed) > 40:
                return 0.0
            good = len(listed & set(ag))
            return min(1.0, (good / len(listed)) / 0.5)                # mitad de la lista acertada = completo
        def legit(sub, _r):
            mention = g.text_matches(r"svc_|leg[ií]tim|monitor|respaldo|reporte|rígid|script|automatizaci", where="text")(sub, _r)
            return mention * shrink(sub)
        signals = (r"cadencia|ritmo|intervalo", r"reintent|corrig|error", r"hora|madrugada|horario|noche", r"diversidad|variedad|comandos|adapt", r"agente|llm|ia\b|inteligencia artificial|aut[oó]nom")
        return [
            ("Usaste un método de detección de anomalías", 15, g.code_matches(r"IsolationForest|LocalOutlierFactor|OneClassSVM|EllipticEnvelope|MLPRegressor|autoencoder|zscore|z_score|np\.abs\(.*>\s*[23]"), "Prueba Isolation Forest o LOF: no necesitan etiquetas."),
            ("Preparaste las variables de comportamiento", 10, lambda s, r: min(1.0, (g.code_matches(r"StandardScaler|zscore|z_score|\.std\(")(s, r) + min(1.0, sum(1 for k in ("peticiones_por_min", "intervalo_desv_s", "comandos_distintos", "errores_pct", "reintento_tras_error_s") if k in s.code) / 3)) / 2), "Escala las variables y usa las de comportamiento, no los identificadores."),
            ("Encontraste los agentes de IA", 30, found, "Imprime los identificadores (S-####) de las sesiones que marcas como sospechosas."),
            ("Tu lista es precisa (no marcas casi todo)", 15, precision, "Una lista corta y justificada vale más que marcar muchas sesiones."),
            ("Distinguiste la automatización legítima", 15, legit, "Hay sesiones rápidas y regulares que son monitoreo o respaldos del banco: no son el atacante. Dilo en tus notas."),
            ("Explicaste las señales de un agente de IA", 15, lambda s, r: min(1.0, sum(1 for p in signals if re.search(p, s.low)) / 3), "Explica en notas qué distingue a un agente de IA: ritmo, reintentos, horario, variedad de acciones."),
        ]
    if chapter == 8:
        key = [f["c2_ip"], f["exfil_ip"], f["pz"], f["svc"], f["phish"], f["c2_domain"], f["family"], f["persistence"]]
        mins = f["minutes_to_encrypt"]
        return [
            ("Citaste evidencias de varios capítulos", 30, g.has_terms(lambda r: key, minimum=5, where="text"), "Cita al menos 5 datos concretos: IPs, host, cuenta, dominios, familia."),
            ("Nombraste el vector de entrada", 15, g.text_matches({"adjunto": r"adjunto|macro|excel|factura", "enlace": r"enlace|link|portal|url", "credencial": r"credencial|vpn|contrase[ñn]a|proveedor"}[f["vector"]]), "Explica cómo entró el atacante."),
            ("Incluiste cifras de tiempo y volumen", 10, g.has_num(mins, f["minutes_from_exec"], round(mins / 60, 1), round(mins / 60), *_bytes_forms(f["exfil_bytes"])), "Incluye cuánto tardó el atacante y cuántos datos sacó."),
            ("Propusiste mitigaciones priorizadas", 20, lambda s, r: min(1.0, sum(1 for p in (r"segment", r"mfa|multifactor|autenticaci[oó]n", r"respaldo|backup", r"credencial|contrase[ñn]a|rotar", r"parche|actualiz", r"capacita|concientiz", r"bloque|ioc|aisl") if re.search(p, s.low)) / 3), "Propón al menos 3 medidas, ordenadas por urgencia."),
            ("Extensión y claridad del informe", 10, g.notes_min(600), "Un informe ejecutivo de al menos ~600 caracteres."),
            ("Publicaste tu reporte en el Muro de Inteligencia", 15, lambda s, r: 1.0 if ctx.get("has_wall_report") else 0.0, "Ve al Muro de Inteligencia y publica tu informe."),
        ]
    raise ValueError(chapter)

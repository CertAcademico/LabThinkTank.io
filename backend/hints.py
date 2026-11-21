"""Pistas graduales de los retos individuales.

Tres niveles por reto, que el estudiante pide de a uno (el servidor entrega solo
el siguiente). No dan los valores finales: orientan, indican el método y, al
final, un esqueleto de código con huecos (___) por completar.
Clave = título exacto del reto.
"""
LEVEL_LABELS = {1: "Orientación", 2: "Método", 3: "Esqueleto de código"}          # compatibilidad (3 niveles)
LABELS_5 = ["Orientación", "Método", "Cuidado con…", "Cómo verificar tu resultado", "Esqueleto de código"]


def label_for(level: int, total: int) -> str:
    """Etiqueta del nivel según cuántos niveles tiene el reto."""
    if total == 5:
        return LABELS_5[level - 1]
    return LEVEL_LABELS.get(level, f"Pista {level}")


# Dos niveles intermedios por reto: el error típico y cómo comprobar el propio resultado (sin dar la respuesta).
EXTRA: dict[str, tuple[str, str]] = {
    "Caza de IOCs — APT28 Fancy Bear": (
        "No cuentes las IPs internas (10.x, 192.168.x): no son C2. Y un destino con muchas filas no es necesariamente el que recibió más datos: puede ser un beacon (muchas filas, pocos bytes).",
        "Debes obtener muy pocas IPs externas (menos de 5). Si te salen decenas, estás incluyendo IPs internas. Tu total de bytes exfiltrados debe ser mucho mayor que el de cualquier fila individual.",
    ),
    "Enriquecimiento y Priorización de IOC Feed": (
        "Las mayúsculas y los duplicados cambian los conteos: normaliza antes de contar. Si confidence llega como texto, convierte con astype(float) antes de multiplicar.",
        "Todos los IOC deben quedar en exactamente uno de los 4 niveles: la suma de value_counts() debe ser igual al número de filas que quedaron tras limpiar.",
    ),
    "Perfilado de Malware con Pandas — AgentTesla & Emotet": (
        "La columna mitre trae varios códigos en una misma celda: contar filas no es contar técnicas. Sepáralos con split y explode antes de agrupar.",
        "Una tabla cruzada bien armada suma tantas celdas como muestras tienes: compruébalo con tabla.values.sum().",
    ),
    "Análisis de Campaña Ransomware LockBit 3.0": (
        "El «primer evento» es el más antiguo por fecha, no la primera fila del archivo: ordena por timestamp antes de decidir.",
        "El host de Paciente Cero debe coincidir con el host de la fase Initial Access. Si no coincide, revisa el orden.",
    ),
    "Extracción de Entidades CTI — NLP sobre Texto de Amenaza": (
        "entries es un texto JSON: si lo usas como lista sin json.loads, los conteos salen mal. Revisa también las filas con entries vacío.",
        "El grafo debe tener al menos tantos nodos como entidades distintas extraíste. Si tiene menos, perdiste relaciones.",
    ),
    "Detección de Phishing con Machine Learning": (
        "Con ~12 filas, el accuracy cambia muchísimo según cómo se parta el conjunto: no te fíes de una sola corrida. Prueba varios random_state o cross_val_score.",
        "La suma de la matriz de confusión debe ser igual al tamaño del conjunto de prueba. Si no, mezclaste conjuntos.",
    ),
}
EXTRA_AURORA: dict[int, tuple[str, str]] = {
    1: ("Un destino con muchas conexiones no es el que recibió más datos. Beacon = mucha frecuencia y pocos bytes; exfiltración = pocas conexiones y muchísimos bytes. Y no cuentes las filas con acción BLOCK.",
        "La IP del beacon y la de exfiltración deben ser distintas, ambas externas (no 10.20.x.x). Tu total de bytes debe estar en el orden de gigabytes."),
    2: ("El feed puede equivocarse: una IP con baja severidad y campaña «sin asignar» puede ser justo la que movió gigas en tu red. Tus datos propios pesan más que el feed.",
        "Los indicadores de tu campaña comparten el valor de la columna campana de tu IP del C2: deberías encontrar 3. La IP de exfiltración no está entre ellos, y justo por eso tienes que reclasificarla."),
    3: ("Hay familias de otros casos mezcladas: si no filtras por tu servidor de mando, tu conclusión mezcla incidentes distintos.",
        "Todas tus muestras comparten el mismo c2_ip y el mismo c2_dominio. Si ves dos servidores distintos, el filtro está mal."),
    4: ("Sin filtrar por severidad, el primer evento es ruido de días antes del incidente. Y el tiempo se mide entre eventos del incidente, no desde el primer registro del archivo.",
        "El Paciente Cero debe aparecer también como origen de las conexiones al C2 en el NetFlow (cruza el host con la columna host de aurora_netflow)."),
    5: ("Las expresiones regulares se pasan de largo: una IP puede capturar parte de un número más largo y los hosts se confunden con palabras en mayúsculas. Revisa a mano lo que extraes en 2 o 3 textos.",
        "Los dos dominios del alias aparecen en textos distintos y hay un tercer dato que los une (misma IP de alojamiento o mismo día de registro). Esa es tu prueba."),
    6: ("Entrenas con pocos ejemplos: un accuracy de 1.0 puede ser suerte. Y no entrenes con los candidatos sin etiqueta: son el examen, no el material de estudio.",
        "Los dominios que recomiendas bloquear comparten IP de alojamiento y tienen pocos días desde el registro. Si recomiendas dominios antiguos, revisa tus features."),
    7: ("No todo lo anómalo es un atacante: el banco tiene automatización legítima (monitoreo, respaldos, reportes) que es rápida y regular. Y no uses la columna sesion ni cuenta como variables: no describen comportamiento.",
        "Deberías marcar más o menos entre 8 y 16 sesiones, no 50. Entre las marcadas, los agentes de IA tienen muchas acciones distintas, reintentan en segundos y trabajan de madrugada; el monitoreo repite siempre lo mismo."),
    8: ("La línea de tiempo se construye SOLO con las alertas de severidad high y critical de aurora_siem_events: el ruido anterior al incidente no cuenta. Y un informe sin cifras no convence: cada afirmación necesita un dato (IP, host, minutos, GB).",
        "Léelo como si fueras el comité: ¿se entiende sin haber visto los datos? ¿hay al menos 3 medidas ordenadas por urgencia? ¿está publicado en el Muro?"),
}

HINTS: dict[str, list[str]] = {
    "Caza de IOCs — APT28 Fancy Bear": [
        "Trabaja solo con las filas de APT28: filtra por la columna threat_actor y usa len() para contarlas. "
        "Un 'C2' es una IP externa (que no empieza por 10. ni 192.168.) que se comunica con la red interna; "
        "la 'exfiltración' es tráfico saliente hacia el exterior con muchos bytes.",
        "IPs externas: junta src_ip y dst_ip con pd.concat, usa .unique() y descarta las privadas con startswith. "
        "Bytes exfiltrados: en MITRE la exfiltración por C2 es la técnica T1041; filtra por esa técnica y suma la columna bytes. "
        "Gráfica: value_counts() de la columna mitre con kind='bar'. Timeline: pd.to_datetime(timestamp) y sort_values.",
        "import matplotlib.pyplot as plt\n"
        "apt = challenge_df[challenge_df['threat_actor'] == '___']\n"
        "print('Eventos APT28:', len(apt))\n"
        "ips = pd.concat([apt['src_ip'], apt['dst_ip']]).___()\n"
        "externas = [ip for ip in ips if not ip.startswith(('10.', '192.168.'))]\n"
        "print('IPs externas:', externas)\n"
        "exfil = apt[apt['mitre'] == '___']['bytes'].___()\n"
        "print('Bytes exfiltrados:', exfil)\n"
        "apt['mitre'].value_counts().plot(kind='bar'); plt.show()\n"
        "apt = apt.assign(t=pd.to_datetime(apt['timestamp'])).sort_values('t')\n"
        "print(apt[['timestamp', 'mitre']])",
    ],
    "Enriquecimiento y Priorización de IOC Feed": [
        "Primero limpia: revisa nulos, duplicados y normaliza texto (minúsculas, strip). severity es texto "
        "(critical/high/medium/low): conviértela a número. El riesgo combina esa severidad con confidence (0-100), "
        "y luego decides los cortes para Crítico, Alto, Medio y Bajo.",
        "Usa un diccionario para severity (por ejemplo critical=4 … low=1) con .map(). Crea la columna de riesgo multiplicando "
        "severidad por confidence. Clasifica con pd.cut(riesgo, bins=[...], labels=['Bajo','Medio','Alto','Crítico']). "
        "Distribución por actor: groupby('threat_actor').size(). Las 3 gráficas salen de value_counts() de threat_actor (top 5), country y type.",
        "import matplotlib.pyplot as plt\n"
        "df = challenge_df.drop_duplicates().dropna(subset=['severity', 'confidence']).copy()\n"
        "df['type'] = df['type'].str.lower().str.strip()\n"
        "sev = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}\n"
        "df['sev_num'] = df['severity'].___(sev)\n"
        "df['risk'] = df['sev_num'] * df['___'] / 100\n"
        "df['nivel'] = pd.cut(df['risk'], bins=[0, ___, ___, ___, 5], labels=['Bajo', 'Medio', 'Alto', 'Crítico'])\n"
        "print(df['nivel'].value_counts())\n"
        "print(df.groupby('threat_actor').size().sort_values(ascending=False))\n"
        "df['threat_actor'].value_counts().head(5).plot(kind='bar'); plt.show()\n"
        "df['country'].value_counts().plot(kind='bar'); plt.show()\n"
        "df['type'].value_counts().plot(kind='bar'); plt.show()",
    ],
    "Perfilado de Malware con Pandas — AgentTesla & Emotet": [
        "Todo gira en torno a la columna family: agrupa por ella. Las IPs C2 y los dominios están en c2_ip y c2_domain "
        "(saca los valores únicos). La columna mitre guarda varios códigos separados por coma. Para el heatmap necesitas "
        "una tabla cruzada de capability contra family.",
        "Conteo por familia: groupby('family').size(). Únicos: challenge_df['c2_ip'].unique() y ['c2_domain'].unique(). "
        "Técnicas por familia: separa mitre con .str.split(',') y .explode(). Heatmap: pd.crosstab(capability, family) y dibújalo con "
        "plt.imshow o seaborn. Tamaño medio por tipo de archivo: groupby('type')['size_kb'].mean().",
        "import matplotlib.pyplot as plt\n"
        "df = challenge_df.copy()\n"
        "print(df.groupby('___').size())\n"
        "print('IPs C2:', df['c2_ip'].___().tolist())\n"
        "print('Dominios C2:', df['c2_domain'].___().tolist())\n"
        "tec = df.assign(mitre=df['mitre'].str.split(',')).explode('mitre')\n"
        "print(tec.groupby('family')['mitre'].unique())\n"
        "tabla = pd.crosstab(df['___'], df['family'])\n"
        "plt.imshow(tabla.values, aspect='auto'); plt.xticks(range(len(tabla.columns)), tabla.columns, rotation=45)\n"
        "plt.yticks(range(len(tabla.index)), tabla.index); plt.colorbar(); plt.show()\n"
        "print(df.groupby('type')['size_kb'].___())\n"
        "print(df.groupby('family')[['persistence', 'evasion']].agg(lambda s: s.mode().iloc[0]))",
    ],
    "Análisis de Campaña Ransomware LockBit 3.0": [
        "Convierte timestamp a fecha y ordena: el Patient Zero es el host del primer evento. La cadena de movimiento lateral "
        "es el orden en que aparecen los hosts. El tiempo total va desde el primer evento hasta el evento de cifrado "
        "(fase Impact, técnica de cifrado de archivos, T1486).",
        "df['ts'] = pd.to_datetime(df['timestamp']); df = df.sort_values('ts'). Patient Zero: df.iloc[0]['host']. "
        "Cadena de hosts: df['host'].drop_duplicates().tolist(). Fases: df.groupby('phase'). "
        "Tiempo: resta el ts del evento de cifrado menos df['ts'].min() y exprésalo en minutos con .total_seconds()/60.",
        "import matplotlib.pyplot as plt\n"
        "df = challenge_df.copy()\n"
        "df['ts'] = pd.to_datetime(df['___'])\n"
        "df = df.sort_values('ts')\n"
        "print('Patient Zero:', df.iloc[0]['___'])\n"
        "print('Camino de hosts:', ' -> '.join(df['host'].drop_duplicates()))\n"
        "print(df.groupby('phase', sort=False).size())\n"
        "cifrado = df[df['mitre'] == '___']['ts'].iloc[0]\n"
        "print('Minutos hasta el cifrado:', (cifrado - df['ts'].min()).total_seconds() / 60)\n"
        "# Kill chain: una barra horizontal por fase, en orden cronológico\n"
        "fases = df.groupby('phase', sort=False)['ts'].min()\n"
        "plt.barh(list(fases.index)[::-1], range(1, len(fases) + 1)); plt.show()\n"
        "# En las notas: 3 mitigaciones (segmentación, parches, backups offline).",
    ],
    "Extracción de Entidades CTI — NLP sobre Texto de Amenaza": [
        "Empieza explorando: distribución de labels, longitud de los textos y nulos. entries es un string JSON dentro del "
        "DataFrame: conviértelo con json.loads antes de usarlo.",
        "El texto de una entidad sale de text[start_offset:end_offset]. Para el grafo usa networkx: G.add_edge(source_id, target_id) "
        "y colorea los nodos por label. Para el clasificador, TF-IDF sobre el texto completo y el label más frecuente de entries como target.",
        "import json, networkx as nx\n"
        "df = challenge_df.copy()\n"
        "df['ents'] = df['entries'].apply(lambda s: json.loads(s) if isinstance(s, str) else [])\n"
        "print(df['text'].str.len().describe())\n"
        "G = nx.Graph()\n"
        "# for rel in json.loads(fila['relations']): G.add_edge(rel['___'], rel['___'])\n"
        "# vec = TfidfVectorizer(); X = vec.fit_transform(df['text']); LogisticRegression().fit(X, y)\n"
        "# El campo diagnosis resume la amenaza: úsalo para validar tus labels.",
    ],
    "Detección de Phishing con Machine Learning": [
        "El dataset no trae una columna 'es_phishing': todos los dominios son maliciosos, así que debes definir tú el objetivo, "
        "por ejemplo status == 'active' (activo vs. sinkholed/inactivo). Si usas confidence para el objetivo, no la uses como feature "
        "(sería trampa). Features típicos: longitud del dominio, nº de guiones, TLD y antigüedad del registro.",
        "Features: df['len'] = df['domain'].str.len(); df['guiones'] = df['domain'].str.count('-'); "
        "df['tld'] = df['domain'].str.split('.').str[-1]; antigüedad con pd.to_datetime(registered). Con solo ~12 filas el split es ruidoso: "
        "usa train_test_split(test_size=0.3, random_state=42) o cross_val_score. Entrena RandomForestClassifier, imprime classification_report, "
        "feature_importances_ y confusion_matrix.",
        "import matplotlib.pyplot as plt\n"
        "from sklearn.ensemble import RandomForestClassifier\n"
        "from sklearn.model_selection import train_test_split\n"
        "from sklearn.metrics import classification_report, confusion_matrix, accuracy_score\n"
        "df = challenge_df.copy()\n"
        "df['len'] = df['domain'].str.___\n"
        "df['guiones'] = df['domain'].str.count('-')\n"
        "df['tld'] = df['domain'].str.split('.').str[-1].astype('category').cat.codes\n"
        "df['edad'] = (pd.Timestamp('2024-04-01') - pd.to_datetime(df['registered'])).dt.days\n"
        "X = df[['len', 'guiones', 'tld', 'edad']]\n"
        "y = (df['status'] == '___').astype(int)\n"
        "Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.3, random_state=42)\n"
        "m = RandomForestClassifier(random_state=42).fit(Xtr, ytr)\n"
        "pred = m.predict(Xte)\n"
        "print('accuracy', accuracy_score(yte, pred)); print(classification_report(yte, pred, zero_division=0))\n"
        "print(dict(zip(X.columns, m.feature_importances_)))\n"
        "cm = confusion_matrix(yte, pred); plt.imshow(cm); plt.colorbar(); plt.show()",
    ],
}


def levels_for(title: str) -> list[str]:
    """5 niveles: orientación, método, cuidado con…, cómo verificar y esqueleto de código."""
    if title in HINTS and title in EXTRA:
        b = HINTS[title]
        return b[:2] + list(EXTRA[title]) + b[2:]
    from aurora.chapters import CHAPTERS, PATH_TITLES
    if title in PATH_TITLES:
        i = PATH_TITLES.index(title)
        b = CHAPTERS[i]["hints"]
        return b[:2] + list(EXTRA_AURORA[i + 1]) + b[2:]
    return HINTS.get(title, [])

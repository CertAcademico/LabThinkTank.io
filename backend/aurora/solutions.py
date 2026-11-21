"""Soluciones de referencia y respuestas esperadas (solo para el admin).

Sirven para: que el docente vea qué se espera en cada reto, calibrar la autocalificación
y resolver dudas puntuales sin depender de improvisar. Las respuestas se calculan para la
variante de un estudiante concreto.
"""
from __future__ import annotations

REFERENCE_CODE = {
    1: """import matplotlib.pyplot as plt
df = aurora_netflow.copy(); df['t'] = pd.to_datetime(df['timestamp']); df = df.sort_values('t')
ok = df[df['action'] == 'ALLOW']
ext = ok[~ok['dst_ip'].str.startswith('10.20.')]          # destinos fuera de la red interna
cnt = ext.groupby('dst_ip').size().sort_values(ascending=False)
print('IP del beacon (C2):', cnt.index[0], '| conexiones permitidas:', cnt.iloc[0])
vol = ext.groupby('dst_ip')['bytes'].sum().sort_values(ascending=False)
print('IP de exfiltración:', vol.index[0], '| bytes:', vol.iloc[0])
vol.head(5).plot(kind='barh'); plt.show()""",
    2: """import matplotlib.pyplot as plt
f = aurora_ioc_feed.copy()
f['tipo'] = f['tipo'].str.lower(); f['severidad'] = f['severidad'].str.lower(); f = f.drop_duplicates()
f['confianza'] = f['confianza'].fillna(f['confianza'].median())
f['riesgo'] = f['severidad'].map({'critical': 4, 'high': 3, 'medium': 2, 'low': 1}) * f['confianza'] / 100
f['nivel'] = pd.cut(f['riesgo'], bins=[0, 0.8, 1.6, 2.6, 5], labels=['Bajo', 'Medio', 'Alto', 'Crítico'])
print(f['nivel'].value_counts())
ext = aurora_netflow[(aurora_netflow['action'] == 'ALLOW') & ~aurora_netflow['dst_ip'].str.startswith('10.20.')]
c2 = ext.groupby('dst_ip').size().idxmax(); ex = ext.groupby('dst_ip')['bytes'].sum().idxmax()
camp = f[f['ioc'] == c2]['campana'].iloc[0]
print(f[f['campana'] == camp][['ioc', 'tipo', 'severidad']])
print('Exfiltración en el feed:', f[f['ioc'] == ex][['severidad', 'confianza', 'campana']].to_string())
f['nivel'].value_counts().plot(kind='bar'); plt.show(); f['tipo'].value_counts().plot(kind='bar'); plt.show()""",
    3: """m = aurora_malware_lab
ext = aurora_netflow[(aurora_netflow['action'] == 'ALLOW') & ~aurora_netflow['dst_ip'].str.startswith('10.20.')]
c2 = ext.groupby('dst_ip').size().idxmax()
mias = m[m['c2_ip'] == c2]
print(mias[['archivo', 'familia', 'c2_ip', 'c2_dominio', 'persistencia', 'evasion']].to_string())
print(mias.assign(mitre=mias['mitre'].str.split(',')).explode('mitre')['mitre'].unique())
print('conexiones en la red a ese C2:', len(aurora_netflow[aurora_netflow['dst_ip'].isin(mias['c2_ip'])]))""",
    4: """ev = aurora_siem_events.copy(); ev['ts'] = pd.to_datetime(ev['timestamp'])
ev = ev[ev['severidad'].isin(['high', 'critical'])].sort_values('ts')       # solo el incidente
print('Paciente Cero:', ev.iloc[0]['host']); print(ev.iloc[0]['detalle'])
print('Ruta:', ' -> '.join(ev['host'].drop_duplicates()))
print('Cuenta abusada:', ev[ev['fase'] == 'Lateral Movement']['usuario'].unique())
c = ev[ev['mitre'] == 'T1486']['ts'].iloc[0]
print('Minutos hasta el cifrado:', (c - ev['ts'].min()).total_seconds() / 60)
print(ev.groupby('fase', sort=False).size())""",
    5: r"""import re, networkx as nx
t = aurora_reportes_texto['texto']
pat = r'\b\d{1,3}(?:\.\d{1,3}){3}\b|[a-z0-9-]+\.example|svc_\w+|[A-Z]{2,}-[A-Z0-9-]+'
G = nx.Graph(); ents = set()
for s in t:
    e = re.findall(pat, s); ents |= set(e)
    for a in e:
        for b in e:
            if a < b: G.add_edge(a, b)
print(sorted(ents)); print(G.number_of_nodes(), 'nodos', G.number_of_edges(), 'aristas')
for s in t:
    if len(re.findall(r'[a-z0-9-]+\.example', s)) >= 2: print('Texto con dos dominios (alias):', s)""",
    6: """import matplotlib.pyplot as plt
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
d = aurora_dominios.copy(); d['tld'] = d['tld'].astype('category').cat.codes
cols = ['longitud', 'guiones', 'dias_desde_registro', 'tld']
lab, cand = d[d['etiqueta'].notna()], d[d['etiqueta'].isna()]
Xtr, Xte, ytr, yte = train_test_split(lab[cols], lab['etiqueta'] == 'malicioso', test_size=0.3, random_state=42)
m = RandomForestClassifier(random_state=42).fit(Xtr, ytr)
p = m.predict(Xte); print('accuracy', accuracy_score(yte, p)); print(classification_report(yte, p, zero_division=0))
cm = confusion_matrix(yte, p); plt.imshow(cm); plt.colorbar(); plt.show()
print('BLOQUEAR:', aurora_dominios.loc[cand.index[m.predict(cand[cols])], 'dominio'].tolist())""",
    7: """import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
t = aurora_telemetria_sesiones.copy()
cols = ['peticiones_por_min', 'intervalo_desv_s', 'comandos_distintos', 'errores_pct', 'reintento_tras_error_s', 'hora', 'paginas_distintas']
X = StandardScaler().fit_transform(t[cols])
t['anomala'] = IsolationForest(contamination=0.12, random_state=42).fit_predict(X) == -1
marcadas = t[t['anomala']]
print(len(marcadas), 'sesiones marcadas')
# Separar la automatización legítima (rápida y regular, pero rígida: pocas acciones distintas)
legitimas = marcadas[(marcadas['comandos_distintos'] <= 4) & (marcadas['cuenta'].str.startswith('svc_'))]
agentes = marcadas.drop(legitimas.index)
print('AGENTES DE IA (aislar):', agentes['sesion'].tolist())
print('Automatización legítima (no aislar):', legitimas['sesion'].tolist())""",
    8: "(Sin código: informe ejecutivo en las notas + publicación en el Muro de Inteligencia.)",
}


def _gb(b: int) -> str:
    return f"{b:,} bytes (≈ {b / 1e9:.2f} GB)"


def expected(chapter: int, f: dict) -> list[str]:
    """Respuesta esperada por criterio, en el mismo orden que la rúbrica del capítulo."""
    if chapter == 1:
        return [f["c2_ip"], f"{f['beacons']} conexiones permitidas (se acepta {f['beacons'] + 1} si incluyen el intento bloqueado)",
                _gb(f["exfil_bytes"]), f["exfil_ip"], "Gráfica de bytes por destino u hora", "Eventos ordenados con pd.to_datetime + sort_values"]
    if chapter == 2:
        return ["Duplicados eliminados y tipo/severidad en minúsculas", f"{f['c2_ip']}, {f['phish']}, {f['c2_domain']} (campaña «Marea Gris»)",
                f"{f['exfil_ip']} figura con baja severidad y campaña «sin asignar»; debe subir a Alto/Crítico porque el NetFlow muestra {_gb(f['exfil_bytes'])} saliendo",
                "Columna de riesgo = severidad numérica × confianza", "Conteo por Crítico/Alto/Medio/Bajo", "2 gráficas: nivel y tipo"]
    if chapter == 3:
        return [f"Familia «{f['family']}» (muestras cuyo c2_ip = {f['c2_ip']})", f"{f['c2_ip']} y {f['c2_domain']}", f["persistence"], f["evasion"],
                "≥ 4 códigos MITRE (ej. T1204.002, T1003.001, T1071.001, T1021.002, T1490, T1486)", "Cruce c2_ip de la muestra con dst_ip del NetFlow"]
    if chapter == 4:
        m, e = f["minutes_to_encrypt"], f["minutes_from_exec"]
        return [f["pz"], f"{m} min desde la primera alerta (≈ {m / 60:.1f} h); se acepta {e} min desde la ejecución",
                " → ".join(f["lateral_path"]), f["svc"], f["vector_text"], "groupby('fase') conservando el orden"]
    if chapter == 5:
        return [f"IPs {f['c2_ip']}, {f['exfil_ip']}; host {f['pz']}; cuenta {f['svc']}; dominios {f['phish']}, {f['alias']}, {f['c2_domain']}; familia {f['family']}",
                f"{f['phish']} y {f['alias']} son el mismo actor (el proveedor dice «antes era»; misma IP y mismo día de registro)", "Extracción con regex y/o grafo (networkx)",
                f"El chat del SOC duda de {f['exfil_ip']} porque el feed la minimiza: los informes la completan", "Hallazgo ≥ 300 caracteres"]
    if chapter == 6:
        return ["RandomForest / LogisticRegression con los dominios etiquetados", "longitud, guiones, dias_desde_registro, tld", "accuracy, precision, recall, F1",
                "accuracy ≥ 0.75", "Dominios a bloquear (los hermanos de Marea Gris): " + ", ".join(f["siblings"]) + " — y NO: " + ", ".join(f["legit_candidates"]),
                "Matriz de confusión", "Conclusión en las notas"]
    if chapter == 7:
        return ["IsolationForest / LOF / otro método sin etiquetas", "StandardScaler + variables de comportamiento (peticiones_por_min, intervalo_desv_s, comandos_distintos, errores_pct, reintento_tras_error_s…)",
                "Las 8 sesiones de agente (basta con ≥ 6): " + ", ".join(f["agent_sessions"]),
                "Lista corta: la mitad o más de lo marcado debe ser de agentes",
                "Las sesiones de automatización legítima NO son el atacante: " + ", ".join(f["legit_bots"]) + " (cuentas svc_, pocas acciones distintas, muy regulares)",
                "Señales de un agente de IA: ritmo rápido, reintentos en segundos, horario de madrugada, mucha variedad de acciones y páginas"]
    if chapter == 8:
        return [f"Cita ≥ 5 de: {f['c2_ip']}, {f['exfil_ip']}, {f['pz']}, {f['svc']}, {f['phish']}, {f['c2_domain']}, {f['family']}, {f['persistence']}",
                f["vector_text"], f"{f['minutes_to_encrypt']} min / {_gb(f['exfil_bytes'])}", "≥ 3 medidas: bloqueo de IOC, rotación de credenciales, segmentación, respaldos fuera de línea, MFA, capacitación",
                "≥ 600 caracteres", "Reporte publicado en el Muro"]
    return []


def reference_note(f: dict) -> str:
    """Informe de ejemplo para el capítulo 8."""
    return (f"Resumen: el atacante entró por {f['vector_text']} en {f['pz']}. Usó {f['family']} con C2 {f['c2_ip']} ({f['c2_domain']}) y persistencia '{f['persistence']}'. "
            f"Se movió con la cuenta {f['svc']} hacia {f['mid']} y FILE-SRV-02, borró respaldos y sacó {round(f['exfil_bytes'] / 1e9, 2)} GB hacia {f['exfil_ip']}. "
            f"Del primer evento al cifrado pasaron {f['minutes_to_encrypt']} minutos. Dominio de phishing: {f['phish']} (alias {f['alias']}). Confianza alta. "
            "Recomendaciones: 1) bloquear los IOC y aislar equipos, 2) rotar credenciales y la cuenta de servicio, 3) segmentación de red, 4) respaldos fuera de línea, 5) MFA y capacitación contra phishing.")


# ── Retos de práctica (1-5): respuestas calculadas sobre su dataset ────────────
PRACTICE_CODE = {
    "Caza de IOCs — APT28 Fancy Bear": "apt = challenge_df[challenge_df['threat_actor'] == 'APT28']\nprint(len(apt))\nips = pd.concat([apt['src_ip'], apt['dst_ip']]).unique()\n"
        "print([i for i in ips if not i.startswith(('10.', '192.168.'))])\nprint(apt[apt['mitre'] == 'T1041']['bytes'].sum())\napt['mitre'].value_counts().plot(kind='bar'); plt.show()",
    "Análisis de Campaña Ransomware LockBit 3.0": "df = challenge_df.copy(); df['ts'] = pd.to_datetime(df['timestamp']); df = df.sort_values('ts')\nprint(df.iloc[0]['host'])\n"
        "print(' -> '.join(df['host'].drop_duplicates()))\nprint((df[df['mitre'] == 'T1486']['ts'].iloc[0] - df['ts'].min()).total_seconds() / 60)",
    "Detección de Phishing con Machine Learning": "(ver pista de nivel 3 del reto; el objetivo se define con status == 'active')",
    "Enriquecimiento y Priorización de IOC Feed": "(ver pista de nivel 3 del reto)",
    "Perfilado de Malware con Pandas — AgentTesla & Emotet": "(ver pista de nivel 3 del reto)",
}


def practice_expected(title: str, rows: list) -> list[str]:
    import grading
    t = title.lower()
    if t.startswith("caza de iocs"):
        n, ext, ex = grading._apt28(rows)
        return [f"{n} eventos de APT28", ", ".join(ext), f"{ex:,} bytes", "Gráfica de técnicas MITRE", "Timeline ordenado"]
    if t.startswith("análisis de campaña ransomware"):
        pz, phases, m1, m2 = grading._lockbit(rows)
        return [pz, f"{m1} min hasta el cifrado (o {m2} hasta el último evento)", "WEB-SRV-01 → DC-01 → FILE-SRV-02", f"{len(phases)} fases", "Diagrama de kill chain", "≥ 3 mitigaciones"]
    return []

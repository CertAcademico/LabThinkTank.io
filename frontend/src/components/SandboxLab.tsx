import { useEffect, useRef, useState, type ReactNode } from 'react'
import { useAuth } from '../contexts/AuthContext'
import HelpBot from './HelpBot'

const API_URL = import.meta.env.VITE_API_URL ?? 'http://127.0.0.1:8000'

// ── Pyodide types ─────────────────────────────────────────────────────────────

import type { PyodideInterface } from '../types/pyodide'

// ── Lesson data ───────────────────────────────────────────────────────────────

interface Lesson {
  id:          string
  title:       string
  concept:     string
  explanation: string
  starterCode: string
  hint:        string
}

interface Track {
  id:       string
  label:    string
  icon:     string
  color:    string
  packages: string[]
  lessons:  Lesson[]
}

const PLT_SETUP = `import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import numpy as np
import pandas as pd
import io, base64

plt.rcParams.update({
    'figure.facecolor': '#0a0f1e', 'axes.facecolor': '#0f172a',
    'axes.edgecolor': '#1e293b', 'text.color': '#94a3b8',
    'xtick.color': '#64748b', 'ytick.color': '#64748b',
    'axes.labelcolor': '#94a3b8', 'grid.color': '#1e293b',
    'grid.linestyle': '--', 'grid.alpha': 0.6, 'font.size': 9,
})

def _mostrar():
    buf = io.BytesIO()
    plt.savefig(buf, format='png', bbox_inches='tight', facecolor='#0a0f1e', dpi=110)
    plt.close()
    buf.seek(0)
    print('__PLOT__:' + base64.b64encode(buf.read()).decode())
`

const TRACKS: Track[] = [
  // ── TRACK 1: CTI & pandas ─────────────────────────────────────────────────
  {
    id: 'cti', label: 'CTI & pandas', icon: '🔍', color: '#a78bfa', packages: [],
    lessons: [
      {
        id: 'cti-1', title: 'Explorando los datos CTI',
        concept: 'DataFrames y estructura de datos',
        explanation: `Los datos de threat intelligence se cargan como un **DataFrame de pandas** llamado \`ioc_df\`.

Un DataFrame es una tabla con filas y columnas. Métodos clave:
- \`ioc_df.head()\` — primeras 5 filas
- \`ioc_df.shape\` — (filas, columnas)
- \`ioc_df.dtypes\` — tipo de cada columna
- \`ioc_df.describe(include="all")\` — estadísticas`,
        starterCode: `# ioc_df se carga automáticamente con datos del feed CTI
print("=== INTEL FEED CARGADO ===")
print(ioc_df.to_string(index=False))

print(f"\\nRegistros: {ioc_df.shape[0]}  Columnas: {ioc_df.shape[1]}")
print(f"\\nColumnas disponibles: {ioc_df.columns.tolist()}")
print(f"\\nTipos de datos:")
print(ioc_df.dtypes)`,
        hint: 'Prueba print(ioc_df.describe(include="all")) para ver conteos y valores únicos.',
      },
      {
        id: 'cti-2', title: 'Filtrar IOCs por severidad',
        concept: 'Boolean indexing y condiciones',
        explanation: `**Filtrado condicional**: selecciona filas que cumplen una condición.

\`df[df['columna'] == 'valor']\`

Combina condiciones:
- \`&\` → AND (ambas verdaderas)
- \`|\` → OR (al menos una)
- \`.isin(['a','b'])\` → múltiples valores`,
        starterCode: `# Filtrar IOCs críticos
criticos = ioc_df[ioc_df['severity'] == 'critical']
print(f"IOCs críticos: {len(criticos)} de {len(ioc_df)} total")
print()
print(criticos[['ioc', 'type', 'threat_actor', 'mitre']].to_string(index=False))

# Filtrar críticos O altos
print("\\n=== ALTO RIESGO (critical + high) ===")
alto_riesgo = ioc_df[ioc_df['severity'].isin(['critical', 'high'])]
print(alto_riesgo[['ioc', 'severity', 'country']].to_string(index=False))`,
        hint: 'Prueba ioc_df[~(ioc_df["severity"] == "low")] — el ~ niega la condición.',
      },
      {
        id: 'cti-3', title: 'Agrupar por actor',
        concept: 'groupby() y agregaciones',
        explanation: `**groupby()** agrupa filas por un campo para calcular estadísticas:

\`\`\`python
df.groupby('campo').size()          # cuenta
df.groupby('campo').agg({...})      # múltiples stats
df.groupby(['a','b']).size().unstack() # tabla cruzada
\`\`\``,
        starterCode: `# ¿Cuántos IOCs por actor?
por_actor = (
    ioc_df.groupby('threat_actor')
    .size()
    .reset_index(name='total')
    .sort_values('total', ascending=False)
)
print("=== IOCs POR ACTOR ===")
print(por_actor.to_string(index=False))

# Pivot: tipo de IOC × actor
print("\\n=== TIPO × ACTOR (tabla cruzada) ===")
pivot = ioc_df.groupby(['threat_actor', 'type']).size().unstack(fill_value=0)
print(pivot.to_string())`,
        hint: 'Agrega .agg({"severity": lambda x: x.value_counts().index[0]}) para la severidad más común por actor.',
      },
      {
        id: 'cti-4', title: 'Risk Score personalizado',
        concept: 'apply(), lambda y columnas calculadas',
        explanation: `**apply()** ejecuta una función en cada fila (con \`axis=1\`) para crear columnas calculadas:

\`\`\`python
df['nueva'] = df.apply(lambda row: ..., axis=1)
\`\`\`

Ideal para scoring, etiquetas o alertas derivadas de múltiples columnas.`,
        starterCode: `score_map = {'critical': 10, 'high': 7, 'medium': 4, 'low': 1}
paises_riesgo = {'RU', 'CN', 'KP', 'IR'}

def risk_score(row):
    score = score_map.get(row['severity'], 4)
    if row.get('country') in paises_riesgo:
        score += 3
    return min(score, 10)

ioc_df['risk_score'] = ioc_df.apply(risk_score, axis=1)

resultado = ioc_df[['ioc', 'severity', 'threat_actor', 'country', 'risk_score']] \
    .sort_values('risk_score', ascending=False)

print("=== RANKING DE RIESGO ===")
print(resultado.to_string(index=False))

inmediatos = resultado[resultado['risk_score'] >= 8]
print(f"\\nAcción inmediata (score ≥ 8): {len(inmediatos)}")
for _, r in inmediatos.iterrows():
    print(f"  [{r['risk_score']}/10] {r['ioc']} — {r['threat_actor']}")`,
        hint: 'Añade una condición: si el puerto (si existe) es 4444, suma 2 puntos extra al score.',
      },
    ],
  },

  // ── TRACK 2: ETL & Limpieza ───────────────────────────────────────────────
  {
    id: 'etl', label: 'ETL & Limpieza', icon: '🔧', color: '#22d3ee', packages: [],
    lessons: [
      {
        id: 'etl-1', title: 'Cargar datos desde texto',
        concept: 'pd.read_csv con StringIO',
        explanation: `En CTI y SOC, los datos llegan como CSV, logs o JSON crudo. \`StringIO\` permite tratar un string como si fuera un archivo:

\`\`\`python
from io import StringIO
df = pd.read_csv(StringIO(texto_csv))
\`\`\`

Simular datos es clave para desarrollar pipelines antes de tener el sistema real conectado.`,
        starterCode: `import pandas as pd
from io import StringIO

# Log simulado de firewall (formato típico de SIEM)
log_raw = """timestamp,src_ip,dst_ip,port,proto,action,bytes
2026-05-28 08:12:01,10.0.0.15,185.220.101.45,443,TCP,ALLOW,2048
2026-05-28 08:13:44,10.0.0.88,198.51.100.42,80,TCP,BLOCK,512
2026-05-28 08:14:23,10.0.0.15,203.0.113.77,4444,TCP,BLOCK,256
2026-05-28 08:15:01,10.0.0.22,8.8.8.8,53,UDP,ALLOW,128
2026-05-28 08:16:30,10.0.0.33,185.220.101.45,443,TCP,ALLOW,4096
2026-05-28 08:17:12,10.0.0.88,198.51.100.42,22,TCP,BLOCK,64
2026-05-28 08:18:55,10.0.0.44,203.0.113.77,4444,TCP,BLOCK,1024
2026-05-28 08:19:23,10.0.0.55,1.1.1.1,53,UDP,ALLOW,96"""

df = pd.read_csv(StringIO(log_raw.strip()))

print("=== LOG DE FIREWALL CARGADO ===")
print(df.to_string(index=False))
print(f"\\nShape: {df.shape}")
print(f"Tipos:\\n{df.dtypes}")
print(f"\\nBloqueadas: {(df['action'] == 'BLOCK').sum()}")`,
        hint: 'Prueba df[df["action"] == "BLOCK"]["dst_ip"].unique() para listar IPs bloqueadas únicas.',
      },
      {
        id: 'etl-2', title: 'Limpieza: nulos y duplicados',
        concept: 'dropna, fillna, drop_duplicates, to_numeric',
        explanation: `Datos reales siempre tienen problemas:
- **Nulos**: \`dropna(subset=[...])\`, \`fillna(valor)\`
- **Duplicados**: \`drop_duplicates()\`
- **Tipos incorrectos**: \`pd.to_numeric(col, errors='coerce')\`
- **Strings como NaN**: \`replace('NULL', pd.NA)\`

El orden importa: primero reemplazar strings → luego convertir tipos → luego nulos.`,
        starterCode: `import pandas as pd
from io import StringIO

raw = """ip,puerto,protocolo,bytes,pais,severidad
192.168.1.100,443,HTTPS,2048,MX,high
10.0.0.55,,TCP,,Unknown,medium
198.51.100.42,80,HTTP,15360,RU,critical
192.168.1.100,443,HTTPS,2048,MX,high
,22,SSH,512,CN,high
203.0.113.77,4444,TCP,NULL,US,critical
176.10.99.11,443,HTTPS,8192,,critical"""

df = pd.read_csv(StringIO(raw.strip()))
print(f"ANTES: {df.shape}  Nulos:\\n{df.isnull().sum().to_string()}\\n")

# Pipeline de limpieza
df = df.replace('NULL', pd.NA)               # strings vacíos → NaN real
df = df.dropna(subset=['ip'])                # IP es obligatoria
n_antes = len(df)
df = df.drop_duplicates()
print(f"Duplicados eliminados: {n_antes - len(df)}")

df['puerto'] = pd.to_numeric(df['puerto'], errors='coerce').fillna(0).astype(int)
df['bytes']  = pd.to_numeric(df['bytes'],  errors='coerce').fillna(df['bytes'].apply(pd.to_numeric, errors='coerce').median())
df['pais']   = df['pais'].fillna('Unknown')

print("DESPUÉS — datos limpios:")
print(df.to_string(index=False))
print(f"\\nShape final: {df.shape}")`,
        hint: 'Aplica df.info() antes y después de limpiar para comparar conteos de no-nulos.',
      },
      {
        id: 'etl-3', title: 'Parseo con regex',
        concept: 're.match, grupos nombrados, pd.DataFrame',
        explanation: `Los logs de IDS/WAF llegan como texto libre. **regex** permite extraer campos estructurados:

\`\`\`python
import re
pattern = r'SRC=(?P<src>[\\d.]+)'
m = re.search(pattern, linea)
m.group('src')  # extrae el grupo
\`\`\`

Los **grupos nombrados** (\`?P<nombre>\`) permiten usar \`m.groupdict()\` para obtener un diccionario directo.`,
        starterCode: `import pandas as pd
import re

# Logs en texto libre (IDS/WAF)
logs = [
    "2026-05-28T08:14:23Z [ALERT] SRC=192.168.1.100 DST=185.220.101.45 PORT=443 MSG='SQL injection'",
    "2026-05-28T08:15:01Z [INFO]  SRC=10.0.0.22 DST=8.8.8.8 PORT=53 MSG='DNS query'",
    "2026-05-28T08:16:44Z [ALERT] SRC=10.0.0.88 DST=198.51.100.42 PORT=80 MSG='Directory traversal'",
    "2026-05-28T08:17:12Z [BLOCK] SRC=10.0.0.33 DST=203.0.113.77 PORT=4444 MSG='C2 beacon bloqueado'",
    "2026-05-28T08:18:30Z [ALERT] SRC=10.0.0.44 DST=176.10.99.11 PORT=443 MSG='Malware download'",
    "2026-05-28T08:19:01Z [INFO]  SRC=10.0.0.55 DST=1.1.1.1 PORT=53 MSG='DNS query'",
]

pattern = (r'(?P<ts>\\S+T\\S+Z)\\s+\\[(?P<nivel>\\w+)\\]\\s+'
           r'SRC=(?P<src>[\\d.]+)\\s+DST=(?P<dst>[\\d.]+)\\s+'
           r"PORT=(?P<port>\\d+)\\s+MSG='(?P<msg>[^']+)'")

records = [m.groupdict() for log in logs if (m := re.match(pattern, log))]
df = pd.DataFrame(records)
df['port'] = df['port'].astype(int)

print("=== LOGS PARSEADOS ===")
print(df.to_string(index=False))

alertas = df[df['nivel'].isin(['ALERT', 'BLOCK'])]
print(f"\\n=== ALERTAS Y BLOQUEOS ({len(alertas)}) ===")
print(alertas[['ts', 'nivel', 'src', 'dst', 'msg']].to_string(index=False))
print(f"\\nIPs destino sospechosas: {alertas['dst'].unique().tolist()}")`,
        hint: 'Modifica el patrón para capturar también el protocolo si aparece como PROTO=TCP en el log.',
      },
    ],
  },

  // ── TRACK 3: Visualización ────────────────────────────────────────────────
  {
    id: 'viz', label: 'Visualización', icon: '📊', color: '#f97316', packages: ['matplotlib'],
    lessons: [
      {
        id: 'viz-1', title: 'Barras: IOCs por severidad y actor',
        concept: 'bar(), subplots(), stacked bars',
        explanation: `Matplotlib organiza las gráficas en **Figure** (lienzo) y **Axes** (cada gráfica).

\`fig, axes = plt.subplots(1, 2, figsize=(10, 4))\`

Para guardar en el browser usamos el backend \`Agg\` (sin pantalla) y exportamos a base64 PNG con \`_mostrar()\`.`,
        starterCode: PLT_SETUP + `
import json

# Usamos los IOCs reales del feed CTI
data = {
    'tipo':      ['IP', 'IP', 'IP', 'domain', 'domain', 'hash', 'hash', 'IP', 'domain', 'hash'],
    'severidad': ['critical', 'high', 'medium', 'critical', 'high', 'critical', 'medium', 'high', 'low', 'high'],
    'actor':     ['APT-Shadow', 'Black Lynx', 'LockBit', 'Black Lynx', 'APT-Shadow',
                  'LockBit', 'LockBit', 'APT-Shadow', 'Black Lynx', 'LockBit'],
}
df = pd.DataFrame(data)

fig, axes = plt.subplots(1, 2, figsize=(10, 4))

# --- Barras por severidad ---
orden   = ['critical', 'high', 'medium', 'low']
colores = {'critical': '#ef4444', 'high': '#f97316', 'medium': '#facc15', 'low': '#4ade80'}
conteo  = df['severidad'].value_counts().reindex(orden, fill_value=0)
bars    = axes[0].bar(conteo.index, conteo.values,
                      color=[colores[s] for s in conteo.index], width=0.55, alpha=0.85)
axes[0].set_title('IOCs por Severidad', color='#e2e8f0', fontsize=10, pad=8)
axes[0].set_ylabel('Cantidad')
for b, v in zip(bars, conteo.values):
    if v: axes[0].text(b.get_x()+b.get_width()/2, b.get_height()+.05,
                        str(v), ha='center', color='#e2e8f0', fontsize=9)

# --- Barras apiladas: tipo × actor ---
pivot  = df.groupby(['actor','tipo']).size().unstack(fill_value=0)
colors = {'IP': '#22d3ee', 'domain': '#a78bfa', 'hash': '#f97316'}
bottom = np.zeros(len(pivot))
for tipo in pivot.columns:
    vals = pivot[tipo].values
    axes[1].bar(pivot.index, vals, bottom=bottom, label=tipo,
                color=colors.get(tipo,'#64748b'), alpha=0.85, width=0.55)
    bottom += vals
axes[1].set_title('IOCs por Actor y Tipo', color='#e2e8f0', fontsize=10, pad=8)
axes[1].set_ylabel('Cantidad')
axes[1].legend(facecolor='#1e293b', edgecolor='#334155', labelcolor='#94a3b8', fontsize=8)
axes[1].tick_params(axis='x', labelrotation=15, labelsize=8)

plt.tight_layout(pad=2.0)
_mostrar()
print("✓ Gráfica generada")
print(f"Distribución: {df['severidad'].value_counts().to_dict()}")`,
        hint: 'Cambia el color de las barras críticas a "#ff0000" con más opacidad para resaltarlas más.',
      },
      {
        id: 'viz-2', title: 'Scatter: actividad de amenaza en el tiempo',
        concept: 'scatter(), plot() con fechas, media móvil',
        explanation: `Para datos temporales usa \`pd.date_range\` y el formatter de fechas de matplotlib.

**Media móvil** (rolling mean) suaviza ruido en series de tiempo:
\`\`\`python
serie.rolling(window=3, center=True, min_periods=1).mean()
\`\`\``,
        starterCode: PLT_SETUP + `
np.random.seed(42)
dias = pd.date_range('2026-05-01', periods=28)
actores = {
    'APT-Shadow': {'base': 4, 'color': '#22d3ee'},
    'Black Lynx':  {'base': 6, 'color': '#a78bfa'},
    'LockBit':     {'base': 8, 'color': '#ef4444'},
}

fig, ax = plt.subplots(figsize=(11, 4.5))
for actor, cfg in actores.items():
    actividad = np.random.poisson(cfg['base'], len(dias))
    actividad[10:14] += np.random.randint(5, 15, 4)   # pico a mitad de mes
    media = pd.Series(actividad).rolling(3, center=True, min_periods=1).mean()
    ax.scatter(dias, actividad, color=cfg['color'], label=actor, alpha=0.7, s=40, zorder=3)
    ax.plot(dias, media, color=cfg['color'], linewidth=1.5, alpha=0.55, linestyle='--')

ax.set_title('Actividad de Amenaza por Actor — Mayo 2026', color='#e2e8f0', fontsize=11, pad=10)
ax.set_xlabel('Fecha'); ax.set_ylabel('Eventos detectados')
ax.legend(facecolor='#1e293b', edgecolor='#334155', labelcolor='#e2e8f0', fontsize=9)
ax.xaxis.set_major_formatter(mdates.DateFormatter('%d/%m'))
plt.xticks(rotation=30)
ax.grid(True)
plt.tight_layout()
_mostrar()
print("✓ Scatter + tendencia generado")`,
        hint: 'Añade ax.axvspan(dias[10], dias[13], alpha=0.08, color="#ef4444") para resaltar el período de pico.',
      },
      {
        id: 'viz-3', title: 'Dashboard: panel multi-gráfica',
        concept: 'gridspec, heatmap manual, pie chart',
        explanation: `Un **dashboard** combina múltiples gráficas en una figura con \`plt.subplots(2, 2)\`.

Para un heatmap sin seaborn usamos \`imshow()\`:
\`\`\`python
ax.imshow(matrix, cmap='Reds', aspect='auto')
\`\`\``,
        starterCode: PLT_SETUP + `
np.random.seed(7)
actores = ['APT-Shadow', 'Black Lynx', 'LockBit']
ttps    = ['T1059', 'T1003', 'T1566', 'T1486', 'T1071', 'T1078']
sev_col = {'critical':'#ef4444','high':'#f97316','medium':'#facc15','low':'#4ade80'}
tipos   = {'IP': 45, 'domain': 30, 'hash': 25}

fig, axes = plt.subplots(2, 2, figsize=(12, 8))
fig.suptitle('CTI Dashboard — Mayo 2026', color='#e2e8f0', fontsize=13, y=1.01)

# 1. Pie: distribución de tipos de IOC
axes[0,0].pie(tipos.values(), labels=tipos.keys(), autopct='%1.0f%%',
              colors=['#22d3ee','#a78bfa','#f97316'], startangle=90,
              textprops={'color':'#94a3b8','fontsize':9})
axes[0,0].set_title('Distribución de IOCs', color='#e2e8f0', fontsize=10)

# 2. Barras horizontales: severidad
sev = {'critical': 12, 'high': 18, 'medium': 8, 'low': 3}
ys  = list(sev.keys())
xs  = list(sev.values())
axes[0,1].barh(ys, xs, color=[sev_col[s] for s in ys], alpha=0.85, height=0.5)
for i, v in enumerate(xs):
    axes[0,1].text(v+0.2, i, str(v), va='center', color='#e2e8f0', fontsize=9)
axes[0,1].set_title('IOCs por Severidad', color='#e2e8f0', fontsize=10)
axes[0,1].set_xlabel('Cantidad')

# 3. Heatmap TTP × Actor
matrix = np.random.randint(0, 10, (len(ttps), len(actores)))
im = axes[1,0].imshow(matrix, cmap='Blues', aspect='auto', vmin=0, vmax=10)
axes[1,0].set_xticks(range(len(actores))); axes[1,0].set_xticklabels(actores, fontsize=8, rotation=15)
axes[1,0].set_yticks(range(len(ttps)));   axes[1,0].set_yticklabels(ttps, fontsize=8)
axes[1,0].set_title('Uso de TTPs por Actor', color='#e2e8f0', fontsize=10)
for i in range(len(ttps)):
    for j in range(len(actores)):
        axes[1,0].text(j, i, matrix[i,j], ha='center', va='center', fontsize=8, color='#e2e8f0')

# 4. Línea: tendencia 4 semanas
semanas = ['S1','S2','S3','S4']
for actor, color in zip(actores, ['#22d3ee','#a78bfa','#ef4444']):
    vals = np.random.randint(10, 40, 4)
    axes[1,1].plot(semanas, vals, marker='o', color=color, label=actor, linewidth=2)
axes[1,1].set_title('Tendencia Semanal (IOCs)', color='#e2e8f0', fontsize=10)
axes[1,1].legend(facecolor='#1e293b', edgecolor='#334155', labelcolor='#e2e8f0', fontsize=8)
axes[1,1].grid(True)

plt.tight_layout(pad=2.5)
_mostrar()
print("✓ Dashboard de 4 paneles generado")`,
        hint: 'Cambia el colormap del heatmap a "Reds" para las amenazas más intensas, o a "YlOrRd" para un gradiente amarillo-rojo.',
      },
    ],
  },

  // ── TRACK 4: Machine Learning ─────────────────────────────────────────────
  {
    id: 'ml', label: 'Machine Learning', icon: '🤖', color: '#4ade80', packages: ['scikit-learn'],
    lessons: [
      {
        id: 'ml-1', title: 'Feature Engineering',
        concept: 'LabelEncoder, columnas calculadas, normalización',
        explanation: `Los modelos de ML solo trabajan con **números**. El primer paso es convertir categóricos:

- **LabelEncoder**: asigna un entero a cada categoría
- **Columnas calculadas**: derivar features útiles de las existentes (ej: \`is_external\`)
- **StandardScaler**: normalizar a media=0, desviación=1

Buen feature engineering supera un buen algoritmo con features pobres.`,
        starterCode: `import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, StandardScaler

data = {
    'tipo':     ['IP','domain','hash','IP','domain','hash','IP','domain'],
    'pais':     ['RU','CN','Unknown','MX','RU','Unknown','US','KP'],
    'puerto':   [443, 80, 0, 22, 4444, 0, 443, 53],
    'bytes':    [4096, 1024, 0, 512, 2048, 0, 8192, 256],
    'severidad':['critical','high','critical','medium','high','critical','low','critical'],
}
df = pd.DataFrame(data)

paises_riesgo = {'RU','CN','KP','IR'}
puertos_sospechosos = {4444, 8080, 1337}

df['is_external']  = df['pais'].isin(paises_riesgo).astype(int)
df['is_susp_port'] = df['puerto'].isin(puertos_sospechosos).astype(int)

le_tipo = LabelEncoder()
le_pais = LabelEncoder()
df['tipo_enc'] = le_tipo.fit_transform(df['tipo'])
df['pais_enc'] = le_pais.fit_transform(df['pais'])

features = ['tipo_enc','pais_enc','puerto','bytes','is_external','is_susp_port']
X = df[features]

scaler = StandardScaler()
X_norm = pd.DataFrame(scaler.fit_transform(X), columns=features)

print("=== FEATURES ORIGINALES ===")
print(df[features + ['severidad']].to_string(index=False))

print("\\n=== FEATURES NORMALIZADOS (media=0, std=1) ===")
print(X_norm.round(2).to_string(index=False))

print(f"\\nCodificación tipo: {dict(zip(le_tipo.classes_, range(len(le_tipo.classes_))))}")
print(f"Codificación país: {dict(zip(le_pais.classes_, range(len(le_pais.classes_))))}")`,
        hint: 'Añade df["bytes_log"] = np.log1p(df["bytes"]) para normalizar la distribución de bytes antes de escalar.',
      },
      {
        id: 'ml-2', title: 'Clasificación con RandomForest',
        concept: 'RandomForestClassifier, cross_val_score, feature_importances_',
        explanation: `**Random Forest** = ensamble de árboles de decisión. Ventajas:
- Robusto a overfitting
- Maneja variables mixtas
- Indica qué features son más importantes

**Cross-validation** (k-fold) evalúa el modelo k veces con distintos conjuntos de train/test para una métrica más confiable.`,
        starterCode: `import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import cross_val_score

np.random.seed(42)
n = 80
paises_riesgo = ['RU','CN','KP','IR']
paises_todos  = paises_riesgo + ['MX','US','DE','Unknown']

df = pd.DataFrame({
    'tipo':  np.random.choice(['IP','domain','hash'], n),
    'pais':  np.random.choice(paises_todos, n, p=[.12,.12,.08,.08,.15,.12,.13,.20]),
    'puerto':np.random.choice([80,443,22,53,4444,8080,0], n),
    'bytes': np.random.randint(0, 20000, n),
})

def sev(r):
    s = 0
    if r['pais'] in paises_riesgo: s += 3
    if r['puerto'] in [4444, 8080]: s += 4
    if r['bytes'] > 10000: s += 2
    return 'critical' if s>=7 else 'high' if s>=3 else 'medium' if s>=1 else 'low'

df['severidad'] = df.apply(sev, axis=1)

le_t = LabelEncoder(); le_p = LabelEncoder(); le_s = LabelEncoder()
X = pd.DataFrame({
    'tipo':  le_t.fit_transform(df['tipo']),
    'pais':  le_p.fit_transform(df['pais']),
    'puerto':df['puerto'], 'bytes':df['bytes'],
})
y = le_s.fit_transform(df['severidad'])

model = RandomForestClassifier(n_estimators=80, random_state=42)
scores = cross_val_score(model, X, y, cv=5, scoring='accuracy')
model.fit(X, y)

print("=== RANDOM FOREST — CLASIFICADOR DE SEVERIDAD ===")
print(f"Accuracy (5-fold CV): {scores.mean():.3f} ± {scores.std():.3f}")
print(f"Scores por fold: {[round(s,3) for s in scores]}")

print("\\n=== IMPORTANCIA DE FEATURES ===")
for f, imp in sorted(zip(X.columns, model.feature_importances_), key=lambda x:-x[1]):
    bar = '█' * int(imp * 35)
    print(f"  {f:<8} {bar} {imp:.3f}")

nuevo = pd.DataFrame({'tipo':[le_t.transform(['IP'])[0]],
                       'pais':[le_p.transform(['RU'])[0]],
                       'puerto':[4444], 'bytes':[15000]})
pred  = le_s.inverse_transform(model.predict(nuevo))[0]
proba = dict(zip(le_s.classes_, model.predict_proba(nuevo)[0].round(3)))
print(f"\\n=== PREDICCIÓN ===")
print(f"IOC: IP rusa, puerto 4444, 15k bytes → {pred.upper()}")
print(f"Probabilidades: {proba}")`,
        hint: 'Cambia n_estimators a 200 y compara la accuracy — ¿mejora o hay diminishing returns?',
      },
      {
        id: 'ml-3', title: 'Clustering con K-Means',
        concept: 'KMeans, StandardScaler, análisis de clusters',
        explanation: `**K-Means** agrupa datos en k clusters **sin etiquetas previas** (aprendizaje no supervisado). Útil para:
- Detectar grupos de comportamiento similar en IOCs
- Threat hunting: encontrar patrones anómalos
- Separar ruido de amenazas activas

**Inertia** mide qué tan compactos son los clusters (menor = mejor).`,
        starterCode: `import pandas as pd
import numpy as np
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler, LabelEncoder

np.random.seed(42)
n = 50
paises = ['RU','CN','KP','MX','US','Unknown']

df = pd.DataFrame({
    'tipo':       np.random.choice(['IP','domain','hash'], n),
    'pais':       np.random.choice(paises, n),
    'puerto':     np.random.choice([80,443,22,53,4444,0], n),
    'bytes':      np.random.randint(100, 20000, n),
    'conexiones': np.random.randint(1, 200, n),
})

le_t = LabelEncoder(); le_p = LabelEncoder()
X = pd.DataFrame({
    'tipo':       le_t.fit_transform(df['tipo']),
    'pais':       le_p.fit_transform(df['pais']),
    'puerto':     df['puerto'],
    'bytes':      df['bytes'],
    'conexiones': df['conexiones'],
})

X_scaled = StandardScaler().fit_transform(X)

# Encontrar k óptimo con el "codo" (elbow method)
print("=== MÉTODO DEL CODO (inercia por k) ===")
for k in range(2, 7):
    km = KMeans(n_clusters=k, random_state=42, n_init=10)
    km.fit(X_scaled)
    bar = '█' * int(km.inertia_ / 40)
    print(f"  k={k}  inercia={km.inertia_:.0f}  {bar}")

# Aplicar k=3
km3 = KMeans(n_clusters=3, random_state=42, n_init=10)
df['cluster'] = km3.fit_predict(X_scaled)

print("\\n=== CLUSTERS (k=3) ===")
for c in range(3):
    sub = df[df['cluster'] == c]
    print(f"\\nCluster {c} ({len(sub)} IOCs):")
    print(f"  Tipos:    {sub['tipo'].value_counts().to_dict()}")
    print(f"  Países:   {sub['pais'].value_counts().head(3).to_dict()}")
    print(f"  Puerto +frec: {sub['puerto'].mode()[0]}")
    print(f"  Bytes prom:   {sub['bytes'].mean():.0f}")

print("\\nClusters con muchos puertos 4444 y bytes altos = posible C2 activo.")`,
        hint: 'Busca el "codo" donde la inercia deja de bajar rápido — ese es el k óptimo. ¿Qué k sugiere el output?',
      },
    ],
  },
]

// ── Helpers ───────────────────────────────────────────────────────────────────

function loadPyodideScript(): Promise<void> {
  return new Promise((res, rej) => {
    if (window.loadPyodide) { res(); return }
    const s = document.createElement('script')
    s.src = 'https://cdn.jsdelivr.net/pyodide/v0.27.5/full/pyodide.js'
    s.onload  = () => res()
    s.onerror = () => rej(new Error('Pyodide CDN error'))
    document.head.appendChild(s)
  })
}

function OutputBlock({ raw }: { raw: string }): ReactNode {
  if (!raw) return null
  const parts = raw.split(/(__PLOT__:[A-Za-z0-9+/=]+)/)
  return (
    <>
      {parts.map((p, i) => {
        if (p.startsWith('__PLOT__:')) {
          return (
            <img key={i} src={`data:image/png;base64,${p.slice(9)}`}
                 className="max-w-full rounded-lg mt-2 mb-1" alt="Python plot" />
          )
        }
        return p ? <span key={i} className="whitespace-pre-wrap">{p}</span> : null
      })}
    </>
  )
}

// ── Component ─────────────────────────────────────────────────────────────────

export default function SandboxLab() {
  const { user } = useAuth()

  const [pyodide,     setPyodide]     = useState<PyodideInterface | null>(null)
  const [initStatus,  setInitStatus]  = useState<'loading' | 'ready' | 'error'>('loading')
  const [trackId,     setTrackId]     = useState('cti')
  const [lessonIdx,   setLessonIdx]   = useState(0)
  const [code,        setCode]        = useState('')
  const [output,      setOutput]      = useState('')
  const [running,     setRunning]     = useState(false)
  const [showHint,    setShowHint]    = useState(false)
  const [pkgLoading,  setPkgLoading]  = useState(false)
  const [loadedPkgs,  setLoadedPkgs]  = useState<Set<string>>(new Set())
  const [done,        setDone]        = useState<Set<string>>(new Set())
  const textareaRef = useRef<HTMLTextAreaElement>(null)

  const track  = TRACKS.find(t => t.id === trackId)!
  const lesson = track.lessons[lessonIdx]

  // Load progress from localStorage
  useEffect(() => {
    const saved = localStorage.getItem(`cti_progress_${user?.email}`)
    if (saved) setDone(new Set(JSON.parse(saved)))
  }, [user?.email])

  const saveDone = (next: Set<string>) => {
    setDone(next)
    localStorage.setItem(`cti_progress_${user?.email}`, JSON.stringify([...next]))
  }

  // Init Pyodide
  useEffect(() => {
    let cancelled = false
    async function init() {
      try {
        await loadPyodideScript()
        if (!window.loadPyodide) throw new Error('loadPyodide not found')
        const py = await window.loadPyodide({ indexURL: 'https://cdn.jsdelivr.net/pyodide/v0.27.5/full/' })
        await py.loadPackage(['pandas', 'numpy'])

        const res = await fetch(`${API_URL}/ioc-feed`)
        const iocs = await res.json()
        py.globals.set('_ioc_json', JSON.stringify(iocs))
        await py.runPythonAsync(`
import pandas as pd, json
ioc_df = pd.DataFrame(json.loads(_ioc_json))
`)
        if (!cancelled) { setPyodide(py); setInitStatus('ready') }
      } catch {
        if (!cancelled) setInitStatus('error')
      }
    }
    init()
    return () => { cancelled = true }
  }, [])

  // Set lesson code when track/lesson changes
  useEffect(() => {
    setCode(lesson.starterCode)
    setOutput('')
    setShowHint(false)
  }, [lesson.starterCode])

  const switchTrack = async (tid: string) => {
    const newTrack = TRACKS.find(t => t.id === tid)!
    setTrackId(tid)
    setLessonIdx(0)
    setOutput('')

    const missing = newTrack.packages.filter(p => !loadedPkgs.has(p))
    if (missing.length > 0 && pyodide) {
      setPkgLoading(true)
      await pyodide.loadPackage(missing)
      setLoadedPkgs(prev => new Set([...prev, ...missing]))
      setPkgLoading(false)
    }
  }

  const runCode = async () => {
    if (!pyodide || running || pkgLoading) return
    setRunning(true)
    setOutput('')
    try {
      await pyodide.runPythonAsync(`
import sys, io
_cap = io.StringIO()
sys.stdout = _cap
`)
      await pyodide.loadPackagesFromImports(code)
      await pyodide.runPythonAsync(code)
      const out = await pyodide.runPythonAsync(`sys.stdout = sys.__stdout__; _cap.getvalue()`)
      const outStr = String(out) || '(sin output)'
      setOutput(outStr)
      if (outStr && !outStr.startsWith('Error')) {
        const next = new Set(done)
        next.add(lesson.id)
        saveDone(next)
      }
    } catch (err) {
      try { await pyodide.runPythonAsync('import sys; sys.stdout = sys.__stdout__') } catch { /* ignore */ }
      setOutput(`Error:\n${err}`)
    } finally {
      setRunning(false)
    }
  }

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Tab') {
      e.preventDefault()
      const el = textareaRef.current!
      const { selectionStart: s, selectionEnd: end } = el
      setCode(code.slice(0, s) + '    ' + code.slice(end))
      requestAnimationFrame(() => { el.selectionStart = el.selectionEnd = s + 4 })
    }
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') runCode()
  }

  const totalLessons = TRACKS.reduce((n, t) => n + t.lessons.length, 0)
  const doneCount    = done.size

  // ── Loading states ──────────────────────────────────────────────────────────

  if (initStatus === 'loading') {
    return (
      <div className="rounded-xl p-10 border flex items-center gap-5"
           style={{ background: 'rgba(15,23,42,0.6)', border: '1px solid rgba(255,255,255,0.07)' }}>
        <div className="w-6 h-6 border-2 border-violet-400 border-t-transparent rounded-full animate-spin shrink-0" />
        <div>
          <p className="text-violet-400 font-semibold">Inicializando entorno Python...</p>
          <p className="text-slate-500 text-xs mt-1">Cargando Pyodide + pandas (~10 MB, se cachea después)</p>
        </div>
      </div>
    )
  }

  if (initStatus === 'error') {
    return (
      <div className="rounded-xl p-8 border border-red-900/50 text-red-400"
           style={{ background: 'rgba(15,23,42,0.6)' }}>
        <p className="font-semibold">Error cargando el entorno Python.</p>
        <p className="text-sm mt-1 text-red-500">Verifica tu conexión a internet — Pyodide carga desde CDN.</p>
      </div>
    )
  }

  // ── Main render ─────────────────────────────────────────────────────────────

  return (
    <div className="flex flex-col gap-4">

      {/* ── Header ─────────────────────────────────────────────────────────── */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-base font-semibold text-slate-100">Sandbox Lab</h2>
          <p className="text-xs text-slate-500 mt-0.5">
            Hola, <span className="text-cyan-400">{user?.name}</span> ·{' '}
            {doneCount}/{totalLessons} lecciones completadas
          </p>
        </div>
        {/* Progress bar */}
        <div className="flex items-center gap-3">
          <div className="w-32 h-1.5 rounded-full" style={{ background: 'rgba(255,255,255,0.06)' }}>
            <div className="h-full rounded-full transition-all"
                 style={{
                   width: `${totalLessons ? (doneCount / totalLessons) * 100 : 0}%`,
                   background: 'linear-gradient(to right, #22d3ee, #a78bfa)',
                 }} />
          </div>
          <span className="text-xs text-slate-600">{Math.round(doneCount / totalLessons * 100)}%</span>
        </div>
      </div>

      {/* ── Track tabs ─────────────────────────────────────────────────────── */}
      <div className="flex gap-2 flex-wrap">
        {TRACKS.map(t => {
          const trackDone = t.lessons.filter(l => done.has(l.id)).length
          const active    = t.id === trackId
          return (
            <button key={t.id} onClick={() => switchTrack(t.id)}
                    disabled={pkgLoading}
                    className="flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-medium transition-all disabled:opacity-50"
                    style={active ? {
                      background: `${t.color}18`,
                      border: `1px solid ${t.color}55`,
                      color: t.color,
                    } : {
                      background: 'rgba(255,255,255,0.03)',
                      border: '1px solid rgba(255,255,255,0.07)',
                      color: '#475569',
                    }}>
              <span>{t.icon}</span>
              <span>{t.label}</span>
              <span className="ml-1 text-[9px] font-bold px-1.5 py-0.5 rounded-full"
                    style={{
                      background: active ? `${t.color}22` : 'rgba(255,255,255,0.05)',
                      color: active ? t.color : '#334155',
                    }}>
                {trackDone}/{t.lessons.length}
              </span>
              {t.packages.length > 0 && !t.packages.every(p => loadedPkgs.has(p)) && (
                <span className="text-[9px] text-slate-700">↓</span>
              )}
            </button>
          )
        })}
      </div>

      {/* Package loading banner */}
      {pkgLoading && (
        <div className="flex items-center gap-3 rounded-xl px-4 py-3 text-xs"
             style={{ background: 'rgba(34,211,238,0.06)', border: '1px solid rgba(34,211,238,0.15)' }}>
          <div className="w-3.5 h-3.5 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin shrink-0" />
          <span className="text-cyan-400">
            Descargando paquetes para este track ({track.packages.join(', ')}) — solo la primera vez...
          </span>
        </div>
      )}

      {/* ── Editor area ────────────────────────────────────────────────────── */}
      <div className="rounded-xl overflow-hidden"
           style={{ background: 'rgba(15,23,42,0.55)', border: '1px solid rgba(255,255,255,0.07)' }}>

        <div className="flex" style={{ height: 640 }}>

          {/* Lesson sidebar */}
          <div className="w-52 shrink-0 flex flex-col border-r overflow-y-auto"
               style={{ borderColor: 'rgba(255,255,255,0.06)' }}>
            <div className="px-3 py-2.5 border-b"
                 style={{ borderColor: 'rgba(255,255,255,0.06)' }}>
              <p className="text-[9px] font-bold tracking-widest uppercase"
                 style={{ color: track.color }}>{track.icon} {track.label}</p>
            </div>
            {track.lessons.map((l, i) => {
              const isActive    = i === lessonIdx
              const isCompleted = done.has(l.id)
              return (
                <button key={l.id} onClick={() => { setLessonIdx(i); setOutput('') }}
                        className="text-left px-3 py-3 border-b transition-colors"
                        style={{
                          borderColor: 'rgba(255,255,255,0.04)',
                          background: isActive ? `${track.color}10` : 'transparent',
                          borderLeft: isActive ? `2px solid ${track.color}` : '2px solid transparent',
                        }}>
                  <div className="flex items-start gap-2">
                    <span className="text-[10px] shrink-0 mt-0.5">
                      {isCompleted ? '✓' : `${i+1}.`}
                    </span>
                    <div>
                      <p className="text-xs leading-tight"
                         style={{ color: isActive ? '#e2e8f0' : '#475569' }}>
                        {l.title}
                      </p>
                      <p className="text-[9px] mt-0.5"
                         style={{ color: isActive ? track.color : '#1e293b' }}>
                        {l.concept}
                      </p>
                    </div>
                  </div>
                </button>
              )
            })}
          </div>

          {/* Main editor */}
          <div className="flex-1 flex flex-col overflow-hidden min-w-0">

            {/* Explanation */}
            <div className="px-4 py-3 border-b overflow-y-auto"
                 style={{ borderColor: 'rgba(255,255,255,0.06)', maxHeight: 140, background: 'rgba(0,0,0,0.2)' }}>
              <p className="text-xs font-semibold text-slate-200 mb-1.5">{lesson.title}</p>
              <p className="text-[11px] text-slate-400 leading-relaxed whitespace-pre-wrap">
                {lesson.explanation.replace(/\*\*(.*?)\*\*/g, '$1').replace(/`([^`]+)`/g, '$1')}
              </p>
            </div>

            {/* Toolbar */}
            <div className="flex items-center justify-between px-4 py-2 border-b shrink-0"
                 style={{ borderColor: 'rgba(255,255,255,0.06)', background: 'rgba(0,0,0,0.3)' }}>
              <span className="text-[10px] font-mono text-slate-700">lab.py</span>
              <div className="flex items-center gap-2">
                <button onClick={() => setShowHint(h => !h)}
                        className="text-xs px-2 py-1 rounded transition-colors"
                        style={{ color: showHint ? '#facc15' : '#475569' }}>
                  💡 {showHint ? 'Ocultar' : 'Pista'}
                </button>
                <button onClick={() => { setCode(lesson.starterCode); setOutput('') }}
                        className="text-xs text-slate-600 hover:text-slate-300 px-2 py-1 rounded transition-colors">
                  Resetear
                </button>
                <button onClick={runCode} disabled={running || pkgLoading}
                        className="text-xs font-semibold px-3 py-1 rounded transition-all disabled:opacity-40"
                        style={{ background: `${track.color}22`, border: `1px solid ${track.color}55`, color: track.color }}>
                  {running ? 'Ejecutando...' : '▶ Ejecutar (Ctrl+Enter)'}
                </button>
              </div>
            </div>

            {showHint && (
              <div className="px-4 py-2 border-b text-xs text-yellow-300 shrink-0"
                   style={{ background: 'rgba(234,179,8,0.06)', borderColor: 'rgba(234,179,8,0.15)' }}>
                💡 {lesson.hint}
              </div>
            )}

            {/* Code editor */}
            <textarea
              ref={textareaRef}
              value={code}
              onChange={e => setCode(e.target.value)}
              onKeyDown={handleKeyDown}
              spellCheck={false}
              className="flex-1 resize-none focus:outline-none font-mono text-sm p-4 leading-relaxed"
              style={{ background: '#050a14', color: '#86efac', minHeight: 0 }}
            />
          </div>
        </div>

        {/* Output panel */}
        <div className="border-t" style={{ borderColor: 'rgba(255,255,255,0.06)', minHeight: 160, maxHeight: 320 }}>
          <div className="flex items-center gap-2 px-4 py-2 border-b"
               style={{ borderColor: 'rgba(255,255,255,0.05)', background: 'rgba(0,0,0,0.3)' }}>
            <span className="text-[10px] text-slate-600 uppercase tracking-wider">Output</span>
            {output && done.has(lesson.id) && (
              <span className="text-[9px] font-bold px-1.5 py-0.5 rounded ml-1"
                    style={{ background: 'rgba(74,222,128,0.1)', color: '#4ade80' }}>
                ✓ Completado
              </span>
            )}
            {output && (
              <button onClick={() => setOutput('')}
                      className="text-[10px] text-slate-700 hover:text-slate-500 ml-auto">
                Limpiar
              </button>
            )}
          </div>
          <div className="p-4 text-xs font-mono text-slate-300 overflow-auto" style={{ maxHeight: 280 }}>
            {running ? (
              <span className="animate-pulse" style={{ color: track.color }}>Ejecutando Python...</span>
            ) : output ? (
              <OutputBlock raw={output} />
            ) : (
              <span className="text-slate-700">El output aparecerá aquí · Ctrl+Enter para ejecutar</span>
            )}
          </div>
        </div>
      </div>

      {/* ── Help Bot ───────────────────────────────────────────────────────── */}
      <HelpBot currentCode={code} lessonTitle={`${track.label} — ${lesson.title}`} />

      {/* ── Footer nav ─────────────────────────────────────────────────────── */}
      <div className="flex items-center justify-between">
        <button onClick={() => {
            if (lessonIdx > 0) { setLessonIdx(i => i - 1) }
            else {
              const idx = TRACKS.findIndex(t => t.id === trackId)
              if (idx > 0) switchTrack(TRACKS[idx - 1].id)
            }
          }}
          className="text-xs text-slate-600 hover:text-slate-300 transition-colors px-3 py-1.5 rounded-lg"
          style={{ border: '1px solid rgba(255,255,255,0.06)' }}>
          ← Anterior
        </button>
        <span className="text-[10px] text-slate-700 font-mono">
          {track.label} · {lessonIdx + 1} / {track.lessons.length}
        </span>
        <button onClick={() => {
            if (lessonIdx < track.lessons.length - 1) { setLessonIdx(i => i + 1) }
            else {
              const idx = TRACKS.findIndex(t => t.id === trackId)
              if (idx < TRACKS.length - 1) switchTrack(TRACKS[idx + 1].id)
            }
          }}
          className="text-xs font-medium transition-colors px-3 py-1.5 rounded-lg"
          style={{ background: `${track.color}15`, border: `1px solid ${track.color}30`, color: track.color }}>
          Siguiente →
        </button>
      </div>
    </div>
  )
}

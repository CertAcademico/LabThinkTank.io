import { useEffect, useRef, useState } from 'react'

const API_URL = import.meta.env.VITE_API_URL ?? 'http://127.0.0.1:8000'

interface PyodideInterface {
  runPythonAsync: (code: string) => Promise<unknown>
  loadPackagesFromImports: (code: string) => Promise<void>
  globals: { set: (k: string, v: unknown) => void }
}

declare global { interface Window { loadPyodide?: (cfg: { indexURL: string }) => Promise<PyodideInterface> } }

interface Model {
  id: string
  label: string
  category: string
  categoryColor: string
  description: string
  theory: string
  code: string
  packages: string[]
}

const MODELS: Model[] = [
  {
    id: 'logistic',
    label: 'Regresión Logística',
    category: 'ML Clásico',
    categoryColor: 'text-cyan-400',
    description: 'Detectar URLs de phishing a partir de features estructurales (longitud, TLD, palabras clave).',
    theory: `La Regresión Logística aplica la función sigmoide a una combinación lineal de features:

  P(y=1|x) = 1 / (1 + e^(-wᵀx))

Donde w son los pesos aprendidos durante el entrenamiento con gradiente descendente.
En CTI: cada feature de la URL (longitud, TLD sospechoso, palabras clave) es una variable x.
El modelo aprende qué combinación de features predice mejor "phishing" vs "legítimo".

Ventajas: interpretable, rápido, bajo en recursos.
Limitación: asume separabilidad lineal — no captura relaciones no lineales entre features.`,
    packages: ['sklearn'],
    code: `from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import numpy as np

# === Dataset: features de URLs ===
# [longitud, tiene_ip, tld_sospechoso, palabras_phishing, guiones, subdominios]
X = np.array([
    # URLs phishing (label=1)
    [38, 0, 1, 1, 2, 3],   # evil-login-security.com
    [52, 0, 0, 1, 1, 2],   # secure-account-verify.bankofamerica.xyz
    [45, 1, 0, 0, 0, 0],   # 192.168.1.1/login.php
    [61, 0, 1, 1, 3, 4],   # microsoft-update-signin.tk/auth
    [33, 0, 0, 1, 2, 2],   # paypal-verify.top/account
    [48, 0, 1, 1, 1, 3],   # signin-banking.gq/portal
    # URLs legítimas (label=0)
    [18, 0, 0, 0, 0, 1],   # google.com/search
    [22, 0, 0, 0, 0, 1],   # github.com/anthropics
    [15, 0, 0, 0, 0, 0],   # amazon.com
    [25, 0, 0, 0, 0, 2],   # mail.company.com/inbox
    [20, 0, 0, 0, 0, 1],   # microsoft.com/login
    [19, 0, 0, 0, 0, 1],   # linkedin.com/feed
])
y = np.array([1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0])

feature_names = ['longitud', 'tiene_ip', 'tld_sospechoso',
                 'palabras_phishing', 'guiones', 'subdominios']

# === Entrenar modelo ===
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.3, random_state=42)

model = LogisticRegression(random_state=42)
model.fit(X_train, y_train)

# === Evaluación ===
y_pred = model.predict(X_test)
print("=== MODELO: Regresión Logística ===")
print(f"Accuracy: {model.score(X_test, y_test):.0%}\\n")
print(classification_report(y_test, y_pred,
      target_names=['Legítimo', 'Phishing']))

# === Interpretabilidad: pesos aprendidos ===
print("\\n=== FEATURES MÁS IMPORTANTES ===")
coefs = list(zip(feature_names, model.coef_[0]))
coefs.sort(key=lambda x: abs(x[1]), reverse=True)
for name, weight in coefs:
    bar = '█' * int(abs(weight) * 3)
    sign = '+' if weight > 0 else '-'
    print(f"  {name:<22} {sign}{abs(weight):.3f}  {bar}")

# === Predicción en nuevas URLs ===
print("\\n=== PREDICCIÓN IOC ACTIVO ===")
evil = np.array([[38, 0, 1, 1, 2, 3]])  # evil-login-security.com
prob = model.predict_proba(evil)[0][1]
print(f"  evil-login-security.com → Phishing probability: {prob:.0%}")`,
  },
  {
    id: 'random_forest',
    label: 'Random Forest',
    category: 'Ensemble Learning',
    categoryColor: 'text-green-400',
    description: 'Clasificar IOCs por nivel de riesgo usando múltiples árboles de decisión en paralelo.',
    theory: `Random Forest construye N árboles de decisión independientes, cada uno entrenado con:
  1. Una muestra aleatoria del dataset (bootstrap)
  2. Un subconjunto aleatorio de features en cada split

La predicción final es la votación mayoritaria de todos los árboles.

En CTI: cada árbol aprende una perspectiva diferente del IOC.
  Árbol 1: enfocado en geolocalización + ASN
  Árbol 2: enfocado en tipo + severidad
  Árbol 3: enfocado en actor attribution

Ventajas: robusto al overfitting, maneja features no lineales, importancia de features nativa.
Limitación: menos interpretable que regresión logística (caja gris).`,
    packages: ['sklearn'],
    code: `from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import cross_val_score
import numpy as np

# === Dataset IOCs ===
# Features: [tipo_ip, tipo_domain, tipo_hash, severidad_num, país_riesgo, tiene_actor, mitre_count]
# Tipo: IP=0, DOMAIN=1, HASH=2, URL=3
# Severidad: low=1, medium=2, high=3, critical=4
# País riesgo: RU/CN/KP/IR=1, otros=0

X = np.array([
    # [tipo, sev, país_riesgo, tiene_actor, mitre_count]  label: 0=low 1=medium 2=high 3=critical
    [0, 3, 1, 1, 2],  # 185.220.101.1 (Tor exit, APT-Shadow)        → high
    [1, 4, 1, 1, 3],  # evil-login-security.com (Black Lynx)         → critical
    [2, 4, 0, 1, 2],  # LockBit hash                                  → critical
    [0, 2, 0, 0, 0],  # IP pública sin actor                          → medium
    [1, 1, 0, 0, 0],  # dominio sin clasificar                        → low
    [0, 1, 0, 0, 0],  # RFC1918 private IP                            → low
    [1, 3, 1, 1, 2],  # dominio phishing CN actor                     → high
    [2, 4, 0, 0, 1],  # hash desconocido con 1 TTP                    → critical
    [0, 2, 1, 0, 1],  # IP en rango RU sin actor confirmado            → medium
    [1, 2, 0, 1, 1],  # dominio con actor pero baja sev                → medium
])
y = np.array([2, 3, 3, 1, 0, 0, 2, 3, 1, 1])
labels = ['low', 'medium', 'high', 'critical']

feature_names = ['tipo_ioc', 'severidad', 'pais_riesgo', 'tiene_actor', 'mitre_count']

# === Entrenar Random Forest ===
rf = RandomForestClassifier(n_estimators=100, max_depth=4, random_state=42)
rf.fit(X, y)

# === Cross-validation ===
scores = cross_val_score(rf, X, y, cv=3, scoring='accuracy')
print("=== MODELO: Random Forest ===")
print(f"Cross-validation accuracy: {scores.mean():.0%} ± {scores.std():.0%}\\n")

# === Feature importance ===
print("=== IMPORTANCIA DE FEATURES ===")
importances = list(zip(feature_names, rf.feature_importances_))
importances.sort(key=lambda x: x[1], reverse=True)
for name, imp in importances:
    bar = '█' * int(imp * 40)
    print(f"  {name:<18} {imp:.3f}  {bar}")

# === Predicción IOCs activos ===
print("\\n=== SCORING DE IOCs ACTIVOS ===")
test_iocs = [
    ([0, 3, 1, 1, 2], "185.220.101.1 (APT-Shadow)"),
    ([1, 4, 1, 1, 3], "evil-login-security.com (Black Lynx)"),
    ([2, 4, 0, 1, 2], "LockBit hash"),
]
for features, name in test_iocs:
    pred = rf.predict([features])[0]
    proba = rf.predict_proba([features])[0]
    conf = proba.max()
    print(f"  {name}")
    print(f"    → Risk: {labels[pred].upper()} (confidence: {conf:.0%})")`,
  },
  {
    id: 'nlp',
    label: 'NLP / TF-IDF',
    category: 'Procesamiento de Lenguaje Natural',
    categoryColor: 'text-purple-400',
    description: 'Clasificar reportes de amenazas por tipo de ataque usando vectorización TF-IDF.',
    theory: `TF-IDF (Term Frequency - Inverse Document Frequency) convierte texto en vectores numéricos:

  TF(t,d)  = frecuencia del término t en documento d
  IDF(t)   = log(N / df(t))  → penaliza palabras comunes

  TF-IDF(t,d) = TF(t,d) × IDF(t)

En CTI: un reporte de ransomware tendrá alta TF-IDF en "encrypted", "ransom", "bitcoin".
Un reporte de APT tendrá alta TF-IDF en "espionage", "lateral movement", "credential".

Naive Bayes complementa a TF-IDF para clasificación:
  P(clase|doc) ∝ P(clase) × ∏ P(palabra|clase)

Aplicación directa: auto-clasificar alertas de SIEM, tickets de incidentes, reportes de threat intel.`,
    packages: ['sklearn'],
    code: `from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline
from sklearn.model_selection import cross_val_score
import numpy as np

# === Dataset: fragmentos de reportes CTI ===
corpus = [
    # Ransomware
    "Files encrypted with AES-256. Bitcoin ransom demand. Shadow copies deleted. Lateral movement via SMB.",
    "LockBit affiliate deployed ransomware payload. Data exfiltrated before encryption. Ransom note dropped.",
    "All documents encrypted with unknown extension. Backup services stopped. Recovery inhibited via bcdedit.",
    # Espionage / APT
    "Long-term persistent access. Credential dumping from LSASS. Exfiltration of classified documents.",
    "State-sponsored actor conducted espionage campaign. Spear-phishing initial access. C2 over HTTPS.",
    "Custom implant ShadowLoader detected. Data collected over 8 months. NightBeacon used for C2 beacon.",
    # Phishing / Credential Theft
    "Phishing campaign targeting banking credentials. Fake login page. Session cookies stolen via LynxStealer.",
    "Mass phishing email with credential harvesting link. MFA bypass using stolen session tokens.",
    "Spear-phishing email impersonating HR department. Credential theft for VPN access. GhostDropper deployed.",
    # Vulnerability Exploitation
    "CVE-2021-44228 Log4Shell exploited for RCE. Reverse shell dropped. Privilege escalation to SYSTEM.",
    "Unpatched VPN appliance exploited. Webshell installed. Network reconnaissance conducted post-access.",
    "Zero-day exploit deployed against web application. SQL injection chain to OS command execution.",
]
labels = ['ransomware','ransomware','ransomware',
          'apt','apt','apt',
          'phishing','phishing','phishing',
          'exploitation','exploitation','exploitation']

# === Pipeline TF-IDF + Naive Bayes ===
pipeline = Pipeline([
    ('tfidf', TfidfVectorizer(ngram_range=(1,2), max_features=200, stop_words='english')),
    ('clf',   MultinomialNB(alpha=0.1)),
])

# === Cross-validation ===
scores = cross_val_score(pipeline, corpus, labels, cv=3, scoring='accuracy')
pipeline.fit(corpus, labels)

print("=== MODELO: NLP Threat Classification (TF-IDF + Naive Bayes) ===")
print(f"Cross-validation accuracy: {scores.mean():.0%}\\n")

# === Top features por clase ===
tfidf = pipeline.named_steps['tfidf']
clf   = pipeline.named_steps['clf']
vocab = tfidf.get_feature_names_out()
print("=== TOP FEATURES POR TIPO DE ATAQUE ===")
for i, clase in enumerate(clf.classes_):
    top_idx = clf.feature_log_prob_[i].argsort()[-5:][::-1]
    print(f"  {clase.upper()}: {', '.join(vocab[top_idx])}")

# === Clasificar nuevos reportes ===
print("\\n=== CLASIFICACIÓN DE REPORTES NUEVOS ===")
nuevos = [
    "Encrypted files found on file server. Ransom demand in Monero cryptocurrency. VSS deleted.",
    "Implant detected maintaining persistence for 6 months. Classified data exfiltrated via DNS tunneling.",
    "Fake Microsoft login page capturing corporate credentials and MFA tokens.",
]
preds = pipeline.predict(nuevos)
probas = pipeline.predict_proba(nuevos)
for text, pred, proba in zip(nuevos, preds, probas):
    conf = proba.max()
    print(f"  [{pred.upper()} {conf:.0%}] {text[:65]}...")`,
  },
  {
    id: 'isolation_forest',
    label: 'Isolation Forest',
    category: 'Anomaly Detection',
    categoryColor: 'text-orange-400',
    description: 'Detectar comportamiento anómalo en logs de red usando detección de anomalías no supervisada.',
    theory: `Isolation Forest detecta anomalías aislando puntos de datos:

  Principio: los puntos anómalos son más fáciles de aislar que los normales.

  Algoritmo:
  1. Selecciona feature aleatoria
  2. Selecciona split point aleatorio entre min y max
  3. Repite hasta aislar el punto
  4. Anomaly score = promedio de profundidad en todos los árboles

  Puntos que se aíslan rápido (poca profundidad) → anómalos
  Puntos normales requieren más splits para ser aislados

En CTI/SOC:
  - Detectar beaconing C2 (intervalos regulares inusuales)
  - Exfiltración de datos (volúmenes anómalos)
  - Movimiento lateral (conexiones internas inusuales)

Ventaja: no supervisado → no requiere ejemplos etiquetados de ataques.`,
    packages: ['sklearn'],
    code: `from sklearn.ensemble import IsolationForest
import numpy as np

np.random.seed(42)

# === Dataset: logs de conexiones de red ===
# Features: [bytes_out, bytes_in, duration_secs, dest_port, conexiones_hora, intervalo_reg]
# intervalo_reg: 0=irregular, 1=muy regular (beaconing)

# Tráfico normal (250 muestras)
normal = np.column_stack([
    np.random.normal(5000,  2000, 250),   # bytes_out
    np.random.normal(15000, 5000, 250),   # bytes_in
    np.random.normal(120,   60,   250),   # duración (seg)
    np.random.choice([80, 443, 8080, 8443, 53], 250),  # puerto destino
    np.random.normal(10, 4, 250),         # conexiones/hora
    np.random.uniform(0, 0.3, 250),       # irregularidad del intervalo
])

# Anomalías (beaconing C2, exfiltración, escaneo)
anomalias = np.array([
    # Beaconing C2 (conexiones regulares cada 60s, poco tráfico)
    [500,  200,  5,  443, 60, 0.02],
    [480,  210,  5,  443, 60, 0.01],
    [510,  195,  4,  443, 60, 0.03],
    # Exfiltración masiva
    [500000, 1000, 3600, 443, 2, 0.8],
    [750000, 800,  7200, 80,  1, 0.9],
    # Escaneo de puertos (muchas conexiones rápidas)
    [100, 50,  0.1, 22,  500, 0.95],
    [80,  40,  0.1, 3389, 450, 0.97],
])

X = np.vstack([normal, anomalias])
true_labels = ['normal']*250 + ['anomalia']*7

# === Entrenar Isolation Forest ===
iso = IsolationForest(contamination=0.05, n_estimators=200, random_state=42)
iso.fit(X)
scores = iso.score_samples(X)
preds  = iso.predict(X)  # 1=normal, -1=anomalía

detected = [true_labels[i] for i, p in enumerate(preds) if p == -1]
fp = detected.count('normal')
tp = detected.count('anomalia')

print("=== MODELO: Isolation Forest (Anomaly Detection) ===")
print(f"Muestras analizadas: {len(X)}")
print(f"Anomalías detectadas: {sum(preds == -1)}")
print(f"  ✓ True positives (ataques reales detectados): {tp}/{7}")
print(f"  ✗ False positives (tráfico normal flaggeado): {fp}")

# === Top anomalías por score ===
print("\\n=== TOP 5 CONEXIONES MÁS ANÓMALAS ===")
feature_names = ['bytes_out', 'bytes_in', 'duration', 'dst_port', 'conn/h', 'regularity']
top_idx = scores.argsort()[:5]
for rank, idx in enumerate(top_idx, 1):
    print(f"  #{rank} [score {scores[idx]:.3f}] {true_labels[idx].upper()}")
    for fname, val in zip(feature_names, X[idx]):
        print(f"       {fname}: {val:.1f}")

# === Umbral adaptable ===
threshold = np.percentile(scores, 5)
print(f"\\n  Umbral de anomalía (percentil 5%): {threshold:.3f}")
print(f"  Ajusta contamination para modificar sensibilidad.")`,
  },
]

function loadPyodideScript(): Promise<void> {
  return new Promise((resolve, reject) => {
    if (window.loadPyodide) { resolve(); return }
    const script = document.createElement('script')
    script.src = 'https://cdn.jsdelivr.net/pyodide/v0.27.5/full/pyodide.js'
    script.onload = () => resolve()
    script.onerror = () => reject(new Error('Failed to load Pyodide'))
    document.head.appendChild(script)
  })
}

function MLModelsTab() {
  const [pyodide, setPyodide]         = useState<PyodideInterface | null>(null)
  const [initStatus, setInitStatus]   = useState<'loading' | 'ready' | 'error'>('loading')
  const [activeModel, setActiveModel] = useState(0)
  const [code, setCode]               = useState(MODELS[0].code)
  const [output, setOutput]           = useState('')
  const [running, setRunning]         = useState(false)
  const [llmLoading, setLlmLoading]   = useState(false)
  const [llmExplanation, setLlmExplanation] = useState('')
  const [showTheory, setShowTheory]   = useState(false)
  const textareaRef = useRef<HTMLTextAreaElement>(null)

  useEffect(() => {
    let cancelled = false
    async function init() {
      try {
        await loadPyodideScript()
        if (!window.loadPyodide) throw new Error()
        const py = await window.loadPyodide({ indexURL: 'https://cdn.jsdelivr.net/pyodide/v0.27.5/full/' })
        await py.loadPackagesFromImports('import sklearn, numpy as np')
        if (!cancelled) { setPyodide(py); setInitStatus('ready') }
      } catch { if (!cancelled) setInitStatus('error') }
    }
    init()
    return () => { cancelled = true }
  }, [])

  const selectModel = (idx: number) => {
    setActiveModel(idx)
    setCode(MODELS[idx].code)
    setOutput('')
    setLlmExplanation('')
    setShowTheory(false)
  }

  const runCode = async () => {
    if (!pyodide || running) return
    setRunning(true)
    setOutput('')
    try {
      await pyodide.runPythonAsync(`import sys, io\n_out = io.StringIO()\nsys.stdout = _out`)
      await pyodide.runPythonAsync(code)
      const out = await pyodide.runPythonAsync(`sys.stdout = sys.__stdout__\n_out.getvalue()`)
      setOutput(String(out) || '(no output)')
    } catch (err) {
      try { await pyodide.runPythonAsync('import sys; sys.stdout = sys.__stdout__') } catch { /* ignore */ }
      setOutput(`Error:\n${err}`)
    } finally { setRunning(false) }
  }

  const askLlama = async () => {
    const model = MODELS[activeModel]
    setLlmLoading(true)
    setLlmExplanation('')
    try {
      const res = await fetch(`${API_URL}/ai/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: `Explain the following ML model used in CTI (Cyber Threat Intelligence) context.
Model: ${model.label} (${model.category})
Use case: ${model.description}

Explain in 3 sections:
1. How the algorithm works mathematically (simple explanation)
2. Why it's useful specifically for cybersecurity/CTI analysts
3. Limitations and when NOT to use it

Keep it technical but accessible for a SOC analyst learning ML.`
        })
      })
      const data = await res.json()
      setLlmExplanation(data.response)
    } catch { setLlmExplanation('Error connecting to Llama. Make sure Ollama is running.') }
    finally { setLlmLoading(false) }
  }

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Tab') {
      e.preventDefault()
      const el = textareaRef.current!
      const start = el.selectionStart; const end = el.selectionEnd
      setCode(code.slice(0, start) + '    ' + code.slice(end))
      requestAnimationFrame(() => { el.selectionStart = el.selectionEnd = start + 4 })
    }
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') runCode()
  }

  const model = MODELS[activeModel]

  if (initStatus === 'loading') return (
    <div className="bg-slate-900 rounded-xl p-8 border border-slate-700 flex items-center gap-4">
      <div className="w-5 h-5 border-2 border-orange-400 border-t-transparent rounded-full animate-spin" />
      <div>
        <p className="text-orange-400 font-semibold">Initializing Python + sklearn...</p>
        <p className="text-slate-500 text-xs mt-1">Cargando Pyodide + scikit-learn desde CDN</p>
      </div>
    </div>
  )

  if (initStatus === 'error') return (
    <div className="bg-slate-900 rounded-xl p-8 border border-red-900 text-red-400">
      <p className="font-semibold">No se pudo cargar el entorno Python.</p>
      <p className="text-sm mt-1">Verifica conexión a internet — Pyodide carga desde CDN.</p>
    </div>
  )

  return (
    <div className="bg-slate-900 rounded-xl border border-slate-700 overflow-hidden">
      {/* Header */}
      <div className="px-6 py-4 border-b border-slate-700 flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-semibold text-orange-400">AI / ML Models Lab</h2>
          <p className="text-slate-500 text-xs mt-0.5">sklearn · Pyodide · Llama3 tutor integrado</p>
        </div>
        <span className="flex items-center gap-1.5 text-xs text-green-400 bg-green-950 border border-green-800 rounded-full px-3 py-1">
          <span className="w-1.5 h-1.5 rounded-full bg-green-400 animate-pulse" />
          sklearn ready
        </span>
      </div>

      <div className="flex h-[720px]">
        {/* Sidebar */}
        <div className="w-56 border-r border-slate-700 flex flex-col overflow-y-auto shrink-0">
          {MODELS.map((m, i) => (
            <button
              key={m.id}
              onClick={() => selectModel(i)}
              className={`text-left px-4 py-4 border-b border-slate-800 transition-colors ${
                i === activeModel
                  ? 'bg-orange-950/50 border-l-2 border-l-orange-500 text-white'
                  : 'text-slate-400 hover:bg-slate-800 hover:text-white'
              }`}
            >
              <span className={`block text-[10px] font-bold mb-1 ${m.categoryColor}`}>{m.category}</span>
              <span className="block text-sm font-semibold leading-tight">{m.label}</span>
              <span className="block text-[10px] text-slate-500 mt-1 leading-tight">{m.description.slice(0, 55)}…</span>
            </button>
          ))}
        </div>

        {/* Main */}
        <div className="flex-1 flex flex-col overflow-hidden">
          {/* Model header */}
          <div className="px-5 py-4 border-b border-slate-700 bg-slate-950/30">
            <div className="flex items-start justify-between">
              <div>
                <span className={`text-xs font-bold ${model.categoryColor}`}>{model.category}</span>
                <h3 className="text-white font-bold text-lg">{model.label}</h3>
                <p className="text-slate-400 text-sm">{model.description}</p>
              </div>
              <div className="flex gap-2 shrink-0 ml-4">
                <button
                  onClick={() => setShowTheory(t => !t)}
                  className="text-xs px-3 py-1.5 rounded-lg bg-slate-800 text-slate-300 hover:text-white transition-colors"
                >
                  {showTheory ? 'Ocultar teoría' : '📐 Ver teoría'}
                </button>
                <button
                  onClick={askLlama}
                  disabled={llmLoading}
                  className="text-xs px-3 py-1.5 rounded-lg bg-orange-900 border border-orange-700 text-orange-300 hover:bg-orange-800 disabled:opacity-40 transition-colors"
                >
                  {llmLoading ? '⏳ Llama pensando...' : '🦙 Explicar con Llama'}
                </button>
              </div>
            </div>

            {showTheory && (
              <pre className="mt-3 bg-black/40 border border-slate-700 rounded-lg p-4 text-slate-300 text-xs font-mono leading-relaxed whitespace-pre-wrap overflow-auto max-h-48">
                {model.theory}
              </pre>
            )}

            {llmExplanation && (
              <div className="mt-3 bg-orange-950/30 border border-orange-900 rounded-lg p-4 text-slate-200 text-xs leading-relaxed max-h-48 overflow-auto">
                <p className="text-orange-400 text-[10px] font-bold uppercase mb-2">Llama3 Explanation</p>
                {llmExplanation}
              </div>
            )}
          </div>

          {/* Code editor */}
          <div className="flex-1 flex flex-col overflow-hidden">
            <div className="flex items-center justify-between px-4 py-2 bg-slate-950 border-b border-slate-800">
              <span className="text-xs text-slate-500 font-mono">{model.id}.py</span>
              <div className="flex gap-2">
                <button
                  onClick={() => { setCode(model.code); setOutput('') }}
                  className="text-xs text-slate-400 hover:text-slate-200 transition-colors px-2 py-1 rounded"
                >
                  Resetear
                </button>
                <button
                  onClick={runCode}
                  disabled={running}
                  className="text-xs bg-orange-600 hover:bg-orange-700 disabled:opacity-40 text-white px-3 py-1 rounded font-semibold transition-colors"
                >
                  {running ? 'Ejecutando...' : '▶ Ejecutar (Ctrl+Enter)'}
                </button>
              </div>
            </div>

            <textarea
              ref={textareaRef}
              value={code}
              onChange={e => setCode(e.target.value)}
              onKeyDown={handleKeyDown}
              spellCheck={false}
              className="flex-1 bg-slate-950 text-green-300 font-mono text-xs p-4 resize-none focus:outline-none leading-relaxed"
              style={{ minHeight: '180px' }}
            />
          </div>

          {/* Output */}
          <div className="border-t border-slate-700 bg-black/40" style={{ height: '200px', overflow: 'hidden' }}>
            <div className="flex items-center gap-2 px-4 py-1.5 border-b border-slate-800">
              <span className="text-xs text-slate-500">Output</span>
              {output && (
                <button onClick={() => setOutput('')} className="text-xs text-slate-600 hover:text-slate-400 ml-auto">
                  Limpiar
                </button>
              )}
            </div>
            <pre className="p-4 text-xs font-mono text-slate-200 overflow-auto h-full leading-relaxed whitespace-pre-wrap">
              {running
                ? <span className="text-orange-400 animate-pulse">Entrenando modelo...</span>
                : output || <span className="text-slate-600">El output aparecerá aquí... (Ctrl+Enter para ejecutar)</span>
              }
            </pre>
          </div>
        </div>
      </div>
    </div>
  )
}

export default MLModelsTab

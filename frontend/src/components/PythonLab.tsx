import { useEffect, useRef, useState } from 'react'

const API_URL = import.meta.env.VITE_API_URL ?? 'http://127.0.0.1:8000'

// ── Types ────────────────────────────────────────────────────────────────────

interface PyodideInterface {
  runPythonAsync: (code: string) => Promise<unknown>
  loadPackagesFromImports: (code: string) => Promise<void>
  globals: { set: (k: string, v: unknown) => void }
}

declare global {
  interface Window {
    loadPyodide?: (cfg: { indexURL: string }) => Promise<PyodideInterface>
  }
}

interface Lesson {
  id: number
  title: string
  concept: string
  explanation: string
  starterCode: string
  hint: string
}

// ── Lessons ──────────────────────────────────────────────────────────────────

const LESSONS: Lesson[] = [
  {
    id: 1,
    title: 'Explorando los datos CTI',
    concept: 'DataFrames y visualización básica',
    explanation: `Los datos de threat intelligence se cargan automáticamente como un **DataFrame de pandas** llamado \`ioc_df\`.

Un DataFrame es como una tabla con filas y columnas. Puedes inspeccionarlo con:
- \`print(ioc_df)\` — muestra toda la tabla
- \`ioc_df.shape\` — filas, columnas
- \`ioc_df.columns.tolist()\` — lista de columnas
- \`ioc_df.dtypes\` — tipos de cada columna`,
    starterCode: `# Los IOCs del feed CTI están en ioc_df
print("=== DATOS CTI CARGADOS ===")
print(ioc_df)

print(f"\\nTotal de registros: {ioc_df.shape[0]}")
print(f"Columnas: {ioc_df.columns.tolist()}")`,
    hint: 'Prueba también: print(ioc_df.describe(include="all")) para un resumen estadístico.',
  },
  {
    id: 2,
    title: 'Filtrar IOCs por severidad',
    concept: 'Filtrado condicional con boolean indexing',
    explanation: `El **filtrado condicional** permite seleccionar filas que cumplen una condición.

Sintaxis: \`df[df['columna'] == 'valor']\`

Puedes combinar condiciones con:
- \`&\` (AND): ambas condiciones deben ser verdaderas
- \`|\` (OR): al menos una condición es verdadera

Ejemplo: \`df[(df['severity'] == 'critical') & (df['type'] == 'IP')]\``,
    starterCode: `# Filtra solo los IOCs de severidad crítica
criticos = ioc_df[ioc_df['severity'] == 'critical']

print(f"IOCs críticos: {len(criticos)} de {len(ioc_df)} total")
print()
print(criticos[['ioc', 'type', 'threat_actor', 'mitre']])

# Ahora filtra críticos O altos (intenta tú solo)
# alto_riesgo = ioc_df[...]`,
    hint: 'Para filtrar por múltiples valores usa .isin(): df[df["severity"].isin(["critical","high"])]',
  },
  {
    id: 3,
    title: 'Agrupar y contar por actor',
    concept: 'groupby() y agregaciones',
    explanation: `**groupby()** agrupa filas que comparten el mismo valor en una columna, permitiendo calcular estadísticas por grupo.

Flujo típico:
\`\`\`
df.groupby('columna')   # agrupa
  .size()               # cuenta filas por grupo
  .reset_index()        # convierte de índice a columna
  .sort_values(...)     # ordena
\`\`\`

También puedes usar \`.agg()\` para múltiples estadísticas a la vez.`,
    starterCode: `# ¿Cuántos IOCs tiene cada threat actor?
por_actor = (
    ioc_df
    .groupby('threat_actor')
    .size()
    .reset_index(name='total_iocs')
    .sort_values('total_iocs', ascending=False)
)
print("=== IOCs POR ACTOR ===")
print(por_actor)

# ¿Cuántos IOCs de cada tipo tiene cada actor?
pivot = ioc_df.groupby(['threat_actor', 'type']).size().unstack(fill_value=0)
print("\\n=== TIPO DE IOC POR ACTOR ===")
print(pivot)`,
    hint: 'Prueba .agg({"ioc": "count", "severity": lambda x: x.value_counts().index[0]}) para obtener la severidad más común por actor.',
  },
  {
    id: 4,
    title: 'Ordenar y seleccionar columnas',
    concept: 'sort_values(), loc[], iloc[]',
    explanation: `Dos formas de seleccionar datos:
- **\`loc\`**: selección por etiqueta (nombre de columna o índice con label)
- **\`iloc\`**: selección por posición numérica (fila 0, columna 2, etc.)

Para ordenar: \`df.sort_values('columna', ascending=False)\`

Para seleccionar columnas específicas: \`df[['col1', 'col2']]\``,
    starterCode: `# Ordena por severidad (crítico primero)
orden_severidad = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
ioc_ordenado = ioc_df.copy()
ioc_ordenado['orden'] = ioc_ordenado['severity'].map(orden_severidad)
ioc_ordenado = ioc_ordenado.sort_values('orden').drop(columns='orden')

print("=== IOCs ORDENADOS POR RIESGO ===")
print(ioc_ordenado[['ioc', 'type', 'severity', 'threat_actor', 'country']].to_string(index=False))

# iloc: selecciona la primera fila
print("\\n=== IOC MÁS CRÍTICO ===")
primero = ioc_ordenado.iloc[0]
print(f"IOC:    {primero['ioc']}")
print(f"Actor:  {primero['threat_actor']}")
print(f"País:   {primero['country']}")`,
    hint: 'Usa .to_string(index=False) para imprimir DataFrames sin el índice numérico de la izquierda.',
  },
  {
    id: 5,
    title: 'Análisis de amenazas activas',
    concept: 'apply(), lambda y análisis compuesto',
    explanation: `**\`apply()\`** ejecuta una función en cada fila o columna.

Con \`axis=1\` aplica la función fila por fila. Muy útil para crear nuevas columnas calculadas:
\`\`\`python
df['nueva_col'] = df.apply(lambda row: ..., axis=1)
\`\`\`

Este es el patrón para generar alertas, etiquetas, o puntajes de riesgo personalizados.`,
    starterCode: `# Genera un score de riesgo numérico para cada IOC
score_map = {'critical': 10, 'high': 7, 'medium': 4, 'low': 1}

def calcular_prioridad(row):
    score = score_map.get(row['severity'], 4)
    # Penalización adicional si el país es conocido
    paises_riesgo = {'RU', 'CN', 'KP', 'IR'}
    if row.get('country') in paises_riesgo:
        score += 3
    return min(score, 10)

ioc_df['risk_score'] = ioc_df.apply(calcular_prioridad, axis=1)

resultado = ioc_df[['ioc', 'severity', 'threat_actor', 'country', 'risk_score']] \\
    .sort_values('risk_score', ascending=False)

print("=== RANKING DE IOCs POR RIESGO ===")
print(resultado.to_string(index=False))

alto = resultado[resultado['risk_score'] >= 8]
print(f"\\n⚠ IOCs de acción inmediata (score ≥ 8): {len(alto)}")
for _, row in alto.iterrows():
    print(f"  [{row['risk_score']}/10] {row['ioc']} ({row['threat_actor']})")`,
    hint: 'Combina este score con el endpoint /ai/analyze/{ioc} para obtener recomendaciones automáticas por cada IOC de alto riesgo.',
  },
]

// ── Pyodide loader ───────────────────────────────────────────────────────────

function loadPyodideScript(): Promise<void> {
  return new Promise((resolve, reject) => {
    if (window.loadPyodide) { resolve(); return }
    const script = document.createElement('script')
    script.src = 'https://cdn.jsdelivr.net/pyodide/v0.27.5/full/pyodide.js'
    script.onload = () => resolve()
    script.onerror = () => reject(new Error('Failed to load Pyodide from CDN'))
    document.head.appendChild(script)
  })
}

// ── Component ────────────────────────────────────────────────────────────────

function PythonLab() {
  const [pyodide, setPyodide] = useState<PyodideInterface | null>(null)
  const [initStatus, setInitStatus] = useState<'loading' | 'ready' | 'error'>('loading')
  const [activeLesson, setActiveLesson] = useState(0)
  const [code, setCode] = useState(LESSONS[0].starterCode)
  const [output, setOutput] = useState('')
  const [running, setRunning] = useState(false)
  const [showHint, setShowHint] = useState(false)
  const textareaRef = useRef<HTMLTextAreaElement>(null)

  // Init Pyodide once
  useEffect(() => {
    let cancelled = false

    async function init() {
      try {
        setInitStatus('loading')
        await loadPyodideScript()
        if (!window.loadPyodide) throw new Error('Pyodide script loaded but loadPyodide is not available')
        const py = await window.loadPyodide({
          indexURL: 'https://cdn.jsdelivr.net/pyodide/v0.27.5/full/'
        })
        await py.loadPackagesFromImports('import pandas as pd, json')

        // Fetch CTI data and inject as DataFrame
        const res = await fetch(`${API_URL}/ioc-feed`)
        const iocs = await res.json()
        py.globals.set('_ioc_json', JSON.stringify(iocs))
        await py.runPythonAsync(`
import pandas as pd, json
ioc_df = pd.DataFrame(json.loads(_ioc_json))
`)
        if (!cancelled) {
          setPyodide(py)
          setInitStatus('ready')
        }
      } catch {
        if (!cancelled) setInitStatus('error')
      }
    }

    init()
    return () => { cancelled = true }
  }, [])

  // Switch lesson → restore starter code
  const selectLesson = (idx: number) => {
    setActiveLesson(idx)
    setCode(LESSONS[idx].starterCode)
    setOutput('')
    setShowHint(false)
  }

  const runCode = async () => {
    if (!pyodide || running) return
    setRunning(true)
    setOutput('')

    try {
      // Capture stdout
      await pyodide.runPythonAsync(`
import sys, io
_stdout_capture = io.StringIO()
sys.stdout = _stdout_capture
`)
      await pyodide.runPythonAsync(code)
      const out = await pyodide.runPythonAsync(`
sys.stdout = sys.__stdout__
_stdout_capture.getvalue()
`)
      setOutput(String(out) || '(no output)')
    } catch (err) {
      try {
        await pyodide.runPythonAsync('import sys; sys.stdout = sys.__stdout__')
      } catch { /* ignore */ }
      setOutput(`Error:\n${err}`)
    } finally {
      setRunning(false)
    }
  }

  // Tab key support in textarea
  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Tab') {
      e.preventDefault()
      const el = textareaRef.current!
      const start = el.selectionStart
      const end = el.selectionEnd
      const spaces = '    '
      setCode(code.substring(0, start) + spaces + code.substring(end))
      requestAnimationFrame(() => {
        el.selectionStart = el.selectionEnd = start + spaces.length
      })
    }
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') runCode()
  }

  const lesson = LESSONS[activeLesson]

  // ── Render ─────────────────────────────────────────────────────────────────

  if (initStatus === 'loading') {
    return (
      <div className="bg-slate-900 rounded-xl p-8 border border-slate-700 flex items-center gap-4">
        <div className="w-5 h-5 border-2 border-violet-400 border-t-transparent rounded-full animate-spin" />
        <div>
          <p className="text-violet-400 font-semibold">Initializing Python environment...</p>
          <p className="text-slate-500 text-xs mt-1">Loading Pyodide + pandas (first load ~5 MB, subsequent loads are cached)</p>
        </div>
      </div>
    )
  }

  if (initStatus === 'error') {
    return (
      <div className="bg-slate-900 rounded-xl p-8 border border-red-900 text-red-400">
        <p className="font-semibold">Failed to load Python environment.</p>
        <p className="text-sm mt-1 text-red-500">Check your internet connection — Pyodide loads from CDN on first use.</p>
      </div>
    )
  }

  return (
    <div className="bg-slate-900 rounded-xl border border-slate-700 overflow-hidden">

      {/* Header */}
      <div className="px-6 py-4 border-b border-slate-700 flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-semibold text-violet-400">Python CTI Lab</h2>
          <p className="text-slate-500 text-xs mt-0.5">Python 3 · pandas · datos CTI en vivo</p>
        </div>
        <span className="flex items-center gap-1.5 text-xs text-green-400 bg-green-950 border border-green-800 rounded-full px-3 py-1">
          <span className="w-1.5 h-1.5 rounded-full bg-green-400 animate-pulse" />
          Python ready
        </span>
      </div>

      <div className="flex h-[680px]">

        {/* Lesson sidebar */}
        <div className="w-56 border-r border-slate-700 flex flex-col overflow-y-auto shrink-0">
          {LESSONS.map((l, i) => (
            <button
              key={l.id}
              onClick={() => selectLesson(i)}
              className={`text-left px-4 py-3 border-b border-slate-800 transition-colors ${
                i === activeLesson
                  ? 'bg-violet-950 border-l-2 border-l-violet-500 text-white'
                  : 'text-slate-400 hover:bg-slate-800 hover:text-white'
              }`}
            >
              <span className="block text-xs text-violet-500 font-bold mb-0.5">Paso {l.id}</span>
              <span className="block text-sm leading-tight">{l.title}</span>
              <span className="block text-[10px] text-slate-500 mt-1">{l.concept}</span>
            </button>
          ))}
        </div>

        {/* Main area */}
        <div className="flex-1 flex flex-col overflow-hidden">

          {/* Explanation */}
          <div className="px-5 py-4 border-b border-slate-700 bg-slate-950/40 overflow-y-auto max-h-48">
            <h3 className="text-white font-semibold mb-2">
              Paso {lesson.id}: {lesson.title}
            </h3>
            <div className="text-slate-300 text-sm leading-relaxed space-y-1 whitespace-pre-wrap">
              {lesson.explanation
                .replace(/\*\*(.*?)\*\*/g, '$1')
                .replace(/`([^`]+)`/g, '$1')}
            </div>
          </div>

          {/* Code editor */}
          <div className="flex-1 flex flex-col overflow-hidden">
            <div className="flex items-center justify-between px-4 py-2 bg-slate-950 border-b border-slate-800">
              <span className="text-xs text-slate-500 font-mono">editor.py</span>
              <div className="flex gap-2">
                <button
                  onClick={() => setShowHint(h => !h)}
                  className="text-xs text-slate-400 hover:text-yellow-400 transition-colors px-2 py-1 rounded"
                >
                  {showHint ? 'Ocultar pista' : '💡 Pista'}
                </button>
                <button
                  onClick={() => { setCode(lesson.starterCode); setOutput('') }}
                  className="text-xs text-slate-400 hover:text-slate-200 transition-colors px-2 py-1 rounded"
                >
                  Resetear
                </button>
                <button
                  onClick={runCode}
                  disabled={running}
                  className="text-xs bg-violet-600 hover:bg-violet-700 disabled:opacity-40 text-white px-3 py-1 rounded font-semibold transition-colors"
                >
                  {running ? 'Ejecutando...' : '▶ Ejecutar (Ctrl+Enter)'}
                </button>
              </div>
            </div>

            {showHint && (
              <div className="px-4 py-2 bg-yellow-950/40 border-b border-yellow-900/50 text-yellow-300 text-xs">
                💡 {lesson.hint}
              </div>
            )}

            <textarea
              ref={textareaRef}
              value={code}
              onChange={e => setCode(e.target.value)}
              onKeyDown={handleKeyDown}
              spellCheck={false}
              className="flex-1 bg-slate-950 text-green-300 font-mono text-sm p-4 resize-none focus:outline-none leading-relaxed"
              style={{ minHeight: '180px' }}
            />
          </div>

          {/* Output */}
          <div className="border-t border-slate-700 bg-black/40" style={{ height: '180px', overflow: 'hidden' }}>
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
                ? <span className="text-violet-400 animate-pulse">Ejecutando código Python...</span>
                : output || <span className="text-slate-600">El output aparecerá aquí...</span>
              }
            </pre>
          </div>

        </div>
      </div>

      {/* Footer nav */}
      <div className="px-6 py-3 border-t border-slate-700 flex justify-between">
        <button
          onClick={() => selectLesson(Math.max(0, activeLesson - 1))}
          disabled={activeLesson === 0}
          className="text-sm text-slate-400 hover:text-white disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
        >
          ← Paso anterior
        </button>
        <span className="text-xs text-slate-600">{activeLesson + 1} / {LESSONS.length}</span>
        <button
          onClick={() => selectLesson(Math.min(LESSONS.length - 1, activeLesson + 1))}
          disabled={activeLesson === LESSONS.length - 1}
          className="text-sm text-slate-400 hover:text-white disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
        >
          Siguiente paso →
        </button>
      </div>
    </div>
  )
}

export default PythonLab

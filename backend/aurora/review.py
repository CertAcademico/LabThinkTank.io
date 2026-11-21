"""Revisión de una entrega: lee lo que el estudiante REALMENTE hizo y lo contrasta con SUS datos.

Tres capas, ninguna da la respuesta:
1. Qué hace tu código (análisis del árbol sintáctico, en lenguaje natural).
2. Qué reportaste (entidades en tu salida y notas) y qué dicen TUS datos de cada una.
3. Observaciones: errores de ejecución, salida vacía, cosas que faltan.
"""
from __future__ import annotations

import ast
import re

IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
DOM = re.compile(r"\b[a-z0-9][a-z0-9-]*\.example\b")
HOST = re.compile(r"\b[A-Z]{2,}(?:-[A-Z0-9]+)+\b")
SES = re.compile(r"\bS-\d{4}\b")
SVC = re.compile(r"\bsvc_[a-z_]+\b")

_AGG = {"sum": "suma", "mean": "promedia", "count": "cuenta", "size": "cuenta filas", "nunique": "cuenta valores distintos",
        "max": "toma el máximo", "min": "toma el mínimo", "median": "calcula la mediana", "value_counts": "cuenta la frecuencia de cada valor"}
_MODELS = {"RandomForestClassifier": "Random Forest", "LogisticRegression": "regresión logística", "IsolationForest": "Isolation Forest",
           "LocalOutlierFactor": "LOF", "KMeans": "KMeans", "DecisionTreeClassifier": "árbol de decisión", "OneClassSVM": "One-Class SVM",
           "TfidfVectorizer": "TF-IDF", "StandardScaler": "estandarización (StandardScaler)", "MLPRegressor": "red neuronal"}
_CLEAN = {"dropna": "elimina nulos", "fillna": "rellena vacíos", "drop_duplicates": "elimina duplicados", "to_datetime": "convierte a fecha",
          "astype": "convierte tipos", "lower": "normaliza a minúsculas", "strip": "recorta espacios"}


def _const(n):
    return n.value if isinstance(n, ast.Constant) else None


def _col_of(n):
    """Nombre de columna si el nodo es df['col'] o df.col."""
    if isinstance(n, ast.Subscript) and isinstance(n.slice, ast.Constant) and isinstance(n.slice.value, str):
        return n.slice.value
    return None


def code_steps(code: str) -> list[str]:
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        return [f"Tu código tiene un error de sintaxis en la línea {e.lineno}: {e.msg}. Mientras no se corrija, no se puede ejecutar."]
    steps: list[str] = []
    seen: set[str] = set()

    def add(s: str):
        if s not in seen:
            seen.add(s); steps.append(s)

    datasets = sorted({n.id for n in ast.walk(tree) if isinstance(n, ast.Name) and n.id.startswith("aurora_")} |
                      {n.id for n in ast.walk(tree) if isinstance(n, ast.Name) and n.id.startswith("up_")})
    if datasets:
        add("Trabajas con " + ", ".join(datasets) + ".")
    prints = 0
    for n in sorted(ast.walk(tree), key=lambda x: (getattr(x, 'lineno', 0), getattr(x, 'col_offset', 0))):
        if isinstance(n, ast.Compare) and len(n.ops) == 1:
            col, val = _col_of(n.left), _const(n.comparators[0])
            op = {ast.Eq: "es igual a", ast.NotEq: "es distinto de", ast.Gt: "es mayor que", ast.Lt: "es menor que", ast.GtE: "es al menos", ast.LtE: "es como máximo", ast.In: "está en"}.get(type(n.ops[0]))
            if col and op and val is not None:
                add(f"Filtras las filas donde «{col}» {op} {val!r}.")
        elif isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute):
            a = n.func.attr
            if a == "startswith" and _col_of(n.func.value.value if isinstance(n.func.value, ast.Attribute) else n.func.value) is not None:
                arg = _const(n.args[0]) if n.args else None
                add(f"Seleccionas o excluyes direcciones que empiezan por {arg!r}.")
            elif a == "isin":
                add("Filtras o cruzas con isin() (los valores de una columna dentro de otra lista).")
            elif a == "groupby":
                cols = [_const(x) for x in n.args if _const(x) is not None] + [e.value for x in n.args if isinstance(x, ast.List) for e in x.elts if isinstance(e, ast.Constant)]
                add("Agrupas por " + (", ".join(f"«{c}»" for c in cols) if cols else "una o más columnas") + ".")
            elif a in _AGG:
                add(f"Después {_AGG[a]} (con {a}()).")
            elif a in ("sort_values", "sort_index", "nlargest", "nsmallest"):
                asc = next((_const(k.value) for k in n.keywords if k.arg == "ascending"), None)
                add("Ordenas los resultados" + (" de mayor a menor." if asc is False else "."))
            elif a in ("merge", "join", "concat"):
                add(f"Cruzas datasets con {a}().")
            elif a in _CLEAN:
                add(f"Limpias datos: {_CLEAN[a]}.")
            elif a in ("plot", "hist", "imshow", "bar", "barh", "scatter", "pie"):
                kind = next((_const(k.value) for k in n.keywords if k.arg == "kind"), a)
                add(f"Dibujas una gráfica ({kind}).")
            elif a in ("findall", "search", "match", "sub"):
                add("Usas expresiones regulares para extraer texto.")
            elif a == "split" and any(isinstance(x, ast.Constant) for x in n.args):
                add("Separas texto con split().")
            elif a == "add_edge":
                add("Construyes un grafo de relaciones (add_edge).")
            elif a in ("fit", "fit_predict", "fit_transform", "predict"):
                add(f"Entrenas o aplicas un modelo ({a}).")
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name):
            if n.func.id in _MODELS:
                add(f"Usas {_MODELS[n.func.id]}.")
            elif n.func.id == "train_test_split":
                add("Separas datos de entrenamiento y de prueba.")
            elif n.func.id in ("classification_report", "accuracy_score", "confusion_matrix"):
                add(f"Evalúas el modelo con {n.func.id}.")
            elif n.func.id == "print":
                prints += 1
    if prints:
        add(f"Imprimes {prints} resultado(s) con print().")
    elif datasets:
        add("No usas print(): nada de lo que calculas llega a la salida ni a tu entrega.")
    return steps[:10]


def _money(b: int) -> str:
    return f"{b / 1e9:.2f} GB" if b >= 1e9 else f"{b / 1e6:.1f} MB" if b >= 1e6 else f"{b / 1e3:.1f} KB" if b >= 1e3 else f"{b} B"


def _ground_ip(ip: str, d: dict) -> list[str]:
    out = []
    nf = d.get("netflow") or []
    rows = [r for r in nf if r["dst_ip"] == ip or r["src_ip"] == ip]
    if rows:
        recv = [r for r in rows if r["dst_ip"] == ip]
        allow = [r for r in recv if r["action"] == "ALLOW"]
        blocked = sum(1 for r in recv if r["action"] == "BLOCK")
        kind = "interna" if ip.startswith("10.20.") else "externa"
        s = f"IP {kind}: aparece en {len(rows)} filas de tu NetFlow"
        if recv:
            s += f"; como destino recibió {len(allow)} conexión(es) permitida(s)" + (f" y {blocked} bloqueada(s)" if blocked else "") + f", con {_money(sum(r['bytes'] for r in allow))} en total"
            if allow:
                s += f" (promedio {_money(sum(r['bytes'] for r in allow) // len(allow))} por conexión)"
        out.append(s + ".")
    elif nf:
        out.append("No aparece en tu NetFlow.")
    for r in (d.get("ioc") or []):
        if str(r["ioc"]).strip().lower() == ip:
            out.append(f"En el feed: severidad {r['severidad']}, confianza {r['confianza']}, campaña «{r.get('campana')}».")
            break
    mal = [r for r in (d.get("malware") or []) if r["c2_ip"] == ip]
    if mal:
        out.append(f"{len(mal)} muestra(s) de malware llaman a esta IP (familia {mal[0]['familia']}).")
    men = sum(1 for r in (d.get("reportes") or []) if ip in r["texto"])
    if men:
        out.append(f"Se menciona en {men} texto(s) de los informes.")
    return out


def _ground_domain(dom: str, d: dict) -> list[str]:
    out = []
    for r in (d.get("ioc") or []):
        if str(r["ioc"]).strip().lower() == dom:
            out.append(f"En el feed: severidad {r['severidad']}, confianza {r['confianza']}, campaña «{r.get('campana')}».")
            break
    mal = [r for r in (d.get("malware") or []) if r["c2_dominio"] == dom]
    if mal:
        out.append(f"{len(mal)} muestra(s) de malware lo usan como servidor de mando (familia {mal[0]['familia']}).")
    dm = next((r for r in (d.get("dominios") or []) if r["dominio"] == dom), None)
    if dm:
        out.append(f"En tu dataset de dominios: {dm['dias_desde_registro']} días desde el registro, etiqueta {dm['etiqueta'] or 'sin etiquetar'}.")
    men = sum(1 for r in (d.get("reportes") or []) if dom in r["texto"])
    if men:
        out.append(f"Se menciona en {men} texto(s) de los informes.")
    return out


def _ground_host(h: str, d: dict) -> list[str]:
    out = []
    ev = [r for r in (d.get("siem") or []) if r["host"] == h]
    if ev:
        grave = [r for r in ev if r["severidad"] in ("high", "critical")]
        out.append(f"En el SIEM: {len(ev)} evento(s), {len(grave)} de severidad alta o crítica" + (f" (fases: {', '.join(sorted({r['fase'] for r in grave}))})." if grave else "."))
    nf = sum(1 for r in (d.get("netflow") or []) if r["host"] == h)
    if nf:
        out.append(f"En el NetFlow figura como origen en {nf} fila(s).")
    return out


def _ground_session(s: str, d: dict) -> list[str]:
    r = next((x for x in (d.get("telemetria") or []) if x["sesion"] == s), None)
    if not r:
        return []
    return [f"Sesión de «{r['cuenta']}» con {r['peticiones_por_min']} peticiones/min, {r['comandos_distintos']} comandos distintos, "
            f"{r['errores_pct']}% de errores, reintento en {r['reintento_tras_error_s']} s, hora {r['hora']}:00 y herramienta {r['herramienta']}."]


def reported(text: str, d: dict) -> list[dict]:
    out, seen = [], set()
    def push(kind, ent, facts):
        if ent not in seen and len(out) < 12:
            seen.add(ent); out.append({"entity": ent, "kind": kind, "facts": facts})
    for ip in IP.findall(text):
        if all(0 <= int(p) <= 255 for p in ip.split(".")):
            push("IP", ip, _ground_ip(ip, d))
    for dom in DOM.findall(text.lower()):
        push("dominio", dom, _ground_domain(dom, d))
    for h in HOST.findall(text):
        if not SES.fullmatch(h):
            push("host", h, _ground_host(h, d))
    for s in SES.findall(text)[:6]:
        push("sesión", s, _ground_session(s, d))
    return out


def observations(code: str, output: str, notes: str, chapter: int) -> list[str]:
    obs = []
    first_err = next((l for l in output.splitlines() if re.match(r"^\w*(Error|Exception)\b|^Error:", l.strip())), None)
    if output.startswith("Error:") or "Traceback" in output:
        last = [l for l in output.strip().splitlines() if l.strip()][-1]
        obs.append(f"Tu código terminó con un error de ejecución: «{last[:160]}». Lo que calculaste antes del error no se entregó completo.")
    elif first_err:
        obs.append(f"Tu salida contiene un error: «{first_err[:160]}».")
    elif not output.strip() and chapter != 8:
        obs.append("Tu entrega no tiene salida: ejecuta el código antes de entregar para que se vea lo que calculaste.")
    if code.strip() and not code.count("\n") and chapter != 8:
        obs.append("Tu código tiene una sola línea. Los capítulos piden varios pasos: revisa la misión.")
    if chapter in (2, 5, 6, 7, 8) and len(notes.strip()) < 60:
        obs.append("Tus notas están vacías o muy cortas. En este capítulo parte de la evaluación es que expliques tu razonamiento.")
    return obs


def nudges(chapter: int, facts: dict, text: str) -> list[str]:
    """Orientaciones según lo que FALTÓ en la entrega. Describen el patrón a buscar, nunca el valor."""
    low = text.lower()
    has = lambda v: str(v).lower() in low
    n = []
    if chapter == 1:
        if not has(facts["c2_ip"]):
            n.append("No reportaste el destino del beacon. Busca, entre las IPs externas permitidas, la que se repite muchas veces con pocos bytes cada vez: ese ritmo regular es la señal.")
        if not has(facts["exfil_ip"]):
            n.append("No reportaste el destino de la exfiltración. Es otro destino externo: pocas conexiones, pero con muchísimos más bytes que cualquier otro.")
    elif chapter == 2:
        if not all(has(x) for x in (facts["phish"], facts["c2_domain"])):
            n.append("Faltan indicadores de tu campaña. Busca en el feed el valor de la columna campana que tiene tu IP del C2 y revisa todos los indicadores que la comparten.")
        if has(facts["exfil_ip"]) and not re.search(r"reclasific|subir|subí|elev|cr[ií]tic|contradic|baja confianza|enga[ñn]", low):
            n.append("Mencionas la IP de exfiltración pero no explicas qué hacer con su clasificación en el feed. Compara lo que el feed dice con lo que viste mover en tu red.")
    elif chapter == 3:
        if not has(facts["family"]):
            n.append("No identificaste la familia. Filtra las muestras cuyo servidor de mando coincide con el que viste en la red; las demás son de otros casos.")
        if has(facts["family"]) and not (has(facts["persistence"]) and has(facts["evasion"])):
            n.append("Identificaste la familia pero faltan su persistencia o su evasión: están en las columnas persistencia y evasion de tus muestras.")
    elif chapter == 4:
        if not has(facts["pz"]):
            n.append("No nombraste el Paciente Cero. Filtra solo las alertas de severidad alta o crítica y mira el host del primer evento.")
        if not has(facts["svc"]):
            n.append("No identificaste la cuenta abusada. Mira la columna usuario en los eventos de movimiento lateral.")
        if not has(facts["mid"]):
            n.append("La ruta lateral está incompleta: lista los hosts de los eventos del incidente en el orden en que ocurrieron.")
    elif chapter == 5:
        if not (has(facts["phish"]) and has(facts["alias"])):
            n.append("No aparecen los dos dominios del alias. Busca los textos donde se mencionan dos dominios juntos o donde un proveedor dice «antes era».")
        if not has(facts["exfil_ip"]):
            n.append("No retomaste la IP que el chat del SOC pone en duda. Los informes completan lo que el feed minimiza.")
    elif chapter == 6:
        hit = sum(1 for d in facts["siblings"] if d in low)
        if hit < len(facts["siblings"]) - 2:
            n.append("Tu lista de dominios a bloquear es corta o imprecisa. Aplica el modelo solo a los candidatos sin etiqueta y entrega los que predice como maliciosos; comparten IP de alojamiento y se registraron hace pocos días.")
        if any(d in low for d in facts["legit_candidates"]):
            n.append("Tu lista incluye dominios que parecen legítimos (antiguos y con otra IP). Revisa qué features hacen que el modelo los marque.")
    elif chapter == 7:
        ids = set(SES.findall(text))
        hit = len(ids & set(facts["agent_sessions"]))
        if hit < 6:
            n.append("Encontraste pocas sesiones de agente. Las que buscas actúan muy rápido, prueban muchas cosas distintas, reintentan en segundos y a veces trabajan de madrugada.")
        if len(ids) > 25:
            n.append("Tu lista es larga (" + str(len(ids)) + " sesiones). Una lista corta y justificada es más útil: ¿qué separa a un agente de IA del resto?")
        if ids & set(facts["legit_bots"]) and not re.search(r"svc_|leg[ií]tim|monitor|respaldo|automatizaci", low):
            n.append("Marcaste sesiones de cuentas svc_ sin explicar qué son. Algunas son automatización legítima del banco: rápida y regular, pero siempre repite lo mismo.")
    return n


def review(chapter: int, code: str, output: str, notes: str, datasets: dict, facts: dict | None = None) -> dict:
    text = output + "\n" + notes
    return {"steps": code_steps(code), "reported": reported(text, datasets),
            "observations": observations(code, output, notes, chapter), "nudges": nudges(chapter, facts, text) if facts else []}

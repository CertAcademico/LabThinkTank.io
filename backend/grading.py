"""Autocalificación de retos del Lab.

Cada reto define una rúbrica de verificaciones. Los valores esperados se calculan
a partir del dataset del reto (no están escritos a mano), y la retroalimentación
nunca revela el valor esperado: solo qué criterio se cumplió y qué falta.
La nota automática es provisional; el docente puede sobrescribirla.
"""
from __future__ import annotations

import json
import re
from typing import Callable

Rows = list[dict]


class Sub:
    """Entrega normalizada: texto visible (output+notas) y código por separado."""
    def __init__(self, code: str, output: str, notes: str, plots: list):
        self.code = code or ""
        self.output = output or ""
        self.notes = notes or ""
        self.plots = plots or []
        self.text = f"{self.output}\n{self.notes}"
        self.low = self.text.lower()
        self.code_low = self.code.lower()


# Cada verificación devuelve (fracción 0..1, pista para el estudiante si falla)
Check = tuple[str, int, Callable[[Sub, Rows], float], str]


def _num_variants(n: float) -> list[str]:
    """Formas en que un estudiante puede imprimir un número (2429440, 2,429,440, 2429440.0)."""
    out = {str(int(n)) if float(n).is_integer() else str(n)}
    if float(n).is_integer():
        out |= {f"{int(n):,}", f"{int(n):,}".replace(",", "."), f"{int(n):,}".replace(",", " "), f"{int(n)}.0"}
    return list(out)


def has_num(*values: float) -> Callable[[Sub, Rows], float]:
    def f(s: Sub, _r: Rows) -> float:
        txt = s.text
        return 1.0 if any(re.search(rf"(?<![\d.,]){re.escape(v)}(?![\d])", txt) for n in values for v in _num_variants(n)) else 0.0
    return f


def has_terms(terms_fn: Callable[[Rows], list[str]], minimum: int | None = None, where: str = "text") -> Callable[[Sub, Rows], float]:
    def f(s: Sub, r: Rows) -> float:
        terms = [t.lower() for t in terms_fn(r)]
        hay = {"text": s.low, "code": s.code_low, "all": s.low + "\n" + s.code_low}[where]
        found = sum(1 for t in terms if t in hay)
        need = minimum or len(terms)
        return min(1.0, found / need) if need else 0.0
    return f


def code_matches(*patterns: str) -> Callable[[Sub, Rows], float]:
    def f(s: Sub, _r: Rows) -> float:
        return 1.0 if any(re.search(p, s.code, re.I) for p in patterns) else 0.0
    return f


def text_matches(*patterns: str, where: str = "text") -> Callable[[Sub, Rows], float]:
    def f(s: Sub, _r: Rows) -> float:
        hay = {"text": s.text, "all": s.text + "\n" + s.code}[where]
        return 1.0 if any(re.search(p, hay, re.I) for p in patterns) else 0.0
    return f


def plots_at_least(n: int, also_code: tuple[str, ...] = ()) -> Callable[[Sub, Rows], float]:
    def f(s: Sub, _r: Rows) -> float:
        have = len(s.plots)
        if also_code and not any(re.search(p, s.code, re.I) for p in also_code):
            return 0.0
        return min(1.0, have / n)
    return f


def metric_min(name_regex: str, minimum: float) -> Callable[[Sub, Rows], float]:
    def f(s: Sub, _r: Rows) -> float:
        vals = []
        for m in re.finditer(rf"{name_regex}\D{{0,20}}?(\d+(?:[.,]\d+)?)", s.output, re.I):
            v = float(m.group(1).replace(",", "."))
            vals.append(v / 100 if v > 1 else v)
        return 1.0 if any(v >= minimum for v in vals) else 0.0
    return f


def notes_min(chars: int) -> Callable[[Sub, Rows], float]:
    return lambda s, _r: min(1.0, len(s.notes.strip()) / chars)


def _col(rows: Rows, key: str) -> list[str]:
    return [str(r[key]) for r in rows if r.get(key) not in (None, "")]


# ── Rúbricas por reto (clave = prefijo del título) ────────────────────────────

def _apt28(rows: Rows):
    apt = [r for r in rows if r.get("threat_actor") == "APT28"]
    ext = sorted({ip for r in apt for ip in (r["src_ip"], r["dst_ip"]) if not ip.startswith(("10.", "192.168."))})
    exfil = sum(r["bytes"] for r in apt if r.get("mitre") == "T1041")
    return len(apt), ext, exfil


def _lockbit(rows: Rows):
    rows = sorted(rows, key=lambda r: r["timestamp"])
    from datetime import datetime
    t0 = datetime.fromisoformat(rows[0]["timestamp"])
    enc = next((r for r in rows if "cifrado de archivos" in r["technique"].lower() or r["mitre"] == "T1486"), rows[-1])
    mins = int((datetime.fromisoformat(enc["timestamp"]) - t0).total_seconds() // 60)
    last = int((datetime.fromisoformat(rows[-1]["timestamp"]) - t0).total_seconds() // 60)
    return rows[0]["host"], sorted({r["phase"] for r in rows}), mins, last


def rubric_for(title: str) -> list[Check] | None:
    t = title.lower()
    if t.startswith("caza de iocs"):
        return [
            ("Filtraste los eventos de APT28 y los contaste", 15,
             lambda s, r: has_num(_apt28(r)[0])(s, r), "Filtra threat_actor == 'APT28' e imprime cuántos eventos hay."),
            ("Identificaste las IPs externas de C2/exfiltración", 25,
             has_terms(lambda r: _apt28(r)[1]), "Lista las IPs únicas externas (no privadas) asociadas a APT28."),
            ("Calculaste los bytes totales exfiltrados", 25,
             lambda s, r: has_num(_apt28(r)[2])(s, r), "Suma los bytes de los eventos de exfiltración (T1041) e imprime el total."),
            ("Graficaste las técnicas MITRE por frecuencia", 20,
             plots_at_least(1, also_code=(r"mitre",)), "Genera una gráfica de barras con la frecuencia de cada técnica MITRE."),
            ("Construiste el timeline ordenado por tiempo", 15,
             code_matches(r"sort_values|sorted\(|to_datetime|sort\("), "Ordena por timestamp (pd.to_datetime + sort_values) para armar el timeline."),
        ]
    if t.startswith("análisis de campaña ransomware"):
        return [
            ("Identificaste el host de entrada (Patient Zero)", 25,
             lambda s, r: has_terms(lambda rr: [_lockbit(rr)[0]])(s, r), "Mira el primer evento cronológico: ¿qué host fue el punto de entrada?"),
            ("Calculaste el tiempo hasta el cifrado", 20,
             lambda s, r: max(has_num(_lockbit(r)[2], _lockbit(r)[3], round(_lockbit(r)[2] / 60, 2), round(_lockbit(r)[3] / 60, 2))(s, r),
                              text_matches(r"\b0?2[:h ]\s?33\b", r"\b0?2[:h ]\s?48\b")(s, r)),
             "Resta el timestamp del primer evento al del cifrado y exprésalo en minutos u horas."),
            ("Mapeaste el camino de movimiento lateral", 20,
             has_terms(lambda r: ["WEB-SRV-01", "DC-01", "FILE-SRV-02"]), "Menciona los hosts por los que se movió el atacante, en orden."),
            ("Agrupaste los eventos por fase del ataque", 15,
             has_terms(lambda r: _lockbit(r)[1], minimum=6), "Agrupa por la columna 'phase' e imprime el resultado."),
            ("Diagramaste la kill chain", 10,
             lambda s, r: max(plots_at_least(1)(s, r), code_matches(r"kill.?chain|networkx|graphviz")(s, r)), "Crea un diagrama (gráfica o grafo) con las fases en orden."),
            ("Propusiste mitigaciones en tus notas", 10,
             lambda s, r: min(notes_min(150)(s, r), text_matches(r"mitig|recomend|contenci|segment|parche|backup", where="text")(s, r)), "En las notas, escribe al menos 3 recomendaciones de mitigación."),
        ]
    if t.startswith("detección de phishing"):
        return [
            ("Entrenaste un clasificador", 20,
             code_matches(r"RandomForest|LogisticRegression|DecisionTree|GradientBoosting"), "Usa Random Forest o Logistic Regression de scikit-learn."),
            ("Creaste features del dominio (longitud, guiones, TLD)", 20,
             lambda s, r: sum([code_matches(r"len\(|\.str\.len")(s, r), code_matches(r"count\(['\"]-|\.str\.count")(s, r),
                               code_matches(r"tld|split\(['\"]\.")(s, r)]) / 3, "Crea al menos: longitud del dominio, número de guiones y TLD."),
            ("Reportaste accuracy, precision, recall y F1", 15,
             lambda s, r: sum(1 for k in ("accuracy", "precision", "recall", "f1") if k in s.low) / 4, "Imprime las cuatro métricas (classification_report sirve)."),
            ("Alcanzaste accuracy ≥ 75%", 15,
             metric_min(r"accuracy", 0.75), "Tu accuracy impreso debe ser ≥ 0.75; revisa features y el split."),
            ("Identificaste los features más importantes", 15,
             lambda s, r: max(text_matches(r"importance|coef")(s, r), code_matches(r"feature_importances_|coef_")(s, r)), "Imprime feature_importances_ y quédate con el top 3."),
            ("Visualizaste la matriz de confusión", 15,
             lambda s, r: max(plots_at_least(1)(s, r) if re.search(r"confusion", s.code, re.I) else 0.0, text_matches(r"confusion")(s, r)),
             "Genera la matriz de confusión (confusion_matrix + heatmap)."),
        ]
    if t.startswith("enriquecimiento y priorización"):
        return [
            ("Limpiaste los datos (nulos / normalización)", 15,
             code_matches(r"dropna|fillna|isna|isnull|\.strip\(|\.lower\(|drop_duplicates|astype"), "Maneja nulos y normaliza tipos de IOC."),
            ("Creaste el score de riesgo con severity y confidence", 20,
             lambda s, r: 1.0 if (re.search(r"severity", s.code, re.I) and re.search(r"confidence", s.code, re.I) and re.search(r"risk|score|riesgo", s.code, re.I)) else 0.0,
             "Combina severity y confidence en una columna de riesgo."),
            ("Clasificaste en Crítico/Alto/Medio/Bajo", 20,
             lambda s, r: min(1.0, sum(1 for k in (("crítico", "critical", "critico"), ("alto", "high"), ("medio", "medium"), ("bajo", "low")) if any(x in s.low for x in k)) / 4),
             "Imprime cuántos IOCs caen en cada nivel."),
            ("Agrupaste por threat_actor", 15,
             has_terms(lambda r: sorted(set(_col(r, "threat_actor")))[:6], minimum=4), "Muestra la distribución por threat_actor."),
            ("Generaste las 3 gráficas pedidas", 20,
             plots_at_least(3), "Top 5 actores, distribución por país e IOCs por tipo (3 gráficas)."),
            ("Escribiste un reporte ejecutivo en las notas", 10,
             notes_min(200), "Resume hallazgos y prioridades en al menos ~200 caracteres."),
        ]
    if t.startswith("perfilado de malware"):
        return [
            ("Agrupaste las muestras por familia", 20,
             has_terms(lambda r: sorted(set(_col(r, "family")))), "Muestra todas las familias con su conteo."),
            ("Extrajiste las IPs C2 y dominios únicos", 20,
             has_terms(lambda r: sorted(set(_col(r, "c2_ip"))), minimum=3), "Lista las IPs C2 y los dominios únicos."),
            ("Mapeaste técnicas MITRE por familia", 15,
             lambda s, r: min(1.0, len(set(re.findall(r"T\d{4}(?:\.\d{3})?", s.text))) / 4), "Imprime los códigos T#### de cada familia."),
            ("Hiciste el heatmap de capabilities vs familias", 20,
             lambda s, r: plots_at_least(1, also_code=(r"heatmap|imshow|pivot|crosstab",))(s, r), "Crea una tabla cruzada (crosstab/pivot) y dibújala como heatmap."),
            ("Analizaste persistencia y evasión", 10,
             lambda s, r: min(1.0, (("persisten" in s.low) + ("evasi" in s.low) + ("evasion" in s.low)) / 2), "Resume patrones comunes de persistencia y de evasión."),
            ("Calculaste el tamaño promedio por tipo de archivo", 15,
             lambda s, r: _mean_sizes(s, r), "Agrupa por 'type' y calcula la media de size_kb."),
        ]
    if t.startswith("extracción de entidades cti"):
        return [
            ("Análisis exploratorio de labels y textos", 25,
             lambda s, r: min(1.0, sum([("label" in s.low), bool(re.search(r"describe|value_counts|len\(", s.code, re.I))]) / 2), "Muestra la distribución de labels y la longitud de los textos."),
            ("Mapeaste attack patterns a MITRE o armaste el grafo", 25,
             lambda s, r: max(code_matches(r"networkx|nx\.|graph")(s, r), min(1.0, len(set(re.findall(r"T\d{4}", s.text))) / 3)), "Relaciona attack_pattern con T-codes o construye el grafo de relations."),
            ("Modelo o clustering explicado", 25,
             code_matches(r"TfidfVectorizer|LogisticRegression|KMeans|community|DBSCAN"), "Entrena TF-IDF + LogisticRegression, o aplica clustering de comunidades."),
            ("Reporte con hallazgos accionables", 25,
             notes_min(300), "Resume hallazgos CTI accionables (al menos ~300 caracteres)."),
        ]
    return None


def _mean_sizes(s: Sub, rows: Rows) -> float:
    by: dict[str, list[float]] = {}
    for r in rows:
        by.setdefault(str(r.get("type")), []).append(float(r.get("size_kb") or 0))
    vals = [sum(v) / len(v) for v in by.values()]
    hit = 0
    for m in vals:
        forms = {f"{m:.1f}", f"{m:.2f}", str(int(round(m))), f"{m:.0f}", str(m)}
        if any(re.search(rf"(?<![\d.]){re.escape(f)}(?!\d)", s.text) for f in forms):
            hit += 1
    return min(1.0, hit / max(1, len(vals) // 2 + 1))


def grade(title: str, dataset_rows: Rows, code: str, output: str, notes: str, plots: list) -> dict | None:
    """Devuelve {score, items:[{label, weight, earned, ok, hint}]} o None si el reto no tiene rúbrica."""
    rubric = rubric_for(title)
    if not rubric:
        return None
    sub = Sub(code, output, notes, plots)
    items, total, earned = [], 0, 0.0
    for label, weight, fn, hint in rubric:
        try:
            frac = max(0.0, min(1.0, float(fn(sub, dataset_rows))))
        except Exception:
            frac = 0.0
        total += weight
        earned += weight * frac
        items.append({"label": label, "weight": weight, "earned": round(weight * frac), "ok": frac >= 0.999,
                      "partial": 0 < frac < 0.999, "hint": "" if frac >= 0.999 else hint})
    return {"score": round(100 * earned / total) if total else 0, "items": items}


def rows_of(data_json: str) -> Rows:
    try:
        d = json.loads(data_json or "[]")
        return d if isinstance(d, list) else []
    except Exception:
        return []

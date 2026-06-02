from __future__ import annotations

"""
RedCiber Think Tank — Motor de Fusión de Amenazas
Python port of geminiService.ts (Google Gemini 3-Flash / 2.5-Flash)

All 16 analysis functions are implemented here and exposed via FastAPI
endpoints in main.py (/ai/gemini/*).  The GEMINI_API_KEY env var must
be set; if it's missing every call raises GeminiNotConfiguredError so
the caller can fall back gracefully.

Model mapping (same as the original TypeScript):
  - "gemini-3-flash-preview"  → general analysis, fast
  - "gemini-2.5-flash"        → quantum analysis (more reasoning)
"""

import json
import os
import re
import time
from typing import Any

_GEMINI_MODEL_FAST   = os.getenv("GEMINI_MODEL_FAST",   "gemini-2.0-flash")
_GEMINI_MODEL_SMART  = os.getenv("GEMINI_MODEL_SMART",  "gemini-2.5-flash")


class GeminiNotConfiguredError(RuntimeError):
    pass


def _get_client():
    """Return a configured Gemini client or raise if key is missing."""
    try:
        from google import genai  # type: ignore
    except ImportError as e:
        raise GeminiNotConfiguredError(
            "google-genai package not installed. Run: pip install google-genai"
        ) from e
    api_key = os.getenv("GEMINI_API_KEY", "")
    if not api_key:
        raise GeminiNotConfiguredError(
            "GEMINI_API_KEY environment variable is not set."
        )
    return genai.Client(api_key=api_key)


def _with_retry(fn, max_retries: int = 3, initial_delay: float = 2.0):
    delay = initial_delay
    for attempt in range(max_retries):
        try:
            return fn()
        except Exception as exc:
            if attempt == max_retries - 1:
                raise
            time.sleep(delay)
            delay *= 2


def _extract_json(text: str) -> str:
    """Strip markdown code fences if model wrapped the JSON."""
    text = text.strip()
    if "```json" in text:
        text = text.split("```json")[1].split("```")[0].strip()
    elif "```" in text:
        text = text.split("```")[1].split("```")[0].strip()
    return text


def _generate(client, model: str, contents: str, config_kwargs: dict) -> Any:
    """Thin wrapper that calls client.models.generate_content."""
    from google.genai import types  # type: ignore

    cfg = types.GenerateContentConfig(**config_kwargs)
    return client.models.generate_content(
        model=model,
        contents=contents,
        config=cfg,
    )


# ── Shared schema fragments ────────────────────────────────────────────────────

_SCHEMA_STRING  = {"type": "STRING"}
_SCHEMA_NUMBER  = {"type": "NUMBER"}
_SCHEMA_BOOL    = {"type": "BOOLEAN"}
_SCHEMA_STR_ARR = {"type": "ARRAY", "items": {"type": "STRING"}}


def _obj(properties: dict, required: list | None = None) -> dict:
    s: dict = {"type": "OBJECT", "properties": properties}
    if required:
        s["required"] = required
    return s


def _arr(items: dict) -> dict:
    return {"type": "ARRAY", "items": items}


# ── 1. generate_threat_data ────────────────────────────────────────────────────

def generate_threat_data(topic: str, is_annual: bool = False) -> dict:
    """
    Generate 60 (operational) or 500 (annual) threat events as structured data.
    Returns: { threats: [...], sector_analysis: str|None }
    """
    from datetime import date
    current_date = date.today().isoformat()
    target_count = "EXACTAMENTE 500" if is_annual else "60"
    time_range = (
        "DESDE ENERO DE 2020 HASTA MARZO DE 2026"
        if is_annual
        else "Últimos 7 días"
    )

    prompt = f"""
ACTÚA COMO: Sistema de Fusión de Inteligencia RedCiber (Think Tank Estratégico).
OBJETIVO: Generar un dataset masivo de {target_count} eventos de ciberseguridad.
CONTEXTO: {topic}. RANGO TEMPORAL: {time_range}.
FECHA ACTUAL: {current_date}.

SI EL CONTEXTO INCLUYE MÚLTIPLES ACTORES (ej: separados por comas):
1. Genera eventos donde estos actores compitan, colaboren o ataquen objetivos similares.
2. Asegura que las TTPs sean distintivas para cada actor según la inteligencia conocida.
3. Crea al menos 3 incidentes de "Fusión Física/Lógica" donde las actividades se crucen.

ESTRUCTURA DE RESPUESTA (ESTRICTA):
ÚNICAMENTE texto plano CSV delimitado por pipes (|). No incluyas explicaciones.
Cabecera: id|timestamp|threatType|severity|sourceCountry|targetCountry|description|ioc|informationSource|malware|threatActor|threatName|victim|mitreTactic|mitreTechniqueId|mitreTechniqueName|dataCollectionMethod|sourceIp|targetIp|protocol|sourcePort|targetPort|payloadSize|confidenceScore|infrastructureType|sessionDuration|isFalsePositive

INSTRUCCIONES CLAVE:
1. Timestamps realistas distribuidos según el rango.
2. Distribución que permita ver tendencias y picos estacionales.
3. Al final, añade "---PREDICTIVE_INSIGHTS---" con un JSON:
   {{"regressionTrend":"Linear/Exponential","acceleration":number,"topPostulatedSector":string,"confidenceScore":number,"multiActorCorrelation":string}}
"""

    client = _get_client()

    def _call():
        from google.genai import types  # type: ignore
        return client.models.generate_content(
            model=_GEMINI_MODEL_FAST,
            contents=prompt,
            config=types.GenerateContentConfig(
                response_mime_type="text/plain",
                temperature=0.2,
            ),
        )

    response = _with_retry(_call)
    text = (response.text or "").strip()
    if not text:
        raise ValueError("Respuesta vacía del motor Gemini.")

    csv_data = text
    predictive_insights = None

    if "---PREDICTIVE_INSIGHTS---" in text:
        parts = text.split("---PREDICTIVE_INSIGHTS---")
        csv_data = parts[0].strip()
        try:
            predictive_insights = json.loads(parts[1].strip())
        except Exception:
            pass

    lines = [l for l in csv_data.splitlines() if "|" in l]
    if len(lines) < 2:
        raise ValueError("Dataset malformado o insuficiente.")

    headers = [h.strip() for h in lines[0].split("|")]
    threats = []
    for idx, line in enumerate(lines[1:]):
        values = [v.strip() for v in line.split("|")]
        row: dict[str, Any] = {headers[i]: values[i] if i < len(values) else "" for i in range(len(headers))}
        row["id"] = row.get("id") or str(idx + 1)
        row["isFalsePositive"] = row.get("isFalsePositive", "false").lower() == "true"
        for int_field in ("sourcePort", "targetPort", "payloadSize", "sessionDuration"):
            try:
                row[int_field] = int(row.get(int_field, 0) or 0)
            except (ValueError, TypeError):
                row[int_field] = 0
        for float_field in ("confidenceScore",):
            try:
                row[float_field] = float(row.get(float_field, 0) or 0)
            except (ValueError, TypeError):
                row[float_field] = 0.0
        threats.append(row)

    return {
        "threats": threats,
        "sector_analysis": json.dumps(predictive_insights) if predictive_insights else None,
    }


# ── 2. generate_quantum_threat_analysis ───────────────────────────────────────

def generate_quantum_threat_analysis(actor: str, events: list[dict]) -> dict:
    schema = _obj({
        "hndlRisk": _obj({
            "score": _SCHEMA_NUMBER,
            "justification": _SCHEMA_STRING,
            "indicators": _SCHEMA_STR_ARR,
        }, ["score", "justification", "indicators"]),
        "pqcVulnerability": _obj({
            "sectorStatus": _SCHEMA_STRING,
            "exposedAlgorithms": _SCHEMA_STR_ARR,
            "migrationPriority": {"type": "STRING", "enum": ["Low", "Medium", "High", "Critical"]},
        }, ["sectorStatus", "exposedAlgorithms", "migrationPriority"]),
        "quantumTTPs": _arr(_obj({
            "technique": _SCHEMA_STRING,
            "description": _SCHEMA_STRING,
            "mitigation": _SCHEMA_STRING,
        }, ["technique", "description", "mitigation"])),
        "cryptoAgilityIndex": _SCHEMA_NUMBER,
    }, ["hndlRisk", "pqcVulnerability", "quantumTTPs", "cryptoAgilityIndex"])

    client = _get_client()

    def _call():
        from google.genai import types  # type: ignore
        return client.models.generate_content(
            model=_GEMINI_MODEL_SMART,
            contents=f"Analiza el riesgo cuántico y Post-Quantum Cryptography (PQC) para el actor {actor}. Eventos de referencia: {json.dumps(events[:10])}. Responde en español.",
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                response_schema=schema,
                temperature=0.3,
            ),
        )

    response = _with_retry(_call)
    return json.loads(_extract_json(response.text))


# ── 3. generate_predictive_analysis ───────────────────────────────────────────

def generate_predictive_analysis(threats: list[dict], query: str) -> dict:
    schema = _obj({
        "potentialImpact": _obj({
            "severity": {"type": "STRING", "enum": ["Medium", "High", "Critical"]},
            "probability": _SCHEMA_NUMBER,
            "reasoning": _SCHEMA_STRING,
        }, ["severity", "probability", "reasoning"]),
        "predictedNextTactic": _obj({
            "tactic": _SCHEMA_STRING,
            "reasoning": _SCHEMA_STRING,
        }, ["tactic", "reasoning"]),
        "recalculatedAttribution": _obj({
            "actor": _SCHEMA_STRING,
            "confidence": _SCHEMA_NUMBER,
            "reasoning": _SCHEMA_STRING,
        }, ["actor", "confidence", "reasoning"]),
        "multiActorCorrelation": _SCHEMA_STRING,
        "historicalValidation": _arr(_obj({
            "actor": _SCHEMA_STRING,
            "consistencyScore": _SCHEMA_NUMBER,
            "anomalousActions": _SCHEMA_STR_ARR,
            "confirmedPatterns": _SCHEMA_STR_ARR,
        }, ["actor", "consistencyScore", "anomalousActions", "confirmedPatterns"])),
        "crossActorNexus": _arr(_obj({
            "actors": _SCHEMA_STR_ARR,
            "sharedTtp": _SCHEMA_STRING,
            "sharedInfrastructure": _SCHEMA_STRING,
            "targetOverlapScore": _SCHEMA_NUMBER,
        }, ["actors", "sharedTtp", "targetOverlapScore"])),
    }, ["potentialImpact", "predictedNextTactic", "recalculatedAttribution"])

    prompt = f"""ACTÚA COMO: Analista de Fusión de Inteligencia RedCiber.

TAREA: Realiza un ANÁLISIS PREDICTIVO Y DE VALIDACIÓN sobre estos eventos: {json.dumps(threats[:20])}.
CONVOCATORIA: "{query}".

REQUERIMIENTOS:
1. CO-RELACIÓN: Si hay múltiples actores, identifica si colaboran, compiten o fusionan infraestructuras.
2. VALIDACIÓN HISTÓRICA: Evalúa si las acciones son consistentes con el perfil histórico. Identifica "Acciones Anómalas".
3. NEXO CRUZADO: Define puntos exactos donde las tácticas se cruzan.

Responde estrictamente en formato JSON en español."""

    client = _get_client()

    def _call():
        from google.genai import types  # type: ignore
        return client.models.generate_content(
            model=_GEMINI_MODEL_FAST,
            contents=prompt,
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                response_schema=schema,
                temperature=0.2,
            ),
        )

    response = _with_retry(_call)
    return json.loads(_extract_json(response.text))


# ── 4. generate_fusion_report ─────────────────────────────────────────────────

def generate_fusion_report(query: str, threats: list[dict]) -> dict:
    schema = _obj({
        "title": _SCHEMA_STRING,
        "executiveSummary": _SCHEMA_STRING,
        "keyMetrics": _obj({
            "analysisPeriod": _SCHEMA_STRING,
            "totalEvents": _SCHEMA_NUMBER,
            "topActors": _SCHEMA_STRING,
            "topTactics": _SCHEMA_STRING,
        }, ["analysisPeriod", "totalEvents", "topActors", "topTactics"]),
        "fusionLogic": _SCHEMA_STRING,
        "priorityThreats": _arr(_obj({
            "title": _SCHEMA_STRING,
            "description": _SCHEMA_STRING,
        }, ["title", "description"])),
        "relevantIocs": _arr(_obj({
            "ioc": _SCHEMA_STRING,
            "description": _SCHEMA_STRING,
        }, ["ioc", "description"])),
        "recommendations": _SCHEMA_STR_ARR,
        "recentSources": _arr(_obj({"title": _SCHEMA_STRING, "uri": _SCHEMA_STRING}, ["title", "uri"])),
    }, ["title", "executiveSummary", "keyMetrics", "fusionLogic", "priorityThreats", "relevantIocs", "recommendations"])

    prompt = f"""Genera un informe detallado de inteligencia de amenazas sobre "{query}" basado en {len(threats)} eventos detectados.
Utiliza la herramienta de búsqueda para complementar con información externa reciente.
Responde estrictamente en formato JSON en español.
Eventos de referencia: {json.dumps(threats[:15])}"""

    client = _get_client()

    def _call():
        from google.genai import types  # type: ignore
        return client.models.generate_content(
            model=_GEMINI_MODEL_FAST,
            contents=prompt,
            config=types.GenerateContentConfig(
                tools=[types.Tool(google_search=types.GoogleSearch())],
                temperature=0.4,
            ),
        )

    response = _with_retry(_call)
    raw = _extract_json(response.text)
    # When using googleSearch, response may not be strict JSON — parse best effort
    try:
        report = json.loads(raw)
    except json.JSONDecodeError:
        # Fallback: extract first JSON object
        m = re.search(r'\{.*\}', raw, re.DOTALL)
        report = json.loads(m.group()) if m else {"title": query, "executiveSummary": raw, "keyMetrics": {}, "fusionLogic": "", "priorityThreats": [], "relevantIocs": [], "recommendations": []}

    # Enrich sources from grounding metadata
    try:
        chunks = response.candidates[0].grounding_metadata.grounding_chunks
        if chunks:
            sources = [
                {"title": c.web.title, "uri": c.web.uri}
                for c in chunks if getattr(c, "web", None) and c.web.title and c.web.uri
            ]
            seen: set = set()
            unique: list = []
            for s in sources:
                if s["uri"] not in seen:
                    seen.add(s["uri"]); unique.append(s)
            report.setdefault("recentSources", unique)
    except Exception:
        pass

    return report


# ── 5. generate_mitre_details ─────────────────────────────────────────────────

def generate_mitre_details(actor: str, technique_ids: list[str]) -> list[dict]:
    schema = _arr(_obj({
        "tactic": _SCHEMA_STRING,
        "techniques": _arr(_obj({
            "id": _SCHEMA_STRING,
            "name": _SCHEMA_STRING,
            "description": _SCHEMA_STRING,
        }, ["id", "name", "description"])),
    }, ["tactic", "techniques"]))

    client = _get_client()

    def _call():
        from google.genai import types  # type: ignore
        return client.models.generate_content(
            model=_GEMINI_MODEL_FAST,
            contents=f"Para el actor {actor}, proporciona detalles de las técnicas MITRE ATT&CK: {', '.join(technique_ids)}. Agrupa por táctica y describe CÓMO este actor usa cada técnica. Responde en JSON en español.",
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                response_schema=schema,
                temperature=0.2,
            ),
        )

    response = _with_retry(_call)
    return json.loads(_extract_json(response.text))


# ── 6. generate_welcome_data ──────────────────────────────────────────────────

def generate_welcome_data() -> dict:
    from datetime import date
    current_date = date.today().strftime("%-d de %B de %Y")

    schema = _obj({
        "apts":  _arr(_obj({"type": _SCHEMA_STRING, "name": _SCHEMA_STRING, "details": _SCHEMA_STRING, "description": _SCHEMA_STRING, "timestamp": _SCHEMA_STRING, "query": _SCHEMA_STRING}, ["type", "name", "details", "description", "timestamp", "query"])),
        "cves":  _arr(_obj({"type": _SCHEMA_STRING, "name": _SCHEMA_STRING, "details": _SCHEMA_STRING, "description": _SCHEMA_STRING, "timestamp": _SCHEMA_STRING, "query": _SCHEMA_STRING}, ["type", "name", "details", "description", "timestamp", "query"])),
        "latam": _arr(_obj({"type": _SCHEMA_STRING, "name": _SCHEMA_STRING, "details": _SCHEMA_STRING, "description": _SCHEMA_STRING, "timestamp": _SCHEMA_STRING, "query": _SCHEMA_STRING}, ["type", "name", "details", "description", "timestamp", "query"])),
    }, ["apts", "cves", "latam"])

    client = _get_client()

    def _call():
        from google.genai import types  # type: ignore
        return client.models.generate_content(
            model=_GEMINI_MODEL_FAST,
            contents=f"Genera 5 actividades de APTs, 5 CVEs críticos y 5 incidentes en LATAM muy recientes. Fecha de referencia: {current_date}. Responde en español en formato JSON.",
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                response_schema=schema,
                temperature=0.7,
            ),
        )

    response = _with_retry(_call)
    return json.loads(_extract_json(response.text))


# ── 7. query_ioc_context ──────────────────────────────────────────────────────

def query_ioc_context(ioc: str) -> dict:
    client = _get_client()

    def _call():
        from google.genai import types  # type: ignore
        return client.models.generate_content(
            model=_GEMINI_MODEL_FAST,
            contents=f"Proporciona contexto detallado para el Indicador de Compromiso (IoC): {ioc}. Usa búsqueda para encontrar información reciente sobre actores, malware o campañas asociadas. Responde en JSON en español con campos: ioc, type, summary, sources.",
            config=types.GenerateContentConfig(
                tools=[types.Tool(google_search=types.GoogleSearch())],
                temperature=0.2,
            ),
        )

    response = _with_retry(_call)
    raw = _extract_json(response.text)
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        data = {"ioc": ioc, "type": "Unknown", "summary": raw, "sources": []}

    try:
        chunks = response.candidates[0].grounding_metadata.grounding_chunks
        if chunks:
            extra = [{"title": c.web.title, "uri": c.web.uri} for c in chunks if getattr(c, "web", None)]
            existing_uris = {s.get("uri") for s in data.get("sources", [])}
            data.setdefault("sources", []).extend(s for s in extra if s["uri"] not in existing_uris)
    except Exception:
        pass

    return data


# ── 8. generate_weekly_flash_report ──────────────────────────────────────────

def generate_weekly_flash_report(query: str, events: list[dict]) -> dict:
    schema = _obj({
        "reportTitle": _SCHEMA_STRING,
        "threatName": _SCHEMA_STRING,
        "dateRange": _SCHEMA_STRING,
        "executiveSummary": _SCHEMA_STRING,
        "threatActorAnalysis": _obj({
            "actor": _SCHEMA_STRING,
            "attributionConfidence": {"type": "STRING", "enum": ["Low", "Medium", "High"]},
            "motivation": _SCHEMA_STRING,
        }, ["actor", "attributionConfidence", "motivation"]),
        "victimology": _SCHEMA_STRING,
        "technicalDetails": _SCHEMA_STRING,
        "mitreAttackTTPs": _arr(_obj({
            "tactic": _SCHEMA_STRING,
            "techniques": _arr(_obj({"id": _SCHEMA_STRING, "name": _SCHEMA_STRING, "description": _SCHEMA_STRING}, ["id", "name", "description"])),
        }, ["tactic", "techniques"])),
        "indicatorsOfCompromise": _arr(_obj({
            "value": _SCHEMA_STRING,
            "type": {"type": "STRING", "enum": ["IP Address", "Domain", "Hash", "URL"]},
            "description": _SCHEMA_STRING,
        }, ["value", "type", "description"])),
        "threatHuntingQueries": _arr(_obj({
            "platform": {"type": "STRING", "enum": ["Sigma", "KQL", "Splunk", "YARA", "PowerShell"]},
            "query": _SCHEMA_STRING,
            "description": _SCHEMA_STRING,
        }, ["platform", "query", "description"])),
        "mitigationRecommendations": _SCHEMA_STR_ARR,
        "sources": _arr(_obj({"title": _SCHEMA_STRING, "uri": _SCHEMA_STRING}, ["title", "uri"])),
    }, ["reportTitle", "threatName", "dateRange", "executiveSummary", "threatActorAnalysis",
        "victimology", "technicalDetails", "mitreAttackTTPs", "indicatorsOfCompromise",
        "threatHuntingQueries", "mitigationRecommendations", "sources"])

    client = _get_client()

    def _call():
        from google.genai import types  # type: ignore
        return client.models.generate_content(
            model=_GEMINI_MODEL_FAST,
            contents=f"Genera un informe flash semanal detallado para la amenaza: {query}. Eventos base: {json.dumps(events[:10])}. Responde en JSON en español.",
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                response_schema=schema,
                temperature=0.4,
            ),
        )

    response = _with_retry(_call)
    return json.loads(_extract_json(response.text))


# ── 9. extract_entities_from_text ─────────────────────────────────────────────

def extract_entities_from_text(text: str) -> dict:
    schema = _obj({
        "mainTopic": _SCHEMA_STRING,
        "iocs":    _SCHEMA_STR_ARR,
        "actors":  _SCHEMA_STR_ARR,
        "malware": _SCHEMA_STR_ARR,
        "cves":    _SCHEMA_STR_ARR,
    }, ["mainTopic", "iocs", "actors", "malware", "cves"])

    client = _get_client()

    def _call():
        from google.genai import types  # type: ignore
        return client.models.generate_content(
            model=_GEMINI_MODEL_FAST,
            contents=f"Extrae entidades de ciberseguridad (IoCs, actores, malware, CVEs) del siguiente texto: {text[:4000]}. Responde en JSON en español.",
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                response_schema=schema,
            ),
        )

    response = _with_retry(_call)
    return json.loads(_extract_json(response.text))


# ── 10. assess_colombian_risk ─────────────────────────────────────────────────

def assess_colombian_risk(actor: str, events: list[dict]) -> dict:
    schema = _obj({
        "riskSummary": _SCHEMA_STRING,
        "sectorAssessments": _arr(_obj({
            "sector": _SCHEMA_STRING,
            "riskLevel": {"type": "STRING", "enum": ["High", "Medium", "Low", "None"]},
            "justification": _SCHEMA_STRING,
            "potentialImpact": _SCHEMA_STRING,
        }, ["sector", "riskLevel", "justification", "potentialImpact"])),
    }, ["riskSummary", "sectorAssessments"])

    client = _get_client()

    def _call():
        from google.genai import types  # type: ignore
        return client.models.generate_content(
            model=_GEMINI_MODEL_FAST,
            contents=f"Evalúa el riesgo para la infraestructura crítica de Colombia (Decreto 338 de 2022) representado por el actor {actor}. Eventos: {json.dumps(events[:10])}. Responde en JSON en español.",
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                response_schema=schema,
            ),
        )

    response = _with_retry(_call)
    return json.loads(_extract_json(response.text))


# ── 11. generate_crisis_map ───────────────────────────────────────────────────

def generate_crisis_map(actor: str, ttps: list[str]) -> dict:
    schema = _obj({
        "crisisTitle": _SCHEMA_STRING,
        "attackPhases": _arr(_obj({
            "tactic": _SCHEMA_STRING,
            "description": _SCHEMA_STRING,
            "techniquesUsed": _SCHEMA_STR_ARR,
        }, ["tactic", "description", "techniquesUsed"])),
        "strategicResponses": _obj({
            "defensiveTactics": _SCHEMA_STR_ARR,
            "counterOffensiveTactics": _SCHEMA_STR_ARR,
        }, ["defensiveTactics", "counterOffensiveTactics"]),
    }, ["crisisTitle", "attackPhases", "strategicResponses"])

    client = _get_client()

    def _call():
        from google.genai import types  # type: ignore
        return client.models.generate_content(
            model=_GEMINI_MODEL_FAST,
            contents=f"Genera un mapa de crisis cibernética para el actor {actor} con las TTPs: {', '.join(ttps)}. Responde en JSON en español.",
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                response_schema=schema,
            ),
        )

    response = _with_retry(_call)
    return json.loads(_extract_json(response.text))


# ── 12. generate_team_scenarios ───────────────────────────────────────────────

def generate_team_scenarios(actor: str, ttps: list[str]) -> dict:
    _scenario = _obj({
        "scenarioTitle": _SCHEMA_STRING,
        "phases": _arr(_obj({
            "phaseName": _SCHEMA_STRING,
            "actions": _SCHEMA_STR_ARR,
        }, ["phaseName", "actions"])),
    }, ["scenarioTitle", "phases"])

    schema = _obj({
        "redTeam": _scenario,
        "blueTeam": _scenario,
        "purpleTeam": _scenario,
        "whiteTeam": _scenario,
    }, ["redTeam", "blueTeam", "purpleTeam", "whiteTeam"])

    client = _get_client()

    def _call():
        from google.genai import types  # type: ignore
        return client.models.generate_content(
            model=_GEMINI_MODEL_FAST,
            contents=f"Genera escenarios de simulación (Red, Blue, Purple, White Team) para el actor {actor} con TTPs: {', '.join(ttps)}. Responde en JSON en español.",
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                response_schema=schema,
            ),
        )

    response = _with_retry(_call)
    return json.loads(_extract_json(response.text))


# ── 13. generate_behavioral_analysis ─────────────────────────────────────────

def generate_behavioral_analysis(topic: str, threats: list[dict]) -> dict:
    schema = _obj({
        "threatBehavior": _SCHEMA_STRING,
        "historicalExplanations": _arr(_obj({
            "event": _SCHEMA_STRING,
            "explanation": _SCHEMA_STRING,
        }, ["event", "explanation"])),
    }, ["threatBehavior", "historicalExplanations"])

    client = _get_client()

    def _call():
        from google.genai import types  # type: ignore
        return client.models.generate_content(
            model=_GEMINI_MODEL_FAST,
            contents=f"Analiza el comportamiento de la amenaza \"{topic}\" y explica los eventos históricos más relevantes de: {json.dumps(threats[:20])}. Responde en español.",
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                response_schema=schema,
            ),
        )

    response = _with_retry(_call)
    return json.loads(_extract_json(response.text))


# ── 14. generate_playbook ─────────────────────────────────────────────────────

def generate_playbook(threat_name: str, threat_type: str) -> dict:
    schema = _obj({
        "identification": _SCHEMA_STR_ARR,
        "containment": _SCHEMA_STR_ARR,
        "eradication": _SCHEMA_STR_ARR,
        "recovery": _SCHEMA_STR_ARR,
        "lessonsLearned": _SCHEMA_STR_ARR,
    }, ["identification", "containment", "eradication", "recovery", "lessonsLearned"])

    client = _get_client()

    def _call():
        from google.genai import types  # type: ignore
        return client.models.generate_content(
            model=_GEMINI_MODEL_FAST,
            contents=f"Genera un playbook de respuesta a incidentes para la amenaza: {threat_name} ({threat_type}). Responde en JSON en español.",
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                response_schema=schema,
            ),
        )

    response = _with_retry(_call)
    return json.loads(_extract_json(response.text))


# ── 15. generate_ml_proposals ─────────────────────────────────────────────────

def generate_ml_proposals(events: list[dict]) -> dict:
    schema = _obj({
        "summary": _SCHEMA_STRING,
        "proposals": _arr(_obj({
            "targetEventId": _SCHEMA_NUMBER,
            "actor": _SCHEMA_STRING,
            "suggestedModel": _SCHEMA_STRING,
            "reasoning": _SCHEMA_STRING,
            "featuresToUse": _SCHEMA_STR_ARR,
            "expectedOutcome": _SCHEMA_STRING,
            "dataErrors": _SCHEMA_STR_ARR,
            "expandedActorAnalysis": _SCHEMA_STRING,
        }, ["targetEventId", "actor", "suggestedModel", "reasoning", "featuresToUse", "expectedOutcome"])),
    }, ["summary", "proposals"])

    client = _get_client()

    def _call():
        from google.genai import types  # type: ignore
        return client.models.generate_content(
            model=_GEMINI_MODEL_FAST,
            contents=f"""Realiza un análisis profundo evento por evento de los datos de amenazas: {json.dumps(events[:20])}.
Para cada evento/actor:
1. Propón un modelo ML específico (Random Forest, LSTM, SVM, Clustering) óptimo para detectar o mitigar ese comportamiento.
2. Identifica errores o inconsistencias en los datos (dataErrors).
3. Amplía el análisis sobre el actor (expandedActorAnalysis) con perfil, motivaciones y TTPs.
4. Explica el razonamiento técnico, features a usar y resultado esperado.
Responde estrictamente en JSON en español.""",
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                response_schema=schema,
                temperature=0.3,
            ),
        )

    response = _with_retry(_call)
    return json.loads(_extract_json(response.text))


# ── 16. generate_geopolitical_analysis ───────────────────────────────────────

def generate_geopolitical_analysis(query: str) -> dict:
    from datetime import date
    current_date = date.today().isoformat()

    schema = _obj({
        "summary": _SCHEMA_STRING,
        "recentEvents": _arr(_obj({
            "date": _SCHEMA_STRING,
            "event": _SCHEMA_STRING,
            "impactOnCybersecurity": _SCHEMA_STRING,
            "source": _SCHEMA_STRING,
        }, ["date", "event", "impactOnCybersecurity"])),
        "anticipatoryThreats": _arr(_obj({
            "threat": _SCHEMA_STRING,
            "probability": {"type": "STRING", "enum": ["Low", "Medium", "High"]},
            "estimatedTimeframe": _SCHEMA_STRING,
            "mitigationStrategy": _SCHEMA_STRING,
        }, ["threat", "probability", "estimatedTimeframe", "mitigationStrategy"])),
        "regionalStabilityScore": _SCHEMA_NUMBER,
    }, ["summary", "recentEvents", "anticipatoryThreats", "regionalStabilityScore"])

    client = _get_client()

    def _call():
        from google.genai import types  # type: ignore
        return client.models.generate_content(
            model=_GEMINI_MODEL_FAST,
            contents=f"""Realiza un análisis geopolítico profundo relacionado con: "{query}".
Busca eventos significativos desde 2023 hasta la fecha actual ({current_date}).
Incluye campañas recientes y su impacto en ciberseguridad global/regional.
Proporciona análisis anticipativo de amenazas basado en estos movimientos geopolíticos.
Responde estrictamente en JSON en español.""",
            config=types.GenerateContentConfig(
                tools=[],  # no google_search to keep response structured
                response_mime_type="application/json",
                response_schema=schema,
                temperature=0.4,
            ),
        )

    response = _with_retry(_call)
    result = json.loads(_extract_json(response.text))

    # Enrich sources from grounding if available
    try:
        chunks = response.candidates[0].grounding_metadata.grounding_chunks
        if chunks:
            web_sources = [c.web.uri for c in chunks if getattr(c, "web", None) and c.web.uri]
            for i, ev in enumerate(result.get("recentEvents", [])):
                if not ev.get("source") and i < len(web_sources):
                    ev["source"] = web_sources[i % len(web_sources)]
    except Exception:
        pass

    return result


# ── generate_threat_graph (shared logic via CISA database) ────────────────────

def generate_threat_graph(events: list[dict], query: str) -> dict:
    """Delegates to the Claude engine's implementation (same logic, no Gemini schema needed)."""
    from ai.claude_fusion_engine import generate_threat_graph as _claude_graph
    return _claude_graph(events, query)


# ── Public convenience dict ────────────────────────────────────────────────────

HANDLERS: dict[str, callable] = {
    "threat-data":       generate_threat_data,
    "quantum":           generate_quantum_threat_analysis,
    "predictive":        generate_predictive_analysis,
    "fusion-report":     generate_fusion_report,
    "mitre-details":     generate_mitre_details,
    "welcome":           generate_welcome_data,
    "ioc-context":       query_ioc_context,
    "weekly-report":     generate_weekly_flash_report,
    "extract-entities":  extract_entities_from_text,
    "colombia-risk":     assess_colombian_risk,
    "crisis-map":        generate_crisis_map,
    "team-scenarios":    generate_team_scenarios,
    "behavioral":        generate_behavioral_analysis,
    "playbook":          generate_playbook,
    "ml-proposals":      generate_ml_proposals,
    "geopolitical":      generate_geopolitical_analysis,
    "threat-graph":      generate_threat_graph,
}

"""
RedCiber Think Tank — Motor de Fusión de Amenazas
Claude (Anthropic) backend — same 16-function API as gemini_engine.py

Uses:
  - claude-sonnet-4-6  (fast, cost-efficient, excellent JSON)
  - Prompt caching on the CTI system context (saves ~80% tokens on repeated calls)
  - Structured JSON output via explicit instructions

All function signatures are identical to gemini_engine.py so the
dispatch logic in main.py can swap engines transparently.
"""
from __future__ import annotations

import json
import logging
import os
import re
import time
from datetime import date
from typing import Any

_MODEL = os.getenv("CLAUDE_FUSION_MODEL", "claude-sonnet-4-6")
_MAX_TOKENS = 4096
_logger = logging.getLogger("cti.claude")

_SYSTEM_CTI = """Eres el Motor de Fusión de Inteligencia RedCiber (Think Tank Estratégico).
Eres un analista senior de Cyber Threat Intelligence con 15 años de experiencia en:
- Atribución de actores de amenaza (APTs, ransomware, hacktivistas)
- Mapeo MITRE ATT&CK y D3FEND
- Análisis de infraestructura crítica latinoamericana
- Propuestas de modelos de Machine Learning para detección de amenazas
- Análisis geopolítico con impacto en ciberseguridad
- Evaluación de riesgo cuántico / Post-Quantum Cryptography (PQC)

Responde SIEMPRE en español. Para respuestas estructuradas, devuelve ÚNICAMENTE JSON válido sin markdown, sin bloques de código, sin explicaciones adicionales."""


class ClaudeNotConfiguredError(RuntimeError):
    pass


_client = None


def _get_client():
    global _client
    try:
        import anthropic  # type: ignore
    except ImportError as e:
        raise ClaudeNotConfiguredError("anthropic package not installed.") from e
    key = os.getenv("ANTHROPIC_API_KEY", "")
    if not key:
        raise ClaudeNotConfiguredError(
            "ANTHROPIC_API_KEY environment variable is not set."
        )
    if _client is None:
        import anthropic as _anthropic  # type: ignore
        globals()["_client"] = _anthropic.Anthropic(api_key=key)
    return _client


def _with_retry(fn, max_retries: int = 3, initial_delay: float = 2.0):
    """Retry with exponential backoff — mirrors gemini_engine._with_retry."""
    delay = initial_delay
    for attempt in range(max_retries):
        try:
            return fn()
        except Exception as exc:
            if attempt == max_retries - 1:
                raise
            _logger.warning(
                "Claude call failed (intento %d/%d): %s — reintentando en %.1fs",
                attempt + 1, max_retries, exc, delay,
            )
            time.sleep(delay)
            delay *= 2


def _call(prompt: str, max_tokens: int = _MAX_TOKENS) -> str:
    """Single call with system-level prompt caching and retry."""
    t0 = time.time()

    def _invoke():
        client = _get_client()
        return client.messages.create(
            model=_MODEL,
            max_tokens=max_tokens,
            system=[{
                "type": "text",
                "text": _SYSTEM_CTI,
                "cache_control": {"type": "ephemeral"},
            }],
            messages=[{"role": "user", "content": prompt}],
        )

    response = _with_retry(_invoke)
    elapsed = time.time() - t0
    _logger.info(
        "Claude ✓ %.1fs | in=%d out=%d | model=%s",
        elapsed,
        response.usage.input_tokens,
        response.usage.output_tokens,
        _MODEL,
    )
    return response.content[0].text.strip()


def _call_json(prompt: str, max_tokens: int = _MAX_TOKENS) -> dict | list:
    """Call Claude and parse the response as JSON."""
    full_prompt = prompt + "\n\nIMPORTANTE: Responde ÚNICAMENTE con JSON válido, sin markdown, sin bloques ```json, sin texto adicional."
    raw = _call(full_prompt, max_tokens)
    raw = re.sub(r'^```(?:json)?\s*', '', raw, flags=re.MULTILINE)
    raw = re.sub(r'\s*```$', '', raw, flags=re.MULTILINE)
    raw = raw.strip()
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        _logger.error("Claude devolvió JSON inválido: %s…", raw[:300])
        raise ValueError(f"Motor Claude devolvió JSON inválido: {exc}") from exc


# ── 1. generate_threat_data ────────────────────────────────────────────────────

def generate_threat_data(topic: str, is_annual: bool = False) -> dict:
    today = date.today().isoformat()
    count = "EXACTAMENTE 1000" if is_annual else "150"
    time_range = "DESDE ENERO DE 2020 HASTA HOY (análisis multianual)" if is_annual else "Últimos 30 días (operativo)"

    prompt = f"""OBJETIVO: Genera {count} eventos de ciberseguridad en formato CSV delimitado por pipes (|).
CONTEXTO: {topic}
RANGO TEMPORAL: {time_range}
FECHA ACTUAL: {today}

Si el contexto incluye múltiples actores:
1. Genera eventos donde compitan, colaboren o ataquen objetivos similares (ej: infraestructuras de Colombia)
2. TTPs distintivas por actor según inteligencia conocida
3. Al menos 3 incidentes de "Fusión" donde actividades de ambos actores se crucen

FORMATO ESTRICTO — solo texto CSV, sin explicaciones:
id|timestamp|threatType|severity|sourceCountry|targetCountry|description|ioc|informationSource|malware|threatActor|threatName|victim|mitreTactic|mitreTechniqueId|mitreTechniqueName|dataCollectionMethod|sourceIp|targetIp|protocol|sourcePort|targetPort|payloadSize|confidenceScore|infrastructureType|sessionDuration|isFalsePositive

Valores válidos:
- severity: Low, Medium, High, Critical
- threatType: Malware, Phishing, DDoS, Ransomware, Insider Threat, SQL Injection, Zero-Day Exploit, Data Exfiltration
- mitreTactic: Reconnaissance, Resource Development, Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Command and Control, Exfiltration, Impact
- isFalsePositive: true/false

Al final añade exactamente: ---PREDICTIVE_INSIGHTS---
Seguido de este JSON en una sola línea: {{"regressionTrend":"Linear","acceleration":1.2,"topPostulatedSector":"Financiero","confidenceScore":85,"multiActorCorrelation":"Colaboración detectada en infraestructura C2 compartida"}}"""

    max_tok = 16000 if is_annual else 10000
    raw = _call(prompt, max_tokens=max_tok)

    csv_data, predictive = raw, None
    if "---PREDICTIVE_INSIGHTS---" in raw:
        parts = raw.split("---PREDICTIVE_INSIGHTS---")
        csv_data = parts[0].strip()
        try:
            predictive = json.loads(parts[1].strip().splitlines()[0])
        except Exception:
            pass

    lines = [l for l in csv_data.splitlines() if "|" in l]
    if len(lines) < 2:
        raise ValueError("Dataset malformado o insuficiente.")

    headers = [h.strip() for h in lines[0].split("|")]
    threats: list[dict[str, Any]] = []
    for idx, line in enumerate(lines[1:]):
        values = [v.strip() for v in line.split("|")]
        row: dict[str, Any] = {headers[i]: values[i] if i < len(values) else "" for i in range(len(headers))}
        row["id"] = row.get("id") or str(idx + 1)
        row["isFalsePositive"] = str(row.get("isFalsePositive", "false")).lower() == "true"
        for f in ("sourcePort", "targetPort", "payloadSize", "sessionDuration"):
            try: row[f] = int(row.get(f, 0) or 0)
            except: row[f] = 0
        try: row["confidenceScore"] = float(row.get("confidenceScore", 0) or 0)
        except: row["confidenceScore"] = 0.0
        threats.append(row)

    return {"threats": threats, "sector_analysis": json.dumps(predictive) if predictive else None}


# ── 2. generate_quantum_threat_analysis ───────────────────────────────────────

def generate_quantum_threat_analysis(actor: str, events: list[dict]) -> dict:
    prompt = f"""Analiza el riesgo cuántico y Post-Quantum Cryptography (PQC) para el actor {actor}.
Eventos de referencia (máx 10): {json.dumps(events[:10])}

Devuelve JSON con esta estructura exacta:
{{
  "hndlRisk": {{
    "score": <número 0-100>,
    "justification": "<texto>",
    "indicators": ["<indicador1>", "<indicador2>"]
  }},
  "pqcVulnerability": {{
    "sectorStatus": "<texto>",
    "exposedAlgorithms": ["RSA-2048", "..."],
    "migrationPriority": "Low|Medium|High|Critical"
  }},
  "quantumTTPs": [
    {{"technique": "<nombre>", "description": "<texto>", "mitigation": "<texto>"}}
  ],
  "cryptoAgilityIndex": <número 0-100>
}}"""
    return _call_json(prompt)


# ── 3. generate_predictive_analysis ───────────────────────────────────────────

def generate_predictive_analysis(threats: list[dict], query: str) -> dict:
    prompt = f"""ANÁLISIS PREDICTIVO Y DE VALIDACIÓN
Consulta: "{query}"
Eventos (máx 20): {json.dumps(threats[:20])}

Analiza:
1. CO-RELACIÓN: Si hay múltiples actores, identifica si colaboran, compiten o fusionan infraestructuras.
2. VALIDACIÓN HISTÓRICA: ¿Son las acciones consistentes con el perfil histórico? Identifica "Acciones Anómalas".
3. NEXO CRUZADO: Puntos donde las tácticas de diferentes actores se cruzan.

Devuelve JSON:
{{
  "potentialImpact": {{"severity": "Medium|High|Critical", "probability": 0.85, "reasoning": "<texto>"}},
  "predictedNextTactic": {{"tactic": "<táctica>", "reasoning": "<texto>"}},
  "recalculatedAttribution": {{"actor": "<nombre>", "confidence": 0.92, "reasoning": "<texto>"}},
  "multiActorCorrelation": "<texto o null>",
  "historicalValidation": [{{"actor": "<nombre>", "consistencyScore": 0.85, "anomalousActions": ["<acción>"], "confirmedPatterns": ["<patrón>"]}}],
  "crossActorNexus": [{{"actors": ["<actor1>","<actor2>"], "sharedTtp": "<TTP>", "sharedInfrastructure": "<texto>", "targetOverlapScore": 0.7}}]
}}"""
    return _call_json(prompt)


# ── 4. generate_fusion_report ─────────────────────────────────────────────────

def generate_fusion_report(query: str, threats: list[dict]) -> dict:
    prompt = f"""Genera un informe ejecutivo de inteligencia de amenazas.
Tema: "{query}"
Total eventos: {len(threats)}
Muestra de eventos: {json.dumps(threats[:15])}

Devuelve JSON:
{{
  "title": "<título>",
  "executiveSummary": "<resumen ejecutivo 3-4 párrafos>",
  "keyMetrics": {{"analysisPeriod": "<periodo>", "totalEvents": {len(threats)}, "topActors": "<lista>", "topTactics": "<lista>"}},
  "fusionLogic": "<metodología de análisis>",
  "priorityThreats": [{{"title": "<amenaza>", "description": "<descripción>"}}],
  "relevantIocs": [{{"ioc": "<valor>", "description": "<contexto>"}}],
  "recommendations": ["<recomendación1>", "<recomendación2>"],
  "recentSources": []
}}"""
    return _call_json(prompt, max_tokens=4096)


# ── 5. generate_mitre_details ─────────────────────────────────────────────────

def generate_mitre_details(actor: str, technique_ids: list[str]) -> list:
    prompt = f"""Para el actor {actor}, describe cómo usa estas técnicas MITRE ATT&CK: {', '.join(technique_ids)}.
Agrupa por táctica. Devuelve JSON array:
[{{"tactic": "<táctica>", "techniques": [{{"id": "T1XXX", "name": "<nombre>", "description": "<cómo lo usa este actor>"}}]}}]"""
    result = _call_json(prompt)
    return result if isinstance(result, list) else [result]


# ── 6. generate_welcome_data ──────────────────────────────────────────────────

def generate_welcome_data() -> dict:
    today = date.today().strftime("%-d de %B de %Y")
    prompt = f"""Genera datos para el panel de bienvenida de una plataforma CTI.
Fecha: {today}

Devuelve JSON con actividad reciente REAL y relevante:
{{
  "apts": [
    {{"type": "APT", "name": "<nombre grupo>", "details": "<país, motivación>", "description": "<actividad reciente>", "timestamp": "<fecha ISO>", "query": "<consulta sugerida>"}}
  ],
  "cves": [
    {{"type": "CVE", "name": "CVE-XXXX-XXXX", "details": "<CVSS score>", "description": "<descripción breve>", "timestamp": "<fecha ISO>", "query": "<consulta sugerida>"}}
  ],
  "latam": [
    {{"type": "LATAM", "name": "<nombre incidente>", "details": "<país afectado>", "description": "<descripción>", "timestamp": "<fecha ISO>", "query": "<consulta sugerida>"}}
  ]
}}

Genera 5 entradas por categoría. Prioriza eventos de 2025-2026."""
    return _call_json(prompt)


# ── 7. query_ioc_context ──────────────────────────────────────────────────────

def query_ioc_context(ioc: str) -> dict:
    prompt = f"""Proporciona contexto detallado de Threat Intelligence para el IOC: {ioc}

Devuelve JSON:
{{
  "ioc": "{ioc}",
  "type": "Hash|IP Address|Domain",
  "summary": "<análisis detallado: actores asociados, campañas, técnicas, historial>",
  "sources": [{{"title": "<fuente>", "uri": "<url si conoces>"}}]
}}"""
    return _call_json(prompt)


# ── 8. generate_weekly_flash_report ──────────────────────────────────────────

def generate_weekly_flash_report(query: str, events: list[dict]) -> dict:
    prompt = f"""Genera un informe flash semanal de amenaza CTI.
Amenaza: {query}
Eventos base: {json.dumps(events[:10])}

Devuelve JSON:
{{
  "reportTitle": "<título>",
  "threatName": "<nombre amenaza>",
  "dateRange": "<rango de fechas>",
  "executiveSummary": "<resumen ejecutivo>",
  "threatActorAnalysis": {{"actor": "<nombre>", "attributionConfidence": "Low|Medium|High", "motivation": "<motivación>"}},
  "victimology": "<descripción de víctimas>",
  "technicalDetails": "<detalles técnicos>",
  "mitreAttackTTPs": [{{"tactic": "<táctica>", "techniques": [{{"id": "T1XXX", "name": "<nombre>", "description": "<descripción>"}}]}}],
  "indicatorsOfCompromise": [{{"value": "<ioc>", "type": "IP Address|Domain|Hash|URL", "description": "<contexto>"}}],
  "threatHuntingQueries": [
    {{"platform": "Sigma|KQL|Splunk|YARA|PowerShell", "query": "<regla o query>", "description": "<qué detecta>"}}
  ],
  "mitigationRecommendations": ["<rec1>", "<rec2>"],
  "sources": []
}}"""
    return _call_json(prompt, max_tokens=4096)


# ── 9. extract_entities_from_text ─────────────────────────────────────────────

def extract_entities_from_text(text: str) -> dict:
    prompt = f"""Extrae entidades de ciberseguridad del siguiente texto:

{text[:4000]}

Devuelve JSON:
{{
  "mainTopic": "<tema principal>",
  "iocs": ["<ip>", "<dominio>", "<hash>"],
  "actors": ["<actor1>"],
  "malware": ["<familia1>"],
  "cves": ["CVE-XXXX-XXXX"]
}}"""
    return _call_json(prompt)


# ── 10. assess_colombian_risk ─────────────────────────────────────────────────

def assess_colombian_risk(actor: str, events: list[dict]) -> dict:
    prompt = f"""Evalúa el riesgo para la infraestructura crítica de Colombia (Decreto 338 de 2022).
Actor: {actor}
Eventos: {json.dumps(events[:10])}

Sectores a evaluar: Energía, Telecomunicaciones, Transporte, Salud, Finanzas, Agua, Gobierno, Defensa.

Devuelve JSON:
{{
  "riskSummary": "<resumen ejecutivo del riesgo>",
  "sectorAssessments": [
    {{"sector": "<nombre>", "riskLevel": "High|Medium|Low|None", "justification": "<texto>", "potentialImpact": "<texto>"}}
  ]
}}"""
    return _call_json(prompt)


# ── 11. generate_crisis_map ───────────────────────────────────────────────────

def generate_crisis_map(actor: str, ttps: list[str]) -> dict:
    prompt = f"""Genera un mapa de crisis cibernética.
Actor: {actor}
TTPs: {', '.join(ttps)}

Devuelve JSON:
{{
  "crisisTitle": "<título>",
  "attackPhases": [
    {{"tactic": "<táctica>", "description": "<descripción>", "techniquesUsed": ["T1XXX"]}}
  ],
  "strategicResponses": {{
    "defensiveTactics": ["<táctica defensiva>"],
    "counterOffensiveTactics": ["<táctica ofensiva>"]
  }}
}}"""
    return _call_json(prompt)


# ── 12. generate_team_scenarios ───────────────────────────────────────────────

def generate_team_scenarios(actor: str, ttps: list[str]) -> dict:
    prompt = f"""Genera escenarios de simulación para equipos de seguridad.
Actor amenaza: {actor}
TTPs: {', '.join(ttps)}

Devuelve JSON con 4 escenarios (Red, Blue, Purple, White Team):
{{
  "redTeam": {{
    "scenarioTitle": "<título>",
    "phases": [{{"phaseName": "<fase>", "actions": ["<acción1>", "<acción2>"]}}]
  }},
  "blueTeam": {{
    "scenarioTitle": "<título>",
    "phases": [{{"phaseName": "<fase>", "actions": ["<acción1>"]}}]
  }},
  "purpleTeam": {{
    "scenarioTitle": "<título>",
    "phases": [{{"phaseName": "<fase>", "actions": ["<acción1>"]}}]
  }},
  "whiteTeam": {{
    "scenarioTitle": "<título>",
    "phases": [{{"phaseName": "<fase>", "actions": ["<acción1>"]}}]
  }}
}}"""
    return _call_json(prompt)


# ── 13. generate_behavioral_analysis ─────────────────────────────────────────

def generate_behavioral_analysis(topic: str, threats: list[dict]) -> dict:
    prompt = f"""Analiza el comportamiento histórico de la amenaza "{topic}".
Eventos relevantes: {json.dumps(threats[:20])}

Devuelve JSON:
{{
  "threatBehavior": "<análisis del comportamiento observable y patrones>",
  "historicalExplanations": [
    {{"event": "<nombre/id evento>", "explanation": "<qué sucedió y por qué es relevante>"}}
  ]
}}"""
    return _call_json(prompt)


# ── 14. generate_playbook ─────────────────────────────────────────────────────

def generate_playbook(threat_name: str, threat_type: str) -> dict:
    prompt = f"""Genera un playbook de respuesta a incidentes siguiendo el framework PICERL.
Amenaza: {threat_name} ({threat_type})

Devuelve JSON:
{{
  "identification": ["<paso1>", "<paso2>"],
  "containment": ["<paso1>", "<paso2>"],
  "eradication": ["<paso1>", "<paso2>"],
  "recovery": ["<paso1>", "<paso2>"],
  "lessonsLearned": ["<lección1>", "<lección2>"]
}}"""
    return _call_json(prompt)


# ── 15. generate_ml_proposals ─────────────────────────────────────────────────

def generate_ml_proposals(events: list[dict]) -> dict:
    prompt = f"""Analiza estos eventos de ciberseguridad y propone modelos de Machine Learning.
Eventos (máx 20): {json.dumps(events[:20])}

Para cada evento/actor:
1. Propón el modelo ML óptimo (Random Forest, LSTM, SVM, Isolation Forest, K-Means, etc.)
2. Identifica errores o inconsistencias en los datos
3. Amplía el análisis del actor (perfil, motivaciones, TTPs)
4. Justifica el modelo con features específicas del dataset

Devuelve JSON:
{{
  "summary": "<resumen del análisis>",
  "proposals": [
    {{
      "targetEventId": 1,
      "actor": "<nombre actor>",
      "suggestedModel": "<nombre modelo>",
      "reasoning": "<justificación técnica>",
      "featuresToUse": ["feature1", "feature2"],
      "expectedOutcome": "<resultado esperado>",
      "dataErrors": ["<error detectado si existe>"],
      "expandedActorAnalysis": "<análisis detallado del actor>"
    }}
  ]
}}"""
    return _call_json(prompt, max_tokens=4096)


# ── 16. generate_geopolitical_analysis ───────────────────────────────────────


def generate_geopolitical_analysis(query: str) -> dict:
    today = date.today().isoformat()
    prompt = f"""Realiza un análisis geopolítico profundo relacionado con: "{query}"
Fecha actual: {today}

Incluye:
- Eventos geopolíticos significativos desde 2023 con impacto en ciberseguridad
- Amenazas anticipativas basadas en movimientos geopolíticos
- Score de estabilidad regional (0-10)

Devuelve JSON:
{{
  "summary": "<análisis geopolítico>",
  "recentEvents": [
    {{"date": "<fecha ISO>", "event": "<descripción>", "impactOnCybersecurity": "<impacto>", "source": "<fuente>"}}
  ],
  "anticipatoryThreats": [
    {{"threat": "<amenaza>", "probability": "Low|Medium|High", "estimatedTimeframe": "<plazo>", "mitigationStrategy": "<estrategia>"}}
  ],
  "regionalStabilityScore": 6.5
}}"""
    return _call_json(prompt)


# ── 17. generate_threat_graph ─────────────────────────────────────────────────

def generate_threat_graph(events: list[dict], query: str) -> dict:
    """Build Actor → IOC → Campaign correlation graph enriched with CISA database."""
    from ai.graph_builder import (
        extract_graph_data, enrich_with_cisa,
        build_actor_profiles, build_graph_nodes_edges,
    )

    actor_counts, ioc_counts, tactic_by_actor, top_actors, top_iocs = extract_graph_data(events)
    cisa_enrichment = enrich_with_cisa(top_actors)
    actor_profiles = build_actor_profiles(top_actors, actor_counts, tactic_by_actor, cisa_enrichment)

    prompt = f"""Eres un analista CTI. Construye un grafo de correlación de amenazas.
Consulta: "{query}"
Actores en los eventos (con datos CISA): {json.dumps(actor_profiles)}
IOCs detectados: {json.dumps(top_iocs[:10])}

Devuelve JSON con esta estructura exacta:
{{
  "campaigns": [
    {{
      "id": "camp_1",
      "name": "<nombre campaña>",
      "attributed_actors": ["<actor1>"],
      "description": "<descripción 1 línea>",
      "timeframe": "<2023-2025>",
      "iocs_generated": ["<ioc si corresponde>"]
    }}
  ],
  "cross_correlations": [
    {{
      "actors": ["<actor1>", "<actor2>"],
      "relationship": "Comparten infraestructura C2|Mismos TTPs|Víctimas coincidentes|Posible colaboración",
      "evidence": "<evidencia técnica>"
    }}
  ],
  "graph_summary": "<párrafo de 2-3 oraciones sobre el panorama de amenazas>"
}}

Genera entre 2-5 campañas y 1-3 correlaciones cruzadas basadas en los actores presentes."""

    ai_data = _call_json(prompt)
    campaigns = ai_data.get("campaigns", []) if isinstance(ai_data, dict) else []
    correlations = ai_data.get("cross_correlations", []) if isinstance(ai_data, dict) else []
    summary = ai_data.get("graph_summary", "") if isinstance(ai_data, dict) else ""

    return build_graph_nodes_edges(
        top_actors, top_iocs, campaigns, correlations, summary,
        actor_counts, ioc_counts, tactic_by_actor, cisa_enrichment,
    )


# ── Public dict (same interface as gemini_engine.HANDLERS) ───────────────────

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

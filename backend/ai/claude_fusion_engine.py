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
import os
import re
import time
from datetime import date
from typing import Any

_MODEL = os.getenv("CLAUDE_FUSION_MODEL", "claude-sonnet-4-6")
_MAX_TOKENS = 4096

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


def _get_client():
    try:
        import anthropic  # type: ignore
    except ImportError as e:
        raise ClaudeNotConfiguredError("anthropic package not installed.") from e
    key = os.getenv("ANTHROPIC_API_KEY", "")
    if not key:
        raise ClaudeNotConfiguredError(
            "ANTHROPIC_API_KEY environment variable is not set."
        )
    return anthropic.Anthropic(api_key=key)


def _call(prompt: str, max_tokens: int = _MAX_TOKENS) -> str:
    """Single call with system-level prompt caching."""
    import anthropic  # type: ignore
    client = _get_client()
    response = client.messages.create(
        model=_MODEL,
        max_tokens=max_tokens,
        system=[{
            "type": "text",
            "text": _SYSTEM_CTI,
            "cache_control": {"type": "ephemeral"},
        }],
        messages=[{"role": "user", "content": prompt}],
    )
    return response.content[0].text.strip()


def _call_json(prompt: str, max_tokens: int = _MAX_TOKENS) -> dict | list:
    """Call Claude and parse the response as JSON."""
    full_prompt = prompt + "\n\nIMPORTANTE: Responde ÚNICAMENTE con JSON válido, sin markdown, sin bloques ```json, sin texto adicional."
    raw = _call(full_prompt, max_tokens)
    # Strip markdown fences if model added them anyway
    raw = re.sub(r'^```(?:json)?\s*', '', raw, flags=re.MULTILINE)
    raw = re.sub(r'\s*```$', '', raw, flags=re.MULTILINE)
    raw = raw.strip()
    return json.loads(raw)


# ── 1. generate_threat_data ────────────────────────────────────────────────────

def generate_threat_data(topic: str, is_annual: bool = False) -> dict:
    today = date.today().isoformat()
    count = "EXACTAMENTE 500" if is_annual else "60"
    time_range = "DESDE ENERO DE 2020 HASTA HOY (análisis multianual)" if is_annual else "Últimos 7 días (operativo)"

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

    raw = _call(prompt, max_tokens=8000)

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
    from intelligence.apt_database import match_actor_to_database, CISA_APT_DATABASE

    # Extract unique actors, IOCs, and deduplicated data from events
    actor_counts: dict[str, int] = {}
    ioc_counts: dict[str, list[str]] = {}
    tactic_by_actor: dict[str, list[str]] = {}

    for ev in events:
        actor = (ev.get("threatActor") or "").strip()
        ioc = (ev.get("ioc") or "").strip()
        tactic = (ev.get("mitreTactic") or "").strip()
        if actor and actor not in ("Unknown", "N/A", ""):
            actor_counts[actor] = actor_counts.get(actor, 0) + 1
            if tactic:
                tactic_by_actor.setdefault(actor, [])
                if tactic not in tactic_by_actor[actor]:
                    tactic_by_actor[actor].append(tactic)
        if ioc and ioc not in ("N/A", "—", ""):
            ioc_counts.setdefault(ioc, [])
            if actor and actor not in ioc_counts[ioc]:
                ioc_counts[ioc].append(actor)

    top_actors = sorted(actor_counts, key=lambda a: actor_counts[a], reverse=True)[:8]
    top_iocs = sorted(ioc_counts, key=lambda i: len(ioc_counts[i]), reverse=True)[:12]

    # Match actors against CISA database
    cisa_enrichment: dict[str, dict] = {}
    for actor in top_actors:
        match = match_actor_to_database(actor)
        if match:
            cisa_enrichment[actor] = match

    # Build context for Claude: enrich + ask for campaign attribution + correlations
    actor_profiles = []
    for actor in top_actors:
        cisa = cisa_enrichment.get(actor)
        profile = {"name": actor, "events": actor_counts[actor], "tactics": tactic_by_actor.get(actor, [])}
        if cisa:
            profile["cisa_country"] = cisa["country"]
            profile["cisa_risk"] = cisa["risk_level"]
            profile["cisa_campaigns"] = cisa["known_campaigns"][:3]
            profile["cisa_advisory"] = cisa["cisa_advisories"][:2] if cisa.get("cisa_advisories") else []
        actor_profiles.append(profile)

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

    # Build ReactFlow-compatible nodes and edges
    nodes: list[dict] = []
    edges: list[dict] = []
    edge_counter = 0

    def add_edge(src: str, tgt: str, label: str, animated: bool = False, color: str = "#475569"):
        nonlocal edge_counter
        edge_counter += 1
        edges.append({
            "id": f"e{edge_counter}",
            "source": src,
            "target": tgt,
            "label": label,
            "animated": animated,
            "style": {"stroke": color, "strokeWidth": 1.5},
            "labelStyle": {"fill": "#94a3b8", "fontSize": 9},
        })

    # Actor nodes (left column)
    for i, actor in enumerate(top_actors):
        cisa = cisa_enrichment.get(actor)
        risk = cisa["risk_level"] if cisa else ("High" if actor_counts[actor] > 3 else "Medium")
        risk_color = {"Critical": "#ef4444", "High": "#f97316", "Medium": "#facc15", "Low": "#4ade80"}.get(risk, "#94a3b8")
        nodes.append({
            "id": f"actor:{actor}",
            "type": "actor",
            "position": {"x": 50, "y": i * 130 + 40},
            "data": {
                "label": actor,
                "nodeType": "actor",
                "country": cisa["country"] if cisa else "Desconocido",
                "motivation": cisa["motivation"] if cisa else "No atribuido",
                "risk": risk,
                "riskColor": risk_color,
                "eventCount": actor_counts[actor],
                "tactics": tactic_by_actor.get(actor, [])[:3],
                "cisaMatch": bool(cisa),
                "cisaAdvisories": cisa["cisa_advisories"][:2] if cisa else [],
                "cisaAliases": cisa["aliases"][:3] if cisa else [],
                "knownCampaigns": cisa["known_campaigns"][:3] if cisa else [],
                "sponsor": cisa.get("sponsor", "") if cisa else "",
            },
        })

    # Campaign nodes (center column)
    for i, camp in enumerate(campaigns[:6]):
        camp_id = f"campaign:{camp['id']}"
        nodes.append({
            "id": camp_id,
            "type": "campaign",
            "position": {"x": 400, "y": i * 110 + 40},
            "data": {
                "label": camp["name"],
                "nodeType": "campaign",
                "description": camp.get("description", ""),
                "timeframe": camp.get("timeframe", ""),
                "attributedActors": camp.get("attributed_actors", []),
            },
        })
        # Actor → Campaign edges
        for actor_name in camp.get("attributed_actors", []):
            if any(n["id"] == f"actor:{actor_name}" for n in nodes):
                add_edge(f"actor:{actor_name}", camp_id, "conducts", animated=True, color="#a78bfa")

    # IOC nodes (right column)
    for i, ioc in enumerate(top_iocs[:10]):
        ioc_id = f"ioc:{ioc}"
        ioc_actors = ioc_counts.get(ioc, [])
        nodes.append({
            "id": ioc_id,
            "type": "ioc",
            "position": {"x": 750, "y": i * 80 + 40},
            "data": {
                "label": ioc[:35] + ("…" if len(ioc) > 35 else ""),
                "fullIoc": ioc,
                "nodeType": "ioc",
                "usedBy": ioc_actors,
            },
        })
        # Actor → IOC edges
        for actor_name in ioc_actors:
            if any(n["id"] == f"actor:{actor_name}" for n in nodes):
                add_edge(f"actor:{actor_name}", ioc_id, "usa", animated=False, color="#22d3ee")
        # Campaign → IOC edges
        for camp in campaigns:
            if ioc in camp.get("iocs_generated", []):
                camp_id = f"campaign:{camp['id']}"
                if any(n["id"] == camp_id for n in nodes):
                    add_edge(camp_id, ioc_id, "genera", animated=False, color="#4ade80")

    return {
        "nodes": nodes,
        "edges": edges,
        "crossCorrelations": correlations,
        "summary": summary,
        "cisaMatchCount": len(cisa_enrichment),
        "totalActors": len(top_actors),
        "totalIocs": len(top_iocs),
        "totalCampaigns": len(campaigns),
    }


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

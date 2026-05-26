import os
import requests
import anthropic
from fastapi import Body, FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware

from intelligence.threat_engine import get_threat_feed, add_uploaded_iocs
from intelligence.actor_engine import get_threat_actors
from intelligence.campaign_engine import get_campaigns
from ai.ai_engine import analyze_ioc
from services.findings_service import get_findings
from services.upload_service import parse_upload
from services.enrichment_service import enrich_ioc
from intelligence.ioa_engine import get_ioas

app = FastAPI(
    title="CTI-Lab API",
    description="AI Native Cyber Threat Intelligence Platform",
    version="1.0.0"
)

_CORS_ORIGINS = os.environ.get(
    "CORS_ORIGINS",
    "http://localhost:3000,http://localhost:5173,http://127.0.0.1:3000,http://127.0.0.1:5173",
).split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=_CORS_ORIGINS,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def home():
    return {
        "platform": "CTI-Lab",
        "status": "running",
        "version": "1.0.0"
    }


@app.get("/missions")
def missions():
    return [
        {
            "id": 1,
            "title": "Operacion Black Lynx",
            "difficulty": "medium",
            "type": "phishing",
            "status": "active"
        },
        {
            "id": 2,
            "title": "Ransomware Universidad",
            "difficulty": "critical",
            "type": "ransomware",
            "status": "active"
        }
    ]


@app.get("/ioc-feed")
def ioc_feed():
    return get_threat_feed()


@app.get("/threat-actors")
def threat_actors():
    return get_threat_actors()


@app.get("/campaigns")
def campaigns():
    return get_campaigns()


@app.get("/findings")
def findings():
    return get_findings()


@app.post("/upload")
async def upload_export(file: UploadFile = File(...)):
    allowed = {".csv", ".json", ".txt", ".stix"}
    ext = "." + (file.filename or "").rsplit(".", 1)[-1].lower()
    if ext not in allowed:
        raise HTTPException(status_code=400, detail=f"Unsupported file type: {ext}. Allowed: {', '.join(allowed)}")

    raw = await file.read()
    if len(raw) > 5 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File too large. Maximum size is 5 MB.")

    try:
        parsed = parse_upload(file.filename or "", raw)
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Parse error: {str(e)}")

    added = add_uploaded_iocs(parsed)

    return {
        "parsed": len(parsed),
        "added": len(added),
        "skipped": len(parsed) - len(added),
        "iocs": added
    }


@app.get("/ai/analyze/{ioc}")
def ai_analysis(ioc: str):
    return analyze_ioc(ioc)


@app.get("/enrich/{ioc:path}")
def enrich(ioc: str):
    return enrich_ioc(ioc)


@app.get("/ioas")
def ioas():
    return get_ioas()


@app.post("/ai/chat")
def ai_chat(payload: dict = Body(...)):
    prompt = payload.get("message", "")

    iocs = get_threat_feed()
    actors = get_threat_actors()

    ioc_summary = "\n".join(
        f"- {i['ioc']} ({i['type']}, {i['severity']}, actor: {i['threat_actor']}, MITRE: {i['mitre']})"
        for i in iocs
    )
    actor_summary = "\n".join(
        f"- {a['name']} ({a['country']}, motivation: {a['motivation']}, campaign: {a['active_campaign']})"
        for a in actors
    )

    system_context = f"""You are an advanced SOC and CTI analyst with access to the following live threat intelligence:

ACTIVE IOCs:
{ioc_summary}

TRACKED THREAT ACTORS:
{actor_summary}

Use this context when answering. Be concise and technical."""

    anthropic_key = os.environ.get("ANTHROPIC_API_KEY")

    if anthropic_key:
        client = anthropic.Anthropic(api_key=anthropic_key)
        message = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=1024,
            system=[
                {
                    "type": "text",
                    "text": system_context,
                    "cache_control": {"type": "ephemeral"},
                }
            ],
            messages=[{"role": "user", "content": prompt}],
        )
        return {"response": message.content[0].text}

    # Fallback to Ollama when no Anthropic key is configured
    ollama_url = os.environ.get("OLLAMA_URL", "http://localhost:11434")
    response = requests.post(
        f"{ollama_url}/api/generate",
        json={
            "model": "llama3",
            "prompt": f"{system_context}\n\nUser query: {prompt}\n\nProvide a technical cybersecurity response.",
            "stream": False,
        },
        timeout=60,
    )
    data = response.json()
    return {"response": data["response"]}

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def home():

    return {
        "message": "CTI-Lab Running"
    }

@app.get("/missions")
def missions():

    return [
        {
            "id": 1,
            "title": "Operacion Black Lynx",
            "difficulty": "medium"
        }
    ]

@app.get("/ioc-feed")
def ioc_feed():

    return [
        {
            "ioc": "185.220.101.1",
            "severity": "high"
        }
    ]

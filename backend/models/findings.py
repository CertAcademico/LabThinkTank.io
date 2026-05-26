from pydantic import BaseModel

class Finding(BaseModel):
    severity: str
    title: str
    description: str
    mitre: str

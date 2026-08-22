from pydantic import BaseModel


class ScanRequest(BaseModel):
    url: str


class ScanResponse(BaseModel):
    url: str
    prediction: int | None = None
    phishing_probability: float | None = None
    risk_level: str | None = None

    flags: list = []
    urgency_terms: list = []

    brand_similarity: dict | None = None

    title: str | None = None
    has_password_field: bool | None = None

    error: str | None = None
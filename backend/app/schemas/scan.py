from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    url: str


class ScanResponse(BaseModel):

    url: str

    # ----------------------------------------
    # ML prediction
    # ----------------------------------------

    prediction: int | None = None

    # Raw probability produced by XGBoost.
    # This represents the ML model's own output.
    ml_probability: float | None = None

    # ----------------------------------------
    # Final security assessment
    # ----------------------------------------

    # Final probability after combining:
    # ML + URL intelligence + NLP + webpage signals
    phishing_probability: float | None = None

    # Overall 0-100 threat score
    threat_score: float | None = None

    # LOW / MEDIUM / HIGH
    risk_level: str | None = None

    # ----------------------------------------
    # Scan status
    # ----------------------------------------

    webpage_available: bool = False

    scan_mode: str = "FULL"

    # ----------------------------------------
    # Intelligence
    # ----------------------------------------

    flags: list[str] = Field(
        default_factory=list
    )

    urgency_terms: list[str] = Field(
        default_factory=list
    )

    url_intelligence_score: float | None = None

    url_intelligence_indicators: list[str] = Field(
        default_factory=list
    )

    suspicious_keywords: list[str] = Field(
        default_factory=list
    )

    intelligence_explanation: str | None = None

    brand_similarity: dict | None = None

    # ----------------------------------------
    # Webpage information
    # ----------------------------------------

    title: str | None = None

    has_password_field: bool | None = None

    # ----------------------------------------
    # Errors
    # ----------------------------------------

    error: str | None = None
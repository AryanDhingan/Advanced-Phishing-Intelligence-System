from fastapi import FastAPI

from app.api.scan import router as scan_router


app = FastAPI(
    title="Advanced Phishing Intelligence System",
    description="AI-powered phishing URL detection system",
    version="1.0.0",
)


app.include_router(
    scan_router
)


@app.get("/")
def root():

    return {
        "message": "Advanced Phishing Intelligence System API",
        "status": "online",
    }
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.scan import router as scan_router


app = FastAPI(
    title="Advanced Phishing Intelligence System",
    description="AI-powered phishing URL detection system",
    version="1.0.0",
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
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
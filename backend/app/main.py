from fastapi import FastAPI

app = FastAPI(
    title="Advanced Phishing Intelligence System",
    version="1.0.0"
)


@app.get("/")
def home():

    return {
        "message": "Backend initialized successfully."
    }
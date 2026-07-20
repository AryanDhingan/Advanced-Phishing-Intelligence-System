from dotenv import load_dotenv
import os

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
SECRET_KEY = os.getenv("SECRET_KEY")
ACCESS_TOKEN_EXPIRE_MINUTES = int(
    os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 60)
)

# ==========================
# Dataset Configuration
# ==========================

DATASET_PATH = os.getenv("DATASET_PATH")

PHISHING_LIMIT = int(os.getenv("PHISHING_LIMIT", 75000))

LEGITIMATE_LIMIT = int(os.getenv("LEGITIMATE_LIMIT", 75000))
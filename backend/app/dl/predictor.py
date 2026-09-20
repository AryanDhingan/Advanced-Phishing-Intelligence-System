"""
Deep Learning prediction service.

Loads the trained PyTorch MLP and scaler, then performs
phishing predictions using the same 49 features used
during Deep Learning training.
"""

from pathlib import Path

import joblib
import torch

from app.dl.train_model import PhishingMLP


# --------------------------------------------------
# Configuration
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parents[2]

MODEL_PATH = BASE_DIR / "data" / "models" / "dl_model.pth"
SCALER_PATH = BASE_DIR / "data" / "models" / "dl_scaler.pkl"


DEVICE = torch.device(
    "cuda" if torch.cuda.is_available() else "cpu"
)


# --------------------------------------------------
# Load model
# --------------------------------------------------

def load_model():
    """
    Load the trained Deep Learning model.
    """

    if not MODEL_PATH.exists():
        raise FileNotFoundError(
            f"Deep Learning model not found: {MODEL_PATH}"
        )

    checkpoint = torch.load(
        MODEL_PATH,
        map_location=DEVICE
    )

    input_size = checkpoint["input_size"]

    model = PhishingMLP(
        input_size=input_size
    ).to(DEVICE)

    model.load_state_dict(
        checkpoint["model_state_dict"]
    )

    model.eval()

    return model, checkpoint["feature_columns"]


# --------------------------------------------------
# Load scaler
# --------------------------------------------------

def load_scaler():
    """
    Load the StandardScaler used during training.
    """

    if not SCALER_PATH.exists():
        raise FileNotFoundError(
            f"Deep Learning scaler not found: {SCALER_PATH}"
        )

    return joblib.load(SCALER_PATH)


# --------------------------------------------------
# Prediction
# --------------------------------------------------

def predict(merged_features: dict) -> dict:
    model, feature_columns = load_model()
    scaler = load_scaler()

    # Use only the exact features used during DL training.
    missing = [
        feature
        for feature in feature_columns
        if feature not in merged_features
    ]

    if missing:
        raise ValueError(
            f"Missing Deep Learning features: {missing}"
        )

    feature_values = [
        merged_features[feature]
        for feature in feature_columns
    ]

    numeric_values = [
        float(value) if value is not None else 0.0
        for value in feature_values
    ]

    import pandas as pd

    input_df = pd.DataFrame(
        [numeric_values],
        columns=feature_columns,
    )

    scaled_values = scaler.transform(input_df)

    model_input = torch.tensor(
        scaled_values,
        dtype=torch.float32,
    ).to(DEVICE)

    with torch.no_grad():
        logits = model(model_input)
        probability = torch.sigmoid(logits).item()

    prediction = int(probability >= 0.50)

    if probability >= 0.80:
        risk_level = "HIGH"
    elif probability >= 0.50:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "prediction": prediction,
        "phishing_probability": float(probability),
        "risk_level": risk_level,
    }
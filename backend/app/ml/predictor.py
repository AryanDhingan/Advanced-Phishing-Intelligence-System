"""
ML prediction service.

Loads the trained phishing detection model and performs
predictions using the exact feature order from training.
"""

import pickle
import os

from app.ml.model_input import prepare_model_input


MODEL_PATH = "data/models/model.pkl"


def load_model():
    """
    Load the trained phishing detection model.
    """

    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(
            f"Model not found: {MODEL_PATH}"
        )

    with open(
        MODEL_PATH,
        "rb",
    ) as file:

        return pickle.load(file)


def predict(
    merged_features: dict,
) -> dict:
    """
    Predict whether a URL is phishing.

    Returns:
        prediction
        probability
        risk_level
    """

    model = load_model()

    model_input = prepare_model_input(
        merged_features
    )

    # Most sklearn-compatible models expect
    # a 2D input: [[feature1, feature2, ...]]
    prediction = model.predict(
        [model_input]
    )[0]

    probability = None

    if hasattr(
        model,
        "predict_proba",
    ):

        probabilities = model.predict_proba(
            [model_input]
        )[0]

        # Assuming class 1 represents phishing
        probability = float(
            probabilities[1]
        )

    if probability is None:

        probability = float(
            prediction
        )

    if probability >= 0.80:

        risk_level = "HIGH"

    elif probability >= 0.50:

        risk_level = "MEDIUM"

    else:

        risk_level = "LOW"

    return {
        "prediction": int(prediction),
        "phishing_probability": probability,
        "risk_level": risk_level,
    }
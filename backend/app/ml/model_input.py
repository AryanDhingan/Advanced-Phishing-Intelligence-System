"""
Prepare merged features for ML model inference.
"""

import pickle


MODEL_FEATURE_PATH = (
    "data/models/feature_columns.pkl"
)


def load_model_features():
    """
    Load the exact feature order used during model training.
    """

    with open(
        MODEL_FEATURE_PATH,
        "rb",
    ) as file:

        return pickle.load(file)


def prepare_model_input(
    merged_features: dict,
) -> list:
    """
    Convert merged application features into the exact
    ordered feature list expected by the trained model.
    """

    model_features = load_model_features()

    missing = [
        feature
        for feature in model_features
        if feature not in merged_features
    ]

    if missing:
        raise ValueError(
            f"Missing model features: {missing}"
        )

    return [
        merged_features[feature]
        for feature in model_features
    ]
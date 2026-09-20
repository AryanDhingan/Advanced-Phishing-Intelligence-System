from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import torch
import torch.nn as nn

from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from app.db.database import SessionLocal
from app.db.models import Feature, URL


# --------------------------------------------------
# Configuration
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parents[2]

MODEL_DIR = BASE_DIR / "data" / "models"

MODEL_PATH = MODEL_DIR / "dl_model.pth"
SCALER_PATH = MODEL_DIR / "dl_scaler.pkl"


TEST_SIZE = 0.20
RANDOM_STATE = 42

EPOCHS = 30
BATCH_SIZE = 256
LEARNING_RATE = 0.001


DEVICE = torch.device(
    "cuda" if torch.cuda.is_available() else "cpu"
)


# --------------------------------------------------
# Feature selection
# --------------------------------------------------

FEATURE_COLUMNS = [
    "url_length",
    "domain_length",
    "is_domain_ip",
    "tld_length",
    "tld_legitimate_prob",
    "url_similarity_index",
    "char_continuation_rate",
    "no_of_subdomain",
    "has_obfuscation",
    "no_of_obfuscated_char",
    "obfuscation_ratio",
    "no_of_letters_in_url",
    "letter_ratio_in_url",
    "no_of_digits_in_url",
    "digit_ratio_in_url",
    "no_of_equals_in_url",
    "no_of_qmark_in_url",
    "no_of_ampersand_in_url",
    "no_of_other_special_chars",
    "special_char_ratio",
    "is_https",
    "line_of_code",
    "largest_line_length",
    "has_title",
    "domain_title_match_score",
    "url_title_match_score",
    "has_favicon",
    "robots",
    "is_responsive",
    "no_of_url_redirect",
    "no_of_self_redirect",
    "has_description",
    "no_of_popup",
    "no_of_iframe",
    "has_external_form_submit",
    "has_social_net",
    "has_submit_button",
    "has_hidden_fields",
    "has_password_field",
    "bank",
    "pay",
    "crypto",
    "has_copyright_info",
    "no_of_image",
    "no_of_css",
    "no_of_js",
    "no_of_self_ref",
    "no_of_empty_ref",
    "no_of_external_ref",
]


# --------------------------------------------------
# Load data
# --------------------------------------------------

def load_training_data():
    """
    Load URL labels and their associated features
    from SQLite.
    """

    session = SessionLocal()

    try:

        rows = (
            session.query(URL, Feature)
            .join(Feature, URL.id == Feature.url_id)
            .all()
        )

    finally:

        session.close()

    if not rows:
        raise RuntimeError(
            "No training data found in the database."
        )

    records = []

    for url, feature in rows:

        record = {
            column: getattr(feature, column)
            for column in FEATURE_COLUMNS
        }

        record["label"] = int(bool(url.label))

        records.append(record)

    df = pd.DataFrame(records)

    return df


# --------------------------------------------------
# Prepare data
# --------------------------------------------------

def prepare_data(df: pd.DataFrame):

    X = df[FEATURE_COLUMNS].copy()
    y = df["label"].copy()

    # Convert boolean columns to numeric.
    boolean_columns = X.select_dtypes(
        include=["bool"]
    ).columns

    for column in boolean_columns:
        X[column] = X[column].astype(int)

    # Convert everything to numeric.
    X = X.apply(
        pd.to_numeric,
        errors="coerce"
    )

    # Replace missing values with zero.
    X = X.fillna(0)

    return X, y


# --------------------------------------------------
# Deep Learning model
# --------------------------------------------------

class PhishingMLP(nn.Module):
    """
    Feed-forward neural network for phishing
    classification.
    """

    def __init__(self, input_size):

        super().__init__()

        self.network = nn.Sequential(

            nn.Linear(input_size, 128),
            nn.ReLU(),
            nn.Dropout(0.30),

            nn.Linear(128, 64),
            nn.ReLU(),
            nn.Dropout(0.20),

            nn.Linear(64, 1)
        )

    def forward(self, x):

        return self.network(x)


# --------------------------------------------------
# Training
# --------------------------------------------------

def train_model(
    model,
    X_train,
    y_train
):

    criterion = nn.BCEWithLogitsLoss()

    optimizer = torch.optim.Adam(
        model.parameters(),
        lr=LEARNING_RATE
    )

    X_tensor = torch.tensor(
        X_train,
        dtype=torch.float32
    ).to(DEVICE)

    y_tensor = torch.tensor(
        y_train,
        dtype=torch.float32
    ).reshape(-1, 1).to(DEVICE)

    dataset = torch.utils.data.TensorDataset(
        X_tensor,
        y_tensor
    )

    loader = torch.utils.data.DataLoader(
        dataset,
        batch_size=BATCH_SIZE,
        shuffle=True
    )

    model.train()

    for epoch in range(EPOCHS):

        epoch_loss = 0.0

        for batch_X, batch_y in loader:

            optimizer.zero_grad()

            outputs = model(batch_X)

            loss = criterion(
                outputs,
                batch_y
            )

            loss.backward()

            optimizer.step()

            epoch_loss += loss.item()

        average_loss = (
            epoch_loss / len(loader)
        )

        print(
            f"Epoch {epoch + 1:02d}/{EPOCHS} "
            f"- Loss: {average_loss:.4f}"
        )

    return model


# --------------------------------------------------
# Evaluation
# --------------------------------------------------

def evaluate_model(
    model,
    X_test,
    y_test
):

    model.eval()

    X_tensor = torch.tensor(
        X_test,
        dtype=torch.float32
    ).to(DEVICE)

    with torch.no_grad():

        logits = model(X_tensor)

        probabilities = torch.sigmoid(
            logits
        )

        predictions = (
            probabilities >= 0.50
        ).int()

    predictions = (
        predictions
        .cpu()
        .numpy()
        .flatten()
    )

    probabilities = (
        probabilities
        .cpu()
        .numpy()
        .flatten()
    )

    accuracy = accuracy_score(
        y_test,
        predictions
    )

    precision = precision_score(
        y_test,
        predictions,
        zero_division=0
    )

    recall = recall_score(
        y_test,
        predictions,
        zero_division=0
    )

    f1 = f1_score(
        y_test,
        predictions,
        zero_division=0
    )

    matrix = confusion_matrix(
        y_test,
        predictions
    )

    print()
    print("=" * 60)
    print("DEEP LEARNING MODEL EVALUATION")
    print("=" * 60)

    print(
        f"Accuracy : {accuracy:.4f}"
    )

    print(
        f"Precision: {precision:.4f}"
    )

    print(
        f"Recall   : {recall:.4f}"
    )

    print(
        f"F1 Score : {f1:.4f}"
    )

    print()
    print("Classification Report:")
    print()

    print(
        classification_report(
            y_test,
            predictions,
            target_names=[
                "Legitimate",
                "Phishing"
            ],
            zero_division=0
        )
    )

    print("Confusion Matrix:")
    print(matrix)

    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "probabilities": probabilities,
    }


# --------------------------------------------------
# Main
# --------------------------------------------------

def main():

    print("=" * 60)
    print("ADVANCED PHISHING INTELLIGENCE SYSTEM")
    print("DEEP LEARNING - MLP TRAINING")
    print("=" * 60)

    print()
    print(f"Device: {DEVICE}")

    MODEL_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    print()
    print("Loading training data from SQLite...")

    df = load_training_data()

    print(
        f"Records loaded: {len(df)}"
    )

    print(
        f"Features used : {len(FEATURE_COLUMNS)}"
    )

    print()
    print("Class distribution:")

    print(
        df["label"]
        .value_counts()
        .sort_index()
        .rename(
            index={
                0: "Legitimate",
                1: "Phishing"
            }
        )
    )

    X, y = prepare_data(df)

    print()
    print("Splitting dataset...")

    X_train, X_test, y_train, y_test = (
        train_test_split(
            X,
            y,
            test_size=TEST_SIZE,
            random_state=RANDOM_STATE,
            stratify=y
        )
    )

    print(
        f"Training records: {len(X_train)}"
    )

    print(
        f"Testing records : {len(X_test)}"
    )

    # --------------------------------------------------
    # Feature scaling
    # --------------------------------------------------

    print()
    print("Scaling features...")

    scaler = StandardScaler()

    X_train_scaled = scaler.fit_transform(
        X_train
    )

    X_test_scaled = scaler.transform(
        X_test
    )

    # --------------------------------------------------
    # Create model
    # --------------------------------------------------

    print()
    print("Creating MLP model...")

    model = PhishingMLP(
        input_size=len(FEATURE_COLUMNS)
    ).to(DEVICE)

    print(model)

    # --------------------------------------------------
    # Train
    # --------------------------------------------------

    print()
    print("Training MLP...")

    model = train_model(
        model,
        X_train_scaled,
        y_train.to_numpy()
    )

    print()
    print("Training completed.")

    # --------------------------------------------------
    # Evaluate
    # --------------------------------------------------

    evaluate_model(
        model,
        X_test_scaled,
        y_test.to_numpy()
    )

    # --------------------------------------------------
    # Save model and scaler
    # --------------------------------------------------

    torch.save(
        {
            "model_state_dict": model.state_dict(),
            "input_size": len(FEATURE_COLUMNS),
            "feature_columns": FEATURE_COLUMNS,
        },
        MODEL_PATH
    )

    joblib.dump(
        scaler,
        SCALER_PATH
    )

    print()
    print("=" * 60)
    print("DEEP LEARNING MODEL SAVED")
    print("=" * 60)

    print(
        f"Model  : {MODEL_PATH}"
    )

    print(
        f"Scaler : {SCALER_PATH}"
    )

    print()
    print("Deep learning training pipeline completed.")


if __name__ == "__main__":
    main()
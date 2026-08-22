from pathlib import Path

import joblib
import matplotlib.pyplot as plt
import pandas as pd

from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    ConfusionMatrixDisplay,
    precision_score,
    recall_score,
    f1_score,
)
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier

from app.db.database import SessionLocal
from app.db.models import Feature, URL


# --------------------------------------------------
# Configuration
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parents[2]

MODEL_DIR = BASE_DIR / "data" / "models"
MODEL_PATH = MODEL_DIR / "model.pkl"
FEATURE_COLUMNS_PATH = MODEL_DIR / "feature_columns.pkl"
CONFUSION_MATRIX_PATH = MODEL_DIR / "confusion_matrix.png"


TEST_SIZE = 0.20
RANDOM_STATE = 42


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
    """
    Prepare feature matrix and target vector.
    """

    X = df[FEATURE_COLUMNS].copy()
    y = df["label"].copy()

    # Convert boolean columns to numeric values.
    boolean_columns = X.select_dtypes(
        include=["bool"]
    ).columns

    for column in boolean_columns:
        X[column] = X[column].astype(int)

    # Convert everything to numeric.
    X = X.apply(pd.to_numeric, errors="coerce")

    # Replace missing values with zero.
    X = X.fillna(0)

    return X, y


# --------------------------------------------------
# Train model
# --------------------------------------------------

def train_model(X_train, y_train):
    """
    Train the single XGBoost classifier used
    by the project.
    """

    model = XGBClassifier(
        n_estimators=200,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        objective="binary:logistic",
        eval_metric="logloss",
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )

    model.fit(X_train, y_train)

    return model


# --------------------------------------------------
# Evaluate model
# --------------------------------------------------

def evaluate_model(model, X_test, y_test):
    """
    Calculate classification metrics and save
    a confusion matrix.
    """

    predictions = model.predict(X_test)

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

    print()
    print("=" * 60)
    print("MODEL EVALUATION")
    print("=" * 60)

    print(f"Accuracy : {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall   : {recall:.4f}")
    print(f"F1 Score : {f1:.4f}")

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

    matrix = confusion_matrix(
        y_test,
        predictions
    )

    print("Confusion Matrix:")
    print(matrix)

    # Save confusion matrix image.
    display = ConfusionMatrixDisplay(
        confusion_matrix=matrix,
        display_labels=[
            "Legitimate",
            "Phishing"
        ]
    )

    display.plot()

    plt.title("Phishing URL Classifier - Confusion Matrix")
    plt.tight_layout()
    plt.savefig(CONFUSION_MATRIX_PATH)
    plt.close()

    print()
    print(
        f"Confusion matrix saved to: "
        f"{CONFUSION_MATRIX_PATH}"
    )

    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


# --------------------------------------------------
# Main
# --------------------------------------------------

def main():

    print("=" * 60)
    print("ADVANCED PHISHING INTELLIGENCE SYSTEM")
    print("XGBOOST MODEL TRAINING")
    print("=" * 60)

    MODEL_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    print()
    print("Loading training data from SQLite...")

    df = load_training_data()

    print(f"Records loaded: {len(df)}")
    print(f"Features used : {len(FEATURE_COLUMNS)}")

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

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=y,
    )

    print(f"Training records: {len(X_train)}")
    print(f"Testing records : {len(X_test)}")

    print()
    print("Training XGBoost model...")

    model = train_model(
        X_train,
        y_train
    )

    print("Training completed.")

    metrics = evaluate_model(
        model,
        X_test,
        y_test
    )

    # Save model.
    joblib.dump(
        model,
        MODEL_PATH
    )

    # Save exact feature ordering.
    joblib.dump(
        FEATURE_COLUMNS,
        FEATURE_COLUMNS_PATH
    )

    print()
    print("=" * 60)
    print("MODEL SAVED")
    print("=" * 60)

    print(f"Model           : {MODEL_PATH}")
    print(f"Feature columns : {FEATURE_COLUMNS_PATH}")

    print()
    print("Final Metrics:")

    for name, value in metrics.items():
        print(f"{name.capitalize():10}: {value:.4f}")

    print()
    print("Training pipeline completed successfully.")


if __name__ == "__main__":
    main()
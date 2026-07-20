from pathlib import Path

import pandas as pd

from app.core.config import DATASET_PATH


REQUIRED_COLUMNS = {
    "URL",
    "Domain",
    "label"
}


def validate_dataset() -> pd.DataFrame:
    """
    Validate the PhiUSIIL dataset before ingestion.
    """

    dataset = Path(DATASET_PATH)

    if not dataset.exists():
        raise FileNotFoundError(
            f"Dataset not found:\n{dataset.resolve()}"
        )

    print(f"Loading dataset:\n{dataset}")

    df = pd.read_csv(dataset)

    print(f"Rows loaded: {len(df):,}")

    missing = REQUIRED_COLUMNS - set(df.columns)

    if missing:
        raise ValueError(
            f"Dataset is missing required columns:\n{sorted(missing)}"
        )

    if df.empty:
        raise ValueError("Dataset is empty.")

    print("Dataset validation successful.\n")

    return df
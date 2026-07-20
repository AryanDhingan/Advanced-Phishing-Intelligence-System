from pathlib import Path

import pandas as pd

from app.core.config import (
    LEGITIMATE_LIMIT,
    PHISHING_LIMIT,
)

from app.utils.url_utils import (
    normalize_url,
    is_valid_url,
)


def clean_dataset(df: pd.DataFrame) -> pd.DataFrame:
    """
    Clean and prepare the PhiUSIIL dataset for ingestion.
    """

    print("Cleaning dataset...\n")

    # -------------------------
    # Select required records
    # -------------------------

    phishing_df = (
    df[df["label"] == 1]
    .sample(n=PHISHING_LIMIT, random_state=42)
    .copy()
)

    legitimate_df = (
    df[df["label"] == 0]
    .sample(n=LEGITIMATE_LIMIT, random_state=42)
    .copy()
)

    df = pd.concat(
        [phishing_df, legitimate_df],
        ignore_index=True
    )

    print(f"Selected rows: {len(df):,}")

    # -------------------------
    # Normalize URLs
    # -------------------------

    df["normalized_url"] = (
        df["URL"]
        .astype(str)
        .apply(normalize_url)
    )

    # -------------------------
    # Remove invalid URLs
    # -------------------------

    before = len(df)

    df = df[
        df["normalized_url"].apply(is_valid_url)
    ].copy()

    invalid_removed = before - len(df)

    # -------------------------
    # Remove duplicate URLs
    # -------------------------

    before = len(df)

    df = df.drop_duplicates(
        subset="normalized_url"
    )

    duplicates_removed = before - len(df)

    # -------------------------
    # Rename columns
    # -------------------------

    df = df.rename(
        columns={
            "URL": "url",
            "Domain": "domain"
        }
    )

    # -------------------------
    # Save cleaned dataset
    # -------------------------

    output_dir = Path("data/processed")
    output_dir.mkdir(
        parents=True,
        exist_ok=True
    )

    output_path = output_dir / "urls_clean.csv"

    df.to_csv(
        output_path,
        index=False
    )

    # -------------------------
    # Summary
    # -------------------------

    print("Cleaning completed.\n")

    print(f"Rows remaining      : {len(df):,}")
    print(f"Duplicates removed : {duplicates_removed:,}")
    print(f"Invalid URLs removed: {invalid_removed:,}")

    print(f"\nSaved cleaned dataset:\n{output_path}\n")

    return df
import pandas as pd

from app.services.ingestor import ingest_dataframe


def main():

    df = pd.read_csv(
        "data/processed/urls_clean.csv"
    )

    # Use only 5 records for the first test.
    test_df = df.head(5)

    print(f"Testing ingestion with {len(test_df)} records...")

    ingest_dataframe(test_df)

    print("Ingestion test completed successfully.")


if __name__ == "__main__":
    main()
from pathlib import Path

from app.services.ingestor import ingest_csv


BASE_DIR = Path(__file__).resolve().parent.parent

DATASET_PATH = BASE_DIR / "data" / "processed" / "urls_clean.csv"


def main():
    """
    Start the dataset ingestion process.
    """

    if not DATASET_PATH.exists():
        raise FileNotFoundError(
            f"Cleaned dataset not found: {DATASET_PATH}"
        )

    ingest_csv(str(DATASET_PATH))


if __name__ == "__main__":
    main()
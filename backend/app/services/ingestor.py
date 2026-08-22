import math
import time

import pandas as pd

from app.core.column_mapping import COLUMN_MAPPING
from app.db.database import SessionLocal
from app.db.models import URL, Feature
from app.services.bulk_insert import save_batch


BATCH_SIZE = 5000


def create_url_object(row) -> URL:
    """
    Create a URL database object from a cleaned dataset row.
    """

    return URL(
        url=row.url,
        normalized_url=row.url,
        domain=row.domain,
        label=bool(row.label),
        source="PhiUSIIL Dataset"
    )


def create_feature_object(row) -> Feature:
    """
    Create a Feature database object from a dataset row.

    COLUMN_MAPPING maps CSV column names to SQLAlchemy
    Feature model field names.
    """

    feature_data = {}

    for csv_column, model_field in COLUMN_MAPPING.items():

        value = getattr(row, csv_column)

        if pd.isna(value):
            value = None

        feature_data[model_field] = value

    return Feature(**feature_data)


def ingest_dataframe(df: pd.DataFrame) -> None:
    """
    Ingest a cleaned DataFrame into the SQLite database
    in batches.
    """

    total_rows = len(df)

    if total_rows == 0:
        print("No records found. Nothing to ingest.")
        return

    total_batches = math.ceil(total_rows / BATCH_SIZE)

    print()
    print("=" * 50)
    print("STARTING DATABASE INGESTION")
    print("=" * 50)
    print(f"Total records : {total_rows}")
    print(f"Batch size    : {BATCH_SIZE}")
    print(f"Total batches : {total_batches}")
    print("=" * 50)
    print()

    session = SessionLocal()

    start_time = time.time()

    url_objects = []

    records_processed = 0
    batch_number = 0

    try:

        for row in df.itertuples(index=False):

            url = create_url_object(row)

            feature = create_feature_object(row)

            # Establish the SQLAlchemy relationship.
            # The URL relationship has cascade enabled,
            # so the Feature will be persisted automatically.
            url.features = feature
            feature.url = url

            url_objects.append(url)

            records_processed += 1

            if len(url_objects) == BATCH_SIZE:

                batch_number += 1

                try:

                    save_batch(
                        session=session,
                        url_objects=url_objects
                    )

                except Exception as exc:

                    print()
                    print("=" * 50)
                    print(f"ERROR IN BATCH {batch_number}/{total_batches}")
                    print("=" * 50)
                    print(f"Records processed before failure: {records_processed}")
                    print(f"Error: {exc}")
                    print("=" * 50)

                    raise

                print(
                    f"Batch {batch_number}/{total_batches} "
                    f"inserted successfully "
                    f"({records_processed}/{total_rows})"
                )

                url_objects.clear()

        # Insert the final incomplete batch.
        if url_objects:

            batch_number += 1

            try:

                save_batch(
                    session=session,
                    url_objects=url_objects
                )

            except Exception as exc:

                print()
                print("=" * 50)
                print(f"ERROR IN FINAL BATCH {batch_number}/{total_batches}")
                print("=" * 50)
                print(f"Records processed before failure: {records_processed}")
                print(f"Error: {exc}")
                print("=" * 50)

                raise

            print(
                f"Batch {batch_number}/{total_batches} "
                f"inserted successfully "
                f"({records_processed}/{total_rows})"
            )

        elapsed_time = time.time() - start_time

        print()
        print("=" * 50)
        print("DATABASE INGESTION COMPLETED")
        print("=" * 50)
        print(f"Records inserted : {records_processed}")
        print(f"Batches inserted : {batch_number}")
        print(f"Time taken       : {elapsed_time:.2f} seconds")
        print("=" * 50)

    finally:

        session.close()


def ingest_csv(csv_path: str) -> None:
    """
    Load a cleaned CSV file and ingest it into the database.
    """

    print(f"Loading cleaned dataset: {csv_path}")

    df = pd.read_csv(csv_path)

    print(f"Loaded {len(df)} records.")

    ingest_dataframe(df)
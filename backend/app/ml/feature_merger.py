"""
Combines URL features and webpage features into the exact
51-feature structure expected by the trained model.
"""

from app.core.column_mapping import COLUMN_MAPPING


def merge_features(
    url_features: dict,
    webpage_features: dict,
) -> dict:
    """
    Merge URL and webpage features.

    Returns exactly the application feature names defined
    by COLUMN_MAPPING.
    """

    merged = {}

    # Start with URL features
    merged.update(url_features)

    # Add webpage features
    merged.update(webpage_features)

    # Remove internal helper fields
    merged = {
        key: value
        for key, value in merged.items()
        if not key.startswith("_")
    }

    # Expected application feature names
    expected_features = set(
        COLUMN_MAPPING.values()
    )

    # Check for missing features
    missing = (
        expected_features
        - set(merged.keys())
    )

    if missing:
        raise ValueError(
            f"Missing features: {sorted(missing)}"
        )

    # Check for unexpected features
    unexpected = (
        set(merged.keys())
        - expected_features
    )

    if unexpected:
        for feature in unexpected:
            merged.pop(feature)

    # Force exact feature order
    ordered_features = {
        feature: merged[feature]
        for feature in COLUMN_MAPPING.values()
    }

    return ordered_features
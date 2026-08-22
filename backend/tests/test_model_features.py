import pickle

from app.nlp.scraper import scrape_url

from app.ml.feature_extractor import (
    extract_url_features,
)

from app.ml.webpage_features import (
    extract_webpage_features,
)

from app.ml.feature_merger import (
    merge_features,
)


MODEL_FEATURE_PATH = (
    "data/models/feature_columns.pkl"
)


url = "https://www.google.com"

print("========================================")
print("MODEL FEATURE COMPATIBILITY TEST")
print("========================================")

# Load trained model feature columns
with open(
    MODEL_FEATURE_PATH,
    "rb",
) as file:

    model_features = pickle.load(file)


print(
    "Model expects:",
    len(model_features),
    "features",
)

# Scrape URL
scraped = scrape_url(url)

if scraped["error"]:
    raise RuntimeError(
        scraped["error"]
    )

# Extract features
url_features = extract_url_features(
    scraped["url"]
)

webpage_features = extract_webpage_features(
    scraped["url"],
    scraped["html"],
)

merged_features = merge_features(
    url_features,
    webpage_features,
)

# Compare names
model_set = set(model_features)

merged_set = set(
    merged_features.keys()
)

missing = model_set - merged_set
extra = merged_set - model_set

print("Missing:", sorted(missing))
print("Extra:", sorted(extra))

# Compare order after selecting model features
ordered_live_features = [
    feature
    for feature in merged_features
    if feature in model_set
]

order_matches = (
    ordered_live_features
    == model_features
)

print(
    "Order matches:",
    order_matches,
)

print("========================================")

if missing:
    raise AssertionError(
        f"Missing model features: {missing}"
    )

if extra:
    print(
        "Extra application features:",
        sorted(extra),
    )

if not order_matches:
    raise AssertionError(
        "Feature order does not match model."
    )

print(
    "MODEL FEATURE COMPATIBILITY PASSED."
)
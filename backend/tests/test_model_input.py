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

from app.ml.model_input import (
    load_model_features,
    prepare_model_input,
)


url = "https://www.google.com"

print("========================================")
print("MODEL INPUT TEST")
print("========================================")

scraped = scrape_url(url)

if scraped["error"]:
    raise RuntimeError(
        scraped["error"]
    )

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

model_input = prepare_model_input(
    merged_features
)

expected_features = load_model_features()

print(
    "Expected features:",
    len(expected_features)
)

print(
    "Model input values:",
    len(model_input)
)

print(
    "First 5 values:",
    model_input[:5]
)

print("========================================")

if len(model_input) != len(expected_features):
    raise AssertionError(
        "Model input length mismatch."
    )

print(
    "MODEL INPUT TEST PASSED."
)
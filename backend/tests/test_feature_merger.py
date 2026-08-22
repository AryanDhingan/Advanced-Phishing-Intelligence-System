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


url = "https://www.google.com"

print("========================================")
print("FEATURE MERGER TEST")
print("========================================")

scraped = scrape_url(url)

if scraped["error"]:
    print("Scraping failed:")
    print(scraped["error"])
    raise SystemExit(1)

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

print("URL features:", len(url_features))
print("Webpage features:", len(webpage_features))
print("Merged features:", len(merged_features))

print("========================================")
print("FIRST 10 FEATURES")
print("========================================")

for index, (key, value) in enumerate(
    merged_features.items()
):

    if index >= 10:
        break

    print(f"{key}: {value}")

print("========================================")

print(
    "Feature merger test PASSED."
)
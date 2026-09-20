from app.nlp.scraper import scrape_url

from app.ml.feature_extractor import extract_url_features
from app.ml.webpage_features import extract_webpage_features
from app.ml.webpage_defaults import get_default_webpage_features
from app.ml.feature_merger import merge_features

from app.dl.predictor import load_model


URL = "https://paypa1.com/login"


print("=" * 60)
print("LIVE FEATURE INSPECTION")
print("=" * 60)

scraped = scrape_url(URL)

print(f"\nURL: {URL}")
print(f"Scrape error: {scraped.get('error')}")

url_features = extract_url_features(
    scraped["url"]
)

if scraped.get("error"):
    webpage_features = get_default_webpage_features()
else:
    webpage_features = extract_webpage_features(
        scraped["url"],
        scraped["html"],
    )

merged_features = merge_features(
    url_features,
    webpage_features,
)

_, feature_columns = load_model()

print(f"\nMerged features: {len(merged_features)}")
print(f"DL features: {len(feature_columns)}")

print("\n" + "=" * 60)
print("FEATURE VALUES")
print("=" * 60)

for feature in feature_columns:
    print(
        f"{feature:30} : "
        f"{merged_features.get(feature)}"
    )
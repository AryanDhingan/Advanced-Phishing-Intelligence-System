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

from app.ml.predictor import predict


url = "https://paypa1.com/login"

print("========================================")
print("ML PREDICTION TEST")
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

result = predict(
    merged_features
)

print("URL:", url)

print(
    "Prediction:",
    result["prediction"]
)

print(
    "Phishing probability:",
    result["phishing_probability"]
)

print(
    "Risk level:",
    result["risk_level"]
)

print("========================================")
print("ML PREDICTION TEST PASSED.")
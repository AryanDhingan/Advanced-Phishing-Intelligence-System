from app.ml.feature_extractor import extract_url_features
from app.ml.webpage_defaults import get_default_webpage_features
from app.ml.feature_merger import merge_features
from app.ml.predictor import predict


url = "https://paypa1.com/login"

print("========================================")
print("ML PREDICTION TEST")
print("========================================")


# Use URL features directly.
# No external webpage request is required.
url_features = extract_url_features(url)


# Use default webpage features because the predictor
# should be testable even when a webpage is unavailable.
webpage_features = get_default_webpage_features()


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
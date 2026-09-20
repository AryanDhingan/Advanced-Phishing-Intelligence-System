from app.utils.url_utils import is_valid_url

from app.nlp.scraper import scrape_url

from app.ml.feature_extractor import extract_url_features
from app.ml.webpage_features import extract_webpage_features
from app.ml.webpage_defaults import get_default_webpage_features
from app.ml.feature_merger import merge_features
from app.ml.predictor import predict as xgb_predict

from app.dl.predictor import predict as dl_predict


TEST_URLS = [
    "https://example.com",
    "https://google.com",
    "https://github.com/login",
    "https://paypa1.com/login",
    "https://secure-paypal-verification.com/account/login",
]


def prepare_features(url: str):

    if not is_valid_url(url):
        raise ValueError("Invalid URL")

    scraped = scrape_url(url)

    webpage_available = not bool(
        scraped.get("error")
    )

    url_features = extract_url_features(
        scraped["url"]
    )

    if webpage_available:
        webpage_features = extract_webpage_features(
            scraped["url"],
            scraped["html"],
        )
    else:
        webpage_features = get_default_webpage_features()

    merged_features = merge_features(
        url_features,
        webpage_features,
    )

    return merged_features


def main():

    print("=" * 90)
    print("XGBOOST VS DEEP LEARNING MODEL COMPARISON")
    print("=" * 90)

    for url in TEST_URLS:

        print()
        print("-" * 90)
        print(f"URL: {url}")
        print("-" * 90)

        try:

            features = prepare_features(url)

            xgb_result = xgb_predict(features)
            dl_result = dl_predict(features)

            print()
            print("XGBoost")
            print(
                f"  Prediction   : "
                f"{xgb_result['prediction']}"
            )
            print(
                f"  Probability  : "
                f"{xgb_result['phishing_probability']:.6f}"
            )
            print(
                f"  Risk         : "
                f"{xgb_result['risk_level']}"
            )

            print()
            print("Deep Learning")
            print(
                f"  Prediction   : "
                f"{dl_result['prediction']}"
            )
            print(
                f"  Probability  : "
                f"{dl_result['phishing_probability']:.6f}"
            )
            print(
                f"  Risk         : "
                f"{dl_result['risk_level']}"
            )

        except Exception as error:

            print()
            print(f"ERROR: {error}")

    print()
    print("=" * 90)
    print("COMPARISON COMPLETE")
    print("=" * 90)


if __name__ == "__main__":
    main()
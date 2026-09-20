from app.utils.url_utils import is_valid_url

from app.nlp.scraper import scrape_url

from app.ml.feature_extractor import extract_url_features
from app.ml.webpage_features import extract_webpage_features
from app.ml.webpage_defaults import get_default_webpage_features
from app.ml.feature_merger import merge_features

from app.dl.predictor import predict


TEST_URL = "https://example.com"


def main():

    print("=" * 60)
    print("DEEP LEARNING PREDICTION TEST")
    print("=" * 60)

    print()
    print(f"Testing URL: {TEST_URL}")

    # --------------------------------------------------
    # 1. Validate URL
    # --------------------------------------------------

    if not is_valid_url(TEST_URL):
        raise ValueError("Invalid test URL.")

    print("URL validation: PASSED")

    # --------------------------------------------------
    # 2. Scrape webpage
    # --------------------------------------------------

    print()
    print("Scraping webpage...")

    scraped = scrape_url(TEST_URL)

    webpage_available = not bool(
        scraped.get("error")
    )

    print(
        f"Webpage available: {webpage_available}"
    )

    # --------------------------------------------------
    # 3. URL features
    # --------------------------------------------------

    print()
    print("Extracting URL features...")

    url_features = extract_url_features(
        scraped["url"]
    )

    # --------------------------------------------------
    # 4. Webpage features
    # --------------------------------------------------

    if webpage_available:

        webpage_features = (
            extract_webpage_features(
                scraped["url"],
                scraped["html"]
            )
        )

    else:

        webpage_features = (
            get_default_webpage_features()
        )

    # --------------------------------------------------
    # 5. Merge features
    # --------------------------------------------------

    print("Merging features...")

    merged_features = merge_features(
        url_features,
        webpage_features
    )

    print(
        f"Merged features: {len(merged_features)}"
    )

    # --------------------------------------------------
    # 6. Deep Learning prediction
    # --------------------------------------------------

    print()
    print("Running MLP prediction...")

    result = predict(
        merged_features
    )

    # --------------------------------------------------
    # 7. Display result
    # --------------------------------------------------

    print()
    print("=" * 60)
    print("DEEP LEARNING RESULT")
    print("=" * 60)

    print(
        f"Prediction           : "
        f"{result['prediction']}"
    )

    print(
        f"Phishing probability : "
        f"{result['phishing_probability']:.4f}"
    )

    print(
        f"Risk level           : "
        f"{result['risk_level']}"
    )

    print("=" * 60)


if __name__ == "__main__":
    main()
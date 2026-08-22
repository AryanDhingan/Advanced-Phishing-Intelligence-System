"""
Main phishing detection service.

Combines:
1. URL validation
2. Webpage scraping
3. URL feature extraction
4. Webpage feature extraction
5. ML prediction
6. NLP analysis
"""

from app.utils.url_utils import is_valid_url

from app.nlp.scraper import scrape_url
from app.nlp.analyzer import analyze_url

from app.ml.feature_extractor import extract_url_features
from app.ml.webpage_features import extract_webpage_features

from app.ml.feature_merger import merge_features
from app.ml.predictor import predict

from app.ml.webpage_defaults import (
    get_default_webpage_features,
)


def detect_url(url: str) -> dict:
    """
    Run the complete phishing detection pipeline.
    """

    # ----------------------------------------
    # 1. Validate URL
    # ----------------------------------------

    if not is_valid_url(url):

        return {
            "url": url,
            "error": "Invalid URL",
        }

    # ----------------------------------------
    # 2. Scrape webpage
    # ----------------------------------------

    scraped = scrape_url(url)

    webpage_available = not bool(
        scraped.get("error")
    )

    scrape_error = scraped.get("error")

    # ----------------------------------------
    # 3. Extract URL features
    # ----------------------------------------

    url_features = extract_url_features(
        scraped["url"]
    )

    # ----------------------------------------
    # 4. Extract webpage features
    # ----------------------------------------

    if webpage_available:

        webpage_features = extract_webpage_features(
            scraped["url"],
            scraped["html"],
        )

    else:

        webpage_features = get_default_webpage_features()

    # ----------------------------------------
    # 5. Merge features
    # ----------------------------------------

    merged_features = merge_features(
        url_features,
        webpage_features,
    )

    # ----------------------------------------
    # 6. ML prediction
    # ----------------------------------------

    ml_result = predict(
        merged_features
    )

    # ----------------------------------------
    # 7. NLP analysis
    # ----------------------------------------

    nlp_result = analyze_url(url)

        # ----------------------------------------
    # 8. Final risk assessment
    # ----------------------------------------

    flags = nlp_result.get(
        "flags",
        []
    )

    brand_similarity = nlp_result.get(
        "brand_similarity"
    )

    risk_level = ml_result[
        "risk_level"
    ]

    # A non-legitimate brand match is a strong
    # phishing indicator, especially when the webpage
    # itself could not be reached.
    brand_impersonation = (
        brand_similarity is not None
        and not brand_similarity.get(
            "is_legitimate",
            True
        )
    )

    if brand_impersonation:

        risk_level = "HIGH"

    # ----------------------------------------
    # 9. Combine results
    # ----------------------------------------

    return {
        "url": url,

        "webpage_available": webpage_available,

        "scan_mode": (
            "FULL"
            if webpage_available
            else "URL_ONLY"
        ),

        # Raw ML result
        "prediction": ml_result[
            "prediction"
        ],

        "phishing_probability": ml_result[
            "phishing_probability"
        ],

        # Final risk after combining ML + NLP
        "risk_level": risk_level,

        "flags": flags,

        "urgency_terms": nlp_result.get(
            "urgency_terms",
            []
        ),

        "brand_similarity": brand_similarity,

        "title": nlp_result.get(
            "title"
        ),

        "has_password_field": nlp_result.get(
            "has_password_field"
        ),

        "error": scrape_error,
    }
"""
Main phishing detection service.

Combines:
1. URL validation
2. Webpage scraping
3. URL feature extraction
4. Webpage feature extraction
5. ML prediction
6. NLP analysis
7. URL intelligence
8. Final threat assessment
"""

import math

from app.utils.url_utils import is_valid_url

from app.nlp.scraper import scrape_url
from app.nlp.analyzer import analyze_url

from app.ml.feature_extractor import extract_url_features
from app.ml.webpage_features import extract_webpage_features
from app.ml.webpage_defaults import get_default_webpage_features

from app.ml.feature_merger import merge_features
from app.ml.predictor import predict

from app.intelligence.url_intelligence import (
    analyze_url_intelligence,
)


def calculate_intelligence_probability(
    intelligence_score: float,
) -> float:
    """
    Convert the URL intelligence score into a
    threat-confidence value.

    This is a heuristic transformation, not a
    statistically calibrated probability.

    The exponential curve prevents low intelligence
    scores from being treated too aggressively while
    allowing strong URL indicators to produce a
    high threat confidence.

    Examples approximately:

        0   -> 0%
        20  -> 55%
        30  -> 70%
        40  -> 80%
        55  -> 89%
        70  -> 94%
        100 -> 98%
    """

    import math

    score = max(
        0.0,
        min(
            float(intelligence_score),
            100.0,
        ),
    )

    probability = 1 - math.exp(-score / 25)

    return probability


def calculate_final_probability(
    ml_probability: float,
    intelligence_score: float,
    brand_similarity: dict | None = None,
) -> float:
    """
    Combine ML probability and URL intelligence into
    the final phishing confidence.

    Legitimate brand domains are protected from being
    incorrectly penalized by generic login/security
    indicators.

    This is a heuristic confidence score, not a
    statistically calibrated probability.
    """

    ml_probability = max(
        0.0,
        min(
            float(ml_probability),
            1.0,
        ),
    )

    intelligence_score = max(
        0.0,
        min(
            float(intelligence_score),
            100.0,
        ),
    )

    # ----------------------------------------
    # Legitimate-domain protection
    # ----------------------------------------

    is_legitimate_domain = brand_similarity is not None and brand_similarity.get(
        "is_legitimate",
        False,
    )

    # A legitimate brand domain should not be
    # treated as suspicious merely because it
    # contains words such as:
    #
    # login
    # account
    # security
    # verify
    #
    # Keep a small amount of intelligence influence
    # for legitimate domains, but strongly reduce it.

    if is_legitimate_domain:

        protected_score = min(
            intelligence_score,
            10.0,
        )

        intelligence_probability = 1 - math.exp(-protected_score / 40)

        final_probability = (0.70 * ml_probability) + (0.30 * intelligence_probability)

    else:

        # ----------------------------------------
        # Normal intelligence scoring
        # ----------------------------------------

        intelligence_probability = 1 - math.exp(-intelligence_score / 25)

        final_probability = (0.20 * ml_probability) + (0.80 * intelligence_probability)

    return min(
        round(
            final_probability,
            6,
        ),
        1.0,
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

    webpage_available = not bool(scraped.get("error"))

    scrape_error = scraped.get("error")

    # ----------------------------------------
    # 3. Extract URL features
    # ----------------------------------------

    url_features = extract_url_features(scraped["url"])

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
    # 5. Merge ML features
    # ----------------------------------------

    merged_features = merge_features(
        url_features,
        webpage_features,
    )

    # ----------------------------------------
    # 6. ML prediction
    # ----------------------------------------

    ml_result = predict(merged_features)

    ml_probability = ml_result.get(
        "phishing_probability",
        0.0,
    )

    ml_prediction = ml_result.get("prediction")

    # ----------------------------------------
    # 7. NLP analysis
    # ----------------------------------------

    nlp_result = analyze_url(url)

    flags = list(
        nlp_result.get(
            "flags",
            [],
        )
    )

    urgency_terms = list(
        nlp_result.get(
            "urgency_terms",
            [],
        )
    )

    nlp_brand_similarity = nlp_result.get("brand_similarity")

    has_password_field = nlp_result.get(
        "has_password_field",
        False,
    )

    # ----------------------------------------
    # 8. URL Intelligence
    # ----------------------------------------

    url_intelligence = analyze_url_intelligence(url)

    intelligence_score = url_intelligence.get(
        "intelligence_score",
        0,
    )

    intelligence_indicators = url_intelligence.get(
        "indicators",
        [],
    )

    suspicious_keywords = url_intelligence.get(
        "suspicious_keywords",
        [],
    )

    intelligence_brand_similarity = url_intelligence.get("brand_similarity")

    intelligence_explanation = url_intelligence.get(
        "explanation",
        "",
    )

    # ----------------------------------------
    # 9. Merge intelligence flags
    # ----------------------------------------

    for indicator in intelligence_indicators:

        if indicator not in flags:

            flags.append(indicator)

    # ----------------------------------------
    # 10. Resolve brand intelligence
    # ----------------------------------------

    brand_similarity = (
        intelligence_brand_similarity
        if intelligence_brand_similarity is not None
        else nlp_brand_similarity
    )

    # ----------------------------------------
    # 11. Calculate final probability
    # ----------------------------------------

    final_probability = (
        calculate_final_probability(
            ml_probability,
            intelligence_score,
            brand_similarity,
        )
    )

    # ----------------------------------------
    # 12. Additional webpage intelligence
    # ----------------------------------------

    # Convert the final probability into
    # percentage points for threat scoring.

    threat_score = final_probability * 100

    # ----------------------------------------
    # Brand impersonation reinforcement
    # ----------------------------------------

    brand_impersonation = brand_similarity is not None and not brand_similarity.get(
        "is_legitimate",
        True,
    )

    if brand_impersonation:

        # Brand impersonation is already reflected
        # in URL intelligence.
        #
        # We do not add another arbitrary 70 points
        # here because doing so would double-count
        # the same signal.

        brand = brand_similarity.get("brand")

        if brand:

            brand_flag = f"brand_impersonation:{brand}"

            if brand_flag not in flags:

                flags.append(brand_flag)

    # ----------------------------------------
    # Urgency language
    # ----------------------------------------

    if "urgency_language" in flags:

        threat_score += 5

    # ----------------------------------------
    # Suspicious phrases
    # ----------------------------------------

    suspicious_phrases = [
        flag for flag in flags if flag.startswith("suspicious_phrase:")
    ]

    if suspicious_phrases:

        threat_score += 5

    # ----------------------------------------
    # Password field
    # ----------------------------------------

    if has_password_field:

        threat_score += 5

    # ----------------------------------------
    # Cap final threat score
    # ----------------------------------------

    threat_score = min(
        round(
            threat_score,
            2,
        ),
        100.0,
    )

    # ----------------------------------------
    # 13. Final risk classification
    # ----------------------------------------

    if threat_score >= 70:

        risk_level = "HIGH"

    elif threat_score >= 40:

        risk_level = "MEDIUM"

    else:

        risk_level = "LOW"

    # ----------------------------------------
    # 14. Return combined intelligence
    # ----------------------------------------

    return {
        "url": url,
        # ------------------------------------
        # Scan status
        # ------------------------------------
        "webpage_available": (webpage_available),
        "scan_mode": ("FULL" if webpage_available else "URL_ONLY"),
        # ------------------------------------
        # Raw ML output
        # ------------------------------------
        "prediction": ml_prediction,
        "ml_probability": (ml_probability),
        # ------------------------------------
        # Final security assessment
        # ------------------------------------
        "phishing_probability": (final_probability),
        "threat_score": (threat_score),
        "risk_level": (risk_level),
        # ------------------------------------
        # URL intelligence
        # ------------------------------------
        "url_intelligence_score": (intelligence_score),
        "url_intelligence_indicators": (intelligence_indicators),
        "suspicious_keywords": (suspicious_keywords),
        "intelligence_explanation": (intelligence_explanation),
        # ------------------------------------
        # NLP intelligence
        # ------------------------------------
        "flags": flags,
        "urgency_terms": (urgency_terms),
        "brand_similarity": (brand_similarity),
        # ------------------------------------
        # Webpage information
        # ------------------------------------
        "title": nlp_result.get("title"),
        "has_password_field": (has_password_field),
        # ------------------------------------
        # Scraping status
        # ------------------------------------
        "error": scrape_error,
    }

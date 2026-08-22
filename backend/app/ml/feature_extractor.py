"""
Feature extraction for URLs submitted to the phishing detection system.

The extractor produces the URL-based features used by the trained
PhiUSIIL model. Webpage/NLP features are handled separately.
"""

import re
from urllib.parse import urlparse

from app.utils.url_utils import normalize_url, extract_domain


def calculate_ratio(numerator: int, denominator: int) -> float:
    """Safely calculate a ratio."""
    if denominator == 0:
        return 0.0

    return numerator / denominator


def count_digits(value: str) -> int:
    """Count numeric characters."""
    return sum(char.isdigit() for char in value)


def count_letters(value: str) -> int:
    """Count alphabetic characters."""
    return sum(char.isalpha() for char in value)


def count_special_characters(value: str) -> int:
    """Count special characters."""
    return sum(
        not char.isalnum()
        for char in value
    )


def count_obfuscated_characters(value: str) -> int:
    """
    Count characters commonly associated with URL obfuscation.
    """

    obfuscation_patterns = [
        "%20",
        "%21",
        "%22",
        "%23",
        "%24",
        "%25",
        "%26",
        "%27",
        "%28",
        "%29",
        "%2f",
        "%3a",
        "%3d",
        "%40",
    ]

    value_lower = value.lower()

    return sum(
        value_lower.count(pattern)
        for pattern in obfuscation_patterns
    )

def calculate_char_continuation_rate(url: str) -> float:
    """
    Calculate the proportion of consecutive characters
    that belong to the same character category.

    Categories:
    - alphabetic
    - numeric
    - special
    """

    if len(url) < 2:
        return 0.0

    def category(char):
        if char.isalpha():
            return "letter"
        if char.isdigit():
            return "digit"
        return "special"

    continuations = 0

    for i in range(len(url) - 1):
        if category(url[i]) == category(url[i + 1]):
            continuations += 1

    return continuations / (len(url) - 1)


def calculate_url_similarity_index(url: str) -> float:
    """
    Estimate URL character continuity/similarity.

    Higher values indicate more repetitive character patterns.
    """

    if not url:
        return 0.0

    url_lower = url.lower()

    if len(url_lower) <= 1:
        return 0.0

    repeated_pairs = sum(
        1
        for i in range(len(url_lower) - 1)
        if url_lower[i] == url_lower[i + 1]
    )

    return repeated_pairs / (len(url_lower) - 1)


def estimate_tld_legitimate_probability(tld: str) -> float:
    """
    Estimate TLD legitimacy using a small known-TLD lookup.

    This is an approximation for live URL inference.
    """

    common_tlds = {
        "com": 0.95,
        "org": 0.90,
        "net": 0.90,
        "edu": 0.98,
        "gov": 0.99,
        "mil": 0.99,
        "in": 0.90,
        "uk": 0.90,
        "de": 0.90,
        "fr": 0.90,
        "ca": 0.90,
        "au": 0.90,
        "nz": 0.90,
        "jp": 0.90,
    }

    return common_tlds.get(
        tld.lower(),
        0.50,
    )

def extract_url_features(url: str) -> dict:
    """
    Extract URL-based phishing features.

    Returns a dictionary using the same feature names used
    by the training pipeline.
    """

    normalized = normalize_url(url)

    parsed = urlparse(normalized)

    domain = extract_domain(normalized)

    path = parsed.path or ""
    query = parsed.query or ""

    full_url = normalized

    url_length = len(full_url)

    domain_length = len(domain)

    is_domain_ip = False

    try:
        parts = domain.split(".")

        if len(parts) == 4 and all(
            part.isdigit() for part in parts
        ):
            is_domain_ip = True

    except Exception:
        is_domain_ip = False

    tld = ""

    domain_parts = domain.split(".")

    if len(domain_parts) >= 2:
        tld = domain_parts[-1]

    tld_length = len(tld)

    subdomain_count = max(
        len(domain_parts) - 2,
        0,
    )

    number_of_letters = count_letters(full_url)

    number_of_digits = count_digits(full_url)

    number_of_special_chars = count_special_characters(
        full_url
    )

    number_of_obfuscated_chars = (
        count_obfuscated_characters(full_url)
    )

    special_char_ratio = calculate_ratio(
        number_of_special_chars,
        url_length,
    )

    letter_ratio = calculate_ratio(
        number_of_letters,
        url_length,
    )

    digit_ratio = calculate_ratio(
        number_of_digits,
        url_length,
    )

    obfuscation_ratio = calculate_ratio(
        number_of_obfuscated_chars,
        url_length,
    )

    return {
        # URL information
        "url_length": url_length,
        "domain_length": domain_length,
        "is_domain_ip": is_domain_ip,

        "tld": tld,
        "tld_length": tld_length,

        "tld_legitimate_prob":
                estimate_tld_legitimate_probability(tld),

        "url_similarity_index":
                calculate_url_similarity_index(
                    full_url
            ),

       "char_continuation_rate":
                calculate_char_continuation_rate(
                    full_url
                ),
        "no_of_subdomain": subdomain_count,

        # Obfuscation
        "has_obfuscation": number_of_obfuscated_chars > 0,
        "no_of_obfuscated_char": number_of_obfuscated_chars,
        "obfuscation_ratio": obfuscation_ratio,

        # Character statistics
        "no_of_letters_in_url": number_of_letters,
        "letter_ratio_in_url": letter_ratio,

        "no_of_digits_in_url": number_of_digits,
        "digit_ratio_in_url": digit_ratio,

        "no_of_equals_in_url": full_url.count("="),
        "no_of_qmark_in_url": full_url.count("?"),
        "no_of_ampersand_in_url": full_url.count("&"),

        "no_of_other_special_chars": (
            number_of_special_chars
            - full_url.count("=")
            - full_url.count("?")
            - full_url.count("&")
        ),

        "special_char_ratio": special_char_ratio,

        # Protocol
        "is_https": parsed.scheme.lower() == "https",

        # Features that require webpage inspection
        # are initialized with safe defaults.
        "line_of_code": 0,
        "largest_line_length": 0,

        "has_title": False,
        "title": "",

        "domain_title_match_score": 0.0,
        "url_title_match_score": 0.0,

        "has_favicon": False,
        "robots": False,
        "is_responsive": False,

        "no_of_url_redirect": 0,
        "no_of_self_redirect": 0,

        "has_description": False,

        "no_of_popup": 0,
        "no_of_iframe": 0,

        "has_external_form_submit": False,

        "has_social_net": False,

        "has_submit_button": False,
        "has_hidden_fields": False,
        "has_password_field": False,

        "bank": False,
        "pay": False,
        "crypto": False,

        "has_copyright_info": False,

        "no_of_image": 0,
        "no_of_css": 0,
        "no_of_js": 0,

        "no_of_self_ref": 0,
        "no_of_empty_ref": 0,
        "no_of_external_ref": 0,

        # Features useful for debugging/integration
        "_domain": domain,
        "_path": path,
        "_query": query,
    }
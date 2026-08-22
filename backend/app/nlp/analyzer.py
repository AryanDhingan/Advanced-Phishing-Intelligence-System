"""
NLP analysis for phishing webpages.

This module performs lightweight NLP analysis suitable for the
minor-project scope:
- urgency/suspicious language detection
- password-field detection
- brand/domain similarity detection
"""

import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from app.nlp.brand_watchlist import BRAND_WATCHLIST
from app.nlp.scraper import scrape_url

BRAND_SIMILARITY_THRESHOLD = 0.85


URGENCY_KEYWORDS = {
    "urgent",
    "urgently",
    "immediately",
    "warning",
    "alert",
    "suspended",
    "suspension",
    "blocked",
    "expired",
    "expire",
    "security",
    "unauthorized",
    "verify",
    "verification",
    "confirm",
    "confirmation",
    "restore",
    "locked",
}


SUSPICIOUS_PHRASES = {
    "verify your account",
    "confirm your account",
    "verify your identity",
    "confirm your identity",
    "your account has been suspended",
    "your account is suspended",
    "your account has been blocked",
    "your account is locked",
    "urgent action required",
    "immediate action required",
    "click here to verify",
    "click here to confirm",
    "update your account",
    "update your payment information",
}


def normalize_text(text: str) -> str:
    """
    Normalize text for keyword and phrase matching.
    """

    if not text:
        return ""

    text = text.lower()

    # Replace punctuation/symbols with spaces.
    text = re.sub(r"[^a-z0-9\s]", " ", text)

    # Collapse repeated whitespace.
    text = re.sub(r"\s+", " ", text)

    return text.strip()


def levenshtein_distance(first: str, second: str) -> int:
    """
    Calculate Levenshtein edit distance between two strings.

    The distance represents the minimum number of insertions,
    deletions, or substitutions required to transform one string
    into the other.
    """

    if first == second:
        return 0

    if not first:
        return len(second)

    if not second:
        return len(first)

    previous_row = list(range(len(second) + 1))

    for i, char_first in enumerate(first, start=1):

        current_row = [i]

        for j, char_second in enumerate(second, start=1):

            insertion = current_row[j - 1] + 1
            deletion = previous_row[j] + 1

            substitution = previous_row[j - 1]

            if char_first != char_second:
                substitution += 1

            current_row.append(
                min(
                    insertion,
                    deletion,
                    substitution,
                )
            )

        previous_row = current_row

    return previous_row[-1]


def similarity_score(first: str, second: str) -> float:
    """
    Convert Levenshtein distance into a normalized similarity score.

    Returns a value between 0.0 and 1.0.
    """

    first = first.lower()
    second = second.lower()

    if first == second:
        return 1.0

    max_length = max(len(first), len(second))

    if max_length == 0:
        return 1.0

    distance = levenshtein_distance(first, second)

    return 1.0 - (distance / max_length)


def extract_registered_domain(url: str) -> str:
    """
    Extract the main domain component used for brand comparison.

    Example:
        https://login.paypal.com/account
        -> paypal

    This is intentionally simple for the minor project.
    """

    parsed = urlparse(url)

    hostname = parsed.hostname or ""

    hostname = hostname.lower().strip()

    if hostname.startswith("www."):
        hostname = hostname[4:]

    parts = hostname.split(".")

    if len(parts) >= 2:
        return parts[-2]

    return hostname


def detect_urgency_flags(text: str) -> Tuple[List[str], List[str]]:
    """
    Detect urgency keywords and suspicious phrases.

    Returns:
        (flags, matched_terms)
    """

    normalized = normalize_text(text)

    flags: List[str] = []
    matched_terms: List[str] = []

    words = set(normalized.split())

    matched_keywords = sorted(
        keyword for keyword in URGENCY_KEYWORDS if keyword in words
    )

    if matched_keywords:
        flags.append("urgency_language")
        matched_terms.extend(matched_keywords)

    for phrase in sorted(SUSPICIOUS_PHRASES):
        normalized_phrase = normalize_text(phrase)

        if normalized_phrase in normalized:
            flags.append(f"suspicious_phrase:{phrase}")

            matched_terms.append(phrase)

    return flags, matched_terms

LEETSPEAK_TRANSLATION = str.maketrans(
    {
        "0": "o",
        "1": "l",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
    }
)


def normalize_brand_lookalike(value: str) -> str:
    """
    Normalize common character substitutions used in
    brand impersonation domains.
    """

    value = value.lower()

    return value.translate(LEETSPEAK_TRANSLATION)

def detect_brand_similarity(
    url: str,
) -> Optional[Dict]:
    """
    Compare the extracted domain against the brand watchlist.

    A match is returned only when similarity >= 0.85.

    Legitimate domains are identified separately so that
    legitimate brand websites are not automatically treated
    as phishing.
    """

    domain = extract_registered_domain(url)

    if not domain:
        return None

    best_match = None

    for brand, legitimate_domain in BRAND_WATCHLIST.items():

        legitimate_brand = legitimate_domain.split(".")[0]

        direct_score = similarity_score(
            domain,
            legitimate_brand,
       )

        normalized_domain = normalize_brand_lookalike(domain)

        normalized_score = similarity_score(
            normalized_domain,
            legitimate_brand,
        )

        score = max(
            direct_score,
            normalized_score,
        )

        if score >= BRAND_SIMILARITY_THRESHOLD:

            is_legitimate = domain == legitimate_brand

            candidate = {
                "brand": brand,
                "score": round(score, 4),
                "domain": domain,
                "legitimate_domain": legitimate_domain,
                "is_legitimate": is_legitimate,
            }

            if best_match is None or score > best_match["score"]:
                best_match = candidate

    return best_match


def analyze_url(url: str) -> Dict:
    """
    Run the complete NLP analysis pipeline on a URL.

    Returns a structured result containing:
    - webpage information
    - NLP flags
    - matched urgency terms
    - brand similarity information
    """

    scraped = scrape_url(url)

    scrape_error = scraped.get("error")

    flags: List[str] = []
    urgency_terms: List[str] = []

    # Brand similarity works directly from the URL,
    # so it can still run even when the webpage is unreachable.
    brand_match = detect_brand_similarity(
        scraped["url"]
    )

    if brand_match is not None:

        if not brand_match["is_legitimate"]:

            flags.append(
                f"brand_impersonation:{brand_match['brand']}"
            )

    # Webpage-based NLP is only available when scraping succeeds.
    if scrape_error is None:

        urgency_flags, urgency_terms = detect_urgency_flags(
            f"{scraped['title']} {scraped['text']}"
        )

        flags.extend(urgency_flags)

        if scraped["has_password_field"]:
            flags.append("password_field")

    return {
        "url": scraped["url"],
        "title": scraped["title"],
        "has_password_field": scraped["has_password_field"],
        "flags": flags,
        "urgency_terms": urgency_terms,
        "brand_similarity": brand_match,
        "error": scrape_error,
    }
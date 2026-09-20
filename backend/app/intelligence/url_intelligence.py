"""
URL Intelligence Layer.

Analyzes URL-level indicators independently from the ML model.

The purpose of this layer is to identify suspicious characteristics
that an ML model may underestimate, such as:

- Brand impersonation
- Suspicious keywords
- Digit substitution
- IP-based domains
- Suspicious subdomains
- Excessive subdomains
- Free-hosting/platform context
- URL obfuscation
- Suspicious TLDs
- Excessive URL length
- Suspicious path structure
- Repeated-character patterns
"""

import re
from urllib.parse import urlparse

from app.utils.url_utils import extract_domain


# ---------------------------------------------------------
# Known brands
# ---------------------------------------------------------

KNOWN_BRANDS = {
    "paypal": "paypal.com",
    "google": "google.com",
    "microsoft": "microsoft.com",
    "apple": "apple.com",
    "amazon": "amazon.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "linkedin": "linkedin.com",
    "netflix": "netflix.com",
    "whatsapp": "whatsapp.com",
    "twitter": "twitter.com",
    "dropbox": "dropbox.com",
    "adobe": "adobe.com",
    "steam": "steampowered.com",
}


# ---------------------------------------------------------
# Hosting / platform domains
# ---------------------------------------------------------

HOSTING_PLATFORMS = {
    "weeblysite.com",
    "weebly.com",
    "github.io",
    "pages.dev",
    "web.app",
    "firebaseapp.com",
    "blogspot.com",
    "wordpress.com",
    "sites.google.com",
}


# ---------------------------------------------------------
# Conventional / benign subdomains
# ---------------------------------------------------------

# These are common infrastructure subdomains and should
# not be treated as suspicious merely because they contain
# repeated characters or are short.
#
# This prevents domains such as:
#
#     www.google.com
#     www.weebly.com
#
# from receiving suspicious-subdomain scores.

BENIGN_SUBDOMAINS = {
    "www",
    "www1",
    "www2",
    "www3",
    "m",
    "mobile",
    "mail",
    "email",
    "ftp",
    "smtp",
    "imap",
    "pop",
    "blog",
    "shop",
    "store",
    "help",
    "support",
    "docs",
    "api",
    "cdn",
    "static",
    "assets",
}


# ---------------------------------------------------------
# Suspicious keywords
# ---------------------------------------------------------

SUSPICIOUS_KEYWORDS = {
    "login",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "account",
    "secure",
    "security",
    "update",
    "confirm",
    "confirmation",
    "password",
    "credential",
    "wallet",
    "payment",
    "billing",
    "recover",
    "unlock",
    "suspend",
    "suspended",
    "authentication",
    "authenticate",
}


# ---------------------------------------------------------
# Suspicious TLDs
# ---------------------------------------------------------

SUSPICIOUS_TLDS = {
    "tk",
    "ml",
    "ga",
    "cf",
    "gq",
    "top",
    "xyz",
    "click",
    "download",
    "zip",
    "review",
    "country",
    "work",
}


# ---------------------------------------------------------
# Digit substitution patterns
# ---------------------------------------------------------

LEET_TRANSLATION = str.maketrans(
    {
        "0": "o",
        "1": "i",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
    }
)


# ---------------------------------------------------------
# Helper: registrable domain
# ---------------------------------------------------------

def get_registrable_domain(domain: str) -> str:
    """
    Return the registrable domain portion.

    Examples:

        example.com
            -> example.com

        login.example.com
            -> example.com

        suspicious.weeblysite.com
            -> weeblysite.com
    """

    domain = domain.lower().strip(".")

    parts = domain.split(".")

    if len(parts) < 2:
        return domain

    return ".".join(parts[-2:])


# ---------------------------------------------------------
# Helper: subdomain
# ---------------------------------------------------------

def get_subdomain(domain: str) -> str:
    """
    Return the subdomain portion of a domain.

    Examples:

        example.com
            -> ""

        login.example.com
            -> "login"

        foo.bar.example.com
            -> "foo.bar"
    """

    domain = domain.lower().strip(".")

    parts = domain.split(".")

    if len(parts) <= 2:
        return ""

    return ".".join(parts[:-2])


# ---------------------------------------------------------
# Brand normalization
# ---------------------------------------------------------

def normalize_brand_candidate(value: str) -> str:
    """
    Normalize a domain string for basic brand impersonation
    detection.

    Example:

        paypa1 -> paypai

    The comparison also checks common digit substitutions
    separately.
    """

    value = value.lower()

    return value.translate(
        LEET_TRANSLATION
    )


# ---------------------------------------------------------
# IP detection
# ---------------------------------------------------------

def detect_ip_domain(domain: str) -> bool:
    """
    Detect whether the domain is an IPv4 address.
    """

    ipv4_pattern = (
        r"^(?:\d{1,3}\.){3}\d{1,3}$"
    )

    return bool(
        re.match(
            ipv4_pattern,
            domain,
        )
    )


# ---------------------------------------------------------
# Brand impersonation
# ---------------------------------------------------------

def detect_brand_impersonation(
    domain: str,
) -> dict | None:
    """
    Detect possible brand impersonation.

    Handles:

    - Exact legitimate brand domains
    - Legitimate brand subdomains
    - Brand names embedded in suspicious domains
    - Common digit substitutions
    """

    domain_lower = domain.lower()

    domain_parts = domain_lower.split(".")

    if len(domain_parts) < 2:
        return None

    domain_name = domain_parts[-2]

    if len(domain_name) < 3:
        return None

    for brand, legitimate_domain in KNOWN_BRANDS.items():

        brand_lower = brand.lower()

        # -------------------------------------------------
        # Exact legitimate domain
        # -------------------------------------------------

        if domain_lower == legitimate_domain:

            return {
                "brand": brand,
                "legitimate_domain": legitimate_domain,
                "domain": domain_name,
                "reason": "legitimate_brand_domain",
                "is_legitimate": True,
            }

        # -------------------------------------------------
        # Legitimate subdomain
        # -------------------------------------------------

        if domain_lower.endswith(
            "." + legitimate_domain
        ):

            return {
                "brand": brand,
                "legitimate_domain": legitimate_domain,
                "domain": domain_name,
                "reason": "legitimate_brand_domain",
                "is_legitimate": True,
            }

        # -------------------------------------------------
        # Brand directly appears in domain
        # -------------------------------------------------

        if brand_lower in domain_name:

            return {
                "brand": brand,
                "legitimate_domain": legitimate_domain,
                "domain": domain_name,
                "reason": "brand_in_suspicious_domain",
                "is_legitimate": False,
            }

        # -------------------------------------------------
        # Digit substitution
        # -------------------------------------------------

        digit_normalized = (
            domain_name
            .replace("0", "o")
            .replace("1", "l")
            .replace("3", "e")
            .replace("4", "a")
            .replace("5", "s")
            .replace("7", "t")
        )

        if brand_lower in digit_normalized:

            return {
                "brand": brand,
                "legitimate_domain": legitimate_domain,
                "domain": domain_name,
                "reason": "possible_brand_typo",
                "is_legitimate": False,
            }

    return None


# ---------------------------------------------------------
# Suspicious keywords
# ---------------------------------------------------------

def detect_suspicious_keywords(
    url: str,
) -> list[str]:
    """
    Find suspicious security-related words in the URL.
    """

    url_lower = url.lower()

    found = []

    for keyword in SUSPICIOUS_KEYWORDS:

        if keyword in url_lower:

            found.append(
                keyword
            )

    return sorted(
        found
    )


# ---------------------------------------------------------
# Suspicious TLD
# ---------------------------------------------------------

def detect_suspicious_tld(
    domain: str,
) -> bool:
    """
    Detect potentially suspicious TLDs.
    """

    parts = domain.lower().split(".")

    if len(parts) < 2:
        return False

    tld = parts[-1]

    return tld in SUSPICIOUS_TLDS


# ---------------------------------------------------------
# URL length
# ---------------------------------------------------------

def calculate_url_length_score(
    url: str,
) -> int:
    """
    Give a small intelligence score for unusually long URLs.
    """

    length = len(url)

    if length >= 200:
        return 15

    if length >= 120:
        return 10

    if length >= 80:
        return 5

    return 0


# ---------------------------------------------------------
# Excessive subdomains
# ---------------------------------------------------------

def calculate_subdomain_score(
    domain: str,
) -> int:
    """
    Give a small score for excessive subdomains.

    IP addresses are excluded because their numeric
    components must not be interpreted as subdomains.
    """

    if detect_ip_domain(domain):
        return 0

    parts = domain.split(".")

    subdomain_count = max(
        len(parts) - 2,
        0,
    )

    if subdomain_count >= 4:
        return 15

    if subdomain_count >= 3:
        return 10

    if subdomain_count >= 2:
        return 5

    return 0


# ---------------------------------------------------------
# Suspicious subdomain structure
# ---------------------------------------------------------

def detect_suspicious_subdomain(
    domain: str,
) -> tuple[list[str], int]:
    """
    Detect suspicious characteristics in a subdomain.

    This is intentionally conservative.

    A subdomain is not considered suspicious merely because
    it exists. Signals are accumulated from characteristics
    such as:

    - unusually long labels
    - repeated characters
    - unusual consonant-heavy strings
    - excessive hyphenation
    - digit-heavy labels

    Conventional benign subdomains such as "www" are ignored.

    Returns:

        (indicators, score)
    """

    if detect_ip_domain(domain):
        return [], 0

    subdomain = get_subdomain(domain)

    if not subdomain:
        return [], 0

    indicators = []
    score = 0

    labels = [
        label
        for label in subdomain.split(".")
        if label
    ]

    # -----------------------------------------------------
    # Analyze each subdomain label
    # -----------------------------------------------------

    for label in labels:

        label_lower = label.lower()

        # ---------------------------------------------
        # Ignore conventional benign labels
        # ---------------------------------------------

        if label_lower in BENIGN_SUBDOMAINS:
            continue

        # ---------------------------------------------
        # Long subdomain label
        # ---------------------------------------------

        if len(label_lower) >= 24:

            if "suspicious_subdomain_structure" not in indicators:
                indicators.append(
                    "suspicious_subdomain_structure"
                )

            score += 10

        elif len(label_lower) >= 18:

            if "suspicious_subdomain_structure" not in indicators:
                indicators.append(
                    "suspicious_subdomain_structure"
                )

            score += 5

        # ---------------------------------------------
        # Repeated characters
        # ---------------------------------------------

        repeated_match = re.search(
            r"(.)\1{2,}",
            label_lower,
        )

        if repeated_match:

            if "repeated_subdomain_characters" not in indicators:
                indicators.append(
                    "repeated_subdomain_characters"
                )

            score += 10

        # ---------------------------------------------
        # Excessive consonant sequence
        # ---------------------------------------------

        consonant_sequence = re.search(
            r"[bcdfghjklmnpqrstvwxyz]{5,}",
            label_lower,
        )

        if consonant_sequence:

            if "unusual_subdomain_pattern" not in indicators:
                indicators.append(
                    "unusual_subdomain_pattern"
                )

            score += 5

        # ---------------------------------------------
        # Excessive digits
        # ---------------------------------------------

        if len(label_lower) >= 8:

            digit_count = sum(
                char.isdigit()
                for char in label_lower
            )

            if digit_count >= 3:

                if "digit_heavy_subdomain" not in indicators:
                    indicators.append(
                        "digit_heavy_subdomain"
                    )

                score += 5

        # ---------------------------------------------
        # Excessive hyphens
        # ---------------------------------------------

        if label_lower.count("-") >= 2:

            if "hyphenated_subdomain" not in indicators:
                indicators.append(
                    "hyphenated_subdomain"
                )

            score += 5

    # -----------------------------------------------------
    # Multiple subdomain labels
    # -----------------------------------------------------

    non_benign_labels = [
        label
        for label in labels
        if label.lower() not in BENIGN_SUBDOMAINS
    ]

    if len(non_benign_labels) >= 3:

        if "complex_subdomain_structure" not in indicators:
            indicators.append(
                "complex_subdomain_structure"
            )

        score += 5

    return (
        indicators,
        min(score, 30),
    )


# ---------------------------------------------------------
# Hosting platform detection
# ---------------------------------------------------------

def detect_hosting_platform(
    domain: str,
) -> str | None:
    """
    Detect whether the URL uses a known hosting/platform
    domain.

    This is contextual information only.

    A hosting platform by itself is NOT considered a
    phishing indicator.
    """

    registrable_domain = get_registrable_domain(
        domain
    )

    for platform in HOSTING_PLATFORMS:

        if (
            registrable_domain == platform
            or domain.lower().endswith(
                "." + platform
            )
        ):

            return platform

    return None


# ---------------------------------------------------------
# Hosting + suspicious subdomain correlation
# ---------------------------------------------------------

def calculate_hosting_context_score(
    domain: str,
    subdomain_indicators: list[str],
) -> tuple[str | None, int]:
    """
    Correlate hosting-platform context with suspicious
    subdomain structure.

    Hosting alone contributes zero points.

    When suspicious subdomain characteristics are present
    on a known hosting platform, a contextual score is
    added.
    """

    platform = detect_hosting_platform(
        domain
    )

    if platform is None:
        return None, 0

    if not subdomain_indicators:
        return platform, 0

    return platform, 10


# ---------------------------------------------------------
# Obfuscation
# ---------------------------------------------------------

def detect_obfuscation(
    url: str,
) -> list[str]:
    """
    Detect common URL obfuscation patterns.
    """

    indicators = []

    if "%" in url:

        indicators.append(
            "encoded_characters"
        )

    if "@" in url:

        indicators.append(
            "at_symbol"
        )

    if "//" in url.split(
        "://",
        1,
    )[-1]:

        indicators.append(
            "nested_url_separator"
        )

    if "\\x" in url.lower():

        indicators.append(
            "hex_encoding"
        )

    return indicators


# ---------------------------------------------------------
# Suspicious path
# ---------------------------------------------------------

def detect_suspicious_path(
    parsed_url,
) -> list[str]:
    """
    Detect suspicious path characteristics.
    """

    path = (
        parsed_url.path
        or ""
    ).lower()

    indicators = []

    if path.count("/") >= 5:

        indicators.append(
            "deep_url_path"
        )

    if re.search(
        r"(login|signin|verify|account|secure|update|confirm)",
        path,
    ):

        indicators.append(
            "sensitive_path"
        )

    return indicators


# ---------------------------------------------------------
# Main intelligence analysis
# ---------------------------------------------------------

def analyze_url_intelligence(
    url: str,
) -> dict:
    """
    Perform complete URL intelligence analysis.

    Returns:

        intelligence_score
        indicators
        brand_similarity
        suspicious_keywords
        explanation
    """

    parsed = urlparse(
        url
    )

    domain = extract_domain(
        url
    )

    indicators = []
    suspicious_keywords = []

    intelligence_score = 0

    # -----------------------------------------------------
    # IP-based domain
    # -----------------------------------------------------

    if detect_ip_domain(domain):

        indicators.append(
            "ip_based_domain"
        )

        intelligence_score += 20

    # -----------------------------------------------------
    # Brand impersonation
    # -----------------------------------------------------

    brand_similarity = (
        detect_brand_impersonation(
            domain
        )
    )

    if (
        brand_similarity
        and not brand_similarity[
            "is_legitimate"
        ]
    ):

        indicators.append(
            "brand_impersonation"
        )

        intelligence_score += 45

    # -----------------------------------------------------
    # Suspicious keywords
    # -----------------------------------------------------

    suspicious_keywords = (
        detect_suspicious_keywords(
            url
        )
    )

    if suspicious_keywords:

        indicators.append(
            "suspicious_keywords"
        )

        intelligence_score += min(
            len(suspicious_keywords) * 5,
            20,
        )

    # -----------------------------------------------------
    # Suspicious TLD
    # -----------------------------------------------------

    if detect_suspicious_tld(
        domain
    ):

        indicators.append(
            "suspicious_tld"
        )

        intelligence_score += 15

    # -----------------------------------------------------
    # URL length
    # -----------------------------------------------------

    length_score = (
        calculate_url_length_score(
            url
        )
    )

    if length_score > 0:

        indicators.append(
            "unusually_long_url"
        )

        intelligence_score += (
            length_score
        )

    # -----------------------------------------------------
    # Excessive subdomains
    # -----------------------------------------------------

    subdomain_score = (
        calculate_subdomain_score(
            domain
        )
    )

    if subdomain_score > 0:

        indicators.append(
            "excessive_subdomains"
        )

        intelligence_score += (
            subdomain_score
        )

    # -----------------------------------------------------
    # Suspicious subdomain structure
    # -----------------------------------------------------

    (
        subdomain_indicators,
        subdomain_score,
    ) = detect_suspicious_subdomain(
        domain
    )

    if subdomain_indicators:

        for indicator in subdomain_indicators:

            if indicator not in indicators:

                indicators.append(
                    indicator
                )

        intelligence_score += (
            subdomain_score
        )

    # -----------------------------------------------------
    # Hosting platform context
    # -----------------------------------------------------

    (
        hosting_platform,
        hosting_score,
    ) = calculate_hosting_context_score(
        domain,
        subdomain_indicators,
    )

    if hosting_platform is not None:

        if hosting_score > 0:

            indicators.append(
                "hosted_on_platform"
            )

            intelligence_score += (
                hosting_score
            )

    # -----------------------------------------------------
    # Obfuscation
    # -----------------------------------------------------

    obfuscation_indicators = (
        detect_obfuscation(
            url
        )
    )

    if obfuscation_indicators:

        indicators.extend(
            obfuscation_indicators
        )

        intelligence_score += min(
            len(obfuscation_indicators) * 10,
            25,
        )

    # -----------------------------------------------------
    # Suspicious path
    # -----------------------------------------------------

    path_indicators = (
        detect_suspicious_path(
            parsed
        )
    )

    if path_indicators:

        indicators.extend(
            path_indicators
        )

        intelligence_score += min(
            len(path_indicators) * 5,
            10,
        )

    # -----------------------------------------------------
    # HTTPS
    # -----------------------------------------------------

    if parsed.scheme.lower() != "https":

        indicators.append(
            "not_https"
        )

        intelligence_score += 5

    # -----------------------------------------------------
    # Clamp score
    # -----------------------------------------------------

    intelligence_score = min(
        intelligence_score,
        100,
    )

    # -----------------------------------------------------
    # Explanation
    # -----------------------------------------------------

    if intelligence_score >= 70:

        explanation = (
            "Strong phishing indicators detected."
        )

    elif intelligence_score >= 40:

        explanation = (
            "Multiple suspicious URL indicators detected."
        )

    elif intelligence_score >= 20:

        explanation = (
            "Some suspicious URL characteristics detected."
        )

    elif intelligence_score > 0:

        explanation = (
            "Minor URL-level indicators detected."
        )

    else:

        explanation = (
            "No significant URL-level phishing indicators detected."
        )

    # -----------------------------------------------------
    # Return result
    # -----------------------------------------------------

    return {
        "intelligence_score": intelligence_score,
        "indicators": indicators,
        "suspicious_keywords": suspicious_keywords,
        "brand_similarity": brand_similarity,
        "explanation": explanation,
    }
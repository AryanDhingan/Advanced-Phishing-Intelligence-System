"""
Extract webpage-based features from scraped HTML.

These features correspond to the webpage-related fields in the
PhiUSIIL dataset and our SQLAlchemy Feature model.
"""

import re
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup


SOCIAL_DOMAINS = {
    "facebook.com",
    "instagram.com",
    "twitter.com",
    "x.com",
    "linkedin.com",
    "youtube.com",
    "tiktok.com",
}


def _normalize_domain(domain: str) -> str:
    """Normalize a domain for comparison."""

    domain = (domain or "").lower().strip()

    if domain.startswith("www."):
        domain = domain[4:]

    return domain


def _get_domain(url: str) -> str:
    """Extract normalized hostname."""

    parsed = urlparse(url)

    return _normalize_domain(parsed.hostname or "")


def _domain_match_score(domain: str, text: str) -> float:
    """
    Calculate a simple domain/title similarity score.

    Returns a value between 0 and 1.
    """

    domain = _normalize_domain(domain)

    if not domain or not text:
        return 0.0

    domain_name = domain.split(".")[0]

    text = text.lower()

    if domain_name in text:
        return 1.0

    domain_chars = set(domain_name)

    if not domain_chars:
        return 0.0

    matched = sum(
        1 for char in domain_name
        if char in text
    )

    return round(
        matched / len(domain_name),
        4,
    )


def _is_external_url(
    base_domain: str,
    target_url: str,
) -> bool:
    """Determine whether a referenced URL is external."""

    if not target_url:
        return False

    parsed = urlparse(target_url)

    if not parsed.netloc:
        return False

    target_domain = _normalize_domain(
        parsed.hostname or ""
    )

    return (
        target_domain != ""
        and target_domain != base_domain
    )


def _is_empty_reference(target_url: str) -> bool:
    """Check for empty/self-placeholder references."""

    if target_url is None:
        return True

    target_url = target_url.strip()

    return target_url in {
        "",
        "#",
        "javascript:void(0)",
        "javascript:;",
    }


def _is_self_reference(
    base_domain: str,
    target_url: str,
) -> bool:
    """Determine whether a URL points to the same domain."""

    if not target_url:
        return False

    parsed = urlparse(target_url)

    if not parsed.netloc:
        return True

    target_domain = _normalize_domain(
        parsed.hostname or ""
    )

    return target_domain == base_domain


def _count_external_references(
    base_url: str,
    soup: BeautifulSoup,
) -> int:
    """Count external links/resources."""

    base_domain = _get_domain(base_url)

    count = 0

    for tag in soup.find_all(
        ["a", "link", "script", "img", "iframe"]
    ):

        target = (
            tag.get("href")
            or tag.get("src")
            or ""
        )

        if _is_external_url(
            base_domain,
            target,
        ):
            count += 1

    return count


def _count_self_references(
    base_url: str,
    soup: BeautifulSoup,
) -> int:
    """Count references pointing to the same domain."""

    base_domain = _get_domain(base_url)

    count = 0

    for tag in soup.find_all(
        ["a", "link", "script", "img", "iframe"]
    ):

        target = (
            tag.get("href")
            or tag.get("src")
            or ""
        )

        if _is_self_reference(
            base_domain,
            target,
        ):
            count += 1

    return count


def _count_empty_references(
    soup: BeautifulSoup,
) -> int:
    """Count empty or placeholder references."""

    count = 0

    for tag in soup.find_all(
        ["a", "link", "script", "img", "iframe"]
    ):

        target = (
            tag.get("href")
            or tag.get("src")
        )

        if _is_empty_reference(target):
            count += 1

    return count


def _detect_external_form_submit(
    base_url: str,
    soup: BeautifulSoup,
) -> bool:
    """Detect forms submitting to external domains."""

    base_domain = _get_domain(base_url)

    for form in soup.find_all("form"):

        action = form.get("action")

        if not action:
            continue

        absolute_action = urljoin(
            base_url,
            action,
        )

        if _is_external_url(
            base_domain,
            absolute_action,
        ):
            return True

    return False


def _detect_social_network(soup: BeautifulSoup) -> bool:
    """Detect links to common social networks."""

    for anchor in soup.find_all("a", href=True):

        href = anchor.get("href", "").lower()

        for social_domain in SOCIAL_DOMAINS:

            if social_domain in href:
                return True

    return False


def _detect_hidden_fields(soup: BeautifulSoup) -> bool:
    """Detect hidden HTML form fields."""

    return (
        soup.find(
            "input",
            attrs={
                "type": lambda value:
                value
                and value.lower() == "hidden"
            },
        )
        is not None
    )


def _detect_password_field(soup: BeautifulSoup) -> bool:
    """Detect password input fields."""

    return (
        soup.find(
            "input",
            attrs={
                "type": lambda value:
                value
                and value.lower() == "password"
            },
        )
        is not None
    )


def _detect_submit_button(soup: BeautifulSoup) -> bool:
    """Detect submit buttons."""

    if soup.find(
        "input",
        attrs={
            "type": lambda value:
            value
            and value.lower() == "submit"
        },
    ):
        return True

    return soup.find("button") is not None


def _detect_description(soup: BeautifulSoup) -> bool:
    """Detect meta description."""

    return (
        soup.find(
            "meta",
            attrs={
                "name": lambda value:
                value
                and value.lower() == "description"
            },
        )
        is not None
    )


def _detect_favicon(soup: BeautifulSoup) -> bool:
    """Detect favicon references."""

    for link in soup.find_all(
        "link",
        href=True,
    ):

        rel = link.get("rel", [])

        if isinstance(rel, str):
            rel = [rel]

        if any(
            "icon" in item.lower()
            for item in rel
        ):
            return True

    return False


def _detect_responsive(soup: BeautifulSoup) -> bool:
    """Detect viewport metadata commonly used for responsive pages."""

    viewport = soup.find(
        "meta",
        attrs={
            "name": lambda value:
            value
            and value.lower() == "viewport"
        },
    )

    return viewport is not None


def _detect_copyright(soup: BeautifulSoup) -> bool:
    """Detect copyright information."""

    text = soup.get_text(
        " ",
        strip=True,
    ).lower()

    return (
        "copyright" in text
        or "©" in text
    )


def _detect_topic_flags(
    url: str,
    text: str,
) -> dict:
    """
    Detect banking/payment/crypto-related terminology.

    These are simple lexical indicators, not definitive classifications.
    """

    combined = (
        f"{url} {text}"
    ).lower()

    bank_terms = [
        "bank",
        "banking",
        "account number",
        "routing number",
        "sort code",
    ]

    pay_terms = [
        "payment",
        "pay",
        "credit card",
        "debit card",
        "billing",
        "invoice",
    ]

    crypto_terms = [
        "bitcoin",
        "ethereum",
        "crypto",
        "cryptocurrency",
        "wallet",
        "usdt",
    ]

    return {
        "bank": any(
            term in combined
            for term in bank_terms
        ),
        "pay": any(
            term in combined
            for term in pay_terms
        ),
        "crypto": any(
            term in combined
            for term in crypto_terms
        ),
    }


def extract_webpage_features(
    url: str,
    html: str,
) -> dict:
    """
    Extract webpage-level features from HTML.

    Args:
        url: Final URL used to fetch the webpage.
        html: Raw HTML response.

    Returns:
        Dictionary containing webpage-related model features.
    """

    soup = BeautifulSoup(
        html,
        "html.parser",
    )

    # Remove scripts/styles from visible-text calculations.
    visible_soup = BeautifulSoup(
        html,
        "html.parser",
    )

    for element in visible_soup(
        ["script", "style", "noscript", "template"]
    ):
        element.decompose()

    visible_text = visible_soup.get_text(
        " ",
        strip=True,
    )

    lines = html.splitlines()

    line_of_code = len(lines)

    largest_line_length = max(
        (len(line) for line in lines),
        default=0,
    )

    title = ""

    if soup.title:
        title = soup.title.get_text(
            " ",
            strip=True,
        )

    domain = _get_domain(url)

    domain_title_match_score = (
        _domain_match_score(
            domain,
            title,
        )
    )

    url_title_match_score = (
        _domain_match_score(
            urlparse(url).path,
            title,
        )
        if urlparse(url).path
        else 0.0
    )

    topic_flags = _detect_topic_flags(
        url,
        visible_text,
    )

    return {
        "line_of_code": line_of_code,
        "largest_line_length": largest_line_length,

        "has_title": bool(title),
        "title": title,

        "domain_title_match_score":
            domain_title_match_score,

        "url_title_match_score":
            url_title_match_score,

        "has_favicon":
            _detect_favicon(soup),

        # Robots cannot be reliably determined from HTML alone.
        "robots": False,

        "is_responsive":
            _detect_responsive(soup),

        # Redirect information is handled by the scraper/request layer.
        "no_of_url_redirect": 0,
        "no_of_self_redirect": 0,

        "has_description":
            _detect_description(soup),

        # Popup detection is unreliable from static HTML.
        "no_of_popup": 0,

        "no_of_iframe":
            len(soup.find_all("iframe")),

        "has_external_form_submit":
            _detect_external_form_submit(
                url,
                soup,
            ),

        "has_social_net":
            _detect_social_network(soup),

        "has_submit_button":
            _detect_submit_button(soup),

        "has_hidden_fields":
            _detect_hidden_fields(soup),

        "has_password_field":
            _detect_password_field(soup),

        "bank":
            topic_flags["bank"],

        "pay":
            topic_flags["pay"],

        "crypto":
            topic_flags["crypto"],

        "has_copyright_info":
            _detect_copyright(soup),

        "no_of_image":
            len(soup.find_all("img")),

        "no_of_css":
            len(
                soup.find_all(
                    "link",
                    rel=lambda value:
                    value
                    and "stylesheet" in value,
                )
            ),

        "no_of_js":
            len(soup.find_all("script")),

        "no_of_self_ref":
            _count_self_references(
                url,
                soup,
            ),

        "no_of_empty_ref":
            _count_empty_references(soup),

        "no_of_external_ref":
            _count_external_references(
                url,
                soup,
            ),
    }
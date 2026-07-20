import re
from urllib.parse import urlparse, urlunparse


def normalize_url(url: str) -> str:
    """
    Normalize a URL for duplicate detection.
    """

    if not url:
        return ""

    url = url.strip()

    try:
        parsed = urlparse(url)

        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        path = parsed.path.rstrip("/")

        if scheme == "http" and netloc.endswith(":80"):
            netloc = netloc[:-3]

        if scheme == "https" and netloc.endswith(":443"):
            netloc = netloc[:-4]

        normalized = urlunparse(
            (
                scheme,
                netloc,
                path,
                "",
                parsed.query,
                ""
            )
        )

        return normalized

    except Exception:
        return url.strip().lower()


def extract_domain(url: str) -> str:
    """
    Extract only the domain.
    """

    if not url:
        return ""

    url = url.strip()

    try:
        return urlparse(url).netloc.lower()
    except Exception:
        return ""


def is_valid_url(url: str) -> bool:
    """
    Basic URL validation.
    """

    if not url:
        return False

    url = url.strip()

    try:
        parsed = urlparse(url)

        return (
            parsed.scheme.lower() in ("http", "https")
            and bool(parsed.netloc)
        )

    except Exception:
        return False
"""
Basic webpage scraper for the NLP phishing intelligence module.

The scraper:
- validates the URL
- blocks obvious private/internal IP targets
- fetches the webpage with a timeout
- extracts title and visible text
- detects forms and password fields
"""

import ipaddress
import socket
from typing import Dict, List
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup


REQUEST_TIMEOUT = 8

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0 Safari/537.36"
)


def _is_private_or_internal_host(hostname: str) -> bool:
    """
    Check whether a hostname resolves to a private/internal IP.

    This is a basic safety measure for the minor project.
    """

    if not hostname:
        return True

    hostname = hostname.strip().lower()

    # Obvious local hostnames
    if hostname in {
        "localhost",
        "localhost.localdomain",
        "local",
    }:
        return True

    try:
        ip = ipaddress.ip_address(hostname)

        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
        )

    except ValueError:
        # Hostname is a domain rather than a literal IP.
        pass

    try:
        resolved_addresses = socket.getaddrinfo(
            hostname,
            None,
            type=socket.SOCK_STREAM,
        )

        for address in resolved_addresses:
            ip_string = address[4][0]

            try:
                ip = ipaddress.ip_address(ip_string)

                if (
                    ip.is_private
                    or ip.is_loopback
                    or ip.is_link_local
                    or ip.is_reserved
                    or ip.is_multicast
                ):
                    return True

            except ValueError:
                continue

    except socket.gaierror:
        # DNS failure will be handled by the actual request.
        pass

    return False


def _validate_target_url(url: str) -> str:
    """
    Validate the basic URL structure and block internal targets.
    """

    if not url or not isinstance(url, str):
        raise ValueError("URL must be a non-empty string.")

    url = url.strip()

    parsed = urlparse(url)

    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Only HTTP and HTTPS URLs are supported.")

    if not parsed.netloc:
        raise ValueError("URL must contain a valid domain.")

    hostname = parsed.hostname

    if not hostname:
        raise ValueError("URL hostname could not be determined.")

    if _is_private_or_internal_host(hostname):
        raise ValueError("Internal or private network targets are not allowed.")

    return url


def scrape_url(url: str) -> Dict:
    """
    Fetch a webpage and extract basic information needed by NLP analysis.

    Returns:
        {
            "url": str,
            "status_code": int,
            "title": str,
            "text": str,
            "forms": int,
            "has_password_field": bool,
            "error": str | None
        }
    """

    try:
        validated_url = _validate_target_url(url)

    except ValueError as exc:
        return {
            "url": url,
            "status_code": None,
            "title": "",
            "text": "",
            "forms": 0,
            "has_password_field": False,
            "error": str(exc),
        }

    headers = {
        "User-Agent": USER_AGENT,
    }

    try:
        response = requests.get(
            validated_url,
            headers=headers,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
        )

        response.raise_for_status()

    except requests.RequestException as exc:
        return {
            "url": validated_url,
            "status_code": getattr(
                getattr(exc, "response", None),
                "status_code",
                None,
            ),
            "title": "",
            "text": "",
            "forms": 0,
            "has_password_field": False,
            "error": f"Request failed: {exc}",
        }

    soup = BeautifulSoup(response.text, "html.parser")

    # Remove elements that don't represent useful visible webpage text.
    for element in soup(
        ["script", "style", "noscript", "template"]
    ):
        element.decompose()

    title = ""

    if soup.title:
        title = soup.title.get_text(" ", strip=True)

    text = soup.get_text(" ", strip=True)

    forms = soup.find_all("form")

    password_fields: List = soup.find_all(
        "input",
        attrs={"type": lambda value: value and value.lower() == "password"},
    )

    return {
        "url": validated_url,
        "status_code": response.status_code,
        "title": title,
        "text": text,
        "forms": len(forms),
        "has_password_field": len(password_fields) > 0,
        "error": None,
    }
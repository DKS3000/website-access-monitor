"""Shared configuration for Website Access Monitor."""
import os
from urllib.parse import urlparse

DEFAULT_TARGET_URL = os.environ.get("TARGET_URL", "https://www.dgft.gov.in")


def validate_target_url(url):
    """Return a normalized http(s) URL or raise ValueError."""
    if not isinstance(url, str) or not url.strip():
        raise ValueError("Target URL is required")
    url = url.strip()
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Target URL must start with http:// or https:// and include a host")
    try:
        parsed.port
    except ValueError:
        raise ValueError("Target URL has an invalid port")
    return url

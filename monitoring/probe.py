"""Safe diagnostics for a single public HTTP or HTTPS URL."""

import ipaddress
import socket
import time
from urllib.parse import urljoin, urlsplit

import requests


MAX_RESPONSE_BYTES = 2 * 1024 * 1024
RECORDED_HEADERS = {
    "cache-control",
    "content-length",
    "content-type",
    "date",
    "server",
    "via",
    "x-cache",
    "x-request-id",
    "cf-ray",
}


class URLValidationError(ValueError):
    """Raised when a URL is not a public HTTP(S) address."""


def validate_public_url(url):
    """Reject malformed URLs and names resolving to non-public addresses."""
    if not isinstance(url, str) or not url.strip() or len(url) > 2048:
        raise URLValidationError("Enter a URL of at most 2048 characters.")
    try:
        parsed = urlsplit(url.strip())
        port = parsed.port
    except ValueError as exc:
        raise URLValidationError("The URL has an invalid host or port.") from exc
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise URLValidationError("Only absolute HTTP and HTTPS URLs are supported.")
    if parsed.username or parsed.password:
        raise URLValidationError("URLs containing credentials are not allowed.")
    if port is not None and not 1 <= port <= 65535:
        raise URLValidationError("The URL port is outside the valid range.")
    hostname = parsed.hostname.rstrip(".")
    if hostname.lower() == "localhost":
        raise URLValidationError("Local and private network URLs are not allowed.")
    try:
        addresses = {ipaddress.ip_address(hostname)}
    except ValueError:
        try:
            addresses = {
                ipaddress.ip_address(item[4][0])
                for item in socket.getaddrinfo(hostname, port or (443 if parsed.scheme == "https" else 80))
            }
        except (OSError, ValueError) as exc:
            raise URLValidationError("The target hostname could not be resolved.") from exc
    if not addresses or any(not address.is_global for address in addresses):
        raise URLValidationError("The target must resolve exclusively to public IP addresses.")
    return url.strip()


def _dns_info(hostname, port):
    started = time.perf_counter()
    records = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    addresses = sorted({record[4][0] for record in records})
    return {"addresses": addresses, "lookup_time_ms": round((time.perf_counter() - started) * 1000, 2)}


def _tls_info(response):
    connection = getattr(response.raw, "connection", None)
    sock = getattr(connection, "sock", None)
    if sock is None:
        return None
    try:
        certificate = sock.getpeercert()
        return {
            "version": sock.version(),
            "subject": dict(item[0] for item in certificate.get("subject", [])),
            "issuer": dict(item[0] for item in certificate.get("issuer", [])),
            "not_before": certificate.get("notBefore"),
            "not_after": certificate.get("notAfter"),
        }
    except (OSError, ValueError):
        return None


def probe_url(url, timeout=20, retries=0, proxy_url=None):
    """Request the supplied public URL once per attempt, recording route evidence."""
    url = validate_public_url(url)
    parsed = urlsplit(url)
    result = {
        "http_status": None,
        "status": "error",
        "classification": "network_error",
        "response_time_ms": None,
        "dns": None,
        "tls": None,
        "redirects": [],
        "redirect_count": 0,
        "final_url": url,
        "headers": {},
        "response_size": 0,
        "error": None,
    }
    try:
        result["dns"] = _dns_info(parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80))
    except OSError as exc:
        result.update(classification="dns_error", error=str(exc))
        return result

    last_error = None
    for attempt in range(max(0, min(int(retries), 5)) + 1):
        started = time.perf_counter()
        try:
            current_url = url
            redirects = []
            for _ in range(11):
                current_url = validate_public_url(current_url)
                with requests.get(
                    current_url,
                    timeout=max(1, min(int(timeout), 120)),
                    allow_redirects=False,
                    stream=True,
                    verify=True,
                    proxies={"http": proxy_url, "https": proxy_url} if proxy_url else None,
                    headers={"User-Agent": "WebsiteAccessMonitor/1.0 (+public reachability diagnostics)"},
                ) as response:
                    location = response.headers.get("Location")
                    if response.status_code in {301, 302, 303, 307, 308} and location:
                        redirects.append(
                            {"url": current_url, "status": response.status_code, "location": location}
                        )
                        current_url = urljoin(current_url, location)
                        continue
                    result["response_time_ms"] = round((time.perf_counter() - started) * 1000, 2)
                    result["http_status"] = response.status_code
                    result["final_url"] = current_url
                    result["tls"] = _tls_info(response) if urlsplit(current_url).scheme == "https" else None
                    result["redirects"] = redirects
                    result["redirect_count"] = len(redirects)
                    result["headers"] = {
                        key: value for key, value in response.headers.items()
                        if key.lower() in RECORDED_HEADERS
                    }
                    body = bytearray()
                    for chunk in response.iter_content(64 * 1024):
                        body.extend(chunk)
                        if len(body) >= MAX_RESPONSE_BYTES:
                            break
                    result["response_size"] = len(body)
                    if response.status_code == 403:
                        result.update(status="error", classification="access_denied")
                    elif 200 <= response.status_code < 400:
                        result.update(status="success", classification="reachable")
                    else:
                        result.update(status="error", classification="http_error")
                    return result
            result.update(classification="http_error", error="Too many redirects.")
            return result
        except URLValidationError as exc:
            result.update(classification="unsafe_redirect", error=str(exc))
            return result
        except requests.exceptions.Timeout as exc:
            last_error = str(exc)
            result["classification"] = "timeout"
        except requests.exceptions.SSLError as exc:
            last_error = str(exc)
            result["classification"] = "tls_error"
        except requests.exceptions.RequestException as exc:
            last_error = str(exc)
            result["classification"] = "network_error"
        if attempt < retries:
            time.sleep(min(0.5 * (attempt + 1), 2))
    result["error"] = last_error or "Request failed."
    return result

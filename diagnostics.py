"""Detailed single-route diagnostics: DNS, TCP, TLS, TTFB, total time."""
import socket
import ssl
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

USER_AGENT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")


def _ms(start):
    return round((time.perf_counter() - start) * 1000, 1)


def classify_error(exc):
    """Map an exception to a clear error reason."""
    text = str(exc).lower()
    if isinstance(exc, socket.gaierror) or "name or service not known" in text \
            or "nodename nor servname" in text or "failed to resolve" in text \
            or "temporary failure in name resolution" in text:
        return "DNS failure"
    if isinstance(exc, (ssl.SSLError, requests.exceptions.SSLError)) or "ssl" in text \
            or "certificate" in text:
        return "SSL error"
    if isinstance(exc, (socket.timeout, TimeoutError, requests.exceptions.Timeout)) \
            or "timed out" in text:
        return "Timeout"
    if isinstance(exc, requests.exceptions.ProxyError):
        return "Proxy error"
    if isinstance(exc, ConnectionRefusedError) or "refused" in text:
        return "Connection refused"
    if isinstance(exc, requests.exceptions.ConnectionError):
        return "Connection error"
    return "Error: %s" % exc


def _cert_info(host, port, timeout, verify=True):
    """Return (tls_ms, cert dict) via a direct connection; best effort."""
    info = {"valid": None, "expires": None, "issuer": None, "error": None}
    try:
        ctx = ssl.create_default_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            start = time.perf_counter()
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                tls_ms = _ms(start)
                cert = tls.getpeercert()
        expires = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        info["expires"] = expires.isoformat()
        info["valid"] = expires > datetime.now(timezone.utc)
        issuer = dict(x[0] for x in cert.get("issuer", ()))
        info["issuer"] = issuer.get("organizationName") or issuer.get("commonName")
        return tls_ms, info
    except ssl.SSLError as exc:
        info["valid"] = False
        info["error"] = str(exc)
    except Exception as exc:  # network failure etc.
        info["error"] = str(exc)
    return None, info


def run_diagnostics(target, route=None, timeout=20, verify_ssl=True):
    """Probe target through a route ({'type': 'direct'|'proxy', 'proxy_url': ...})."""
    route = route or {"name": "direct", "type": "direct"}
    parsed = urlparse(target)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    proxies = {}
    if route.get("type") == "proxy" and route.get("proxy_url"):
        proxies = {"http": route["proxy_url"], "https": route["proxy_url"]}

    result = {
        "timestamp": datetime.now().isoformat(),
        "route": route.get("name", "direct"),
        "route_type": route.get("type", "direct"),
        "target": target,
        "status": "error",
        "http_status": None,
        "response_time_ms": None,
        "final_url": None,
        "server": None,
        "ssl": None,
        "error": None,
        "diagnostics": {"dns_ms": None, "dns_ips": [], "tcp_ms": None,
                        "tls_ms": None, "ttfb_ms": None, "total_ms": None},
    }
    diag = result["diagnostics"]

    # Step-by-step timings are only meaningful for direct connections.
    if not proxies:
        try:
            start = time.perf_counter()
            infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            diag["dns_ms"] = _ms(start)
            diag["dns_ips"] = sorted({i[4][0] for i in infos})
            last_exc = None
            for info in infos:
                start = time.perf_counter()
                try:
                    socket.create_connection(info[4][:2], timeout=timeout).close()
                    diag["tcp_ms"] = _ms(start)
                    break
                except OSError as exc:
                    last_exc = exc
            if diag["tcp_ms"] is None:
                raise last_exc
        except Exception as exc:
            result["error"] = classify_error(exc)
            return result
        if parsed.scheme == "https":
            diag["tls_ms"], result["ssl"] = _cert_info(host, port, timeout, verify_ssl)

    session = requests.Session()
    resp = None
    start = time.perf_counter()
    try:
        resp = session.get(target, headers={"User-Agent": USER_AGENT}, proxies=proxies,
                           timeout=timeout, verify=verify_ssl, allow_redirects=True, stream=True)
        diag["ttfb_ms"] = _ms(start)
        resp.content  # read body
        diag["total_ms"] = _ms(start)
        result.update(
            http_status=resp.status_code,
            response_time_ms=diag["total_ms"],
            final_url=resp.url,
            server=resp.headers.get("Server"),
        )
        if 200 <= resp.status_code < 400:
            result["status"] = "success"
        elif resp.status_code in (401, 403):
            result["error"] = "Blocked / forbidden (HTTP %d)" % resp.status_code
        else:
            result["error"] = "HTTP %d" % resp.status_code
    except Exception as exc:
        diag["total_ms"] = _ms(start)
        result["error"] = classify_error(exc)
    finally:
        if resp is not None:
            resp.close()
        session.close()
    return result

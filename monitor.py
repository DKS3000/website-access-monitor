import argparse
import hashlib
import json
import sys
import time
from typing import Any, Dict, List

import requests


def parse_args():
    parser = argparse.ArgumentParser(
        description="Monitor website accessibility from multiple routes"
    )
    parser.add_argument("--target", required=True, help="Target URL to test")
    parser.add_argument("--config", default="routes.json", help="Routes JSON config")
    parser.add_argument("--output", help="Write JSON report to file")
    parser.add_argument("--html", help="Write HTML report to file")
    parser.add_argument("--timeout", type=int, default=20, help="Request timeout in seconds")
    parser.add_argument("--retries", type=int, default=1, help="Retry count per route")
    parser.add_argument("--verbose", action="store_true", help="Show verbose output")
    parser.add_argument(
        "--no-verify-ssl",
        action="store_true",
        help="Disable SSL certificate verification",
    )
    return parser.parse_args()


def load_routes(path: str) -> List[Dict[str, Any]]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            payload = json.load(fh)
    except FileNotFoundError:
        return [{"name": "direct", "type": "direct", "description": "Direct connection"}]
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON config: {exc}") from exc

    routes = payload.get("routes", [])
    if not routes:
        return [{"name": "direct", "type": "direct", "description": "Direct connection"}]
    return routes


def build_headers() -> Dict[str, str]:
    return {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Upgrade-Insecure-Requests": "1",
        "Connection": "keep-alive",
    }


def build_proxies(route: Dict[str, Any]) -> Dict[str, str]:
    proxies = {}
    if route.get("type") == "proxy":
        proxy_url = route.get("proxy_url")
        if proxy_url:
            proxies["http"] = proxy_url
            proxies["https"] = proxy_url
    return proxies


def normalize_result(target: str, route_name: str, result: Dict[str, Any]) -> Dict[str, Any]:
    status_code = result.get("http_status")
    if status_code is not None and 200 <= status_code < 400:
        result["status"] = "success"
    else:
        result["status"] = "error"

    result["route"] = route_name
    result["target"] = target
    return result


def probe_route(
    target: str,
    route: Dict[str, Any],
    timeout: int,
    retries: int,
    verify_ssl: bool,
    verbose: bool,
):
    route_name = route.get("name", "unnamed_route")
    proxies = build_proxies(route)
    headers = build_headers()

    last_error = None

    for attempt in range(1, retries + 2):
        try:
            start = time.perf_counter()
            response = requests.get(
                target,
                headers=headers,
                proxies=proxies,
                timeout=timeout,
                verify=verify_ssl,
                allow_redirects=True,
            )
            elapsed_ms = int((time.perf_counter() - start) * 1000)

            content_hash = ""
            if response.content:
                content_hash = hashlib.sha256(response.content).hexdigest()

            result = {
                "http_status": response.status_code,
                "response_time_ms": elapsed_ms,
                "final_url": response.url,
                "server": response.headers.get("Server"),
                "content_type": response.headers.get("Content-Type"),
                "content_hash": content_hash,
                "redirect_count": len(response.history),
                "headers": dict(response.headers),
                "error": None,
            }

            if verbose:
                print(
                    f"[INFO] {route_name}: status={response.status_code}, "
                    f"time={elapsed_ms}ms, final_url={response.url}"
                )

            return normalize_result(target, route_name, result)

        except requests.exceptions.RequestException as exc:
            last_error = str(exc)
            if verbose:
                print(f"[WARN] {route_name}: attempt {attempt} failed: {exc}")
            time.sleep(0.5)

    return normalize_result(
        target,
        route_name,
        {
            "http_status": None,
            "response_time_ms": None,
            "final_url": target,
            "server": None,
            "content_type": None,
            "content_hash": None,
            "redirect_count": 0,
            "headers": {},
            "error": last_error or "Request failed",
        },
    )


def write_json(path: str, data: Dict[str, Any]):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)


def generate_html(report: Dict[str, Any]) -> str:
    rows = []
    for result in report["results"]:
        rows.append(
            "<tr>"
            f"<td>{result.get('route', '')}</td>"
            f"<td>{result.get('http_status', 'n/a')}</td>"
            f"<td>{result.get('response_time_ms', 'n/a')}</td>"
            f"<td>{result.get('final_url', '')}</td>"
            f"<td>{result.get('status', 'error')}</td>"
            f"<td>{result.get('error', '')}</td>"
            "</tr>"
        )

    return f"""
    <html>
      <head>
        <title>Website Access Monitor</title>
        <style>
          body {{ font-family: Arial, sans-serif; margin: 20px; }}
          table {{ border-collapse: collapse; width: 100%; }}
          th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
          th {{ background: #f2f2f2; }}
        </style>
      </head>
      <body>
        <h1>Website Access Monitor</h1>
        <p>Target: {report['target']}</p>
        <p>Timestamp: {report['timestamp']}</p>
        <table>
          <thead>
            <tr>
              <th>Route</th>
              <th>Status Code</th>
              <th>Response Time (ms)</th>
              <th>Final URL</th>
              <th>Result</th>
              <th>Error</th>
            </tr>
          </thead>
          <tbody>
            {''.join(rows)}
          </tbody>
        </table>
      </body>
    </html>
    """


def main():
    args = parse_args()

    try:
        routes = load_routes(args.config)
    except ValueError as exc:
        print(f"Config error: {exc}", file=sys.stderr)
        return 1

    report = {
        "target": args.target,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "results": [],
    }

    for route in routes:
        result = probe_route(
            target=args.target,
            route=route,
            timeout=args.timeout,
            retries=args.retries,
            verify_ssl=not args.no_verify_ssl,
            verbose=args.verbose,
        )
        report["results"].append(result)

    print(json.dumps(report, indent=2))

    if args.output:
        write_json(args.output, report)

    if args.html:
        with open(args.html, "w", encoding="utf-8") as fh:
            fh.write(generate_html(report))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

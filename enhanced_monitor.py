#!/usr/bin/env python3
"""
Enhanced Website Access Monitor v2.0
Unified monitoring tool with advanced diagnostics, reporting, and retry logic.
Merges CLI and web dashboard capabilities with improved output formatting.
"""

import argparse
import hashlib
import json
import sys
import time
import threading
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple
from pathlib import Path
from dataclasses import dataclass, asdict
from enum import Enum

from config import DEFAULT_TARGET_URL, validate_target_url
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry as URLRetry


class RouteType(Enum):
    """Supported route types."""
    DIRECT = "direct"
    PROXY = "proxy"
    VPN = "vpn"
    WIREGUARD = "wireguard"
    SSH_TUNNEL = "ssh_tunnel"
    OPENWRT = "openwrt"


@dataclass
class ProbeResult:
    """Single probe result for a route."""
    route_name: str
    route_type: str
    target: str
    timestamp: str
    http_status: Optional[int]
    response_time_ms: Optional[int]
    final_url: str
    server: Optional[str]
    content_type: Optional[str]
    content_hash: str
    redirect_count: int
    status: str  # "success" or "error"
    error: Optional[str]
    attempt: int = 1
    
    def to_dict(self):
        return asdict(self)


@dataclass
class MonitoringReport:
    """Complete monitoring report."""
    target: str
    timestamp: str
    total_duration_ms: int
    routes_tested: int
    success_count: int
    failure_count: int
    success_rate_percent: float
    avg_response_time_ms: float
    results: List[ProbeResult]


class EnhancedMonitor:
    """Enhanced monitoring engine with advanced features."""
    
    def __init__(self, config_path: str = "routes.json", verbose: bool = False):
        self.config_path = config_path
        self.verbose = verbose
        self.session = self._create_session()
        
    def _create_session(self) -> requests.Session:
        """Create requests session with retry logic."""
        session = requests.Session()
        retry_strategy = URLRetry(
            total=3,
            status_forcelist=[429, 500, 502, 503, 504],
            method_whitelist=["HEAD", "GET", "OPTIONS"],
            backoff_factor=1
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session
    
    def _build_headers(self) -> Dict[str, str]:
        """Build standard request headers."""
        return {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Upgrade-Insecure-Requests": "1",
            "Connection": "keep-alive",
        }
    
    def load_routes(self) -> List[Dict[str, Any]]:
        """Load routes from configuration."""
        try:
            with open(self.config_path, "r", encoding="utf-8") as fh:
                payload = json.load(fh)
        except FileNotFoundError:
            self._log("Config not found, using direct connection only")
            return [{"name": "direct", "type": "direct", "description": "Direct connection"}]
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON config: {exc}")
        
        routes = payload.get("routes", [])
        return routes if routes else [{"name": "direct", "type": "direct", "description": "Direct connection"}]
    
    def _log(self, message: str):
        """Log with timestamp."""
        if self.verbose:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"[{timestamp}] {message}")
    
    def probe_route(
        self,
        target: str,
        route: Dict[str, Any],
        timeout: int = 20,
        retries: int = 1,
        verify_ssl: bool = True
    ) -> ProbeResult:
        """Probe a single route with retry logic."""
        route_name = route.get("name", "unnamed")
        route_type = route.get("type", "direct")
        
        headers = self._build_headers()
        proxies = {}
        
        if route_type == "proxy":
            proxy_url = route.get("proxy_url")
            if proxy_url:
                proxies = {"http": proxy_url, "https": proxy_url}
        
        last_error = None
        best_result = None
        
        for attempt in range(1, retries + 1):
            try:
                self._log(f"Probing {route_name} (attempt {attempt}/{retries + 1})")
                
                start = time.perf_counter()
                response = self.session.get(
                    target,
                    headers=headers,
                    proxies=proxies,
                    timeout=timeout,
                    verify=verify_ssl,
                    allow_redirects=True
                )
                elapsed_ms = int((time.perf_counter() - start) * 1000)
                
                content_hash = ""
                if response.content:
                    content_hash = hashlib.sha256(response.content).hexdigest()
                
                status = "success" if 200 <= response.status_code < 400 else "error"
                
                result = ProbeResult(
                    route_name=route_name,
                    route_type=route_type,
                    target=target,
                    timestamp=datetime.utcnow().isoformat() + "Z",
                    http_status=response.status_code,
                    response_time_ms=elapsed_ms,
                    final_url=response.url,
                    server=response.headers.get("Server"),
                    content_type=response.headers.get("Content-Type"),
                    content_hash=content_hash,
                    redirect_count=len(response.history),
                    status=status,
                    error=None,
                    attempt=attempt
                )
                
                self._log(f"✓ {route_name}: {response.status_code} ({elapsed_ms}ms)")
                return result
                
            except requests.exceptions.RequestException as exc:
                last_error = str(exc)
                self._log(f"✗ {route_name}: {exc}")
                best_result = ProbeResult(
                    route_name=route_name,
                    route_type=route_type,
                    target=target,
                    timestamp=datetime.utcnow().isoformat() + "Z",
                    http_status=None,
                    response_time_ms=None,
                    final_url=target,
                    server=None,
                    content_type=None,
                    content_hash="",
                    redirect_count=0,
                    status="error",
                    error=last_error,
                    attempt=attempt
                )
                time.sleep(0.5)
        
        return best_result or ProbeResult(
            route_name=route_name,
            route_type=route_type,
            target=target,
            timestamp=datetime.utcnow().isoformat() + "Z",
            http_status=None,
            response_time_ms=None,
            final_url=target,
            server=None,
            content_type=None,
            content_hash="",
            redirect_count=0,
            status="error",
            error=last_error or "Request failed",
        )
    
    def run_all_routes(
        self,
        target: str,
        timeout: int = 20,
        retries: int = 1,
        verify_ssl: bool = True
    ) -> MonitoringReport:
        """Run monitoring across all configured routes."""
        start_time = time.time()
        routes = self.load_routes()
        results: List[ProbeResult] = []
        
        for route in routes:
            result = self.probe_route(target, route, timeout, retries, verify_ssl)
            results.append(result)
        
        elapsed_ms = int((time.time() - start_time) * 1000)
        success_count = sum(1 for r in results if r.status == "success")
        failure_count = len(results) - success_count
        
        success_rate = (success_count / len(results) * 100) if results else 0
        
        response_times = [r.response_time_ms for r in results if r.response_time_ms]
        avg_response_time = sum(response_times) / len(response_times) if response_times else 0
        
        return MonitoringReport(
            target=target,
            timestamp=datetime.utcnow().isoformat() + "Z",
            total_duration_ms=elapsed_ms,
            routes_tested=len(results),
            success_count=success_count,
            failure_count=failure_count,
            success_rate_percent=success_rate,
            avg_response_time_ms=avg_response_time,
            results=results
        )


class ReportFormatter:
    """Format reports in various output formats."""
    
    @staticmethod
    def format_json(report: MonitoringReport) -> str:
        """Format as JSON."""
        return json.dumps({
            "target": report.target,
            "timestamp": report.timestamp,
            "summary": {
                "total_duration_ms": report.total_duration_ms,
                "routes_tested": report.routes_tested,
                "success_count": report.success_count,
                "failure_count": report.failure_count,
                "success_rate_percent": round(report.success_rate_percent, 2),
                "avg_response_time_ms": round(report.avg_response_time_ms, 2)
            },
            "results": [r.to_dict() for r in report.results]
        }, indent=2)
    
    @staticmethod
    def format_text(report: MonitoringReport) -> str:
        """Format as human-readable text."""
        lines = []
        lines.append("=" * 80)
        lines.append(f"Website Access Monitor Report")
        lines.append("=" * 80)
        lines.append(f"Target:              {report.target}")
        lines.append(f"Timestamp:           {report.timestamp}")
        lines.append("")
        
        lines.append("SUMMARY")
        lines.append("-" * 80)
        lines.append(f"Routes Tested:       {report.routes_tested}")
        lines.append(f"Success Count:       {report.success_count}")
        lines.append(f"Failure Count:       {report.failure_count}")
        lines.append(f"Success Rate:        {report.success_rate_percent:.1f}%")
        lines.append(f"Avg Response Time:   {report.avg_response_time_ms:.0f}ms")
        lines.append(f"Total Duration:      {report.total_duration_ms}ms")
        lines.append("")
        
        lines.append("RESULTS BY ROUTE")
        lines.append("-" * 80)
        lines.append(f"{'Route':<25} {'Type':<15} {'Status':<10} {'HTTP':<6} {'Time':<8}")
        lines.append("-" * 80)
        
        for result in report.results:
            status_icon = "✓" if result.status == "success" else "✗"
            http_status = str(result.http_status) if result.http_status else "—"
            response_time = f"{result.response_time_ms}ms" if result.response_time_ms else "—"
            
            lines.append(
                f"{result.route_name:<25} {result.route_type:<15} "
                f"{status_icon} {result.status:<8} {http_status:<6} {response_time:<8}"
            )
        
        lines.append("=" * 80)
        return "\n".join(lines)
    
    @staticmethod
    def format_html(report: MonitoringReport) -> str:
        """Format as HTML dashboard."""
        rows = []
        for result in report.results:
            status_class = "success" if result.status == "success" else "error"
            status_icon = "✓" if result.status == "success" else "✗"
            
            rows.append(f"""
            <tr class="{status_class}">
                <td>{status_icon}</td>
                <td>{result.route_name}</td>
                <td>{result.route_type}</td>
                <td>{result.http_status or '—'}</td>
                <td>{result.response_time_ms or '—'}ms</td>
                <td>{result.final_url}</td>
                <td>{result.error or '—'}</td>
            </tr>
            """)
        
        return f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Website Access Monitor Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f5f5; padding: 20px; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }}
        header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 8px 8px 0 0; }}
        header h1 {{ font-size: 28px; margin-bottom: 10px; }}
        header p {{ font-size: 14px; opacity: 0.9; }}
        
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; padding: 30px; border-bottom: 1px solid #eee; }}
        .summary-card {{ background: #f9f9f9; padding: 15px; border-radius: 6px; border-left: 4px solid #667eea; }}
        .summary-card-label {{ font-size: 12px; color: #666; font-weight: 600; text-transform: uppercase; }}
        .summary-card-value {{ font-size: 24px; font-weight: bold; color: #333; margin-top: 8px; }}
        
        table {{ width: 100%; border-collapse: collapse; margin: 0; }}
        th {{ background: #f5f5f5; padding: 12px; text-align: left; font-weight: 600; font-size: 12px; color: #666; border-bottom: 2px solid #ddd; }}
        td {{ padding: 12px; border-bottom: 1px solid #eee; }}
        
        tr.success {{ background: #f0f9f0; }}
        tr.success td:first-child {{ color: #22c55e; font-weight: bold; }}
        
        tr.error {{ background: #fef2f2; }}
        tr.error td:first-child {{ color: #ef4444; font-weight: bold; }}
        
        tr:hover {{ background: #fafafa; }}
        
        footer {{ padding: 20px 30px; background: #f5f5f5; border-radius: 0 0 8px 8px; font-size: 12px; color: #666; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🌍 Website Access Monitor</h1>
            <p>Target: <strong>{report.target}</strong> | Generated: {report.timestamp}</p>
        </header>
        
        <div class="summary">
            <div class="summary-card">
                <div class="summary-card-label">Routes Tested</div>
                <div class="summary-card-value">{report.routes_tested}</div>
            </div>
            <div class="summary-card">
                <div class="summary-card-label">Success Rate</div>
                <div class="summary-card-value">{report.success_rate_percent:.1f}%</div>
            </div>
            <div class="summary-card">
                <div class="summary-card-label">Successful</div>
                <div class="summary-card-value" style="color: #22c55e;">{report.success_count}</div>
            </div>
            <div class="summary-card">
                <div class="summary-card-label">Failed</div>
                <div class="summary-card-value" style="color: #ef4444;">{report.failure_count}</div>
            </div>
            <div class="summary-card">
                <div class="summary-card-label">Avg Response</div>
                <div class="summary-card-value">{report.avg_response_time_ms:.0f}ms</div>
            </div>
            <div class="summary-card">
                <div class="summary-card-label">Total Time</div>
                <div class="summary-card-value">{report.total_duration_ms}ms</div>
            </div>
        </div>
        
        <table>
            <thead>
                <tr>
                    <th style="width: 30px;">Status</th>
                    <th>Route</th>
                    <th>Type</th>
                    <th>HTTP Status</th>
                    <th>Response Time</th>
                    <th>Final URL</th>
                    <th>Error</th>
                </tr>
            </thead>
            <tbody>
                {''.join(rows)}
            </tbody>
        </table>
        
        <footer>
            <p>🔍 Website Access Monitor v2.0 | Enhanced unified monitoring tool</p>
        </footer>
    </div>
</body>
</html>
"""
    
    @staticmethod
    def format_csv(report: MonitoringReport) -> str:
        """Format as CSV."""
        lines = [
            "route_name,route_type,http_status,response_time_ms,status,error,final_url,timestamp"
        ]
        for result in report.results:
            lines.append(
                f'"{result.route_name}","{result.route_type}",{result.http_status or ""}'
                f',{result.response_time_ms or ""},"{result.status}","{result.error or ""}"'
                f',"{result.final_url}","{result.timestamp}"'
            )
        return "\n".join(lines)


def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Enhanced Website Access Monitor v2.0"
    )
    parser.add_argument("--target", default=DEFAULT_TARGET_URL, help="Target URL to test (default: %(default)s)")
    parser.add_argument("--config", default="routes.json", help="Routes config file")
    parser.add_argument("--output", help="Write JSON report")
    parser.add_argument("--html", help="Write HTML report")
    parser.add_argument("--csv", help="Write CSV report")
    parser.add_argument("--text", help="Write text report")
    parser.add_argument("--timeout", type=int, default=20, help="Request timeout (seconds)")
    parser.add_argument("--retries", type=int, default=2, help="Retries per route")
    parser.add_argument("--no-verify-ssl", action="store_true", help="Disable SSL verification")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--json-stdout", action="store_true", help="Print JSON to stdout")
    
    return parser.parse_args()


def main():
    """Main entry point."""
    args = parse_args()
    
    try:
        args.target = validate_target_url(args.target)
    except ValueError as exc:
        print(f"✗ Invalid target: {exc}", file=sys.stderr)
        return 2

    try:
        monitor = EnhancedMonitor(args.config, args.verbose)
        
        print(f"🔍 Starting monitoring for: {args.target}")
        report = monitor.run_all_routes(
            target=args.target,
            timeout=args.timeout,
            retries=args.retries,
            verify_ssl=not args.no_verify_ssl
        )
        
        # JSON output
        if args.json_stdout or args.output:
            json_report = ReportFormatter.format_json(report)
            if args.json_stdout:
                print(json_report)
            if args.output:
                Path(args.output).write_text(json_report)
                print(f"✓ JSON report saved: {args.output}")
        
        # Text output
        if args.text:
            text_report = ReportFormatter.format_text(report)
            Path(args.text).write_text(text_report)
            print(f"✓ Text report saved: {args.text}")
        else:
            print(ReportFormatter.format_text(report))
        
        # HTML output
        if args.html:
            html_report = ReportFormatter.format_html(report)
            Path(args.html).write_text(html_report)
            print(f"✓ HTML report saved: {args.html}")
        
        # CSV output
        if args.csv:
            csv_report = ReportFormatter.format_csv(report)
            Path(args.csv).write_text(csv_report)
            print(f"✓ CSV report saved: {args.csv}")
        
        # Exit with appropriate code
        return 0 if report.success_rate_percent == 100 else 1
        
    except Exception as e:
        print(f"✗ Error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

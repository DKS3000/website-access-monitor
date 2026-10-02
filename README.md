# Website Access Monitor

Monitor and test website accessibility from multiple network locations, VPN endpoints, and custom routes using your own servers and infrastructure.

## Features

- ✅ Test websites from multiple locations/routes
- ✅ Support for direct connection, VPN, OpenVPN, WireGuard, OpenWrt, and proxy routes
- ✅ Detailed diagnostics: HTTP status, headers, latency, redirects, TLS info
- ✅ JSON output for integration and automation
- ✅ HTML report generation
- ✅ Content fingerprinting and comparison
- ✅ Scheduled monitoring with history persisted to `logs/history.json`
- ✅ Web dashboard: live status cards, per-test diagnostics (DNS, TCP, TLS, TTFB, total), response-time chart, uptime %, history filter, compare-all-routes view, JSON/CSV export, dark/light theme, browser notification/sound when the site becomes reachable
- ✅ "Retry until success" mode with configurable interval and max attempts
- ✅ Works without NordVPN (shows "VPN not available"; direct and proxy routes still work)
- ✅ Editable target URL (dashboard and `--target`), default `https://www.dgft.gov.in`

## Use Cases

- Monitor if a website is accessible from your servers/locations
- Test connectivity through different VPN providers and custom routes
- Verify website availability across geographic regions
- Diagnose access issues from specific network paths
- Compare response times and content across routes

## Installation

Ubuntu:

```bash
sudo apt update && sudo apt install -y git python3 python3-venv python3-pip
git clone https://github.com/DKS3000/website-access-monitor.git
cd website-access-monitor
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

Then open the dashboard at <http://localhost:5000> (set `PORT=8000` to change the port).
The default target is `https://www.dgft.gov.in`; override it with the `TARGET_URL`
environment variable, the dashboard input, or `--target` on the CLI.
`./install_ubuntu.sh` automates these steps and creates `start_dashboard.sh`.

The dashboard schedules tests in-process, so run a single server process.

## Quick Start

### 1. Test a single website from direct connection

```bash
python monitor.py --target https://www.dgft.gov.in
```

### 2. Test from multiple routes (using config file)

```bash
python monitor.py --target https://www.dgft.gov.in --config routes.json
```

### 3. Generate JSON report

```bash
python monitor.py --target https://www.dgft.gov.in --config routes.json --output report.json
```

### 4. Generate HTML dashboard report

```bash
python monitor.py --target https://www.dgft.gov.in --config routes.json --html report.html
```

## Configuration

### routes.json example

```json
{
  "routes": [
    {
      "name": "direct",
      "type": "direct",
      "description": "Direct internet connection"
    },
    {
      "name": "vpn_node_1",
      "type": "vpn",
      "description": "OpenVPN - US Server",
      "vpn_config": "/path/to/openvpn.ovpn",
      "vpn_username": "user",
      "vpn_password": "pass"
    },
    {
      "name": "wireguard_1",
      "type": "wireguard",
      "description": "WireGuard - EU Server",
      "wg_config": "/path/to/wg0.conf"
    },
    {
      "name": "openwrt_router",
      "type": "openwrt",
      "description": "OpenWrt Router",
      "ssh_host": "192.168.1.1",
      "ssh_user": "root",
      "ssh_password": "password",
      "ssh_port": 22
    },
    {
      "name": "proxy_server",
      "type": "proxy",
      "description": "HTTP Proxy",
      "proxy_url": "http://proxy.example.com:8080",
      "proxy_auth": "user:pass"
    },
    {
      "name": "remote_server",
      "type": "ssh_tunnel",
      "description": "SSH Tunnel through Remote Server",
      "ssh_host": "server.example.com",
      "ssh_user": "ubuntu",
      "ssh_key": "/path/to/key.pem",
      "local_bind_port": 9090,
      "remote_bind_host": "localhost",
      "remote_bind_port": 8080
    }
  ]
}
```

## Output

### JSON Report

```json
{
  "target": "https://www.dgft.gov.in",
  "timestamp": "2026-09-26T10:30:00Z",
  "results": [
    {
      "route": "direct",
      "status": "success",
      "http_status": 200,
      "response_time_ms": 523,
      "final_url": "https://www.dgft.gov.in/",
      "server": "nginx",
      "content_hash": "abc123def456",
      "headers": {
        "Content-Type": "text/html",
        "Content-Length": "12345"
      },
      "error": null
    }
  ]
}
```

## Quick command

```bash
python monitor.py --target https://www.dgft.gov.in --config routes.json --output report.json
```

## License

MIT License.

#!/usr/bin/env python3
"""Poll a central monitor and run its queued public-URL diagnostics."""

import argparse
import os
import subprocess
import time

import requests

from monitoring.probe import probe_url

VPN_CONNECT_TIMEOUT = 45
VPN_POLL_INTERVAL = 2


class VPNError(Exception):
    """Raised when the local VPN client cannot be confirmed as connected to the requested country."""


def _run(command, timeout=20):
    return subprocess.run(command, capture_output=True, text=True, timeout=timeout)


def nordvpn_current_country():
    """Return the country NordVPN's CLI reports itself connected to, or None."""
    try:
        result = _run(["nordvpn", "status"])
    except (OSError, subprocess.SubprocessError):
        return None
    if "Status: Connected" not in result.stdout:
        return None
    for line in result.stdout.splitlines():
        if line.strip().lower().startswith("country:"):
            return line.split(":", 1)[1].strip()
    return None


def mullvad_current_country():
    """Return the country Mullvad's CLI reports itself connected to, or None."""
    try:
        result = _run(["mullvad", "status"])
    except (OSError, subprocess.SubprocessError):
        return None
    lines = result.stdout.splitlines()
    if not lines or "Connected" not in lines[0]:
        return None
    for line in lines:
        if "in" in line and "," in line:
            return line.rsplit(",", 1)[-1].strip().rstrip(".")
    return None


VPN_BACKENDS = {
    "nordvpn": {
        "current_country": nordvpn_current_country,
        "connect": lambda country: _run(["nordvpn", "connect", country], timeout=VPN_CONNECT_TIMEOUT),
    },
    "mullvad": {
        "current_country": mullvad_current_country,
        "connect": lambda country: (
            _run(["mullvad", "relay", "set", "location", country.lower()], timeout=VPN_CONNECT_TIMEOUT),
            _run(["mullvad", "connect"], timeout=VPN_CONNECT_TIMEOUT),
        ),
    },
}


def ensure_vpn_connected(provider, country, deadline_seconds=VPN_CONNECT_TIMEOUT):
    """Use the operator's already-installed/logged-in VPN client to reach the assigned country.

    This selects exactly the operator-configured country for this agent; it never tries
    alternate countries or servers to work around an access-denied result.
    """
    backend = VPN_BACKENDS.get(provider)
    if not backend:
        raise VPNError(f"Unsupported vpn_provider '{provider}'.")
    current = backend["current_country"]()
    if current and current.lower() == country.lower():
        return
    try:
        backend["connect"](country)
    except (OSError, subprocess.SubprocessError) as exc:
        raise VPNError(f"Could not run the {provider} CLI: {exc}") from exc
    deadline = time.monotonic() + deadline_seconds
    while time.monotonic() < deadline:
        current = backend["current_country"]()
        if current and current.lower() == country.lower():
            return
        time.sleep(VPN_POLL_INTERVAL)
    raise VPNError(
        f"{provider} did not confirm a connection to {country} within {deadline_seconds}s; "
        "check that the client is installed, logged in, and that country is a valid server location."
    )


def run_agent(central_url, agent_id, token, public_ip=None, poll_interval=3):
    central_url = central_url.rstrip("/")
    headers = {"Authorization": "Bearer " + token}
    session = requests.Session()
    while True:
        try:
            session.post(
                f"{central_url}/api/agent/{agent_id}/heartbeat",
                json={"public_ip": public_ip},
                headers=headers,
                timeout=10,
            ).raise_for_status()
            response = session.get(
                f"{central_url}/api/agent/{agent_id}/tasks/next",
                headers=headers,
                timeout=20,
            )
            if response.status_code == 204:
                time.sleep(poll_interval)
                continue
            response.raise_for_status()
            task = response.json()
            vpn_provider = task.get("vpn_provider")
            if vpn_provider:
                try:
                    ensure_vpn_connected(vpn_provider, task["country_code"])
                except VPNError as exc:
                    session.post(
                        f"{central_url}/api/agent/{agent_id}/tasks/{task['task_id']}/result",
                        json={"classification": "vpn_error", "error": str(exc)},
                        headers=headers,
                        timeout=20,
                    ).raise_for_status()
                    print(f"Task {task['task_id']}: vpn_error {exc}")
                    continue
            result = probe_url(
                task["url"],
                timeout=task["timeout"],
                retries=task["retries"],
                proxy_url=task.get("proxy_url"),
            )
            session.post(
                f"{central_url}/api/agent/{agent_id}/tasks/{task['task_id']}/result",
                json=result,
                headers=headers,
                timeout=20,
            ).raise_for_status()
            print(
                f"Task {task['task_id']}: {result['classification']} "
                f"HTTP {result.get('http_status')} in {result.get('response_time_ms')} ms"
            )
        except requests.RequestException as exc:
            print(f"Central service unavailable: {exc}")
            time.sleep(max(poll_interval, 5))
        except (KeyError, ValueError) as exc:
            print(f"Invalid task received: {exc}")
            time.sleep(max(poll_interval, 5))



def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--central-url", required=True, help="Central dashboard base URL")
    parser.add_argument("--agent-id", required=True, type=int, help="Agent ID shown in dashboard")
    parser.add_argument("--token", default=os.environ.get("PROBE_AGENT_TOKEN"),
                        help="One-time enrollment token (prefer PROBE_AGENT_TOKEN env var)")
    parser.add_argument("--public-ip", default=os.environ.get("AGENT_PUBLIC_IP"),
                        help="Optional known public egress IP for diagnostics")
    parser.add_argument("--poll-interval", type=int, default=3)
    args = parser.parse_args()
    if not args.token:
        parser.error("Set PROBE_AGENT_TOKEN or pass --token.")
    if not args.central_url.startswith("https://") and not args.central_url.startswith(
        ("http://127.0.0.1", "http://localhost")
    ):
        parser.error("Use HTTPS for remote central dashboard connections.")
    run_agent(args.central_url, args.agent_id, args.token, args.public_ip,
              max(1, min(args.poll_interval, 60)))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Poll a central monitor and run its queued public-URL diagnostics."""

import argparse
import os
import time

import requests

from monitoring.probe import probe_url


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

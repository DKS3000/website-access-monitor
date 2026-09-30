# Website Access Monitor

An operator-managed dashboard for checking the ordinary HTTP(S) reachability of public URLs from VPS agents in different countries or through explicitly configured HTTP proxies. A `403` is saved as a route-specific access-denied observation. The monitor does not submit credentials, evade a site restriction, or retry a 403 to seek access.

## Current capabilities

- Manage public HTTP(S) targets and country-labelled probe agents, routed directly, through an HTTP(S) proxy, or through a pre-configured VPN client (NordVPN/Mullvad).
- Create one-shot or recurring jobs (5, 15, 30 minutes, hourly, daily).
- Probe selected agents sequentially and keep results in SQLite.
- Record status/classification, duration, DNS answers, TLS certificate details when available, redirect chain, selected response headers, response size, known egress IP and timestamp.
- Compare route history, see 403 counts and latency history, inspect evidence, and open the original public URL in a normal browser.
- Authenticate agent-to-dashboard requests with one-time enrollment tokens; optionally protect dashboard APIs with a dashboard token.

Countries and egress IPs are operator-provided labels/configuration, not geolocation assertions. To compare locations, deploy an agent on a VPS in each location, or a single host running a VPN client, and supply its known public IP if desired. `direct` probes use the host's normal egress. `proxy` probes use the administrator-configured HTTP(S) proxy URL. `vpn` probes rely on a VPN client (NordVPN or Mullvad) the operator has already installed and logged in on that host, switched only to the single country configured for that agent — the agent does not manage WireGuard/OpenWrt/SSH tunnels itself, search alternate countries or servers, or verify the host's physical location.

## Run the dashboard

Python 3.9 or newer is recommended.

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
export MONITOR_DATABASE="$PWD/instance/monitor.db"
export DASHBOARD_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
gunicorn --workers 1 --threads 8 --bind 127.0.0.1:5000 app:app
```

Open `http://127.0.0.1:5000` and enter the `DASHBOARD_TOKEN` in the dashboard token field. The production command uses one Gunicorn worker because the scheduler is in-process; the thread count handles dashboard requests and agents. For remote use, deploy behind HTTPS and an authenticated reverse proxy, set a strong dashboard token, and configure the bind address only when network exposure is controlled. SQLite files contain monitoring data and should have restrictive filesystem permissions and backups. `python app.py` is a localhost-only development server.

Set `MONITOR_DATABASE` to move the SQLite database. The schema separates targets, countries, agents, jobs, results, redirects, response headers, alerts, audit events, and agent tasks to ease a future PostgreSQL migration. This first version is intended to run as one dashboard process; SQLite and the in-process scheduler are not a multi-worker/HA scheduler.

## Enroll a VPS agent

In the dashboard, add an agent with a name, country, and a direct, proxy, or VPN route. An enrollment token appears once. On the VPS, install this repository and its Python requirements, then run:

```bash
export PROBE_AGENT_TOKEN='paste-the-one-time-token'
export AGENT_PUBLIC_IP='203.0.113.10' # optional; use the actual egress IP
python agent/probe_agent.py --central-url https://monitor.example.net --agent-id 1
```

Use a service manager (for example systemd) to keep the agent running. Agent connections to a remote dashboard require HTTPS. The agent polls for one task, probes only the supplied target URL, submits structured evidence, and continues polling. The dashboard stores only a SHA-256 token hash; agents must be enabled in the dashboard. A proxy URL is configured centrally and passed to the selected agent for that agent's probes. Do not configure a proxy you do not administer or have permission to use.

For a local development agent, use `--central-url http://127.0.0.1:5000`. If a public egress IP is not supplied, the result leaves it blank rather than contacting an IP-echo service.

### VPN route (NordVPN / Mullvad)

Instead of maintaining a separate VPS per country, an agent can use a pre-configured, already-logged-in NordVPN or Mullvad client on its host. Choose "Pre-configured VPN client" as the route when adding the agent, pick the VPN provider, and set the agent's country to the location to monitor from. On the agent's host:

- Install and authenticate the client yourself ahead of time (`nordvpn login` or `mullvad account login`); the app never stores or transmits VPN account credentials.
- The agent, before each probe, confirms via `nordvpn status` / `mullvad status` that the client is already connected to the assigned country and issues `nordvpn connect <country>` / `mullvad relay set location <code>` + `mullvad connect` only if it is not. It never tries other countries or servers to get around a 403 — it always targets the single country you configured for that agent.
- To monitor from a different country, edit the agent in the dashboard and change its country (and/or VPN provider); no re-enrollment or new token is required. The agent picks up the new assignment on its next queued task.
- If the client cannot confirm the connection within about 45 seconds (not installed, not logged in, or an invalid location), the task is recorded with the `vpn_error` classification and the probe is not attempted, so a result is never misattributed to the wrong vantage point.


## Dashboard workflow

1. Add a public URL using the Targets form.
2. Enroll and start agents on your VPS locations.
3. Select a target, one or more enabled agents, a timeout, and an optional schedule.
4. Run checks. The selected agents are processed sequentially in the order shown.
5. View route-specific results and diagnostic details. The same page can be opened through the normal browser link; a 403 only shows the diagnostics.

The scheduler checks due recurring jobs in the dashboard process. Pausing cancels queued work; resuming or retrying starts a sequential run. Network retries are bounded and apply to network exceptions; HTTP 403 is recorded and never retried as a bypass attempt.

## Safety and limitations

- Targets accept only absolute HTTP(S) URLs without embedded credentials. Hostnames must resolve exclusively to public IP addresses; local/private, reserved, and loopback targets are rejected. Redirects are followed one hop at a time and each new URL is validated before a request.
- Response bodies are read only to measure a maximum of 2 MiB; they are not stored. Only a small diagnostic header allowlist is persisted.
- A successful HTTP result is 2xx/3xx; `403` is classified as `access_denied`; other HTTP codes and network failures have distinct classifications.
- DNS and TLS evidence is observed from the agent's network. Public IP is optional operator input because the service does not call a third-party IP discovery endpoint.
- The agent token is a bearer credential and must be protected. Dashboard API authentication is disabled when `DASHBOARD_TOKEN` is unset; keep the default listener local or configure authentication before exposing it.
- The scheduler and worker coordination are in-process. For high availability or multiple web workers, move scheduling and task delivery to a dedicated durable queue/worker and migrate SQLite to PostgreSQL.
- External DNS/IP intelligence, alert delivery, richer charting, user accounts/roles, database migrations, agent deployment automation, and automated public-IP discovery are not included.

## CLI report

The original one-shot command-line monitor remains available:

```bash
python monitor.py --target https://example.com/some-public-page --output report.json --html report.html
```

The dashboard agent uses `monitoring/probe.py`, which performs the additional DNS/TLS and redirect diagnostics and enforces public-target validation.

## Tests

Run the built-in test suite without installing additional test frameworks:

```bash
python -m unittest discover -s tests -v
```

## License

MIT License.

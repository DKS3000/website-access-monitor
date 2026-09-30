import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import requests

from app import create_app
from monitoring.probe import URLValidationError, probe_url, validate_public_url
from agent.probe_agent import VPNError, ensure_vpn_connected


PUBLIC_DNS = [(None, None, None, None, ("93.184.216.34", 443))]


def response(status, headers=None, body=b"public content"):
    item = MagicMock()
    item.status_code = status
    item.headers = headers or {"Content-Type": "text/html", "Server": "example"}
    item.url = "https://example.com/public"
    item.raw.connection.sock = None
    item.iter_content.return_value = [body]
    item.__enter__.return_value = item
    item.__exit__.return_value = False
    return item


class PublicURLValidationTests(unittest.TestCase):
    @patch("monitoring.probe.socket.getaddrinfo", return_value=PUBLIC_DNS)
    def test_accepts_public_http_url(self, _dns):
        self.assertEqual(
            validate_public_url("https://example.com/some-public-page"),
            "https://example.com/some-public-page",
        )

    def test_rejects_non_http_and_credentials(self):
        for url in ("ftp://example.com/file", "https://user@example.com/", "relative/path"):
            with self.subTest(url=url), self.assertRaises(URLValidationError):
                validate_public_url(url)

    def test_rejects_private_ip(self):
        for url in ("http://127.0.0.1/", "http://10.0.0.2/", "http://[::1]/"):
            with self.subTest(url=url), self.assertRaises(URLValidationError):
                validate_public_url(url)

    @patch("monitoring.probe.socket.getaddrinfo", return_value=[
        (None, None, None, None, ("93.184.216.34", 443)),
        (None, None, None, None, ("10.0.0.2", 443)),
    ])
    def test_rejects_hostname_with_private_dns_answer(self, _dns):
        with self.assertRaises(URLValidationError):
            validate_public_url("https://mixed.example/")


class ProbeTests(unittest.TestCase):
    @patch("monitoring.probe.socket.getaddrinfo", return_value=PUBLIC_DNS)
    @patch("monitoring.probe.requests.Session.get")
    def test_records_403_as_route_specific_access_denied(self, get, _dns):
        get.return_value = response(403, {"Server": "edge", "Content-Type": "text/html"})
        result = probe_url("https://example.com/public")
        self.assertEqual(result["classification"], "access_denied")
        self.assertEqual(result["http_status"], 403)
        self.assertEqual(result["response_size"], len(b"public content"))
        self.assertIn("Server", result["headers"])
        get.assert_called_once()
        self.assertFalse(get.call_args.kwargs["allow_redirects"])

    @patch("monitoring.probe.socket.getaddrinfo", return_value=PUBLIC_DNS)
    @patch("monitoring.probe.requests.Session.get")
    def test_processes_redirects_sequentially(self, get, _dns):
        first = response(302, {"Location": "/new"})
        second = response(200)
        second.url = "https://example.com/new"
        get.side_effect = [first, second]
        result = probe_url("https://example.com/public")
        self.assertEqual(result["classification"], "reachable")
        self.assertEqual(result["redirect_count"], 1)
        self.assertEqual(result["redirects"][0]["status"], 302)
        self.assertEqual(get.call_count, 2)

    @patch("monitoring.probe.socket.getaddrinfo", return_value=PUBLIC_DNS)
    @patch("monitoring.probe.requests.Session.get")
    def test_refuses_private_redirect_destination(self, get, _dns):
        get.return_value = response(302, {"Location": "http://127.0.0.1/admin"})
        result = probe_url("https://example.com/public")
        self.assertEqual(result["classification"], "unsafe_redirect")
        get.assert_called_once()

    @patch("monitoring.probe.socket.getaddrinfo", return_value=PUBLIC_DNS)
    @patch("monitoring.probe.requests.Session.get", side_effect=requests.exceptions.Timeout("slow"))
    def test_classifies_timeout(self, _get, _dns):
        self.assertEqual(probe_url("https://example.com/", timeout=1)["classification"], "timeout")


def cli_result(stdout="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.returncode = returncode
    return result


class VPNAgentTests(unittest.TestCase):
    """Confirms the VPN route only ever targets the operator-configured country - never
    an alternate country/server search to get around an access-denied result."""

    @patch("agent.probe_agent._run")
    def test_nordvpn_already_connected_skips_reconnect(self, run):
        run.return_value = cli_result("Status: Connected\nCountry: France\n")
        ensure_vpn_connected("nordvpn", "France")
        run.assert_called_once()  # only the status check; no connect attempt was issued

    @patch("agent.probe_agent._run")
    def test_nordvpn_connects_and_confirms(self, run):
        run.side_effect = [
            cli_result("Status: Disconnected\n"),
            cli_result(""),  # connect call
            cli_result("Status: Connected\nCountry: Germany\n"),
        ]
        ensure_vpn_connected("nordvpn", "Germany", deadline_seconds=5)
        self.assertEqual(run.call_count, 3)

    @patch("agent.probe_agent._run")
    def test_nordvpn_raises_when_confirmation_never_arrives(self, run):
        run.return_value = cli_result("Status: Disconnected\n")
        with self.assertRaises(VPNError):
            ensure_vpn_connected("nordvpn", "Germany", deadline_seconds=0)

    def test_unsupported_provider_rejected(self):
        with self.assertRaises(VPNError):
            ensure_vpn_connected("supersecretvpn", "France")


class DashboardPersistenceTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.database = os.path.join(self.directory.name, "monitor.sqlite")
        self.app = create_app({"TESTING": True, "DATABASE": self.database, "START_SCHEDULER": False})
        self.client = self.app.test_client()
        self.db = self.app.extensions["monitor_database"]
        self.dns_patcher = patch("monitoring.probe.socket.getaddrinfo", return_value=PUBLIC_DNS)
        self.dns_patcher.start()
        self.assertEqual(self.client.get("/").status_code, 200)

    def tearDown(self):
        self.dns_patcher.stop()
        self.directory.cleanup()

    def add_target(self):
        response = self.client.post("/api/targets", json={"url": "https://example.com/public"})
        self.assertEqual(response.status_code, 201)
        return response.json["id"]

    def add_agent(self, name, country):
        response = self.client.post("/api/agents", json={
            "name": name, "country_code": country, "route_type": "direct",
            "public_ip": "8.8.8.8",
        })
        self.assertEqual(response.status_code, 201)
        return response.json

    def test_rejects_private_target_and_persists_403_and_sequential_comparison(self):
        self.assertEqual(self.client.post("/api/targets", json={"url": "http://127.0.0.1"}).status_code, 400)
        target_id = self.add_target()
        india = self.add_agent("India VPS", "IN")
        usa = self.add_agent("USA VPS", "US")
        job = self.client.post("/api/jobs", json={
            "target_id": target_id,
            "agent_ids": [india["agent"]["id"], usa["agent"]["id"]],
            "timeout": 10,
            "retries": 0,
        })
        self.assertEqual(job.status_code, 201)

        def get_task(agent):
            return self.client.get(
                f"/api/agent/{agent['agent']['id']}/tasks/next",
                headers={"Authorization": "Bearer " + agent["token"]},
            )

        first = get_task(india)
        self.assertEqual(first.json["country_code"], "IN")
        self.assertEqual(self.client.post(
            f"/api/agent/{india['agent']['id']}/tasks/{first.json['task_id']}/result",
            headers={"Authorization": "Bearer " + india["token"]},
            json={"classification": "access_denied", "http_status": 403, "redirects": [],
                  "headers": {"Server": "edge"}, "response_time_ms": 180},
        ).status_code, 200)

        second = get_task(usa)
        self.assertEqual(second.json["country_code"], "US")
        self.client.post(
            f"/api/agent/{usa['agent']['id']}/tasks/{second.json['task_id']}/result",
            headers={"Authorization": "Bearer " + usa["token"]},
            json={"classification": "reachable", "http_status": 200, "redirects": [],
                  "headers": {}, "response_time_ms": 120},
        )

        results = self.client.get(f"/api/results?target_id={target_id}").json
        self.assertEqual({item["classification"] for item in results}, {"access_denied", "reachable"})
        self.assertEqual({item["country"] for item in results}, {"India", "United States"})
        with self.db.connect() as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM alerts WHERE kind='http_403'").fetchone()[0], 1)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM redirects").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT status FROM probe_jobs").fetchone()[0], "completed")
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM response_headers").fetchone()[0], 1)

    def test_agent_authentication_and_heartbeat(self):
        agent = self.add_agent("UK VPS", "GB")
        agent_id = agent["agent"]["id"]
        self.assertEqual(self.client.post(f"/api/agent/{agent_id}/heartbeat").status_code, 401)
        self.assertEqual(self.client.post(
            f"/api/agent/{agent_id}/heartbeat",
            headers={"Authorization": "Bearer " + agent["token"]},
            json={"public_ip": "8.8.4.4"},
        ).status_code, 200)
        self.assertEqual(self.client.get("/api/agents").json[0]["status"], "online")

    def test_recurring_schedule_is_persisted(self):
        target_id = self.add_target()
        agent = self.add_agent("Germany VPS", "DE")
        result = self.client.post("/api/jobs", json={
            "target_id": target_id, "agent_ids": [agent["agent"]["id"]],
            "schedule_interval": 300,
        })
        self.assertEqual(result.status_code, 201)
        with self.db.connect() as connection:
            row = connection.execute(
                "SELECT schedule_interval,next_run_at FROM probe_jobs WHERE id=?",
                (result.json["id"],),
            ).fetchone()
            self.assertEqual(row["schedule_interval"], 300)
            self.assertIsNotNone(row["next_run_at"])

        task = self.client.get(
            f"/api/agent/{agent['agent']['id']}/tasks/next",
            headers={"Authorization": "Bearer " + agent["token"]},
        ).json
        self.client.post(
            f"/api/agent/{agent['agent']['id']}/tasks/{task['task_id']}/result",
            headers={"Authorization": "Bearer " + agent["token"]},
            json={"classification": "reachable", "http_status": 200},
        )
        with self.db.connect() as connection:
            connection.execute(
                "UPDATE probe_jobs SET next_run_at='2000-01-01T00:00:00+00:00' WHERE id=?",
                (result.json["id"],),
            )
        self.app.extensions["monitor_scheduler_tick"]()
        next_task = self.client.get(
            f"/api/agent/{agent['agent']['id']}/tasks/next",
            headers={"Authorization": "Bearer " + agent["token"]},
        )
        self.assertEqual(next_task.json["job_id"], result.json["id"])

    def test_offline_agent_failure_is_recorded_and_next_agent_is_queued(self):
        target_id = self.add_target()
        first = self.add_agent("France VPS", "FR")
        second = self.add_agent("Japan VPS", "JP")
        job = self.client.post("/api/jobs", json={
            "target_id": target_id,
            "agent_ids": [first["agent"]["id"], second["agent"]["id"]],
        }).json
        with self.db.connect() as connection:
            connection.execute(
                "UPDATE agent_tasks SET created_at='2000-01-01T00:00:00+00:00' WHERE job_id=?",
                (job["id"],),
            )
        self.app.extensions["monitor_scheduler_tick"]()
        next_task = self.client.get(
            f"/api/agent/{second['agent']['id']}/tasks/next",
            headers={"Authorization": "Bearer " + second["token"]},
        )
        self.assertEqual(next_task.json["job_id"], job["id"])
        self.assertEqual(self.client.get(f"/api/results?target_id={target_id}").json[0]["classification"], "agent_error")

    def test_dashboard_api_requires_configured_token(self):
        protected = create_app({
            "TESTING": True,
            "DATABASE": os.path.join(self.directory.name, "protected.sqlite"),
            "START_SCHEDULER": False,
            "DASHBOARD_TOKEN": "unit-test-token",
        }).test_client()
        self.assertEqual(protected.get("/api/targets").status_code, 401)
        self.assertEqual(protected.get(
            "/api/targets", headers={"X-Dashboard-Token": "unit-test-token"}
        ).status_code, 200)

    def test_vpn_route_requires_supported_provider(self):
        response = self.client.post("/api/agents", json={
            "name": "VPN agent", "country_code": "FR", "route_type": "vpn",
        })
        self.assertEqual(response.status_code, 400)
        self.assertIn("vpn_provider", response.json["error"])

    def test_vpn_route_blocks_task_until_verified_then_unblocks(self):
        agent = self.client.post("/api/agents", json={
            "name": "VPN agent", "country_code": "FR", "route_type": "vpn", "vpn_provider": "nordvpn",
        }).json
        agent_id = agent["agent"]["id"]
        target_id = self.add_target()
        job = self.client.post("/api/jobs", json={
            "target_id": target_id, "agent_ids": [agent_id],
        }).json
        self.assertEqual(job["status"], "waiting_for_vpn")
        headers = {"Authorization": "Bearer " + agent["token"]}

        # No verified VPN yet: the real probe task must never be handed out.
        gated = self.client.get(f"/api/agent/{agent_id}/tasks/next", headers=headers)
        self.assertTrue(gated.json["vpn_required"])
        self.assertEqual(self.client.get("/api/jobs").json[0]["status"], "waiting_for_vpn")

        # Operator explicitly requests the connection from the dashboard.
        connect = self.client.post(f"/api/agents/{agent_id}/vpn/connect")
        self.assertEqual(connect.status_code, 200)
        self.assertEqual(connect.json["vpn_state"], "connecting")
        profile = self.client.get(f"/api/agent/{agent_id}/profile", headers=headers).json
        self.assertEqual(profile["vpn_command"], "connect")

        # Agent reports a public IP that independently resolves to the assigned country.
        self.app.config["IP_COUNTRY_RESOLVER"] = lambda ip: "FR"
        report = self.client.post(
            f"/api/agent/{agent_id}/vpn/state", headers=headers,
            json={"state": "connected", "public_ip": "8.8.8.8"},
        )
        self.assertEqual(report.status_code, 200)
        self.assertEqual(report.json["vpn_state"], "connected")
        self.assertEqual(self.client.get("/api/jobs").json[0]["status"], "running")

        task = self.client.get(f"/api/agent/{agent_id}/tasks/next", headers=headers)
        self.assertFalse(task.json.get("vpn_required"))
        self.assertEqual(task.json["vpn_provider"], "nordvpn")
        self.assertEqual(task.json["country_code"], "FR")

    def test_vpn_country_mismatch_fails_agent_and_blocked_job(self):
        agent = self.client.post("/api/agents", json={
            "name": "VPN agent", "country_code": "FR", "route_type": "vpn", "vpn_provider": "nordvpn",
        }).json
        agent_id = agent["agent"]["id"]
        target_id = self.add_target()
        job = self.client.post("/api/jobs", json={
            "target_id": target_id, "agent_ids": [agent_id],
        }).json
        headers = {"Authorization": "Bearer " + agent["token"]}
        self.client.post(f"/api/agents/{agent_id}/vpn/connect")

        # The reported IP resolves to a different country than the one assigned to this agent.
        self.app.config["IP_COUNTRY_RESOLVER"] = lambda ip: "DE"
        report = self.client.post(
            f"/api/agent/{agent_id}/vpn/state", headers=headers,
            json={"state": "connected", "public_ip": "8.8.8.8"},
        )
        self.assertEqual(report.json["vpn_state"], "failed")
        self.assertEqual(self.client.get("/api/agents").json[0]["vpn_state"], "failed")
        self.assertEqual(self.client.get("/api/jobs").json[0]["status"], "failed")
        self.assertEqual(self.client.get(f"/api/agent/{agent_id}/tasks/next", headers=headers).status_code, 204)

    def test_vpn_connect_endpoint_rejects_non_vpn_agent(self):
        agent = self.add_agent("Direct VPS", "GB")
        response = self.client.post(f"/api/agents/{agent['agent']['id']}/vpn/connect")
        self.assertEqual(response.status_code, 400)

    def test_direct_route_agent_is_never_vpn_gated(self):
        # Regression check: non-vpn agents must be unaffected by the hard gate.
        target_id = self.add_target()
        agent = self.add_agent("UK VPS", "GB")
        job = self.client.post("/api/jobs", json={
            "target_id": target_id, "agent_ids": [agent["agent"]["id"]],
        }).json
        self.assertEqual(job["status"], "running")
        task = self.client.get(
            f"/api/agent/{agent['agent']['id']}/tasks/next",
            headers={"Authorization": "Bearer " + agent["token"]},
        )
        self.assertFalse(task.json.get("vpn_required"))

    def test_editing_agent_switches_country_and_route_without_new_token(self):
        created = self.add_agent("Roaming VPS", "FR")
        agent_id = created["agent"]["id"]
        response = self.client.patch(f"/api/agents/{agent_id}", json={
            "country_code": "DE", "route_type": "vpn", "vpn_provider": "mullvad",
        })
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["country_code"], "DE")
        self.assertEqual(response.json["route_type"], "vpn")
        self.assertEqual(response.json["vpn_provider"], "mullvad")
        # The original enrollment token still authenticates; no re-enrollment is needed.
        self.assertEqual(self.client.get(
            f"/api/agent/{agent_id}/tasks/next",
            headers={"Authorization": "Bearer " + created["token"]},
        ).status_code, 204)


if __name__ == "__main__":
    unittest.main()

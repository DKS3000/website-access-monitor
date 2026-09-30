"""SQLite persistence for targets, agents, jobs, probe evidence, and audit events."""

import json
import os
import sqlite3
from datetime import datetime, timezone


def utcnow():
    return datetime.now(timezone.utc).isoformat()


SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS countries (
  code TEXT PRIMARY KEY, name TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS targets (
  id INTEGER PRIMARY KEY, url TEXT NOT NULL, name TEXT NOT NULL DEFAULT '',
  enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS agents (
  id INTEGER PRIMARY KEY, name TEXT NOT NULL, country_code TEXT NOT NULL REFERENCES countries(code),
  enabled INTEGER NOT NULL DEFAULT 1, token_hash TEXT NOT NULL, public_ip TEXT,
  route_type TEXT NOT NULL DEFAULT 'direct', proxy_url TEXT, vpn_provider TEXT,
  status TEXT NOT NULL DEFAULT 'offline', last_heartbeat TEXT, created_at TEXT NOT NULL,
  vpn_state TEXT NOT NULL DEFAULT 'disconnected', vpn_command TEXT,
  vpn_verified_ip TEXT, vpn_verified_country TEXT, vpn_verified_at TEXT,
  vpn_last_error TEXT, vpn_state_updated_at TEXT
);
CREATE TABLE IF NOT EXISTS probe_jobs (
  id INTEGER PRIMARY KEY, target_id INTEGER NOT NULL REFERENCES targets(id), status TEXT NOT NULL,
  schedule_interval INTEGER, next_run_at TEXT, timeout INTEGER NOT NULL DEFAULT 20,
  retries INTEGER NOT NULL DEFAULT 0, agent_ids TEXT NOT NULL, current_index INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL, started_at TEXT, ended_at TEXT, last_success_at TEXT,
  last_failure_at TEXT, paused INTEGER NOT NULL DEFAULT 0, error TEXT
);
CREATE TABLE IF NOT EXISTS probe_results (
  id INTEGER PRIMARY KEY, job_id INTEGER NOT NULL REFERENCES probe_jobs(id),
  target_id INTEGER NOT NULL REFERENCES targets(id), agent_id INTEGER REFERENCES agents(id),
  country_code TEXT, agent_name TEXT, public_ip TEXT, timestamp TEXT NOT NULL,
  status TEXT NOT NULL, classification TEXT NOT NULL, http_status INTEGER,
  response_time_ms REAL, dns_json TEXT, tls_json TEXT, redirect_count INTEGER NOT NULL DEFAULT 0,
  final_url TEXT, response_size INTEGER NOT NULL DEFAULT 0, error TEXT
);
CREATE TABLE IF NOT EXISTS redirects (
  id INTEGER PRIMARY KEY, result_id INTEGER NOT NULL REFERENCES probe_results(id) ON DELETE CASCADE,
  ordinal INTEGER NOT NULL, url TEXT, status INTEGER, location TEXT
);
CREATE TABLE IF NOT EXISTS response_headers (
  id INTEGER PRIMARY KEY, result_id INTEGER NOT NULL REFERENCES probe_results(id) ON DELETE CASCADE,
  name TEXT NOT NULL, value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY, target_id INTEGER REFERENCES targets(id), result_id INTEGER REFERENCES probe_results(id),
  kind TEXT NOT NULL, message TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_events (
  id INTEGER PRIMARY KEY, event_type TEXT NOT NULL, details_json TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS agent_tasks (
  id INTEGER PRIMARY KEY, job_id INTEGER NOT NULL REFERENCES probe_jobs(id),
  agent_id INTEGER NOT NULL REFERENCES agents(id), sequence INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'queued', created_at TEXT NOT NULL, started_at TEXT,
  finished_at TEXT, error TEXT, UNIQUE(job_id, sequence)
);
CREATE INDEX IF NOT EXISTS idx_results_target_time ON probe_results(target_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_results_job ON probe_results(job_id);
CREATE INDEX IF NOT EXISTS idx_tasks_agent_status ON agent_tasks(agent_id, status);
"""


class ClosingConnection(sqlite3.Connection):
    def __exit__(self, exc_type, exc_value, traceback):
        try:
            return super().__exit__(exc_type, exc_value, traceback)
        finally:
            self.close()


class Database:
    def __init__(self, path=None):
        self.path = path or os.environ.get(
            "MONITOR_DATABASE", os.path.join(os.path.dirname(os.path.dirname(__file__)), "instance", "monitor.db")
        )
        if self.path != ":memory:":
            os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
        self.initialize()

    def connect(self):
        connection = sqlite3.connect(self.path, timeout=30, factory=ClosingConnection)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        if self.path != ":memory:":
            connection.execute("PRAGMA journal_mode = WAL")
        return connection

    def initialize(self):
        with self.connect() as connection:
            connection.executescript(SCHEMA)
            self._migrate(connection)
            connection.executemany(
                "INSERT OR IGNORE INTO countries(code, name) VALUES (?, ?)",
                [("IN", "India"), ("US", "United States"), ("GB", "United Kingdom"),
                 ("DE", "Germany"), ("SG", "Singapore"), ("CA", "Canada"),
                 ("FR", "France"), ("JP", "Japan"), ("AU", "Australia")],
            )

    @staticmethod
    def _migrate(connection):
        """Add columns introduced after a database file's initial creation."""
        columns = {row["name"] for row in connection.execute("PRAGMA table_info(agents)")}
        if "vpn_provider" not in columns:
            connection.execute("ALTER TABLE agents ADD COLUMN vpn_provider TEXT")
        if "vpn_state" not in columns:
            connection.execute("ALTER TABLE agents ADD COLUMN vpn_state TEXT NOT NULL DEFAULT 'disconnected'")
        if "vpn_command" not in columns:
            connection.execute("ALTER TABLE agents ADD COLUMN vpn_command TEXT")
        if "vpn_verified_ip" not in columns:
            connection.execute("ALTER TABLE agents ADD COLUMN vpn_verified_ip TEXT")
        if "vpn_verified_country" not in columns:
            connection.execute("ALTER TABLE agents ADD COLUMN vpn_verified_country TEXT")
        if "vpn_verified_at" not in columns:
            connection.execute("ALTER TABLE agents ADD COLUMN vpn_verified_at TEXT")
        if "vpn_last_error" not in columns:
            connection.execute("ALTER TABLE agents ADD COLUMN vpn_last_error TEXT")
        if "vpn_state_updated_at" not in columns:
            connection.execute("ALTER TABLE agents ADD COLUMN vpn_state_updated_at TEXT")

    @staticmethod
    def row(row):
        return dict(row) if row is not None else None

    @staticmethod
    def json(value):
        return json.dumps(value, separators=(",", ":"))

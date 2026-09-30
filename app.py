#!/usr/bin/env python3
"""Flask dashboard and durable agent task coordinator."""

import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import Flask, jsonify, render_template, request

from monitoring.database import Database, utcnow
from monitoring.probe import URLValidationError, validate_public_url


SCHEDULES = {None, 300, 900, 1800, 3600, 86400}


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.update(
        DATABASE=os.environ.get(
            "MONITOR_DATABASE",
            os.path.join(os.path.dirname(__file__), "instance", "monitor.db"),
        ),
        DASHBOARD_TOKEN=os.environ.get("DASHBOARD_TOKEN", ""),
        START_SCHEDULER=True,
    )
    if test_config:
        app.config.update(test_config)
    db = Database(app.config["DATABASE"])
    app.extensions["monitor_database"] = db

    @app.before_request
    def require_dashboard_token():
        if not request.path.startswith("/api/") or request.path.startswith("/api/agent/"):
            return None
        token = app.config["DASHBOARD_TOKEN"]
        if token and not hmac.compare_digest(
            request.headers.get("X-Dashboard-Token", ""), token
        ):
            return jsonify({"error": "Dashboard authentication required."}), 401
        return None

    @app.errorhandler(URLValidationError)
    def invalid_url(exc):
        return jsonify({"error": str(exc)}), 400

    @app.get("/")
    def dashboard():
        return render_template("dashboard.html")

    @app.get("/api/countries")
    def countries():
        with db.connect() as connection:
            return jsonify([dict(row) for row in connection.execute(
                "SELECT code, name FROM countries ORDER BY name"
            )])

    @app.get("/api/targets")
    def list_targets():
        with db.connect() as connection:
            return jsonify([dict(row) for row in connection.execute(
                "SELECT * FROM targets ORDER BY id DESC"
            )])

    @app.post("/api/targets")
    def add_target():
        data = request.get_json(silent=True) or {}
        url = validate_public_url(data.get("url"))
        now = utcnow()
        with db.connect() as connection:
            cursor = connection.execute(
                "INSERT INTO targets(url,name,enabled,created_at,updated_at) VALUES(?,?,1,?,?)",
                (url, str(data.get("name", "")).strip()[:100], now, now),
            )
            target_id = cursor.lastrowid
            connection.execute(
                "INSERT INTO audit_events(event_type,details_json,created_at) VALUES(?,?,?)",
                ("target.created", db.json({"target_id": target_id}), now),
            )
            row = connection.execute("SELECT * FROM targets WHERE id=?", (target_id,)).fetchone()
        return jsonify(dict(row)), 201

    @app.patch("/api/targets/<int:target_id>")
    def update_target(target_id):
        data = request.get_json(silent=True) or {}
        with db.connect() as connection:
            target = connection.execute("SELECT * FROM targets WHERE id=?", (target_id,)).fetchone()
            if not target:
                return jsonify({"error": "Target not found."}), 404
            url = validate_public_url(data["url"]) if "url" in data else target["url"]
            name = str(data.get("name", target["name"])).strip()[:100]
            enabled = int(bool(data.get("enabled", target["enabled"])))
            connection.execute(
                "UPDATE targets SET url=?,name=?,enabled=?,updated_at=? WHERE id=?",
                (url, name, enabled, utcnow(), target_id),
            )
            return jsonify(dict(connection.execute(
                "SELECT * FROM targets WHERE id=?", (target_id,)
            ).fetchone()))

    @app.delete("/api/targets/<int:target_id>")
    def delete_target(target_id):
        with db.connect() as connection:
            if not connection.execute("SELECT 1 FROM targets WHERE id=?", (target_id,)).fetchone():
                return jsonify({"error": "Target not found."}), 404
            if connection.execute(
                "SELECT 1 FROM probe_jobs WHERE target_id=? LIMIT 1", (target_id,)
            ).fetchone():
                return jsonify({"error": "Targets with monitoring history cannot be deleted; disable them instead."}), 409
            connection.execute("DELETE FROM targets WHERE id=?", (target_id,))
            return "", 204

    @app.get("/api/agents")
    def list_agents():
        with db.connect() as connection:
            rows = connection.execute(
                """SELECT a.id,a.name,a.country_code,c.name AS country,a.enabled,a.public_ip,
                          a.route_type,a.status,a.last_heartbeat,a.created_at
                   FROM agents a JOIN countries c ON c.code=a.country_code ORDER BY c.name,a.name"""
            ).fetchall()
            agents = []
            for row in rows:
                item = dict(row)
                if item["last_heartbeat"]:
                    heartbeat = datetime.fromisoformat(item["last_heartbeat"])
                    if datetime.now(timezone.utc) - heartbeat > timedelta(minutes=2):
                        item["status"] = "offline"
                agents.append(item)
            return jsonify(agents)

    @app.post("/api/agents")
    def add_agent():
        data = request.get_json(silent=True) or {}
        name = str(data.get("name", "")).strip()[:100]
        country = str(data.get("country_code", "")).upper()
        route_type = data.get("route_type", "direct")
        proxy_url = data.get("proxy_url")
        if not name or route_type not in {"direct", "proxy"}:
            return jsonify({"error": "Agent name and a direct/proxy route type are required."}), 400
        if route_type == "proxy":
            if not isinstance(proxy_url, str) or not proxy_url.startswith(("http://", "https://")):
                return jsonify({"error": "Proxy routes require an HTTP or HTTPS proxy URL."}), 400
            if "@" in proxy_url.split("://", 1)[-1]:
                return jsonify({"error": "Credentials in proxy URLs are not supported; configure a trusted proxy without embedded credentials."}), 400
        with db.connect() as connection:
            if not connection.execute("SELECT 1 FROM countries WHERE code=?", (country,)).fetchone():
                return jsonify({"error": "Select a supported country."}), 400
            token = secrets.token_urlsafe(32)
            cursor = connection.execute(
                """INSERT INTO agents(name,country_code,token_hash,public_ip,route_type,proxy_url,created_at)
                   VALUES(?,?,?,?,?,?,?)""",
                (name, country, hashlib.sha256(token.encode()).hexdigest(),
                 str(data.get("public_ip", "")).strip()[:64] or None,
                 route_type, proxy_url if route_type == "proxy" else None, utcnow()),
            )
            agent_id = cursor.lastrowid
            connection.execute(
                "INSERT INTO audit_events(event_type,details_json,created_at) VALUES(?,?,?)",
                ("agent.created", db.json({"agent_id": agent_id}), utcnow()),
            )
            agent = connection.execute(
                """SELECT a.id,a.name,a.country_code,c.name AS country,a.route_type,a.public_ip
                   FROM agents a JOIN countries c ON c.code=a.country_code WHERE a.id=?""",
                (agent_id,),
            ).fetchone()
        return jsonify({"agent": dict(agent), "token": token}), 201

    @app.patch("/api/agents/<int:agent_id>")
    def update_agent(agent_id):
        data = request.get_json(silent=True) or {}
        with db.connect() as connection:
            row = connection.execute("SELECT * FROM agents WHERE id=?", (agent_id,)).fetchone()
            if not row:
                return jsonify({"error": "Agent not found."}), 404
            enabled = int(bool(data.get("enabled", row["enabled"])))
            connection.execute("UPDATE agents SET enabled=? WHERE id=?", (enabled, agent_id))
        return jsonify({"id": agent_id, "enabled": bool(enabled)})

    @app.get("/api/jobs")
    def list_jobs():
        with db.connect() as connection:
            rows = connection.execute(
                """SELECT j.*,t.url AS target_url,t.name AS target_name
                   FROM probe_jobs j JOIN targets t ON t.id=j.target_id ORDER BY j.id DESC LIMIT 100"""
            ).fetchall()
            return jsonify([dict(row) for row in rows])

    def queue_task(connection, job, agent_id, sequence):
        connection.execute(
            "INSERT INTO agent_tasks(job_id,agent_id,sequence,status,created_at) VALUES(?,?,?,'queued',?)",
            (job["id"], agent_id, sequence, utcnow()),
        )

    def begin_job(connection, job_id):
        job = connection.execute("SELECT * FROM probe_jobs WHERE id=?", (job_id,)).fetchone()
        if not job or job["paused"]:
            return False
        agent_ids = json.loads(job["agent_ids"])
        if not agent_ids:
            connection.execute(
                "UPDATE probe_jobs SET status='failed',error='No agents selected',ended_at=? WHERE id=?",
                (utcnow(), job_id),
            )
            return False
        if job["status"] == "running":
            return False
        sequence = connection.execute(
            "SELECT COALESCE(MAX(sequence),0)+1 FROM agent_tasks WHERE job_id=?", (job_id,)
        ).fetchone()[0]
        connection.execute(
            "UPDATE probe_jobs SET status='running',started_at=?,ended_at=NULL,current_index=0,error=NULL WHERE id=?",
            (utcnow(), job_id),
        )
        queue_task(connection, job, agent_ids[0], sequence)
        return True

    @app.post("/api/jobs")
    def create_job():
        data = request.get_json(silent=True) or {}
        try:
            target_id = int(data.get("target_id"))
            timeout = int(data.get("timeout", 20))
            retries = int(data.get("retries", 0))
            interval = data.get("schedule_interval")
            interval = None if interval in (None, "", "once") else int(interval)
            agent_ids = [int(value) for value in data.get("agent_ids", [])]
        except (TypeError, ValueError):
            return jsonify({"error": "Target, agents, timeout, retries, and interval must be valid values."}), 400
        if interval not in SCHEDULES or not 1 <= timeout <= 120 or not 0 <= retries <= 5:
            return jsonify({"error": "Schedule, timeout, or retry value is outside its allowed range."}), 400
        if not agent_ids or len(set(agent_ids)) != len(agent_ids):
            return jsonify({"error": "Select one or more distinct agents."}), 400
        with db.connect() as connection:
            target = connection.execute(
                "SELECT id FROM targets WHERE id=? AND enabled=1", (target_id,)
            ).fetchone()
            if not target:
                return jsonify({"error": "Enabled target not found."}), 404
            placeholders = ",".join("?" for _ in agent_ids)
            agents = connection.execute(
                f"SELECT id FROM agents WHERE enabled=1 AND id IN ({placeholders})", agent_ids
            ).fetchall()
            if len(agents) != len(agent_ids):
                return jsonify({"error": "One or more selected agents are disabled or unavailable."}), 400
            now = utcnow()
            cursor = connection.execute(
                """INSERT INTO probe_jobs(target_id,status,schedule_interval,next_run_at,timeout,retries,
                   agent_ids,created_at) VALUES(?,'queued',?,?,?,?,?,?)""",
                (target_id, interval,
                 (datetime.now(timezone.utc) + timedelta(seconds=interval)).isoformat() if interval else None,
                 timeout, retries, db.json(agent_ids), now),
            )
            job_id = cursor.lastrowid
            begin_job(connection, job_id)
            connection.execute(
                "INSERT INTO audit_events(event_type,details_json,created_at) VALUES(?,?,?)",
                ("job.created", db.json({"job_id": job_id}), now),
            )
            return jsonify({"id": job_id, "status": "running"}), 201

    @app.post("/api/jobs/<int:job_id>/pause")
    def pause_job(job_id):
        with db.connect() as connection:
            result = connection.execute(
                "UPDATE probe_jobs SET paused=1,status='paused' WHERE id=? AND status IN ('running','scheduled','queued')",
                (job_id,),
            )
            if not result.rowcount:
                return jsonify({"error": "Job is not active."}), 409
            connection.execute(
                "UPDATE agent_tasks SET status='cancelled',finished_at=? WHERE job_id=? AND status IN ('queued','running')",
                (utcnow(), job_id),
            )
        return jsonify({"status": "paused"})

    @app.post("/api/jobs/<int:job_id>/resume")
    def resume_job(job_id):
        with db.connect() as connection:
            row = connection.execute("SELECT * FROM probe_jobs WHERE id=?", (job_id,)).fetchone()
            if not row or not row["paused"]:
                return jsonify({"error": "Job is not paused."}), 409
            connection.execute("UPDATE probe_jobs SET paused=0 WHERE id=?", (job_id,))
            connection.execute("UPDATE probe_jobs SET status='scheduled' WHERE id=?", (job_id,))
            begin_job(connection, job_id)
        return jsonify({"status": "running"})

    @app.post("/api/jobs/<int:job_id>/retry")
    def retry_job(job_id):
        with db.connect() as connection:
            row = connection.execute("SELECT * FROM probe_jobs WHERE id=?", (job_id,)).fetchone()
            if not row:
                return jsonify({"error": "Job not found."}), 404
            if not begin_job(connection, job_id):
                return jsonify({"error": "Job is already running or cannot be retried."}), 409
        return jsonify({"status": "running"})

    @app.get("/api/results")
    def results():
        target_id = request.args.get("target_id", type=int)
        limit = min(max(request.args.get("limit", 100, type=int), 1), 500)
        sql = """SELECT r.*,t.url AS target_url,a.route_type,c.name AS country
                 FROM probe_results r JOIN targets t ON t.id=r.target_id
                 LEFT JOIN agents a ON a.id=r.agent_id
                 LEFT JOIN countries c ON c.code=r.country_code"""
        parameters = []
        if target_id:
            sql += " WHERE r.target_id=?"
            parameters.append(target_id)
        sql += " ORDER BY r.timestamp DESC LIMIT ?"
        parameters.append(limit)
        with db.connect() as connection:
            rows = connection.execute(sql, parameters).fetchall()
            output = []
            for row in rows:
                item = dict(row)
                item["dns"] = json.loads(item.pop("dns_json") or "null")
                item["tls"] = json.loads(item.pop("tls_json") or "null")
                item["redirects"] = [dict(redirect) for redirect in connection.execute(
                    "SELECT url,status,location FROM redirects WHERE result_id=? ORDER BY ordinal",
                    (item["id"],),
                )]
                item["headers"] = {
                    header["name"]: header["value"] for header in connection.execute(
                        "SELECT name,value FROM response_headers WHERE result_id=?",
                        (item["id"],),
                    )
                }
                output.append(item)
            return jsonify(output)

    def agent_authorized(connection, agent_id):
        authorization = request.headers.get("Authorization", "")
        supplied = authorization.removeprefix("Bearer ").strip()
        row = connection.execute(
            "SELECT token_hash FROM agents WHERE id=? AND enabled=1", (agent_id,)
        ).fetchone()
        return bool(row and supplied and hmac.compare_digest(
            row["token_hash"], hashlib.sha256(supplied.encode()).hexdigest()
        ))

    @app.post("/api/agent/<int:agent_id>/heartbeat")
    def agent_heartbeat(agent_id):
        data = request.get_json(silent=True) or {}
        with db.connect() as connection:
            if not agent_authorized(connection, agent_id):
                return jsonify({"error": "Agent authentication failed."}), 401
            connection.execute(
                "UPDATE agents SET status='online',last_heartbeat=?,public_ip=COALESCE(?,public_ip) WHERE id=?",
                (utcnow(), str(data.get("public_ip", "")).strip()[:64] or None, agent_id),
            )
        return jsonify({"status": "online"})

    @app.get("/api/agent/<int:agent_id>/tasks/next")
    def agent_next_task(agent_id):
        with db.connect() as connection:
            if not agent_authorized(connection, agent_id):
                return jsonify({"error": "Agent authentication failed."}), 401
            connection.execute(
                "UPDATE agents SET status='online',last_heartbeat=? WHERE id=?",
                (utcnow(), agent_id),
            )
            task = connection.execute(
                """SELECT q.id AS task_id,q.job_id,j.target_id,j.timeout,j.retries,t.url,
                          a.name AS agent_name,a.country_code,a.public_ip,a.proxy_url
                   FROM agent_tasks q JOIN probe_jobs j ON j.id=q.job_id
                   JOIN targets t ON t.id=j.target_id JOIN agents a ON a.id=q.agent_id
                   WHERE q.agent_id=? AND q.status='queued' AND j.paused=0
                   ORDER BY q.id LIMIT 1""",
                (agent_id,),
            ).fetchone()
            if not task:
                return "", 204
            connection.execute(
                "UPDATE agent_tasks SET status='running',started_at=? WHERE id=?",
                (utcnow(), task["task_id"]),
            )
            return jsonify(dict(task))

    @app.post("/api/agent/<int:agent_id>/tasks/<int:task_id>/result")
    def agent_submit_result(agent_id, task_id):
        data = request.get_json(silent=True) or {}
        with db.connect() as connection:
            if not agent_authorized(connection, agent_id):
                return jsonify({"error": "Agent authentication failed."}), 401
            task = connection.execute(
                """SELECT q.*,j.target_id,j.agent_ids,j.schedule_interval,j.paused,
                          a.name AS agent_name,a.country_code,a.public_ip
                   FROM agent_tasks q JOIN probe_jobs j ON j.id=q.job_id
                   JOIN agents a ON a.id=q.agent_id
                   WHERE q.id=? AND q.agent_id=? AND q.status='running'""",
                (task_id, agent_id),
            ).fetchone()
            if not task:
                return jsonify({"error": "Task is not active or does not belong to this agent."}), 404
            classification = str(data.get("classification", "network_error"))
            if classification not in {
                "reachable", "access_denied", "http_error", "dns_error",
                "tls_error", "timeout", "network_error", "unsafe_redirect",
            }:
                classification = "network_error"
            status = "success" if classification == "reachable" else "error"
            now = utcnow()
            result_cursor = connection.execute(
                """INSERT INTO probe_results(job_id,target_id,agent_id,country_code,agent_name,public_ip,
                   timestamp,status,classification,http_status,response_time_ms,dns_json,tls_json,
                   redirect_count,final_url,response_size,error)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (task["job_id"], task["target_id"], agent_id, task["country_code"],
                 task["agent_name"], task["public_ip"], now, status, classification,
                 data.get("http_status"), data.get("response_time_ms"),
                 db.json(data.get("dns")) if data.get("dns") is not None else None,
                 db.json(data.get("tls")) if data.get("tls") is not None else None,
                 int(data.get("redirect_count") or 0), data.get("final_url"),
                 int(data.get("response_size") or 0), str(data.get("error") or "")[:1000] or None),
            )
            result_id = result_cursor.lastrowid
            for index, redirect in enumerate(data.get("redirects", [])[:20]):
                connection.execute(
                    "INSERT INTO redirects(result_id,ordinal,url,status,location) VALUES(?,?,?,?,?)",
                    (result_id, index, str(redirect.get("url", ""))[:2048],
                     redirect.get("status"), str(redirect.get("location") or "")[:2048]),
                )
            headers = data.get("headers", {})
            if isinstance(headers, dict):
                connection.executemany(
                    "INSERT INTO response_headers(result_id,name,value) VALUES(?,?,?)",
                    [(str(k)[:100], str(v)[:2000]) for k, v in headers.items()],
                )
            connection.execute(
                "UPDATE agent_tasks SET status='completed',finished_at=? WHERE id=?",
                (now, task_id),
            )
            connection.execute(
                "UPDATE agents SET status='online',last_heartbeat=? WHERE id=?",
                (now, agent_id),
            )
            if classification == "access_denied":
                connection.execute(
                    "INSERT INTO alerts(target_id,result_id,kind,message,created_at) VALUES(?,?,?,?,?)",
                    (task["target_id"], result_id, "http_403",
                     f"HTTP 403 from {task['agent_name']} ({task['country_code']}); recorded without retrying or bypassing the restriction.", now),
                )
            job = connection.execute("SELECT * FROM probe_jobs WHERE id=?", (task["job_id"],)).fetchone()
            agent_ids = json.loads(job["agent_ids"])
            next_index = job["current_index"] + 1
            if not job["paused"] and next_index < len(agent_ids):
                sequence = connection.execute(
                    "SELECT COALESCE(MAX(sequence),0)+1 FROM agent_tasks WHERE job_id=?",
                    (job["id"],),
                ).fetchone()[0]
                queue_task(connection, job, agent_ids[next_index], sequence)
                connection.execute(
                    "UPDATE probe_jobs SET current_index=? WHERE id=?", (next_index, job["id"])
                )
            else:
                run_status = (
                    "paused" if job["paused"]
                    else "scheduled" if job["schedule_interval"]
                    else "completed"
                )
                next_run = (
                    (datetime.now(timezone.utc) + timedelta(seconds=job["schedule_interval"])).isoformat()
                    if run_status == "scheduled" else None
                )
                connection.execute(
                    """UPDATE probe_jobs SET status=?,ended_at=?,next_run_at=?,
                       last_success_at=CASE WHEN ?='success' THEN ? ELSE last_success_at END,
                       last_failure_at=CASE WHEN ?='error' THEN ? ELSE last_failure_at END
                       WHERE id=?""",
                    (run_status, now, next_run, status, now, status, now, job["id"]),
                )
            return jsonify({"status": "stored", "result_id": result_id})

    def scheduler_loop():
        while True:
            try:
                with db.connect() as connection:
                    now = utcnow()
                    due = connection.execute(
                        """SELECT id FROM probe_jobs WHERE schedule_interval IS NOT NULL
                           AND paused=0 AND status='scheduled' AND next_run_at<=? ORDER BY next_run_at""",
                        (now,),
                    ).fetchall()
                    for row in due:
                        begin_job(connection, row["id"])
                    stale = connection.execute(
                        """SELECT q.*,j.target_id,j.agent_ids,j.current_index,j.schedule_interval,j.paused,
                                  j.timeout,j.retries,
                                  a.country_code,a.name AS agent_name,a.public_ip,t.url
                           FROM agent_tasks q JOIN probe_jobs j ON j.id=q.job_id
                           JOIN agents a ON a.id=q.agent_id JOIN targets t ON t.id=j.target_id
                           WHERE q.status='running'""",
                    ).fetchall()
                    for task in stale:
                        task_timeout = task["timeout"] * (task["retries"] + 1) + 60
                        if datetime.now(timezone.utc) - datetime.fromisoformat(task["started_at"]) < timedelta(seconds=task_timeout):
                            continue
                        connection.execute(
                            "UPDATE agent_tasks SET status='failed',finished_at=?,error='Agent task timed out' WHERE id=?",
                            (now, task["id"]),
                        )
                        connection.execute(
                            """INSERT INTO probe_results(job_id,target_id,agent_id,country_code,agent_name,
                               public_ip,timestamp,status,classification,error)
                               VALUES(?,?,?,?,?,?,?,'error','agent_error','Agent did not complete the probe.')""",
                            (task["job_id"], task["target_id"], task["agent_id"], task["country_code"],
                             task["agent_name"], task["public_ip"], now),
                        )
                        job = connection.execute("SELECT * FROM probe_jobs WHERE id=?", (task["job_id"],)).fetchone()
                        ids = json.loads(job["agent_ids"])
                        next_index = job["current_index"] + 1
                        if not job["paused"] and next_index < len(ids):
                            sequence = connection.execute(
                                "SELECT COALESCE(MAX(sequence),0)+1 FROM agent_tasks WHERE job_id=?",
                                (job["id"],),
                            ).fetchone()[0]
                            queue_task(connection, job, ids[next_index], sequence)
                            connection.execute(
                                "UPDATE probe_jobs SET current_index=? WHERE id=?", (next_index, job["id"])
                            )
                        else:
                            connection.execute(
                                "UPDATE probe_jobs SET status='failed',ended_at=?,last_failure_at=?,error='Agent task timed out' WHERE id=?",
                                (now, now, job["id"]),
                            )
            except Exception:
                app.logger.exception("Scheduler iteration failed")
            time.sleep(2)

    if app.config["START_SCHEDULER"]:
        threading.Thread(target=scheduler_loop, daemon=True, name="monitor-scheduler").start()
    return app


app = create_app()


if __name__ == "__main__":
    if not app.config["DASHBOARD_TOKEN"]:
        app.logger.warning("DASHBOARD_TOKEN is unset; API authentication is disabled.")
    app.run(host=os.environ.get("DASHBOARD_HOST", "127.0.0.1"),
            port=int(os.environ.get("PORT", "5000")), debug=False, use_reloader=False)

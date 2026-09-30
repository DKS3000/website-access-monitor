const tokenInput = document.querySelector("#dashboardToken");
tokenInput.value = localStorage.getItem("dashboardToken") || "";
tokenInput.addEventListener("change", () => {
  localStorage.setItem("dashboardToken", tokenInput.value);
  refresh();
});

async function api(path, options = {}) {
  const headers = {...(options.headers || {}), "Content-Type": "application/json"};
  if (tokenInput.value) headers["X-Dashboard-Token"] = tokenInput.value;
  const response = await fetch(path, {...options, headers});
  if (response.status === 204) return null;
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || `Request failed (${response.status})`);
  return data;
}
function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
}
function showError(error) { window.alert(error.message || String(error)); }
function selectedTarget() { return document.querySelector("#historyTarget").value; }

async function refresh() {
  try {
    const [targets, agents, jobs, countries] = await Promise.all([
      api("/api/targets"), api("/api/agents"), api("/api/jobs"), api("/api/countries")
    ]);
    renderTargets(targets);
    renderAgents(agents);
    renderJobs(jobs);
    if (!document.querySelector("#agentCountry").options.length) {
      document.querySelector("#agentCountry").innerHTML = countries.map(c => `<option value="${escapeHtml(c.code)}">${escapeHtml(c.name)} (${escapeHtml(c.code)})</option>`).join("");
    }
    if (!selectedTarget() && targets.length) {
      const options = targets.filter(t => t.enabled).map(t => `<option value="${t.id}">${escapeHtml(t.name || t.url)}</option>`).join("");
      document.querySelector("#historyTarget").innerHTML = options;
    }
    if (!document.querySelector("#jobTarget").options.length) {
      document.querySelector("#jobTarget").innerHTML = targets.filter(t => t.enabled).map(t => `<option value="${t.id}">${escapeHtml(t.name || t.url)}</option>`).join("");
    }
    if (selectedTarget()) await refreshResults();
  } catch (error) { showError(error); }
}

function renderTargets(targets) {
  document.querySelector("#targets").innerHTML = targets.map(t => `
    <div class="item"><div><strong>${escapeHtml(t.name || t.url)}</strong><br><small>${escapeHtml(t.url)} · ${t.enabled ? "enabled" : "disabled"}</small></div>
    <span class="target-actions"><button data-action="edit-target" data-id="${t.id}">Edit</button>
    <button data-action="toggle-target" data-id="${t.id}" data-enabled="${t.enabled ? 0 : 1}">${t.enabled ? "Disable" : "Enable"}</button>
    <button data-action="delete-target" data-id="${t.id}">Delete</button></span></div>`).join("") || '<p class="muted">No targets added.</p>';
  const enabled = targets.filter(t => t.enabled);
  const options = enabled.map(t => `<option value="${t.id}">${escapeHtml(t.name || t.url)}</option>`).join("");
  const targetSelect = document.querySelector("#jobTarget");
  const historySelect = document.querySelector("#historyTarget");
  const oldTarget = targetSelect.value;
  const oldHistory = historySelect.value;
  targetSelect.innerHTML = options;
  historySelect.innerHTML = options;
  if (enabled.some(t => String(t.id) === oldTarget)) targetSelect.value = oldTarget;
  if (enabled.some(t => String(t.id) === oldHistory)) historySelect.value = oldHistory;
}

function renderAgents(agents) {
  const selected = new Set([...document.querySelectorAll("#agentChoices input:checked")].map(input => input.value));
  document.querySelector("#agents").innerHTML = agents.map(a => `
    <div class="item"><div><strong>${escapeHtml(a.name)}</strong> · ${escapeHtml(a.country)} (${escapeHtml(a.country_code)})<br>
    <small>${escapeHtml(a.route_type)} · ${escapeHtml(a.public_ip || "public IP not configured")} · ${escapeHtml(a.status)}${a.last_heartbeat ? ` · heartbeat ${escapeHtml(a.last_heartbeat)}` : ""}</small></div>
    <button data-action="toggle-agent" data-id="${a.id}" data-enabled="${a.enabled ? 0 : 1}">${a.enabled ? "Disable" : "Enable"}</button></div>`).join("") || '<p class="muted">Enroll and start an agent on each VPS/vantage point.</p>';
  document.querySelector("#agentChoices").innerHTML = agents.filter(a => a.enabled).map(a =>
    `<label><input type="checkbox" value="${a.id}" ${selected.has(String(a.id)) ? "checked" : ""}> ${escapeHtml(a.country)} · ${escapeHtml(a.name)}</label>`
  ).join("") || '<span class="muted">Add an agent before running probes.</span>';
}

function renderJobs(jobs) {
  document.querySelector("#jobs").innerHTML = jobs.slice(0, 10).map(j => `
    <div class="item"><div><strong>Job #${j.id} · ${escapeHtml(j.target_name || j.target_url)}</strong><br>
    <small>${escapeHtml(j.status)} · started ${escapeHtml(j.started_at || "not yet")} · schedule ${j.schedule_interval ? `every ${j.schedule_interval}s` : "once"}${j.error ? ` · ${escapeHtml(j.error)}` : ""}</small></div>
    <span class="job-actions">${j.paused ? `<button data-action="resume-job" data-id="${j.id}">Resume</button>` : ["running","scheduled","queued"].includes(j.status) ? `<button data-action="pause-job" data-id="${j.id}">Pause</button>` : ""}
    <button data-action="retry-job" data-id="${j.id}">Run again</button></span></div>`).join("") || '<p class="muted">No probe jobs yet.</p>';
}

function renderChart(results) {
  const canvas = document.querySelector("#latencyChart");
  const context = canvas.getContext("2d");
  const width = canvas.clientWidth || 800;
  const height = 180;
  const ratio = window.devicePixelRatio || 1;
  canvas.width = width * ratio;
  canvas.height = height * ratio;
  context.scale(ratio, ratio);
  context.clearRect(0, 0, width, height);
  const values = results.filter(r => r.response_time_ms != null).slice().reverse();
  if (!values.length) {
    context.fillStyle = "#718096";
    context.fillText("Latency history appears after the first completed probe.", 14, 30);
    return;
  }
  const max = Math.max(...values.map(r => r.response_time_ms), 1);
  context.strokeStyle = "#d9e1ef";
  context.beginPath(); context.moveTo(35, 12); context.lineTo(35, height - 28); context.lineTo(width - 10, height - 28); context.stroke();
  context.strokeStyle = "#2d63cb";
  context.lineWidth = 2;
  context.beginPath();
  values.forEach((r, index) => {
    const x = 38 + index * ((width - 54) / Math.max(values.length - 1, 1));
    const y = height - 30 - (r.response_time_ms / max) * (height - 55);
    if (!index) context.moveTo(x, y); else context.lineTo(x, y);
  });
  context.stroke();
  context.fillStyle = "#526078"; context.font = "11px system-ui";
  context.fillText(`${Math.round(max)} ms max`, 8, 12);
}

async function refreshResults() {
  const results = await api(`/api/results?target_id=${encodeURIComponent(selectedTarget())}&limit=200`);
  const tbody = document.querySelector("#results");
  tbody.innerHTML = results.map(r => `<tr>
    <td>${escapeHtml(new Date(r.timestamp).toLocaleString())}</td>
    <td>${escapeHtml(r.country || "Unknown")} · ${escapeHtml(r.agent_name || "Agent")}</td>
    <td>${r.http_status ?? "—"}</td><td>${r.response_time_ms == null ? "—" : `${escapeHtml(r.response_time_ms)} ms`}</td>
    <td>${escapeHtml(r.classification)}</td><td>${r.redirect_count}</td>
    <td><button data-action="details" data-id="${r.id}">View details</button>
    ${r.status === "success" ? `<a target="_blank" rel="noopener noreferrer" href="${escapeHtml(r.target_url)}">Open Page</a>` : ""}</td></tr>`).join("") || '<tr><td colspan="7" class="muted">No results for this target yet.</td></tr>';
  const counts = {reachable: 0, denied: 0, failures: 0};
  for (const r of results) {
    if (r.classification === "reachable") counts.reachable++;
    else if (r.classification === "access_denied") counts.denied++;
    else counts.failures++;
  }
  const latestByCountry = new Map();
  for (const r of results) if (r.country && !latestByCountry.has(r.country)) latestByCountry.set(r.country, r);
  const has403 = [...latestByCountry.values()].some(r => r.http_status === 403);
  const hasSuccess = [...latestByCountry.values()].some(r => r.status === "success");
  const insight = has403 && hasSuccess ? '<span class="badge danger">Route-specific difference detected: successful and HTTP 403 routes coexist. Compare DNS, TLS, headers, and egress IP; no bypass is attempted.</span>' : "";
  document.querySelector("#summary").innerHTML = `
    <span class="badge success">Reachable<strong>${counts.reachable}</strong></span>
    <span class="badge danger">HTTP 403<strong>${counts.denied}</strong></span>
    <span class="badge">Other failures<strong>${counts.failures}</strong></span>${insight}`;
  renderChart(results);
  tbody.querySelectorAll('[data-action="details"]').forEach(button => button.addEventListener("click", () => {
    const item = results.find(r => String(r.id) === button.dataset.id);
    document.querySelector("#detailBody").textContent = JSON.stringify(item, null, 2);
    document.querySelector("#details").showModal();
  }));
}

document.querySelector("#targetForm").addEventListener("submit", async event => {
  event.preventDefault();
  try {
    await api("/api/targets", {method: "POST", body: JSON.stringify({
      name: document.querySelector("#targetName").value, url: document.querySelector("#targetUrl").value
    })});
    event.target.reset(); await refresh();
  } catch (error) { showError(error); }
});

document.querySelector("#agentRoute").addEventListener("change", event => {
  document.querySelector("#agentProxy").required = event.target.value === "proxy";
});
document.querySelector("#agentForm").addEventListener("submit", async event => {
  event.preventDefault();
  try {
    const created = await api("/api/agents", {method: "POST", body: JSON.stringify({
      name: document.querySelector("#agentName").value,
      country_code: document.querySelector("#agentCountry").value,
      route_type: document.querySelector("#agentRoute").value,
      proxy_url: document.querySelector("#agentProxy").value,
      public_ip: document.querySelector("#agentIp").value
    })});
    const enrollment = document.querySelector("#enrollment");
    enrollment.classList.remove("hidden");
    enrollment.textContent = `Save this token now; it is shown only once. Agent ID: ${created.agent.id}; country: ${created.agent.country}; token: ${created.token}. On the VPS install the project dependencies, then set PROBE_AGENT_TOKEN to this token and run: python agent/probe_agent.py --central-url https://YOUR-DASHBOARD --agent-id ${created.agent.id}`;
    event.target.reset(); await refresh();
  } catch (error) { showError(error); }
});

document.querySelector("#jobForm").addEventListener("submit", async event => {
  event.preventDefault();
  const agentIds = [...document.querySelectorAll("#agentChoices input:checked")].map(input => Number(input.value));
  try {
    await api("/api/jobs", {method: "POST", body: JSON.stringify({
      target_id: Number(document.querySelector("#jobTarget").value),
      agent_ids: agentIds,
      timeout: Number(document.querySelector("#timeout").value),
      retries: 1,
      schedule_interval: document.querySelector("#schedule").value
    })});
    await refresh();
  } catch (error) { showError(error); }
});

document.body.addEventListener("click", async event => {
  const button = event.target.closest("[data-action]");
  if (!button) return;
  try {
    const {action, id} = button.dataset;
    if (action === "edit-target") {
      const current = await api("/api/targets");
      const target = current.find(t => String(t.id) === id);
      const url = window.prompt("Public HTTP(S) URL", target.url);
      if (url) await api(`/api/targets/${id}`, {method: "PATCH", body: JSON.stringify({url})});
    } else if (action === "toggle-target") {
      await api(`/api/targets/${id}`, {method: "PATCH", body: JSON.stringify({enabled: button.dataset.enabled === "1"})});
    } else if (action === "delete-target") {
      if (window.confirm("Delete this target? Targets with saved history must be disabled instead.")) await api(`/api/targets/${id}`, {method: "DELETE"});
    } else if (action === "toggle-agent") {
      await api(`/api/agents/${id}`, {method: "PATCH", body: JSON.stringify({enabled: button.dataset.enabled === "1"})});
    } else if (action === "pause-job" || action === "resume-job" || action === "retry-job") {
      const suffix = action.replace("-job", "");
      await api(`/api/jobs/${id}/${suffix}`, {method: "POST", body: "{}"});
    }
    await refresh();
  } catch (error) { showError(error); }
});

document.querySelector("#historyTarget").addEventListener("change", () => refreshResults().catch(showError));
document.querySelector("#closeDetails").addEventListener("click", () => document.querySelector("#details").close());
window.addEventListener("resize", () => refreshResults().catch(() => {}));
refresh();
setInterval(refresh, 5000);

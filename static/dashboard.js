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

function updateClock() {
  const el = document.querySelector("#clock");
  if (el) el.textContent = new Date().toLocaleString();
}
updateClock();
setInterval(updateClock, 1000);

function renderGauges(agents, results) {
  const el = document.querySelector("#agentGauges");
  if (!el) return;
  const enabled = agents.filter(a => a.enabled).slice(0, 4);
  if (!enabled.length) { el.innerHTML = '<div class="gauge empty"><div class="g-label">Agents</div><div class="g-value">0</div><div class="g-sub">none enrolled</div></div>'; return; }
  el.innerHTML = enabled.map(a => {
    const own = results.filter(r => r.agent_name === a.name);
    const total = own.length;
    const ok = own.filter(r => r.classification === "reachable").length;
    const pct = total ? Math.round((ok / total) * 100) : null;
    const staleClass = pct === null ? "empty" : pct < 100 ? "stale" : "";
    return `<div class="gauge ${staleClass}"><div class="g-label">${escapeHtml(a.name)}</div>
      <div class="g-value">${pct === null ? "—" : `${pct}%`}</div>
      <div class="g-sub">${escapeHtml(a.country_code || "")} · ${ok}/${total} reachable</div></div>`;
  }).join("");
}

let lastAgents = [];

async function refresh() {
  try {
    const [targets, agents, jobs, countries] = await Promise.all([
      api("/api/targets"), api("/api/agents"), api("/api/jobs"), api("/api/countries")
    ]);
    lastAgents = agents;
    renderTargets(targets);
    renderAgents(agents);
    renderJobs(jobs);
    if (!selectedTarget()) renderGauges(agents, []);
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

function routeLabel(a) {
  if (a.route_type === "vpn") return `vpn · ${escapeHtml(a.vpn_provider || "?")} → ${escapeHtml(a.country_code)}`;
  if (a.route_type === "proxy") return "proxy";
  return "direct";
}

function vpnStatus(a) {
  if (a.route_type !== "vpn") return "";
  const stateLabel = escapeHtml((a.vpn_state || "disconnected").replace(/_/g, " "));
  let extra = "";
  if (a.vpn_state === "connected" && a.vpn_verified_country) {
    extra = ` · verified egress ${escapeHtml(a.vpn_verified_country)}${a.vpn_verified_ip ? ` (${escapeHtml(a.vpn_verified_ip)})` : ""}`;
  } else if (a.vpn_state === "failed" && a.vpn_last_error) {
    extra = ` · ${escapeHtml(a.vpn_last_error)}`;
  }
  return ` · vpn: ${stateLabel}${extra}`;
}

function renderAgents(agents) {
  const selected = new Set([...document.querySelectorAll("#agentChoices input:checked")].map(input => input.value));
  document.querySelector("#agents").innerHTML = agents.map(a => `
    <div class="item"><div><strong>${escapeHtml(a.name)}</strong> · ${escapeHtml(a.country)} (${escapeHtml(a.country_code)})<br>
    <small>${routeLabel(a)} · ${escapeHtml(a.public_ip || "public IP not configured")} · ${escapeHtml(a.status)}${a.last_heartbeat ? ` · heartbeat ${escapeHtml(a.last_heartbeat)}` : ""}${vpnStatus(a)}</small></div>
    <span class="target-actions">${a.route_type === "vpn" ? `<button data-action="connect-vpn" data-id="${a.id}" ${a.vpn_state === "connected" || a.vpn_state === "connecting" ? "disabled" : ""}>Connect VPN</button>
    <button data-action="disconnect-vpn" data-id="${a.id}" ${a.vpn_state === "disconnected" ? "disabled" : ""}>Disconnect VPN</button>` : ""}
    <button data-action="edit-agent" data-id="${a.id}">Edit</button>
    <button data-action="toggle-agent" data-id="${a.id}" data-enabled="${a.enabled ? 0 : 1}">${a.enabled ? "Disable" : "Enable"}</button></span></div>`).join("") || '<p class="muted">Enroll and start an agent on each VPS/vantage point.</p>';
  document.querySelector("#agentChoices").innerHTML = agents.filter(a => a.enabled).map(a =>
    `<label><input type="checkbox" value="${a.id}" ${selected.has(String(a.id)) ? "checked" : ""}> ${escapeHtml(a.country)} · ${escapeHtml(a.name)}</label>`
  ).join("") || '<span class="muted">Add an agent before running probes.</span>';
}

function jobStatusLabel(status) {
  return escapeHtml((status || "").replace(/_/g, " "));
}

function renderJobs(jobs) {
  document.querySelector("#jobs").innerHTML = jobs.slice(0, 10).map(j => `
    <div class="item"><div><strong>Job #${j.id} · ${escapeHtml(j.target_name || j.target_url)}</strong><br>
    <small>${jobStatusLabel(j.status)} · started ${escapeHtml(j.started_at || "not yet")} · schedule ${j.schedule_interval ? `every ${j.schedule_interval}s` : "once"}${j.error ? ` · ${escapeHtml(j.error)}` : ""}</small></div>
    <span class="job-actions">${j.paused ? `<button data-action="resume-job" data-id="${j.id}">Resume</button>` : ["running","scheduled","queued","waiting_for_vpn","verifying_vpn"].includes(j.status) ? `<button data-action="pause-job" data-id="${j.id}">Pause</button>` : ""}
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
  const groups = new Map();
  for (const result of results.filter(r => r.response_time_ms != null).slice().reverse()) {
    const label = `${result.country || "Unknown"} · ${result.agent_name || "Agent"}`;
    if (!groups.has(label)) groups.set(label, []);
    groups.get(label).push(result);
  }
  if (!groups.size) {
    context.fillStyle = "#718096";
    context.fillText("Latency history appears after the first completed probe.", 14, 30);
    return;
  }
  const max = Math.max(...[...groups.values()].flat().map(r => r.response_time_ms), 1);
  context.strokeStyle = "#d9e1ef";
  context.beginPath(); context.moveTo(35, 12); context.lineTo(35, height - 28); context.lineTo(width - 10, height - 28); context.stroke();
  const colors = ["#2d63cb", "#16855b", "#cb6b26", "#a34fb0", "#dc3f54", "#078b9c"];
  context.lineWidth = 2;
  [...groups.entries()].forEach(([label, values], groupIndex) => {
    context.strokeStyle = colors[groupIndex % colors.length];
    context.beginPath();
    values.forEach((r, index) => {
      const x = 38 + index * ((width - 54) / Math.max(values.length - 1, 1));
      const y = height - 30 - (r.response_time_ms / max) * (height - 55);
      if (!index) context.moveTo(x, y); else context.lineTo(x, y);
    });
    context.stroke();
    context.fillStyle = colors[groupIndex % colors.length];
    context.font = "11px system-ui";
    context.fillText(label, 45 + (groupIndex % 3) * (width / 3), 16 + Math.floor(groupIndex / 3) * 13);
  });
  context.fillStyle = "#526078"; context.font = "11px system-ui";
  context.fillText(`${Math.round(max)} ms max`, 8, 12);
}

async function refreshResults() {
  const results = await api(`/api/results?target_id=${encodeURIComponent(selectedTarget())}&limit=200`);
  const tbody = document.querySelector("#results");
  tbody.innerHTML = results.map(r => `<tr data-classification="${escapeHtml(r.classification)}">
    <td>${escapeHtml(new Date(r.timestamp).toLocaleString())}</td>
    <td>${escapeHtml(r.country || "Unknown")} · ${escapeHtml(r.agent_name || "Agent")}</td>
    <td>${r.http_status ?? "—"}</td><td>${r.response_time_ms == null ? "—" : `${escapeHtml(r.response_time_ms)} ms`}</td>
    <td>${escapeHtml(r.classification)}</td><td>${r.redirect_count}</td>
    <td><button data-action="details" data-id="${r.id}">View details</button>
    ${r.status === "success" ? `<a target="_blank" rel="noopener noreferrer" href="${escapeHtml(r.target_url)}">Open Page</a>` : ""}</td></tr>`).join("") || '<tr><td colspan="7" class="muted">No results for this target yet.</td></tr>';
  const counts = {reachable: 0, denied: 0, failures: 0};
  const statusCounts = new Map();
  const routeStats = new Map();
  for (const r of results) {
    if (r.classification === "reachable") counts.reachable++;
    else if (r.classification === "access_denied") counts.denied++;
    else counts.failures++;
    const statusKey = r.http_status == null ? "Network error" : `HTTP ${r.http_status}`;
    statusCounts.set(statusKey, (statusCounts.get(statusKey) || 0) + 1);
    const route = `${r.country || "Unknown"} · ${r.agent_name || "Agent"}`;
    if (!routeStats.has(route)) routeStats.set(route, {total: 0, success: 0, denied: 0, latency: [], redirects: 0});
    const stats = routeStats.get(route);
    stats.total++;
    if (r.status === "success") stats.success++;
    if (r.classification === "access_denied") stats.denied++;
    if (r.response_time_ms != null) stats.latency.push(r.response_time_ms);
    stats.redirects += r.redirect_count || 0;
  }
  const latestByCountry = new Map();
  for (const r of results) if (r.country && !latestByCountry.has(r.country)) latestByCountry.set(r.country, r);
  const has403 = [...latestByCountry.values()].some(r => r.http_status === 403);
  const hasSuccess = [...latestByCountry.values()].some(r => r.status === "success");
  const insight = has403 && hasSuccess ? '<span class="badge danger">Route-specific difference detected: successful and HTTP 403 routes coexist. Compare DNS, TLS, headers, and egress IP; no bypass is attempted.</span>' : "";
  const availability = results.length ? ((counts.reachable / results.length) * 100).toFixed(1) : "0.0";
  document.querySelector("#summary").innerHTML = `
    <span class="badge">Availability<strong>${availability}%</strong></span>
    <span class="badge success">Reachable<strong>${counts.reachable}</strong></span>
    <span class="badge danger">HTTP 403<strong>${counts.denied}</strong></span>
    <span class="badge">Other failures<strong>${counts.failures}</strong></span>
    ${[...statusCounts.entries()].map(([status, count]) => `<span class="badge">${escapeHtml(status)}<strong>${count}</strong></span>`).join("")}${insight}`;
  document.querySelector("#routeComparison").innerHTML = [...routeStats.entries()].map(([route, stats]) => `
    <tr><td>${escapeHtml(route)}</td><td>${((stats.success / stats.total) * 100).toFixed(1)}% (${stats.success}/${stats.total})</td>
    <td>${stats.latency.length ? `${Math.round(stats.latency.reduce((a, b) => a + b, 0) / stats.latency.length)} ms` : "—"}</td>
    <td>${stats.denied}</td><td>${stats.redirects}</td></tr>`).join("") || '<tr><td colspan="5" class="muted">No route history yet.</td></tr>';
  renderChart(results);
  renderGauges(lastAgents, results);
  document.querySelector("#counters").innerHTML = `
    <div class="counter c-blue">Checked<strong>${results.length}</strong></div>
    <div class="counter c-green">Reachable<strong>${counts.reachable}</strong></div>
    <div class="counter c-red">Denied / failed<strong>${counts.denied + counts.failures}</strong></div>`;
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

function toggleRouteFields(routeValue, proxyInput, vpnSelect) {
  proxyInput.required = routeValue === "proxy";
  proxyInput.classList.toggle("hidden", routeValue !== "proxy");
  vpnSelect.classList.toggle("hidden", routeValue !== "vpn");
}

document.querySelector("#agentRoute").addEventListener("change", event => {
  toggleRouteFields(event.target.value, document.querySelector("#agentProxy"), document.querySelector("#agentVpnProvider"));
});
document.querySelector("#editAgentRoute").addEventListener("change", event => {
  toggleRouteFields(event.target.value, document.querySelector("#editAgentProxy"), document.querySelector("#editAgentVpnProvider"));
});
document.querySelector("#agentForm").addEventListener("submit", async event => {
  event.preventDefault();
  try {
    const created = await api("/api/agents", {method: "POST", body: JSON.stringify({
      name: document.querySelector("#agentName").value,
      country_code: document.querySelector("#agentCountry").value,
      route_type: document.querySelector("#agentRoute").value,
      proxy_url: document.querySelector("#agentProxy").value,
      vpn_provider: document.querySelector("#agentVpnProvider").value,
      public_ip: document.querySelector("#agentIp").value
    })});
    const enrollment = document.querySelector("#enrollment");
    enrollment.classList.remove("hidden");
    enrollment.textContent = `Save this token now; it is shown only once. Agent ID: ${created.agent.id}; country: ${created.agent.country}; token: ${created.token}. On the VPS install the project dependencies, then set PROBE_AGENT_TOKEN to this token and run: python agent/probe_agent.py --central-url https://YOUR-DASHBOARD --agent-id ${created.agent.id}`;
    event.target.reset(); await refresh();
  } catch (error) { showError(error); }
});

document.querySelector("#editAgentForm").addEventListener("submit", async event => {
  event.preventDefault();
  const id = document.querySelector("#editAgentId").value;
  try {
    await api(`/api/agents/${id}`, {method: "PATCH", body: JSON.stringify({
      name: document.querySelector("#editAgentName").value,
      country_code: document.querySelector("#editAgentCountry").value,
      route_type: document.querySelector("#editAgentRoute").value,
      proxy_url: document.querySelector("#editAgentProxy").value,
      vpn_provider: document.querySelector("#editAgentVpnProvider").value
    })});
    document.querySelector("#editAgentDialog").close();
    await refresh();
  } catch (error) { showError(error); }
});
document.querySelector("#closeEditAgent").addEventListener("click", () => document.querySelector("#editAgentDialog").close());

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
    } else if (action === "connect-vpn") {
      await api(`/api/agents/${id}/vpn/connect`, {method: "POST", body: "{}"});
    } else if (action === "disconnect-vpn") {
      await api(`/api/agents/${id}/vpn/disconnect`, {method: "POST", body: "{}"});
    } else if (action === "edit-agent") {
      const agent = lastAgents.find(a => String(a.id) === id);
      if (!agent) return;
      document.querySelector("#editAgentId").value = agent.id;
      document.querySelector("#editAgentName").value = agent.name;
      document.querySelector("#editAgentCountry").innerHTML = document.querySelector("#agentCountry").innerHTML;
      document.querySelector("#editAgentCountry").value = agent.country_code;
      document.querySelector("#editAgentRoute").value = agent.route_type;
      document.querySelector("#editAgentProxy").value = agent.proxy_url || "";
      if (agent.vpn_provider) document.querySelector("#editAgentVpnProvider").value = agent.vpn_provider;
      toggleRouteFields(agent.route_type, document.querySelector("#editAgentProxy"), document.querySelector("#editAgentVpnProvider"));
      document.querySelector("#editAgentDialog").showModal();
      return;
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
toggleRouteFields(document.querySelector("#agentRoute").value, document.querySelector("#agentProxy"), document.querySelector("#agentVpnProvider"));
refresh();
setInterval(refresh, 5000);

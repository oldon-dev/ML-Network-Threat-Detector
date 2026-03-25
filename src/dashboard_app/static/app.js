const state = {
  payload: null,
  autoRefresh: true,
};

async function fetchDashboard() {
  const response = await fetch("/api/dashboard");
  if (!response.ok) {
    throw new Error("Failed to load dashboard state");
  }
  state.payload = await response.json();
  render();
}

async function postJson(url, payload = {}) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  const data = await response.json();
  if (!response.ok) {
    throw new Error(data.error || "Request failed");
  }
  return data;
}

function render() {
  const payload = state.payload;
  if (!payload) {
    return;
  }

  renderMonitor(payload.monitor);
  renderStats(payload);
  renderCharts(payload.summary);
  renderAlerts(payload.recent_alerts);
  renderFlows(payload.recent_flows);
  renderJobs(payload.analysis_jobs);
  renderSettings(payload.settings);
  renderDatasets(payload.datasets);
  renderInterfaces(payload.interfaces);
  renderConsole(payload.monitor);
}

function renderMonitor(monitor) {
  const badge = document.getElementById("monitorBadge");
  const meta = document.getElementById("monitorMeta");
  const startButton = document.getElementById("startMonitorButton");
  const stopButton = document.getElementById("stopMonitorButton");

  const running = Boolean(monitor && monitor.running);
  badge.textContent = running ? "Live" : "Idle";
  badge.className = `status-pill ${running ? "live" : "neutral"}`;
  startButton.disabled = running;
  stopButton.disabled = !running;

  const details = [
    ["Process", running ? `PID ${monitor.pid}` : "Not running"],
    ["Target", monitor?.interface || monitor?.label || "Auto-select"],
    ["Started", monitor?.started_at || "Waiting"],
    ["Exit Code", monitor?.exit_code ?? "-"],
    ["Uptime", monitor?.status?.uptime || "-"],
    ["Alerts", monitor?.status?.alerts ?? 0],
  ];

  meta.innerHTML = details.map(([label, value]) => (
    `<div class="meta-tile"><span>${escapeHtml(label)}</span><strong>${escapeHtml(String(value))}</strong></div>`
  )).join("");
}

function renderStats(payload) {
  const statsGrid = document.getElementById("statsGrid");
  const monitorStatus = payload.monitor?.status || {};
  const system = payload.system || {};
  const stats = [
    ["Alerts", payload.summary.total_alerts, `${payload.summary.alerts_last_24h} in the last 24h`],
    ["Recent Flows", payload.summary.total_flows, `${formatBytes(payload.summary.traffic_bytes_total)} observed`],
    ["Average Score", payload.summary.average_alert_score, "Binary suspiciousness mean"],
    ["Active Flows", monitorStatus.active_flows ?? 0, "Open flow table entries"],
    ["Packets Seen", monitorStatus.analyzed_packets ?? 0, "Current live runtime counter"],
    ["ML Analyzed", monitorStatus.ml_analyzed_flows ?? 0, "Scored by the detection engine"],
    ["CPU", `${formatPercent(system.cpu_percent)}`, "Host utilization snapshot"],
    ["Memory", `${formatPercent(system.memory_percent)}`, "Host utilization snapshot"],
  ];

  const template = document.getElementById("statCardTemplate");
  statsGrid.innerHTML = "";

  for (const [label, value, note] of stats) {
    const clone = template.content.cloneNode(true);
    clone.querySelector(".stat-label").textContent = label;
    clone.querySelector(".stat-value").textContent = String(value);
    clone.querySelector(".stat-footnote").textContent = note;
    statsGrid.appendChild(clone);
  }
}

function renderCharts(summary) {
  renderBarList("familyChart", summary.family_counts);
  renderBarList("severityChart", summary.severity_counts, true);
  renderBarList("protocolChart", summary.protocol_counts, true);
  renderBarList("activityChart", summary.activity_series, false, "count");
}

function renderBarList(id, items, compact = false, valueKey = "count") {
  const container = document.getElementById(id);
  const data = items && items.length ? items : [{ label: "No data", count: 0 }];
  const max = Math.max(...data.map((item) => item[valueKey] || 0), 1);

  if (compact) {
    container.classList.add("compact");
  }

  container.innerHTML = data.map((item) => {
    const count = item[valueKey] || 0;
    const width = (count / max) * 100;
    return `
      <div class="bar-row">
        <div class="bar-top">
          <span>${escapeHtml(item.label)}</span>
          <strong>${escapeHtml(String(count))}</strong>
        </div>
        <div class="bar-track"><div class="bar-fill" style="width:${width}%"></div></div>
      </div>
    `;
  }).join("");
}

function renderAlerts(alerts) {
  const list = document.getElementById("alertsList");
  const severityFilter = document.getElementById("severityFilter").value;
  const query = document.getElementById("alertSearch").value.trim().toLowerCase();

  const filtered = alerts.filter((alert) => {
    const matchesSeverity = !severityFilter || alert.severity === severityFilter;
    const haystack = [
      alert.attack_family,
      alert.src_ip,
      alert.dst_ip,
      ...(alert.reasons || []),
    ].join(" ").toLowerCase();
    const matchesQuery = !query || haystack.includes(query);
    return matchesSeverity && matchesQuery;
  });

  if (!filtered.length) {
    list.innerHTML = `<p class="subtle">No alerts match the current filters.</p>`;
    return;
  }

  list.innerHTML = filtered.map((alert) => `
    <article class="alert-card">
      <header>
        <div>
          <h3 class="alert-title">${escapeHtml(alert.attack_family || "unknown")}</h3>
          <p class="subtle">${escapeHtml(alert.timestamp || "")}</p>
        </div>
        <span class="status-pill ${severityPill(alert.severity)}">${escapeHtml(alert.severity || "unknown")}</span>
      </header>
      <div class="mini-meta">
        <span>Score ${Number(alert.score || 0).toFixed(4)}</span>
        <span>Confidence ${Number(alert.confidence || 0).toFixed(3)}</span>
        <span>${escapeHtml(alert.protocol || "OTHER")}</span>
        <span>${escapeHtml(`${alert.src_ip}:${alert.src_port} -> ${alert.dst_ip}:${alert.dst_port}`)}</span>
      </div>
      <div class="reason-list">
        ${(alert.reasons || []).map((reason) => `<span class="reason-chip">${escapeHtml(reason)}</span>`).join("")}
      </div>
    </article>
  `).join("");
}

function renderFlows(flows) {
  const list = document.getElementById("flowList");
  if (!flows.length) {
    list.innerHTML = `<p class="subtle">No flow telemetry available yet.</p>`;
    return;
  }

  list.innerHTML = flows.slice(0, 12).map((flow) => `
    <article class="flow-card">
      <header>
        <div>
          <h3 class="flow-title">${escapeHtml(flow.protocol || "OTHER")} flow</h3>
          <p class="subtle">${escapeHtml(flow.timestamp || "")}</p>
        </div>
        <span class="status-pill neutral">${escapeHtml(flow.source_name || flow.mode || "runtime")}</span>
      </header>
      <div class="mini-meta">
        <span>${escapeHtml(`${flow.src_ip}:${flow.src_port}`)}</span>
        <span>${escapeHtml(`${flow.dst_ip}:${flow.dst_port}`)}</span>
        <span>${flow.packets || 0} packets</span>
        <span>${formatBytes(flow.bytes || 0)}</span>
      </div>
    </article>
  `).join("");
}

function renderJobs(jobs) {
  const list = document.getElementById("jobList");
  if (!jobs.length) {
    list.innerHTML = `<p class="subtle">No dataset analysis jobs launched from the app yet.</p>`;
    return;
  }

  list.innerHTML = jobs.map((job) => `
    <article class="job-card">
      <header>
        <div>
          <h3 class="job-title">${escapeHtml(job.label || "Analysis Job")}</h3>
          <p class="subtle">${escapeHtml(job.started_at || "")}</p>
        </div>
        <span class="status-pill ${job.running ? "busy" : job.exit_code === 0 ? "live" : "danger"}">
          ${job.running ? "Running" : job.exit_code === 0 ? "Complete" : "Stopped"}
        </span>
      </header>
      <div class="mini-meta">
        <span>${escapeHtml(job.dataset_path || "")}</span>
        <span>${job.status?.alerts ?? 0} alerts</span>
        <span>${job.status?.completed_flows ?? 0} flows</span>
        <span>Exit ${job.exit_code ?? "-"}</span>
      </div>
    </article>
  `).join("");
}

function renderSettings(settings) {
  const list = document.getElementById("settingsList");
  list.innerHTML = Object.entries(settings).map(([key, value]) => `
    <div class="setting-row">
      <span>${escapeHtml(key.replaceAll("_", " "))}</span>
      <strong>${escapeHtml(String(value))}</strong>
    </div>
  `).join("");
}

function renderDatasets(datasets) {
  const select = document.getElementById("datasetSelect");
  const current = select.value;
  select.innerHTML = `<option value="">Choose a prepared dataset</option>` + datasets.map((dataset) => `
    <option value="${escapeAttribute(dataset.path)}">${escapeHtml(dataset.name)} (${dataset.size_mb} MB)</option>
  `).join("");
  if ([...select.options].some((option) => option.value === current)) {
    select.value = current;
  }
}

function renderInterfaces(interfaces) {
  const select = document.getElementById("interfaceSelect");
  const current = select.value;
  const options = [`<option value="">Auto-select busiest interface</option>`]
    .concat((interfaces || []).map((iface) => `<option value="${escapeAttribute(iface)}">${escapeHtml(iface)}</option>`));
  select.innerHTML = options.join("");
  if ([...select.options].some((option) => option.value === current)) {
    select.value = current;
  }
}

function renderConsole(monitor) {
  const consoleOutput = document.getElementById("consoleOutput");
  const lines = (monitor?.output_tail || []).filter(Boolean);
  consoleOutput.textContent = lines.length ? lines.join("\n") : "Runtime console output will appear here when monitoring starts.";
}

function severityPill(severity) {
  if (severity === "high") {
    return "danger";
  }
  if (severity === "medium") {
    return "busy";
  }
  if (severity === "low") {
    return "neutral";
  }
  return "neutral";
}

function formatBytes(bytes) {
  const value = Number(bytes || 0);
  if (value >= 1024 * 1024) {
    return `${(value / (1024 * 1024)).toFixed(2)} MB`;
  }
  if (value >= 1024) {
    return `${(value / 1024).toFixed(1)} KB`;
  }
  return `${value} B`;
}

function formatPercent(value) {
  return `${Number(value || 0).toFixed(1)}%`;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function escapeAttribute(value) {
  return escapeHtml(value);
}

function bindEvents() {
  document.getElementById("refreshButton").addEventListener("click", () => {
    fetchDashboard().catch(showError);
  });

  document.getElementById("severityFilter").addEventListener("change", render);
  document.getElementById("alertSearch").addEventListener("input", render);

  document.getElementById("autoRefreshToggle").addEventListener("change", (event) => {
    state.autoRefresh = event.target.checked;
  });

  document.getElementById("startMonitorButton").addEventListener("click", async () => {
    const interfaceName = document.getElementById("interfaceSelect").value;
    try {
      await postJson("/api/monitor/start", { interface: interfaceName });
      await fetchDashboard();
    } catch (error) {
      showError(error);
    }
  });

  document.getElementById("stopMonitorButton").addEventListener("click", async () => {
    try {
      await postJson("/api/monitor/stop", {});
      await fetchDashboard();
    } catch (error) {
      showError(error);
    }
  });

  document.getElementById("runAnalysisButton").addEventListener("click", async () => {
    const selected = document.getElementById("datasetSelect").value;
    const custom = document.getElementById("datasetPathInput").value.trim();
    const datasetPath = custom || selected;

    if (!datasetPath) {
      showError(new Error("Select a dataset or provide a custom path."));
      return;
    }

    try {
      await postJson("/api/analysis/start", { dataset_path: datasetPath });
      await fetchDashboard();
    } catch (error) {
      showError(error);
    }
  });
}

function showError(error) {
  window.alert(error.message || String(error));
}

document.addEventListener("DOMContentLoaded", () => {
  bindEvents();
  fetchDashboard().catch(showError);
  window.setInterval(() => {
    if (state.autoRefresh) {
      fetchDashboard().catch(() => {});
    }
  }, 4000);
});

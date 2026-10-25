/**
 * script.js — AI Incident Investigator frontend logic
 * Vanilla JavaScript, no frameworks.
 */

"use strict";

/* ══════════════════════════════════════════════════════════
   Constants
   ══════════════════════════════════════════════════════════ */
const API_BASE = "";   // Same origin — Flask serves both

/* ══════════════════════════════════════════════════════════
   State
   ══════════════════════════════════════════════════════════ */
let selectedFile = null;
let currentIncidentId = null;
let historyDebounceTimer = null;

/* ══════════════════════════════════════════════════════════
   DOM helpers
   ══════════════════════════════════════════════════════════ */
const $ = (id) => document.getElementById(id);
const show = (el) => el && el.classList.remove("hidden");
const hide = (el) => el && el.classList.add("hidden");
const toggle = (el, condition) =>
  condition ? show(el) : hide(el);

/* ══════════════════════════════════════════════════════════
   Page navigation
   ══════════════════════════════════════════════════════════ */
function navigateTo(pageId, title) {
  // Hide all pages
  document.querySelectorAll(".page").forEach((p) => p.classList.add("hidden"));
  // Show target page
  const target = $(`page-${pageId}`);
  if (target) {
    target.classList.remove("hidden");
    target.classList.add("active");
  }

  // Update nav active state
  document.querySelectorAll(".nav-item").forEach((btn) => {
    btn.classList.remove("active");
    btn.removeAttribute("aria-current");
  });
  const navBtn = $(`nav-${pageId}`);
  if (navBtn) {
    navBtn.classList.add("active");
    navBtn.setAttribute("aria-current", "page");
  }

  // Update header title
  $("page-title").textContent = title || pageId;

  // Close sidebar on mobile
  $("sidebar").classList.remove("open");

  // Page-specific init
  if (pageId === "dashboard") loadDashboard();
  if (pageId === "history")   loadHistory();
}

/* ══════════════════════════════════════════════════════════
   Toast notifications
   ══════════════════════════════════════════════════════════ */
function toast(message, type = "info", duration = 4000) {
  const container = $("toast-container");
  const el = document.createElement("div");
  el.className = `toast ${type}`;
  el.setAttribute("role", "status");
  el.textContent = message;
  container.appendChild(el);
  setTimeout(() => {
    el.style.opacity = "0";
    el.style.transform = "translateX(20px)";
    el.style.transition = "200ms ease";
    setTimeout(() => el.remove(), 200);
  }, duration);
}

/* ══════════════════════════════════════════════════════════
   API helpers
   ══════════════════════════════════════════════════════════ */
async function apiFetch(url, options = {}) {
  const resp = await fetch(API_BASE + url, options);
  const json = await resp.json().catch(() => ({}));
  if (!resp.ok) {
    throw new Error(json.error || `HTTP ${resp.status}`);
  }
  return json;
}

/* ══════════════════════════════════════════════════════════
   Health / model status
   ══════════════════════════════════════════════════════════ */
async function checkHealth() {
  try {
    const data = await apiFetch("/api/health");
    const dot = $("status-dot");
    const label = $("status-label");

    const aiOk = data.ai_model?.available;
    const srchOk = data.search_model?.available;
    const dbOk = data.database?.ok;

    if (dbOk && aiOk && srchOk) {
      dot.className = "status-dot ok";
      label.textContent = "All models ready";
    } else if (dbOk && (aiOk || srchOk)) {
      dot.className = "status-dot partial";
      label.textContent = "Partial AI (fallback)";
    } else if (dbOk) {
      dot.className = "status-dot partial";
      label.textContent = "Rule-based mode";
    } else {
      dot.className = "status-dot error";
      label.textContent = "DB error";
    }
  } catch {
    $("status-dot").className = "status-dot error";
    $("status-label").textContent = "Backend offline";
  }
}

/* ══════════════════════════════════════════════════════════
   Dashboard
   ══════════════════════════════════════════════════════════ */
async function loadDashboard() {
  show($("dashboard-loading"));
  hide($("dashboard-empty"));
  $("dashboard-incident-list").innerHTML = "";

  try {
    const data = await apiFetch("/api/incidents?limit=10");
    hide($("dashboard-loading"));

    // Stats
    const stats = data.stats || {};
    $("stat-total").textContent    = stats.total_incidents   ?? 0;
    $("stat-errors").textContent   = stats.total_errors      ?? 0;
    $("stat-warnings").textContent = stats.total_warnings    ?? 0;
    $("stat-critical").textContent = (stats.critical_count ?? 0) + (stats.high_count ?? 0);

    const incidents = data.incidents || [];
    if (incidents.length === 0) {
      show($("dashboard-empty"));
      return;
    }

    const list = $("dashboard-incident-list");
    incidents.forEach((inc) => {
      list.appendChild(buildIncidentCard(inc));
    });
  } catch (err) {
    hide($("dashboard-loading"));
    toast(`Failed to load dashboard: ${err.message}`, "error");
  }
}

function buildIncidentCard(inc) {
  const card = document.createElement("button");
  card.className = "incident-card";
  card.setAttribute("role", "listitem");
  card.setAttribute("aria-label", `View incident for ${inc.filename}`);
  card.addEventListener("click", () => openIncident(inc.id));

  const when = formatDate(inc.analyzed_at);

  card.innerHTML = `
    <div class="incident-card-meta">
      <div class="incident-card-name">${escHtml(inc.filename)}</div>
      <div class="incident-card-summary">${escHtml(inc.summary || "No summary available")}</div>
    </div>
    <div class="incident-card-stats">
      <span>🔴 ${inc.error_count} errors</span>
      <span>⚠️ ${inc.warn_count} warnings</span>
    </div>
    <span class="severity-badge ${inc.severity || 'INFO'}">${inc.severity || 'INFO'}</span>
    <span class="incident-card-date">${when}</span>
  `;
  return card;
}

/* ══════════════════════════════════════════════════════════
   File upload / analysis (Analyze page)
   ══════════════════════════════════════════════════════════ */
function setupDropZone() {
  const zone = $("drop-zone");
  const fileInput = $("file-input");

  zone.addEventListener("dragover", (e) => {
    e.preventDefault();
    zone.classList.add("drag-over");
  });

  zone.addEventListener("dragleave", () => zone.classList.remove("drag-over"));

  zone.addEventListener("drop", (e) => {
    e.preventDefault();
    zone.classList.remove("drag-over");
    const file = e.dataTransfer?.files?.[0];
    if (file) setSelectedFile(file);
  });

  zone.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") fileInput.click();
  });

  fileInput.addEventListener("change", () => {
    const file = fileInput.files?.[0];
    if (file) setSelectedFile(file);
  });
}

function setSelectedFile(file) {
  // Client-side validation
  const name = file.name.toLowerCase();
  if (!name.endsWith(".log") && !name.endsWith(".txt")) {
    showUploadError("Only .log and .txt files are supported.");
    return;
  }
  if (file.size === 0) {
    showUploadError("The selected file is empty.");
    return;
  }
  if (file.size > 16 * 1024 * 1024) {
    showUploadError("File is too large. Maximum allowed size is 16 MB.");
    return;
  }

  selectedFile = file;
  hideUploadError();
  show($("file-info"));
  $("selected-filename").textContent = file.name;
  $("selected-filesize").textContent = formatBytes(file.size);
  $("btn-analyze").disabled = false;

  // Reset results from previous run
  hide($("analysis-results"));
  hide($("analysis-progress-card"));
}

function clearFile() {
  selectedFile = null;
  $("file-input").value = "";
  hide($("file-info"));
  hide($("analysis-results"));
  hide($("upload-error"));
  $("btn-analyze").disabled = true;
}

function showUploadError(msg) {
  const el = $("upload-error");
  el.textContent = msg;
  show(el);
}

function hideUploadError() {
  hide($("upload-error"));
}

async function runAnalysis() {
  if (!selectedFile) return;

  const btn = $("btn-analyze");
  btn.disabled = true;

  hide($("analysis-results"));
  show($("analysis-progress-card"));
  $("progress-label").textContent = "Uploading and analyzing…";

  const formData = new FormData();
  formData.append("file", selectedFile);

  try {
    const data = await fetch(`${API_BASE}/api/analyze`, {
      method: "POST",
      body: formData,
    }).then(async (resp) => {
      const json = await resp.json().catch(() => ({}));
      if (!resp.ok) throw new Error(json.error || `HTTP ${resp.status}`);
      return json;
    });

    hide($("analysis-progress-card"));
    renderAnalysisResults(data);
    show($("analysis-results"));
    currentIncidentId = data.incident_id;
    toast("Analysis complete!", "success");

  } catch (err) {
    hide($("analysis-progress-card"));
    showUploadError(`Analysis failed: ${err.message}`);
    toast(`Analysis failed: ${err.message}`, "error");
  } finally {
    btn.disabled = false;
  }
}

function renderAnalysisResults(data) {
  // Banner
  const sevEl = $("result-severity");
  sevEl.textContent = data.severity || "INFO";
  sevEl.className = `severity-badge ${data.severity || "INFO"}`;

  $("result-filename").textContent = data.filename || "—";
  $("result-summary").textContent  = data.summary  || "—";
  $("result-errors").textContent   = data.error_count   ?? 0;
  $("result-warnings").textContent = data.warn_count    ?? 0;
  $("result-lines").textContent    = data.total_lines   ?? 0;

  // Evidence
  renderEvidence($("evidence-list"), data.evidence || []);

  // Causes
  renderCauses($("cause-list"), data.causes || []);

  // Actions
  renderActions($("action-list"), data.actions || []);

  // Similar
  renderSimilar($("similar-list"), data.similar_incidents || []);

  // Full report
  $("report-text").textContent = data.report || "No report generated.";

  // Method badge
  const mb = $("method-badge");
  if (data.generation_method === "ai+rules") {
    mb.textContent = "AI + Rule-based";
    mb.className = "method-badge ai";
  } else {
    mb.textContent = "Rule-based";
    mb.className = "method-badge rules";
  }

  // Download buttons
  $("btn-download-txt").onclick  = () => downloadReport(data.incident_id, "txt");
  $("btn-download-json").onclick = () => downloadReport(data.incident_id, "json");
}

/* ══════════════════════════════════════════════════════════
   Render helpers
   ══════════════════════════════════════════════════════════ */
function renderEvidence(container, lines) {
  container.innerHTML = "";
  if (!lines || lines.length === 0) {
    container.innerHTML = `<div class="similar-empty">No specific log lines captured as evidence.</div>`;
    return;
  }
  lines.forEach((line) => {
    const el = document.createElement("div");
    el.className = "evidence-item";
    el.setAttribute("role", "listitem");
    el.textContent = line;
    container.appendChild(el);
  });
}

function renderCauses(container, causes) {
  container.innerHTML = "";
  if (!causes || causes.length === 0) {
    container.innerHTML = `<div class="similar-empty">No specific causes identified.</div>`;
    return;
  }
  causes.forEach((cause) => {
    const el = document.createElement("div");
    el.className = "cause-item";
    el.setAttribute("role", "listitem");
    el.textContent = cause;
    container.appendChild(el);
  });
}

function renderActions(container, actions) {
  container.innerHTML = "";
  if (!actions || actions.length === 0) {
    container.innerHTML = `<li class="action-item">No specific actions recommended.</li>`;
    return;
  }
  actions.forEach((action) => {
    const li = document.createElement("li");
    li.className = "action-item";
    li.textContent = action;
    container.appendChild(li);
  });
}

function renderSimilar(container, items) {
  container.innerHTML = "";
  if (!items || items.length === 0) {
    container.innerHTML = `<div class="similar-empty">No similar past incidents found.</div>`;
    return;
  }
  items.forEach((item) => {
    const el = document.createElement("div");
    el.className = "similar-item";
    el.setAttribute("role", "listitem");
    const pct = Math.round((item.similarity_score || 0) * 100);
    el.innerHTML = `
      <div class="similar-header">
        <span class="similar-filename">${escHtml(item.filename || "—")}</span>
        <span class="similar-score">${pct}% similar</span>
        <span class="severity-badge ${item.severity || "INFO"}">${item.severity || "INFO"}</span>
      </div>
      <div class="incident-card-summary">${escHtml(item.summary || "")}</div>
      <div class="similar-note">${escHtml(item.note || "")}</div>
    `;
    el.style.cursor = "pointer";
    el.addEventListener("click", () => openIncident(item.incident_id));
    container.appendChild(el);
  });
}

/* ══════════════════════════════════════════════════════════
   History page
   ══════════════════════════════════════════════════════════ */
async function loadHistory(params = {}) {
  show($("history-loading"));
  hide($("history-empty"));
  hide($("history-table"));

  const search   = $("history-search")?.value.trim() || "";
  const severity = $("history-severity")?.value || "";

  const qs = new URLSearchParams();
  if (search)   qs.set("search",   search);
  if (severity) qs.set("severity", severity);
  qs.set("limit", "100");

  try {
    const data = await apiFetch(`/api/incidents?${qs.toString()}`);
    hide($("history-loading"));

    const incidents = data.incidents || [];
    if (incidents.length === 0) {
      show($("history-empty"));
      return;
    }

    const tbody = $("history-tbody");
    tbody.innerHTML = "";
    incidents.forEach((inc) => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>#${inc.id}</td>
        <td>${escHtml(inc.filename)}</td>
        <td><span class="severity-badge ${inc.severity || 'INFO'}">${inc.severity || 'INFO'}</span></td>
        <td style="color:var(--sev-critical)">${inc.error_count}</td>
        <td style="color:var(--sev-medium)">${inc.warn_count}</td>
        <td>${formatDate(inc.analyzed_at)}</td>
        <td>
          <button class="btn btn-secondary btn-sm" aria-label="View incident ${inc.id}">View</button>
        </td>
      `;
      tr.querySelector("button").addEventListener("click", () => openIncident(inc.id));
      tbody.appendChild(tr);
    });

    show($("history-table"));
  } catch (err) {
    hide($("history-loading"));
    toast(`Failed to load history: ${err.message}`, "error");
  }
}

/* ══════════════════════════════════════════════════════════
   Incident detail page
   ══════════════════════════════════════════════════════════ */
async function openIncident(id) {
  navigateTo("detail", `Incident #${id}`);
  $("detail-title").textContent   = `Incident #${id}`;
  $("detail-severity").textContent = "Loading…";
  $("detail-filename").textContent = "…";
  $("detail-summary").textContent  = "";
  $("detail-errors").textContent   = "—";
  $("detail-warnings").textContent = "—";
  $("detail-evidence").innerHTML   = `<div class="loading-state"><div class="spinner"></div><span>Loading…</span></div>`;
  $("detail-causes").innerHTML     = "";
  $("detail-actions").innerHTML    = "";
  $("detail-similar").innerHTML    = "";
  $("detail-report").textContent   = "";

  try {
    const data = await apiFetch(`/api/incidents/${id}?similar=true`);

    // Banner
    const sevEl = $("detail-severity");
    sevEl.textContent = data.severity || "INFO";
    sevEl.className = `severity-badge ${data.severity || "INFO"}`;

    $("detail-filename").textContent = data.filename || "—";
    $("detail-summary").textContent  = data.summary  || "—";
    $("detail-errors").textContent   = data.error_count   ?? 0;
    $("detail-warnings").textContent = data.warn_count    ?? 0;
    $("detail-subtitle").textContent = formatDate(data.analyzed_at);

    renderEvidence($("detail-evidence"), data.evidence || []);
    renderCauses($("detail-causes"), data.causes || []);
    renderActions($("detail-actions"), data.actions || []);
    renderSimilar($("detail-similar"), data.similar_incidents || []);

    $("detail-report").textContent = data.report || "No report available.";

    // Download buttons
    $("detail-dl-txt").onclick  = () => downloadReport(id, "txt");
    $("detail-dl-json").onclick = () => downloadReport(id, "json");

  } catch (err) {
    $("detail-evidence").innerHTML = `<div class="similar-empty" style="color:var(--red)">Failed to load: ${escHtml(err.message)}</div>`;
    toast(`Failed to load incident: ${err.message}`, "error");
  }
}

/* ══════════════════════════════════════════════════════════
   Download report
   ══════════════════════════════════════════════════════════ */
function downloadReport(id, fmt) {
  const a = document.createElement("a");
  a.href = `${API_BASE}/api/incidents/${id}/download?format=${fmt}`;
  a.download = `incident_${id}.${fmt}`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  toast(`Downloading report as .${fmt}…`, "info");
}

/* ══════════════════════════════════════════════════════════
   Utility functions
   ══════════════════════════════════════════════════════════ */
function escHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function formatDate(iso) {
  if (!iso) return "—";
  try {
    const d = new Date(iso.endsWith("Z") ? iso : iso + "Z");
    return d.toLocaleString(undefined, {
      year: "numeric", month: "short", day: "numeric",
      hour: "2-digit", minute: "2-digit",
    });
  } catch { return iso; }
}

function formatBytes(bytes) {
  if (bytes < 1024)          return `${bytes} B`;
  if (bytes < 1024 * 1024)   return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(2)} MB`;
}

/* ══════════════════════════════════════════════════════════
   Bootstrap / event listeners
   ══════════════════════════════════════════════════════════ */
document.addEventListener("DOMContentLoaded", () => {

  // ── Sidebar nav ──────────────────────────────────────────
  document.querySelectorAll(".nav-item[data-page]").forEach((btn) => {
    const page = btn.dataset.page;
    const titles = { dashboard: "Dashboard", analyze: "Analyze Log", history: "Incident History" };
    btn.addEventListener("click", () => navigateTo(page, titles[page]));
  });

  // ── Mobile menu toggle ───────────────────────────────────
  $("menu-toggle").addEventListener("click", () => {
    const sb = $("sidebar");
    sb.classList.toggle("open");
    const expanded = sb.classList.contains("open");
    $("menu-toggle").setAttribute("aria-expanded", String(expanded));
  });

  // ── Header "Analyze Log" button ──────────────────────────
  $("btn-analyze-header").addEventListener("click", () =>
    navigateTo("analyze", "Analyze Log")
  );

  // ── Dashboard action buttons ─────────────────────────────
  $("btn-refresh-dashboard").addEventListener("click", loadDashboard);

  $("btn-first-analyze").addEventListener("click", () =>
    navigateTo("analyze", "Analyze Log")
  );

  // ── Drop zone setup ──────────────────────────────────────
  setupDropZone();

  // ── Analyze button ───────────────────────────────────────
  $("btn-analyze").addEventListener("click", runAnalysis);

  // ── Clear file button ────────────────────────────────────
  $("btn-clear-file").addEventListener("click", clearFile);

  // ── History filters ──────────────────────────────────────
  $("history-search").addEventListener("input", () => {
    clearTimeout(historyDebounceTimer);
    historyDebounceTimer = setTimeout(loadHistory, 350);
  });

  $("history-severity").addEventListener("change", loadHistory);

  // ── Back from detail ─────────────────────────────────────
  $("btn-back-history").addEventListener("click", () =>
    navigateTo("history", "Incident History")
  );

  // ── Initial load ─────────────────────────────────────────
  navigateTo("dashboard", "Dashboard");

  // Poll health every 15 seconds
  checkHealth();
  setInterval(checkHealth, 15_000);
});

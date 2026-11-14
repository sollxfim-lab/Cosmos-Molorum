/* Cosmos Molorum Sentinel — self-contained console. */
"use strict";

if ("scrollRestoration" in history) history.scrollRestoration = "manual";

const state = {
  user: null,
  modules: null,
  timer: null,
  historyFilter: "all",
  libraryQuery: "",
  libraryCategory: "all",
  prefillTarget: "",
  currentScanId: "",
};

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));

const ROUTE_META = {
  overview: { label: "Ikhtisar", nav: "overview" },
  scan: { label: "Pemindaian Baru", nav: "scan" },
  history: { label: "Riwayat", nav: "history" },
  analysis: { label: "Analisis Temuan", nav: "analysis" },
  intel: { label: "Intelijen", nav: "intel" },
  modules: { label: "Pustaka Modul", nav: "modules" },
  audit: { label: "Audit", nav: "audit" },
  scans: { label: "Detail Pemindaian", nav: "history" },
};

const STATUS_LABEL = {
  queued: "Menunggu",
  running: "Berjalan",
  completed: "Selesai",
  cancelled: "Dibatalkan",
  failed: "Gagal",
  pass: "Lulus",
  warn: "Perhatian",
  fail: "Bermasalah",
  info: "Informasi",
  skipped: "Dilewati",
  error: "Galat",
};

const SEVERITY_LABEL = {
  critical: "Kritis",
  high: "Tinggi",
  medium: "Sedang",
  low: "Rendah",
  info: "Info",
};

const OWASP_NAMES = {
  "A01:2021": "Broken Access Control",
  "A02:2021": "Cryptographic Failures",
  "A03:2021": "Injection",
  "A04:2021": "Insecure Design",
  "A05:2021": "Security Misconfiguration",
  "A06:2021": "Vulnerable and Outdated Components",
  "A07:2021": "Identification and Authentication Failures",
  "A08:2021": "Software and Data Integrity Failures",
  "A09:2021": "Security Logging and Monitoring Failures",
  "A10:2021": "Server-Side Request Forgery",
};

const CATEGORY_INDEX = {
  "Transport & DNS": "01",
  "Session & Browser": "02",
  "Exposure & Discovery": "03",
  "Injection & Input": "04",
  "Edge & Defense": "05",
};

const CATEGORY_COPY = {
  "Transport & DNS": "TLS, DNS, autentikasi email, dan postur protokol.",
  "Session & Browser": "Cookie, CORS, cache, framing, dan mixed content.",
  "Exposure & Discovery": "Berkas, metadata, debug, API, dan kebocoran rahasia.",
  "Injection & Input": "Probe non-destruktif untuk injeksi dan penanganan input.",
  "Edge & Defense": "Deteksi perlindungan edge dan kontrol pertahanan.",
};

const ICON = {
  arrow: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 12h14M13 6l6 6-6 6"/></svg>',
  plus: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 5v14M5 12h14"/></svg>',
  score: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 19V9M10 19V5M16 19v-7M22 19H2"/></svg>',
  scan: '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="11" cy="11" r="6.5"/><path d="m16 16 4.5 4.5"/></svg>',
  alert: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3 2.5 20h19z"/><path d="M12 9v5M12 17h.01"/></svg>',
  clock: '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="8.5"/><path d="M12 7.5V12l3 2"/></svg>',
  layers: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3 4 7v10l8 4 8-4V7z"/><path d="m4 7 8 4 8-4M12 11v10"/></svg>',
  orbit: '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="3"/><ellipse cx="12" cy="12" rx="9.2" ry="4" transform="rotate(-26 12 12)"/><ellipse cx="12" cy="12" rx="9.2" ry="4" transform="rotate(38 12 12)"/><circle cx="19.3" cy="7.8" r="1.1"/></svg>',
  print: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M7 8V3h10v5M7 17H5a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/><path d="M7 14h10v7H7z"/></svg>',
  download: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3v12M7.5 10.5 12 15l4.5-4.5M5 20h14"/></svg>',
};

function esc(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

/* Apply dynamic widths and CSS custom properties through the CSSOM so the
   Content-Security-Policy can keep style-src at 'self' (no inline style). */
function applyDynamicStyles(root = document) {
  $$("[data-width]", root).forEach((node) => {
    const value = Number(node.dataset.width);
    const width = Number.isFinite(value) ? Math.max(0, Math.min(100, value)) : 0;
    node.style.width = `${width}%`;
  });
  $$("[data-style]", root).forEach((node) => {
    String(node.dataset.style || "")
      .split(";")
      .forEach((pair) => {
        const index = pair.indexOf(":");
        if (index < 0) return;
        const prop = pair.slice(0, index).trim();
        const value = pair.slice(index + 1).trim();
        if (prop && value) node.style.setProperty(prop, value);
      });
  });
}

function fmtDate(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return esc(value);
  return new Intl.DateTimeFormat("id-ID", {
    day: "2-digit",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  }).format(date);
}

function fmtDuration(ms) {
  const value = Number(ms || 0);
  if (!value) return "0 dtk";
  if (value < 1000) return `${value} mdtk`;
  const seconds = Math.round(value / 1000);
  if (seconds < 60) return `${seconds} dtk`;
  const minutes = Math.floor(seconds / 60);
  return `${minutes} mnt ${String(seconds % 60).padStart(2, "0")} dtk`;
}

function statusBadge(status) {
  const key = String(status || "info").toLowerCase();
  return `<span class="badge badge-${esc(key)}">${esc(STATUS_LABEL[key] || key)}</span>`;
}

function severityBadge(severity) {
  const key = String(severity || "info").toLowerCase();
  return `<span class="badge badge-${esc(key)}">${esc(SEVERITY_LABEL[key] || key)}</span>`;
}

function scoreColor(score) {
  if (score >= 90) return "#6cc4a0";
  if (score >= 75) return "#d8b97f";
  if (score >= 60) return "#e0a172";
  return "#df8b90";
}

function greeting() {
  const hour = new Date().getHours();
  if (hour < 11) return "Selamat pagi";
  if (hour < 15) return "Selamat siang";
  if (hour < 19) return "Selamat sore";
  return "Selamat malam";
}

function toast(message, variant = "info") {
  const stack = $("#toast-stack");
  const node = document.createElement("div");
  node.className = `toast ${variant}`;
  node.textContent = message;
  stack.appendChild(node);
  setTimeout(() => {
    node.style.opacity = "0";
    node.style.transform = "translateY(6px)";
    setTimeout(() => node.remove(), 220);
  }, 4200);
}

class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
  }
}

async function api(path, options = {}) {
  const opts = {
    credentials: "same-origin",
    ...options,
    headers: { ...(options.headers || {}) },
  };
  if (opts.body && typeof opts.body !== "string") {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(opts.body);
  }
  const response = await fetch(path, opts);
  const contentType = response.headers.get("content-type") || "";
  let payload = null;
  if (contentType.includes("json")) {
    payload = await response.json().catch(() => null);
  } else {
    payload = await response.text().catch(() => "");
  }
  if (!response.ok) {
    if (response.status === 401 && state.user && path !== "/api/auth/login") {
      showLogin("Sesi berakhir. Silakan masuk kembali.");
    }
    const detail =
      payload && typeof payload === "object" && payload.detail
        ? payload.detail
        : typeof payload === "string" && payload
          ? payload
          : "Permintaan tidak dapat diselesaikan.";
    throw new ApiError(detail, response.status);
  }
  return payload;
}

/* Auth ------------------------------------------------------------------- */

async function boot() {
  try {
    const me = await api("/api/auth/me");
    showApp(me);
  } catch {
    showLogin();
  }
}

function showLogin(message = "") {
  clearInterval(state.timer);
  state.timer = null;
  state.user = null;
  $("#boot").hidden = true;
  $("#shell").hidden = true;
  $("#login").hidden = false;
  document.body.classList.remove("nav-open");
  window.scrollTo(0, 0);
  const error = $("#login-error");
  if (message) {
    error.textContent = message;
    error.hidden = false;
  } else {
    error.hidden = true;
  }
  setTimeout(() => $("#login-username").focus(), 80);
}

function showApp(me) {
  state.user = me;
  $("#boot").hidden = true;
  $("#login").hidden = true;
  $("#shell").hidden = false;
  window.scrollTo(0, 0);
  $("#user-name").textContent = me.username;
  $("#user-role").textContent = me.role || "admin";
  $("#user-avatar").textContent = String(me.username || "CM").slice(0, 2).toUpperCase();
  if (!location.hash) location.hash = "#/overview";
  route();
}

$("#login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const error = $("#login-error");
  const button = $("#login-submit");
  error.hidden = true;
  button.disabled = true;
  button.textContent = "Memeriksa kredensial";
  try {
    const result = await api("/api/auth/login", {
      method: "POST",
      body: {
        username: $("#login-username").value.trim(),
        password: $("#login-password").value,
      },
    });
    $("#login-password").value = "";
    showApp({ ...result.user, product: "Cosmos Molorum Sentinel" });
  } catch (err) {
    error.textContent = err.message || "Tidak dapat masuk.";
    error.hidden = false;
  } finally {
    button.disabled = false;
    button.textContent = "Masuk";
  }
});

$("#logout-btn").addEventListener("click", async () => {
  try {
    await api("/api/auth/logout", { method: "POST" });
  } catch {
    /* the cookie is cleared locally regardless */
  }
  showLogin();
});

/* Navigation ------------------------------------------------------------- */

function navigate(path) {
  location.hash = `#/${path}`;
  document.body.classList.remove("nav-open");
}

function route() {
  if (!state.user) return;
  window.scrollTo(0, 0);
  clearInterval(state.timer);
  state.timer = null;
  const raw = location.hash.replace(/^#\/?/, "") || "overview";
  const parts = raw.split("/");
  const root = parts[0] || "overview";
  const meta = ROUTE_META[root] || ROUTE_META.overview;
  $("#crumb-current").textContent = meta.label;
  $$(".nav-item").forEach((item) => {
    item.classList.toggle("active", item.dataset.route === meta.nav);
  });
  const view = $("#view");
  view.focus({ preventScroll: true });
  if (root === "scans" && parts[1]) {
    renderScanDetail(parts[1]);
    return;
  }
  if (root === "analysis") {
    renderAnalysis(parts[1] || "");
    return;
  }
  if (root === "intel") {
    renderIntel(parts[1] || "");
    return;
  }
  switch (root) {
    case "scan":
      renderScanForm();
      break;
    case "history":
      renderHistory();
      break;
    case "modules":
      renderModules();
      break;
    case "audit":
      renderAudit();
      break;
    default:
      renderOverview();
  }
}

window.addEventListener("hashchange", route);

$("#menu-btn").addEventListener("click", () => {
  document.body.classList.toggle("nav-open");
});
$("#nav-scrim").addEventListener("click", () => {
  document.body.classList.remove("nav-open");
});
$("#refresh-btn").addEventListener("click", () => route());
$("#account-btn").addEventListener("click", openAccountModal);

/* Shared ----------------------------------------------------------------- */

function pageHead(kicker, title, lede, actions = "") {
  return `
    <div class="page-head">
      <div>
        <p class="eyebrow">${esc(kicker)}</p>
        <h1>${title}</h1>
        <p class="page-lede">${lede}</p>
      </div>
      ${actions ? `<div class="page-actions">${actions}</div>` : ""}
    </div>`;
}

function loadingBlock() {
  return `<div class="card card-pad"><div class="loading-block">
    <div class="loading-line"></div><div class="loading-line"></div><div class="loading-line"></div>
  </div></div>`;
}

function emptyState(title, copy) {
  return `<div class="empty">
    <div class="empty-mark"></div>
    <h3>${esc(title)}</h3>
    <p>${esc(copy)}</p>
  </div>`;
}

function errorState(message) {
  return `<div class="card card-pad"><div class="form-error">${esc(message)}</div>
    <div class="mt-12"><button class="btn btn-secondary btn-sm" data-retry>Muat ulang</button></div>
  </div>`;
}

function bindRetry(root, callback) {
  const button = $("[data-retry]", root);
  if (button) button.addEventListener("click", callback);
}

async function ensureModules() {
  if (!state.modules) {
    state.modules = await api("/api/modules");
  }
  return state.modules;
}

/* Overview --------------------------------------------------------------- */

async function renderOverview() {
  const view = $("#view");
  view.innerHTML = `<div class="stack">${loadingBlock()}</div>`;
  try {
    const [dash] = await Promise.all([api("/api/dashboard"), ensureModules()]);
    const categories = state.modules.categories;
    const severity = dash.severity || {};
    const totalFindings =
      (severity.critical || 0) +
      (severity.high || 0) +
      (severity.medium || 0) +
      (severity.low || 0) +
      (severity.info || 0);
    const urgent = (severity.critical || 0) + (severity.high || 0);
    const recent = dash.recent || [];

    view.innerHTML = `
      <section class="hero">
        <div class="hero-copy">
          <p class="eyebrow brass">Ringkasan operasional · ${esc(new Intl.DateTimeFormat("id-ID", { day: "2-digit", month: "long", year: "numeric" }).format(new Date()))}</p>
          <h1>${greeting()}, ${esc(state.user.username)}.<br /><em>Postur aset, tanpa noise.</em></h1>
          <p>Sentinel merangkum hasil pemeriksaan keamanan Anda dalam satu pandangan: skor, temuan yang perlu perhatian, dan modul yang telah berjalan. Setiap asesmen tercatat lengkap dengan analisis temuan.</p>
          <div class="hero-actions">
            <button class="btn btn-primary" data-start-scan>${ICON.plus} Pemindaian baru</button>
            <button class="btn btn-secondary" data-open-modules>${ICON.layers} Lihat ${dash.modules} modul</button>
          </div>
        </div>
        <div class="hero-aside">
          <figure class="hero-poster">
            <img src="/assets/posters/orbit.svg?v=2.2.0" alt="" width="640" height="440" decoding="async" />
            <figcaption><span>Observatorium sinyal</span><strong>Dari pantauan ke keputusan.</strong></figcaption>
          </figure>
          <div class="hero-stat"><span>Skor rata-rata</span><strong>${dash.avg_score || 0}</strong></div>
          <div class="hero-stat"><span>Pemindaian aktif</span><strong>${dash.active_scans || 0}</strong></div>
          <div class="hero-stat"><span>Tujuh hari terakhir</span><strong>${dash.week || 0}</strong></div>
        </div>
      </section>

      <div class="section">
        <div class="grid-4">
          <div class="card stat-card">
            <div class="stat-top"><span class="stat-label">Total pemindaian</span><span class="stat-icon">${ICON.scan}</span></div>
            <div class="stat-value"><strong>${dash.scans || 0}</strong><span>asesmen tersimpan</span></div>
          </div>
          <div class="card stat-card">
            <div class="stat-top"><span class="stat-label">Skor rata-rata</span><span class="stat-icon">${ICON.score}</span></div>
            <div class="stat-value"><strong>${dash.avg_score || 0}</strong><span>dari 100</span></div>
          </div>
          <div class="card stat-card">
            <div class="stat-top"><span class="stat-label">Temuan kritis & tinggi</span><span class="stat-icon">${ICON.alert}</span></div>
            <div class="stat-value"><strong>${urgent}</strong><span>perlu perhatian</span></div>
          </div>
          <div class="card stat-card">
            <div class="stat-top"><span class="stat-label">Berjalan sekarang</span><span class="stat-icon">${ICON.clock}</span></div>
            <div class="stat-value"><strong>${dash.running || 0}</strong><span>antrean aktif</span></div>
          </div>
        </div>
      </div>

      <div class="section summary-grid">
        <div class="card severity-panel">
          <div class="section-head tight">
            <div><p class="eyebrow">Distribusi temuan</p><h2 class="display-sm">Lanskap risiko</h2></div>
            <span class="mono dim">${totalFindings} temuan</span>
          </div>
          <div class="severity-bar" data-severity-bar></div>
          <div class="severity-legend">
            ${["critical", "high", "medium", "low", "info"]
              .map(
                (key) => `<div><i class="sev-${key}"></i>${esc(SEVERITY_LABEL[key])}<strong>${severity[key] || 0}</strong></div>`,
              )
              .join("")}
          </div>
          <p class="dim fine-print">Skor dimulai dari 100 dan berkurang sesuai bobot keparahan temuan. Skor bukan pengganti penilaian manual.</p>
        </div>
        <div class="card card-pad">
          <p class="eyebrow">Disiplin pemeriksaan</p>
          <h2 class="display-md">Lima lapisan pertahanan</h2>
          <div class="severity-panel flush">
            ${categories
              .map(
                (cat) => `<div class="aside-metric"><span>${esc(cat.name)}</span><strong>${cat.count} modul</strong></div>`,
              )
              .join("")}
          </div>
          <button class="btn btn-ghost btn-sm mt-14" data-open-modules>Buka pustaka modul</button>
        </div>
      </div>

      <div class="section">
        <div class="section-head">
          <div><p class="eyebrow">Aktivitas terbaru</p><h2>Pemindaian terkini</h2></div>
          <a class="section-link" href="#/history">Semua riwayat</a>
        </div>
        ${
          recent.length
            ? `<div class="table-wrap"><table class="data">
                <thead><tr><th>Target</th><th>Status</th><th>Skor</th><th>Temuan</th><th>Waktu</th><th></th></tr></thead>
                <tbody>
                  ${recent
                    .map(
                      (scan) => `<tr>
                        <td class="target-cell"><a href="#/scans/${esc(scan.id)}">${esc(scan.host || scan.target)}</a></td>
                        <td>${statusBadge(scan.status)}</td>
                        <td class="num">${scan.score === null || scan.score === undefined ? "—" : esc(scan.score)}</td>
                        <td class="num">${esc(scan.finding_count || 0)}</td>
                        <td>${esc(fmtDate(scan.created_at))}</td>
                        <td class="row-action"><a class="text-btn" href="#/scans/${esc(scan.id)}">Buka</a></td>
                      </tr>`,
                    )
                    .join("")}
                </tbody>
              </table></div>`
            : `<div class="card">${emptyState("Belum ada pemindaian", "Mulai asesmen pertama pada aset organisasi Anda untuk membangun baseline keamanan.")}</div>`
        }
      </div>

      <div class="section">
        <div class="section-head">
          <div><p class="eyebrow">Cakupan</p><h2>Kategori modul</h2></div>
          <a class="section-link" href="#/modules">Pustaka lengkap</a>
        </div>
        <div class="category-grid">
          ${categories
            .map(
              (cat) => `<button class="category-tile" type="button" data-category-jump="${esc(cat.name)}">
                <span class="cat-index">${esc(CATEGORY_INDEX[cat.name] || "—")}</span>
                <h3>${esc(cat.name)}</h3>
                <p>${esc(CATEGORY_COPY[cat.name] || "Pemeriksaan terfokus pada lapisan ini.")}</p>
                <strong>${cat.count} modul</strong>
              </button>`,
            )
            .join("")}
        </div>
      </div>
    `;

    const bar = $("[data-severity-bar]", view);
    if (bar) {
      const colors = {
        critical: "#df8b90",
        high: "#e0a172",
        medium: "#d8b97f",
        low: "#86b2bd",
        info: "#586d7e",
      };
      ["critical", "high", "medium", "low", "info"].forEach((key) => {
        const value = severity[key] || 0;
        if (!value) return;
        const span = document.createElement("span");
        span.style.width = `${(value / Math.max(1, totalFindings)) * 100}%`;
        span.style.background = colors[key];
        span.title = `${SEVERITY_LABEL[key]}: ${value}`;
        bar.appendChild(span);
      });
      if (!totalFindings) {
        const span = document.createElement("span");
        span.style.width = "100%";
        span.style.background = "rgba(108,196,160,.35)";
        bar.appendChild(span);
      }
    }

    $("[data-start-scan]", view)?.addEventListener("click", () => navigate("scan"));
    $$("[data-open-modules]", view).forEach((button) =>
      button.addEventListener("click", () => navigate("modules")),
    );
    $$("[data-category-jump]", view).forEach((button) =>
      button.addEventListener("click", () => {
        state.libraryCategory = button.dataset.categoryJump;
        navigate("modules");
      }),
    );
  } catch (err) {
    view.innerHTML = errorState(err.message);
    bindRetry(view, renderOverview);
  }
}

/* Scan form -------------------------------------------------------------- */

async function renderScanForm() {
  const view = $("#view");
  view.innerHTML = `<div class="stack">${loadingBlock()}</div>`;
  try {
    const modules = await ensureModules();
    const preselected = state.prefillTarget;
    view.innerHTML = `
      ${pageHead(
        "Asesmen keamanan",
        "Pemindaian baru",
        "Tentukan satu target, pilih modul, lalu jalankan asesmen. Sentinel hanya melakukan probe non-destruktif dan membatasi jumlah permintaan.",
        `<button class="btn btn-ghost btn-sm" data-goto-history>Riwayat</button>`,
      )}
      <div class="scan-layout">
        <form class="card scan-form" id="scan-form" novalidate>
          <div class="form-steps">
            <section class="form-step">
              <div class="step-head"><span class="step-num">01</span><h2>Target aset</h2><span>Satu host per asesmen</span></div>
              <div class="target-row">
                <label class="field">
                  <span>URL target</span>
                  <input id="scan-target" type="text" inputmode="url" spellcheck="false" maxlength="2048"
                    placeholder="https://contoh.com" value="${esc(preselected)}" required />
                  <small class="field-note">Gunakan http:// atau https://. Target privat dan internal dapat diuji langsung dari konsol ini.</small>
                </label>
              </div>
            </section>

            <section class="form-step">
              <div class="step-head"><span class="step-num">02</span><h2>Modul pemeriksaan</h2><span id="module-selected-count">${modules.count} dari ${modules.count} dipilih</span></div>
              <div class="module-toolbar">
                <span class="count">${modules.count} modul dalam lima kategori. Semua dipilih secara default.</span>
                <div class="mini-actions">
                  <button class="text-btn" type="button" data-select-all>Pilih semua</button>
                  <button class="text-btn" type="button" data-select-none>Kosongkan</button>
                </div>
              </div>
              <div class="select-groups" id="module-groups">
                ${modules.categories
                  .map(
                    (cat) => `<section class="select-group" data-group="${esc(cat.name)}">
                      <div class="select-group-head"><h3>${esc(cat.name)}</h3><span>${cat.count} modul</span></div>
                      <div class="select-group-body">
                        ${cat.modules
                          .map(
                            (mod) => `<label class="module-check">
                              <input type="checkbox" value="${esc(mod.id)}" checked />
                              <span class="mc-copy">
                                <span class="mc-name">${esc(mod.name)}</span>
                                <span class="mc-meta">${esc(mod.passive ? "Pasif" : "Aktif")} · ${esc(SEVERITY_LABEL[mod.severity] || mod.severity)}</span>
                              </span>
                            </label>`,
                          )
                          .join("")}
                      </div>
                    </section>`,
                  )
                  .join("")}
              </div>
            </section>

            <section class="form-step">
              <div class="step-head"><span class="step-num">03</span><h2>Catatan operator</h2><span>Opsional</span></div>
              <div class="note-box">
                <label class="field">
                  <span>Catatan untuk jejak audit</span>
                  <textarea id="scan-note" rows="2" maxlength="500" placeholder="Contoh: asesmen rutin kuartal empat untuk layanan publik."></textarea>
                  <small class="field-note">Catatan disimpan bersama target dan hasil. Kosongkan untuk memakai catatan operator terautentikasi secara otomatis.</small>
                </label>
                <div class="form-error" id="scan-error" role="alert" hidden></div>
              </div>
            </section>

            <div class="form-actions">
              <span class="hint">Pemindaian berjalan dengan pembatasan bawaan: tanpa eksploitasi destruktif, tanpa brute force, dan tanpa akses ke endpoint metadata cloud.</span>
              <button class="btn btn-primary" type="submit" id="scan-submit">${ICON.scan} Mulai pemindaian</button>
            </div>
          </div>
        </form>

        <aside class="scan-aside">
          <div class="card aside-card">
            <p class="eyebrow">Batas pengujian</p>
            <h3>Anggaran yang dijaga</h3>
            <div class="aside-metric"><span>Total permintaan</span><strong>maks. 900</strong></div>
            <div class="aside-metric"><span>Batas waktu</span><strong>8 menit</strong></div>
            <div class="aside-metric"><span>Pekerja modul</span><strong>6 paralel</strong></div>
            <div class="aside-metric"><span>Jeda antar permintaan</span><strong>50 mdtk</strong></div>
            <p class="mt-12">Scanner menghormati batas ini dan menghentikan modul yang tersisa bila anggaran habis.</p>
          </div>
          <div class="card aside-card">
            <p class="eyebrow">Yang diperiksa</p>
            <h3>${modules.count} modul</h3>
            <ul class="aside-list">
              <li><span class="n">01</span><span>Transport & DNS: sertifikat, protokol, HSTS, CSP, SPF, DMARC, DKIM.</span></li>
              <li><span class="n">02</span><span>Sesi & browser: cookie, CORS, cache, framing, mixed content, CSRF, SRI.</span></li>
              <li><span class="n">03</span><span>Eksposur: Git, .env, backup, source map, debug, admin surface.</span></li>
              <li><span class="n">04</span><span>Injeksi: SQLi error, boolean, union, time, header, evasion; XSS reflected, DOM, atribut, header, JSON; NoSQL, LDAP, SSTI, XXE, redirect, traversal.</span></li>
              <li><span class="n">05</span><span>Edge: deteksi WAF, konsistensi header, cache deception, dan signature server.</span></li>
            </ul>
          </div>
          <div class="card aside-card">
            <p class="eyebrow">Privasi</p>
            <h3>Data tetap lokal</h3>
            <p>Hasil, bukti, dan catatan operator disimpan pada basis data Sentinel di server ini. Tidak ada pengiriman hasil ke pihak ketiga.</p>
          </div>
        </aside>
      </div>
    `;

    const form = $("#scan-form");
    const countNode = $("#module-selected-count");
    const checkboxes = $$('#module-groups input[type="checkbox"]', view);
    const updateCount = () => {
      const selected = checkboxes.filter((box) => box.checked).length;
      countNode.textContent = `${selected} dari ${checkboxes.length} dipilih`;
    };
    checkboxes.forEach((box) => box.addEventListener("change", updateCount));
    $("[data-select-all]", view).addEventListener("click", () => {
      checkboxes.forEach((box) => (box.checked = true));
      updateCount();
    });
    $("[data-select-none]", view).addEventListener("click", () => {
      checkboxes.forEach((box) => (box.checked = false));
      updateCount();
    });
    $("[data-goto-history]", view).addEventListener("click", () => navigate("history"));

    form.addEventListener("submit", (event) => {
      event.preventDefault();
      const error = $("#scan-error");
      error.hidden = true;
      const target = $("#scan-target").value.trim();
      const note = $("#scan-note").value.trim();
      const selected = checkboxes.filter((box) => box.checked).map((box) => box.value);
      if (!target) {
        showFormError("Masukkan URL target terlebih dahulu.");
        return;
      }
      if (!selected.length) {
        showFormError("Pilih minimal satu modul pemeriksaan.");
        return;
      }
      openModal({
        kicker: "Konfirmasi akhir",
        title: "Mulai pemindaian?",
        body: `<p>Sentinel akan menguji <strong>${esc(target)}</strong> dengan <strong>${selected.length} modul</strong>. Probe bersifat non-destruktif dan dibatasi 900 permintaan.</p>
          <div class="modal-note">Target: ${esc(target)}<br />Operator: ${esc((state.user && state.user.username) || "terautentikasi")}${note ? `<br />Catatan: ${esc(note)}` : ""}</div>`,
        actions: [
          { label: "Batal", variant: "ghost", close: true },
          {
            label: "Ya, mulai pemindaian",
            variant: "primary",
            onClick: async () => {
              closeModal();
              const button = $("#scan-submit");
              button.disabled = true;
              button.textContent = "Menyiapkan pemindaian";
              try {
                const result = await api("/api/scans", {
                  method: "POST",
                  body: {
                    target,
                    modules: selected,
                    note,
                  },
                });
                state.prefillTarget = "";
                toast("Pemindaian dimulai. Hasil akan tampil saat modul selesai.", "success");
                navigate(`scans/${result.scan_id}`);
              } catch (err) {
                button.disabled = false;
                button.innerHTML = `${ICON.scan} Mulai pemindaian`;
                showFormError(err.message);
                toast(err.message, "error");
              }
            },
          },
        ],
      });

      function showFormError(message) {
        error.textContent = message;
        error.hidden = false;
        error.scrollIntoView({ behavior: "smooth", block: "center" });
      }
    });
  } catch (err) {
    view.innerHTML = errorState(err.message);
    bindRetry(view, renderScanForm);
  }
}

/* History ---------------------------------------------------------------- */

function historyMatches(scan, filter) {
  if (filter === "all") return true;
  if (filter === "active") return scan.status === "running" || scan.status === "queued";
  return scan.status === filter;
}

async function renderHistory() {
  const view = $("#view");
  view.innerHTML = `<div class="stack">${loadingBlock()}</div>`;
  try {
    const data = await api("/api/scans?limit=120");
    const scans = data.scans || [];
    const filters = [
      ["all", "Semua"],
      ["active", "Berjalan"],
      ["completed", "Selesai"],
      ["cancelled", "Dibatalkan"],
      ["failed", "Gagal"],
    ];
    view.innerHTML = `
      ${pageHead(
        "Jejak asesmen",
        "Riwayat pemindaian",
        "Setiap asesmen tersimpan bersama skor, temuan, dan catatan operator. Gunakan filter untuk meninjau status tertentu.",
        `<button class="btn btn-primary btn-sm" data-new-scan>${ICON.plus} Pemindaian baru</button>`,
      )}
      <div class="filters">
        ${filters
          .map(
            ([key, label]) =>
              `<button class="filter-btn ${state.historyFilter === key ? "active" : ""}" data-filter="${key}">${label}</button>`,
          )
          .join("")}
      </div>
      <div id="history-table"></div>
    `;
    const tableRoot = $("#history-table", view);
    const paint = () => {
      const visible = scans.filter((scan) => historyMatches(scan, state.historyFilter));
      if (!visible.length) {
        tableRoot.innerHTML = `<div class="card">${emptyState("Tidak ada asesmen pada filter ini", "Ubah filter atau mulai pemindaian baru untuk mengisi riwayat.")}</div>`;
        return;
      }
      tableRoot.innerHTML = `<div class="table-wrap"><table class="data">
        <thead><tr><th>Target</th><th>Status</th><th>Modul</th><th>Temuan</th><th>Skor</th><th>Dimulai</th><th></th></tr></thead>
        <tbody>
          ${visible
            .map(
              (scan) => `<tr>
                <td class="target-cell"><a href="#/scans/${esc(scan.id)}">${esc(scan.host || scan.target)}</a></td>
                <td>${statusBadge(scan.status)}</td>
                <td class="num">${esc(scan.module_count || 0)}</td>
                <td class="num">${esc(scan.finding_count || 0)}${scan.urgent_count ? ` <span class="badge badge-high">${esc(scan.urgent_count)} prioritas</span>` : ""}</td>
                <td class="num">${scan.score === null || scan.score === undefined ? "—" : esc(scan.score)}</td>
                <td>${esc(fmtDate(scan.created_at))}</td>
                <td class="row-action"><a class="text-btn" href="#/scans/${esc(scan.id)}">Buka</a></td>
              </tr>`,
            )
            .join("")}
        </tbody>
      </table></div>`;
    };
    paint();
    $$("[data-filter]", view).forEach((button) =>
      button.addEventListener("click", () => {
        state.historyFilter = button.dataset.filter;
        $$("[data-filter]", view).forEach((item) =>
          item.classList.toggle("active", item === button),
        );
        paint();
      }),
    );
    $("[data-new-scan]", view).addEventListener("click", () => navigate("scan"));
  } catch (err) {
    view.innerHTML = errorState(err.message);
    bindRetry(view, renderHistory);
  }
}

/* Scan detail ------------------------------------------------------------ */

async function renderScanDetail(scanId) {
  const view = $("#view");
  state.currentScanId = scanId;
  view.innerHTML = `<div class="stack">${loadingBlock()}</div>`;
  try {
    const scan = await api(`/api/scans/${encodeURIComponent(scanId)}`);
    const summary = scan.summary || {};
    const severity = summary.severity || {};
    const findings = scan.findings || [];
    const modulesRun = scan.modules || [];
    const running = scan.status === "running" || scan.status === "queued";
    const totalModules = (scan.modules_json || []).length || modulesRun.length;
    const completedModules = modulesRun.length;
    const elapsed = summary.elapsed_ms || 0;
    const requests = summary.requests || modulesRun.reduce((sum, item) => sum + (item.requests || 0), 0);
    const score = scan.score;
    const ringColor = scoreColor(score ?? 0);

    const grouped = ["critical", "high", "medium", "low", "info"].map((key) => ({
      key,
      items: findings.filter((finding) => finding.severity === key),
    }));

    view.innerHTML = `
      <div class="detail-head">
        <div>
          <div class="flex-row">
            <p class="eyebrow">Asesmen ${esc(scan.id)}</p>
            ${statusBadge(scan.status)}
          </div>
          <h1>${esc(scan.target)}</h1>
          <div class="detail-meta">
            <span>Diminta oleh <strong>${esc(scan.requested_by)}</strong></span>
            <span>Dibuat <strong>${esc(fmtDate(scan.created_at))}</strong></span>
            ${scan.finished_at ? `<span>Selesai <strong>${esc(fmtDate(scan.finished_at))}</strong></span>` : ""}
            <span>Host <strong>${esc(scan.host)}</strong></span>
          </div>
          <div class="detail-meta mt-9">
            <span>Catatan operator: <strong>${esc(scan.authorization_note || "Dijalankan oleh operator terautentikasi melalui konsol Sentinel")}</strong></span>
          </div>
        </div>
        <div class="detail-actions">
          <a class="btn btn-primary btn-sm" href="#/analysis/${encodeURIComponent(scan.id)}">Analisis temuan</a>
          <a class="btn btn-secondary btn-sm" href="#/intel/${encodeURIComponent(scan.id)}">Intelijen</a>
          <a class="btn btn-ghost btn-sm" href="/api/scans/${encodeURIComponent(scan.id)}/export?format=json">Ekspor JSON</a>
          <a class="btn btn-ghost btn-sm" href="/api/scans/${encodeURIComponent(scan.id)}/export?format=csv">Ekspor CSV</a>
          <button class="btn btn-secondary btn-sm" data-rescan>Pindai lagi</button>
          ${running ? `<button class="btn btn-danger btn-sm" data-cancel-scan>Batalkan</button>` : ""}
        </div>
      </div>

      ${
        running
          ? `<div class="card progress-panel mb-16">
              <div class="progress-top"><span>Modul berjalan</span><strong id="scan-progress-value">${completedModules}/${totalModules}</strong></div>
              <div class="progress-track"><span id="scan-progress-fill"></span></div>
              <div class="progress-sub"><span id="scan-progress-label">${esc(scan.status === "queued" ? "Menunggu pekerja" : "Menyiapkan probe")}</span><span>${requests} permintaan</span></div>
            </div>`
          : ""
      }

      <div class="detail-grid">
        <div class="stack">
          <div class="card score-card">
            ${
              score === null || score === undefined
                ? `<div class="score-ring" data-score-ring><div class="score-inner"><strong>—</strong><span>Belum ada skor</span></div></div>`
                : `<div class="score-ring" data-score-ring><div class="score-inner"><strong>${esc(score)}</strong><span>dari 100</span></div></div>`
            }
            <div class="grade-pill">Grade <strong>${esc(scan.grade || "—")}</strong></div>
            <p class="score-note">${running ? "Skor dihitung setelah seluruh modul selesai." : "Skor dikurangi sesuai bobot keparahan temuan."}</p>
          </div>
          ${
            scan.error
              ? `<div class="card card-pad"><div class="form-error">${esc(scan.error)}</div></div>`
              : ""
          }
        </div>

        <div class="stack">
          <div class="scan-stats">
            <div class="scan-stat"><span>Modul</span><strong>${completedModules}/${totalModules}</strong></div>
            <div class="scan-stat"><span>Temuan</span><strong>${findings.length}</strong></div>
            <div class="scan-stat"><span>Durasi</span><strong>${esc(fmtDuration(elapsed))}</strong></div>
            <div class="scan-stat"><span>Permintaan</span><strong>${requests}</strong></div>
          </div>
          <div class="card severity-panel">
            <div class="section-head tight">
              <div><p class="eyebrow">Ringkasan keparahan</p><h2 class="display-sm">Temuan per tingkat</h2></div>
              <span class="mono dim">${findings.length} total</span>
            </div>
            <div class="severity-bar" data-detail-severity></div>
            <div class="severity-legend">
              ${["critical", "high", "medium", "low", "info"]
                .map(
                  (key) =>
                    `<div><i class="sev-${key}"></i>${esc(SEVERITY_LABEL[key])}<strong>${severity[key] || 0}</strong></div>`,
                )
                .join("")}
            </div>
          </div>
        </div>
      </div>

      <div class="section">
        <div class="section-head"><div><p class="eyebrow">Temuan</p><h2>Detail per keparahan</h2></div></div>
        ${
          findings.length
            ? `<div class="finding-group">
                ${grouped
                  .filter((group) => group.items.length)
                  .map(
                    (group) => `<div class="card card-pad">
                      <div class="section-head tight-10">
                        <div class="flex-inline">${severityBadge(group.key)}<span class="dim fine">${group.items.length} temuan</span></div>
                      </div>
                      <div class="finding-group">
                        ${group.items
                          .map(
                            (finding) => `<details class="finding">
                              <summary>
                                ${severityBadge(finding.severity)}
                                <span class="finding-title">${esc(finding.title)}</span>
                                <svg class="finding-chevron" viewBox="0 0 24 24" aria-hidden="true"><path d="m6 9 6 6 6-6"/></svg>
                              </summary>
                              <div class="finding-body">
                                <p>${esc(finding.detail)}</p>
                                <div class="finding-meta">
                                  <div><span class="label">Modul</span><span class="mono">${esc(finding.module_id)}</span></div>
                                  ${finding.evidence ? `<div><span class="label">Bukti</span><code>${esc(finding.evidence)}</code></div>` : ""}
                                  ${finding.remediation ? `<div><span class="label">Rekomendasi</span><p>${esc(finding.remediation)}</p></div>` : ""}
                                </div>
                              </div>
                            </details>`,
                          )
                          .join("")}
                      </div>
                    </div>`,
                  )
                  .join("")}
              </div>`
            : `<div class="card">${emptyState(
                running ? "Pemindaian sedang berjalan" : "Tidak ada temuan tercatat",
                running
                  ? "Temuan akan muncul saat modul selesai. Halaman ini memperbarui otomatis."
                  : "Tidak ada temuan yang dilaporkan pada cakupan modul ini. Tetap lakukan validasi manual.",
              )}</div>`
        }
      </div>

      <div class="section">
        <div class="section-head"><div><p class="eyebrow">Eksekusi</p><h2>Hasil per modul</h2></div><span class="mono dim">${completedModules} modul</span></div>
        ${
          modulesRun.length
            ? `<div class="table-wrap"><table class="data module-table">
                <thead><tr><th>Modul</th><th>Kategori</th><th>Status</th><th>Ringkasan</th><th>Permintaan</th><th>Durasi</th></tr></thead>
                <tbody>
                  ${modulesRun
                    .map(
                      (item) => `<tr>
                        <td>${esc(item.name)}<div class="mono dim">${esc(item.module_id)}</div></td>
                        <td>${esc(item.category)}</td>
                        <td>${statusBadge(item.status)}</td>
                        <td class="module-summary">${esc(item.summary)}</td>
                        <td class="num">${esc(item.requests)}</td>
                        <td class="num">${esc(fmtDuration(item.duration_ms))}</td>
                      </tr>`,
                    )
                    .join("")}
                </tbody>
              </table></div>`
            : `<div class="card">${emptyState("Belum ada modul selesai", "Riwayat modul akan terisi saat eksekusi berjalan.")}</div>`
        }
      </div>
    `;

    const ring = $("[data-score-ring]", view);
    if (ring) {
      ring.style.setProperty("--score", String(score ?? 0));
      ring.style.setProperty("--grade-color", ringColor);
    }
    applySeverityBar($("[data-detail-severity]", view), severity, findings.length);
    const fill = $("#scan-progress-fill", view);
    if (fill) {
      fill.style.width = `${Math.min(100, Math.round((completedModules / Math.max(1, totalModules)) * 100))}%`;
    }

    $("[data-rescan]", view).addEventListener("click", () => {
      state.prefillTarget = scan.target;
      navigate("scan");
    });
    $("[data-cancel-scan]", view)?.addEventListener("click", () => {
      openModal({
        kicker: "Hentikan asesmen",
        title: "Batalkan pemindaian?",
        body: `<p>Modul yang sedang berjalan akan dihentikan dan hasil parsial tetap disimpan pada riwayat.</p>`,
        actions: [
          { label: "Kembali", variant: "ghost", close: true },
          {
            label: "Batalkan pemindaian",
            variant: "danger",
            onClick: async () => {
              closeModal();
              try {
                await api(`/api/scans/${encodeURIComponent(scan.id)}/cancel`, {
                  method: "POST",
                });
                toast("Permintaan pembatalan dikirim.", "success");
              } catch (err) {
                toast(err.message, "error");
              }
            },
          },
        ],
      });
    });

    if (running) {
      let lastStatus = scan.status;
      state.timer = setInterval(async () => {
        if (state.currentScanId !== scanId) {
          clearInterval(state.timer);
          return;
        }
        try {
          const progress = await api(
            `/api/scans/${encodeURIComponent(scanId)}/progress`,
          );
          const valueNode = $("#scan-progress-value");
          const labelNode = $("#scan-progress-label");
          const fillNode = $("#scan-progress-fill");
          if (valueNode) valueNode.textContent = `${progress.completed}/${progress.total}`;
          if (labelNode) {
            labelNode.textContent =
              progress.status === "queued"
                ? "Menunggu pekerja"
                : progress.current
                  ? `Menjalankan ${progress.current}`
                  : progress.status === "cancelled"
                    ? "Pembatalan diproses"
                    : "Menyelesaikan hasil";
          }
          if (fillNode) fillNode.style.width = `${Math.max(2, progress.percent || 0)}%`;
          if (["completed", "cancelled", "failed"].includes(progress.status)) {
            clearInterval(state.timer);
            state.timer = null;
            renderScanDetail(scanId);
            return;
          }
          lastStatus = progress.status;
        } catch {
          clearInterval(state.timer);
          state.timer = null;
        }
      }, 1600);
    }
  } catch (err) {
    view.innerHTML = errorState(err.message);
    bindRetry(view, () => renderScanDetail(scanId));
  }
}

function applySeverityBar(bar, severity, total) {
  if (!bar) return;
  const colors = {
    critical: "#df8b90",
    high: "#e0a172",
    medium: "#d8b97f",
    low: "#86b2bd",
    info: "#586d7e",
  };
  bar.innerHTML = "";
  ["critical", "high", "medium", "low", "info"].forEach((key) => {
    const count = severity[key] || 0;
    if (!count) return;
    const span = document.createElement("span");
    span.style.width = `${(count / Math.max(1, total)) * 100}%`;
    span.style.background = colors[key];
    span.title = `${SEVERITY_LABEL[key]}: ${count}`;
    bar.appendChild(span);
  });
  if (!bar.children.length) {
    const span = document.createElement("span");
    span.style.width = "100%";
    span.style.background = "rgba(108,196,160,.35)";
    bar.appendChild(span);
  }
}

/* Analysis --------------------------------------------------------------- */

function sparkline(points) {
  if (!points.length) {
    return `<div class="analysis-empty">Belum ada titik skor untuk digambar.</div>`;
  }
  const width = 680;
  const height = 190;
  const pad = 24;
  const x = (index) =>
    pad + (index * (width - pad * 2)) / Math.max(1, points.length - 1);
  const y = (score) =>
    pad + ((100 - Math.max(0, Math.min(100, Number(score) || 0))) / 100) * (height - pad * 2);
  const line = points
    .map((point, index) => `${x(index).toFixed(1)},${y(point.score).toFixed(1)}`)
    .join(" ");
  const area = `${pad},${height - pad} ${line} ${width - pad},${height - pad}`;
  const grid = [25, 50, 75, 100]
    .map(
      (value) =>
        `<line x1="${pad}" y1="${y(value)}" x2="${width - pad}" y2="${y(value)}" class="spark-grid" />`,
    )
    .join("");
  const dots = points
    .map(
      (point, index) =>
        `<circle cx="${x(index)}" cy="${y(point.score)}" r="4" class="spark-dot"><title>${esc(point.score)} · ${esc(fmtDate(point.created_at))}</title></circle>`,
    )
    .join("");
  return `<svg class="sparkline" viewBox="0 0 ${width} ${height}" role="img" aria-label="Tren skor asesmen">
    ${grid}
    <polygon points="${area}" class="spark-area" />
    <polyline points="${line}" class="spark-line" />
    ${dots}
  </svg>`;
}

async function renderAnalysis(scanId = "") {
  const view = $("#view");
  view.innerHTML = `<div class="stack">${loadingBlock()}</div>`;
  try {
    const [report, scanList] = await Promise.all([
      api(`/api/analysis${scanId ? `?scan_id=${encodeURIComponent(scanId)}` : ""}`),
      api("/api/scans?limit=80").catch(() => ({ scans: [] })),
    ]);
    const scan = report.scan;
    const exec = report.executive;
    const trend = report.trend;
    const coverage = report.coverage;
    const scans = (scanList.scans || []).filter(
      (item) => item.status === "completed" || item.status === "cancelled",
    );
    const options = scans
      .map(
        (item) =>
          `<option value="${esc(item.id)}" ${item.id === scan.id ? "selected" : ""}>${esc(item.host || item.target)} · ${esc(item.score ?? "—")} · ${esc(fmtDate(item.created_at))}</option>`,
      )
      .join("");
    const trendLabel =
      trend.points.length < 2
        ? "Baseline pertama"
        : trend.direction === "up"
          ? `Naik ${trend.delta} poin`
          : trend.direction === "down"
            ? `Turun ${Math.abs(trend.delta)} poin`
            : "Stabil";
    const trendTone =
      trend.direction === "up" ? "up" : trend.direction === "down" ? "down" : "flat";
    const maxOwasp = Math.max(1, ...report.owasp.map((item) => item.findings));

    view.innerHTML = `
      ${pageHead(
        "Laporan eksekutif",
        "Analisis temuan",
        `Pembacaan terarah untuk <strong>${esc(scan.host)}</strong>. Ringkasan, tren, peta OWASP, prioritas, dan roadmap perbaikan dalam satu laporan.`,
        `<label class="analysis-select"><span>Asesmen</span><select id="analysis-scan">${options}</select></label>
         <a class="btn btn-secondary btn-sm" href="#/intel/${encodeURIComponent(scan.id)}">Intelijen</a>
         <a class="btn btn-ghost btn-sm" href="#/scans/${encodeURIComponent(scan.id)}">Detail asesmen</a>`,
      )}

      <section class="analysis-hero">
        <div class="analysis-score" data-style="--score:${scan.score ?? 0};--tone:${scoreColor(scan.score ?? 0)}">
          <div class="analysis-score-ring">
            <strong>${scan.score ?? "—"}</strong>
            <span>dari 100</span>
          </div>
          <div class="analysis-grade">Grade <strong>${esc(exec.grade)}</strong></div>
        </div>
        <div class="analysis-exec">
          <div class="analysis-exec-top">
            <p class="eyebrow brass">Ringkasan eksekutif</p>
            <span class="analysis-band tone-${esc(exec.band.toLowerCase())}">${esc(exec.band)} · ${esc(exec.band_note)}</span>
          </div>
          <h2>${esc(exec.headline)}</h2>
          <p>${esc(exec.narrative)}</p>
          <div class="analysis-chips">
            <span>${ICON.alert} ${exec.urgent} prioritas</span>
            <span>${ICON.layers} ${exec.total_findings} temuan</span>
            <span>${ICON.scan} ${exec.modules} modul</span>
            <span>${ICON.clock} ${fmtDuration(scan.elapsed_ms)}</span>
            <span>${ICON.orbit} ${exec.requests} permintaan</span>
          </div>
        </div>
      </section>

      <div class="section">
        <div class="grid-4 analysis-kpis">
          <div class="card analysis-kpi"><span>Prioritas tinggi</span><strong>${exec.urgent}</strong><small>kritis & tinggi</small></div>
          <div class="card analysis-kpi"><span>Total temuan</span><strong>${exec.total_findings}</strong><small>seluruh kategori</small></div>
          <div class="card analysis-kpi"><span>Cakupan modul</span><strong>${coverage.modules_completed}/${coverage.modules_expected}</strong><small>${coverage.completion}% selesai</small></div>
          <div class="card analysis-kpi"><span>Operator</span><strong class="analysis-operator">${esc(scan.requested_by || "—")}</strong><small>${esc(fmtDate(scan.finished_at || scan.created_at))}</small></div>
        </div>
      </div>

      <div class="section analysis-split">
        <div class="card analysis-card">
          <div class="section-head tight">
            <div><p class="eyebrow">Tren skor</p><h2 class="display-sm">Perjalanan postur</h2></div>
            <span class="analysis-trend tone-${trendTone}">${esc(trendLabel)}</span>
          </div>
          ${sparkline(trend.points)}
          <div class="analysis-axis">
            ${trend.points
              .map(
                (point) => `<span><i>${esc(point.score)}</i>${esc(fmtDate(point.created_at))}</span>`,
              )
              .join("")}
          </div>
        </div>

        <div class="card analysis-card">
          <div class="section-head tight">
            <div><p class="eyebrow">Kepatuhan</p><h2 class="display-sm">Peta OWASP Top 10</h2></div>
            <span class="mono dim">${exec.total_findings} temuan</span>
          </div>
          <div class="owasp-grid">
            ${report.owasp
              .map(
                (item) => `<div class="owasp-card ${item.findings ? "has-findings" : "is-clear"}">
                  <div class="owasp-top"><span class="mono">${esc(item.id)}</span><strong>${esc(item.findings)}</strong></div>
                  <h3>${esc(item.name)}</h3>
                  <div class="owasp-track"><span data-width="${Math.max(item.findings ? 6 : 0, Math.round((item.findings / maxOwasp) * 100))}"></span></div>
                  <small>${item.findings ? `${item.critical + item.high} prioritas · ${item.modules.length} modul` : "Tidak ada temuan"}</small>
                </div>`,
              )
              .join("")}
          </div>
        </div>
      </div>

      <div class="section">
        <div class="section-head">
          <div><p class="eyebrow">Temuan prioritas</p><h2>Urutan tindakan</h2></div>
          <span class="mono dim">8 teratas</span>
        </div>
        ${
          report.priority.length
            ? `<div class="priority-list">
                ${report.priority
                  .map(
                    (item, index) => `<article class="priority-item">
                      <div class="priority-rank">${String(index + 1).padStart(2, "0")}</div>
                      <div class="priority-body">
                        <div class="priority-head">
                          ${severityBadge(item.severity)}
                          <h3>${esc(item.title)}</h3>
                          <span class="priority-score">Prioritas ${esc(item.priority)}</span>
                        </div>
                        <div class="priority-meta">
                          <span>Modul <strong class="mono">${esc(item.module_id)}</strong></span>
                          <span>OWASP <strong>${esc(item.owasp)} · ${esc(OWASP_NAMES[item.owasp] || "")}</strong></span>
                        </div>
                        <p>${esc(item.detail)}</p>
                        ${item.evidence ? `<div class="priority-evidence"><span>Bukti</span><code>${esc(item.evidence)}</code></div>` : ""}
                        ${item.remediation ? `<div class="priority-fix"><span>Perbaikan</span><p>${esc(item.remediation)}</p></div>` : ""}
                      </div>
                    </article>`,
                  )
                  .join("")}
              </div>`
            : `<div class="card">${emptyState("Tidak ada temuan prioritas", "Semua modul yang berjalan tidak melaporkan temuan pada asesmen ini. Lanjutkan dengan validasi manual dan asesmen berkala.")}</div>`
        }
      </div>

      <div class="section">
        <div class="section-head">
          <div><p class="eyebrow">Roadmap</p><h2>Rencana perbaikan</h2></div>
          <span class="mono dim">30–90 hari</span>
        </div>
        <div class="roadmap-grid">
          ${report.roadmap
            .map(
              (phase, index) => `<div class="roadmap-card ${index === 0 ? "is-first" : ""}">
                <div class="roadmap-head"><span class="roadmap-window">${esc(phase.window)}</span><strong>${esc(phase.count)}</strong></div>
                <h3>${esc(phase.title)}</h3>
                <p>${esc(phase.detail)}</p>
                <ul>
                  ${(phase.items.length
                    ? phase.items
                    : [{ title: "Tidak ada temuan pada fase ini", severity: "info", module_id: "", remediation: "" }]
                  )
                    .map(
                      (item) => `<li><span class="roadmap-dot sev-${esc(item.severity)}"></span><span>${esc(item.title)}</span></li>`,
                    )
                    .join("")}
                </ul>
              </div>`,
            )
            .join("")}
        </div>
      </div>

      <div class="section">
        <div class="card analysis-card coverage-card">
          <div class="section-head tight">
            <div><p class="eyebrow">Cakupan</p><h2 class="display-sm">Kualitas eksekusi</h2></div>
            <span class="mono dim">${coverage.library_size} modul tersedia</span>
          </div>
          <div class="coverage-grid">
            <div>
              <div class="coverage-bar"><span data-width="${coverage.completion}"></span></div>
              <div class="coverage-status">
                <span><i class="sev-low"></i>Lulus <strong>${coverage.pass}</strong></span>
                <span><i class="sev-medium"></i>Perhatian <strong>${coverage.warn}</strong></span>
                <span><i class="sev-critical"></i>Bermasalah <strong>${coverage.fail}</strong></span>
                <span><i class="sev-info"></i>Info <strong>${coverage.info}</strong></span>
                <span><i class="sev-info"></i>Dilewati <strong>${coverage.skipped}</strong></span>
              </div>
              <p class="fine-print">${coverage.modules_completed} dari ${coverage.modules_expected} modul terpilih selesai. Modul error: ${coverage.error}.</p>
            </div>
            <div class="coverage-categories">
              ${coverage.categories
                .map(
                  (category) => `<div class="coverage-row"><span>${esc(category.name)}</span><div class="coverage-track"><span data-width="${Math.round((category.modules / Math.max(1, coverage.modules_total)) * 100)}"></span></div><strong>${category.modules}</strong></div>`,
                )
                .join("")}
            </div>
          </div>
        </div>
      </div>
    `;

    applyDynamicStyles(view);
    const select = $("#analysis-scan", view);
    if (select) {
      select.addEventListener("change", () => {
        if (select.value) navigate(`analysis/${select.value}`);
      });
    }
  } catch (err) {
    if (err.status === 404) {
      view.innerHTML = `<div class="card card-pad">${emptyState(
        "Belum ada asesmen selesai",
        "Analisis tersedia setelah satu pemindaian selesai. Mulai asesmen baru atau buka riwayat untuk memeriksa proses yang masih berjalan.",
      )}<div class="mt-14"><button class="btn btn-primary btn-sm" data-new-scan>${ICON.plus} Pemindaian baru</button></div></div>`;
      $("[data-new-scan]", view)?.addEventListener("click", () => navigate("scan"));
      return;
    }
    view.innerHTML = errorState(err.message);
    bindRetry(view, () => renderAnalysis(scanId));
  }
}

/* Exploit intelligence --------------------------------------------------- */

const INTEL_STAGE_LABEL = {
  "Initial Access": "Akses awal",
  Execution: "Eksekusi",
  "Credential Access": "Akses kredensial",
  Collection: "Koleksi",
  Reconnaissance: "Recon",
  Discovery: "Discovery",
};

function intelTone(value) {
  const n = Number(value) || 0;
  if (n >= 80) return "critical";
  if (n >= 60) return "high";
  if (n >= 40) return "medium";
  return "low";
}

function intelColor(value) {
  const tone = intelTone(value);
  if (tone === "critical") return "#df8b90";
  if (tone === "high") return "#e0a172";
  if (tone === "medium") return "#d8b97f";
  return "#6cc4a0";
}

function intelMeter(value, tone) {
  const n = Math.max(0, Math.min(100, Number(value) || 0));
  return `<div class="intel-bar tone-${esc(tone)}"><span data-width="${n}"></span></div>`;
}

function intelVerifyBlock(item) {
  const verification = item.verification || {};
  const steps = (verification.steps || [])
    .map((step) => `<li>${esc(step)}</li>`)
    .join("");
  return `
    <div class="intel-verify">
      <button class="btn btn-ghost btn-sm" type="button" data-toggle-verify>Verifikasi aman</button>
      <div class="intel-verify-body" hidden>
        <p>${esc(verification.summary || "")}</p>
        <div class="intel-command">
          <code>${esc(verification.request || "")}</code>
          <button class="btn btn-ghost btn-sm" type="button" data-copy="${esc(verification.request || "")}">Salin</button>
        </div>
        <ol class="intel-steps">${steps}</ol>
        <p class="fine-print">${esc(verification.safety || "")}</p>
      </div>
    </div>`;
}

async function copyToClipboard(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    const area = document.createElement("textarea");
    area.value = text;
    area.style.position = "fixed";
    area.style.opacity = "0";
    document.body.appendChild(area);
    area.select();
    let ok = false;
    try {
      ok = document.execCommand("copy");
    } catch {
      ok = false;
    }
    area.remove();
    return ok;
  }
}

function markdownText(value) {
  return String(value ?? "")
    .replace(/\r?\n/g, " ")
    .replace(/\|/g, "\\|")
    .trim();
}

function reportFilename(scan) {
  const rawHost = String(scan.host || scan.target || "target")
    .replace(/^https?:\/\//i, "")
    .split(/[/?#]/, 1)[0];
  const host = rawHost
    .replace(/[^a-z0-9.-]+/gi, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 64) || "target";
  const stamp = String(scan.finished_at || scan.created_at || "")
    .slice(0, 10)
    .replace(/-/g, "") || "report";
  return `sentinel-intel-${host}-${stamp}.md`;
}

function downloadTextFile(filename, text) {
  const blob = new Blob([text], { type: "text/markdown;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.rel = "noopener";
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function buildIntelMarkdown(report) {
  const scan = report.scan || {};
  const posture = report.posture || {};
  const summary = report.summary || {};
  const edge = report.edge || {};
  const bounty = edge.bounty || {};
  const toolkit = report.toolkit || { items: [], disclaimer: "" };
  const best = report.best_findings || [];
  const paths = report.attack_paths || [];
  const components = report.components || [];
  const mitre = report.mitre || [];
  const advice = report.advice || [];
  const gaps = report.coverage_gaps || [];
  const lines = [];
  const add = (...values) => lines.push(...values);

  add(
    "# Cosmos Molorum Sentinel — Laporan Intelijen",
    "",
    "> Laporan ini dihasilkan dari asesmen non-destruktif yang diotorisasi. Temuan perlu validasi manual dan bukan bukti eksploitasi.",
    "",
    "## Ringkasan asesmen",
    "",
    `- **Target:** ${markdownText(scan.target) || "—"}`,
    `- **ID asesmen:** ${markdownText(scan.id) || "—"}`,
    `- **Status:** ${markdownText(STATUS_LABEL[scan.status] || scan.status) || "—"}`,
    `- **Skor bertahan:** ${markdownText(scan.score ?? "—")}${scan.grade ? ` (${markdownText(scan.grade)})` : ""}`,
    `- **Waktu:** ${markdownText(fmtDate(scan.finished_at || scan.created_at))}`,
    `- **Operator:** ${markdownText(scan.requested_by) || "—"}`,
    `- **Permintaan:** ${markdownText(scan.requests ?? 0)}`,
    `- **Durasi:** ${markdownText(fmtDuration(scan.elapsed_ms))}`,
    `- **Catatan otorisasi:** ${markdownText(scan.note) || "—"}`,
    "",
    "## Postur ofensif",
    "",
    `- **Eksploitabilitas:** ${markdownText(posture.exploitability ?? "—")}/100 (${markdownText(posture.label) || "—"})`,
    `- **Permukaan serangan:** ${markdownText(posture.attack_surface ?? "—")}/100 (${markdownText(posture.surface_label) || "—"})`,
    `- **Temuan:** ${markdownText(summary.findings ?? 0)}`,
    `- **Jalur serangan:** ${markdownText(summary.paths ?? 0)}`,
    `- **Komponen:** ${markdownText(summary.components ?? 0)}`,
    `- **Teknik MITRE:** ${markdownText(summary.mitre ?? 0)}`,
    `- **Celah cakupan:** ${markdownText(summary.gaps ?? 0)}`,
    "",
  );
  if (posture.note) add(`**${markdownText(posture.note)}**`, "");
  if (posture.operator_note) add(markdownText(posture.operator_note), "");

  add("## Temuan prioritas", "");
  if (!best.length) {
    add("Tidak ada temuan yang diprioritaskan pada asesmen ini.", "");
  } else {
    best.forEach((item, index) => {
      const verification = item.verification || {};
      add(
        `### ${index + 1}. [${markdownText(SEVERITY_LABEL[item.severity] || item.severity).toUpperCase()}] ${markdownText(item.title)}`,
        "",
        `- **CWE:** ${markdownText(item.cwe) || "—"}${item.cwe_name ? ` — ${markdownText(item.cwe_name)}` : ""}`,
        `- **Teknik:** ${markdownText(item.technique) || "—"}${item.technique_name ? ` — ${markdownText(item.technique_name)}` : ""}`,
        `- **Tahap:** ${markdownText(INTEL_STAGE_LABEL[item.stage] || item.stage) || "—"}`,
        `- **Eksploitabilitas:** ${markdownText(item.exploitability ?? "—")}/100`,
        `- **Dampak:** ${markdownText(item.impact ?? "—")}/100`,
        `- **Keyakinan:** ${markdownText(item.confidence ?? "—")}/100`,
        `- **Risiko:** ${markdownText(item.risk ?? "—")}/100`,
        "",
      );
      if (item.detail) add(markdownText(item.detail), "");
      if (item.evidence) add("**Bukti**", "", "```", String(item.evidence).trim(), "```", "");
      add("**Verifikasi aman**", "", markdownText(verification.summary) || "Gunakan satu permintaan non-destruktif untuk konfirmasi.", "");
      if (verification.request) add("```bash", String(verification.request).trim(), "```", "");
      const steps = (verification.steps || []).map((step) => markdownText(step)).filter(Boolean);
      if (steps.length) add(...steps.map((step) => `1. ${step}`), "");
      if (verification.safety) add(`_${markdownText(verification.safety)}_`, "");
      add("", `**Perbaikan:** ${markdownText(item.remediation) || "—"}`, "");
    });
  }

  add("## Jalur serangan", "");
  if (!paths.length) {
    add("Belum ada jalur serangan yang dapat disusun dari temuan.", "");
  } else {
    paths.forEach((path) => {
      add(`### ${markdownText(path.name)}`, "");
      add(`- **Kemungkinan:** ${markdownText(path.likelihood)} (${markdownText(path.likelihood_score ?? "—")}/100)`);
      add("", "**Tahapan:**", "");
      (path.stages || []).forEach((stage, index) => {
        add(`${index + 1}. **${markdownText(stage.name)}** — ${markdownText(stage.detail)}`);
      });
      add("", `**Titik putus:** ${markdownText(path.breakpoint) || "—"}`, "");
      if ((path.evidence || []).length) {
        add(`**Bukti:** ${path.evidence.map((item) => `[${markdownText(SEVERITY_LABEL[item.severity] || item.severity)}] ${markdownText(item.title)}`).join("; ")}`, "");
      }
    });
  }

  add("## Intelijen komponen", "");
  if (!components.length) {
    add("Belum ada komponen yang terdeteksi dari bukti temuan.", "");
  } else {
    add("| Komponen | Keyakinan | Bukti |", "| --- | --- | --- |");
    components.forEach((component) => {
      add(`| ${markdownText(component.name)} | ${markdownText(component.confidence)} | ${markdownText(component.evidence)} |`);
    });
    add("");
  }

  add("## MITRE ATT&CK", "");
  if (!mitre.length) {
    add("Belum ada teknik yang terpetakan.", "");
  } else {
    add("| Teknik | Nama | Temuan |", "| --- | --- | --- |");
    mitre.forEach((item) => {
      add(`| ${markdownText(item.id)} | ${markdownText(item.name)} | ${markdownText(item.findings)} |`);
    });
    add("");
  }

  add("## Saran operator", "");
  if (!advice.length) {
    add("Belum ada saran operator untuk asesmen ini.", "");
  } else {
    advice.forEach((item) => {
      add(`### ${markdownText(item.title)}`, "", `- **Jendela:** ${markdownText(item.window)}`, `- **Pemilik:** ${markdownText(item.owner)}`, "");
      if (item.why) add(markdownText(item.why), "");
      if (item.action) add(`**Tindakan:** ${markdownText(item.action)}`, "");
    });
  }

  add("## Edge & origin", "");
  add(
    `- **Terdeteksi:** ${edge.detected ? "Ya" : "Tidak"}`,
    `- **Provider:** ${(edge.providers || []).map(markdownText).filter(Boolean).join(", ") || "—"}`,
    `- **Provider utama:** ${markdownText(edge.primary) || "—"}`,
    `- **Keyakinan:** ${markdownText(edge.confidence) || "—"}`,
    `- **Challenge terlihat:** ${edge.challenge ? "Ya" : "Tidak"}`,
    "",
  );
  if (edge.summary) add(markdownText(edge.summary), "");
  if ((edge.signals || []).length) {
    add("", "**Fingerprint edge**", "");
    edge.signals.forEach((signal) => {
      add(`- **${markdownText(signal.provider)}** — ${markdownText(signal.source)}: ${markdownText(signal.evidence)}`);
    });
  }
  if ((edge.origin_signals || []).length) {
    add("", "**Indikasi origin**", "");
    edge.origin_signals.forEach((signal) => {
      add(`- **${markdownText(signal.label)}** — ${markdownText(signal.source)}: ${markdownText(signal.evidence)}`);
    });
  }
  if (edge.origin_note) add("", markdownText(edge.origin_note));
  if ((edge.authorized_paths || []).length) {
    add("", "**Jalur uji resmi**", "");
    edge.authorized_paths.forEach((item) => add(`- ${markdownText(item)}`));
  }
  if ((edge.prohibited || []).length) {
    add("", "**Jangan dilakukan**", "");
    edge.prohibited.forEach((item) => add(`- ${markdownText(item)}`));
  }
  if ((edge.limitations || []).length) {
    add("", `_${(edge.limitations || []).map(markdownText).join(" ")}_`);
  }
  add("");

  add("## Bounty & disclosure", "");
  add(
    `- **Mode:** ${markdownText(bounty.mode) || "authorized-only"}`,
    "",
  );
  if (bounty.scope_note) add(markdownText(bounty.scope_note), "");
  if ((bounty.checklist || []).length) {
    add("", "**Checklist**", "");
    bounty.checklist.forEach((item) => add(`- ${markdownText(item)}`));
  }
  if ((bounty.not_findings || []).length) {
    add("", "**Bukan temuan**", "");
    bounty.not_findings.forEach((item) => add(`- ${markdownText(item)}`));
  }
  if ((bounty.report_fields || []).length) {
    add("", `**Isi laporan:** ${bounty.report_fields.map(markdownText).join(" ")}`);
  }
  if ((bounty.disclosure || []).length) {
    add("", bounty.disclosure.map(markdownText).join(" "));
  }
  add("");

  add("## Toolkit verifikasi aman", "");
  if (toolkit.disclaimer) add(markdownText(toolkit.disclaimer), "");
  if (!(toolkit.items || []).length) {
    add("Toolkit belum tersedia untuk asesmen ini.", "");
  } else {
    toolkit.items.forEach((item) => {
      const verification = item.verification || {};
      add(`### ${markdownText(item.title)}`, "", `- **Keparahan:** ${markdownText(SEVERITY_LABEL[item.severity] || item.severity)}`, `- **CWE:** ${markdownText(item.cwe) || "—"}`, "");
      if (verification.request) add("```bash", String(verification.request).trim(), "```", "");
      if (verification.safety) add(`_${markdownText(verification.safety)}_`, "");
    });
  }

  add("## Cakupan yang belum memberi hasil", "");
  if (!gaps.length) {
    add("Tidak ada celah cakupan yang dilaporkan.", "");
  } else {
    gaps.forEach((gap) => {
      add(`- **${markdownText(gap.name)}** (${markdownText(gap.module_id)}) — ${markdownText(STATUS_LABEL[gap.status] || gap.status)}: ${markdownText(gap.reason)}`);
    });
    add("");
  }

  add(
    "---",
    "",
    `Dihasilkan oleh Cosmos Molorum Sentinel pada ${markdownText(fmtDate(new Date().toISOString()))}.`,
    "Aktivitas operator tercatat pada jejak audit. Gunakan laporan ini hanya untuk aset yang Anda berwenang menilai.",
  );

  return lines.join("\n").replace(/\n{3,}/g, "\n\n").trimEnd() + "\n";
}

async function renderIntel(scanId = "") {
  const view = $("#view");
  view.innerHTML = `<div class="stack">${loadingBlock()}</div>`;
  try {
    const [report, scanList] = await Promise.all([
      api(`/api/intel${scanId ? `?scan_id=${encodeURIComponent(scanId)}` : ""}`),
      api("/api/scans?limit=80").catch(() => ({ scans: [] })),
    ]);
    const scan = report.scan;
    const posture = report.posture;
    const scans = (scanList.scans || []).filter(
      (item) => item.status === "completed" || item.status === "cancelled",
    );
    const options = scans
      .map(
        (item) =>
          `<option value="${esc(item.id)}" ${item.id === scan.id ? "selected" : ""}>${esc(item.host || item.target)} · ${esc(item.score ?? "—")} · ${esc(fmtDate(item.created_at))}</option>`,
      )
      .join("");
    const tone = intelTone(posture.exploitability);
    const best = report.best_findings || [];
    const paths = report.attack_paths || [];
    const components = report.components || [];
    const mitre = report.mitre || [];
    const advice = report.advice || [];
    const gaps = report.coverage_gaps || [];
    const toolkit = report.toolkit || { items: [], disclaimer: "" };
    const edge = report.edge || {
      detected: false,
      providers: [],
      primary: "",
      challenge: false,
      confidence: "—",
      summary: "Profil edge belum tersedia pada laporan ini.",
      signals: [],
      origin_signals: [],
      origin_note: "",
      authorized_paths: [],
      prohibited: [],
      bounty: {
        mode: "authorized-only",
        scope_note: "",
        checklist: [],
        report_fields: [],
        disclosure: [],
        not_findings: [],
      },
      limitations: [],
    };
    const maxMitre = Math.max(1, ...mitre.map((item) => item.findings));

    const bestMarkup = best.length
      ? best
          .map(
            (item, index) => `
            <article class="card intel-best">
              <div class="intel-rank">${String(index + 1).padStart(2, "0")}</div>
              <div class="intel-best-main">
                <div class="intel-best-top">
                  ${severityBadge(item.severity)}
                  <span class="intel-chip mono" title="${esc(item.cwe_name || item.cwe)}">${esc(item.cwe)}</span>
                  ${item.capec ? `<span class="intel-chip mono">${esc(item.capec)}</span>` : ""}
                  <span class="intel-chip">${esc(INTEL_STAGE_LABEL[item.stage] || item.stage)}</span>
                  <span class="intel-chip mono">${esc(item.technique)}</span>
                  ${item.occurrences > 1 ? `<span class="intel-chip">${item.occurrences} kemunculan</span>` : ""}
                </div>
                <h3>${esc(item.title)}</h3>
                <p>${esc(item.detail)}</p>
                ${item.evidence ? `<div class="intel-evidence mono">${esc(String(item.evidence).slice(0, 280))}</div>` : ""}
                <div class="intel-metrics">
                  <div class="intel-metric">
                    <span>Eksploitabilitas</span>
                    ${intelMeter(item.exploitability, intelTone(item.exploitability))}
                    <strong>${item.exploitability}</strong>
                  </div>
                  <div class="intel-metric">
                    <span>Dampak</span>
                    ${intelMeter(item.impact, intelTone(item.impact))}
                    <strong>${item.impact}</strong>
                  </div>
                  <div class="intel-metric">
                    <span>Keyakinan</span>
                    ${intelMeter(item.confidence, intelTone(item.confidence))}
                    <strong>${item.confidence}</strong>
                  </div>
                </div>
                <div class="intel-best-foot">
                  ${intelVerifyBlock(item)}
                  <p class="intel-fix"><strong>Perbaikan:</strong> ${esc(item.remediation)}</p>
                </div>
              </div>
              <div class="intel-risk tone-${intelTone(item.risk)}">
                <strong>${item.risk}</strong>
                <span>risiko</span>
              </div>
            </article>`,
          )
          .join("")
      : `<div class="card card-pad">${emptyState("Tidak ada temuan untuk diprioritaskan", "Semua modul yang berjalan tidak melaporkan temuan pada asesmen ini. Lanjutkan dengan validasi manual dan asesmen berkala.")}</div>`;

    const pathMarkup = paths.length
      ? paths
          .map(
            (path) => `
            <article class="intel-path">
              <div class="intel-path-top">
                <h3>${esc(path.name)}</h3>
                <span class="intel-likelihood tone-${intelTone(path.likelihood_score)}">${esc(path.likelihood)}</span>
              </div>
              <div class="intel-flow">
                ${path.stages
                  .map(
                    (stage, index) => `
                    <div class="intel-stage-node">
                      <span class="intel-stage-state">${String(index + 1).padStart(2, "0")}</span>
                      <strong>${esc(stage.name)}</strong>
                      <small>${esc(stage.detail)}</small>
                    </div>
                    ${index < path.stages.length - 1 ? `<span class="intel-arrow" aria-hidden="true">→</span>` : ""}`,
                  )
                  .join("")}
              </div>
              <p class="intel-breakpoint"><strong>Titik putus:</strong> ${esc(path.breakpoint)}</p>
              <div class="intel-path-evidence">
                ${path.evidence
                  .map(
                    (item) =>
                      `<span class="intel-evidence-chip">${severityBadge(item.severity)}${esc(item.title)}</span>`,
                  )
                  .join("")}
              </div>
            </article>`,
          )
          .join("")
      : `<div class="intel-empty">${emptyState("Belum ada jalur serangan", "Jalur disusun dari kombinasi temuan. Perluas cakupan modul atau validasi temuan secara manual.")}</div>`;

    const componentMarkup = components.length
      ? components
          .map(
            (component) => `
            <div class="intel-component">
              <div><strong>${esc(component.name)}</strong><span class="mono">${esc(component.confidence)}</span></div>
              <p class="mono">${esc(component.evidence)}</p>
            </div>`,
          )
          .join("")
      : `<div class="intel-empty">${emptyState("Belum ada komponen terdeteksi", "Fingerprint teknologi diambil dari bukti temuan pada asesmen ini.")}</div>`;

    const mitreMarkup = mitre.length
      ? mitre
          .map(
            (item) => `
            <div class="intel-mitre-row">
              <span class="mono">${esc(item.id)}</span>
              <div><strong>${esc(item.name)}</strong>${intelMeter((item.findings / maxMitre) * 100, "brass")}</div>
              <strong>${item.findings}</strong>
            </div>`,
          )
          .join("")
      : `<div class="intel-empty">${emptyState("Belum ada teknik terpetakan", "Teknik ATT&CK muncul setelah temuan dipetakan ke kategori.")}</div>`;

    const adviceMarkup = advice.length
      ? advice
          .map(
            (item) => `
            <article class="intel-advice">
              <div class="intel-advice-head">
                <span class="intel-window">${esc(item.window)}</span>
                <span class="intel-owner">${esc(item.owner)}</span>
              </div>
              <h3>${esc(item.title)}</h3>
              <p>${esc(item.why)}</p>
              <p class="intel-action">${esc(item.action)}</p>
            </article>`,
          )
          .join("")
      : `<div class="intel-empty">${emptyState("Belum ada saran", "Saran operator muncul setelah ada temuan yang dapat dikelompokkan.")}</div>`;

    const toolkitMarkup = toolkit.items.length
      ? toolkit.items
          .map(
            (item) => `
            <article class="intel-tool">
              <div class="intel-tool-head">
                ${severityBadge(item.severity)}
                <strong>${esc(item.title)}</strong>
                <span class="intel-chip mono" title="${esc(item.cwe_name || item.cwe)}">${esc(item.cwe)}</span>
              </div>
              <div class="intel-command">
                <code>${esc(item.verification.request)}</code>
                <button class="btn btn-ghost btn-sm" type="button" data-copy="${esc(item.verification.request)}">Salin</button>
              </div>
              <p class="fine-print">${esc(item.verification.safety)}</p>
            </article>`,
          )
          .join("")
      : `<div class="intel-empty">${emptyState("Toolkit belum tersedia", "Toolkit terisi setelah ada temuan prioritas pada asesmen ini.")}</div>`;

    const gapMarkup = gaps.length
      ? `<div class="card intel-gaps">
          <div class="section-head tight">
            <div><p class="eyebrow">Cakupan</p><h2 class="display-sm">Modul yang belum memberi hasil</h2></div>
            <span class="mono dim">${gaps.length} modul</span>
          </div>
          <div class="intel-gap-list">
            ${gaps
              .map(
                (gap) => `
              <div class="intel-gap">
                <div><strong>${esc(gap.name)}</strong><span class="mono">${esc(gap.module_id)}</span></div>
                ${statusBadge(gap.status)}
                <p>${esc(gap.reason)}</p>
              </div>`,
              )
              .join("")}
          </div>
        </div>`
      : "";

    const edgeSignalMarkup = edge.signals.length
      ? edge.signals
          .map(
            (signal) => `
          <div class="intel-edge-signal">
            <strong>${esc(signal.provider)}</strong>
            <span>${esc(signal.source)} · ${esc(signal.evidence)}</span>
          </div>`,
          )
          .join("")
      : `<p class="fine-print">Tidak ada fingerprint edge positif pada data pemindaian.</p>`;
    const originSignalMarkup = edge.origin_signals
      .map(
        (signal) => `
        <div class="intel-edge-signal">
          <strong>${esc(signal.label)}</strong>
          <span>${esc(signal.source)} · ${esc(signal.evidence)}</span>
        </div>`,
      )
      .join("");
    const edgePathMarkup = edge.authorized_paths.map((item) => `<li>${esc(item)}</li>`).join("");
    const edgeStopMarkup = edge.prohibited.map((item) => `<li>${esc(item)}</li>`).join("");
    const bounty = edge.bounty || {
      mode: "authorized-only",
      scope_note: "",
      checklist: [],
      report_fields: [],
      disclosure: [],
      not_findings: [],
    };
    const bountyChecklistMarkup = (bounty.checklist || [])
      .map((item) => `<li>${esc(item)}</li>`)
      .join("");
    const bountyNotFindingsMarkup = (bounty.not_findings || [])
      .map((item) => `<li>${esc(item)}</li>`)
      .join("");
    const bountyReportMarkup = (bounty.report_fields || []).join(" ");
    const bountyDisclosureMarkup = (bounty.disclosure || []).join(" ");
    const edgeMarkup = `
      <div class="section">
        <div class="card intel-panel intel-edge">
          <figure class="intel-edge-banner">
            <img src="/assets/posters/edge.svg?v=2.2.0" alt="" width="1200" height="440" loading="lazy" decoding="async" />
            <figcaption><span>Profil edge</span><strong>Bukti pasif, keputusan terukur.</strong></figcaption>
          </figure>
          <div class="section-head tight">
            <div><p class="eyebrow">Edge &amp; origin</p><h2 class="display-sm">Asesmen edge Cloudflare</h2></div>
            <span class="intel-tone tone-${edge.detected ? "medium" : "low"}">${edge.detected ? esc(edge.primary || "Edge WAF") : "Tanpa edge"}</span>
          </div>
          <p class="intel-edge-summary">${esc(edge.summary)}</p>
          <div class="intel-edge-grid">
            <div class="intel-edge-col">
              <h3>Fingerprint edge</h3>
              <div class="intel-edge-signals">${edgeSignalMarkup}</div>
              <h3>Indikasi origin</h3>
              ${originSignalMarkup ? `<div class="intel-edge-signals">${originSignalMarkup}</div>` : ""}
              <p class="fine-print">${esc(edge.origin_note || "")}</p>
            </div>
            <div class="intel-edge-col">
              <h3>Jalur uji resmi</h3>
              <ul class="intel-edge-list">${edgePathMarkup}</ul>
              <h3 class="intel-edge-stop-title">Jangan dilakukan</h3>
              <ul class="intel-edge-list intel-edge-stop">${edgeStopMarkup}</ul>
            </div>
          </div>
          <div class="intel-bounty">
            <div class="intel-bounty-head">
              <h3>Bounty &amp; disclosure</h3>
              <span class="intel-chip mono">${esc(bounty.mode || "authorized-only")}</span>
            </div>
            <p class="intel-edge-summary">${esc(bounty.scope_note || "")}</p>
            <div class="intel-bounty-grid">
              <div>
                <h4>Checklist</h4>
                <ul class="intel-edge-list">${bountyChecklistMarkup}</ul>
              </div>
              <div>
                <h4>Bukan temuan</h4>
                <ul class="intel-edge-list intel-edge-stop">${bountyNotFindingsMarkup}</ul>
              </div>
            </div>
            ${bountyReportMarkup ? `<p class="fine-print intel-bounty-report"><strong>Isi laporan:</strong> ${esc(bountyReportMarkup)}</p>` : ""}
            ${bountyDisclosureMarkup ? `<p class="fine-print">${esc(bountyDisclosureMarkup)}</p>` : ""}
          </div>
          ${
            edge.limitations.length
              ? `<p class="fine-print intel-edge-limits">${esc(edge.limitations.join(" "))}</p>`
              : ""
          }
        </div>
      </div>`;

    view.innerHTML = `
      <div class="print-head">
        <p class="print-brand">Cosmos Molorum Sentinel</p>
        <h1>Laporan Intelijen Keamanan</h1>
        <p class="print-meta">${esc(scan.host)} · ${esc(scan.id)} · ${esc(fmtDate(scan.finished_at || scan.created_at))}</p>
        <p class="print-note">Dihasilkan dari asesmen non-destruktif yang diotorisasi. Temuan perlu validasi manual dan bukan bukti eksploitasi.</p>
      </div>

      ${pageHead(
        "Intelijen ofensif",
        "Intelijen temuan",
        `Pembacaan ofensif untuk <strong>${esc(scan.host)}</strong>. Peringkat eksploitabilitas, jalur serangan yang mungkin, fingerprint komponen, dan resep verifikasi aman dalam satu laporan.`,
        `<label class="analysis-select"><span>Asesmen</span><select id="intel-scan">${options}</select></label>
         <a class="btn btn-ghost btn-sm" href="#/analysis/${encodeURIComponent(scan.id)}">Analisis</a>
         <a class="btn btn-ghost btn-sm" href="#/scans/${encodeURIComponent(scan.id)}">Detail</a>`,
      )}

      <div class="report-bar">
        <div class="report-copy">
          <p class="eyebrow">Laporan asesmen</p>
          <strong>Bawa hasil ke rapat dan tiket perbaikan.</strong>
          <span>Cetak halaman ini atau unduh ringkasan Markdown. Keduanya dihasilkan lokal dari data asesmen yang tersimpan.</span>
        </div>
        <div class="report-actions">
          <button class="btn btn-secondary btn-sm" type="button" data-print-intel>${ICON.print} Cetak laporan</button>
          <button class="btn btn-ghost btn-sm" type="button" data-export-intel>${ICON.download} Unduh Markdown</button>
        </div>
      </div>

      <section class="analysis-hero intel-hero">
        <div class="analysis-score" data-style="--score:${posture.exploitability};--tone:${intelColor(posture.exploitability)}">
          <div class="analysis-score-ring">
            <strong>${posture.exploitability}</strong>
            <span>dari 100</span>
          </div>
          <div class="analysis-grade">Eksploitabilitas <strong>${esc(posture.label)}</strong></div>
        </div>
        <div class="analysis-exec">
          <div class="analysis-exec-top">
            <p class="eyebrow brass">Postur ofensif</p>
            <span class="intel-tone tone-${tone}">${esc(posture.surface_label)} · permukaan ${posture.attack_surface}/100</span>
          </div>
          <h2>${esc(posture.note)}</h2>
          <p>${esc(posture.operator_note)}</p>
          <div class="intel-surface">
            <div class="intel-surface-head"><span>Permukaan serangan</span><strong>${posture.attack_surface}/100</strong></div>
            ${intelMeter(posture.attack_surface, intelTone(posture.attack_surface))}
          </div>
          <div class="analysis-chips">
            <span>${ICON.alert} ${report.summary.findings} temuan</span>
            <span>${ICON.layers} ${report.summary.paths} jalur</span>
            <span>${ICON.scan} ${report.summary.components} komponen</span>
            <span>${ICON.orbit} ${report.summary.mitre} teknik</span>
            ${edge.detected ? `<span>${ICON.layers} ${esc(edge.primary || "Edge WAF")} edge</span>` : ""}
          </div>
        </div>
      </section>

      <div class="section">
        <div class="grid-4 analysis-kpis">
          <div class="card analysis-kpi"><span>Risiko tertinggi</span><strong>${best.length ? best[0].risk : 0}</strong><small>skor gabungan</small></div>
          <div class="card analysis-kpi"><span>Jalur serangan</span><strong>${report.summary.paths}</strong><small>terindikasi dari temuan</small></div>
          <div class="card analysis-kpi"><span>Komponen</span><strong>${report.summary.components}</strong><small>fingerprint dari bukti</small></div>
          <div class="card analysis-kpi"><span>Modul belum hasil</span><strong>${report.summary.gaps}</strong><small>skipped atau error</small></div>
        </div>
      </div>

      <div class="section">
        <div class="section-head">
          <div><p class="eyebrow">Prioritas ofensif</p><h2>Temuan paling layak dieksploitasi</h2></div>
          <span class="mono dim">${best.length} dari ${report.summary.findings} temuan</span>
        </div>
        <div class="intel-best-list">${bestMarkup}</div>
      </div>

      <div class="section intel-split">
        <div class="card intel-panel intel-paths">
          <div class="section-head tight">
            <div><p class="eyebrow">Rantai serangan</p><h2 class="display-sm">Peta jalur serangan</h2></div>
            <span class="mono dim">${paths.length} jalur</span>
          </div>
          ${pathMarkup}
        </div>
        <div class="stack">
          <div class="card intel-panel">
            <div class="section-head tight">
              <div><p class="eyebrow">Tindakan</p><h2 class="display-sm">Saran operator</h2></div>
            </div>
            ${adviceMarkup}
          </div>
          <div class="card intel-panel">
            <div class="section-head tight">
              <div><p class="eyebrow">Fingerprint</p><h2 class="display-sm">Intelijen komponen</h2></div>
              <span class="mono dim">${components.length} komponen</span>
            </div>
            ${componentMarkup}
          </div>
          <div class="card intel-panel">
            <div class="section-head tight">
              <div><p class="eyebrow">Pemetaan</p><h2 class="display-sm">MITRE ATT&CK</h2></div>
              <span class="mono dim">${mitre.length} teknik</span>
            </div>
            ${mitreMarkup}
          </div>
        </div>
      </div>

      ${edgeMarkup}

      <div class="section">
        <div class="card intel-panel intel-toolkit">
          <div class="section-head tight">
            <div><p class="eyebrow">Toolkit</p><h2 class="display-sm">PoC verifikasi aman</h2></div>
            <span class="intel-safe">Non-destruktif</span>
          </div>
          <p class="intel-disclaimer">${esc(toolkit.disclaimer)}</p>
          ${toolkitMarkup}
        </div>
      </div>

      ${gapMarkup}
    `;

    applyDynamicStyles(view);
    const select = $("#intel-scan", view);
    if (select) {
      select.addEventListener("change", () => {
        if (select.value) navigate(`intel/${select.value}`);
      });
    }
    $$("[data-toggle-verify]", view).forEach((button) => {
      button.addEventListener("click", () => {
        const body = button.parentElement?.querySelector(".intel-verify-body");
        if (!body) return;
        body.hidden = !body.hidden;
        button.textContent = body.hidden ? "Verifikasi aman" : "Tutup verifikasi";
      });
    });
    $$("[data-copy]", view).forEach((button) => {
      button.addEventListener("click", async () => {
        const ok = await copyToClipboard(button.dataset.copy || "");
        toast(ok ? "Perintah disalin." : "Penyalinan tidak tersedia.", ok ? "success" : "error");
      });
    });
    $("[data-print-intel]", view)?.addEventListener("click", () => {
      window.print();
    });
    $("[data-export-intel]", view)?.addEventListener("click", () => {
      try {
        downloadTextFile(reportFilename(scan), buildIntelMarkdown(report));
        toast("Laporan Markdown diunduh.", "success");
      } catch {
        toast("Laporan tidak dapat diunduh.", "error");
      }
    });
  } catch (err) {
    if (err.status === 404) {
      view.innerHTML = `<div class="card card-pad">${emptyState(
        "Belum ada asesmen selesai",
        "Intelijen tersedia setelah satu pemindaian selesai. Mulai asesmen baru atau buka riwayat untuk memeriksa proses yang masih berjalan.",
      )}<div class="mt-14"><button class="btn btn-primary btn-sm" data-new-scan>${ICON.plus} Pemindaian baru</button></div></div>`;
      $("[data-new-scan]", view)?.addEventListener("click", () => navigate("scan"));
      return;
    }
    view.innerHTML = errorState(err.message);
    bindRetry(view, () => renderIntel(scanId));
  }
}

/* Module library --------------------------------------------------------- */

async function renderModules() {
  const view = $("#view");
  view.innerHTML = `<div class="stack">${loadingBlock()}</div>`;
  try {
    const data = await ensureModules();
    view.innerHTML = `
      ${pageHead(
        "Katalog pemeriksaan",
        "Pustaka modul",
        `${data.count} modul disusun dalam lima kategori. Modul pasif membaca konfigurasi yang sudah tersedia; modul aktif mengirim probe non-destruktif dalam batas anggaran.`,
        `<button class="btn btn-primary btn-sm" data-new-scan>${ICON.plus} Pemindaian baru</button>`,
      )}
      <div class="library-toolbar">
        <div class="search-field">
          <svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="11" cy="11" r="6.5"/><path d="m16 16 4.5 4.5"/></svg>
          <input id="module-search" type="search" placeholder="Cari nama modul atau kategori" value="${esc(state.libraryQuery)}" />
        </div>
        <div class="filters flush">
          <button class="filter-btn ${state.libraryCategory === "all" ? "active" : ""}" data-cat="all">Semua</button>
          ${data.categories
            .map(
              (cat) =>
                `<button class="filter-btn ${state.libraryCategory === cat.name ? "active" : ""}" data-cat="${esc(cat.name)}">${esc(cat.name)}</button>`,
            )
            .join("")}
        </div>
        <span class="library-meta" id="library-count">${data.count} modul</span>
      </div>
      <div id="module-results"></div>
    `;

    const results = $("#module-results", view);
    const queryInput = $("#module-search", view);
    const paint = () => {
      const query = state.libraryQuery.trim().toLowerCase();
      const filteredCategories = data.categories
        .filter(
          (cat) => state.libraryCategory === "all" || cat.name === state.libraryCategory,
        )
        .map((cat) => ({
          ...cat,
          modules: cat.modules.filter((mod) => {
            if (!query) return true;
            return (
              mod.name.toLowerCase().includes(query) ||
              mod.id.toLowerCase().includes(query) ||
              mod.category.toLowerCase().includes(query) ||
              mod.description.toLowerCase().includes(query)
            );
          }),
        }))
        .filter((cat) => cat.modules.length);
      const total = filteredCategories.reduce((sum, cat) => sum + cat.modules.length, 0);
      $("#library-count", view).textContent = `${total} modul`;
      if (!total) {
        results.innerHTML = `<div class="card">${emptyState("Modul tidak ditemukan", "Coba kata kunci lain atau pilih kategori yang berbeda.")}</div>`;
        return;
      }
      results.innerHTML = filteredCategories
        .map(
          (cat) => `<section class="category-block">
            <div class="category-block-head">
              <span class="mono dim">${esc(CATEGORY_INDEX[cat.name] || "—")}</span>
              <h2>${esc(cat.name)}</h2>
              <span class="dim fine">${cat.modules.length} modul</span>
            </div>
            <div class="module-grid">
              ${cat.modules
                .map(
                  (mod) => `<article class="card module-card">
                    <div class="module-card-top">
                      <span class="module-id">${esc(mod.id)}</span>
                      ${severityBadge(mod.severity)}
                    </div>
                    <h3>${esc(mod.name)}</h3>
                    <p>${esc(mod.description)}</p>
                    <div class="module-foot">
                      <span>${esc(mod.passive ? "Pasif" : "Aktif")}</span>
                      <span>·</span>
                      <span>${esc(mod.category)}</span>
                    </div>
                  </article>`,
                )
                .join("")}
            </div>
          </section>`,
        )
        .join("");
    };
    paint();
    queryInput.addEventListener("input", (event) => {
      state.libraryQuery = event.target.value;
      paint();
    });
    $$("[data-cat]", view).forEach((button) =>
      button.addEventListener("click", () => {
        state.libraryCategory = button.dataset.cat;
        $$("[data-cat]", view).forEach((item) =>
          item.classList.toggle("active", item === button),
        );
        paint();
      }),
    );
    $("[data-new-scan]", view).addEventListener("click", () => navigate("scan"));
  } catch (err) {
    view.innerHTML = errorState(err.message);
    bindRetry(view, renderModules);
  }
}

/* Audit ------------------------------------------------------------------ */

async function renderAudit() {
  const view = $("#view");
  view.innerHTML = `<div class="stack">${loadingBlock()}</div>`;
  try {
    const data = await api("/api/audit?limit=150");
    const entries = data.entries || [];
    view.innerHTML = `
      ${pageHead(
        "Keterlacakan",
        "Jejak audit",
        "Aktivitas masuk, pembuatan asesmen, pembatalan, ekspor, dan perubahan kredensial dicatat dengan waktu dan alamat klien.",
        "",
      )}
      ${
        entries.length
          ? `<div class="table-wrap"><table class="data">
              <thead><tr><th>Waktu</th><th>Aktor</th><th>Aksi</th><th>Target</th><th>Alamat</th><th>Detail</th></tr></thead>
              <tbody>
                ${entries
                  .map(
                    (entry) => `<tr>
                      <td>${esc(fmtDate(entry.ts))}</td>
                      <td>${esc(entry.actor)}</td>
                      <td><span class="audit-action">${esc(entry.action)}</span></td>
                      <td class="target-cell">${esc(entry.target || "—")}</td>
                      <td><span class="audit-meta">${esc(entry.client_ip || "—")}</span></td>
                      <td><span class="audit-meta">${esc(JSON.stringify(entry.meta || {}))}</span></td>
                    </tr>`,
                  )
                  .join("")}
              </tbody>
            </table></div>`
          : `<div class="card">${emptyState("Audit masih kosong", "Aktivitas konsol akan tercatat otomatis setelah Anda mulai menggunakan Sentinel.")}</div>`
      }
    `;
  } catch (err) {
    view.innerHTML = errorState(err.message);
    bindRetry(view, renderAudit);
  }
}

/* Modal ------------------------------------------------------------------ */

let modalCleanup = null;

function openModal({ kicker = "Konfirmasi", title, body, actions = [] }) {
  closeModal();
  const modal = $("#modal");
  $("#modal-kicker").textContent = kicker;
  $("#modal-title").textContent = title;
  $("#modal-body").innerHTML = body;
  const actionRoot = $("#modal-actions");
  actionRoot.innerHTML = "";
  actions.forEach((action) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = `btn btn-${action.variant || "secondary"}`;
    button.textContent = action.label;
    button.addEventListener("click", () => {
      if (action.close) closeModal();
      if (action.onClick) action.onClick();
    });
    actionRoot.appendChild(button);
  });
  modal.hidden = false;
  document.body.style.overflow = "hidden";
  const onKey = (event) => {
    if (event.key === "Escape") closeModal();
  };
  document.addEventListener("keydown", onKey);
  modalCleanup = () => document.removeEventListener("keydown", onKey);
  setTimeout(() => actionRoot.querySelector("button")?.focus(), 40);
}

function closeModal() {
  const modal = $("#modal");
  modal.hidden = true;
  document.body.style.overflow = "";
  if (modalCleanup) {
    modalCleanup();
    modalCleanup = null;
  }
}

$$("[data-modal-close]").forEach((node) =>
  node.addEventListener("click", closeModal),
);

function openAccountModal() {
  openModal({
    kicker: "Keamanan akun",
    title: "Ganti kata sandi",
    body: `
      <p>Gunakan kata sandi unik minimal 12 karakter. Sesi saat ini tetap aktif setelah perubahan.</p>
      <label class="field"><span>Kata sandi saat ini</span><input id="pwd-current" type="password" autocomplete="current-password" /></label>
      <label class="field"><span>Kata sandi baru</span><input id="pwd-new" type="password" autocomplete="new-password" /></label>
      <label class="field"><span>Ulangi kata sandi baru</span><input id="pwd-confirm" type="password" autocomplete="new-password" /></label>
      <div class="form-error" id="pwd-error" role="alert" hidden></div>
    `,
    actions: [
      { label: "Batal", variant: "ghost", close: true },
      {
        label: "Simpan kata sandi",
        variant: "primary",
        onClick: async () => {
          const current = $("#pwd-current").value;
          const next = $("#pwd-new").value;
          const confirm = $("#pwd-confirm").value;
          const error = $("#pwd-error");
          error.hidden = true;
          if (next.length < 12) {
            error.textContent = "Kata sandi baru minimal 12 karakter.";
            error.hidden = false;
            return;
          }
          if (next !== confirm) {
            error.textContent = "Konfirmasi kata sandi tidak cocok.";
            error.hidden = false;
            return;
          }
          try {
            await api("/api/auth/password", {
              method: "POST",
              body: { current_password: current, new_password: next },
            });
            closeModal();
            toast("Kata sandi diperbarui.", "success");
          } catch (err) {
            error.textContent = err.message;
            error.hidden = false;
          }
        },
      },
    ],
  });
}

/* Start ------------------------------------------------------------------ */

boot();

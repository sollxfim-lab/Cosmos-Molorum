# Cosmos Molorum

Cosmos Molorum is a Debian-first, self-hosted control plane for application and game servers. It pairs a FastAPI panel with a responsive React interface and a local node runtime covering the day-to-day work of running workloads: live console, resource telemetry, file management, backups, schedules, databases, allocations, subusers, and a complete audit trail.

Version **2.2.0** sharpens that surface for daily use: an observatory mission poster with live fleet totals, a keyboard-first command palette on `Ctrl`/`Cmd` + `K`, a renewal radar that ranks plan expiries by urgency, expiry badges on workload cards, CSV fleet export for administrators, and a version-aware shell. It builds on 2.1.0, which introduced granular Pterodactyl-style subuser permissions, TOTP two-factor authentication with single-use recovery codes, archive, extract, chmod and copy operations in the file manager, multi-task schedules, managed MySQL and MariaDB database hosts, a Debian and Ubuntu host health view, self-healing egg catalogues with deployment coverage and bulk installation, an owner terminal with administrator-controlled per-server sudo, safe Minecraft version upgrades with automatic pre-upgrade backups, Modrinth plugin and mod update detection, paid plans with manual DANA and Touch 'n Go checkout, automatically provisioned orders, redeem codes, per-server acceptable-use rules, and automatic enforcement against dangerous activity.

## Highlights

- **Minecraft servers** — install Vanilla, Paper, Purpur, Folia, Fabric, Quilt, Forge, NeoForge, Velocity, Waterfall, BungeeCord, or Bedrock Dedicated Server, choose the Minecraft version and loader build, accept the EULA, edit `server.properties`, query live status, and install plugins or mods from Modrinth or local uploads.
- **Safe maintenance** — compare installed server software with the current upstream release, upgrade with one click, and keep an automatic pre-upgrade backup. Check tracked plugins and mods for newer compatible Modrinth builds and update them individually.
- **Catalogue integrity** — built-in nests and eggs are upserted on startup and repaired automatically if a database row is missing, so Minecraft Java egg 27 and Bedrock egg 28 remain available after an upgrade.
- **Deployment coverage** — the nests catalogue marks installed eggs in green and those without a deployment in yellow, previews node capacity, and can install selected eggs or every missing egg in one sequential batch.
- **Owner terminal** — server owners and administrators get an xterm terminal scoped to the server directory, with command history, cancellation, output limits, activity auditing, and an administrator-controlled per-server sudo switch.
- **Plans and billing** — four deliberately distinct tiers (Starter, Standard, Pro and Premium) with their own artwork, limits and deployment slots. Customers pay by DANA QR, DANA account, Touch 'n Go QR, Touch 'n Go account, bank transfer or another configured channel, attach a receipt, and follow the order until an owner approves it.
- **Approval provisioning** — an approved order creates the requested server or applies the plan to an existing one, enforces plan slots, database, backup and allocation limits, and queues the Minecraft installer when the selected egg needs it. Redeem codes grant a plan without manual payment review.
- **Rules and enforcement** — global, nest, egg and per-server rules appear in each server workspace. Console commands, terminal input, saved files, uploads and schedules are scanned for DDoS tooling, floods, scanners, reverse shells, destructive host commands and credential theft. Critical findings suspend the server; repeated attempts ban the account.
- **Operations dashboard** — fleet health, node capacity, workload filters, live CPU/memory/disk figures, an observatory mission poster with live totals, and recent activity.
- **Renewal radar** — every plan expiry sorted by urgency with critical/warning tones, day counts, and a direct renewal action on the dashboard, plus expiry badges on workload cards.
- **Command palette** — `Ctrl`/`Cmd` + `K` opens a keyboard-first search across pages, admin tools, actions and workloads, with arrow-key navigation, grouped results and a mobile-friendly topbar trigger.
- **Fleet export** — administrators can download the current server list, including owner, node, limits, plan and expiry, as a UTF-8 CSV file from the Servers page.
- **Server workspace** — console over WebSocket, power controls, command input, file editor and uploads, backups with download and restore, cron schedules, databases, network allocations, startup variables, access lists, and settings.
- **Node management** — auto-install the local Debian host, inspect capacity, regenerate daemon tokens, copy the node configuration, and manage allocations in bulk.
- **Administration** — server creation, suspend/unsuspend, ownership transfer, and full cleanup delete; user, location, nest, and egg management; a manual account ban flow with a required reason and optional server hold; paginated audit log; branding and panel settings.
- **Account controls** — profile editing, password changes, session context, and revocable API keys (`vt_` bearer tokens).
- **Cybersecurity suite** — **Cosmos Molorum Sentinel**, an assessment console with its own login, audit trail and 105 non-destructive security modules covering transport, sessions, exposure, injection and edge defence. It runs on port `7999`, keeps results locally, contains no plan, billing or payment pages, and produces an executive findings analysis with OWASP Top 10 mapping, prioritised remediation and score trends.
- **Interface** — Cormorant Garamond display type, Plus Jakarta Sans, JetBrains Mono, Font Awesome icons, local SVG artwork, and a responsive deep-navy design system with ivory and brass accents inspired by the observatory mark. Accessible dialogs, confirmations, and toasts are included. All assets are bundled locally; the UI makes no CDN requests.

## Stack

| Layer | Technology |
|-------|------------|
| Panel API | FastAPI, SQLite, psutil |
| Interface | React 18, Vite 5, TypeScript, xterm.js |
| Realtime | WebSocket console and resource streams |
| Runtime | Python, Node.js, Java, Minecraft, voice, databases, bots, Go/Rust/PHP/Deno, static HTTP, shell, or Docker OCI images |
| Sentinel mode | FastAPI, SQLite, httpx, a self-contained HTML/CSS/JS console |
| Assets | npm-bundled Font Awesome, Cormorant Garamond, Plus Jakarta Sans, JetBrains Mono, local SVG art |

## Requirements

- Debian **12 (bookworm)** or **13 (trixie)**, or a Debian derivative with systemd and nginx
- Python **3.10+** (3.11/3.12 recommended)
- Node.js **18+** and npm for hosting mode (the installer provisions Node 20 when needed)
- Optional: Docker for OCI-based eggs
- Linux for workload execution. The panel can be started on Windows for development, but the process runtime depends on POSIX process groups. Sentinel needs only Python, nginx and systemd, and it is installed in both hosting and cybersecurity modes.

## Debian production install

Clone the repository onto the host, then run the installer as root:

```bash
git clone <your-repository-url> /opt/vitestl
cd /opt/vitestl
sudo bash deploy/install.sh
```

Without `--mode`, the installer prints the Cosmos Molorum banner and asks whether to install the **Hosting Panel** or the **Cybersecurity Suite**. For unattended deployments, pass the mode explicitly:

```bash
sudo bash deploy/install.sh --mode hosting --domain panel.example.com
```

With Docker-backed eggs and the Docker group drop-in:

```bash
sudo bash deploy/install.sh --mode hosting --domain panel.example.com --with-docker
```

The installer:

1. Installs Python, nginx, SQLite, and build tooling. Hosting mode also installs Node.js.
2. Copies the application to `/opt/vitestl` when run from another directory.
3. Creates the `vitestl` system account and the `/var/lib/vitestl` data directory.
4. Builds `frontend/dist` in hosting mode and installs the Python environment.
5. Generates `/etc/vitestl.env` with a random JWT secret, a random initial admin password, and `CM_CYBER_PORT`.
6. Installs and starts `vitestl.service` and `cosmos-sentinel.service`, then health-checks both upstreams.
7. Installs nginx as the static frontend and reverse proxy for the panel on `LISTEN_PORT`, and as the Sentinel console proxy on `CYBER_PORT`.
8. Saves the initial credentials to `/root/vitestl-credentials.txt`.

Useful installer options:

| Option | Purpose |
|--------|---------|
| `--mode MODE` | `hosting` or `cyber`; an interactive chooser is shown when omitted |
| `--domain NAME` | nginx `server_name`; use `_` for an IP-only install |
| `--port PORT` | hosting nginx listen port (default `80`) |
| `--cyber-port PORT` | public Sentinel port for both modes (default `7999`) |
| `--app-dir PATH` | application directory (default `/opt/vitestl`) |
| `--data-dir PATH` | writable data directory (default `/var/lib/vitestl`) |
| `--admin-pass PASS` | initial password for a fresh database |
| `--with-docker` | install Docker and grant the hosting service access to the socket |
| `--no-build` | reuse an existing `frontend/dist` build |
| `--no-nginx` | do not install or reload nginx |
| `--yes` | skip the cybersecurity confirmation prompt |
| `--force` | continue on a non-Debian distribution |

After DNS points at the host, add TLS:

```bash
sudo apt-get install -y certbot python3-certbot-nginx
sudo certbot --nginx -d panel.example.com
```

The service binds only to `127.0.0.1:8000`; nginx is the public entry point. The systemd unit uses `ProtectSystem=strict`, a dedicated account, and a single writable data path.

### Upgrade

```bash
cd /opt/vitestl
sudo git pull
sudo bash deploy/install.sh --mode hosting --domain panel.example.com --with-docker
```

The installer preserves an existing `/etc/vitestl.env` and `/var/lib/vitestl` database. It rebuilds the frontend and restarts the service.

Version 2.1.0 migrates the schedules, database hosts, schedule tasks, recovery codes and TOTP columns automatically and upserts the built-in nests and eggs during startup. If a panel upgrade ever leaves an egg missing, open **Administration → Nests & eggs** and use **Sync catalogue**; missing built-in rows are also repaired the first time the catalogue is read.

### Cosmos Molorum rename

The panel is now branded **Cosmos Molorum** with the operator name **Cosmos Molorum Host** and **Cosmos Molorum Payments**. The rename keeps the existing technical identifiers so installations upgrade in place: `VITESTL_DATA_DIR`, `KESTREL_*` variables, `kestrel.db`, `/opt/vitestl`, `/var/lib/vitestl`, `/etc/vitestl.env`, the `vitestl.service` unit and the `vitestl` service account are unchanged. The Docker container prefix `meridian-` is also retained for running workloads. The startup migration renames the default company and payment labels, moves legacy `@vitestl.local` and `@meridian.local` addresses to `@cosmosmolorum.local`, and keeps reading `.meridian-minecraft.json` and `.vitestl-minecraft.json` when a world has not been reinstalled. Redeem codes now use the `CM-` prefix; previously issued `MDN-` and earlier codes remain valid.

## Sentinel — cybersecurity mode

Sentinel is a FastAPI application under `cyber/` with its own self-contained console. It has a login page, a dashboard, a scan workspace, history, a findings-analysis report, an exploit-intelligence report, a module library, and an audit trail. There are no plan, billing, order, payment or redeem pages.

### Install

Run the installer as root and choose option **2) Cybersecurity Suite** to install Sentinel on its own:

```bash
sudo bash deploy/install.sh
```

The chooser shows the Cosmos Molorum banner, asks for confirmation, and then installs Sentinel on public port `7999`. Automation can skip the prompts:

```bash
sudo bash deploy/install.sh --mode cyber --domain sentinel.example.com --yes
```

Use a different public port with `--cyber-port`:

```bash
sudo bash deploy/install.sh --mode cyber --domain sentinel.example.com --cyber-port 8443 --yes
```

The cyber path skips Node.js, the npm frontend build and Docker. It installs the same Python environment, creates the `vitestl` service account when needed, writes `/etc/vitestl.env` if it is missing, and enables `cosmos-sentinel.service`.

| Item | Value |
|------|-------|
| Public entry point | nginx on port `7999` (`--cyber-port` changes it) |
| Upstream | uvicorn on `127.0.0.1:7998` |
| systemd unit | `cosmos-sentinel.service` |
| Database | `${VITESTL_DATA_DIR}/cyber/cyber.db` (default `/var/lib/vitestl/cyber/cyber.db`) |
| Credentials | `/root/sentinel-credentials.txt` on a fresh install |
| Interface source | `cyber/web/` (no build step) |

### Hosting mode coexistence

Hosting mode installs Sentinel alongside the panel. The panel stays on `LISTEN_PORT` (default `80`), Sentinel listens publicly on `CYBER_PORT` (default `7999`), and both run as separate systemd units:

| Item | Panel | Sentinel |
|------|-------|----------|
| systemd unit | `vitestl.service` | `cosmos-sentinel.service` |
| Upstream | `127.0.0.1:8000` | `127.0.0.1:7998` |
| nginx site | `/etc/nginx/sites-available/vitestl` | `/etc/nginx/sites-available/cosmos-sentinel` |
| Public port | `LISTEN_PORT` | `CYBER_PORT` |

The installer writes `CM_CYBER_PORT` to `/etc/vitestl.env`. The panel API exposes that value as `sentinel_port` from `/api/system`, and the sidebar plus the dashboard **Operating modes** section render a working **Security testing** switch pointing at the Sentinel console. When `CM_CYBER_PORT` is absent, the switch is hidden rather than shown as a dead link.

The public listeners are plain HTTP by default. Terminate TLS in front of both ports before exposing them to the internet, and restrict access to the operators who need it. All scanner state and evidence stay on the host.

### Authentication and audit

The first startup seeds the administrator from `KESTREL_ADMIN_USER`, `KESTREL_ADMIN_PASS` and `KESTREL_ADMIN_EMAIL` in `/etc/vitestl.env`. Passwords are stored as PBKDF2 hashes, and sessions are HMAC-signed JWTs in an `HttpOnly`, `SameSite=Lax` cookie. State-changing endpoints require the same origin, login attempts are rate-limited per address, and sign-ins, scans, cancellations, exports and credential changes are written to the audit trail. Change the seeded password after the first sign-in from the account menu.

Operators who can sign in to the console are treated as authorized to run assessments. There is no authorization checkbox or client-side gate. Each scan accepts an optional operator note for the audit trail and otherwise records `Dijalankan oleh operator terautentikasi melalui konsol Sentinel.`

### The 105 modules

| Category | Count | Modules |
|----------|-------|---------|
| Transport & DNS | 16 | TLS Certificate Health; TLS Protocol & Cipher Posture; HTTPS Enforcement; Security Header Baseline; Content Security Policy Quality; DNS Hygiene & Takeover Signals; Email Authentication Posture; HTTP/2 & Modern Transport; HSTS Policy Depth; CAA Record Policy; DNSSEC Posture; Wildcard DNS Resolution; IPv6 Address Publication; Redirect Chain Quality; HTTP/3 Advertisement; Permissions Policy Review |
| Session & Browser | 14 | Cookie Security Flags; CORS Policy; Cache & Sensitive Response Policy; Clickjacking & Frame Protection; CSRF Token Coverage; Subresource Integrity Coverage; Mixed Content & Form Transport; Cookie Name Prefixes; CORS Preflight Evaluation; Cross-Origin Isolation; HTTP Method Surface; Referrer Leakage; Password Field Semantics; Iframe Sandboxing |
| Exposure & Discovery | 27 | robots.txt Disclosure; security.txt Presence; Sitemap Exposure; Directory Listing Exposure; Source Map Exposure; API Documentation Exposure; GraphQL Introspection; Debug & Actuator Exposure; Git Metadata Exposure; Environment & Config Exposure; Backup Archive Exposure; Administrative Surface Discovery; Error Handling Disclosure; Frontend Secret Leakage; Package Metadata Exposure; CI Configuration Exposure; Editor Backup File Exposure; Server Status Page Exposure; API Console Exposure; Metrics Endpoint Exposure; Database Admin Exposure; Application Log Exposure; Cross-Domain Policy; ASP.NET Trace Exposure; Docker Registry Exposure; Kubernetes API Exposure; Directory Fuzzing Probe |
| Injection & Input | 42 | Reflected Cross-Site Scripting; DOM XSS Sink Analysis; Attribute-Context Cross-Site Scripting; Header-Reflected Cross-Site Scripting; JSONP & Script-Context XSS; SQL Injection; Boolean Blind SQL Injection; UNION-Based SQL Injection; Time-Based Blind SQL Injection; SQL Injection via HTTP Headers; SQL Filter & WAF Evasion; NoSQL Operator Injection; LDAP Injection; Server-Side Template Injection; XML External Entity Handling; Open Redirect; CRLF & Header Injection; Host Header Injection; Path Traversal & LFI; HTTP Parameter Pollution; XSS Polyglot Reflection; SVG Script Injection; CSS Injection Breakout; Meta Refresh Injection; Iframe srcdoc Injection; Markdown Injection; Event Handler Injection; Client-Side Template Expression; SQL ORDER BY Injection; SQL Error Fingerprinting; JSON SQL Error Exposure; NoSQL Boolean Probing; NoSQL Regex Injection; LDAP Filter Injection; XPath Injection; Encoded Path Traversal; Redirect Parameter Abuse; Cookie Value Reflection; SQL Injection Wordlist Probe; Local File Inclusion Wordlist Probe; XSS Wordlist Probe; Open Redirect Wordlist Probe |
| Edge & Defense | 6 | WAF & Edge Defense Detection; Bot Management Detection; Cache Deception Risk; Compression Side-Channel; Security Header Consistency; Server Version Signature |

Wordlist-driven probes read plain-text files in `cyber/resources/` (`sql_payloads.txt`, `lfi_payloads.txt`, `xss_payloads.txt`, `redirect_targets.txt`, `dir_fuzz.txt`). The corpus combines curated entries with SecLists collections (CC-BY-4.0), and each scan samples only a small, evenly spaced subset so the request budget stays predictable.

### Findings analysis

Every completed assessment has an **Analisis** report at `#/analysis/<scan_id>`, also linked from the scan detail page. The report is generated by `cyber/analysis.py` and served by the authenticated `GET /api/analysis?scan_id=...` endpoint. It includes:

- An executive summary with risk band, headline, narrative and severity counts.
- A score trend for the same host across recent assessments.
- An OWASP Top 10 (2021) mapping with finding and module counts.
- Priority findings ranked by severity, evidence and remediation availability.
- A three-phase remediation roadmap covering 0–7, 8–30 and 31–90 days.
- Coverage quality across the selected modules, including pass, warn, fail, info, skipped and error states.

The analysis is deterministic, so the UI, API and exports describe the same findings. When no completed assessment exists, the page shows an empty state that links to a new scan.

### Exploit intelligence

Every completed assessment also has an **Intelijen** report at `#/intel/<scan_id>`, linked from the sidebar, the scan detail page and the analysis report. It is generated locally by `cyber/intel.py` and served by the authenticated `GET /api/intel?scan_id=...` endpoint. No external threat feed, CVE service or exploit database is contacted.

The report is advisory and operator-facing. It includes:

- Exploitability, impact, confidence and combined risk scores for each finding, including duplicate handling through an occurrence count.
- A ranked list of the findings most worth validating first, with CWE, CAPEC, MITRE ATT&CK technique and attack stage.
- Plausible attack paths assembled from finding groups, with each stage's state, impact and the defensive breakpoint that interrupts the chain.
- Component fingerprints derived from finding evidence, plus an aggregated ATT&CK technique table.
- Operator advice grouped by owner and remediation window, and a list of modules that were skipped or errored so coverage gaps stay visible.
- A safe verification toolkit: one non-destructive `curl` recipe per priority finding. Recipes use a single GET, benign markers, `-o /dev/null`, and explicit stop conditions. They never run automatically, never brute force, never change data, never dump databases and never read credentials.

The intelligence layer is generation-only. It does not execute the recipes, contact the target, or turn a finding into an exploit chain. Use it only on assets you are authorized to assess, and prefer a test account and a written scope.

### Asesmen edge Cloudflare

When a target sits behind Cloudflare, Akamai, Imperva, Sucuri, AWS WAF, Fastly, DataDome or PerimeterX, the Intelijen report includes an **Edge & origin** panel. It reads only stored scan evidence and never contacts the edge provider. The panel shows:

- Positive edge fingerprints and the module that observed them.
- Passive origin hints such as `X-Origin`, `X-Backend`, `X-Served-By`, `Via` or a non-CDN `Server` value, labelled as hints rather than proof.
- Limitations: probes can be blocked, normalized or served from cache before reaching the origin; a negative edge result does not prove the origin is safe.
- Authorized paths: a written WAF allowlist for the scanner egress, an official staging or origin target supplied by the asset owner, Cloudflare Access service tokens, or mTLS where the owner provides them.
- Prohibited actions: challenge solving, browser impersonation, header spoofing, IP rotation, guessed origin scanning and attacks on Cloudflare or third-party infrastructure.

The same panel includes a **Bounty & disclosure** block for authorized bug bounty work. It records scope expectations, a reporting checklist, disclosure rules and examples that are not findings. It does not add a bypass mode: the scanner never solves a challenge, rotates IPs, spoofs headers, scans guessed origin IPs or treats a `403`, `429` or challenge page as a vulnerability. Those controls are designed to stop automated traffic; circumventing them is out of scope even when a program offers a reward.

### Guard rails

- A hard budget of **900 requests** and a **480 second** wall-clock limit per assessment.
- Six module workers and a 50 ms pause between requests.
- Wordlist probes draw a small, evenly spaced sample from the bundled SQL injection, LFI/traversal, XSS and directory-fuzzing wordlists in `cyber/resources/`, so the request budget is shared fairly across all modules.
- Non-destructive probes only: no exploitation, brute force, destructive payloads or cloud metadata access.
- Intelligence recipes are recommendations, not actions. They are generated locally, are limited to one request, use benign markers, and are never executed by the console.
- Analisis edge Cloudflare bersifat pasif. There is no WAF evasion, challenge solving, IP rotation, header spoofing, guessed-origin scanning or testing of edge-provider infrastructure.
- Metadata, link-local and multicast destinations are blocked. Private and loopback targets are allowed with a visible private-target note, because internal assets are a normal assessment case.
- Responses are capped at 1.5 MB, redirects at 5, and each module contributes at most 12 findings.
- Results can be exported as JSON or CSV. Cancellation keeps partial results and marks the remaining modules as skipped.

### Performance and asset caching

- API, HTML, JavaScript and CSS responses above 1 KB are gzip-compressed by the application; nginx can still compress at the edge.
- Fonts are cached for one year with `immutable`. Brand and poster SVGs revalidate with `no-cache`, and scripts and styles stay `no-cache`, so a deploy is visible without a hard reload.
- The console ships local SVG poster artwork for the login, overview, and Edge & origin views. Artwork lives in `cyber/web/assets/posters/`, contains no external references, and loads under `img-src 'self' data:`.
- Intelijen includes a print-optimised report and a Markdown download. Both are generated in the browser from the stored assessment and retain the passive edge and bounty boundaries.
- Scope validation caches target DNS for 15 seconds during a scan. This avoids hundreds of repeated lookups while still re-checking often enough to catch rebinding.
- SQLite runs in WAL mode with `synchronous=NORMAL`, a memory temp store and an 8 MB page cache.
- The hosting frontend must be built from its own directory so npm resolves the local Vite binary:

```bash
cd frontend
npm ci --no-audit --no-fund --prefer-offline
npm run build
```

If `vite: not found` appears, the frontend dependencies were not installed. Run `npm ci` again from `frontend/`; the installer checks for `node_modules/.bin/vite` and fails with a clear message instead of leaving a partial build.

### Upgrade and data

```bash
cd /opt/vitestl
sudo git pull
sudo bash deploy/install.sh --mode cyber --domain sentinel.example.com --yes
```

For a hosting install that includes Sentinel, rerun the hosting installer instead; it refreshes both units and both nginx sites:

```bash
sudo bash deploy/install.sh --mode hosting --domain panel.example.com
```

The installer keeps `/etc/vitestl.env` and the existing `${VITESTL_DATA_DIR}/cyber/cyber.db`. Back up the whole `cyber/` data directory, not just the database file, while the service is stopped or with SQLite's online backup tooling.

## Node auto-install

Cosmos Molorum executes workloads on the panel host. The auto-installer does not pretend to install a remote agent; it provisions the local host as a first-class node:

- Audits the distribution, Python, systemd, Docker, privileges, storage, and free ports.
- Reuses an existing local node (matching this hostname) instead of creating duplicates.
- Registers or updates the node, capacity, and location.
- Reserves a contiguous allocation block in `9000–9999`.
- Writes `<data>/nodes/node-<id>/node.json` and `install.log`.
- Streams a live step-by-step log to the admin interface.

Open **Administration → Nodes → Auto-install**, review the host audit, adjust capacity and ports, then run the installer. The resulting node is connected to the local runtime and can accept workloads immediately.

System packages are never installed by the web process. Install Docker during host setup with `sudo bash deploy/install.sh --with-docker`; the installer reports Docker as an optional warning when it is absent and uses the native process runtime.

## Development quick start

### Linux / macOS

```bash
python3 -m venv .venv
.venv/bin/pip install -r backend/requirements.txt

cd frontend
npm install
cd ..

bash start.sh
```

### Windows (PowerShell)

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt

cd frontend
npm install
cd ..

# Terminal 1
cd backend
..\.venv\Scripts\python.exe -m uvicorn main:app --host 127.0.0.1 --port 8000

# Terminal 2
cd frontend
npm run dev
```

Open **http://localhost:5173**. The API listens on port 8000; Vite proxies `/api`, `/ws`, and `/gate` to it.

For a production-style local preview:

```bash
cd frontend
npm run build
npm run preview
```

## First sign-in

The initial administrator is seeded on first start. For a Debian install, use the random credentials in `/root/vitestl-credentials.txt`.

The development fallback is:

- Username: `Yanxzyx`
- Password: `Kestrel.admin1` (retained from older databases for compatibility)

Change the password from **Account** immediately. Override the seeded account with environment variables before the first launch:

| Variable | Default | Purpose |
|----------|---------|---------|
| `VITESTL_DATA_DIR` | `./data` | Writable database, server, backup, and node directory |
| `KESTREL_ADMIN_USER` | `Yanxzyx` | Initial administrator username |
| `KESTREL_ADMIN_PASS` | `Kestrel.admin1` | Initial administrator password |
| `KESTREL_ADMIN_EMAIL` | `yanxzyx@cosmosmolorum.local` | Initial administrator email |
| `KESTREL_SECRET` | development value | Token signing secret |

`BUILDP_DATA_DIR` and `KESTREL_DATA_DIR` remain accepted as fallbacks for existing installations. Internal compatibility identifiers such as `kestrel.db`, `kestrel.token`, and the `KESTREL_*` variable names are intentionally retained so existing databases upgrade in place. The same applies to deploy paths, the `vitestl` service account, and the `meridian-` Docker container prefix: they keep their names across the Cosmos Molorum rebrand.

Set `KESTREL_SECRET` to a long random value in every non-development deployment.

## Architecture

```text
backend/
  main.py          API routes, authorization, server lifecycle, node installer
  db.py            SQLite schema, migrations, seed data, activity logging
  auth.py          Password hashing and JWT issue/verify
  runtime.py       Local process and Docker runtime, console streams
  minecraft.py     Minecraft catalogues, installers, properties, content and pings
  security_scan.py Dangerous-activity detection rules and text-file helpers
  eggs.py          Nests, eggs, startup templates, variables
  config.py        Paths, versions, defaults
frontend/
  src/pages/       Login, dashboard, billing, server workspace, administration, account
  src/layout/      Sidebar, topbar, responsive shell
  src/assets/      Local SVG illustrations
  src/ui.tsx       Shared controls, dialogs, confirmations, toasts
  src/styles.css   Design system and responsive layout
deploy/
  install.sh       Debian installer and upgrader
  vitestl.service  systemd unit
  nginx.conf       Static frontend + API/WebSocket proxy
data/
  kestrel.db       SQLite database
  servers/         Per-server working directories
  backups/         Compressed backup archives
  nodes/           Auto-installed node manifests and logs
```

## Runtime modes

When Docker is available, eggs marked `docker` are launched as OCI containers with memory limits applied. The native process runtime launches workloads directly and is the default when Docker is absent. Process mode does not provide cgroup isolation; CPU and memory figures are observed usage against configured limits.

Each server receives an allocation. Start it from the console, then use **Open allocation** to reach the bound port through the panel proxy.

## Minecraft servers

Minecraft is a first-class workload type with dedicated eggs:

| Edition | Egg | Software |
|---------|-----|----------|
| Java | Minecraft Java (auto-installer), egg 27 | Vanilla, Paper, Purpur, Folia, Fabric, Quilt, Forge, NeoForge, Velocity, Waterfall, BungeeCord |
| Bedrock | Minecraft Bedrock (auto-installer), egg 28 | Bedrock Dedicated Server |

The version picker reads live upstream catalogues rather than a bundled list:

- **Vanilla** uses Mojang piston metadata.
- **Paper**, **Folia**, and **Velocity** use the PaperMC Fill v3 API.
- **Purpur** uses the PurpurMC API.
- **Fabric** and **Quilt** use their loader metadata APIs.
- **Forge** uses the promotions feed and Maven metadata; **NeoForge** uses the NeoForged Maven metadata.
- **Waterfall** and **BungeeCord** use the PaperMC and SpigotMC CI APIs.
- **Bedrock** uses Minecraft Services download metadata.

Every server download is HTTPS-only and host-validated. Transient failures are retried with backoff, partial transfers resume with HTTP Range requests, and Java artifacts are checksum-verified whenever the upstream publishes a digest.

Installations run as background jobs with live progress and logs. Existing worlds, plugins, mods, and configuration are preserved on reinstall. The panel writes the EULA choice, `server.properties`, and a restart-safe start script, and selects a matching Java runtime image from the version metadata. Java and Bedrock editions use different server directories and cannot share a single workload; choose the edition when creating the server.

The **Minecraft** tab shows the installed build, live Java server-list or Bedrock RakNet status, and editable gameplay properties. When a newer release or loader build is available, the maintenance card offers a one-click upgrade. The server is stopped first, a full backup is written, and the new binary is installed while worlds, plugins, mods, `server.properties` and the EULA decision are preserved.

The **Content** tab installs plugins or mods from Modrinth using the catalogues and loaders appropriate to the selected software. **Check updates** compares every tracked Modrinth project with the latest build compatible with the installed Minecraft version and loader; update buttons replace the old archive and keep disabled files disabled. The tab can also toggle or remove installed files and accept `.jar` or `.zip` uploads. Vanilla, Bedrock, and proxy software expose only the capabilities that apply to them.

If an older installation is missing built-in eggs, opening **Administration → Nests & eggs**, or creating a server, re-syncs the catalogue before failing. The API error includes the requested egg ID and the known built-in IDs, which distinguishes a stale deployment from an invalid request.

## Catalogue deployment coverage

The nests screen treats an egg as **installed** when at least one server already exists for it. Installed egg names are green; eggs without a deployment are yellow. The All, Installed, and Not installed filters make gaps visible, and the coverage meter summarises how much of the bundled catalogue has been deployed.

Use **Install all missing** to deploy one default server for every egg that does not yet have one. Use the per-egg **Install** action, or select any combination of eggs and choose **Install selected**, for a custom batch. Every selection creates a separate server; existing deployments are never replaced or modified.

The bulk installer asks for an owner, node, optional name prefix, and per-application memory and disk. Minecraft Java defaults to 2048 MiB and 10240 MiB, Bedrock to 1024 MiB and 5120 MiB, and other eggs to 256 MiB and 1024 MiB. It previews memory and disk usage against the node's free capacity before starting. Provisioning runs sequentially, reports success or the exact failure reason for each egg, and requires the Minecraft EULA checkbox when Java or Bedrock is included. The **Start each server** option is off by default so a large batch does not consume CPU and memory immediately.

## Owner terminal and per-server sudo

The **Terminal** tab is available to the server owner and panel administrators. Subusers are intentionally excluded: normal server access grants the console and file manager, not a shell on the panel host. Commands run in the server directory as the panel service account (`vitestl` on Debian), with a 120-second timeout, a 1 MiB output cap, cancellation support, history, and activity logging. The terminal confines `cd` to the server directory, but it is not a chroot or container boundary; commands can still read and write anything the service account can access.

Each server has a separate sudo switch controlled only by administrators. When enabled, new commands run with `sudo -n -- bash -c ...`. Enabling the switch verifies the exact non-interactive `bash` execution path first; if that is not permitted without a password, the API returns an error and the setting stays off. The panel never edits sudoers and never grants operating-system privileges by itself. To make the switch usable on Debian, an administrator can create an explicit sudoers drop-in:

```bash
sudo visudo -f /etc/sudoers.d/vitestl-terminal
```

```sudoers
vitestl ALL=(root) NOPASSWD: /usr/bin/bash
```

Use the path printed by `command -v bash`; on Debian it is `/usr/bin/bash`. This is effectively host-root access for every server whose sudo switch is enabled. Grant it only when server owners are trusted with the host, keep the panel behind TLS and strong authentication, and remove the drop-in to revoke the capability. Use `sudo -l -U vitestl` to verify what the service account may run. Disabling the switch takes effect for the next command; the WebSocket re-reads the setting before each execution.

## Permissions and subusers

Subusers are existing panel accounts invited by email. The owner and administrators always receive the `*` wildcard. Every other account receives an explicit allow-list using Pterodactyl-style identifiers such as `control.start`, `file.read`, `database.create`, `backup.restore`, `schedule.update`, `allocation.delete`, `startup.update`, `settings.rename`, and `user.create`. Unknown identifiers are discarded before storage, and every API route enforces the matching permission server-side.

The Access tab presents permissions grouped by Console, Files, Databases, Backups, Schedules, Network, Access and Configuration, with select-all controls per group and Viewer, Operator and Manager templates. Editing permissions requires `user.update`; removing a subuser requires `user.delete`. Server payloads redact `environment` and `startup` from accounts without `startup.read`, so secrets are not leaked to read-only collaborators.

## Two-factor authentication

Any account can enroll a TOTP authenticator from **Account ? Two-factor authentication**. Enrollment requires the account password, displays the Base32 secret and `otpauth://` URI, and activates only after a valid six-digit code is entered. Activation generates ten recovery codes; only their SHA-256 hashes are stored. The login endpoint returns a short-lived two-factor challenge instead of a session token when TOTP is enabled. The challenge is exchanged for a session with a current code or a recovery code, and codes from a previously accepted time step are rejected to prevent replay. Recovery codes are single use. Password or code failures use the same rate limiter as normal sign-in.

## File manager

The Files tab supports multi-select operations and a full editor. Selected entries can be deleted in bulk, compressed into `.zip` or `.tar.gz`, copied to a new name, or assigned an octal mode such as `644`, `664`, `755` or `775`. Archives can be extracted in place. Uploads, downloads, rename, and text editing remain available. Every operation is resolved through the server root, rejects path escapes, runs with the panel service account, and writes an audit event. Symlinks are displayed but not followed outside the server volume.

## Managed databases

Administrators create database hosts under **Administration ? Database hosts**, choosing MariaDB or MySQL, hostname, port, administrator credentials, an optional linked client address, and a database limit. Credentials are never returned by the API after creation. Provisioning shells out to the panel host's `mariadb` or `mysql` client with the password passed through the environment, then creates a database, a scoped user, and a grant. If no host exists or the local SQLite option is selected, the panel creates a local SQLite file instead. Deleting a managed database drops the remote database and user when the host is reachable.

Install the client on Debian or Ubuntu with `sudo apt-get install -y mariadb-client` or `mysql-client`. A missing client returns a clear HTTP 503 with the same guidance rather than silently falling back to an unusable endpoint. Hosts that still manage databases cannot be deleted until those databases are removed.

## Host health

**Administration ? System health** reads the panel host directly, without package-manager or network calls. It reports OS release, kernel, architecture, uptime, logical and physical cores, per-core utilisation, load averages, memory and swap, every mounted filesystem, systemd state for the panel runtime and common dependencies, failed units, the top processes by CPU and memory, Docker availability and container count, panel storage usage, SSH password and root-login policy, firewall state for ufw, firewalld or nftables, AppArmor, unattended upgrades, and whether a reboot is pending. The endpoint is administrator-only and refreshes automatically unless disabled.

## Scheduled automation

Schedules use standard five-field cron expressions in UTC: minute, hour, day of month, month, and weekday (Sunday is `0` or `7`). The interface includes presets for hourly, six-hourly, daily, weekly, and monthly maintenance, plus a free-form expression field. Each row stores its next run time, so a restart does not duplicate or skip work.

A schedule can chain up to 20 ordered tasks. Actions cover start, stop, restart, kill, backup, console commands, and file deletion. Each task has its own delay of up to 3600 seconds, and combined delays are capped at 7200 seconds. Every task records whether later tasks should continue after a failure. Schedules can be edited in place, run on demand, paused, or deleted, and on-demand runs return a per-task result list.

Examples:

| Expression | Meaning |
|------------|---------|
| `*/15 * * * *` | Every 15 minutes |
| `0 * * * *` | Every hour at minute 0 |
| `0 4 * * *` | Daily at 04:00 UTC |
| `0 4 * * 0` | Every Sunday at 04:00 UTC |
| `0 4 1 * *` | The first day of each month at 04:00 UTC |

Legacy `*/N * * * *` rows created by earlier releases continue to work, including the non-standard values above 59 minutes that older panels accepted.

## Plans and billing

Four paid plans are seeded on a fresh database. Prices are monthly MYR, and every limit, feature line, accent colour, badge, artifact motif and deployment slot count is editable under **Administration > Commerce > Plans**.

| Plan | Price | Memory | CPU | Disk | Deployment slots | Databases | Backups | Allocations |
|------|-------|--------|-----|------|------------------|-----------|---------|-------------|
| Starter | MYR 15 | 1 GB | 100% | 5 GB | 1 | 1 | 2 | 1 |
| Standard | MYR 35 | 4 GB | 150% | 15 GB | 2 | 2 | 5 | 2 |
| Pro | MYR 69 | 8 GB | 250% | 30 GB | 4 | 4 | 10 | 3 |
| Premium | MYR 129 | 16 GB | 400% | 60 GB | 8 | 8 | 20 | 5 |

Plan resources become the server's memory, CPU, disk and swap targets when an order is approved or a code is redeemed. The database, backup and allocation limits are enforced when those resources are created, so a plan change takes effect without restarting the panel. Each activation also sets a 30-day renewal date. An expired plan is marked **Renewal due** and keeps its current capacity until the owner renews or changes it; expiry does not delete files or silently remove a running server.

### Payment methods

Checkout is manual by design. Before customers can order, an administrator configures at least one channel under **Administration > Commerce > Payment methods**:

- **DANA QR** and **Touch 'n Go QR** require an uploaded PNG, JPEG or WebP QR image. The image is stored as a data URL and rendered in the checkout panel.
- **DANA account** and **Touch 'n Go account** require an account or wallet ID, with an optional account name.
- **Bank transfer** and **Manual** accept instructions and an optional account ID.
- Every method has its own instructions, sort order and enabled state. A method without a QR image or account ID is shown as **Setup needed** and is not offered at checkout.

There is no merchant API integration in this release. The owner verifies the incoming payment against the attached receipt and approves the order manually. Keep the account name, wallet ID and QR image accurate, and treat the Commerce screen as payment configuration rather than a public checkout page.

### Orders and provisioning

The customer selects a plan, chooses **New deployment** or **Existing server**, picks a configured payment method, sends the exact total, and attaches a receipt. The checkout records an order code such as `CM-20261030-A1B2`, the amount, reference, optional note, target server and workload. Receipts must be PNG, JPEG or WebP images under 2 MB, and the acceptable-use checkbox is mandatory.

New-deployment orders also require a workload egg and a server name. The order is accepted while the account owns fewer servers than the selected plan's deployment-slot count; an existing-server order applies the plan in place and does not consume that check. This means a plan's slots describe the total deployments on the account, not only servers previously assigned to that plan.

Orders move through **pending**, **approved**, **rejected** and **cancelled**. Approval happens under **Administration > Commerce > Orders**:

1. The owner opens the pending order, checks the receipt and reference, and adds an approval note.
2. The panel selects a node with enough free memory, disk, CPU and a free allocation.
3. A new deployment is created from the selected egg, or the target server receives the plan resources and limits.
4. Minecraft Java and Bedrock orders queue their installer immediately after provisioning.
5. The customer sees the approved order, the provisioned server and an **Open server** action in **Plans & billing > Orders**.

If no node can satisfy the plan, the order stays pending with the exact capacity error in its admin note. Add node memory, disk or a free allocation and approve again. An approved order cannot be re-approved; use a new order or a plan change for later modifications.

### Redeem codes

Administrators issue codes under **Administration > Commerce > Redeem codes**. A code belongs to one plan and records its maximum uses, optional expiry, note and active state. Codes are normalised to uppercase letters, digits and dashes; examples are `CM-GIFT-2026` and `CM-STANDARD-DEMO`.

Customers redeem under **Plans & billing > Redeem** by entering the code, choosing a new deployment or an existing server, and accepting the acceptable-use policy. A successful redemption provisions the same way an approved order does, but without a payment receipt or a second approval step. Each account may redeem a given code once, the global use count is incremented only after provisioning succeeds, and a failed provisioning attempt removes the order and the use record so the code is not consumed. Redeemed plans still pass through the same security detection and rules as paid plans.

## Rules and acceptable use

Rules are published under **Administration > Safety > Rules** and appear in every affected server workspace under the **Rules** tab. Each rule has a scope, category, severity, title, body, sort order and enabled flag:

| Scope | Applies to |
|-------|------------|
| `global` | Every server |
| `nest` | Every server in a nest, such as Minecraft or Bots |
| `egg` | One workload template, such as Minecraft Java or Bedrock |
| `server` | One specific server |

The default catalogue includes panel-wide network-abuse, account-security, recoverability and fair-use rules, a Minecraft nest content policy, a Java plugin-integrity rule and a Bedrock compatibility rule. Server pages group the effective rules by server, egg, nest and global scope and show the active plan, renewal date, current strikes and ban threshold alongside them.

Rules are policy text, not executable controls. Use them to explain expectations and review evidence; the server-side scanner described below performs the actual blocking. Disabling or editing a rule does not disable detection.

## Dangerous-activity enforcement

The panel scans dangerous activity before execution and records every blocked attempt as a strike. Detection is enabled by default and can be tuned under **Administration > Safety > Policy**:

- **Dangerous-activity detection** scans console commands, terminal input, saved text files, uploads and schedule creation or execution.
- **Automatic suspension** places a server on security hold when a finding is critical. Warning findings are blocked and recorded without suspending the server.
- **Ban threshold** defaults to 4 recorded strikes. More than three repeated attempts therefore bans the account. Administrators and owner accounts are never banned automatically, but their strikes remain in the ledger for review.

### What is scanned

The detector is deliberately conservative. It looks for known DDoS and stress tools (`hping3`, GoldenEye, Slowloris, LOIC, HOIC, Xerxes, MHDDoS and similar), explicit flood or scan intent, raw packet and Scapy constructs, reverse shells, destructive host commands such as recursive root deletion, credential-theft patterns, packet-flood loops and unbounded request loops. Files that are not text candidates, such as ordinary binaries, are not parsed as source code.

Every match is blocked before the command runs or the file is written. Critical matches suspend the server and set a security-hold reason. Terminal and console WebSocket clients receive a `security warning` frame with the strike count, and the API returns HTTP 400 with the same explanation. The event, source, severity, identifier and a short snippet are stored in `security_strikes`.

### Reviewing and releasing holds

**Administration > Safety** shows the strike ledger, affected accounts, banned users and held servers. Use **Release** to clear a security-hold suspension on one server. Releasing a server does not clear its strikes; the same account can be banned on a later attempt. To restore a banned account, unban it from the Safety screen. Unbanning can also release the account's security-held servers and optionally clear its strikes, which resets the threshold count.

The scanner is an application-layer safeguard, not a network sandbox. It reduces accidental attacks and gives the owner evidence, but it cannot replace egress filtering, firewall rules, resource limits or host monitoring. Do not rely on string matching alone to stop a determined attacker.

## Security checklist

- Change the seeded administrator password and email.
- Set a strong, unique `KESTREL_SECRET`.
- Terminate TLS at nginx and do not expose the API directly to the public internet.
- Restrict access to `/var/lib/vitestl` and the SQLite database; they contain server files and account data.
- Review admin roles and subuser permissions regularly; use the smallest template that works.
- Enable TOTP on administrator accounts and store recovery codes offline.
- Restrict database host administrator credentials and prefer a dedicated MySQL account with grant privileges over `root`.
- Keep Python and npm dependencies patched, and rebuild the frontend after updates.
- Backups are stored on the same host by default; replicate them off-host for disaster recovery.
- Run the service as `vitestl`, not root. The auto-installer only writes inside the data directory.
- Treat the owner terminal as host shell access for the service account. It is not a sandbox; restrict who can be a server owner.
- Only add the NOPASSWD sudoers rule when owners should be able to elevate to root, and review `terminal_sudo` on each server regularly.
- Configure DANA and Touch 'n Go payment details with the real account name, wallet ID and QR image, then place a test order and verify the receipt appears correctly before announcing checkout.
- Review every pending order and its receipt before approval; approval immediately provisions a server or changes plan limits.
- Keep plan prices, slot counts and resource limits current. Expired plans remain at their last capacity until renewed, so review the renewal list regularly.
- Treat redeem codes as value-bearing credentials. Issue them with a use limit and expiry, and revoke or replace leaked codes.
- Review the safety strike ledger and held servers after alerts. Releasing a server does not clear strikes; unban only after the evidence has been reviewed.
- Tune the ban threshold for your community, but keep administrator accounts exempt and monitor their strikes manually.

Password, TOTP and recovery-code attempts are rate-limited by the panel. API access uses signed bearer tokens; console and resource streams authenticate with the same signed token. Put the panel behind TLS so tokens are never sent in clear text.

## API overview

All panel routes live under `/api`:

- `POST /api/auth/login`, `POST /api/auth/2fa`, `GET /api/auth/me`, `POST /api/auth/password`
- `GET /api/account/2fa`, `POST /api/account/2fa/setup|enable|disable`
- `GET /api/servers`, server detail, resources, power, command, activity
- Files, including `compress`, `extract`, `chmod` and `copy`; startup, settings, reinstall, databases, backups, schedules, network and subusers
- `PUT /api/servers/{id}/users/{sub_id}` for granular subuser permission changes
- `GET /api/admin/database-hosts` and CRUD plus connection tests under `/api/admin/database-hosts`
- `GET /api/admin/system` for Debian and Ubuntu host health
- `GET /api/minecraft/catalog`, version and loader catalogues, Minecraft status and install jobs
- `GET|PUT /api/servers/{id}/minecraft/properties`, `POST /api/servers/{id}/minecraft/install`
- `GET /api/servers/{id}/minecraft/update`, `POST /api/servers/{id}/minecraft/upgrade`
- Plugin and mod search, versions, install, upload, toggle, and delete under `/api/servers/{id}/plugins`
- `GET /api/servers/{id}/plugins/updates`, `POST /api/servers/{id}/plugins/{filename}/update`
- `GET /api/servers/{id}/terminal`, `POST /api/servers/{id}/terminal/sudo` (administrators only)
- `WS /ws/terminal/{id}` for the owner terminal; owners and administrators only
- `GET /api/billing/catalog` for plans, configured payment methods and account summary; `GET /api/billing/workloads` for order eggs
- `GET|POST /api/billing/orders`, `GET /api/billing/orders/{id}`, order proof update, `POST /api/billing/orders/{id}/cancel` and `POST /api/billing/redeem`
- `GET|POST /api/admin/plans`, `PUT|DELETE /api/admin/plans/{id}` for the plan catalogue
- `GET|POST /api/admin/payment-methods`, `PUT|DELETE /api/admin/payment-methods/{id}` for DANA, Touch 'n Go and manual channels
- `GET /api/admin/orders`, `POST /api/admin/orders/{id}/approve` and `POST /api/admin/orders/{id}/reject` for the review queue
- `GET|POST /api/admin/redeem-codes`, `PUT|DELETE /api/admin/redeem-codes/{id}` for gift and upgrade codes
- `GET|POST /api/admin/rules`, `PUT|DELETE /api/admin/rules/{id}` for global, nest, egg and server rules
- `GET /api/admin/security`, `PUT /api/admin/security/settings`, `POST /api/admin/security/users/{id}/unban` and `POST /api/admin/security/servers/{id}/release`
- `GET /api/servers/{id}/rules` and `GET /api/servers/{id}/security` for per-server policy and strike context
- `GET /api/admin/nests` returns `catalog_health`, per-egg `installed`, and deployment counts; `POST /api/admin/nests/sync` repairs built-in nests and eggs
- `GET /api/admin/overview`, users, nodes, allocations, locations, nests, activity, settings
- `GET /api/admin/node-installer/audit`
- `POST /api/admin/node-installer/install`
- `GET /api/admin/node-installer/jobs/{job_id}`
- `PUT /api/account` for profile changes

Interactive API documentation is available at **http://localhost:8000/docs** while the API is running. It is not exposed by the production nginx configuration.

## Brand assets and trademarks

Workload marks in `frontend/src/assets/logos/` are the official brand files published by each project. The panel only scales them for the interface and, for the monochrome Rust gear, recolours the black artwork to ivory so it stays visible on the dark plate. No logo geometry is redrawn or generated.

| Workload | Source | Trademark or licence holder |
|----------|--------|-----------------------------|
| Python | `python.org` (PSF media assets) | Python Software Foundation |
| Node.js | `nodejs.org` official hex mark | OpenJS Foundation |
| Go | `go.dev` official blue logo | Google LLC |
| Rust | `rust-lang.org` official black logo, CC BY 4.0 | Rust Foundation |
| Java | Official Java mark, via Wikimedia Commons | Oracle Corporation |
| PHP | `php.net` official logo, CC BY-SA 4.0 | The PHP Group; artwork by Colin Viebrock |
| Ruby | `ruby-lang.org` official logo, CC BY-SA 2.5 | Ruby Association and Yukihiro Matsumoto |
| .NET | `dotnet.microsoft.com` official logo | Microsoft Corporation |

These marks identify the runtimes the panel can host. Their use does not imply sponsorship or endorsement by the trademark holders. Minecraft, Bedrock, and the remaining generic workload icons are neutral artwork drawn for Cosmos Molorum and are not official Mojang or Microsoft assets.

## Troubleshooting

- **Port already in use** — stop the previous panel or frontend process, or change the port in `start.sh`, the uvicorn command, and `frontend/vite.config.ts`.
- **Blank page or missing icons** — run `npm install` in `frontend/` and rebuild. Fonts and icons are resolved from `node_modules`, so a partial install breaks asset loading.
- **`Unknown egg` when creating a Minecraft server** — the panel could not find the requested egg in both SQLite and the bundled catalogue, which means the running backend is older than the frontend or the catalogue rows were deleted. Run `sudo bash deploy/install.sh` to rebuild and restart the service, then open **Administration → Nests & eggs → Sync catalogue**. Version 2.1.0 also repairs missing built-in eggs automatically and includes the submitted egg ID in the error message.
- **Sudo cannot be enabled** — the panel requires non-interactive sudo. Confirm `sudo` is installed, the service account has the NOPASSWD rule shown above, and `sudo -u vitestl sudo -n -- bash -c 'exit 0'` succeeds. The panel deliberately refuses to store a password or modify sudoers.
- **Terminal reconnects or closes immediately** — verify nginx is proxying `/ws/` with the `Upgrade` and `Connection` headers, the panel is behind TLS, and the signed session token is still valid. Subusers cannot open the owner terminal even when they can use the console.
- **No payment method appears at checkout** — open **Administration > Commerce > Payment methods** and confirm at least one method is enabled, has a QR image or account ID, and shows **Ready** rather than **Setup needed**. Clearing the method's QR image or account ID automatically removes it from checkout.
- **Order approval fails with a capacity error** — the selected plan needs free memory, disk, CPU and an unassigned allocation on one node. Add capacity under **Administration > Nodes** or free an allocation, then approve the same pending order again. The failure is stored in the order's admin note.
- **A redeem code is rejected** — codes are case-insensitive after normalisation but must exist, be active, be within their expiry and have uses remaining. Each account can redeem a code only once. A code is not consumed when provisioning fails, so correct the capacity or target and try again.
- **Database, backup or allocation creation is blocked by the plan** — the server's plan limit has been reached. Upgrade the plan through checkout or a redeem code, or remove an existing resource. Servers without a plan use the panel defaults rather than unlimited resources.
- **A server is suspended after a file or command** — the dangerous-activity scanner recorded a critical finding and placed the server on security hold. Review the strike under **Administration > Safety**, then use **Release** to restore the server. Releasing does not clear the strike; repeated attempts can ban the owning account.
- **An account is banned for security strikes** — administrators are exempt, but regular accounts are banned at the configured threshold (default 4). Review the evidence in the strike ledger, then unban the account. Use the optional release and clear-strikes controls only after the incident has been investigated.
- **Plan shows Renewal due** — the 30-day plan period has ended. The server keeps its current limits until the owner renews or changes the plan. Apply a paid or redeemed plan to reset the expiry and limits.
- **Node shows `awaiting`** — the node must match the panel hostname (or `localhost`/`127.0.0.1`). Run the auto-installer again to repair the local node record.
- **Docker eggs fall back to process mode** — install Docker with `--with-docker` and verify `systemctl status docker` and `docker info`.
- **Processes do not start on Windows** — the process runtime uses POSIX process groups. Use Linux for workload execution.
- **Auto-install reports a port conflict** — choose another first allocation port in the installer; it searches for the next free contiguous block.
- **Service fails to start** — inspect `journalctl -u vitestl -n 80 --no-pager` and confirm `/var/lib/vitestl` is writable by `vitestl`.

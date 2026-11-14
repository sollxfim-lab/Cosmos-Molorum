from __future__ import annotations

import json
import re
import secrets
from urllib.parse import urljoin, urlsplit

from ..engine import Probe, ScanContext, redact_secret
from ..models import Finding, Outcome
from ..registry import module, verdict

CATEGORY = "Exposure & Discovery"

SENSITIVE_PATH_RE = re.compile(
    r"(admin|backup|config|database|db[-_]|private|internal|staging|dev|test|"
    r"upload|log|secret|token|credential|api/v\d|graphql)",
    re.IGNORECASE,
)


def _looks_like_spa(probe: Probe) -> bool:
    if not probe.ok:
        return False
    body = probe.text[:120_000]
    if not body.lstrip().startswith("<"):
        return False
    return bool(
        re.search(
            r"(<div[^>]+id=[\"'](?:root|app|__next)[\"']|__NEXT_DATA__|"
            r"ng-version=|data-reactroot)",
            body,
            re.IGNORECASE,
        )
    )


def _is_plaintext(probe: Probe) -> bool:
    return probe.ok and not _looks_like_spa(probe)


@module(
    "robots_disclosure",
    "robots.txt Disclosure",
    CATEGORY,
    "Reads robots.txt and highlights sensitive paths that are publicly advertised.",
    severity="low",
    passive=True,
)
def robots_disclosure(ctx: ScanContext) -> Outcome:
    probe = ctx.get("/robots.txt")
    if not probe.ok or probe.status != 200 or not _is_plaintext(probe):
        return Outcome("pass", "No usable robots.txt disclosure was found.")
    body = probe.text[:120_000]
    if "user-agent" not in body.lower():
        return Outcome("pass", "The robots.txt response did not contain directives.")
    paths = re.findall(r"(?im)^\s*(?:disallow|allow)\s*:\s*(\S+)", body)
    sensitive = [path for path in paths if SENSITIVE_PATH_RE.search(path)]
    if not sensitive:
        return Outcome(
            "info",
            f"robots.txt exposes {len(paths)} path directive(s) without obvious secrets.",
            [
                Finding(
                    "robots.txt is publicly readable",
                    "info",
                    "The file lists crawl directives but no sensitive-looking paths.",
                    f"directives={len(paths)}",
                    "Do not use robots.txt as an access-control mechanism.",
                )
            ],
        )
    findings = [
        Finding(
            "Sensitive paths advertised in robots.txt",
            "low",
            "Robots directives reveal administrative or private-looking locations.",
            ", ".join(sensitive[:8]),
            "Remove sensitive paths from robots.txt and enforce authorization server-side.",
        )
    ]
    return Outcome("warn", f"{len(sensitive)} sensitive-looking path(s) disclosed.", findings)


@module(
    "security_txt",
    "security.txt Presence",
    CATEGORY,
    "Checks for a valid RFC 9116 security contact discovery file.",
    severity="low",
    passive=True,
)
def security_txt(ctx: ScanContext) -> Outcome:
    probe = None
    used = ""
    for path in ("/.well-known/security.txt", "/security.txt"):
        candidate = ctx.get(path)
        if candidate.ok and candidate.status == 200 and "contact:" in candidate.text.lower():
            probe = candidate
            used = path
            break
    if probe is None:
        return Outcome(
            "warn",
            "No security.txt contact file was found.",
            [
                Finding(
                    "security.txt is missing",
                    "low",
                    "Researchers have no published channel for coordinated disclosure.",
                    "paths=/.well-known/security.txt,/security.txt",
                    "Publish a security.txt with Contact and Expires fields.",
                )
            ],
        )
    body = probe.text[:20_000]
    findings: list[Finding] = []
    if "expires:" not in body.lower():
        findings.append(
            Finding(
                "security.txt has no Expires field",
                "low",
                "RFC 9116 requires an Expires field.",
                used,
                "Add an Expires timestamp and rotate it periodically.",
            )
        )
    return Outcome(
        verdict(findings) if findings else "pass",
        f"security.txt is published at {used}.",
        findings,
    )


@module(
    "sitemap_exposure",
    "Sitemap Exposure",
    CATEGORY,
    "Parses sitemap.xml for internal, staging or administrative URLs.",
    severity="low",
    passive=True,
)
def sitemap_exposure(ctx: ScanContext) -> Outcome:
    probe = ctx.get("/sitemap.xml")
    if not probe.ok or probe.status != 200:
        return Outcome("pass", "No sitemap.xml was returned.")
    body = probe.text[:300_000]
    if "<urlset" not in body.lower() and "<sitemapindex" not in body.lower():
        return Outcome("pass", "The sitemap response was not a sitemap document.")
    urls = re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", body, re.IGNORECASE)
    sensitive = [url for url in urls if SENSITIVE_PATH_RE.search(url)]
    if not sensitive:
        return Outcome(
            "info",
            f"Sitemap exposes {len(urls)} public URL(s).",
            [
                Finding(
                    "Sitemap is publicly readable",
                    "info",
                    "The sitemap lists public URLs and no obvious sensitive paths.",
                    f"urls={len(urls)}",
                    "Review the sitemap whenever new internal routes are added.",
                )
            ],
        )
    return Outcome(
        "warn",
        f"{len(sensitive)} sensitive-looking URL(s) appear in the sitemap.",
        [
            Finding(
                "Sensitive URLs in sitemap",
                "low",
                "Sitemap entries disclose internal or administrative locations.",
                ", ".join(sensitive[:8]),
                "Remove non-public routes from the sitemap and enforce access control.",
            )
        ],
    )


@module(
    "directory_listing",
    "Directory Listing Exposure",
    CATEGORY,
    "Probes common directories for auto-index pages that expose files.",
    severity="high",
    passive=False,
)
def directory_listing(ctx: ScanContext) -> Outcome:
    paths = [
        ("/uploads/", "medium"),
        ("/files/", "medium"),
        ("/backup/", "high"),
        ("/backups/", "high"),
        ("/logs/", "high"),
        ("/tmp/", "high"),
        ("/private/", "high"),
    ]
    findings: list[Finding] = []
    for path, severity in paths:
        probe = ctx.get(path)
        if not probe.ok or probe.status != 200 or _looks_like_spa(probe):
            continue
        body = probe.text[:30_000]
        if re.search(
            r"(<title>\s*Index of|Directory listing for|\[To Parent Directory\])",
            body,
            re.IGNORECASE,
        ):
            findings.append(
                Finding(
                    "Directory listing is enabled",
                    severity,
                    f"Auto-index is enabled at {path}.",
                    f"path={path}; status={probe.status}",
                    "Disable auto-index and require explicit authorization for file access.",
                )
            )
    status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        "No directory listings were exposed."
        if not findings
        else "One or more directories expose an index.",
        findings,
    )


@module(
    "source_map_exposure",
    "Source Map Exposure",
    CATEGORY,
    "Checks whether JavaScript source maps are publicly downloadable.",
    severity="medium",
    passive=False,
)
def source_map_exposure(ctx: ScanContext) -> Outcome:
    page = ctx.homepage()
    scripts = []
    for script in page.scripts:
        if not ctx.same_host(script):
            continue
        clean = script.split("?")[0].split("#")[0]
        if clean.lower().endswith(".js") and clean not in scripts:
            scripts.append(clean)
    findings: list[Finding] = []
    checked = 0
    for script in scripts[:6]:
        map_url = script + ".map"
        probe = ctx.get(map_url)
        checked += 1
        if not probe.ok or probe.status != 200:
            continue
        body = probe.text[:250_000]
        if '"version"' in body and '"sources"' in body:
            findings.append(
                Finding(
                    "JavaScript source map is public",
                    "medium",
                    "Original source paths and code can be recovered from the map.",
                    f"map={urlsplit(map_url).path}",
                    "Do not publish source maps in production, or restrict them to authenticated users.",
                )
            )
    status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        f"Checked {checked} script map(s); none were public."
        if not findings
        else f"{len(findings)} source map(s) exposed.",
        findings,
    )


@module(
    "api_docs_exposure",
    "API Documentation Exposure",
    CATEGORY,
    "Looks for Swagger, OpenAPI, Redoc and GraphiQL interfaces left public.",
    severity="medium",
    passive=False,
)
def api_docs_exposure(ctx: ScanContext) -> Outcome:
    paths = [
        "/openapi.json",
        "/swagger.json",
        "/api-docs",
        "/docs",
        "/swagger-ui",
        "/swagger-ui/index.html",
        "/redoc",
        "/graphiql",
    ]
    findings: list[Finding] = []
    for path in paths:
        probe = ctx.get(path)
        if not probe.ok or probe.status != 200 or _looks_like_spa(probe):
            continue
        body = probe.text[:180_000]
        lowered = body.lower()
        is_openapi = (
            '"openapi"' in lowered
            or '"swagger"' in lowered
            or ("swagger ui" in lowered)
            or ("redoc" in lowered and "spec-url" in lowered)
            or ("graphiql" in lowered and "graphql" in lowered)
        )
        if is_openapi:
            findings.append(
                Finding(
                    "API documentation is publicly reachable",
                    "medium",
                    "An interactive API description can disclose routes, schemas and parameters.",
                    f"path={path}; content-type={probe.content_type}",
                    "Require authentication or restrict API documentation to an internal network.",
                )
            )
    status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        "No public API documentation interface was found."
        if not findings
        else f"{len(findings)} documentation endpoint(s) exposed.",
        findings,
    )


@module(
    "graphql_introspection",
    "GraphQL Introspection",
    CATEGORY,
    "Tests common GraphQL endpoints for unrestricted schema introspection.",
    severity="high",
    passive=False,
)
def graphql_introspection(ctx: ScanContext) -> Outcome:
    query = "{__schema{queryType{name} mutationType{name}}}"
    payload = json.dumps({"query": query}).encode()
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    findings: list[Finding] = []
    for path in ("/graphql", "/api/graphql", "/v1/graphql", "/query"):
        probe = ctx.fetch("POST", ctx.origin + path, content=payload, headers=headers)
        if not probe.ok:
            continue
        body = probe.text[:180_000]
        if probe.status == 200 and "__schema" in body and "queryType" in body:
            findings.append(
                Finding(
                    "GraphQL introspection is enabled",
                    "high",
                    "The full schema can be queried by unauthenticated clients.",
                    f"path={path}; status={probe.status}",
                    "Disable introspection outside development or require authorization.",
                )
            )
            break
        if probe.status in {401, 403}:
            return Outcome("pass", "GraphQL endpoints require authorization.")
    status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        "No open GraphQL introspection endpoint was found."
        if not findings
        else "GraphQL schema introspection is exposed.",
        findings,
    )


@module(
    "debug_exposure",
    "Debug & Actuator Exposure",
    CATEGORY,
    "Probes Spring Actuator, server-status, phpinfo and debug endpoints.",
    severity="high",
    passive=False,
)
def debug_exposure(ctx: ScanContext) -> Outcome:
    checks = [
        ("/actuator/env", ['"propertySources"', '"activeProfiles"'], "high"),
        ("/actuator", ['"_links"', '"self"'], "medium"),
        ("/actuator/health", ['"status"', '"UP"'], "low"),
        ("/server-status", ["Apache Server Status"], "medium"),
        ("/phpinfo.php", ["phpinfo()", "PHP Version", "PHP Credits"], "high"),
        ("/metrics", ["# HELP", "# TYPE"], "medium"),
        ("/debug", ['"debug"', '"config"', '"environment"'], "medium"),
        ("/trace", ['"traces"', '"requests"'], "medium"),
    ]
    findings: list[Finding] = []
    for path, markers, severity in checks:
        probe = ctx.get(path)
        if not probe.ok or probe.status != 200 or _looks_like_spa(probe):
            continue
        body = probe.text[:160_000]
        lowered = body.lower()
        if any(marker.lower() in lowered for marker in markers):
            findings.append(
                Finding(
                    "Debug or management endpoint exposed",
                    severity,
                    f"A management interface is reachable at {path}.",
                    f"path={path}; content-type={probe.content_type}",
                    "Disable the endpoint publicly or require strong authentication and network controls.",
                )
            )
    status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        "No exposed debug or actuator endpoint was found."
        if not findings
        else f"{len(findings)} debug surface(s) exposed.",
        findings,
    )


@module(
    "git_exposure",
    "Git Metadata Exposure",
    CATEGORY,
    "Checks for publicly readable .git, .svn and .hg metadata.",
    severity="critical",
    passive=False,
)
def git_exposure(ctx: ScanContext) -> Outcome:
    checks = [
        ("/.git/config", ["[core]", "repositoryformatversion"], "critical"),
        ("/.git/HEAD", ["ref: refs/", "refs/heads/"], "critical"),
        ("/.svn/entries", ["dir", "svn://", "12"], "high"),
        ("/.hg/requires", ["dotencode", "fncache", "store"], "high"),
    ]
    findings: list[Finding] = []
    for path, markers, severity in checks:
        probe = ctx.get(path)
        if not probe.ok or probe.status != 200 or _looks_like_spa(probe):
            continue
        body = probe.text[:50_000]
        if any(marker in body for marker in markers):
            findings.append(
                Finding(
                    "Version-control metadata is public",
                    severity,
                    f"Repository metadata can be downloaded from {path}.",
                    f"path={path}; bytes={len(probe.raw)}",
                    "Block dotfiles at the web server and redeploy from a clean artifact.",
                )
            )
    status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        "No version-control metadata was exposed."
        if not findings
        else "Version-control metadata is reachable.",
        findings,
    )


@module(
    "env_exposure",
    "Environment & Config Exposure",
    CATEGORY,
    "Checks for leaked .env files, application settings and cloud credentials.",
    severity="critical",
    passive=False,
)
def env_exposure(ctx: ScanContext) -> Outcome:
    checks = [
        ("/.env", ["APP_KEY=", "DB_PASSWORD=", "SECRET_KEY=", "KESTREL_SECRET="]),
        ("/.env.local", ["APP_KEY=", "DB_PASSWORD=", "SECRET_KEY="]),
        ("/.env.production", ["APP_KEY=", "DB_PASSWORD=", "SECRET_KEY="]),
        ("/config.json", ['"password"', '"secret"', '"database"']),
        ("/config.js", ["password", "secret", "apiKey"]),
        ("/appsettings.json", ['"ConnectionStrings"', '"Password"']),
        ("/web.config", ["<configuration", "connectionString"]),
        ("/.aws/credentials", ["aws_access_key_id", "aws_secret_access_key"]),
    ]
    findings: list[Finding] = []
    for path, markers in checks:
        probe = ctx.get(path)
        if not probe.ok or probe.status != 200 or _looks_like_spa(probe):
            continue
        body = probe.text[:120_000]
        if any(marker.lower() in body.lower() for marker in markers):
            findings.append(
                Finding(
                    "Configuration or secret file is public",
                    "critical",
                    f"A sensitive configuration file is reachable at {path}.",
                    f"path={path}; bytes={len(probe.raw)}",
                    "Remove the file from the web root, rotate exposed secrets, and block dotfiles.",
                )
            )
    status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        "No environment or configuration file was exposed."
        if not findings
        else "Sensitive configuration files are downloadable.",
        findings,
    )


@module(
    "backup_exposure",
    "Backup Archive Exposure",
    CATEGORY,
    "Probes for downloadable database dumps, site archives and editor backups.",
    severity="critical",
    passive=False,
)
def backup_exposure(ctx: ScanContext) -> Outcome:
    checks = [
        ("/backup.zip", "zip"),
        ("/site.zip", "zip"),
        ("/www.zip", "zip"),
        ("/public_html.zip", "zip"),
        ("/backup.tar.gz", "gzip"),
        ("/db.sql", "sql"),
        ("/database.sql", "sql"),
        ("/dump.sql", "sql"),
        ("/config.php.bak", "php"),
        ("/wp-config.php.bak", "php"),
        ("/.DS_Store", "dsstore"),
    ]
    findings: list[Finding] = []
    for path, kind in checks:
        probe = ctx.get(path, max_bytes=8192)
        if not probe.ok or probe.status != 200 or _looks_like_spa(probe):
            continue
        raw = probe.raw[:8192]
        matched = False
        if kind == "zip" and raw.startswith(b"PK\x03\x04"):
            matched = True
        elif kind == "gzip" and raw.startswith(b"\x1f\x8b"):
            matched = True
        elif kind == "dsstore" and raw.startswith(b"\x00\x00\x00\x01Bud1"):
            matched = True
        elif kind == "sql" and re.search(
            rb"(-- MySQL dump|CREATE TABLE|INSERT INTO|SQLite format)",
            raw,
            re.IGNORECASE,
        ):
            matched = True
        elif kind == "php" and re.search(rb"<\?php|DB_PASSWORD|DB_NAME", raw):
            matched = True
        if matched:
            findings.append(
                Finding(
                    "Backup or database artifact is public",
                    "critical",
                    f"A backup-like file is downloadable at {path}.",
                    f"path={path}; bytes={len(probe.raw)}; signature={kind}",
                    "Remove the artifact, rotate any contained credentials, and block backup extensions.",
                )
            )
    status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        "No backup artifact was exposed."
        if not findings
        else "Backup artifacts are publicly downloadable.",
        findings,
    )


@module(
    "admin_surface",
    "Administrative Surface Discovery",
    CATEGORY,
    "Maps reachable administrative, database and hosting management interfaces.",
    severity="medium",
    passive=False,
)
def admin_surface(ctx: ScanContext) -> Outcome:
    paths = [
        ("/admin", "admin"),
        ("/administrator", "admin"),
        ("/wp-admin/", "WordPress"),
        ("/wp-login.php", "WordPress"),
        ("/phpmyadmin/", "phpMyAdmin"),
        ("/pma/", "phpMyAdmin"),
        ("/cpanel", "cPanel"),
        ("/manager/html", "Tomcat Manager"),
        ("/server-status", "Apache status"),
    ]
    findings: list[Finding] = []
    for path, label in paths:
        probe = ctx.get(path)
        if not probe.ok:
            continue
        if probe.status in {401, 403}:
            findings.append(
                Finding(
                    "Protected administrative surface",
                    "low",
                    f"{label} responds with HTTP {probe.status} at {path} and is access-controlled.",
                    f"path={path}; status={probe.status}",
                    "Keep the interface behind a VPN or IP allowlist and review default accounts.",
                )
            )
            continue
        if probe.status != 200 or _looks_like_spa(probe):
            continue
        body = probe.text[:80_000].lower()
        if any(
            marker in body
            for marker in (
                "login",
                "password",
                "sign in",
                "dashboard",
                "phpmyadmin",
                "manager",
                "username",
            )
        ):
            findings.append(
                Finding(
                    "Administrative interface is reachable",
                    "medium",
                    f"{label} appears reachable at {path}.",
                    f"path={path}; status={probe.status}",
                    "Restrict the interface to trusted networks and enforce MFA.",
                )
            )
    status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        "No administrative interface was discovered."
        if not findings
        else f"{len(findings)} administrative surface(s) mapped.",
        findings,
    )


@module(
    "error_disclosure",
    "Error Handling Disclosure",
    CATEGORY,
    "Triggers controlled error responses and looks for stack traces or framework leakage.",
    severity="medium",
    passive=False,
)
def error_disclosure(ctx: ScanContext) -> Outcome:
    token = secrets.token_hex(4)
    probes = [
        ("404 path", ctx.get(f"/cm-missing-{token}")),
        ("malformed query", ctx.get(f"/?cm_probe={token}%27")),
    ]
    patterns = [
        (r"Traceback \(most recent call last\)", "Python traceback"),
        (r"at [A-Za-z0-9_.]+\.[A-Za-z0-9_]+\([A-Za-z0-9_]+\.java:\d+\)", "Java stack trace"),
        (r"Fatal error:\s+.*? in .*? on line \d+", "PHP fatal error"),
        (r"Microsoft \.NET Framework.*?Exception", ".NET exception"),
        (r"SQLSTATE\[[A-Z0-9]+\]", "SQL error state"),
        (r"DEBUG\s*=\s*True", "Django debug mode"),
        (r"<b>Warning</b>:\s+.*? on line \d+", "PHP warning"),
        (r"Stack trace:", "Stack trace"),
    ]
    findings: list[Finding] = []
    for label, probe in probes:
        if not probe.ok:
            continue
        body = probe.text[:250_000]
        matched = []
        for pattern, name in patterns:
            if re.search(pattern, body, re.IGNORECASE):
                matched.append(name)
        if matched:
            findings.append(
                Finding(
                    "Error response discloses implementation details",
                    "medium",
                    f"{label} exposed {', '.join(matched[:3])}.",
                    f"status={probe.status}; bytes={len(probe.raw)}",
                    "Return generic error pages, disable debug mode, and log details server-side.",
                )
            )
    debug_header = probes[0][1].header("x-debug-token") if probes[0][1].ok else ""
    if debug_header:
        findings.append(
            Finding(
                "Debug header is exposed",
                "low",
                "The response includes a framework debug token.",
                "x-debug-token=<present>",
                "Remove debug headers from production responses.",
            )
        )
    status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        "Error responses do not disclose stack traces."
        if not findings
        else "Error handling leaks implementation details.",
        findings,
    )


@module(
    "secret_leakage",
    "Frontend Secret Leakage",
    CATEGORY,
    "Scans HTML and same-origin JavaScript for embedded credentials and API keys.",
    severity="critical",
    passive=False,
)
def secret_leakage(ctx: ScanContext) -> Outcome:
    page = ctx.homepage()
    sources: list[tuple[str, str]] = [("inline HTML", page.html[:1_200_000])]
    scripts = [url for url in page.scripts if ctx.same_host(url)]
    seen = set()
    for script in scripts:
        if script in seen:
            continue
        seen.add(script)
        probe = ctx.get(script, max_bytes=900_000)
        if probe.ok and probe.status == 200 and "javascript" in (
            probe.content_type or "javascript"
        ):
            sources.append((urlsplit(script).path or script, probe.text[:900_000]))
        if len(sources) >= 7:
            break
    patterns: list[tuple[str, str, re.Pattern[str]]] = [
        (
            "Private key material",
            "critical",
            re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
        ),
        ("AWS access key", "high", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
        (
            "Google API key",
            "high",
            re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
        ),
        (
            "Stripe live secret",
            "critical",
            re.compile(r"\bsk_live_[0-9a-zA-Z]{20,}\b"),
        ),
        (
            "Slack token",
            "high",
            re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
        ),
        (
            "JWT embedded in frontend",
            "info",
            re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        ),
    ]
    generic = re.compile(
        r"(?i)(api[_-]?key|client[_-]?secret|secret|access[_-]?token|password)"
        r"\s*[=:]\s*['\"]([A-Za-z0-9_\-./+=]{20,})['\"]"
    )
    findings: list[Finding] = []
    seen_values: set[str] = set()
    for label, source in sources:
        for name, severity, pattern in patterns:
            for match in pattern.finditer(source):
                value = match.group(0)
                if value in seen_values:
                    continue
                seen_values.add(value)
                findings.append(
                    Finding(
                        f"{name} exposed in frontend",
                        severity,
                        f"A {name.lower()} pattern appears in {label}.",
                        f"source={label}; value={redact_secret(value)}",
                        "Remove the secret from client code, rotate it, and move access server-side.",
                    )
                )
                if len(findings) >= 8:
                    break
        for match in generic.finditer(source):
            value = match.group(2)
            if len(value) < 24 or value in seen_values:
                continue
            seen_values.add(value)
            findings.append(
                Finding(
                    "High-entropy assignment in frontend",
                    "medium",
                    "A secret-looking assignment is embedded in client-side code.",
                    f"source={label}; key={match.group(1)}; value={redact_secret(value)}",
                    "Confirm whether the value is sensitive; move real secrets to the server.",
                )
            )
            if len(findings) >= 10:
                break
        if len(findings) >= 10:
            break
    # Avoid reporting a JWT that is simply a public session token twice.
    if findings and all(f.severity == "info" for f in findings):
        status = "info"
    else:
        status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        "No embedded secrets were detected in frontend assets."
        if not findings
        else f"{len(findings)} secret-like value(s) require review.",
        findings,
    )

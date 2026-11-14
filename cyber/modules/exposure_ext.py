"""Extended exposure and discovery modules."""

from __future__ import annotations

import json
import re
from urllib.parse import urlsplit

from ..engine import ScanContext
from ..models import Finding, Outcome
from ..registry import module, verdict
from ._shared import contains_any, excerpt, plain

CATEGORY = "Exposure & Discovery"


@module(
    "package_metadata",
    "Package Metadata Exposure",
    CATEGORY,
    "Probes package manifests and lockfiles for dependency metadata.",
    severity="medium",
    passive=False,
)
def package_metadata(ctx: ScanContext) -> Outcome:
    findings: list[Finding] = []
    for path, label in (
        ("/package.json", "Node package manifest"),
        ("/composer.json", "Composer manifest"),
        ("/package-lock.json", "Node lockfile"),
    ):
        probe = ctx.get(path)
        if not plain(probe) or not probe.text.lstrip().startswith(("{", "[")):
            continue
        try:
            payload = json.loads(probe.text[:200_000])
        except (ValueError, TypeError):
            payload = None
        if not isinstance(payload, dict):
            continue
        keys = set(payload)
        if label == "Node lockfile":
            if "lockfileVersion" not in keys:
                continue
        elif not ({"name", "version", "dependencies", "require", "autoload"} & keys):
            continue
        findings.append(
            Finding(
                f"{label} is publicly readable",
                "medium",
                "Dependency names and versions help an attacker select known vulnerable components.",
                f"path={path}; keys={', '.join(sorted(keys)[:8])}",
                "Block manifest and lockfile requests at the edge and keep them outside the web root.",
            )
        )
        if len(findings) >= 3:
            break
    status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        "No package metadata was exposed." if not findings else "Package metadata is exposed.",
        findings,
    )


@module(
    "ci_config_exposure",
    "CI Configuration Exposure",
    CATEGORY,
    "Checks for publicly readable pipeline definitions that reveal build secrets or deploy paths.",
    severity="medium",
    passive=False,
)
def ci_config_exposure(ctx: ScanContext) -> Outcome:
    paths = (
        "/.gitlab-ci.yml",
        "/.github/workflows/ci.yml",
        "/.circleci/config.yml",
        "/.travis.yml",
        "/Jenkinsfile",
        "/azure-pipelines.yml",
        "/bitbucket-pipelines.yml",
    )
    findings: list[Finding] = []
    for path in paths:
        probe = ctx.get(path)
        if not plain(probe) or len(probe.text.strip()) < 20:
            continue
        marker = contains_any(
            probe.text,
            (
                r"^stages:",
                r"^jobs:",
                r"^pipeline:",
                r"^on:\s*$",
                r"^script:",
                r"^steps:",
                r"^trigger:",
                r"pipeline\s*\{",
            ),
        )
        if not marker:
            continue
        findings.append(
            Finding(
                "CI pipeline definition is publicly readable",
                "medium",
                "Pipeline files disclose build steps, registries and sometimes secret names.",
                f"path={path}; marker={marker}",
                "Serve CI configuration only from the repository and deny it at the web root.",
            )
        )
    status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        "No CI configuration was exposed." if not findings else "CI configuration is exposed.",
        findings,
    )


@module(
    "editor_backup_files",
    "Editor Backup File Exposure",
    CATEGORY,
    "Probes common editor and deployment backup suffixes for source code disclosure.",
    severity="high",
    passive=False,
)
def editor_backup_files(ctx: ScanContext) -> Outcome:
    current = urlsplit(ctx.target).path or "/"
    if current.endswith("/"):
        current += "index.php"
    basename = current.rsplit("/", 1)[-1] or "index.php"
    directory = current.rsplit("/", 1)[0]
    names = [
        f"{current}~",
        f"{current}.bak",
        f"{current}.old",
        f"{current}.save",
        f"{directory}/.{basename}.swp",
        "/config.php.bak",
        "/.env.save",
        "/web.config.old",
        "/appsettings.json.bak",
    ]
    findings: list[Finding] = []
    for path in names:
        probe = ctx.get(path)
        if not plain(probe) or len(probe.text.strip()) < 8:
            continue
        marker = contains_any(
            probe.text,
            (
                r"<\?php",
                r"DB_(?:HOST|PASSWORD|USER)",
                r"api[_-]?key",
                r"connectionstring",
                r"^\s*(?:def|class)\s+",
                r"\{\s*\"[a-z_]+\"\s*:",
            ),
        )
        if not marker:
            continue
        findings.append(
            Finding(
                "Backup or editor swap file is readable",
                "high",
                "A backup copy can expose source code, credentials or configuration.",
                f"path={path}; marker={marker}",
                "Delete backup artifacts, deny dotfile and backup suffixes at the edge, and redeploy through a clean pipeline.",
            )
        )
        if len(findings) >= 4:
            break
    status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        "No editor backup files were exposed." if not findings else "Backup files leak source material.",
        findings,
    )


@module(
    "server_status_page",
    "Server Status Page Exposure",
    CATEGORY,
    "Probes Apache and nginx status handlers for live request and worker data.",
    severity="medium",
    passive=False,
)
def server_status_page(ctx: ScanContext) -> Outcome:
    paths = ("/server-status", "/server-status/", "/server-info", "/nginx_status")
    findings: list[Finding] = []
    for path in paths:
        probe = ctx.get(path)
        if not plain(probe):
            continue
        marker = contains_any(
            probe.text,
            (
                r"Apache Server Status",
                r"Server Version:",
                r"Active connections",
                r"requests currently being processed",
                r"nginx status",
                r"Active connections:",
            ),
        )
        if not marker:
            continue
        findings.append(
            Finding(
                "Server status handler is publicly reachable",
                "medium",
                "Live worker, request and upstream data are exposed to unauthenticated users.",
                f"path={path}; marker={marker}",
                "Restrict status handlers to localhost or an authenticated monitoring network.",
            )
        )
    status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        "No server status page was exposed." if not findings else "A server status page is exposed.",
        findings,
    )


@module(
    "swagger_ui",
    "API Console Exposure",
    CATEGORY,
    "Detects publicly reachable Swagger UI and OpenAPI descriptions.",
    severity="medium",
    passive=False,
)
def swagger_ui(ctx: ScanContext) -> Outcome:
    findings: list[Finding] = []
    for path in ("/swagger-ui.html", "/swagger-ui/", "/swagger.json", "/openapi.json", "/api/openapi.json"):
        probe = ctx.get(path)
        if not plain(probe):
            continue
        text = probe.text[:200_000]
        if path.endswith(".json"):
            try:
                payload = json.loads(text)
            except (ValueError, TypeError):
                payload = None
            if not isinstance(payload, dict) or not (payload.get("openapi") or payload.get("swagger")):
                continue
            marker = f"openapi={payload.get('openapi') or payload.get('swagger')}"
        else:
            marker = contains_any(text, (r"SwaggerUIBundle", r"swagger-ui", r"OpenAPI"))
            if not marker:
                continue
        findings.append(
            Finding(
                "Interactive API description is publicly readable",
                "medium",
                "The schema exposes every route, parameter and model to unauthenticated users.",
                f"path={path}; {marker}"[:220],
                "Require authentication for API consoles and publish only a minimal public schema.",
            )
        )
    status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        "No API console was exposed." if not findings else "An API console is publicly readable.",
        findings,
    )


@module(
    "metrics_exposure",
    "Metrics Endpoint Exposure",
    CATEGORY,
    "Checks Prometheus and Actuator metric endpoints for anonymous scraping.",
    severity="medium",
    passive=False,
)
def metrics_exposure(ctx: ScanContext) -> Outcome:
    findings: list[Finding] = []
    for path in ("/metrics", "/actuator/prometheus", "/debug/metrics", "/actuator/metrics"):
        probe = ctx.get(path)
        if not plain(probe):
            continue
        marker = contains_any(
            probe.text,
            (
                r"^# HELP",
                r"^# TYPE",
                r"go_gc_duration_seconds",
                r"process_cpu_seconds_total",
                r"http_requests_total",
                r"jvm_memory_used_bytes",
            ),
        )
        if not marker:
            continue
        findings.append(
            Finding(
                "Metrics endpoint accepts anonymous requests",
                "medium",
                "Counters, latency histograms and runtime labels reveal internals and attack timing.",
                f"path={path}; marker={marker}",
                "Restrict metrics to an authenticated scrape network and remove high-cardinality user labels.",
            )
        )
    status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        "No metrics endpoint was exposed." if not findings else "Metrics are exposed anonymously.",
        findings,
    )


@module(
    "database_admin",
    "Database Admin Exposure",
    CATEGORY,
    "Probes common database administration consoles for public reachability.",
    severity="medium",
    passive=False,
)
def database_admin(ctx: ScanContext) -> Outcome:
    paths = ("/phpmyadmin/", "/phpMyAdmin/", "/adminer.php", "/adminer/", "/pgadmin4/", "/dbadmin/")
    findings: list[Finding] = []
    for path in paths:
        probe = ctx.get(path)
        if not plain(probe):
            continue
        marker = contains_any(
            probe.text,
            (
                r"phpMyAdmin",
                r"Adminer",
                r"pgAdmin",
                r"Database (?:Management|Administration)",
                r"login.*database",
            ),
        )
        if not marker:
            continue
        findings.append(
            Finding(
                "Database administration console is reachable",
                "medium",
                "A public database console widens brute-force and credential-stuffing exposure.",
                f"path={path}; marker={marker}",
                "Bind database consoles to localhost or a private network and require SSO plus MFA.",
            )
        )
    status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        "No database console was exposed." if not findings else "A database console is publicly reachable.",
        findings,
    )


@module(
    "log_exposure",
    "Application Log Exposure",
    CATEGORY,
    "Probes common log locations for stack traces, credentials and request history.",
    severity="high",
    passive=False,
)
def log_exposure(ctx: ScanContext) -> Outcome:
    paths = (
        "/error.log",
        "/access.log",
        "/debug.log",
        "/app.log",
        "/logs/error.log",
        "/storage/logs/laravel.log",
        "/wp-content/debug.log",
    )
    findings: list[Finding] = []
    for path in paths:
        probe = ctx.get(path)
        if not plain(probe) or len(probe.text.strip()) < 40:
            continue
        text = probe.text[:200_000]
        hits = sum(
            1
            for pattern in (
                r"\[\d{2}-[A-Za-z]{3}-\d{4}",
                r"^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}",
                r"PHP (?:Fatal|Warning|Notice) error",
                r"Traceback \(most recent call last\)",
                r"SQLSTATE\[",
                r"(?:GET|POST) /\S* HTTP/",
            )
            if re.search(pattern, text, re.I | re.M)
        )
        if hits < 2:
            continue
        findings.append(
            Finding(
                "Application log is publicly readable",
                "high",
                "Logs can contain session identifiers, stack traces, internal paths and customer data.",
                f"path={path}; patterns={hits}",
                "Remove logs from the web root, rotate them off-host, and deny log suffixes at the edge.",
            )
        )
    status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        "No application log was exposed." if not findings else "Application logs are exposed.",
        findings,
    )


@module(
    "crossdomain_policy",
    "Cross-Domain Policy",
    CATEGORY,
    "Inspects legacy crossdomain.xml and clientaccesspolicy.xml allowlists.",
    severity="medium",
    passive=False,
)
def crossdomain_policy(ctx: ScanContext) -> Outcome:
    findings: list[Finding] = []
    for path, label in (
        ("/crossdomain.xml", "crossdomain.xml"),
        ("/clientaccesspolicy.xml", "clientaccesspolicy.xml"),
    ):
        probe = ctx.get(path)
        if not plain(probe) or "<" not in probe.text[:2000]:
            continue
        text = probe.text[:120_000]
        if re.search(r'allow-access-from[^>]+domain\s*=\s*["\']\*["\']', text, re.I):
            severity = "high" if re.search(r'secure\s*=\s*["\']false["\']', text, re.I) else "medium"
            findings.append(
                Finding(
                    "Cross-domain policy allows every origin",
                    severity,
                    "A wildcard policy lets any Flash or Silverlight origin read responses from this host.",
                    f"path={path}; wildcard=true; secure=false={severity == 'high'}",
                    "Remove wildcard domains and restrict the policy to explicitly trusted origins, then retire legacy plugins.",
                )
            )
        elif "allow-access-from" in text:
            findings.append(
                Finding(
                    "Legacy cross-domain policy is published",
                    "info",
                    "A restrictive policy remains available for deprecated plugin clients.",
                    f"path={path}",
                    "Remove the file once no legacy client depends on it.",
                )
            )
    status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        "No permissive cross-domain policy was found."
        if not findings
        else "Cross-domain policy needs review.",
        findings,
    )


@module(
    "trace_axd",
    "ASP.NET Trace Exposure",
    CATEGORY,
    "Probes trace.axd, elmah.axd and glimpse diagnostics for request and exception data.",
    severity="medium",
    passive=False,
)
def trace_axd(ctx: ScanContext) -> Outcome:
    findings: list[Finding] = []
    for path in ("/trace.axd", "/elmah.axd", "/glimpse.axd"):
        probe = ctx.get(path)
        if not plain(probe):
            continue
        marker = contains_any(
            probe.text,
            (
                r"Application Trace",
                r"Trace Information",
                r"ELMAH",
                r"Error Log for",
                r"Glimpse",
                r"Request Details",
            ),
        )
        if not marker:
            continue
        findings.append(
            Finding(
                "ASP.NET diagnostics endpoint is reachable",
                "medium",
                "Request traces and exception details disclose cookies, server paths and framework versions.",
                f"path={path}; marker={marker}",
                "Disable tracing in production and restrict diagnostics to localhost.",
            )
        )
    page = ctx.homepage()
    version = page.headers.get("x-aspnet-version", "").strip()
    if version:
        findings.append(
            Finding(
                "ASP.NET version header is disclosed",
                "low",
                "The runtime version narrows the set of applicable exploits.",
                f"x-aspnet-version={version[:80]}",
                "Remove version headers at the server or edge.",
            )
        )
    status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        "No ASP.NET diagnostics were exposed." if not findings else "ASP.NET diagnostics expose internals.",
        findings,
    )


@module(
    "docker_registry",
    "Docker Registry Exposure",
    CATEGORY,
    "Checks the Registry v2 API for anonymous catalog access.",
    severity="high",
    passive=False,
)
def docker_registry(ctx: ScanContext) -> Outcome:
    base = ctx.get("/v2/")
    if not base.ok:
        return Outcome("pass", "No Docker Registry API was detected.")
    api_header = base.header("docker-distribution-api-version", "")
    if not api_header and base.status not in {200, 401}:
        return Outcome("pass", "No Docker Registry API was detected.")
    findings: list[Finding] = []
    catalog = ctx.get("/v2/_catalog")
    if catalog.ok and catalog.status == 200 and catalog.text.lstrip().startswith("{"):
        try:
            payload = json.loads(catalog.text[:200_000])
        except (ValueError, TypeError):
            payload = None
        repositories = payload.get("repositories") if isinstance(payload, dict) else None
        if isinstance(repositories, list):
            findings.append(
                Finding(
                    "Docker Registry catalog is publicly readable",
                    "high",
                    "Anonymous users can enumerate repositories and pull image layers.",
                    f"path=/v2/_catalog; repositories={len(repositories)}; sample={', '.join(map(str, repositories[:5]))}",
                    "Require authentication for the registry API and disable the catalog endpoint for anonymous clients.",
                )
            )
    if not findings and (api_header or base.status in {200, 401}):
        findings.append(
            Finding(
                "Docker Registry API is exposed",
                "medium",
                "The Registry v2 endpoint is reachable from the public assessment origin.",
                f"path=/v2/; status={base.status}; api={api_header or '<implicit>'}",
                "Place the registry behind authentication and network policy, or remove it from the public listener.",
            )
        )
    status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        "No public Docker Registry API was detected."
        if not findings
        else "Docker Registry API is exposed.",
        findings,
    )


@module(
    "kubernetes_api",
    "Kubernetes API Exposure",
    CATEGORY,
    "Detects anonymous Kubernetes API discovery endpoints.",
    severity="critical",
    passive=False,
)
def kubernetes_api(ctx: ScanContext) -> Outcome:
    findings: list[Finding] = []
    for path in ("/version", "/api", "/apis", "/healthz"):
        probe = ctx.get(path)
        if not probe.ok or probe.status != 200:
            continue
        text = probe.text[:120_000]
        if not text.lstrip().startswith(("{", "[")):
            continue
        try:
            payload = json.loads(text)
        except (ValueError, TypeError):
            continue
        if not isinstance(payload, dict):
            continue
        keys = set(payload)
        kubernetes_markers = {"gitVersion", "buildDate", "goVersion", "platform"} <= keys
        kubernetes_markers = kubernetes_markers or (
            "kind" in keys and str(payload.get("kind", "")).startswith("APIVersions")
        )
        if not kubernetes_markers:
            continue
        findings.append(
            Finding(
                "Kubernetes API is anonymously reachable",
                "critical",
                "Cluster discovery is exposed; misconfigured RBAC could allow workload or secret access.",
                f"path={path}; keys={', '.join(sorted(keys)[:8])}",
                "Restrict the API server to the control-plane network and require strong authentication plus RBAC.",
            )
        )
        break
    status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        "No Kubernetes API was exposed." if not findings else "Kubernetes API is publicly reachable.",
        findings,
    )

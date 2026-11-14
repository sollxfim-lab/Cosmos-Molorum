"""Wordlist-driven probes.

Each probe consumes a curated wordlist of benign markers and only reports a
finding when the response demonstrates unsafe handling. Nothing is executed
and no sensitive file is read.
"""

from __future__ import annotations

import re
import secrets

from ..engine import ScanContext
from ..models import Finding, Outcome
from ..registry import module, verdict
from ..resources import (
    DIR_FUZZ,
    LFI_PAYLOADS,
    REDIRECT_TARGETS,
    SQL_PAYLOADS,
    XSS_PAYLOADS,
)

INJECTION = "Injection & Input"
DISCOVERY = "Exposure & Discovery"

SQL_ERROR_PATTERNS = (
    r"SQL syntax.*MySQL",
    r"Warning.*mysql_",
    r"You have an error in your SQL syntax",
    r"PostgreSQL.*ERROR",
    r"pg_query\(\)",
    r"Microsoft SQL Server",
    r"Unclosed quotation mark",
    r"SqlException",
    r"ORA-\d{4,5}",
    r"sqlite3\.OperationalError",
    r"PDOException",
    r"SQLSTATE\[",
    r"java\.sql\.SQLException",
    r"org\.hibernate",
    r"MongoError",
    r"MongoServerError",
    r"Cast to ObjectId failed",
    r"Invalid DN syntax",
    r"LDAPException",
    r"XPathException",
    r"DOMXPath",
)

LFI_MARKERS = (
    # (path fragment in the marker, response signature of real file content)
    ("/etc/passwd", r"root:[^:\r\n]*:0:0:"),
    ("/etc/group", r"(?m)^root:[^:\r\n]*:0:"),
    ("/etc/hosts", r"(?m)^\s*127\.0\.0\.1\s+localhost"),
    ("/etc/resolv.conf", r"(?m)^\s*nameserver\s+\d"),
    ("win.ini", r"\[(?:fonts|extensions|mci extensions|Mail)\]"),
    ("boot.ini", r"\[boot loader\]"),
    ("proc/self/environ", r"(?:^|\x00)PATH="),
    ("apache2.conf", r"(?:ServerRoot|LoadModule|<\s*Directory)"),
    ("nginx.conf", r"(?:worker_processes|http\s*\{)"),
    ("auth.log", r"sshd\[\d+\]|session opened for user"),
    ("laravel.log", r"local\.(?:ERROR|INFO)|#\d+\s+[^\r\n]*\.php\(\d+\)"),
    ("wp-config.php", r"DB_(?:NAME|PASSWORD|USER)"),
)

_BLOCKED_STATUSES = {401, 403, 404, 410, 429, 501}


def _window(names: list[str], quota: int) -> list[str]:
    """Return up to quota entries: half from the head, half spread evenly.

    Wordlists are ordered by usefulness, so the head stays in the sample
    while the spread portion still covers the long tail.
    """
    if not names or quota <= 0:
        return []
    if quota >= len(names):
        return list(names)
    head_count = max(1, quota // 2)
    picked = list(dict.fromkeys(names[:head_count]))
    remaining = quota - len(picked)
    if remaining <= 0:
        return picked[:quota]
    step = len(names) / remaining
    position = head_count / 2
    while len(picked) < quota and int(position) < len(names):
        entry = names[int(position)]
        if entry not in picked:
            picked.append(entry)
        position += step
    index = 0
    while len(picked) < quota and index < len(names):
        if names[index] not in picked:
            picked.append(names[index])
        index += 1
    return picked[:quota]


def _sql_error(text: str) -> str:
    for pattern in SQL_ERROR_PATTERNS:
        if re.search(pattern, text, re.I):
            return pattern
    return ""


@module(
    "sql_wordlist",
    "SQL Injection Wordlist Probe",
    INJECTION,
    "Sends a curated sample of SQL markers to each input point and reports"
    " database errors or suspicious response changes.",
    severity="high",
    passive=False,
)
def sql_wordlist(ctx: ScanContext) -> Outcome:
    markers = _window(SQL_PAYLOADS, 12)
    if not markers:
        return Outcome("pass", "SQL wordlist tidak tersedia; probe dilewati.", [])

    points = ctx.candidate_points(limit=2)
    findings: list[Finding] = []
    examined = 0
    for point in points:
        for marker in markers:
            probe = ctx.send_point(point, marker, follow=False)
            examined += 1
            if not probe.ok or not probe.text:
                continue
            error = _sql_error(probe.text)
            if error:
                findings.append(
                    Finding(
                        "SQL marker reaches a database error",
                        "high",
                        "A SQL marker produced a database error, exposing query structure.",
                        f"param={point.param}; marker={marker!r}; matched={error}",
                        "Parameterize every database query, validate input by type and disable verbose database errors.",
                    )
                )
                break
            if probe.is_json and probe.status >= 500 and "error" in probe.text.lower():
                findings.append(
                    Finding(
                        "SQL marker produces a server error response",
                        "medium",
                        "A JSON endpoint returned a server error after receiving a SQL marker.",
                        f"param={point.param}; marker={marker!r}; status={probe.status}",
                        "Handle malformed input with a stable 4xx response and parameterize queries.",
                    )
                )
                break

    status = verdict(findings) if findings else "pass"
    summary = (
        f"{examined} marker SQL diuji pada {len(points)} parameter."
        if not findings
        else f"{len(findings)} parameter bereaksi terhadap marker SQL."
    )
    return Outcome(status, summary, findings)


@module(
    "lfi_wordlist",
    "Local File Inclusion Wordlist Probe",
    INJECTION,
    "Sends a curated sample of traversal and inclusion markers to file-like"
    " parameters and checks for path evidence in the response.",
    severity="high",
    passive=False,
)
def lfi_wordlist(ctx: ScanContext) -> Outcome:
    markers = _window(LFI_PAYLOADS, 15)
    if not markers:
        return Outcome("pass", "Wordlist LFI tidak tersedia; probe dilewati.", [])

    file_like = [
        point
        for point in ctx.candidate_points(limit=6)
        if re.search(r"(file|path|doc|page|view|include|template|dir|src|load|read)", point.param, re.I)
    ]
    points = (file_like or ctx.candidate_points(limit=2))[:2]

    findings: list[Finding] = []
    examined = 0
    for point in points:
        for marker in markers:
            probe = ctx.send_point(point, marker, follow=False)
            examined += 1
            if not probe.ok or not probe.text:
                continue
            if probe.status in _BLOCKED_STATUSES:
                continue
            evidence = next(
                (
                    name
                    for name, signature in LFI_MARKERS
                    if name.lower() in marker.lower() and re.search(signature, probe.text)
                ),
                "",
            )
            if evidence:
                findings.append(
                    Finding(
                        "File content is exposed through a path parameter",
                        "high",
                        "A traversal marker returned content that matches a real file signature, not merely a reflected path.",
                        f"param={point.param}; marker={marker!r}; evidence={evidence}",
                        "Resolve file names against an allowlist, reject traversal sequences and keep sensitive files outside the web root.",
                    )
                )
                break

    status = verdict(findings) if findings else "pass"
    summary = (
        f"{examined} marker traversal diuji pada {len(points)} parameter."
        if not findings
        else f"{len(findings)} parameter menerima marker traversal."
    )
    return Outcome(status, summary, findings)


@module(
    "dir_fuzz",
    "Directory Fuzzing Probe",
    DISCOVERY,
    "Checks a sampled directory and file wordlist against the web root and"
    " reports paths that resolve outside the soft-404 baseline.",
    severity="low",
    passive=False,
)
def dir_fuzz(ctx: ScanContext) -> Outcome:
    entries = _window(DIR_FUZZ, 40)
    if not entries:
        return Outcome("pass", "Wordlist direktori tidak tersedia; probe dilewati.", [])

    base = ctx.base_url.rstrip("/")
    findings: list[Finding] = []
    examined = 0

    baseline_probe = ctx.fetch("GET", f"{base}/sentinel-nonexistent-{ctx.requests_made}-path")
    baseline_status = baseline_probe.status or 404
    baseline_length = len(baseline_probe.raw)

    for entry in entries:
        path = entry.lstrip("/")
        probe = ctx.fetch("GET", f"{base}/{path}")
        examined += 1
        if not probe.ok or probe.status in _BLOCKED_STATUSES:
            continue
        if probe.status == baseline_status and abs(len(probe.raw) - baseline_length) <= max(64, baseline_length // 100):
            continue
        findings.append(
            Finding(
                "Discoverable path outside the baseline",
                "low",
                f"Path '{path}' returned status {probe.status} with a response that differs from the soft-404 baseline.",
                f"path={path}; status={probe.status}; bytes={len(probe.raw)}",
                "Serve only intended routes, return a consistent 404 for unknown paths and disable directory listings.",
            )
        )

    status = verdict(findings) if findings else "pass"
    summary = (
        f"{examined} path diuji; tidak ada path yang menonjol dari baseline."
        if not findings
        else f"{examined} path diuji; {len(findings)} path dapat ditemukan."
    )
    return Outcome(status, summary, findings)


@module(
    "xss_wordlist",
    "XSS Wordlist Probe",
    INJECTION,
    "Sends a curated sample of script and attribute markers to input points and"
    " reports markers reflected verbatim into an HTML response.",
    severity="high",
    passive=False,
)
def xss_wordlist(ctx: ScanContext) -> Outcome:
    markers = _window(XSS_PAYLOADS, 15)
    if not markers:
        return Outcome("pass", "Wordlist XSS tidak tersedia; probe dilewati.", [])

    points = ctx.candidate_points(limit=2)
    findings: list[Finding] = []
    examined = 0
    for point in points:
        for marker in markers:
            if "<" not in marker:
                continue
            probe = ctx.send_point(point, marker, follow=False)
            examined += 1
            if not probe.ok or not probe.is_html:
                continue
            if marker not in probe.text:
                continue
            findings.append(
                Finding(
                    "Script marker is reflected without encoding",
                    "high",
                    "An HTML response contains the payload verbatim, so the input point may execute script.",
                    f"param={point.param}; marker={marker!r}",
                    "Context-aware output encoding, a strict Content Security Policy and input validation prevent script execution.",
                )
            )
            break

    status = verdict(findings) if findings else "pass"
    summary = (
        f"{examined} marker XSS diuji pada {len(points)} parameter."
        if not findings
        else f"{len(findings)} parameter memantulkan marker tanpa encoding."
    )
    return Outcome(status, summary, findings)


@module(
    "open_redirect_wordlist",
    "Open Redirect Wordlist Probe",
    INJECTION,
    "Sends unique external redirect targets to navigation-style parameters and"
    " reports off-site redirects.",
    severity="medium",
    passive=False,
)
def open_redirect_wordlist(ctx: ScanContext) -> Outcome:
    targets = _window(REDIRECT_TARGETS, 8)
    if not targets:
        return Outcome("pass", "Wordlist redirect tidak tersedia; probe dilewati.", [])

    redirect_points = [
        point
        for point in ctx.candidate_points(limit=8)
        if re.search(r"(redirect|url|next|return|continue|dest|target|goto|back|redir)", point.param, re.I)
    ]
    if not redirect_points:
        return Outcome(
            "pass",
            "Tidak ada parameter navigasi yang dapat diuji untuk open redirect.",
            [],
        )

    findings: list[Finding] = []
    examined = 0
    for point in redirect_points[:2]:
        for target in targets:
            token = secrets.token_hex(4)
            marker_host = f"sentinel-{token}.example.com"
            payload = target.replace("example.com", marker_host).replace("example.org", marker_host)
            probe = ctx.send_point(point, payload, follow=False)
            examined += 1
            if not probe.ok:
                continue
            location = probe.header("location")
            body = probe.text[:20000]
            if marker_host in location or (
                "<meta" in body.lower() and marker_host in body
            ) or re.search(r"location(?:\.href)?\s*=\s*['\"][^'\"]*" + re.escape(marker_host), body, re.I):
                findings.append(
                    Finding(
                        "Navigation parameter redirects off-site",
                        "medium",
                        "The application accepts an external destination and emits it in a redirect.",
                        f"param={point.param}; target={payload!r}; location={location[:200]!r}",
                        "Allowlist relative paths or trusted hosts and reject absolute external destinations.",
                    )
                )
                break

    status = verdict(findings) if findings else "pass"
    summary = (
        f"{examined} target redirect diuji pada {len(redirect_points[:2])} parameter."
        if not findings
        else f"{len(findings)} parameter menerima tujuan eksternal."
    )
    return Outcome(status, summary, findings)

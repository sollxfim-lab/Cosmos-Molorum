from __future__ import annotations

import difflib
import json
import re
import secrets
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from ..engine import InputPoint, Probe, ScanContext
from ..models import Finding, Outcome
from ..registry import module, verdict

CATEGORY = "Injection & Input"

SQL_ERROR_PATTERNS = [
    (re.compile(r"SQL syntax.*MySQL|Warning.*mysql_|You have an error in your SQL syntax", re.I), "MySQL"),
    (re.compile(r"PostgreSQL.*ERROR|pg_query\(\)|syntax error at or near", re.I), "PostgreSQL"),
    (re.compile(r"Microsoft SQL Server|Unclosed quotation mark after the character string|SqlException", re.I), "MSSQL"),
    (re.compile(r"ORA-\d{4,5}|quoted string not properly terminated", re.I), "Oracle"),
    (re.compile(r"SQLite/JDBCDriver|sqlite3\.OperationalError|SQLite3::query", re.I), "SQLite"),
    (re.compile(r"SQLSTATE\[\w+\]|PDOException|Doctrine\\DBAL", re.I), "PDO/SQLSTATE"),
    (re.compile(r"java\.sql\.SQLException|org\.hibernate", re.I), "JDBC/Hibernate"),
]

NOSQL_ERROR_PATTERNS = [
    re.compile(r"MongoError|MongoServerError|BSONTypeError|E11000 duplicate key", re.I),
    re.compile(r"Cast to ObjectId failed|CastError|Cannot cast", re.I),
    re.compile(r"redis\.exceptions|WRONGTYPE|ERR unknown command", re.I),
]

LDAP_ERROR_PATTERNS = [
    re.compile(r"LDAPException|javax\.naming|Invalid DN|ldap_search|LDAP result code", re.I),
    re.compile(r"Protocol error occurred|Bad search filter|Filter parsing", re.I),
]

WAF_MARKERS = [
    "cloudflare",
    "attention required! | cloudflare",
    "cf-error-details",
    "akamai",
    "incapsula",
    "sucuri",
    "modsecurity",
    "not acceptable!",
    "request blocked",
    "web application firewall",
    "access denied",
    "aws waf",
    "wordfence",
]


def _baseline(ctx: ScanContext, point: InputPoint) -> Probe:
    cache = getattr(ctx, "_baseline_cache", None)
    if cache is None:
        cache = {}
        setattr(ctx, "_baseline_cache", cache)
    key = (point.method, point.url, point.param, point.value)
    if key not in cache:
        cache[key] = ctx.send_point(point, point.value)
    return cache[key]


def _similarity(left: str, right: str) -> float:
    a = re.sub(r"\s+", " ", left[:14_000]).strip().lower()
    b = re.sub(r"\s+", " ", right[:14_000]).strip().lower()
    if not a and not b:
        return 1.0
    if abs(len(a) - len(b)) > max(len(a), len(b)) * 0.75:
        return 0.0
    return difflib.SequenceMatcher(None, a, b, autojunk=False).ratio()


def _blocked(probe: Probe) -> bool:
    if not probe.ok:
        return False
    if probe.status in {403, 406, 429, 503}:
        body = probe.text[:20_000].lower()
        return any(marker in body for marker in WAF_MARKERS) or probe.status == 429
    return False


def _error_signature(
    probe: Probe, patterns: list[re.Pattern[str]] | list[tuple[re.Pattern[str], str]]
) -> str:
    body = probe.text[:200_000]
    for entry in patterns:
        pattern = entry[0] if isinstance(entry, tuple) else entry
        match = pattern.search(body)
        if match:
            return match.group(0)[:180]
    return ""


def _raw_query_variant(
    point: InputPoint, keys: list[tuple[str, str]]
) -> tuple[str, dict[str, str] | None]:
    if point.method == "POST":
        data = dict(point.form or {})
        for key, value in keys:
            data[key] = value
        return point.url, data
    parts = urlsplit(point.url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    pairs.extend(keys)
    return (
        urlunsplit(
            (
                parts.scheme,
                parts.netloc,
                parts.path,
                urlencode(pairs, doseq=True),
                "",
            )
        ),
        None,
    )


def _send_variant(
    ctx: ScanContext, point: InputPoint, keys: list[tuple[str, str]]
) -> Probe:
    url, data = _raw_query_variant(point, keys)
    if point.method == "POST":
        return ctx.fetch("POST", url, data=data)
    return ctx.fetch("GET", url)


@module(
    "reflected_xss",
    "Reflected Cross-Site Scripting",
    CATEGORY,
    "Injects an inert HTML canary into query and form inputs and checks for raw reflection.",
    severity="high",
    passive=False,
)
def reflected_xss(ctx: ScanContext) -> Outcome:
    points = ctx.candidate_points(limit=4)
    if not points:
        return Outcome("skipped", "No safe query or form inputs were discovered.")
    findings: list[Finding] = []
    blocked = 0
    for point in points:
        baseline = _baseline(ctx, point)
        if not baseline.ok:
            continue
        token = secrets.token_hex(5)
        payload = f'"><cmxss-{token}>'
        probe = ctx.send_point(point, payload)
        if _blocked(probe):
            blocked += 1
            continue
        if not probe.ok or probe.status >= 500 or not probe.is_html:
            continue
        if payload in probe.text and payload not in baseline.text:
            findings.append(
                Finding(
                    "Unescaped input reflection",
                    "high",
                    f"The value of '{point.param}' is reflected into HTML without encoding.",
                    f"param={point.param}; method={point.method}; source={point.source}",
                    "Encode output contextually and deploy a restrictive CSP; never rely on blocklists.",
                )
            )
        elif token in probe.text and token not in baseline.text:
            findings.append(
                Finding(
                    "Input is reflected with encoding",
                    "info",
                    f"The value of '{point.param}' is reflected but the HTML canary was encoded.",
                    f"param={point.param}; method={point.method}",
                    "Keep contextual output encoding in place and review DOM sinks.",
                )
            )
    if not findings and blocked and blocked == len(points):
        return Outcome("skipped", "All reflection probes were blocked by an edge control.")
    status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        "No raw reflected XSS canary was observed."
        if not findings
        else "Reflection behavior requires remediation.",
        findings,
    )


@module(
    "dom_xss",
    "DOM XSS Sink Analysis",
    CATEGORY,
    "Statically correlates browser-controlled sources with dangerous DOM sinks in scripts.",
    severity="high",
    passive=True,
)
def dom_xss(ctx: ScanContext) -> Outcome:
    page = ctx.homepage()
    sources = re.compile(
        r"(location\.(?:search|hash|href)|document\.(?:URL|documentURI|referrer)|"
        r"window\.name|event\.data|postMessage)",
        re.I,
    )
    sinks = re.compile(
        r"(innerHTML|outerHTML|document\.write|insertAdjacentHTML|"
        r"dangerouslySetInnerHTML|eval\s*\(|new\s+Function|setTimeout\s*\(|"
        r"setInterval\s*\()",
        re.I,
    )
    chunks: list[tuple[str, str]] = [("inline script", code) for code in page.inline_scripts]
    for script in page.scripts:
        if not ctx.same_host(script):
            continue
        probe = ctx.get(script, max_bytes=800_000)
        if probe.ok and probe.status == 200:
            chunks.append((urlsplit(script).path or script, probe.text[:800_000]))
        if len(chunks) >= 7:
            break
    findings: list[Finding] = []
    for label, code in chunks:
        if not code:
            continue
        source_match = sources.search(code)
        sink_match = sinks.search(code)
        if not source_match or not sink_match:
            continue
        window = code[
            max(0, min(source_match.start(), sink_match.start()) - 120) :
            min(len(code), max(source_match.end(), sink_match.end()) + 180)
        ]
        findings.append(
            Finding(
                "Controlled source reaches a DOM sink",
                "medium",
                f"{label} reads browser-controlled data and writes it through a dangerous sink.",
                re.sub(r"\s+", " ", window)[:320],
                "Use textContent or a sanitizer, and validate every postMessage origin.",
            )
        )
        if len(findings) >= 4:
            break
    status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        "No source-to-sink DOM pattern was identified."
        if not findings
        else "Static analysis found DOM XSS candidates; manual confirmation is advised.",
        findings,
    )


@module(
    "xss_attribute",
    "Attribute-Context Cross-Site Scripting",
    CATEGORY,
    "Injects quote breakouts into inputs and checks whether a canary attribute lands inside an HTML tag.",
    severity="high",
    passive=False,
)
def xss_attribute(ctx: ScanContext) -> Outcome:
    points = ctx.candidate_points(limit=6)
    if not points:
        return Outcome("skipped", "No safe query or form inputs were discovered.")
    findings: list[Finding] = []
    blocked = 0
    for point in points:
        baseline = _baseline(ctx, point)
        if not baseline.ok:
            continue
        token = "cmattr" + secrets.token_hex(4)
        probes = (
            ("double-quoted attribute", f'cmx" data-cmxss="{token}" autofocus onfocus="1'),
            ("single-quoted attribute", f"cmx' data-cmxss='{token}' autofocus onfocus='1"),
            ("unquoted attribute", f"cmx data-cmxss={token} autofocus onfocus=1"),
        )
        attribute_pattern = re.compile(
            r"<[a-zA-Z][^<>]*\bdata-cmxss\s*=\s*(?:\"[^\"]*"
            + re.escape(token)
            + r"|'[^']*"
            + re.escape(token)
            + r"|"
            + re.escape(token)
            + r")",
            re.I,
        )
        for label, payload in probes:
            probe = ctx.send_point(point, payload)
            if _blocked(probe):
                blocked += 1
                continue
            if not probe.ok or not probe.is_html or probe.status >= 500:
                continue
            if token in baseline.text:
                continue
            if attribute_pattern.search(probe.text):
                findings.append(
                    Finding(
                        "Attribute-context XSS injection",
                        "high",
                        f"The '{point.param}' input escapes its attribute context and injects a new attribute.",
                        f"param={point.param}; context={label}; method={point.method}",
                        "Encode quotes and attribute values contextually; use a template engine with auto-escaping.",
                    )
                )
                break
    if not findings and blocked and blocked == len(points) * 3:
        return Outcome("skipped", "All attribute probes were blocked by an edge control.")
    status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        "No attribute-context injection was observed."
        if not findings
        else "Attribute-context injection requires remediation.",
        findings,
    )


@module(
    "xss_header",
    "Header-Reflected Cross-Site Scripting",
    CATEGORY,
    "Places an inert HTML canary in request headers and checks whether error or echo pages reflect it raw.",
    severity="high",
    passive=False,
)
def xss_header(ctx: ScanContext) -> Outcome:
    baseline = ctx.get(ctx.target)
    if not baseline.ok:
        return Outcome("skipped", "The landing page did not respond.")
    token = secrets.token_hex(5)
    tag = f"<cmxss-hdr-{token}>"
    payload = f'"><cmxss-hdr-{token}>'
    probes = (
        ("User-Agent", {"User-Agent": payload}),
        ("Referer", {"Referer": ctx.origin + "/" + payload}),
        ("X-Forwarded-For", {"X-Forwarded-For": payload}),
    )
    findings: list[Finding] = []
    blocked = 0
    for label, headers in probes:
        probe = ctx.fetch("GET", ctx.target, headers=headers)
        if _blocked(probe):
            blocked += 1
            continue
        if not probe.ok or not probe.is_html:
            continue
        if tag in probe.text and tag not in baseline.text:
            findings.append(
                Finding(
                    "Header value is reflected into HTML",
                    "high",
                    f"The {label} header is echoed into the page without HTML encoding.",
                    f"header={label}; canary={tag}",
                    "Never render request headers into HTML; encode all output and use a strict CSP.",
                )
            )
    if not findings and blocked == len(probes):
        return Outcome("skipped", "All header reflection probes were blocked.")
    status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        "No header reflection was observed."
        if not findings
        else "Header reflection requires remediation.",
        findings,
    )


def _inside_script(text: str, marker: str) -> bool:
    index = text.find(marker)
    if index < 0:
        return False
    before = text[:index].lower()
    return before.rfind("<script") > before.rfind("</script")


@module(
    "xss_json",
    "JSONP & Script-Context XSS",
    CATEGORY,
    "Tests JSONP callbacks and script-context breakout payloads for executable reflection.",
    severity="high",
    passive=False,
)
def xss_json(ctx: ScanContext) -> Outcome:
    points = ctx.candidate_points(limit=6)
    if not points:
        return Outcome("skipped", "No safe query or form inputs were discovered.")
    callback_re = re.compile(r"(callback|jsonp|json_callback|cb)", re.I)
    findings: list[Finding] = []
    blocked = 0
    for point in points:
        baseline = _baseline(ctx, point)
        if not baseline.ok:
            continue
        if callback_re.search(point.param):
            identifier = "cmjsonp" + secrets.token_hex(4)
            probe = ctx.send_point(point, identifier)
            if _blocked(probe):
                blocked += 1
                continue
            if probe.ok and identifier in probe.text:
                head = probe.text.lstrip()[:600]
                if re.match(r"^" + re.escape(identifier) + r"\s*\(", head) or (
                    "javascript" in probe.content_type and identifier in head
                ):
                    findings.append(
                        Finding(
                            "JSONP callback is attacker-controlled",
                            "medium",
                            f"The '{point.param}' parameter is emitted as an executable callback name.",
                            f"param={point.param}; callback={identifier}",
                            "Avoid JSONP; use CORS with an explicit origin allowlist and JSON responses.",
                        )
                    )
                    continue
        token = secrets.token_hex(4)
        breakout = f"</script><cmjs-{token}>"
        probe = ctx.send_point(point, f'x"</script><cmjs-{token}>')
        if _blocked(probe):
            blocked += 1
            continue
        if (
            probe.ok
            and probe.is_html
            and breakout in probe.text
            and breakout not in baseline.text
            and _inside_script(probe.text, breakout)
        ):
            findings.append(
                Finding(
                    "Script-context breakout in HTML",
                    "high",
                    f"The '{point.param}' input can close a script block and inject markup.",
                    f"param={point.param}; canary=<cmjs-{token}>",
                    "Encode values for the script context and serve scripts with a nonce-based CSP.",
                )
            )
    if not findings and blocked and blocked == len(points):
        return Outcome("skipped", "All JSON and script-context probes were blocked.")
    status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        "No JSONP or script-context injection was observed."
        if not findings
        else "Script-context reflection requires remediation.",
        findings,
    )


@module(
    "sql_injection",
    "SQL Injection",
    CATEGORY,
    "Runs error-based and boolean differential probes against discovered input points.",
    severity="critical",
    passive=False,
)
def sql_injection(ctx: ScanContext) -> Outcome:
    points = ctx.candidate_points(limit=3)
    if not points:
        return Outcome("skipped", "No safe query or form inputs were discovered.")
    findings: list[Finding] = []
    blocked = 0
    for point in points:
        baseline = _baseline(ctx, point)
        if not baseline.ok:
            continue
        error_hit = ""
        error_payload = ""
        for payload in ("'", '"', "')", "'-- "):
            probe = ctx.send_point(point, payload)
            if _blocked(probe):
                blocked += 1
                continue
            signature = _error_signature(probe, SQL_ERROR_PATTERNS)
            if signature:
                error_hit = signature
                error_payload = payload
                break
        if error_hit:
            findings.append(
                Finding(
                    "Error-based SQL injection signal",
                    "critical",
                    f"The '{point.param}' input triggered a database error signature.",
                    f"param={point.param}; payload={error_payload!r}; signature={error_hit}",
                    "Use parameterized queries, remove database errors from responses, and review the endpoint.",
                )
            )
            continue
        true_probe = ctx.send_point(point, "' OR '1'='1")
        false_probe = ctx.send_point(point, "' OR '1'='2")
        if _blocked(true_probe) or _blocked(false_probe):
            blocked += 2
            continue
        if (
            baseline.ok
            and true_probe.ok
            and false_probe.ok
            and true_probe.status == false_probe.status
            and _similarity(true_probe.text, false_probe.text) < 0.82
            and _similarity(baseline.text, true_probe.text) > 0.55
        ):
            findings.append(
                Finding(
                    "Boolean-based SQL injection signal",
                    "high",
                    f"Contradictory boolean payloads produced materially different responses for '{point.param}'.",
                    f"param={point.param}; method={point.method}; true_vs_false_similarity="
                    f"{_similarity(true_probe.text, false_probe.text):.2f}",
                    "Use parameterized queries and verify server-side input validation.",
                )
            )
    if not findings and blocked and blocked >= len(points) * 2:
        return Outcome("skipped", "SQL probes were blocked by an edge control.")
    status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        "No SQL injection signal was observed."
        if not findings
        else "SQL injection behavior was detected.",
        findings,
    )


@module(
    "sql_boolean",
    "Boolean Blind SQL Injection",
    CATEGORY,
    "Compares multiple true/false predicate pairs to confirm blind boolean inference.",
    severity="critical",
    passive=False,
)
def sql_boolean(ctx: ScanContext) -> Outcome:
    points = ctx.candidate_points(limit=3)
    if not points:
        return Outcome("skipped", "No safe query or form inputs were discovered.")
    families = (
        ("quoted string", "' AND '1'='1", "' AND '1'='2"),
        ("numeric", "1 AND 1=1", "1 AND 1=2"),
        ("parenthesized", "') AND ('1'='1", "') AND ('1'='2"),
    )
    findings: list[Finding] = []
    blocked = 0
    for point in points:
        baseline = _baseline(ctx, point)
        if not baseline.ok:
            continue
        confirmations: list[tuple[str, float, float]] = []
        for label, true_payload, false_payload in families:
            true_probe = ctx.send_point(point, true_payload)
            false_probe = ctx.send_point(point, false_payload)
            if _blocked(true_probe) or _blocked(false_probe):
                blocked += 2
                continue
            if not (true_probe.ok and false_probe.ok):
                continue
            if true_probe.status != false_probe.status or true_probe.status >= 500:
                continue
            pair_similarity = _similarity(true_probe.text, false_probe.text)
            baseline_similarity = _similarity(baseline.text, true_probe.text)
            if pair_similarity < 0.82 and baseline_similarity > 0.62:
                confirmations.append((label, pair_similarity, baseline_similarity))
        if confirmations:
            severity = "critical" if len(confirmations) >= 2 else "high"
            labels = ", ".join(item[0] for item in confirmations)
            best = min(confirmations, key=lambda item: item[1])
            findings.append(
                Finding(
                    "Boolean blind SQL injection confirmed",
                    severity,
                    f"{len(confirmations)} true/false predicate pair(s) produced a stable response difference for '{point.param}'.",
                    f"param={point.param}; method={point.method}; families={labels}; "
                    f"true_vs_false={best[1]:.2f}; baseline_vs_true={best[2]:.2f}",
                    "Use parameterized queries for every SQL statement and remove input concatenation.",
                )
            )
    if not findings and blocked and blocked >= len(points) * 4:
        return Outcome("skipped", "Boolean SQL probes were blocked by an edge control.")
    status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        "No boolean blind SQL injection signal was observed."
        if not findings
        else "Boolean inference is possible.",
        findings,
    )


@module(
    "sql_union",
    "UNION-Based SQL Injection",
    CATEGORY,
    "Attempts marker-based UNION SELECT injections and compares against a neutralized control.",
    severity="critical",
    passive=False,
)
def sql_union(ctx: ScanContext) -> Outcome:
    points = ctx.candidate_points(limit=3)
    if not points:
        return Outcome("skipped", "No safe query or form inputs were discovered.")
    findings: list[Finding] = []
    blocked = 0
    for point in points:
        baseline = _baseline(ctx, point)
        if not baseline.ok:
            continue
        token = "cmunion" + secrets.token_hex(5)
        families = (
            ("quoted string", f"' UNION SELECT '{token}'-- -", f"' UNI0N SELECT '{token}'-- -"),
            ("numeric", f"1 UNION SELECT '{token}'-- -", f"1 UNI0N SELECT '{token}'-- -"),
        )
        for label, payload, control in families:
            probe = ctx.send_point(point, payload)
            if _blocked(probe):
                blocked += 1
                continue
            if not probe.ok or token not in probe.text or token in baseline.text:
                continue
            # A raw or encoded echo of the payload still contains the SQL
            # keywords. Extracted data appears without the UNION statement.
            if re.search(r"union\s+select", probe.text, re.I):
                continue
            control_probe = ctx.send_point(point, control)
            if _blocked(control_probe):
                blocked += 1
                continue
            if token in control_probe.text:
                continue
            findings.append(
                Finding(
                    "UNION-based SQL injection signal",
                    "critical",
                    f"A UNION SELECT payload returned an injected marker through '{point.param}'.",
                    f"param={point.param}; method={point.method}; family={label}; marker={token}",
                    "Use parameterized queries and ensure database errors and query text never reach clients.",
                )
            )
            break
    if not findings and blocked and blocked >= len(points) * 2:
        return Outcome("skipped", "UNION SQL probes were blocked by an edge control.")
    status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        "No UNION-based SQL injection signal was observed."
        if not findings
        else "UNION-based extraction is possible.",
        findings,
    )


@module(
    "sql_time",
    "Time-Based Blind SQL Injection",
    CATEGORY,
    "Measures response delays from vendor-specific sleep payloads with a confirmation run.",
    severity="critical",
    passive=False,
)
def sql_time(ctx: ScanContext) -> Outcome:
    points = ctx.candidate_points(limit=2)
    if not points:
        return Outcome("skipped", "No safe query or form inputs were discovered.")
    families = (
        ("MySQL SLEEP", "' AND SLEEP(2)-- -"),
        ("PostgreSQL pg_sleep", "'; SELECT pg_sleep(2)-- -"),
        ("MSSQL WAITFOR", "'; WAITFOR DELAY '0:0:2'-- -"),
        ("Oracle DBMS_PIPE", "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('CM',2)-- -"),
    )
    findings: list[Finding] = []
    blocked = 0
    slow_baseline = False
    for point in points:
        baseline = _baseline(ctx, point)
        if not baseline.ok:
            continue
        if baseline.elapsed_ms > 4000:
            slow_baseline = True
            continue
        for label, payload in families:
            probe = ctx.send_point(point, payload)
            if _blocked(probe):
                blocked += 1
                continue
            if not probe.ok or probe.status >= 500:
                continue
            delta = probe.elapsed_ms - baseline.elapsed_ms
            if delta < 1400:
                continue
            confirm = ctx.send_point(point, payload)
            if _blocked(confirm):
                blocked += 1
                continue
            confirm_delta = confirm.elapsed_ms - baseline.elapsed_ms
            if confirm.ok and confirm_delta >= 1200:
                findings.append(
                    Finding(
                        "Time-based blind SQL injection confirmed",
                        "critical",
                        f"The '{point.param}' input delayed the response twice using a {label} payload.",
                        f"param={point.param}; method={point.method}; baseline={baseline.elapsed_ms}ms; "
                        f"observed={probe.elapsed_ms}ms/{confirm.elapsed_ms}ms",
                        "Use parameterized queries, enforce statement timeouts, and monitor unusual query latency.",
                    )
                )
                break
    if not findings and slow_baseline:
        return Outcome(
            "skipped",
            "Baseline response time was too high for reliable time-based inference.",
        )
    if not findings and blocked and blocked >= len(points) * 2:
        return Outcome("skipped", "Time-based SQL probes were blocked by an edge control.")
    status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        "No time-based SQL injection delay was observed."
        if not findings
        else "Time-based inference is possible.",
        findings,
    )


@module(
    "sql_header",
    "SQL Injection via HTTP Headers",
    CATEGORY,
    "Injects quote canaries into common request headers and watches for database error signatures.",
    severity="critical",
    passive=False,
)
def sql_header(ctx: ScanContext) -> Outcome:
    baseline = ctx.get(ctx.target)
    if not baseline.ok:
        return Outcome("skipped", "The landing page did not respond.")
    headers = ("User-Agent", "Referer", "X-Forwarded-For")
    payloads = ("'", '"', "')")
    findings: list[Finding] = []
    blocked = 0
    for header in headers:
        for payload in payloads:
            probe = ctx.fetch("GET", ctx.target, headers={header: payload})
            if _blocked(probe):
                blocked += 1
                continue
            if not probe.ok:
                continue
            signature = _error_signature(probe, SQL_ERROR_PATTERNS)
            if signature and signature not in baseline.text:
                findings.append(
                    Finding(
                        f"SQL injection through {header}",
                        "critical",
                        f"A quote in the {header} header produced a database error signature.",
                        f"header={header}; payload={payload!r}; signature={signature}",
                        "Sanitize or avoid SQL built from request metadata; use parameterized queries everywhere.",
                    )
                )
                break
    if not findings and blocked == len(headers) * len(payloads):
        return Outcome("skipped", "Header SQL probes were blocked by an edge control.")
    status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        "No SQL error was triggered through request headers."
        if not findings
        else "Header-driven SQL injection is possible.",
        findings,
    )


@module(
    "sql_evasion",
    "SQL Filter & WAF Evasion",
    CATEGORY,
    "Uses case, comment and parenthesis obfuscation to test whether naive SQL filters are bypassable.",
    severity="high",
    passive=False,
)
def sql_evasion(ctx: ScanContext) -> Outcome:
    points = ctx.candidate_points(limit=2)
    if not points:
        return Outcome("skipped", "No safe query or form inputs were discovered.")
    families = (
        ("case obfuscation", "' oR '1'='1", "' oR '1'='2"),
        ("inline comments", "'/**/OR/**/'1'='1", "'/**/OR/**/'1'='2"),
        ("parenthesis mix", "') oR ('1'='1", "') oR ('1'='2"),
    )
    findings: list[Finding] = []
    blocked = 0
    for point in points:
        baseline = _baseline(ctx, point)
        if not baseline.ok:
            continue
        for label, true_payload, false_payload in families:
            true_probe = ctx.send_point(point, true_payload)
            false_probe = ctx.send_point(point, false_payload)
            if _blocked(true_probe) or _blocked(false_probe):
                blocked += 2
                continue
            if not (true_probe.ok and false_probe.ok):
                continue
            if true_probe.status != false_probe.status or true_probe.status >= 500:
                continue
            pair_similarity = _similarity(true_probe.text, false_probe.text)
            baseline_similarity = _similarity(baseline.text, true_probe.text)
            if pair_similarity < 0.82 and baseline_similarity > 0.62:
                findings.append(
                    Finding(
                        "Obfuscated SQL predicate bypassed input filtering",
                        "high",
                        f"Case, comment or parenthesis obfuscation preserved boolean inference on '{point.param}'.",
                        f"param={point.param}; method={point.method}; family={label}; "
                        f"true_vs_false={pair_similarity:.2f}; baseline_vs_true={baseline_similarity:.2f}",
                        "Do not rely on keyword blocklists; use parameterized queries and normalize input at the application layer.",
                    )
                )
                break
    if not findings and blocked and blocked >= len(points) * 4:
        return Outcome("skipped", "Obfuscated SQL probes were blocked by an edge control.")
    status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        "No filter-evasion SQL signal was observed."
        if not findings
        else "Naive SQL filtering can be bypassed.",
        findings,
    )


@module(
    "nosql_injection",
    "NoSQL Operator Injection",
    CATEGORY,
    "Tests query-string and form inputs for MongoDB-style operator injection errors.",
    severity="high",
    passive=False,
)
def nosql_injection(ctx: ScanContext) -> Outcome:
    points = ctx.candidate_points(limit=3)
    if not points:
        return Outcome("skipped", "No safe query or form inputs were discovered.")
    findings: list[Finding] = []
    for point in points:
        baseline = _baseline(ctx, point)
        if not baseline.ok:
            continue
        error_hit = ""
        variant = ""
        for suffix, value in (
            ("[$ne]", "cm-noop"),
            ("[$gt]", ""),
            ("[$regex]", ".*"),
        ):
            probe = _send_variant(ctx, point, [(point.param + suffix, value)])
            signature = _error_signature(probe, NOSQL_ERROR_PATTERNS)
            if signature:
                error_hit = signature
                variant = point.param + suffix
                break
        if error_hit:
            findings.append(
                Finding(
                    "NoSQL operator injection signal",
                    "high",
                    f"The '{point.param}' input accepted an operator object.",
                    f"param={point.param}; operator={variant}; signature={error_hit}",
                    "Reject object-shaped input, cast parameters to scalar types, and use an ODM allowlist.",
                )
            )
            continue
        operator_probe = _send_variant(ctx, point, [(point.param + "[$ne]", "cm-noop")])
        if (
            operator_probe.ok
            and baseline.ok
            and operator_probe.status == baseline.status
            and _similarity(baseline.text, operator_probe.text) < 0.7
        ):
            findings.append(
                Finding(
                    "NoSQL operator changes response",
                    "medium",
                    f"An operator-shaped parameter altered the response for '{point.param}'.",
                    f"param={point.param}; similarity={_similarity(baseline.text, operator_probe.text):.2f}",
                    "Confirm server-side type enforcement and reject unexpected query operators.",
                )
            )
    status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        "No NoSQL operator injection signal was observed."
        if not findings
        else "NoSQL injection behavior requires review.",
        findings,
    )


@module(
    "ldap_injection",
    "LDAP Injection",
    CATEGORY,
    "Sends filter metacharacter probes and looks for LDAP error signatures.",
    severity="medium",
    passive=False,
)
def ldap_injection(ctx: ScanContext) -> Outcome:
    points = ctx.candidate_points(limit=3)
    if not points:
        return Outcome("skipped", "No safe query or form inputs were discovered.")
    findings: list[Finding] = []
    for point in points:
        hit = ""
        payload = ""
        for candidate in ("*)(uid=*))(|(uid=*", "*)(objectClass=*)", ")(|(password=*)"):
            probe = ctx.send_point(point, candidate)
            signature = _error_signature(probe, LDAP_ERROR_PATTERNS)
            if signature:
                hit = signature
                payload = candidate
                break
        if hit:
            findings.append(
                Finding(
                    "LDAP filter injection signal",
                    "medium",
                    f"The '{point.param}' input reached an LDAP parser with filter metacharacters.",
                    f"param={point.param}; payload={payload!r}; signature={hit}",
                    "Escape LDAP filter metacharacters and validate input against a strict allowlist.",
                )
            )
    status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        "No LDAP injection error signature was observed."
        if not findings
        else "LDAP filter handling requires review.",
        findings,
    )


@module(
    "ssti",
    "Server-Side Template Injection",
    CATEGORY,
    "Uses a distinctive arithmetic expression to detect template expression evaluation.",
    severity="high",
    passive=False,
)
def ssti(ctx: ScanContext) -> Outcome:
    points = ctx.candidate_points(limit=3)
    if not points:
        return Outcome("skipped", "No safe query or form inputs were discovered.")
    expected = "62710561"
    findings: list[Finding] = []
    for point in points:
        baseline = _baseline(ctx, point)
        if not baseline.ok or expected in baseline.text:
            continue
        hit_payload = ""
        for payload in (
            "{{7919*7919}}",
            "${7919*7919}",
            "<%= 7919*7919 %>",
            "#{7919*7919}",
        ):
            probe = ctx.send_point(point, payload)
            if probe.ok and expected in probe.text and expected not in baseline.text:
                hit_payload = payload
                break
        if hit_payload:
            findings.append(
                Finding(
                    "Template expression was evaluated",
                    "high",
                    f"The '{point.param}' input was evaluated by a server-side template engine.",
                    f"param={point.param}; payload={hit_payload}",
                    "Do not build templates from user input; use strict data binding and sandboxing.",
                )
            )
    status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        "No template expression evaluation was observed."
        if not findings
        else "Server-side template injection was detected.",
        findings,
    )


@module(
    "xxe",
    "XML External Entity Handling",
    CATEGORY,
    "Checks XML-capable forms for unsafe internal entity expansion.",
    severity="high",
    passive=False,
)
def xxe(ctx: ScanContext) -> Outcome:
    page = ctx.homepage()
    targets = []
    for form in page.forms:
        action = str(form.get("action") or "")
        enctype = str(form.get("enctype") or "").lower()
        if not action or not ctx.same_host(action):
            continue
        if "xml" in enctype or "xml" in action.lower() or "soap" in action.lower():
            targets.append(action)
    if not targets and page.headers.get("content-type", "").lower().startswith("application/xml"):
        targets.append(page.url)
    if not targets:
        return Outcome("skipped", "No XML form or XML endpoint was discovered.")
    findings: list[Finding] = []
    for action in targets[:2]:
        token = "CMXXE" + secrets.token_hex(4)
        payload = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            f'<!DOCTYPE cm [<!ENTITY cmx "{token}">]>'
            "<cm><name>&cmx;</name></cm>"
        ).encode()
        probe = ctx.fetch(
            "POST",
            action,
            content=payload,
            headers={"Content-Type": "application/xml", "Accept": "application/xml,text/xml,*/*"},
        )
        if probe.ok and token in probe.text:
            findings.append(
                Finding(
                    "XML entity expansion is enabled",
                    "medium",
                    "A defined internal entity was expanded in the XML response.",
                    f"endpoint={urlsplit(action).path}; status={probe.status}",
                    "Disable DTDs and external entities in the XML parser; prefer JSON.",
                )
            )
    status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        "No XML entity expansion was observed."
        if not findings
        else "XML parser configuration requires review.",
        findings,
    )


@module(
    "open_redirect",
    "Open Redirect",
    CATEGORY,
    "Tests redirect-like parameters with an inert external destination.",
    severity="medium",
    passive=False,
)
def open_redirect(ctx: ScanContext) -> Outcome:
    points = ctx.candidate_points(limit=4)
    redirect_names = re.compile(
        r"(redirect|next|return|url|continue|dest|target|goto|forward|callback|back)",
        re.I,
    )
    candidates = [point for point in points if redirect_names.search(point.param)]
    if not candidates:
        candidates = points[:2]
    if not candidates:
        return Outcome("skipped", "No redirect-like parameter was discovered.")
    findings: list[Finding] = []
    for point in candidates:
        token = secrets.token_hex(4)
        for payload in (
            f"https://example.com/cm-redirect-{token}",
            f"//example.com/cm-redirect-{token}",
        ):
            probe = ctx.send_point(point, payload, follow=False)
            if not probe.ok:
                continue
            location = probe.header("location")
            if probe.status in {301, 302, 303, 307, 308} and (
                location.startswith(payload)
                or "example.com/cm-redirect-" in location
            ):
                findings.append(
                    Finding(
                        "External redirect is accepted",
                        "medium",
                        f"The '{point.param}' parameter controls a redirect to an external host.",
                        f"param={point.param}; status={probe.status}; location={location[:180]}",
                        "Allowlist destination paths and reject absolute and scheme-relative URLs.",
                    )
                )
                break
    status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        "No open redirect behavior was observed."
        if not findings
        else "An open redirect was detected.",
        findings,
    )


@module(
    "crlf_injection",
    "CRLF & Header Injection",
    CATEGORY,
    "Injects encoded line breaks into inputs and checks for response-header injection.",
    severity="high",
    passive=False,
)
def crlf_injection(ctx: ScanContext) -> Outcome:
    points = ctx.candidate_points(limit=3)
    if not points:
        return Outcome("skipped", "No safe query or form inputs were discovered.")
    findings: list[Finding] = []
    for point in points:
        token = secrets.token_hex(5)
        for payload in (
            f"\r\nX-CM-Canary: {token}",
            f"\nX-CM-Canary: {token}",
        ):
            probe = ctx.send_point(point, payload)
            if not probe.ok:
                continue
            if probe.header("x-cm-canary") == token:
                findings.append(
                    Finding(
                        "CRLF sequence reached the response",
                        "high",
                        f"The '{point.param}' input can inject line breaks into a response header.",
                        f"param={point.param}; header=x-cm-canary",
                        "Reject CR/LF characters at the edge and never interpolate input into headers.",
                    )
                )
                break
    status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        "No CRLF response injection was observed."
        if not findings
        else "Header injection is possible.",
        findings,
    )


@module(
    "host_header_injection",
    "Host Header Injection",
    CATEGORY,
    "Sends forwarded-host canaries and checks whether absolute URLs trust them.",
    severity="medium",
    passive=False,
)
def host_header_injection(ctx: ScanContext) -> Outcome:
    token = secrets.token_hex(5)
    canary = f"cm-{token}.example"
    probes = [
        ("X-Forwarded-Host", ctx.fetch("GET", ctx.target, headers={"X-Forwarded-Host": canary})),
        ("X-Forwarded-Server", ctx.fetch("GET", ctx.target, headers={"X-Forwarded-Server": canary})),
        ("Forwarded", ctx.fetch("GET", ctx.target, headers={"Forwarded": f"host={canary}"})),
    ]
    findings: list[Finding] = []
    for label, probe in probes:
        if not probe.ok:
            continue
        if canary in probe.text or canary in probe.header("location"):
            findings.append(
                Finding(
                    "Forwarded host is reflected",
                    "medium",
                    f"The {label} header influences generated absolute URLs or redirects.",
                    f"header={label}; canary={canary}",
                    "Use a configured canonical host allowlist and ignore untrusted forwarding headers.",
                )
            )
            break
    status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        "No host-header reflection was observed."
        if not findings
        else "Forwarded host handling requires review.",
        findings,
    )


@module(
    "path_traversal",
    "Path Traversal & LFI",
    CATEGORY,
    "Probes input points with traversal sequences and checks for local file disclosure.",
    severity="critical",
    passive=False,
)
def path_traversal(ctx: ScanContext) -> Outcome:
    points = ctx.candidate_points(limit=2)
    findings: list[Finding] = []
    patterns = [
        ("Linux passwd", re.compile(r"root:x:0:0:")),
        ("Windows win.ini", re.compile(r"\[(?:fonts|extensions|mci extensions)\]", re.I)),
    ]
    for point in points:
        for payload in ("../../../../etc/passwd", "..\\..\\..\\..\\windows\\win.ini"):
            probe = ctx.send_point(point, payload)
            if not probe.ok or probe.status != 200:
                continue
            for label, pattern in patterns:
                if pattern.search(probe.text[:250_000]):
                    findings.append(
                        Finding(
                            "Local file disclosure via traversal",
                            "critical",
                            f"The '{point.param}' input returned {label} content.",
                            f"param={point.param}; method={point.method}; signature={label}",
                            "Canonicalize paths against an allowlisted root and reject traversal sequences.",
                        )
                    )
                    break
            if findings:
                break
        if findings:
            break
    if not findings:
        probe = ctx.get("/%2e%2e/%2e%2e/%2e%2e/etc/passwd")
        if probe.ok and probe.status == 200 and patterns[0][1].search(probe.text[:250_000]):
            findings.append(
                Finding(
                    "Path traversal in the URL path",
                    "critical",
                    "The web server returned a local passwd file through an encoded traversal path.",
                    "path=/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
                    "Normalize and authorize every requested path; reject encoded traversal sequences.",
                )
            )
    status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        "No local file disclosure was observed."
        if not findings
        else "Path traversal exposes local files.",
        findings,
    )


@module(
    "hpp",
    "HTTP Parameter Pollution",
    CATEGORY,
    "Checks how duplicate parameters are merged and whether the response becomes ambiguous.",
    severity="medium",
    passive=False,
)
def hpp(ctx: ScanContext) -> Outcome:
    points = ctx.candidate_points(limit=3)
    if not points:
        return Outcome("skipped", "No safe query or form inputs were discovered.")
    findings: list[Finding] = []
    for point in points:
        token = secrets.token_hex(3)
        single = "cmhpp" + token + "a"
        baseline = ctx.send_point(point, single)
        if not baseline.ok:
            continue
        if point.method == "POST":
            data = dict(point.form or {})
            data[point.param] = single
            pairs = list(data.items()) + [(point.param, "cmhpp" + token + "b")]
            from urllib.parse import urlencode as _urlencode

            probe = ctx.fetch("POST", point.url, content=_urlencode(pairs).encode(), headers={"Content-Type": "application/x-www-form-urlencoded"})
        else:
            url, _ = _raw_query_variant(point, [(point.param, "cmhpp" + token + "b")])
            probe = ctx.fetch("GET", url)
        if not probe.ok or probe.status != baseline.status:
            continue
        similarity = _similarity(baseline.text, probe.text)
        if similarity < 0.96:
            findings.append(
                Finding(
                    "Duplicate parameter changes the response",
                    "low",
                    f"Supplying '{point.param}' twice produced a materially different response.",
                    f"param={point.param}; similarity={similarity:.2f}",
                    "Choose one canonical parameter source and reject duplicates at the edge.",
                )
            )
    status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        "Duplicate parameter handling is consistent."
        if not findings
        else "Duplicate parameter handling is ambiguous.",
        findings,
    )


@module(
    "waf_detection",
    "WAF & Edge Defense Detection",
    "Edge & Defense",
    "Identifies edge protections and observes whether a benign injection probe is challenged.",
    severity="low",
    passive=False,
)
def waf_detection(ctx: ScanContext) -> Outcome:
    page = ctx.homepage()
    headers = page.headers
    cookies = " ".join(headers.get_list("set-cookie")) if headers else ""
    haystack = " ".join(
        [
            headers.get("server", ""),
            headers.get("via", ""),
            headers.get("x-sucuri-id", ""),
            headers.get("cf-ray", ""),
            headers.get("x-akamai-transformed", ""),
            headers.get("x-amzn-waf", ""),
            headers.get("x-fastly-request-id", ""),
            cookies,
            page.html[:120_000],
        ]
    ).lower()
    signals = {
        "Cloudflare": ["cf-ray", "__cf_bm", "cloudflare"],
        "Akamai": ["akamai", "ak_bmsc", "x-akamai"],
        "Imperva": ["incap_ses", "visid_incap", "imperva"],
        "Sucuri": ["x-sucuri-id", "sucuri"],
        "AWS WAF": ["x-amzn-waf", "aws waf"],
        "Fastly": ["fastly", "x-fastly"],
        "F5 BIG-IP": ["bigip", "tscookie"],
        "ModSecurity": ["mod_security", "modsecurity"],
        "Wordfence": ["wordfence"],
    }
    detected = [name for name, markers in signals.items() if any(m in haystack for m in markers)]
    findings: list[Finding] = []
    if detected:
        findings.append(
            Finding(
                "Edge protection detected",
                "info",
                "The response contains fingerprints associated with a web application firewall or CDN.",
                ", ".join(detected),
                "Keep the WAF ruleset current and test it against the application's real traffic.",
            )
        )
    token = secrets.token_hex(4)
    probe = ctx.get(f"/?cm_waf={token}%27")
    challenged = probe.ok and probe.status in {403, 406, 429}
    if challenged:
        body = probe.text[:30_000].lower()
        challenged = any(marker in body for marker in WAF_MARKERS)
    if challenged:
        findings.append(
            Finding(
                "Benign injection probe was challenged",
                "info",
                "A malformed value was blocked by an edge control before reaching the application.",
                f"status={probe.status}",
                "Confirm the WAF is tuned and does not block legitimate application input.",
            )
        )
    status = "info" if findings else "pass"
    return Outcome(
        status,
        "No WAF or edge fingerprint was detected."
        if not findings
        else "Edge protection is present.",
        findings,
    )

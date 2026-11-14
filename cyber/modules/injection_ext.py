"""Extended injection and input-handling probes.

Every payload is non-destructive: markers are reflected back or compared with a
baseline response. No exploit is executed and no data is modified.
"""

from __future__ import annotations

import re
import secrets
from urllib.parse import urlsplit

from ..engine import InputPoint, Probe, ScanContext
from ..models import Finding, Outcome
from ..registry import module, verdict

CATEGORY = "Injection & Input"

SQL_ERROR_PATTERNS = (
    r"SQL syntax.*MySQL",
    r"Warning.*mysql_",
    r"You have an error in your SQL syntax",
    r"PostgreSQL.*ERROR",
    r"pg_query\(\)",
    r"syntax error at or near",
    r"Microsoft SQL Server",
    r"Unclosed quotation mark",
    r"SqlException",
    r"ORA-\d{4,5}",
    r"SQLite/JDBCDriver",
    r"sqlite3\.OperationalError",
    r"PDOException",
    r"SQLSTATE\[",
    r"java\.sql\.SQLException",
    r"org\.hibernate",
)
NOSQL_ERROR_PATTERNS = (
    r"MongoError",
    r"MongoServerError",
    r"BSONTypeError",
    r"Cast to ObjectId failed",
    r"unknown operator",
    r"neo4j",
    r"CouchDB",
    r"Invalid JSON",
)
LDAP_ERROR_PATTERNS = (
    r"LDAP",
    r"javax\.naming",
    r"Invalid DN syntax",
    r"protocol error",
    r"ldap_search",
    r"Directory returned an error",
)
XPATH_ERROR_PATTERNS = (
    r"XPath",
    r"XPathException",
    r"Invalid expression",
    r"xmldom",
    r"DOMXPath",
    r"SimpleXMLElement",
)


def _match(text: str, patterns: tuple[str, ...]) -> str:
    for pattern in patterns:
        match = re.search(pattern, text or "", re.IGNORECASE)
        if match:
            return match.group(0)[:160]
    return ""


def _baseline(ctx: ScanContext, point: InputPoint) -> Probe:
    return ctx.send_point(point, point.value or "cm-baseline", follow=False)


def _marginally_different(baseline: Probe, probe: Probe) -> tuple[bool, str]:
    if not baseline.ok or not probe.ok:
        return False, ""
    if baseline.status != probe.status:
        return True, f"status {baseline.status}->{probe.status}"
    base_len = max(1, len(baseline.text))
    delta = abs(len(probe.text) - base_len) / base_len
    if delta >= 0.4:
        return True, f"length {len(baseline.text)}->{len(probe.text)} ({round(delta * 100)}%)"
    return False, ""


def _reflection(
    ctx: ScanContext,
    payload: str,
    marker: str,
    *,
    limit: int = 3,
    follow: bool = True,
) -> list[tuple[InputPoint, Probe]]:
    hits: list[tuple[InputPoint, Probe]] = []
    for point in ctx.candidate_points(limit=limit):
        probe = ctx.send_point(point, payload, follow=follow)
        if probe.ok and marker in probe.text:
            hits.append((point, probe))
    return hits


def _xss_outcome(
    hits: list[tuple[InputPoint, Probe]], title: str, marker: str, severity: str = "high"
) -> Outcome:
    findings = [
        Finding(
            title,
            severity,
            "A script-capable payload is reflected without output encoding in the response.",
            f"param={point.param}; marker={marker[:80]}; response_bytes={len(probe.text)}",
            "Context-aware output encoding, a restrictive CSP, and server-side input validation must be applied together.",
        )
        for point, probe in hits[:2]
    ]
    return Outcome(
        verdict(findings),
        f"{len(hits)} reflection(s) confirmed for {marker[:40]}."
        if findings
        else f"No unencoded reflection of {marker[:40]} was observed.",
        findings,
    )


@module(
    "xss_polyglot",
    "XSS Polyglot Reflection",
    CATEGORY,
    "Sends a multi-context polyglot and checks for unencoded reflection.",
    severity="high",
    passive=False,
)
def xss_polyglot(ctx: ScanContext) -> Outcome:
    token = secrets.token_hex(3)
    payload = f"'\"--><svg/onload=confirm('{token}')>cm{token}"
    marker = f"<svg/onload=confirm('{token}')>"
    hits = _reflection(ctx, payload, marker, limit=3)
    return _xss_outcome(hits, "Polyglot payload is reflected unencoded", marker)


@module(
    "xss_svg",
    "SVG Script Injection",
    CATEGORY,
    "Tests whether SVG script content survives reflection into an HTML response.",
    severity="high",
    passive=False,
)
def xss_svg(ctx: ScanContext) -> Outcome:
    token = secrets.token_hex(3)
    payload = f"<svg><script>confirm('{token}')</script></svg>"
    marker = f"<script>confirm('{token}')</script>"
    hits = _reflection(ctx, payload, marker, limit=3)
    return _xss_outcome(hits, "SVG script payload is reflected unencoded", marker)


@module(
    "xss_css",
    "CSS Injection Breakout",
    CATEGORY,
    "Checks for style-context breakout that can load attacker-controlled CSS.",
    severity="high",
    passive=False,
)
def xss_css(ctx: ScanContext) -> Outcome:
    token = secrets.token_hex(3)
    payload = f"</style><link rel=stylesheet href=//sentinel.invalid/{token}.css>"
    marker = f"</style><link rel=stylesheet href=//sentinel.invalid/{token}.css>"
    hits = _reflection(ctx, payload, marker, limit=3)
    return _xss_outcome(hits, "Style-context breakout is reflected", marker, "medium")


@module(
    "xss_meta_refresh",
    "Meta Refresh Injection",
    CATEGORY,
    "Tests whether meta refresh markup can be injected into a response.",
    severity="medium",
    passive=False,
)
def xss_meta_refresh(ctx: ScanContext) -> Outcome:
    token = secrets.token_hex(3)
    payload = f'"><meta http-equiv=refresh content="0;url=//sentinel.invalid/{token}">'
    marker = f'<meta http-equiv=refresh content="0;url=//sentinel.invalid/{token}">'
    hits = _reflection(ctx, payload, marker, limit=3)
    return _xss_outcome(hits, "Meta refresh markup is reflected", marker, "medium")


@module(
    "xss_iframe_srcdoc",
    "Iframe srcdoc Injection",
    CATEGORY,
    "Checks whether an iframe srcdoc payload is reflected without encoding.",
    severity="high",
    passive=False,
)
def xss_iframe_srcdoc(ctx: ScanContext) -> Outcome:
    token = secrets.token_hex(3)
    payload = f'"><iframe srcdoc="<script>confirm(\'{token}\')</script>"></iframe>'
    marker = f'<iframe srcdoc="<script>confirm(\'{token}\')</script>">'
    hits = _reflection(ctx, payload, marker, limit=3)
    return _xss_outcome(hits, "Iframe srcdoc payload is reflected unencoded", marker)


@module(
    "xss_markdown",
    "Markdown Injection",
    CATEGORY,
    "Sends markdown link and image syntax to detect unsafe client-side rendering.",
    severity="medium",
    passive=False,
)
def xss_markdown(ctx: ScanContext) -> Outcome:
    token = secrets.token_hex(3)
    payload = f"[cm](javascript:confirm('{token}')) ![cm](x\"onerror=\"confirm('{token}'))"
    findings: list[Finding] = []
    for point in ctx.candidate_points(limit=3):
        probe = ctx.send_point(point, payload)
        if not probe.ok:
            continue
        text = probe.text
        if f"javascript:confirm('{token}')" in text or f"onerror=\"confirm('{token}')" in text:
            findings.append(
                Finding(
                    "Markdown payload is reflected into an executable context",
                    "medium",
                    "Unsanitised markdown can produce javascript: links or event handlers.",
                    f"param={point.param}; token={token}",
                    "Render markdown with a sanitizer that strips javascript: URLs and event attributes.",
                )
            )
            break
    status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        "Markdown input is not reflected into executable markup."
        if not findings
        else "Markdown rendering is unsafe.",
        findings,
    )


@module(
    "xss_event_handler",
    "Event Handler Injection",
    CATEGORY,
    "Tests whether attribute-context payloads can inject DOM event handlers.",
    severity="high",
    passive=False,
)
def xss_event_handler(ctx: ScanContext) -> Outcome:
    token = secrets.token_hex(3)
    payload = f'cm{token}" onmouseover="confirm(\'{token}\')" autofocus="'
    marker = f'onmouseover="confirm(\'{token}\')"'
    hits = _reflection(ctx, payload, marker, limit=3)
    return _xss_outcome(hits, "Event handler attribute is reflected", marker)


@module(
    "csti_expression",
    "Client-Side Template Expression",
    CATEGORY,
    "Checks whether template expressions are reflected into a client-side evaluation context.",
    severity="high",
    passive=False,
)
def csti_expression(ctx: ScanContext) -> Outcome:
    token = secrets.token_hex(3)
    payload = f"{{{{constructor.constructor('confirm(\"{token}\")')()}}}}"
    marker = f"constructor.constructor('confirm(\"{token}\")')"
    hits = _reflection(ctx, payload, marker, limit=3)
    return _xss_outcome(hits, "Template expression is reflected", marker, "medium")


@module(
    "sql_order_by",
    "SQL ORDER BY Injection",
    CATEGORY,
    "Adds benign ORDER BY fragments to sorting parameters and watches for database errors.",
    severity="high",
    passive=False,
)
def sql_order_by(ctx: ScanContext) -> Outcome:
    points = [
        point
        for point in ctx.candidate_points(limit=8)
        if re.search(r"(sort|order|orderby|column|field|dir|by)", point.param, re.I)
    ][:3]
    if not points:
        points = ctx.candidate_points(limit=2)
    findings: list[Finding] = []
    for point in points:
        baseline = _baseline(ctx, point)
        for payload in (",1", ",1-- -", " (select 1)"):
            probe = ctx.send_point(point, payload, follow=False)
            error = _match(probe.text, SQL_ERROR_PATTERNS) if probe.ok else ""
            if error:
                findings.append(
                    Finding(
                        "ORDER BY parameter reaches the database unsafely",
                        "high",
                        "A sort fragment triggered a database error, exposing query structure.",
                        f"param={point.param}; payload={payload}; error={error}",
                        "Use an allowlist mapping for sortable columns and parameterize every query.",
                    )
                )
                break
            changed, detail = _marginally_different(baseline, probe)
            if changed and probe.ok and "error" in probe.text.lower():
                findings.append(
                    Finding(
                        "Sorting parameter changes query behaviour",
                        "medium",
                        "The response diverges when a sort fragment is supplied.",
                        f"param={point.param}; payload={payload}; {detail}",
                        "Whitelist sort columns and directions; never concatenate them into SQL.",
                    )
                )
                break
    status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        "Sorting parameters do not expose SQL errors."
        if not findings
        else "Sorting parameters are injectable or unstable.",
        findings,
    )


@module(
    "sql_error_fingerprint",
    "SQL Error Fingerprinting",
    CATEGORY,
    "Sends quote characters and fingerprints database error families.",
    severity="high",
    passive=False,
)
def sql_error_fingerprint(ctx: ScanContext) -> Outcome:
    findings: list[Finding] = []
    for point in ctx.candidate_points(limit=4):
        for payload in ("'", '"', "\\", "')"):
            probe = ctx.send_point(point, payload, follow=False)
            if not probe.ok:
                continue
            error = _match(probe.text, SQL_ERROR_PATTERNS)
            if not error:
                continue
            findings.append(
                Finding(
                    "Database error is returned to the client",
                    "high",
                    "Error text reveals the database engine and confirms unsafe query construction.",
                    f"param={point.param}; payload={payload}; error={error}",
                    "Disable verbose database errors, validate input, and parameterize queries.",
                )
            )
            break
    status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        "No SQL error fingerprint was observed."
        if not findings
        else f"{len(findings)} parameter(s) leak SQL errors.",
        findings,
    )


@module(
    "sql_json",
    "JSON SQL Error Exposure",
    CATEGORY,
    "Probes JSON responses for SQL errors after a quote is supplied.",
    severity="high",
    passive=False,
)
def sql_json(ctx: ScanContext) -> Outcome:
    findings: list[Finding] = []
    for point in ctx.candidate_points(limit=4):
        baseline = _baseline(ctx, point)
        probe = ctx.send_point(point, "'", follow=False)
        if not probe.ok:
            continue
        if not (probe.is_json or baseline.is_json):
            continue
        error = _match(probe.text, SQL_ERROR_PATTERNS)
        if not error:
            continue
        findings.append(
            Finding(
                "JSON endpoint leaks a SQL error",
                "high",
                "A JSON response exposes database error text after a quote character.",
                f"param={point.param}; error={error}",
                "Return a generic error envelope and log the database detail server-side only.",
            )
        )
    status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        "JSON endpoints do not leak SQL errors."
        if not findings
        else "JSON endpoints leak SQL error details.",
        findings,
    )


@module(
    "nosql_boolean",
    "NoSQL Boolean Probing",
    CATEGORY,
    "Uses benign boolean operators to detect NoSQL query manipulation.",
    severity="medium",
    passive=False,
)
def nosql_boolean(ctx: ScanContext) -> Outcome:
    findings: list[Finding] = []
    for point in ctx.candidate_points(limit=3):
        baseline = _baseline(ctx, point)
        for payload in ("' || '1'=='1", '{"$ne":null}'):
            probe = ctx.send_point(point, payload, follow=False)
            if not probe.ok:
                continue
            error = _match(probe.text, NOSQL_ERROR_PATTERNS)
            changed, detail = _marginally_different(baseline, probe)
            if error or (changed and probe.status == 200):
                findings.append(
                    Finding(
                        "NoSQL query handling responds to boolean input",
                        "medium",
                        "A boolean operator changed the response shape, which may indicate unsafe document queries.",
                        f"param={point.param}; payload={payload}; {detail or 'error=' + error}",
                        "Cast and validate scalar inputs, reject object and array parameters, and use typed query builders.",
                    )
                )
                break
    status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        "NoSQL boolean tampering was not observed."
        if not findings
        else "NoSQL boolean tampering changed responses.",
        findings,
    )


@module(
    "nosql_regex",
    "NoSQL Regex Injection",
    CATEGORY,
    "Checks whether regex operators are accepted through query parameters.",
    severity="medium",
    passive=False,
)
def nosql_regex(ctx: ScanContext) -> Outcome:
    findings: list[Finding] = []
    for point in ctx.candidate_points(limit=3):
        baseline = _baseline(ctx, point)
        for payload in ('{"$regex":".*"}', "[$regex]=.*"):
            probe = ctx.send_point(point, payload, follow=False)
            if not probe.ok:
                continue
            error = _match(probe.text, NOSQL_ERROR_PATTERNS)
            changed, detail = _marginally_different(baseline, probe)
            if error or (changed and probe.status == 200):
                findings.append(
                    Finding(
                        "NoSQL regex operator is accepted",
                        "medium",
                        "Regex operators can turn a scalar filter into a broad document match.",
                        f"param={point.param}; payload={payload}; {detail or 'error=' + error}",
                        "Reject query operators from untrusted input and enforce schema validation.",
                    )
                )
                break
    status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        "Regex operators are not accepted."
        if not findings
        else "Regex operators influence query handling.",
        findings,
    )


@module(
    "ldap_blind",
    "LDAP Filter Injection",
    CATEGORY,
    "Sends filter fragments and watches for directory-service errors.",
    severity="high",
    passive=False,
)
def ldap_blind(ctx: ScanContext) -> Outcome:
    findings: list[Finding] = []
    for point in ctx.candidate_points(limit=3):
        baseline = _baseline(ctx, point)
        for payload in ("*)(uid=*", ")(cn=*", "*"):
            probe = ctx.send_point(point, payload, follow=False)
            if not probe.ok:
                continue
            error = _match(probe.text, LDAP_ERROR_PATTERNS)
            changed, detail = _marginally_different(baseline, probe)
            if error or (changed and probe.status >= 500):
                findings.append(
                    Finding(
                        "LDAP filter input is not escaped",
                        "high",
                        "A filter fragment changed directory query behaviour or raised a directory error.",
                        f"param={point.param}; payload={payload}; {detail or 'error=' + error}",
                        "Escape RFC 4515 filter characters and validate identifiers before directory queries.",
                    )
                )
                break
    status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        "No LDAP filter injection signal was observed."
        if not findings
        else "LDAP filter injection is likely.",
        findings,
    )


@module(
    "xpath_injection",
    "XPath Injection",
    CATEGORY,
    "Uses boolean XPath fragments to detect unsafe XML query construction.",
    severity="high",
    passive=False,
)
def xpath_injection(ctx: ScanContext) -> Outcome:
    findings: list[Finding] = []
    for point in ctx.candidate_points(limit=3):
        baseline = _baseline(ctx, point)
        for payload in ("' or '1'='1", "x' or name()='x", "1 or 1=1"):
            probe = ctx.send_point(point, payload, follow=False)
            if not probe.ok:
                continue
            error = _match(probe.text, XPATH_ERROR_PATTERNS)
            changed, detail = _marginally_different(baseline, probe)
            if error or (changed and probe.status >= 500):
                findings.append(
                    Finding(
                        "XPath query input is not parameterized",
                        "high",
                        "An XPath fragment changed the response or raised an XML query error.",
                        f"param={point.param}; payload={payload}; {detail or 'error=' + error}",
                        "Use parameterized XPath or precompiled queries and reject operator characters.",
                    )
                )
                break
    status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        "No XPath injection signal was observed."
        if not findings
        else "XPath injection is likely.",
        findings,
    )


@module(
    "path_traversal_encoded",
    "Encoded Path Traversal",
    CATEGORY,
    "Sends encoded traversal sequences to file-like parameters and checks for system file disclosure.",
    severity="high",
    passive=False,
)
def path_traversal_encoded(ctx: ScanContext) -> Outcome:
    file_params = re.compile(
        r"(file|path|page|doc|template|include|download|view|load|asset|folder)", re.I
    )
    points = [point for point in ctx.candidate_points(limit=8) if file_params.search(point.param)][:3]
    if not points:
        return Outcome("skipped", "No file-like parameter was discovered.")
    signatures = ("root:x:0:0", "daemon:x:", "[boot loader]", "[extensions]", "root:*:0:0")
    findings: list[Finding] = []
    for point in points:
        for payload in (
            "../../../../etc/passwd",
            "..%2f..%2f..%2fetc%2fpasswd",
            "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "....//....//etc/passwd",
        ):
            probe = ctx.send_point(point, payload, follow=False)
            if not probe.ok:
                continue
            match = next((item for item in signatures if item in probe.text), "")
            if not match:
                continue
            findings.append(
                Finding(
                    "Path traversal discloses a system file",
                    "high",
                    "An encoded traversal sequence returned the contents of a sensitive operating-system file.",
                    f"param={point.param}; payload={payload}; signature={match}",
                    "Resolve paths against a fixed root, reject traversal segments after decoding, and run the service with least privilege.",
                )
            )
            break
    status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        "No traversal disclosure was observed."
        if not findings
        else "Path traversal is exploitable.",
        findings,
    )


@module(
    "open_redirect_meta",
    "Redirect Parameter Abuse",
    CATEGORY,
    "Tests redirect-like parameters for open redirection through headers or meta refresh.",
    severity="medium",
    passive=False,
)
def open_redirect_meta(ctx: ScanContext) -> Outcome:
    redirect_params = re.compile(
        r"(redirect|return|next|continue|target|dest|goto|url|callback)", re.I
    )
    points = [
        point for point in ctx.candidate_points(limit=8) if redirect_params.search(point.param)
    ][:3]
    if not points:
        return Outcome("skipped", "No redirect-like parameter was discovered.")
    findings: list[Finding] = []
    for point in points:
        for payload in ("//sentinel.invalid/redirect", "https://sentinel.invalid/redirect"):
            probe = ctx.send_point(point, payload, follow=False)
            if not probe.ok:
                continue
            location = probe.header("location", "")
            body = probe.text[:40_000]
            meta = re.search(
                r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]+url=([^"\'>\s]+)',
                body,
                re.I,
            )
            target = location or (meta.group(1) if meta else "")
            if "sentinel.invalid" not in target:
                continue
            findings.append(
                Finding(
                    "Redirect parameter accepts an external destination",
                    "medium",
                    "The application hands users to an attacker-chosen origin, enabling phishing and token leakage.",
                    f"param={point.param}; payload={payload}; target={target[:160]}",
                    "Resolve redirects against a server-side allowlist and reject values that contain a scheme or leading double slash.",
                )
            )
            break
    status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        "Redirect parameters stay on-site."
        if not findings
        else "Redirect parameters accept external destinations.",
        findings,
    )


@module(
    "cookie_reflection",
    "Cookie Value Reflection",
    CATEGORY,
    "Checks whether request parameters are reflected into Set-Cookie headers.",
    severity="medium",
    passive=False,
)
def cookie_reflection(ctx: ScanContext) -> Outcome:
    token = f"cmck{secrets.token_hex(4)}"
    findings: list[Finding] = []
    for point in ctx.candidate_points(limit=3):
        probe = ctx.send_point(point, token, follow=False)
        if not probe.ok:
            continue
        cookies = " ".join(probe.headers.get_list("set-cookie"))
        if token not in cookies:
            continue
        findings.append(
            Finding(
                "Request value is copied into a response cookie",
                "medium",
                "Reflected cookie content can be used for session fixation or header injection if delimiters are not sanitised.",
                f"param={point.param}; set-cookie={cookies[:220]}",
                "Never build cookies from raw request values; generate opaque server-side identifiers and validate header characters.",
            )
        )
    status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        "Request values are not reflected into cookies."
        if not findings
        else "A request value is reflected into a cookie.",
        findings,
    )

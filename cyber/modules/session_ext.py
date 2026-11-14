"""Extended session, cookie and browser-boundary modules."""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlsplit

from ..engine import ScanContext
from ..models import Finding, Outcome
from ..registry import module, verdict

CATEGORY = "Session & Browser"


def _parse_cookie(raw: str) -> tuple[str, dict[str, str]]:
    parts = [part.strip() for part in raw.split(";") if part.strip()]
    if not parts:
        return "", {}
    name = parts[0].split("=", 1)[0].strip()
    attrs: dict[str, str] = {}
    for part in parts[1:]:
        if "=" in part:
            key, value = part.split("=", 1)
            attrs[key.strip().lower()] = value.strip()
        else:
            attrs[part.strip().lower()] = ""
    return name, attrs


@module(
    "cookie_prefixes",
    "Cookie Name Prefixes",
    CATEGORY,
    "Validates __Host- and __Secure- cookie prefixes and their required attributes.",
    severity="low",
    passive=True,
)
def cookie_prefixes(ctx: ScanContext) -> Outcome:
    page = ctx.homepage()
    cookies = page.headers.get_list("set-cookie") if page.headers else []
    if not cookies:
        return Outcome("skipped", "The landing page did not set any cookies.")
    findings: list[Finding] = []
    for raw in cookies[:12]:
        name, attrs = _parse_cookie(raw)
        if not name:
            continue
        lowered = name.lower()
        secure = "secure" in attrs
        if lowered.startswith("__host-"):
            problems = []
            if not secure:
                problems.append("Secure")
            if attrs.get("path") != "/":
                problems.append("Path=/")
            if "domain" in attrs:
                problems.append("no Domain")
            if problems:
                findings.append(
                    Finding(
                        "__Host- cookie violates prefix requirements",
                        "medium",
                        "Browsers reject the cookie or silently drop the prefix guarantee.",
                        f"cookie={name}; missing={', '.join(problems)}",
                        "Set Secure, Path=/, and omit Domain for every __Host- cookie.",
                    )
                )
        elif lowered.startswith("__secure-"):
            if not secure:
                findings.append(
                    Finding(
                        "__Secure- cookie is not marked Secure",
                        "medium",
                        "The prefix is only accepted together with the Secure attribute.",
                        f"cookie={name}",
                        "Add Secure and serve the cookie exclusively over HTTPS.",
                    )
                )
        elif secure:
            findings.append(
                Finding(
                    "Secure cookie does not use a protective prefix",
                    "info",
                    "A prefix lets browsers enforce transport and path constraints.",
                    f"cookie={name}",
                    "Rename host-bound cookies with the __Host- prefix after confirming Path=/ and no Domain.",
                )
            )
    status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        "Cookie prefixes are valid." if not findings else "Cookie prefix usage needs review.",
        findings,
    )


@module(
    "cors_preflight",
    "CORS Preflight Evaluation",
    CATEGORY,
    "Sends an OPTIONS preflight from an untrusted origin and inspects the allowlist decision.",
    severity="high",
    passive=False,
)
def cors_preflight(ctx: ScanContext) -> Outcome:
    origin = "https://sentinel-probe.invalid"
    probe = ctx.fetch(
        "OPTIONS",
        ctx.target,
        headers={
            "Origin": origin,
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "content-type",
        },
        follow=False,
    )
    if not probe.ok:
        return Outcome("skipped", "The CORS preflight could not be completed.")
    allow_origin = probe.header("access-control-allow-origin", "").strip()
    allow_credentials = probe.header("access-control-allow-credentials", "").lower()
    if probe.status in {405, 501} and not allow_origin:
        return Outcome("pass", "The endpoint does not implement a CORS preflight.")
    findings: list[Finding] = []
    if allow_origin == origin and allow_credentials == "true":
        findings.append(
            Finding(
                "Arbitrary origin is allowed with credentials",
                "high",
                "The preflight reflects an attacker-controlled origin and permits credentialed reads.",
                f"origin={origin}; allow-origin={allow_origin}; credentials=true",
                "Use a strict server-side origin allowlist and never reflect arbitrary Origin values when credentials are enabled.",
            )
        )
    elif allow_origin == origin:
        findings.append(
            Finding(
                "Arbitrary origin is reflected in CORS",
                "medium",
                "Any site can read responses from this endpoint without credentials.",
                f"origin={origin}; allow-origin={allow_origin}",
                "Replace reflection with an explicit allowlist of trusted origins.",
            )
        )
    elif allow_origin == "*" and allow_credentials == "true":
        findings.append(
            Finding(
                "Wildcard CORS is combined with credentials",
                " medium".strip(),
                "Credentialed wildcard CORS is contradictory and often paired with broken origin checks.",
                f"allow-origin=*; credentials=true",
                "Use exact origins whenever credentials are allowed.",
            )
        )
    status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        "CORS preflight rejects untrusted origins."
        if not findings
        else "CORS preflight trusts an untrusted origin.",
        findings,
    )


@module(
    "cross_origin_isolation",
    "Cross-Origin Isolation",
    CATEGORY,
    "Reviews Cross-Origin-Opener-Policy, Embedder-Policy and Resource-Policy headers.",
    severity="low",
    passive=True,
)
def cross_origin_isolation(ctx: ScanContext) -> Outcome:
    page = ctx.homepage()
    coop = page.headers.get("cross-origin-opener-policy", "").strip()
    coep = page.headers.get("cross-origin-embedder-policy", "").strip()
    corp = page.headers.get("cross-origin-resource-policy", "").strip()
    findings: list[Finding] = []
    if not coop:
        findings.append(
            Finding(
                "Cross-Origin-Opener-Policy is missing",
                "low",
                "A cross-origin opener can retain a reference to the window and observe navigation.",
                "cross-origin-opener-policy=<missing>",
                "Set Cross-Origin-Opener-Policy: same-origin on top-level documents.",
            )
        )
    elif coop.lower() == "unsafe-none":
        findings.append(
            Finding(
                "Cross-Origin-Opener-Policy is unsafe-none",
                "medium",
                "The document explicitly opts out of process isolation.",
                coop[:160],
                "Use same-origin unless a documented integration requires otherwise.",
            )
        )
    if not coep:
        findings.append(
            Finding(
                "Cross-Origin-Embedder-Policy is missing",
                "low",
                "Cross-origin resources are not required to opt in with CORP or CORS.",
                "cross-origin-embedder-policy=<missing>",
                "Adopt require-corp after auditing every embedded resource.",
            )
        )
    if not corp:
        findings.append(
            Finding(
                "Cross-Origin-Resource-Policy is missing",
                "info",
                "Other origins can embed the resource unless CORS or fetch metadata blocks it.",
                "cross-origin-resource-policy=<missing>",
                "Set same-origin or same-site on sensitive responses.",
            )
        )
    status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        "Cross-origin isolation headers are complete."
        if not findings
        else "Cross-origin isolation headers need hardening.",
        findings,
    )


@module(
    "http_methods",
    "HTTP Method Surface",
    CATEGORY,
    "Reads OPTIONS and Allow metadata for write verbs and TRACE exposure.",
    severity="medium",
    passive=False,
)
def http_methods(ctx: ScanContext) -> Outcome:
    probe = ctx.fetch(
        "OPTIONS",
        ctx.target,
        headers={"Origin": ctx.origin},
        follow=False,
    )
    if not probe.ok:
        return Outcome("skipped", "The OPTIONS probe could not be completed.")
    advertised = " ".join(
        [
            probe.header("allow", ""),
            probe.header("public", ""),
            probe.header("access-control-allow-methods", ""),
        ]
    ).upper()
    methods = sorted(
        {
            token.strip()
            for token in re.split(r"[, ]+", advertised)
            if token.strip() and re.fullmatch(r"[A-Z]+", token.strip())
        }
    )
    if not methods:
        return Outcome(
            "info",
            "The server did not advertise supported methods.",
            [
                Finding(
                    "HTTP method metadata is absent",
                    "info",
                    "The OPTIONS response carries no Allow or Access-Control-Allow-Methods value.",
                    f"status={probe.status}",
                    "Return an explicit Allow header and disable unused verbs at the edge.",
                )
            ],
        )
    findings: list[Finding] = []
    dangerous = [method for method in methods if method in {"TRACE", "CONNECT"}]
    write_methods = [method for method in methods if method in {"PUT", "DELETE", "PATCH"}]
    if dangerous:
        findings.append(
            Finding(
                "Debug or tunnel methods are advertised",
                "medium",
                "TRACE or CONNECT can disclose request data or enable proxying.",
                ", ".join(dangerous),
                "Disable TRACE and CONNECT at the web server and edge.",
            )
        )
    if write_methods:
        findings.append(
            Finding(
                "Write methods are advertised on the landing route",
                "low",
                f"{', '.join(write_methods)} are accepted or listed for a route that normally only serves content.",
                f"allow={', '.join(methods)[:220]}",
                "Return 405 for verbs a route does not implement and enforce authorization server-side.",
            )
        )
    status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        f"Advertised methods: {', '.join(methods)}."
        if not findings
        else "HTTP method surface includes risky verbs.",
        findings,
    )


@module(
    "referrer_leakage",
    "Referrer Leakage",
    CATEGORY,
    "Checks referrer policy quality and whether sensitive query links can leak to third parties.",
    severity="low",
    passive=True,
)
def referrer_leakage(ctx: ScanContext) -> Outcome:
    page = ctx.homepage()
    policy = page.headers.get("referrer-policy", "").strip().lower()
    if not policy:
        match = re.search(
            r'<meta[^>]+name=["\']referrer["\'][^>]+content=["\']([^"\']+)',
            page.html,
            re.I,
        )
        policy = match.group(1).strip().lower() if match else ""
    strict = {
        "no-referrer",
        "same-origin",
        "strict-origin",
        "strict-origin-when-cross-origin",
    }
    risky = {"unsafe-url", "no-referrer-when-downgrade", "origin-when-cross-origin", ""}
    sensitive_keys = re.compile(
        r"(token|key|secret|password|email|session|auth|code|invite)", re.I
    )
    sensitive_links = []
    for link in page.links[:80]:
        query = urlsplit(link).query
        if not query:
            continue
        if any(sensitive_keys.search(key) for key, _ in parse_qsl(query, keep_blank_values=True)):
            sensitive_links.append(link)
    findings: list[Finding] = []
    if policy in risky:
        findings.append(
            Finding(
                "Referrer policy permits URL leakage",
                "medium" if sensitive_links else "low",
                "Full URLs can cross origins in the Referer header, including query parameters.",
                f"referrer-policy={policy or '<missing>'}; sensitive_links={len(sensitive_links)}",
                "Set Referrer-Policy: strict-origin-when-cross-origin or no-referrer.",
            )
        )
    elif policy not in strict and policy:
        findings.append(
            Finding(
                "Referrer policy is non-standard",
                "info",
                "The browser may fall back to its default policy.",
                policy[:180],
                "Use a documented policy value such as strict-origin-when-cross-origin.",
            )
        )
    if sensitive_links:
        findings.append(
            Finding(
                "Sensitive query parameters appear in outbound links",
                "low",
                "Token or identity values in URLs can leak through referrers, logs and browser history.",
                ", ".join(link[:160] for link in sensitive_links[:4]),
                "Move sensitive values out of query strings and use POST bodies or short-lived server-side references.",
            )
        )
    status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        "Referrer policy is restrictive."
        if not findings
        else "Referrer handling can leak sensitive URLs.",
        findings,
    )


@module(
    "password_autocomplete",
    "Password Field Semantics",
    CATEGORY,
    "Reviews password inputs for autocomplete hints that impede password managers.",
    severity="low",
    passive=True,
)
def password_autocomplete(ctx: ScanContext) -> Outcome:
    page = ctx.homepage()
    if not page.html:
        return Outcome("skipped", "The landing page did not return HTML.")
    inputs = re.findall(r"<input\b[^>]*>", page.html, re.I | re.S)
    password_inputs = []
    for tag in inputs:
        attrs = {
            key.lower(): value
            for key, _quote, value in re.findall(
                r"([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*([\"'])(.*?)\2", tag, re.S
            )
        }
        if attrs.get("type", "").lower() != "password":
            continue
        password_inputs.append(attrs)
    if not password_inputs:
        return Outcome("skipped", "No password input was found on the landing page.")
    findings: list[Finding] = []
    for attrs in password_inputs[:6]:
        autocomplete = attrs.get("autocomplete", "").strip().lower()
        if autocomplete in {"", "off", "on"}:
            findings.append(
                Finding(
                    "Password field lacks a specific autocomplete hint",
                    "low",
                    "Password managers cannot reliably distinguish current and new credentials.",
                    f"name={attrs.get('name', '<unnamed>')}; autocomplete={autocomplete or '<missing>'}",
                    "Use autocomplete=current-password on login and new-password on registration or reset forms.",
                )
            )
    status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        "Password fields declare autocomplete semantics."
        if not findings
        else "Password field semantics need review.",
        findings,
    )


@module(
    "iframe_sandbox",
    "Iframe Sandboxing",
    CATEGORY,
    "Inspects embedded frames for missing or ineffective sandbox restrictions.",
    severity="medium",
    passive=True,
)
def iframe_sandbox(ctx: ScanContext) -> Outcome:
    page = ctx.homepage()
    if not page.html:
        return Outcome("skipped", "The landing page did not return HTML.")
    frames = re.findall(r"<iframe\b[^>]*>", page.html, re.I | re.S)
    if not frames:
        return Outcome("skipped", "No iframe was found on the landing page.")
    findings: list[Finding] = []
    for tag in frames[:10]:
        attrs = {
            key.lower(): value
            for key, _quote, value in re.findall(
                r"([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*([\"'])(.*?)\2", tag, re.S
            )
        }
        src = attrs.get("src", "").strip()
        srcdoc = "srcdoc" in attrs
        sandbox = attrs.get("sandbox")
        if sandbox is None:
            if srcdoc or (src and not ctx.same_host(src)):
                findings.append(
                    Finding(
                        "Untrusted frame runs without a sandbox",
                        "medium",
                        "An embedded document can script the parent context or navigate the top window.",
                        f"src={src[:180] or 'srcdoc'}; sandbox=<missing>",
                        'Add sandbox="" and grant only the tokens the frame actually needs.',
                    )
                )
            continue
        tokens = {token.strip().lower() for token in sandbox.split() if token.strip()}
        if "allow-scripts" in tokens and "allow-same-origin" in tokens:
            findings.append(
                Finding(
                    "Sandbox allows scripts and same-origin access together",
                    "medium",
                    "The frame can remove its own sandbox attribute and escape the restriction.",
                    f"src={src[:180] or 'srcdoc'}; sandbox={sandbox[:180]}",
                    "Remove allow-same-origin from scripted frames or serve them from a separate origin.",
                )
            )
    status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        "Iframes are sandboxed." if not findings else "Iframe sandboxing needs review.",
        findings,
    )

from __future__ import annotations

import re
from urllib.parse import urlsplit

from ..engine import ScanContext
from ..models import Finding, Outcome
from ..registry import module, verdict

CATEGORY = "Session & Browser"


def _parse_cookie(raw: str) -> tuple[str, dict[str, str]]:
    parts = [part.strip() for part in raw.split(";") if part.strip()]
    if not parts:
        return "", {}
    name = parts[0].split("=", 1)[0].strip()
    attributes: dict[str, str] = {}
    for part in parts[1:]:
        if "=" in part:
            key, value = part.split("=", 1)
            attributes[key.strip().lower()] = value.strip()
        else:
            attributes[part.strip().lower()] = ""
    return name, attributes


@module(
    "cookie_security",
    "Cookie Security Flags",
    CATEGORY,
    "Reviews Secure, HttpOnly, SameSite and lifetime attributes on response cookies.",
    severity="medium",
    passive=True,
)
def cookie_security(ctx: ScanContext) -> Outcome:
    page = ctx.homepage()
    cookies = page.headers.get_list("set-cookie") if page.headers else []
    if not cookies:
        return Outcome("pass", "The landing page did not set any cookies.")
    findings: list[Finding] = []
    session_re = re.compile(r"(sess|session|auth|token|jwt|sid|csrf|remember)", re.I)
    for raw in cookies[:12]:
        name, attributes = _parse_cookie(raw)
        if not name:
            continue
        problems: list[str] = []
        severity = "low"
        if ctx.scheme == "https" and "secure" not in attributes:
            problems.append("Secure is missing")
            severity = "medium"
        if "httponly" not in attributes and session_re.search(name):
            problems.append("HttpOnly is missing on a session-like cookie")
            severity = "medium"
        same_site = attributes.get("samesite", "").lower()
        if not same_site:
            problems.append("SameSite is not declared")
            severity = "medium" if severity == "low" else severity
        elif same_site == "none" and "secure" not in attributes:
            problems.append("SameSite=None without Secure")
            severity = "high"
        if "domain" in attributes and attributes["domain"].startswith("."):
            problems.append("Cookie is scoped to every subdomain")
            severity = "medium" if severity == "low" else severity
        max_age = attributes.get("max-age")
        if max_age and max_age.isdigit() and int(max_age) > 31_536_000:
            problems.append("Cookie lifetime exceeds one year")
        if problems:
            findings.append(
                Finding(
                    f"Insecure cookie attributes: {name}",
                    severity,
                    "; ".join(problems) + ".",
                    f"cookie={name}; flags={', '.join(sorted(attributes.keys())) or 'none'}",
                    "Set Secure, HttpOnly where appropriate, and SameSite=Lax or Strict.",
                )
            )
    status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        "Cookie flags are appropriately hardened."
        if not findings
        else f"{len(findings)} cookie(s) require attribute hardening.",
        findings,
    )


@module(
    "cors_policy",
    "CORS Policy",
    CATEGORY,
    "Tests whether arbitrary origins are reflected with credentials in CORS responses.",
    severity="high",
    passive=False,
)
def cors_policy(ctx: ScanContext) -> Outcome:
    canary = "https://cm-cors-canary.example"
    findings: list[Finding] = []
    probes = [
        ("normal origin", canary),
        ("null origin", "null"),
    ]
    for label, origin in probes:
        probe = ctx.fetch("GET", ctx.target, headers={"Origin": origin})
        if not probe.ok:
            continue
        allow_origin = probe.header("access-control-allow-origin")
        allow_credentials = probe.header("access-control-allow-credentials").lower()
        if not allow_origin:
            continue
        if allow_origin == origin and origin != "null":
            severity = "high" if allow_credentials == "true" else "medium"
            findings.append(
                Finding(
                    "Arbitrary origin is reflected in CORS",
                    severity,
                    "The server reflects an untrusted Origin header in Access-Control-Allow-Origin.",
                    f"origin={origin}; allow-credentials={allow_credentials or 'false'}",
                    "Use an explicit allowlist of trusted origins and avoid credentialed wildcard CORS.",
                )
            )
        elif allow_origin == "*" and allow_credentials == "true":
            findings.append(
                Finding(
                    "Wildcard CORS with credentials",
                    "high",
                    "Access-Control-Allow-Origin is * while credentials are allowed.",
                    f"origin={origin}; allow-credentials=true",
                    "Never combine credentialed CORS with a wildcard origin.",
                )
            )
        elif allow_origin == "*":
            findings.append(
                Finding(
                    "Wildcard CORS policy",
                    "low",
                    "Any origin may read unauthenticated responses.",
                    f"origin={origin}",
                    "Restrict Access-Control-Allow-Origin to known front-end origins.",
                )
            )
        if origin == "null" and allow_origin == "null":
            findings.append(
                Finding(
                    "Null origin is trusted",
                    "high",
                    "A sandboxed or data: origin can satisfy a null-origin allowlist.",
                    "origin=null",
                    "Never allow the null origin for authenticated resources.",
                )
            )
    status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        "No permissive CORS reflection was observed."
        if not findings
        else "CORS policy requires tightening.",
        findings,
    )


@module(
    "cache_policy",
    "Cache & Sensitive Response Policy",
    CATEGORY,
    "Checks whether HTML and authenticated responses can be stored by shared caches.",
    severity="medium",
    passive=True,
)
def cache_policy(ctx: ScanContext) -> Outcome:
    page = ctx.homepage()
    cache = page.headers.get("cache-control", "").lower()
    pragma = page.headers.get("pragma", "").lower()
    expires = page.headers.get("expires", "")
    vary = page.headers.get("vary", "").lower()
    set_cookie = bool(page.headers.get_list("set-cookie")) if page.headers else False
    findings: list[Finding] = []
    if not cache and not pragma and not expires:
        findings.append(
            Finding(
                "No explicit cache policy",
                "low",
                "The HTML response has no Cache-Control directive.",
                "cache-control=<missing>",
                "Set Cache-Control: no-store on authenticated or account-specific responses.",
            )
        )
    elif "no-store" not in cache and "private" not in cache:
        if "public" in cache or re.search(r"max-age=\s*[1-9]", cache):
            severity = "medium" if set_cookie else "low"
            findings.append(
                Finding(
                    "Potentially cacheable HTML response",
                    "medium" if set_cookie else severity,
                    "The response permits shared caching"
                    + (" while also setting cookies." if set_cookie else "."),
                    f"cache-control={cache or '<missing>'}; set-cookie={set_cookie}",
                    "Use no-store or private, must-revalidate for personalized responses.",
                )
            )
            if set_cookie and "cookie" not in vary:
                findings.append(
                    Finding(
                        "Cache key does not vary on Cookie",
                        "medium",
                        "A cacheable response sets cookies without a Vary: Cookie signal.",
                        f"vary={vary or '<missing>'}",
                        "Add Vary: Cookie or, preferably, make the response non-cacheable.",
                    )
                )
    status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        "Sensitive response caching is restricted."
        if not findings
        else "Cache policy needs review.",
        findings,
    )


@module(
    "framing_defense",
    "Clickjacking & Frame Protection",
    CATEGORY,
    "Verifies X-Frame-Options and CSP frame-ancestors against framing attacks.",
    severity="medium",
    passive=True,
)
def framing_defense(ctx: ScanContext) -> Outcome:
    page = ctx.homepage()
    xfo = page.headers.get("x-frame-options", "").strip()
    csp = page.headers.get("content-security-policy", "").lower()
    frame_ancestors = ""
    for directive in csp.split(";"):
        if directive.strip().startswith("frame-ancestors"):
            frame_ancestors = directive.strip()
            break
    findings: list[Finding] = []
    if not xfo and not frame_ancestors:
        findings.append(
            Finding(
                "Page can be framed",
                "medium",
                "No X-Frame-Options or CSP frame-ancestors directive protects the page.",
                "x-frame-options=<missing>; frame-ancestors=<missing>",
                "Set X-Frame-Options: DENY and CSP frame-ancestors 'none'.",
            )
        )
    elif xfo and xfo.upper() not in {"DENY", "SAMEORIGIN"}:
        findings.append(
            Finding(
                "Weak X-Frame-Options value",
                "low",
                "ALLOW-FROM is obsolete and inconsistently enforced by browsers.",
                f"x-frame-options={xfo[:120]}",
                "Use X-Frame-Options: DENY or SAMEORIGIN.",
            )
        )
    if frame_ancestors and re.search(r"frame-ancestors\s+[^;]*(\*|http:)", frame_ancestors):
        findings.append(
            Finding(
                "CSP frame-ancestors is overly broad",
                "medium",
                "The policy allows any origin to frame the application.",
                frame_ancestors[:220],
                "Restrict frame-ancestors to trusted origins or use 'none'.",
            )
        )
    status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        "Framing is restricted."
        if not findings
        else "Framing protection is missing or weak.",
        findings,
    )


@module(
    "csrf_protection",
    "CSRF Token Coverage",
    CATEGORY,
    "Checks POST forms for anti-CSRF tokens and records SameSite cookie coverage.",
    severity="medium",
    passive=True,
)
def csrf_protection(ctx: ScanContext) -> Outcome:
    page = ctx.homepage()
    forms = [
        form
        for form in page.forms
        if str(form.get("method") or "GET").upper() == "POST"
    ]
    if not forms:
        return Outcome("skipped", "No POST form was discovered on the landing page.")
    cookies = page.headers.get_list("set-cookie") if page.headers else []
    same_site = any(
        re.search(r"samesite\s*=\s*(lax|strict)", cookie, re.I) for cookie in cookies
    )
    token_re = re.compile(
        r"(csrf|xsrf|authenticity|__requestverificationtoken|nonce)", re.I
    )
    sensitive_re = re.compile(
        r"(password|passwd|email|username|account|delete|remove|transfer|admin|role)",
        re.I,
    )
    findings: list[Finding] = []
    for form in forms[:8]:
        fields = form.get("fields") or []
        names = [str(field.get("name") or "") for field in fields]
        types = {str(field.get("type") or "").lower() for field in fields}
        if any(token_re.search(name) for name in names):
            continue
        action = str(form.get("action") or page.url)
        sensitive = "password" in types or any(
            sensitive_re.search(name) for name in names
        )
        if not sensitive:
            sensitive = bool(sensitive_re.search(action))
        findings.append(
            Finding(
                "POST form lacks an anti-CSRF token",
                "medium" if sensitive else "low",
                "A state-changing form is submitted without a hidden anti-CSRF token.",
                f"action={urlsplit(action).path or '/'}; fields={', '.join(names[:8]) or 'none'}; "
                f"samesite_cookie={'yes' if same_site else 'no'}",
                "Issue a per-session CSRF token, validate it server-side, and set SameSite=Lax or Strict on session cookies.",
            )
        )
    status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        "POST forms carry anti-CSRF tokens."
        if not findings
        else f"{len(findings)} POST form(s) lack anti-CSRF protection.",
        findings,
    )


@module(
    "sri_integrity",
    "Subresource Integrity Coverage",
    CATEGORY,
    "Reviews cross-origin scripts and stylesheets for valid Subresource Integrity hashes.",
    severity="medium",
    passive=True,
)
def sri_integrity(ctx: ScanContext) -> Outcome:
    page = ctx.homepage()
    if not page.html:
        return Outcome("skipped", "The landing page did not return HTML.")
    tag_re = re.compile(r"<(script|link)\b([^>]*)>", re.I | re.S)
    attr_re = re.compile(r"([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*([\"'])(.*?)\2", re.S)
    integrity_re = re.compile(
        r"^(?:sha(?:256|384|512)-[A-Za-z0-9+/]+={0,2}\s*)+$", re.I
    )
    findings: list[Finding] = []
    checked = 0
    for match in tag_re.finditer(page.html):
        tag = match.group(1).lower()
        attrs = {
            key.lower(): value
            for key, _quote, value in attr_re.findall(match.group(2))
        }
        if tag == "script":
            url = attrs.get("src", "")
            label = "script"
        else:
            if "stylesheet" not in attrs.get("rel", "").lower():
                continue
            url = attrs.get("href", "")
            label = "stylesheet"
        if not url or url.startswith(("data:", "blob:")):
            continue
        if ctx.same_host(url):
            continue
        checked += 1
        integrity = attrs.get("integrity", "").strip()
        if not integrity or not integrity_re.match(integrity):
            findings.append(
                Finding(
                    f"Third-party {label} lacks Subresource Integrity",
                    "medium" if label == "script" else "low",
                    "A cross-origin resource is loaded without a valid SRI hash, so a compromised CDN can alter it.",
                    f"tag={label}; url={url[:220]}; integrity={integrity[:80] or '<missing>'}",
                    "Add an integrity hash and crossorigin attribute to every third-party script and stylesheet.",
                )
            )
        elif "crossorigin" not in attrs:
            findings.append(
                Finding(
                    f"Third-party {label} uses SRI without CORS",
                    "low",
                    "The integrity attribute cannot be enforced unless the request uses CORS.",
                    f"tag={label}; url={url[:220]}",
                    'Add crossorigin="anonymous" and serve the asset with a permissive CORS header.',
                )
            )
        if len(findings) >= 8:
            break
    if not checked:
        return Outcome("skipped", "No cross-origin scripts or stylesheets were found.")
    status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        "Cross-origin resources use Subresource Integrity."
        if not findings
        else "Subresource Integrity coverage needs review.",
        findings,
    )


@module(
    "mixed_content",
    "Mixed Content & Form Transport",
    CATEGORY,
    "Finds active and passive HTTP subresources loaded by an HTTPS page.",
    severity="high",
    passive=True,
)
def mixed_content(ctx: ScanContext) -> Outcome:
    if ctx.scheme != "https":
        return Outcome("skipped", "Plain HTTP target; mixed-content analysis is not applicable.")
    page = ctx.homepage()
    html = page.html
    active_patterns = [
        (r"<script[^>]+src=[\"']http://[^\"']+", "script"),
        (r"<link[^>]+href=[\"']http://[^\"']+", "stylesheet/preload"),
        (r"<iframe[^>]+src=[\"']http://[^\"']+", "iframe"),
        (r"<form[^>]+action=[\"']http://[^\"']+", "form action"),
    ]
    passive_patterns = [
        (r"<img[^>]+src=[\"']http://[^\"']+", "image"),
        (r"<source[^>]+src=[\"']http://[^\"']+", "media source"),
        (r"<video[^>]+src=[\"']http://[^\"']+", "video"),
    ]
    findings: list[Finding] = []
    for pattern, label in active_patterns:
        for match in re.findall(pattern, html, re.I)[:3]:
            findings.append(
                Finding(
                    f"Active mixed content: {label}",
                    "high",
                    "An HTTPS page loads an active resource over plain HTTP, allowing tampering.",
                    match[:220],
                    "Serve every active subresource over HTTPS and add upgrade-insecure-requests.",
                )
            )
    passive_count = 0
    for pattern, label in passive_patterns:
        matches = re.findall(pattern, html, re.I)
        passive_count += len(matches)
        if matches:
            findings.append(
                Finding(
                    f"Passive mixed content: {label}",
                    "low",
                    f"{len(matches)} {label} resource(s) are loaded over HTTP.",
                    matches[0][:220],
                    "Serve all media over HTTPS to avoid mixed-content warnings and tampering.",
                )
            )
    status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        "No mixed HTTP subresources were found."
        if not findings
        else "Mixed content was detected on the HTTPS page.",
        findings,
    )

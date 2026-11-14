"""Extended edge-protection and defensive-control modules."""

from __future__ import annotations

import re
import secrets
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from ..engine import ScanContext
from ..models import Finding, Outcome
from ..registry import module, verdict

CATEGORY = "Edge & Defense"


@module(
    "bot_management",
    "Bot Management Detection",
    CATEGORY,
    "Detects edge bot-management products through response headers and cookies.",
    severity="info",
    passive=True,
)
def bot_management(ctx: ScanContext) -> Outcome:
    page = ctx.homepage()
    headers = page.headers
    cookies = " ".join(headers.get_list("set-cookie")) if headers else ""
    signals = []
    for name, label in (
        ("cf-ray", "Cloudflare"),
        ("cf-cache-status", "Cloudflare cache"),
        ("x-akamai-transformed", "Akamai"),
        ("akamai-grn", "Akamai"),
        ("x-datadome", "DataDome"),
        ("x-px", "PerimeterX"),
        ("x-iinfo", "Imperva"),
        ("x-sucuri-id", "Sucuri"),
        ("x-amzn-waf", "AWS WAF"),
        ("x-aws-waf-token", "AWS WAF token"),
    ):
        if headers.get(name):
            signals.append(label)
    lowered = cookies.lower()
    for marker, label in (
        ("datadome", "DataDome cookie"),
        ("_px", "PerimeterX cookie"),
        ("incap_ses", "Imperva cookie"),
        ("aws-waf-token", "AWS WAF cookie"),
        ("__cf_bm", "Cloudflare bot cookie"),
    ):
        if marker in lowered:
            signals.append(label)
    unique = sorted(set(signals))
    if unique:
        return Outcome("pass", f"Bot management signals: {', '.join(unique[:6])}.")
    return Outcome(
        "info",
        "No edge bot-management signal was detected.",
        [
            Finding(
                "No bot management signal is present",
                "info",
                "Automated abuse may reach the origin unless rate limits and challenge controls are applied elsewhere.",
                "headers=cf-ray,x-datadome,x-px,x-iinfo,x-sucuri-id",
                "Add managed bot protection or origin rate limiting for authentication and search routes.",
            )
        ],
    )


@module(
    "cache_deception",
    "Cache Deception Risk",
    CATEGORY,
    "Requests static-looking dynamic paths and inspects cacheability of HTML responses.",
    severity="medium",
    passive=False,
)
def cache_deception(ctx: ScanContext) -> Outcome:
    token = secrets.token_hex(4)
    findings: list[Finding] = []
    for path in (f"/cm-cache-{token}.css", f"/account/cm-cache-{token}.css"):
        probe = ctx.get(path)
        if not probe.ok or probe.status != 200:
            continue
        content_type = probe.content_type
        cache_control = probe.header("cache-control", "")
        cache_status = " ".join(
            [
                probe.header("x-cache", ""),
                probe.header("cf-cache-status", ""),
                probe.header("x-proxy-cache", ""),
            ]
        ).lower()
        age = probe.header("age", "")
        public = bool(re.search(r"(?:^|,)\s*public\b", cache_control, re.I)) or bool(
            re.search(r"max-age\s*=\s*[1-9]", cache_control, re.I)
        )
        hit = "hit" in cache_status or (age.isdigit() and int(age) > 0)
        if "html" not in content_type and "text" not in content_type:
            continue
        if public and not probe.header("vary"):
            findings.append(
                Finding(
                    "Dynamic HTML is cacheable on a static-looking path",
                    "medium",
                    "An attacker may trick a shared cache into storing authenticated content for a crafted URL.",
                    f"path={path}; cache-control={cache_control[:140]}; cache={cache_status[:80] or 'none'}; hit={hit}",
                    "Set Cache-Control: no-store on authenticated HTML and normalize extensions before routing.",
                )
            )
        elif hit and "html" in content_type:
            findings.append(
                Finding(
                    "Shared cache served an HTML response for a static path",
                    "medium",
                    "A cache hit on a non-static URL indicates risky cache key normalization.",
                    f"path={path}; cache={cache_status[:100]}; age={age}",
                    "Include the full path and authentication state in the cache key, and never cache private HTML.",
                )
            )
        if len(findings) >= 2:
            break
    status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        "Dynamic HTML is not publicly cacheable."
        if not findings
        else "Cache deception risk is present.",
        findings,
    )


@module(
    "compression_breach",
    "Compression Side-Channel",
    CATEGORY,
    "Checks whether attacker-controlled input is compressed alongside HTML content.",
    severity="medium",
    passive=False,
)
def compression_breach(ctx: ScanContext) -> Outcome:
    if ctx.scheme != "https":
        return Outcome("skipped", "Plain HTTP target; compression side-channel analysis needs TLS.")
    token = f"cmbreach{secrets.token_hex(5)}"
    parts = urlsplit(ctx.target)
    query = parse_qsl(parts.query, keep_blank_values=True)
    query.append(("cm_breach_probe", token))
    url = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), ""))
    probe = ctx.fetch("GET", url, follow=True)
    if not probe.ok:
        return Outcome("skipped", "The compression probe could not be completed.")
    encoding = probe.header("content-encoding", "").lower()
    cache_control = probe.header("cache-control", "").lower()
    if not re.search(r"(gzip|br|deflate)", encoding):
        return Outcome("pass", "The response is not compressed; BREACH-style extraction is not available.")
    if token not in probe.text:
        return Outcome(
            "pass",
            "The response is compressed but does not reflect attacker-controlled input.",
        )
    severity = "low" if "no-store" in cache_control else "medium"
    return Outcome(
        "warn",
        "Compressed HTML reflects attacker-controlled input.",
        [
            Finding(
                "Compression side-channel candidate",
                severity,
                "Reflected input is compressed with the page, the precondition for BREACH-style secret extraction.",
                f"encoding={encoding[:60]}; reflected=true; cache-control={cache_control[:120] or '<none>'}",
                "Disable response compression for authenticated HTML, add random padding, and avoid reflecting secrets beside user input.",
            )
        ],
    )


@module(
    "security_header_consistency",
    "Security Header Consistency",
    CATEGORY,
    "Compares security headers on normal, error and discovery responses.",
    severity="low",
    passive=False,
)
def security_header_consistency(ctx: ScanContext) -> Outcome:
    token = secrets.token_hex(4)
    page = ctx.homepage()
    other = ctx.get(f"/cm-header-probe-{token}")
    if not other.ok:
        return Outcome("skipped", "The comparison response could not be fetched.")
    names = (
        "strict-transport-security",
        "content-security-policy",
        "x-frame-options",
        "x-content-type-options",
        "referrer-policy",
        "permissions-policy",
        "cross-origin-opener-policy",
    )
    mismatches = []
    for name in names:
        left = page.headers.get(name, "")
        right = other.headers.get(name, "")
        if bool(left) != bool(right):
            mismatches.append(name)
    if not mismatches:
        return Outcome("pass", "Security headers are consistent across response types.")
    return Outcome(
        "warn",
        "Security headers differ between response types.",
        [
            Finding(
                "Security headers are applied inconsistently",
                "low",
                "Edge or error responses omit headers that the main document receives.",
                f"missing_on_secondary={', '.join(mismatches[:8])}; status={other.status}",
                "Apply the header policy at the edge or server level so every response inherits it.",
            )
        ],
    )


@module(
    "server_signature",
    "Server Version Signature",
    CATEGORY,
    "Fingerprints product and version banners in headers, meta tags and error responses.",
    severity="low",
    passive=True,
)
def server_signature(ctx: ScanContext) -> Outcome:
    page = ctx.homepage()
    candidates = [
        ("server", page.headers.get("server", "")),
        ("x-powered-by", page.headers.get("x-powered-by", "")),
        ("x-aspnet-version", page.headers.get("x-aspnet-version", "")),
        ("x-runtime", page.headers.get("x-runtime", "")),
        ("x-generator", page.headers.get("x-generator", "")),
        ("meta-generator", page.meta_generator),
    ]
    findings: list[Finding] = []
    for name, value in candidates:
        value = (value or "").strip()
        if not value:
            continue
        if name in {"server", "x-powered-by"} and not re.search(r"\d", value):
            continue
        if name in {"x-runtime", "x-generator", "meta-generator"} and len(value) < 3:
            continue
        findings.append(
            Finding(
                "Product or version banner is disclosed",
                "low",
                "Version metadata narrows the set of applicable exploits and aids fingerprinting.",
                f"{name}={value[:140]}",
                "Remove version tokens from headers and generator meta tags at the server or edge.",
            )
        )
    status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        "No product version banner was disclosed."
        if not findings
        else f"{len(findings)} version banner(s) disclosed.",
        findings,
    )

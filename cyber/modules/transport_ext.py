"""Extended transport, DNS and browser-policy modules."""

from __future__ import annotations

import re
import secrets
from urllib.parse import urljoin, urlsplit

from ..engine import ScanContext
from ..models import Finding, Outcome
from ..registry import module, verdict

CATEGORY = "Transport & DNS"


@module(
    "hsts_policy",
    "HSTS Policy Depth",
    CATEGORY,
    "Evaluates Strict-Transport-Security max-age, includeSubDomains and preload readiness.",
    severity="medium",
    passive=True,
)
def hsts_policy(ctx: ScanContext) -> Outcome:
    if ctx.scheme != "https":
        return Outcome("skipped", "Plain HTTP target; HSTS is not applicable.")
    page = ctx.homepage()
    value = page.headers.get("strict-transport-security", "").strip()
    if not value:
        return Outcome(
            "warn",
            "Strict-Transport-Security is not sent.",
            [
                Finding(
                    "HSTS header is missing",
                    "medium",
                    "Browsers receive no instruction to pin future requests to HTTPS.",
                    "strict-transport-security=<missing>",
                    "Send Strict-Transport-Security with a long max-age, includeSubDomains and preload after auditing every subdomain.",
                )
            ],
        )
    findings: list[Finding] = []
    lowered = value.lower()
    match = re.search(r"max-age\s*=\s*(\d+)", lowered)
    max_age = int(match.group(1)) if match else 0
    if max_age == 0:
        findings.append(
            Finding(
                "HSTS max-age is zero",
                "medium",
                "A zero max-age disables the protection and can erase a previous pin.",
                value[:220],
                "Raise max-age to at least 15552000 seconds once HTTPS coverage is complete.",
            )
        )
    elif max_age < 15_552_000:
        findings.append(
            Finding(
                "HSTS max-age is short",
                "low",
                "The pin expires quickly, leaving users exposed between visits.",
                f"max-age={max_age}",
                "Use max-age of at least 15552000 seconds, preferably 31536000.",
            )
        )
    if "includesubdomains" not in lowered:
        findings.append(
            Finding(
                "HSTS does not cover subdomains",
                "low",
                "Subdomains remain reachable over HTTP even after the apex is pinned.",
                value[:220],
                "Add includeSubDomains after validating TLS on every subdomain.",
            )
        )
    if "preload" not in lowered:
        findings.append(
            Finding(
                "HSTS preload is not declared",
                "info",
                "Preload is optional, but it closes the first-visit trust gap.",
                value[:220],
                "Submit the domain to the HSTS preload list once the policy is stable.",
            )
        )
    status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        "HSTS policy is strong." if not findings else "HSTS policy needs tightening.",
        findings,
    )


@module(
    "caa_policy",
    "CAA Record Policy",
    CATEGORY,
    "Checks DNS Certification Authority Authorization records for issuance restrictions.",
    severity="low",
    passive=True,
)
def caa_policy(ctx: ScanContext) -> Outcome:
    records = ctx.doh_query(ctx.host, "CAA")
    if not records:
        return Outcome(
            "warn",
            "No CAA record is published.",
            [
                Finding(
                    "CAA record is missing",
                    "low",
                    "Any public certificate authority may issue a certificate for this name.",
                    f"name={ctx.host}; type=CAA",
                    "Publish CAA records listing only the authorities you use, and add an iodef contact.",
                )
            ],
        )
    text = " ".join(records)
    findings: list[Finding] = []
    if not re.search(r"\bissue\b", text, re.I):
        findings.append(
            Finding(
                "CAA has no issue directive",
                "low",
                "The record set does not explicitly authorize an issuing authority.",
                text[:220],
                "Add issue directives for each approved certificate authority.",
            )
        )
    if re.search(r'issue\s+"?;"?', text):
        findings.append(
            Finding(
                "CAA blocks all issuance",
                "medium",
                "An empty issue directive forbids every authority, which can break renewals.",
                text[:220],
                "Keep at least one approved authority in the issue directive.",
            )
        )
    if "iodef" not in text.lower():
        findings.append(
            Finding(
                "CAA lacks an iodef contact",
                "info",
                "No reporting address is published for policy violations.",
                text[:220],
                'Add iodef "mailto:security@example.com" for violation reports.',
            )
        )
    status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        f"CAA policy is published with {len(records)} record(s)."
        if not findings
        else "CAA policy is present but incomplete.",
        findings,
    )


@module(
    "dnssec_posture",
    "DNSSEC Posture",
    CATEGORY,
    "Looks for DNSKEY and DS records that prove the zone is signed.",
    severity="low",
    passive=True,
)
def dnssec_posture(ctx: ScanContext) -> Outcome:
    dnskey = ctx.doh_query(ctx.host, "DNSKEY")
    ds = ctx.doh_query(ctx.host, "DS")
    if not dnskey:
        return Outcome(
            "warn",
            "The zone does not publish DNSKEY records.",
            [
                Finding(
                    "DNSSEC is not enabled",
                    "low",
                    "Unsigned DNS answers can be spoofed by an on-path attacker.",
                    f"name={ctx.host}; dnskey=0; ds={len(ds)}",
                    "Enable DNSSEC at the DNS provider and publish the DS record at the registrar.",
                )
            ],
        )
    findings: list[Finding] = []
    if not ds:
        findings.append(
            Finding(
                "DNSKEY exists without a parent DS record",
                "low",
                "The chain of trust is incomplete, so validating resolvers cannot authenticate the zone.",
                f"dnskey={len(dnskey)}; ds=0",
                "Publish the DS record at the registrar and verify the chain with a validating resolver.",
            )
        )
    status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        f"DNSSEC is published with {len(dnskey)} DNSKEY record(s)."
        if not findings
        else "DNSSEC is partially configured.",
        findings,
    )


@module(
    "wildcard_dns",
    "Wildcard DNS Resolution",
    CATEGORY,
    "Resolves a random label to detect wildcard DNS that can mask subdomain takeover.",
    severity="medium",
    passive=False,
)
def wildcard_dns(ctx: ScanContext) -> Outcome:
    label = f"cm-wildcard-{secrets.token_hex(5)}.{ctx.host}"
    addresses = ctx.doh_query(label, "A")
    if not addresses:
        addresses = ctx.doh_query(label, "AAAA")
    if not addresses:
        return Outcome("pass", "Random labels do not resolve; wildcard DNS is not active.")
    return Outcome(
        "warn",
        "Wildcard DNS resolves every label.",
        [
            Finding(
                "Wildcard DNS record is active",
                "medium",
                "A non-existent label resolves, which can hide dangling subdomains and simplify phishing.",
                f"name={label}; answers={', '.join(addresses[:3])}",
                "Review wildcard records, remove unused targets and add explicit CNAME ownership checks.",
            )
        ],
    )


@module(
    "ipv6_reachability",
    "IPv6 Address Publication",
    CATEGORY,
    "Checks AAAA records and resolved addresses for IPv6 reachability gaps.",
    severity="info",
    passive=True,
)
def ipv6_reachability(ctx: ScanContext) -> Outcome:
    aaaa = ctx.doh_query(ctx.host, "AAAA")
    resolved = [address for address in ctx.system_addresses() if ":" in address]
    if aaaa or resolved:
        return Outcome(
            "pass",
            f"IPv6 is published with {len(aaaa) or len(resolved)} address(es).",
        )
    return Outcome(
        "info",
        "No IPv6 address is published.",
        [
            Finding(
                "IPv6 is not advertised",
                "info",
                "Dual-stack clients fall back to IPv4, and IPv6-only networks cannot reach the service.",
                f"name={ctx.host}; aaaa=0",
                "Publish AAAA records if the edge supports IPv6, then include the range in monitoring and firewall policy.",
            )
        ],
    )


@module(
    "redirect_chain",
    "Redirect Chain Quality",
    CATEGORY,
    "Follows the redirect chain to detect downgrades, loops, credential leaks and excessive hops.",
    severity="medium",
    passive=False,
)
def redirect_chain(ctx: ScanContext) -> Outcome:
    current = ctx.target
    chain: list[tuple[str, int, str]] = []
    seen = {current}
    for _ in range(6):
        probe = ctx.fetch("GET", current, follow=False)
        if not probe.ok:
            return Outcome(
                "info" if not chain else "warn",
                "The redirect chain could not be completed.",
                [
                    Finding(
                        "Redirect probe failed",
                        "info",
                        "The chain stopped before a final response.",
                        str(probe.error or f"status={probe.status}")[:200],
                        "Verify the first hop manually and remove unreachable redirect targets.",
                    )
                ]
                if not chain
                else [
                    Finding(
                        "Redirect chain ends in an error",
                        "low",
                        "At least one hop did not resolve to a usable response.",
                        f"last={current[:220]}; error={probe.error[:120]}",
                        "Remove broken hops and redirect directly to the canonical URL.",
                    )
                ],
            )
        location = probe.header("location")
        if probe.status not in {301, 302, 303, 307, 308} or not location:
            chain.append((current, probe.status, ""))
            break
        target = urljoin(current, location)
        chain.append((current, probe.status, target))
        if target in seen:
            return Outcome(
                "warn",
                "Redirect loop detected.",
                [
                    Finding(
                        "Redirect loop",
                        "medium",
                        "A request cycles between the same URLs and never reaches content.",
                        " -> ".join(item[0] for item in chain)[:300],
                        "Break the loop and redirect to a single canonical destination.",
                    )
                ],
            )
        seen.add(target)
        current = target
    findings: list[Finding] = []
    if len(chain) > 3:
        findings.append(
            Finding(
                "Redirect chain is longer than necessary",
                "low",
                f"{len(chain)} hops add latency and obscure the final destination.",
                " -> ".join(item[0] for item in chain)[:320],
                "Collapse intermediate redirects into one canonical 301/308 response.",
            )
        )
    for source, status, target in chain:
        if not target:
            continue
        if source.startswith("https://") and target.startswith("http://"):
            findings.append(
                Finding(
                    "Redirect downgrades HTTPS to HTTP",
                    "high",
                    "A secure request is redirected to an unencrypted destination.",
                    f"{source[:160]} -> {target[:160]}",
                    "Redirect only to HTTPS destinations and enable HSTS.",
                )
            )
        if urlsplit(target).username or urlsplit(target).password:
            findings.append(
                Finding(
                    "Redirect target embeds credentials",
                    "medium",
                    "Credentials in a Location header leak through browser history and logs.",
                    target[:220],
                    "Remove userinfo from redirect URLs and use a secure session instead.",
                )
            )
        if not ctx.same_host(target):
            findings.append(
                Finding(
                    "Redirect leaves the assessed host",
                    "info",
                    "The chain hands the visitor to a different origin.",
                    f"{source[:160]} -> {target[:160]}",
                    "Confirm the destination is intentional and documented.",
                )
            )
    status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        f"Redirect chain completed in {len(chain)} hop(s)."
        if not findings
        else "Redirect chain has quality issues.",
        findings,
    )


@module(
    "http3_advertisement",
    "HTTP/3 Advertisement",
    CATEGORY,
    "Reads Alt-Svc to confirm whether HTTP/3 is advertised by the edge.",
    severity="info",
    passive=True,
)
def http3_advertisement(ctx: ScanContext) -> Outcome:
    page = ctx.homepage()
    alt_svc = page.headers.get("alt-svc", "").strip()
    if re.search(r"h3(?:-\d+)?\s*=", alt_svc, re.I):
        return Outcome("pass", "HTTP/3 is advertised through Alt-Svc.")
    return Outcome(
        "info",
        "HTTP/3 is not advertised.",
        [
            Finding(
                "Alt-Svc does not advertise HTTP/3",
                "info",
                "Clients stay on HTTP/2 or HTTP/1.1, missing the reduced-latency transport.",
                f"alt-svc={alt_svc[:180] or '<missing>'}",
                "Advertise h3 through Alt-Svc once the edge and origin support QUIC consistently.",
            )
        ],
    )


@module(
    "permissions_policy",
    "Permissions Policy Review",
    CATEGORY,
    "Inspects Permissions-Policy for powerful browser features delegated to any origin.",
    severity="low",
    passive=True,
)
def permissions_policy(ctx: ScanContext) -> Outcome:
    page = ctx.homepage()
    policy = page.headers.get("permissions-policy", "").strip()
    legacy = page.headers.get("feature-policy", "").strip()
    if not policy:
        findings = [
            Finding(
                "Permissions-Policy is missing",
                "low",
                "Powerful browser features are not explicitly restricted.",
                f"feature-policy={legacy[:180] or '<missing>'}",
                "Send Permissions-Policy with explicit self or none allowlists for camera, microphone, geolocation and payment.",
            )
        ]
        return Outcome("warn", "No Permissions-Policy header is present.", findings)
    findings: list[Finding] = []
    wildcard_directives = []
    for directive in policy.split(","):
        name, _, value = directive.partition("=")
        feature = name.strip().lower()
        if not feature:
            continue
        if "*" in value:
            wildcard_directives.append(feature)
    if wildcard_directives:
        findings.append(
            Finding(
                "Permissions-Policy delegates features to any origin",
                "medium",
                "Powerful capabilities are available to embedded third-party frames.",
                ", ".join(sorted(set(wildcard_directives))[:8]),
                "Replace * with explicit origins, or use () to disable unused features.",
            )
        )
    if legacy and "permissions-policy" not in page.headers:
        findings.append(
            Finding(
                "Only the deprecated Feature-Policy is present",
                "info",
                "Modern browsers ignore Feature-Policy in favour of Permissions-Policy.",
                legacy[:200],
                "Migrate every directive to Permissions-Policy syntax.",
            )
        )
    status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        "Permissions-Policy is restrictive." if not findings else "Permissions-Policy needs review.",
        findings,
    )

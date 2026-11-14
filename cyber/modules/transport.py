from __future__ import annotations

import re
import socket
import ssl
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit

from ..engine import ScanContext
from ..models import Finding, Outcome
from ..registry import module, verdict

CATEGORY = "Transport & DNS"


def _severity(status: str) -> str:
    return status


def _cert_time(value: str) -> float | None:
    try:
        return ssl.cert_time_to_seconds(value)
    except (ValueError, TypeError):
        return None


@module(
    "tls_certificate",
    "TLS Certificate Health",
    CATEGORY,
    "Inspects the served certificate, trust chain, hostname coverage and expiry window.",
    severity="high",
    passive=True,
)
def tls_certificate(ctx: ScanContext) -> Outcome:
    if ctx.scheme != "https":
        return Outcome(
            "skipped",
            "Target uses plain HTTP; certificate inspection is not applicable.",
        )
    info = ctx.tls_info()
    if not info.get("ok"):
        return Outcome(
            "fail",
            "TLS handshake failed.",
            [
                Finding(
                    "TLS endpoint unavailable",
                    "high",
                    "The HTTPS endpoint did not complete a TLS handshake.",
                    str(info.get("error") or "")[:220],
                    "Confirm the certificate, listener and SNI configuration for this hostname.",
                )
            ],
        )
    findings: list[Finding] = []
    cert = info.get("cert") or {}
    not_after = _cert_time(str(cert.get("notAfter") or ""))
    not_before = _cert_time(str(cert.get("notBefore") or ""))
    now = time.time()
    days_left = int((not_after - now) / 86400) if not_after else None
    subject = ", ".join(
        "=".join(part) for group in cert.get("subject", ()) for part in group
    )
    issuer = ", ".join(
        "=".join(part) for group in cert.get("issuer", ()) for part in group
    )
    sans = [value for kind, value in cert.get("subjectAltName", ()) if kind == "DNS"]
    if not_after is not None:
        if not_after < now:
            findings.append(
                Finding(
                    "Certificate has expired",
                    "critical",
                    "Browsers will reject the certificate until it is renewed.",
                    f"notAfter={cert.get('notAfter')}",
                    "Renew the certificate and reload the web server.",
                )
            )
        elif days_left is not None and days_left < 14:
            findings.append(
                Finding(
                    "Certificate expires imminently",
                    "high",
                    f"The certificate expires in {days_left} day(s).",
                    f"notAfter={cert.get('notAfter')}",
                    "Renew and deploy the certificate before the expiry window.",
                )
            )
        elif days_left is not None and days_left < 30:
            findings.append(
                Finding(
                    "Certificate expiry approaching",
                    "medium",
                    f"The certificate expires in {days_left} day(s).",
                    f"notAfter={cert.get('notAfter')}",
                    "Schedule certificate renewal.",
                )
            )
    if not info.get("hostname_match", True):
        findings.append(
            Finding(
                "Certificate does not match the hostname",
                "high",
                "The certificate SAN/CN does not cover the requested host.",
                f"host={ctx.host}; sans={', '.join(sans[:8]) or 'none'}",
                "Issue a certificate that includes the exact hostname in its SAN list.",
            )
        )
    if not info.get("verified"):
        self_signed = bool(subject and subject == issuer)
        findings.append(
            Finding(
                "Certificate chain is not trusted",
                "high" if self_signed else "medium",
                "The certificate did not validate against the system trust store.",
                str(info.get("verify_error") or "")[:220],
                "Install a publicly trusted certificate or distribute the private CA root.",
            )
        )
    if not_before is not None and not_before > now + 300:
        findings.append(
            Finding(
                "Certificate is not yet valid",
                "high",
                "The certificate's NotBefore timestamp is in the future.",
                f"notBefore={cert.get('notBefore')}",
                "Check the host clock and reissue the certificate.",
            )
        )
    status = verdict(findings) if findings else "pass"
    summary = (
        f"Certificate valid for {days_left} more day(s)."
        if days_left is not None and not findings
        else "Certificate findings require attention."
        if findings
        else "Certificate metadata collected."
    )
    return Outcome(status, summary, findings)


@module(
    "tls_protocols",
    "TLS Protocol & Cipher Posture",
    CATEGORY,
    "Tests which TLS versions the endpoint accepts and reports deprecated protocol support.",
    severity="high",
    passive=True,
)
def tls_protocols(ctx: ScanContext) -> Outcome:
    if ctx.scheme != "https":
        return Outcome("skipped", "Plain HTTP target; TLS protocol probing is not applicable.")
    port = ctx.port
    supported: list[str] = []
    unsupported: list[str] = []
    versions = [
        ("TLS 1.0", getattr(ssl.TLSVersion, "TLSv1", None), "high"),
        ("TLS 1.1", getattr(ssl.TLSVersion, "TLSv1_1", None), "medium"),
        ("TLS 1.2", getattr(ssl.TLSVersion, "TLSv1_2", None), "pass"),
        ("TLS 1.3", getattr(ssl.TLSVersion, "TLSv1_3", None), "pass"),
    ]
    for label, version, _ in versions:
        if version is None:
            continue
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.minimum_version = version
            context.maximum_version = version
            with socket.create_connection((ctx.host, port), timeout=6) as raw:
                with context.wrap_socket(raw, server_hostname=ctx.host) as tls:
                    if tls.version():
                        supported.append(label)
        except (OSError, ssl.SSLError, ValueError):
            unsupported.append(label)
    findings: list[Finding] = []
    if "TLS 1.0" in supported:
        findings.append(
            Finding(
                "Deprecated TLS 1.0 is accepted",
                "high",
                "TLS 1.0 is obsolete and no longer considered secure.",
                "Accepted protocol: TLS 1.0",
                "Disable TLS 1.0 and require TLS 1.2 or newer.",
            )
        )
    if "TLS 1.1" in supported:
        findings.append(
            Finding(
                "Deprecated TLS 1.1 is accepted",
                "medium",
                "TLS 1.1 has known weaknesses and should not be offered.",
                "Accepted protocol: TLS 1.1",
                "Disable TLS 1.1 and keep TLS 1.2/1.3 only.",
            )
        )
    info = ctx.tls_info()
    cipher = info.get("cipher")
    if cipher and re.search(r"(RC4|3DES|DES|EXPORT|NULL|MD5)", str(cipher[0]), re.I):
        findings.append(
            Finding(
                "Weak negotiated cipher suite",
                "high",
                "The negotiated cipher is deprecated or cryptographically weak.",
                f"cipher={cipher[0]}",
                "Configure a modern AEAD cipher suite policy.",
            )
        )
    status = verdict(findings) if findings else "pass"
    summary = (
        "Accepted: " + ", ".join(supported)
        if supported
        else "No TLS protocol completed a handshake."
    )
    return Outcome(status, summary, findings)


@module(
    "https_enforcement",
    "HTTPS Enforcement",
    CATEGORY,
    "Checks whether the site is reachable over plain HTTP and whether it redirects to HTTPS.",
    severity="high",
    passive=False,
)
def https_enforcement(ctx: ScanContext) -> Outcome:
    target = urlsplit(ctx.target)
    path = target.path or "/"
    if target.query:
        path += "?" + target.query
    findings: list[Finding] = []
    if ctx.scheme == "http":
        https_url = urlunsplit(("https", target.netloc, path, "", ""))
        probe = ctx.fetch("GET", https_url, follow=False)
        if probe.ok and probe.status < 500:
            findings.append(
                Finding(
                    "Site is served over plain HTTP",
                    "high",
                    "The target was requested over HTTP and HTTPS is available.",
                    f"https_status={probe.status}",
                    "Redirect all HTTP traffic to HTTPS and enable HSTS.",
                )
            )
        else:
            findings.append(
                Finding(
                    "No working HTTPS endpoint detected",
                    "high",
                    "The target uses HTTP and an HTTPS request did not succeed.",
                    str(probe.error or f"https_status={probe.status}")[:180],
                    "Install a valid certificate and serve the application over HTTPS.",
                )
            )
    else:
        http_url = urlunsplit(("http", target.netloc, path, "", ""))
        probe = ctx.fetch("GET", http_url, follow=False)
        if probe.ok:
            location = probe.header("location")
            if probe.status in {301, 302, 307, 308} and location.lower().startswith(
                "https://"
            ):
                pass
            elif probe.status >= 400 and probe.status not in {401, 403, 404}:
                findings.append(
                    Finding(
                        "Plain HTTP returns a server error",
                        "low",
                        "HTTP is still accepted by the listener but returned an error.",
                        f"http_status={probe.status}",
                        "Close port 80 or redirect every request to HTTPS.",
                    )
                )
            else:
                findings.append(
                    Finding(
                        "Plain HTTP is served without a redirect",
                        "high",
                        "The same content is reachable over unencrypted HTTP.",
                        f"http_status={probe.status}",
                        "Return a 301/308 redirect to the HTTPS URL on port 80.",
                    )
                )
        else:
            pass
    status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        "HTTPS enforcement is configured correctly."
        if not findings
        else "HTTP traffic is not strictly redirected to HTTPS.",
        findings,
    )


@module(
    "security_headers",
    "Security Header Baseline",
    CATEGORY,
    "Audits HSTS, CSP, frame protection, MIME sniffing, referrer and permissions headers.",
    severity="medium",
    passive=True,
)
def security_headers(ctx: ScanContext) -> Outcome:
    page = ctx.homepage()
    headers = page.headers
    findings: list[Finding] = []

    def missing(name: str, label: str, severity: str, remediation: str) -> None:
        if not headers.get(name):
            findings.append(
                Finding(
                    f"Missing {label} header",
                    severity,
                    f"The response does not include the {label} header.",
                    f"header={name}",
                    remediation,
                )
            )

    if ctx.scheme == "https":
        missing(
            "strict-transport-security",
            "Strict-Transport-Security",
            "medium",
            "Add Strict-Transport-Security with a long max-age and includeSubDomains after validating HTTPS coverage.",
        )
    missing(
        "content-security-policy",
        "Content-Security-Policy",
        "medium",
        "Define a restrictive Content-Security-Policy and roll it out in report-only mode first.",
    )
    if not headers.get("x-frame-options") and "frame-ancestors" not in headers.get(
        "content-security-policy", ""
    ).lower():
        findings.append(
            Finding(
                "Clickjacking protection is absent",
                "medium",
                "Neither X-Frame-Options nor a CSP frame-ancestors directive is present.",
                "x-frame-options=<missing>",
                "Set X-Frame-Options: DENY or CSP frame-ancestors 'none'.",
            )
        )
    missing(
        "x-content-type-options",
        "X-Content-Type-Options",
        "low",
        "Set X-Content-Type-Options: nosniff on every response.",
    )
    missing(
        "referrer-policy",
        "Referrer-Policy",
        "low",
        "Set Referrer-Policy to strict-origin-when-cross-origin or a stricter policy.",
    )
    missing(
        "permissions-policy",
        "Permissions-Policy",
        "low",
        "Disable unneeded browser features with a Permissions-Policy header.",
    )
    status = verdict(findings) if findings else "pass"
    summary = (
        "All baseline security headers are present."
        if not findings
        else f"{len(findings)} security header gap(s) detected."
    )
    return Outcome(status, summary, findings)


@module(
    "csp_quality",
    "Content Security Policy Quality",
    CATEGORY,
    "Reviews CSP directives for unsafe-inline, unsafe-eval, wildcards and missing hardening.",
    severity="medium",
    passive=True,
)
def csp_quality(ctx: ScanContext) -> Outcome:
    page = ctx.homepage()
    csp = page.headers.get("content-security-policy", "")
    if not csp:
        return Outcome(
            "warn",
            "No Content-Security-Policy is present.",
            [
                Finding(
                    "Content-Security-Policy is missing",
                    "medium",
                    "Without CSP the browser has no policy-level mitigation for injected script.",
                    "content-security-policy=<missing>",
                    "Deploy a restrictive CSP with nonce or hash-based script allowlisting.",
                )
            ],
        )
    lowered = csp.lower()
    findings: list[Finding] = []
    if "unsafe-inline" in lowered:
        findings.append(
            Finding(
                "CSP allows unsafe-inline",
                "medium",
                "Inline script execution weakens the XSS mitigation value of CSP.",
                csp[:300],
                "Replace inline handlers with nonce or hash allowlisting.",
            )
        )
    if "unsafe-eval" in lowered:
        findings.append(
            Finding(
                "CSP allows unsafe-eval",
                "medium",
                "Dynamic code evaluation remains available to injected script.",
                csp[:300],
                "Remove eval and new Function usage, then drop unsafe-eval.",
            )
        )
    script_directive = ""
    for part in csp.split(";"):
        if part.strip().lower().startswith("script-src"):
            script_directive = part.strip()
            break
    if script_directive and re.search(r"(^|\s)(\*|http:)(\s|$)", script_directive):
        findings.append(
            Finding(
                "CSP script source is overly broad",
                "high",
                "script-src permits any host or plain HTTP sources.",
                script_directive[:220],
                "Restrict script-src to explicit HTTPS origins and trusted nonces.",
            )
        )
    if "default-src" not in lowered and "script-src" not in lowered:
        findings.append(
            Finding(
                "CSP lacks a script default",
                "medium",
                "No default-src or script-src directive controls script loading.",
                csp[:220],
                "Add a default-src 'self' baseline and a dedicated script-src.",
            )
        )
    if "object-src" not in lowered:
        findings.append(
            Finding(
                "CSP does not restrict object-src",
                "low",
                "Legacy plugin content may be loaded from unintended origins.",
                csp[:220],
                "Add object-src 'none'.",
            )
        )
    if "frame-ancestors" not in lowered:
        findings.append(
            Finding(
                "CSP lacks frame-ancestors",
                "low",
                "Framing protection is not expressed in the policy.",
                csp[:220],
                "Add frame-ancestors 'none' or a finite allowlist.",
            )
        )
    if "upgrade-insecure-requests" not in lowered:
        findings.append(
            Finding(
                "CSP does not upgrade insecure requests",
                "info",
                "Legacy HTTP subresources are not automatically upgraded.",
                csp[:220],
                "Add upgrade-insecure-requests when all subresources support HTTPS.",
            )
        )
    status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        "CSP is present and uses a restrictive policy."
        if not findings
        else "CSP is present but contains weaker directives.",
        findings,
    )


@module(
    "dns_hygiene",
    "DNS Hygiene & Takeover Signals",
    CATEGORY,
    "Resolves A/AAAA/CNAME/MX records and reviews dangling-service takeover indicators.",
    severity="high",
    passive=True,
)
def dns_hygiene(ctx: ScanContext) -> Outcome:
    addresses = ctx.system_addresses()
    cnames = ctx.doh_query(ctx.host, "CNAME")
    mx = ctx.doh_query(ctx.host, "MX")
    aaaa = [value for value in ctx.doh_query(ctx.host, "AAAA") if ":" in value]
    findings: list[Finding] = []
    takeover_services = {
        "github.io": ("There isn't a GitHub Pages site here",),
        "herokuapp.com": ("No such app", "heroku | no such app"),
        "s3.amazonaws.com": ("NoSuchBucket",),
        "azurewebsites.net": ("404 Web Site not found",),
        "cloudfront.net": ("Bad request", "ERROR: The request could not be satisfied"),
        "netlify.app": ("Not Found - Request ID",),
        "vercel.app": ("DEPLOYMENT_NOT_FOUND",),
        "surge.sh": ("project not found",),
        "bitbucket.io": ("Repository not found",),
        "readme.io": ("Project not found",),
        "trafficmanager.net": ("404 Not Found",),
    }
    takeover = False
    for cname in cnames:
        lowered = cname.lower().rstrip(".")
        for service, signatures in takeover_services.items():
            if lowered.endswith(service):
                page = ctx.homepage()
                body = page.html[:120_000]
                if any(signature.lower() in body.lower() for signature in signatures):
                    takeover = True
                    findings.append(
                        Finding(
                            "Possible subdomain takeover",
                            "high",
                            f"The CNAME points to {service} and the response matches an unclaimed-service page.",
                            f"cname={cname}; http_status={page.status}",
                            "Claim the upstream resource, or remove the dangling CNAME immediately.",
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            "External CNAME dependency",
                            "info",
                            f"The hostname is an alias for {service}.",
                            f"cname={cname}",
                            "Inventory the dependency and make sure the upstream resource stays claimed.",
                        )
                    )
    if len(addresses) > 4:
        findings.append(
            Finding(
                "Large address footprint",
                "info",
                f"The hostname resolves to {len(addresses)} addresses.",
                ", ".join(addresses[:8]),
                "Confirm that every address is an intentional edge or origin.",
            )
        )
    if not aaaa:
        findings.append(
            Finding(
                "No AAAA record returned",
                "info",
                "The hostname has no IPv6 address in public DNS.",
                "AAAA=<none>",
                "Add IPv6 where the service is expected to support it.",
            )
        )
    if mx:
        findings.append(
            Finding(
                "Mail exchangers are exposed in DNS",
                "info",
                "MX records are visible and should be covered by the email authentication review.",
                ", ".join(mx[:5]),
                "Confirm SPF, DKIM and DMARC posture for every mail exchanger.",
            )
        )
    if ctx.private_target:
        findings.append(
            Finding(
                "Target resolves to a private address",
                "info",
                "The assessment is running against an internal or local address.",
                ", ".join(addresses[:6]),
                "Keep this scan scoped to authorized internal assets only.",
            )
        )
    status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        "DNS records are consistent."
        if not findings
        else f"DNS review produced {len(findings)} observation(s).",
        findings,
    )


@module(
    "email_auth",
    "Email Authentication Posture",
    CATEGORY,
    "Checks SPF, DMARC and common DKIM selectors for the target domain.",
    severity="medium",
    passive=True,
)
def email_auth(ctx: ScanContext) -> Outcome:
    if re.fullmatch(r"[0-9a-fA-F:.]+", ctx.host):
        return Outcome("skipped", "IP address target; email authentication is not applicable.")
    txt = [value.lower() for value in ctx.txt_records(ctx.host)]
    spf = [value for value in txt if value.startswith("v=spf1")]
    dmarc = [
        value
        for value in ctx.txt_records("_dmarc." + ctx.host)
        if value.lower().startswith("v=dmarc1")
    ]
    findings: list[Finding] = []
    if not spf:
        findings.append(
            Finding(
                "SPF record is missing",
                "medium",
                "The domain publishes no SPF policy, so senders are not constrained.",
                f"TXT {ctx.host}=<no v=spf1>",
                "Publish a single SPF record that ends with -all after inventorying senders.",
            )
        )
    else:
        if len(spf) > 1:
            findings.append(
                Finding(
                    "Multiple SPF records",
                    "medium",
                    "More than one SPF record breaks policy evaluation.",
                    f"records={len(spf)}",
                    "Merge the mechanisms into a single SPF record.",
                )
            )
        record = spf[0]
        if re.search(r"(^|\s)\+all(\s|$)", record):
            findings.append(
                Finding(
                    "SPF allows every sender",
                    "high",
                    "The +all mechanism authorizes any host to send mail as this domain.",
                    record[:300],
                    "Replace +all with an explicit sender inventory and -all.",
                )
            )
        elif re.search(r"(^|\s)\?all(\s|$)", record):
            findings.append(
                Finding(
                    "SPF uses a neutral policy",
                    "medium",
                    "?all provides no effective rejection signal.",
                    record[:300],
                    "Use -all once all legitimate senders are covered.",
                )
            )
        if record.count("include:") > 8 or record.count("ip4:") > 20:
            findings.append(
                Finding(
                    "SPF lookup complexity is high",
                    "low",
                    "A large SPF record can exceed DNS lookup limits and break delivery.",
                    record[:300],
                    "Reduce includes, use an SPF flattening service, or split sending domains.",
                )
            )
    if not dmarc:
        findings.append(
            Finding(
                "DMARC record is missing",
                "medium",
                "The domain has no DMARC policy for alignment and reporting.",
                f"TXT _dmarc.{ctx.host}=<missing>",
                "Publish v=DMARC1 with p=none for monitoring, then move to quarantine/reject.",
            )
        )
    else:
        record = " ".join(dmarc)
        if "p=none" in record:
            findings.append(
                Finding(
                    "DMARC is in monitoring mode",
                    "low",
                    "The policy does not instruct receivers to quarantine or reject failures.",
                    record[:300],
                    "Move to p=quarantine and then p=reject after monitoring.",
                )
            )
        if "rua=" not in record and "ruf=" not in record:
            findings.append(
                Finding(
                    "DMARC has no reporting address",
                    "low",
                    "Without rua/ruf reports, authentication failures are invisible.",
                    record[:300],
                    "Add a monitored rua= mailbox.",
                )
            )
    dkim_found = []
    for selector in ("default", "google", "selector1", "selector2", "mail", "k1"):
        records = ctx.txt_records(f"{selector}._domainkey.{ctx.host}")
        if any("v=dkim1" in value.lower() or "k=rsa" in value.lower() for value in records):
            dkim_found.append(selector)
    if not dkim_found:
        findings.append(
            Finding(
                "No DKIM selector detected",
                "low",
                "Common DKIM selectors did not return a key record.",
                "selectors=default,google,selector1,selector2,mail,k1",
                "Confirm the active selector and publish a 2048-bit DKIM key.",
            )
        )
    status = verdict(findings) if findings else "pass"
    return Outcome(
        status,
        "SPF, DMARC and DKIM posture is healthy."
        if not findings
        else f"Email authentication review produced {len(findings)} finding(s).",
        findings,
    )


@module(
    "http2_support",
    "HTTP/2 & Modern Transport",
    CATEGORY,
    "Checks ALPN negotiation and Alt-Svc for modern HTTP transport support.",
    severity="low",
    passive=True,
)
def http2_support(ctx: ScanContext) -> Outcome:
    if ctx.scheme != "https":
        return Outcome("skipped", "Plain HTTP target; ALPN inspection requires HTTPS.")
    info = ctx.tls_info()
    alpn = str(info.get("alpn") or "")
    page = ctx.homepage()
    alt_svc = page.headers.get("alt-svc", "")
    findings: list[Finding] = []
    if alpn == "h2":
        findings.append(
            Finding(
                "HTTP/2 negotiated",
                "info",
                "The TLS handshake selected HTTP/2 via ALPN.",
                f"alpn={alpn}",
                "Keep the modern transport configuration.",
            )
        )
    elif alpn == "http/1.1":
        findings.append(
            Finding(
                "HTTP/1.1 only",
                "low",
                "The endpoint did not negotiate HTTP/2.",
                f"alpn={alpn}",
                "Enable HTTP/2 on the TLS listener where compatible.",
            )
        )
    else:
        findings.append(
            Finding(
                "ALPN not advertised",
                "info",
                "No ALPN protocol was returned, so HTTP/2 could not be confirmed.",
                f"alpn={alpn or 'none'}",
                "Confirm the proxy and TLS configuration support ALPN.",
            )
        )
    if alt_svc:
        findings.append(
            Finding(
                "Alt-Svc advertised",
                "info",
                "The response advertises an alternate service endpoint.",
                alt_svc[:220],
                "Review the alternate endpoint and its TLS posture.",
            )
        )
    status = verdict(findings) if findings else "pass"
    return Outcome(status, f"Negotiated transport: {alpn or 'not advertised'}.", findings)

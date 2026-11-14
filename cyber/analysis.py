"""Findings analysis for the Sentinel console.

The analyser turns a stored assessment into an operator-facing report:
executive summary, score trend for the same host, OWASP Top 10 mapping,
prioritised findings and a remediation roadmap. It is intentionally
deterministic and side-effect free so exports and UI views always agree.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from . import db
from .config import MODULE_COUNT

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
SEVERITY_SCORE = {"critical": 10, "high": 7, "medium": 4, "low": 2, "info": 1}

OWASP_TOP10 = [
    ("A01:2021", "Broken Access Control"),
    ("A02:2021", "Cryptographic Failures"),
    ("A03:2021", "Injection"),
    ("A04:2021", "Insecure Design"),
    ("A05:2021", "Security Misconfiguration"),
    ("A06:2021", "Vulnerable and Outdated Components"),
    ("A07:2021", "Identification and Authentication Failures"),
    ("A08:2021", "Software and Data Integrity Failures"),
    ("A09:2021", "Security Logging and Monitoring Failures"),
    ("A10:2021", "Server-Side Request Forgery"),
]

CATEGORY_DEFAULT = {
    "Transport & DNS": "A02:2021",
    "Session & Browser": "A05:2021",
    "Exposure & Discovery": "A05:2021",
    "Injection & Input": "A03:2021",
    "Edge & Defense": "A05:2021",
}

# Explicit overrides keep the mapping stable as the module library grows.
MODULE_OWASP: dict[str, str] = {}


def _assign(owasp_id: str, *module_ids: str) -> None:
    for module_id in module_ids:
        MODULE_OWASP[module_id] = owasp_id


_assign(
    "A01:2021",
    "admin_surface",
    "directory_listing",
    "path_traversal",
    "path_traversal_encoded",
    "cors_policy",
    "csrf_protection",
    "cross_origin_isolation",
    "http_methods",
    "open_redirect",
    "redirect_chain",
    "server_status_page",
    "database_admin",
    "wildcard_dns",
)
_assign(
    "A02:2021",
    "tls_certificate",
    "tls_protocols",
    "https_enforcement",
    "hsts_policy",
    "caa_policy",
    "dnssec_posture",
    "cookie_security",
    "cookie_prefixes",
    "mixed_content",
    "ipv6_reachability",
    "http3_advertisement",
)
_assign(
    "A03:2021",
    "reflected_xss",
    "dom_xss",
    "xss_attribute",
    "xss_header",
    "xss_json",
    "xss_polyglot",
    "xss_svg",
    "xss_css",
    "xss_meta_refresh",
    "xss_iframe_srcdoc",
    "xss_markdown",
    "xss_event_handler",
    "sql_injection",
    "sql_boolean",
    "sql_union",
    "sql_time",
    "sql_header",
    "sql_evasion",
    "sql_order_by",
    "sql_error_fingerprint",
    "sql_json",
    "nosql_injection",
    "nosql_boolean",
    "nosql_regex",
    "ldap_injection",
    "ldap_blind",
    "xpath_injection",
    "ssti",
    "csti_expression",
    "xxe",
    "crlf_injection",
    "host_header_injection",
    "cookie_reflection",
    "hpp",
)
_assign(
    "A04:2021",
    "cache_policy",
    "cache_deception",
    "framing_defense",
    "iframe_sandbox",
    "csp_quality",
    "permissions_policy",
    "bot_management",
)
_assign(
    "A05:2021",
    "security_headers",
    "dns_hygiene",
    "http2_support",
    "robots_disclosure",
    "security_txt",
    "sitemap_exposure",
    "debug_exposure",
    "api_docs_exposure",
    "graphql_introspection",
    "waf_detection",
    "swagger_ui",
    "metrics_exposure",
    "log_exposure",
    "server_signature",
    "trace_axd",
    "docker_registry",
    "kubernetes_api",
    "crossdomain_policy",
    "security_header_consistency",
)
_assign(
    "A06:2021",
    "sri_integrity",
    "package_metadata",
    "source_map_exposure",
    "compression_breach",
)
_assign(
    "A07:2021",
    "email_auth",
    "password_autocomplete",
    "referrer_leakage",
)
_assign(
    "A08:2021",
    "git_exposure",
    "env_exposure",
    "backup_exposure",
    "secret_leakage",
    "ci_config_exposure",
    "editor_backup_files",
)
_assign(
    "A09:2021",
    "error_disclosure",
)
_assign(
    "A10:2021",
    "open_redirect",
    "redirect_chain",
)

# Last assignment wins for ids listed more than once; restore the primary
# category deliberately for the overlap above.
MODULE_OWASP.update(
    {
        "open_redirect": "A01:2021",
        "redirect_chain": "A01:2021",
        "server_status_page": "A01:2021",
        "package_metadata": "A06:2021",
        "source_map_exposure": "A06:2021",
        "sri_integrity": "A06:2021",
        "compression_breach": "A06:2021",
        "ci_config_exposure": "A08:2021",
        "editor_backup_files": "A08:2021",
        "error_disclosure": "A09:2021",
        "log_exposure": "A05:2021",
        "metrics_exposure": "A05:2021",
    }
)

OWASP_NAME = dict(OWASP_TOP10)


def owasp_for(module_id: str, category: str) -> str:
    return MODULE_OWASP.get(module_id) or CATEGORY_DEFAULT.get(category, "A05:2021")


def _risk_band(score: int | None) -> tuple[str, str]:
    if score is None:
        return "Menunggu", "Belum ada skor"
    if score < 45:
        return "Kritis", "Perlu tindakan segera"
    if score < 62:
        return "Tinggi", "Eksposur berarti"
    if score < 74:
        return "Sedang", "Perlu perbaikan terarah"
    if score < 84:
        return "Baik", "Postur terkendali"
    return "Kuat", "Pertahankan kontrol"


def _latest_completed_scan() -> dict[str, Any] | None:
    for scan in db.list_scans(limit=200):
        if scan.get("status") == "completed" and scan.get("score") is not None:
            return scan
    return None


def _trend(scan: dict[str, Any]) -> dict[str, Any]:
    rows = [
        row
        for row in db.list_scans(limit=200)
        if row.get("host") == scan.get("host")
        and row.get("score") is not None
        and row.get("status") in {"completed", "cancelled"}
    ][:8]
    rows.reverse()
    points = [
        {
            "id": row["id"],
            "score": int(row["score"]),
            "grade": row.get("grade") or "—",
            "created_at": row.get("created_at"),
            "findings": row.get("finding_count", 0),
        }
        for row in rows
    ]
    if len(points) >= 2:
        delta = points[-1]["score"] - points[-2]["score"]
    elif points:
        delta = points[-1]["score"] - 100
    else:
        delta = 0
    direction = "up" if delta > 0 else "down" if delta < 0 else "flat"
    return {"direction": direction, "delta": delta, "points": points}


def _priority(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    enriched: list[dict[str, Any]] = []
    for finding in findings:
        severity = str(finding.get("severity", "info")).lower()
        weight = SEVERITY_SCORE.get(severity, 1)
        boost = 2 if finding.get("evidence") else 0
        boost += 1 if finding.get("remediation") else 0
        enriched.append(
            {
                **finding,
                "severity": severity,
                "priority": weight * 10 + boost,
                "owasp": owasp_for(
                    str(finding.get("module_id", "")),
                    str(finding.get("category", "")),
                ),
            }
        )
    enriched.sort(
        key=lambda item: (
            SEVERITY_ORDER.index(item["severity"])
            if item["severity"] in SEVERITY_ORDER
            else 9,
            -item["priority"],
            str(item.get("title", "")),
        )
    )
    return enriched


def _roadmap(priority: list[dict[str, Any]]) -> list[dict[str, Any]]:
    phases = [
        {
            "window": "0–7 hari",
            "title": "Hentikan paparan kritis",
            "detail": "Tutup temuan yang dapat langsung dieksploitasi atau membocorkan kredensial.",
            "severities": {"critical", "high"},
        },
        {
            "window": "8–30 hari",
            "title": "Perkuat kontrol inti",
            "detail": "Rapikan konfigurasi, sesi, dan validasi input yang menurunkan skor.",
            "severities": {"medium"},
        },
        {
            "window": "31–90 hari",
            "title": "Hardening berkelanjutan",
            "detail": "Tutup celah rendah, tambahkan pemantauan, lalu jadwalkan asesmen ulang.",
            "severities": {"low", "info"},
        },
    ]
    for phase in phases:
        items = [
            finding
            for finding in priority
            if finding["severity"] in phase["severities"]
        ]
        phase["count"] = len(items)
        phase["items"] = [
            {
                "title": item["title"],
                "severity": item["severity"],
                "module_id": item.get("module_id", ""),
                "owasp": item["owasp"],
                "remediation": item.get("remediation", ""),
            }
            for item in items[:5]
        ]
    return phases


def _coverage(scan: dict[str, Any]) -> dict[str, Any]:
    modules = scan.get("modules") or []
    statuses = Counter(str(item.get("status", "info")) for item in modules)
    categories: dict[str, int] = {}
    for item in modules:
        name = str(item.get("category") or "Lainnya")
        categories[name] = categories.get(name, 0) + 1
    selected = scan.get("modules_json") or []
    expected = len(selected) or len(modules)
    completed = statuses.get("pass", 0) + statuses.get("warn", 0) + statuses.get("fail", 0)
    completed += statuses.get("info", 0)
    return {
        "modules_total": len(modules),
        "modules_expected": expected,
        "modules_completed": completed,
        "pass": statuses.get("pass", 0),
        "warn": statuses.get("warn", 0),
        "fail": statuses.get("fail", 0),
        "info": statuses.get("info", 0),
        "skipped": statuses.get("skipped", 0),
        "error": statuses.get("error", 0),
        "completion": round(completed / max(1, expected) * 100),
        "categories": [
            {"name": name, "modules": count}
            for name, count in categories.items()
        ],
        "library_size": MODULE_COUNT,
    }


def build_analysis(scan_id: str | None = None) -> dict[str, Any] | None:
    scan = None
    if scan_id:
        scan = db.scan_detail(scan_id)
    else:
        latest = _latest_completed_scan()
        if latest:
            scan = db.scan_detail(latest["id"])
    if not scan:
        return None

    findings = scan.get("findings") or []
    modules = scan.get("modules") or []
    module_categories = {
        str(item.get("module_id")): str(item.get("category") or "")
        for item in modules
    }
    for finding in findings:
        finding["category"] = module_categories.get(str(finding.get("module_id")), "")

    priority = _priority(findings)
    severity = Counter(item["severity"] for item in priority)
    urgent = severity.get("critical", 0) + severity.get("high", 0)
    score = scan.get("score")
    band, band_note = _risk_band(score)
    trend = _trend(scan)
    coverage = _coverage(scan)

    owasp: list[dict[str, Any]] = []
    for owasp_id, name in OWASP_TOP10:
        items = [item for item in priority if item["owasp"] == owasp_id]
        owasp.append(
            {
                "id": owasp_id,
                "name": name,
                "findings": len(items),
                "critical": sum(1 for item in items if item["severity"] == "critical"),
                "high": sum(1 for item in items if item["severity"] == "high"),
                "modules": sorted({str(item.get("module_id", "")) for item in items}),
            }
        )

    if score is None:
        narrative = (
            "Asesmen belum menyelesaikan perhitungan skor. Tinjau modul yang berjalan "
            "dan jalankan ulang asesmen setelah seluruh probe selesai."
        )
    elif urgent:
        narrative = (
            f"Postur {scan.get('host')} berada pada band {band.lower()}. "
            f"{urgent} temuan kritis atau tinggi menuntut tindakan pada pekan ini, "
            f"sementara {severity.get('medium', 0)} temuan sedang membentuk risiko struktural. "
            "Prioritaskan pemangkasan paparan eksternal sebelum hardening jangka panjang."
        )
    elif severity.get("medium", 0):
        narrative = (
            f"Postur {scan.get('host')} berada pada band {band.lower()}. Tidak ada temuan "
            "kritis atau tinggi, tetapi konfigurasi menengah masih memperlebar permukaan serangan. "
            "Fokuskan perbaikan pada kontrol sesi, header, dan validasi input."
        )
    else:
        narrative = (
            f"Postur {scan.get('host')} berada pada band {band.lower()}. Tidak ada temuan "
            "berisiko tinggi pada cakupan modul ini. Pertahankan disiplin konfigurasi dan "
            "jadwalkan asesmen ulang untuk menangkap regresi."
        )

    top = priority[0] if priority else None
    headline = (
        f"{urgent} prioritas tinggi pada {scan.get('host')}"
        if urgent
        else f"Tidak ada temuan kritis pada {scan.get('host')}"
    )
    if top and urgent:
        headline = f"{top['title']} memimpin {urgent} prioritas"

    return {
        "scan": {
            "id": scan.get("id"),
            "target": scan.get("target"),
            "host": scan.get("host"),
            "status": scan.get("status"),
            "score": score,
            "grade": scan.get("grade"),
            "created_at": scan.get("created_at"),
            "finished_at": scan.get("finished_at"),
            "requested_by": scan.get("requested_by"),
            "note": scan.get("authorization_note", ""),
            "requests": (scan.get("summary") or {}).get("requests", 0),
            "elapsed_ms": (scan.get("summary") or {}).get("elapsed_ms", 0),
        },
        "executive": {
            "headline": headline,
            "narrative": narrative,
            "band": band,
            "band_note": band_note,
            "score": score,
            "grade": scan.get("grade") or "—",
            "urgent": urgent,
            "total_findings": len(priority),
            "severity": {key: severity.get(key, 0) for key in SEVERITY_ORDER},
            "modules": len(modules),
            "requests": (scan.get("summary") or {}).get("requests", 0),
        },
        "trend": trend,
        "owasp": owasp,
        "priority": priority[:8],
        "roadmap": _roadmap(priority),
        "coverage": coverage,
    }

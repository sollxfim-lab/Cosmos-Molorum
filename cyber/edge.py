"""Edge and origin visibility for assessments behind a CDN or WAF.

This module is passive and advisory. It reads stored scan results, identifies
the visible edge provider, and explains what the assessment could and could not
observe. It deliberately does not implement WAF evasion, challenge solving, IP
rotation, host-header origin discovery or direct-to-origin scanning.
"""

from __future__ import annotations

from typing import Any

PROVIDERS: dict[str, tuple[str, ...]] = {
    "Cloudflare": ("cloudflare", "cf-ray", "cf-cache-status", "__cf_bm"),
    "Akamai": ("akamai", "ak_bmsc", "x-akamai"),
    "Imperva": ("imperva", "incap_ses", "visid_incap", "x-iinfo"),
    "Sucuri": ("sucuri", "x-sucuri-id"),
    "AWS WAF": ("aws waf", "x-amzn-waf", "aws-waf-token"),
    "Fastly": ("fastly", "x-fastly"),
    "DataDome": ("datadome", "x-datadome"),
    "PerimeterX": ("perimeterx", "x-px"),
}

ORIGIN_MARKERS = (
    ("x-origin", "Header X-Origin"),
    ("x-backend", "Header X-Backend"),
    ("x-served-by", "Header X-Served-By"),
    ("x-real-ip", "Header X-Real-IP"),
    ("x-forwarded-server", "Header X-Forwarded-Server"),
    ("x-host", "Header X-Host"),
    ("via=", "Header Via"),
    ("server=", "Header Server"),
)

CDN_WORDS = ("cloudflare", "akamai", "imperva", "sucuri", "fastly", "datadome", "perimeterx")


def _snippet(text: str, token: str = "", size: int = 110) -> str:
    cleaned = " ".join(str(text or "").split())
    if token:
        index = cleaned.lower().find(token.lower())
        if index >= 0:
            cleaned = cleaned[max(0, index - 24) : index + size]
    return cleaned[:200]


def _positive_items(scan: dict[str, Any]) -> list[tuple[str, str]]:
    """Return only evidence that positively indicates an edge product.

    Negative modules sometimes mention header names they looked for. Those
    strings must not be treated as proof that the header was present.
    """
    items: list[tuple[str, str]] = []
    for finding in scan.get("findings") or []:
        module_id = str(finding.get("module_id") or "")
        title = str(finding.get("title") or "")
        evidence = str(finding.get("evidence") or "")
        detail = str(finding.get("detail") or "")
        lowered = f"{title} {evidence} {detail}".lower()
        if module_id == "waf_detection" and (
            "edge protection" in title.lower() or "challenged" in title.lower()
        ):
            items.append((module_id, f"{evidence} {detail}".strip()))
        elif module_id == "cache_deception" and "cf-cache-status" in lowered:
            items.append((module_id, evidence))
        elif "cloudflare" in lowered and module_id not in {
            "bot_management",
            "waf_detection",
        }:
            items.append((module_id, evidence or detail))
    for module in scan.get("modules") or []:
        if str(module.get("module_id") or "") != "bot_management":
            continue
        summary = str(module.get("summary") or "")
        if summary.lower().startswith("bot management signals:"):
            items.append(("bot_management", summary))
    return items


def _provider_signals(items: list[tuple[str, str]]) -> tuple[list[str], list[dict[str, Any]]]:
    providers: set[str] = set()
    signals: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for module_id, text in items:
        lowered = text.lower()
        for provider, markers in PROVIDERS.items():
            marker = next((item for item in markers if item in lowered), "")
            if not marker:
                continue
            key = (provider, _snippet(text, marker))
            if key in seen:
                continue
            seen.add(key)
            providers.add(provider)
            signals.append(
                {
                    "provider": provider,
                    "source": module_id,
                    "evidence": _snippet(text, marker),
                }
            )
    signals.sort(key=lambda item: (item["provider"], item["source"]))
    return sorted(providers), signals[:10]


def _origin_signals(scan: dict[str, Any]) -> list[dict[str, str]]:
    signals: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for finding in scan.get("findings") or []:
        module_id = str(finding.get("module_id") or "")
        text = " ".join(
            [
                str(finding.get("title") or ""),
                str(finding.get("evidence") or ""),
                str(finding.get("detail") or ""),
            ]
        ).lower()
        for token, label in ORIGIN_MARKERS:
            index = text.find(token)
            if index < 0:
                continue
            snippet = _snippet(text, token)
            if token in {"server=", "via="} and any(word in snippet for word in CDN_WORDS):
                continue
            key = (label, snippet)
            if key in seen:
                continue
            seen.add(key)
            signals.append(
                {
                    "label": label,
                    "source": module_id,
                    "evidence": snippet,
                }
            )
    return signals[:6]


def build_edge_profile(scan: dict[str, Any]) -> dict[str, Any]:
    items = _positive_items(scan)
    providers, signals = _provider_signals(items)
    challenge = any(
        "challenged" in str(finding.get("title") or "").lower()
        for finding in scan.get("findings") or []
        if str(finding.get("module_id") or "") == "waf_detection"
    )
    detected = bool(providers) or challenge
    primary = providers[0] if providers else ("Edge WAF" if challenge else "")
    origin = _origin_signals(scan)

    if providers:
        summary = (
            f"Target berada di belakang {', '.join(providers)}. Pemindaian ini "
            "menilai respons edge, bukan origin secara langsung."
        )
    elif challenge:
        summary = (
            "Edge WAF merespons tantangan, tetapi provider tidak dapat dipastikan "
            "dari data yang tersimpan. Pemindaian ini menilai edge, bukan origin."
        )
    else:
        summary = (
            "Tidak ada indikasi CDN atau WAF dari data pemindaian. Ini tidak "
            "berarti origin tidak terlindungi atau sepenuhnya terlihat."
        )

    limitations = [
        "Probe dapat diblokir, dinormalkan, atau dilayani dari cache sebelum mencapai origin.",
        "Temuan negatif di edge bukan bukti bahwa origin aman.",
        "Konten cache dapat menampilkan versi lama atau respons yang berbeda dari origin.",
        "Pemindaian tidak mencoba melewati challenge, WAF, atau rate limit.",
    ]
    if origin:
        limitations.append(
            "Sinyal origin di bawah hanya petunjuk pasif; validasi hanya pada origin yang tercakup izin."
        )

    return {
        "detected": detected,
        "providers": providers,
        "primary": primary,
        "challenge": challenge,
        "confidence": "Tinggi" if providers else "Sedang" if challenge else "—",
        "scope": "edge" if detected else "direct-or-unknown",
        "summary": summary,
        "signals": signals,
        "origin_signals": origin,
        "origin_note": (
            "Indikasi origin ditemukan pada bukti pasif. Jangan menebak atau memindai "
            "IP origin; gunakan origin resmi yang disediakan pemilik aset."
            if origin
            else "Tidak ada indikasi origin yang terlihat dari respons edge. Ini normal "
            "untuk konfigurasi CDN yang rapi dan bukan bukti origin terekspos."
        ),
        "authorized_paths": [
            "Minta pemilik aset memasukkan egress scanner ke allowlist WAF untuk jendela uji tertulis.",
            "Uji origin atau staging resmi yang disediakan pemilik, bukan IP origin yang ditebak.",
            "Gunakan Cloudflare Access service token atau mTLS bila disediakan.",
            "Catat scope, tanggal, dan header uji pada audit, lalu bandingkan hasil edge dan origin.",
        ],
        "prohibited": [
            "Jangan menyelesaikan challenge atau meniru browser untuk melewati proteksi.",
            "Jangan memalsukan header, merotasi IP, atau memindai origin tanpa izin.",
            "Jangan menganggap 403, 429, atau halaman challenge sebagai kerentanan.",
            "Jangan menyerang infrastruktur Cloudflare atau layanan pihak ketiga.",
        ],
        "bounty": {
            "mode": "authorized-only",
            "scope_note": (
                "Mode bug bounty tidak mengubah batas teknis. Hanya aset yang tercantum "
                "dalam scope program yang boleh diuji, dengan aturan rate limit dan data "
                "uji dari pemilik program."
            ),
            "checklist": [
                "Pastikan aset target tercantum dalam scope program dan simpan bukti izinnya.",
                "Gunakan akun uji dan data sintetis yang diizinkan oleh program.",
                "Hentikan pengujian bila menyentuh data nyata atau mengganggu layanan.",
                "Catat waktu, request ID, dan kondisi edge saat temuan muncul.",
            ],
            "report_fields": [
                "Program, aset dalam scope, dan referensi izin atau aturan program.",
                "Langkah reproduksi minimal dengan dampak yang dapat dibuktikan.",
                "Batas uji: tanpa perubahan data dan tanpa akses data pihak lain.",
                "Bukti yang sudah diredaksi; jangan sertakan token atau data pribadi.",
            ],
            "disclosure": [
                "Ikuti kebijakan disclosure program; jangan publikasi sebelum ada izin.",
                "Pisahkan observasi edge dari kerentanan yang dapat dieksploitasi.",
                "Kirim bukti secukupnya dan redaksi cookie, token, serta data sensitif.",
            ],
            "not_findings": [
                "Halaman challenge, 403, 429, atau blokir WAF bukan kerentanan dengan sendirinya.",
                "Fingerprint Cloudflare bukan celah pada Cloudflare.",
                "Perbedaan respons cache belum tentu cache poisoning; perlu bukti dampak.",
            ],
        },
        "limitations": limitations,
    }

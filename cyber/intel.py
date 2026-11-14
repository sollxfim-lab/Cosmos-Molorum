"""Exploitability intelligence for the Sentinel console.

The intelligence layer is deliberately local, deterministic and advisory.
It turns stored findings into an operator briefing: exploitability and impact
scores, the findings most worth fixing first, plausible attack paths, component
fingerprints, MITRE ATT&CK coverage and safe (non-destructive) verification
recipes. It never executes an exploit and never contacts a third party.
"""

from __future__ import annotations

import re
from collections import Counter
from typing import Any
from urllib.parse import urlsplit

from . import db
from . import modules as _modules  # noqa: F401  (populates the registry)
from .edge import build_edge_profile
from .registry import MODULES

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
SEVERITY_EXPLOIT = {"critical": 84, "high": 72, "medium": 48, "low": 26, "info": 8}
SEVERITY_IMPACT = {"critical": 95, "high": 82, "medium": 55, "low": 30, "info": 10}

PASSIVE = {spec.id: spec.passive for spec in MODULES}

CWE_NAMES = {
    "CWE-16": "Configuration",
    "CWE-22": "Path Traversal",
    "CWE-79": "Cross-site Scripting",
    "CWE-89": "SQL Injection",
    "CWE-90": "LDAP Injection",
    "CWE-91": "XML Injection",
    "CWE-94": "Code Injection",
    "CWE-113": "HTTP Header Injection",
    "CWE-200": "Information Exposure",
    "CWE-290": "Authentication Spoofing",
    "CWE-319": "Cleartext Transmission",
    "CWE-345": "Data Authenticity",
    "CWE-352": "Cross-Site Request Forgery",
    "CWE-524": "Sensitive Cache Exposure",
    "CWE-538": "Sensitive File Exposure",
    "CWE-601": "Open Redirect",
    "CWE-611": "XML External Entity",
    "CWE-614": "Insecure Session Cookie",
    "CWE-693": "Protection Mechanism Failure",
    "CWE-942": "Permissive CORS Policy",
    "CWE-943": "NoSQL Injection",
}

GROUPS: dict[str, dict[str, Any]] = {
    "sql": {
        "cwe": "CWE-89",
        "capec": "CAPEC-66",
        "technique": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "stage": "Initial Access",
        "vector": "Parameter aplikasi yang menyusun kueri",
        "impact": "Baca atau ubah data, potensi eksekusi kueri lanjutan",
        "preconditions": [
            "Parameter dapat dijangkau dari luar atau dengan sesi rendah.",
            "Input digabungkan ke kueri tanpa parameterisasi.",
        ],
        "verify": "Bandingkan respons baseline dengan satu marker kutip. Jangan gunakan UNION, SLEEP, atau dump data.",
        "boost": 10,
    },
    "nosql": {
        "cwe": "CWE-943",
        "capec": "CAPEC-66",
        "technique": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "stage": "Initial Access",
        "vector": "Objek JSON atau operator kueri",
        "impact": "Bypass filter, enumerasi dokumen, atau perubahan data",
        "preconditions": [
            "Endpoint menerima objek JSON yang dapat menyisipkan operator.",
            "Validasi tipe tidak ketat.",
        ],
        "verify": "Kirim satu operator non-destruktif dan bandingkan jumlah atau bentuk respons.",
        "boost": 9,
    },
    "ldap": {
        "cwe": "CWE-90",
        "capec": "CAPEC-66",
        "technique": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "stage": "Initial Access",
        "vector": "Filter direktori",
        "impact": "Bypass autentikasi atau enumerasi entri direktori",
        "preconditions": ["Input masuk ke filter LDAP tanpa escapes."],
        "verify": "Gunakan satu karakter wildcard dan bandingkan respons autentikasi.",
        "boost": 7,
    },
    "xpath": {
        "cwe": "CWE-91",
        "capec": "CAPEC-66",
        "technique": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "stage": "Initial Access",
        "vector": "Ekspresi XPath",
        "impact": "Bypass autentikasi atau baca node XML",
        "preconditions": ["Input masuk ke ekspresi XPath."],
        "verify": "Kirim satu ekspresi selalu-benar dan bandingkan hasil.",
        "boost": 6,
    },
    "xss": {
        "cwe": "CWE-79",
        "capec": "CAPEC-63",
        "technique": "T1059.007",
        "technique_name": "JavaScript/JScript",
        "stage": "Execution",
        "vector": "Konteks HTML, atribut, atau DOM",
        "impact": "Eksekusi skrip di sesi korban dan pengambilalihan sesi",
        "preconditions": [
            "Input dipantulkan tanpa encoding sesuai konteks.",
            "Korban membuka tautan atau halaman yang terpengaruh.",
        ],
        "verify": "Kirim marker unik dan periksa apakah marker muncul verbatim di HTML.",
        "boost": 8,
    },
    "template": {
        "cwe": "CWE-94",
        "capec": "CAPEC-242",
        "technique": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "stage": "Initial Access",
        "vector": "Ekspresi template sisi server",
        "impact": "Eksekusi ekspresi dan potensi eksekusi kode",
        "preconditions": ["Input dievaluasi oleh mesin template."],
        "verify": "Gunakan ekspresi aritmetika sederhana dan bandingkan hasil render.",
        "boost": 11,
    },
    "xxe": {
        "cwe": "CWE-611",
        "capec": "CAPEC-228",
        "technique": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "stage": "Initial Access",
        "vector": "Parser XML",
        "impact": "Baca file lokal, SSRF, atau denial of service",
        "preconditions": ["Parser memproses entitas eksternal."],
        "verify": "Gunakan entitas internal non-sensitif dan periksa hasil parsing.",
        "boost": 10,
    },
    "path": {
        "cwe": "CWE-22",
        "capec": "CAPEC-126",
        "technique": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "stage": "Initial Access",
        "vector": "Nama file atau path",
        "impact": "Baca file di luar direktori yang diizinkan",
        "preconditions": ["Path pengguna digabungkan tanpa normalisasi."],
        "verify": "Gunakan satu traversal menuju file uji yang tidak sensitif; jangan baca kredensial.",
        "boost": 9,
    },
    "redirect": {
        "cwe": "CWE-601",
        "capec": "",
        "technique": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "stage": "Initial Access",
        "vector": "Parameter navigasi",
        "impact": "Phishing atau pencurian token lewat domain tepercaya",
        "preconditions": ["Tujuan eksternal diterima tanpa allowlist."],
        "verify": "Gunakan domain contoh unik dan periksa header Location.",
        "boost": 4,
    },
    "header": {
        "cwe": "CWE-113",
        "capec": "",
        "technique": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "stage": "Initial Access",
        "vector": "Header HTTP",
        "impact": "Cache poisoning, split respons, atau routing yang salah",
        "preconditions": ["Nilai header masuk ke respons atau routing."],
        "verify": "Kirim satu karakter pemisah dan periksa header respons.",
        "boost": 6,
    },
    "csrf": {
        "cwe": "CWE-352",
        "capec": "CAPEC-62",
        "technique": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "stage": "Initial Access",
        "vector": "Aksi yang mengubah state",
        "impact": "Perubahan data atas nama korban",
        "preconditions": ["Tidak ada token anti-CSRF atau pemeriksaan origin."],
        "verify": "Periksa keberadaan token dan atribut SameSite; jangan ubah data.",
        "boost": 5,
    },
    "cors": {
        "cwe": "CWE-942",
        "capec": "",
        "technique": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "stage": "Collection",
        "vector": "Origin lintas domain",
        "impact": "Baca respons terautentikasi dari origin penyerang",
        "preconditions": ["Origin sembarang dipantulkan dengan kredensial."],
        "verify": "Kirim satu Origin contoh dan periksa header ACAO/ACAC.",
        "boost": 6,
    },
    "cookie": {
        "cwe": "CWE-614",
        "capec": "CAPEC-60",
        "technique": "T1539",
        "technique_name": "Steal Web Session Cookie",
        "stage": "Credential Access",
        "vector": "Cookie sesi",
        "impact": "Penyalahgunaan sesi bila cookie bocor",
        "preconditions": ["Cookie tidak memakai Secure, HttpOnly, atau SameSite memadai."],
        "verify": "Periksa atribut Set-Cookie; jangan menyalin nilai sesi.",
        "boost": 4,
    },
    "transport": {
        "cwe": "CWE-319",
        "capec": "CAPEC-117",
        "technique": "T1040",
        "technique_name": "Network Sniffing",
        "stage": "Collection",
        "vector": "Kanal transport",
        "impact": "Intersepsi kredensial atau data",
        "preconditions": ["TLS lemah, tidak dipaksakan, atau konfigurasi DNS rentan."],
        "verify": "Periksa protokol dan sertifikat dengan klien standar; jangan melakukan downgrade.",
        "boost": 2,
    },
    "email": {
        "cwe": "CWE-290",
        "capec": "",
        "technique": "T1598",
        "technique_name": "Phishing for Information",
        "stage": "Reconnaissance",
        "vector": "DNS email",
        "impact": "Pemalsuan pengirim dan phishing",
        "preconditions": ["SPF, DKIM, atau DMARC tidak menolak pesan palsu."],
        "verify": "Periksa record DNS saja; jangan kirim email uji.",
        "boost": 1,
    },
    "headers": {
        "cwe": "CWE-693",
        "capec": "",
        "technique": "T1592",
        "technique_name": "Gather Victim Host Information",
        "stage": "Reconnaissance",
        "vector": "Konfigurasi respons",
        "impact": "Memperlemah pertahanan berlapis dan memudahkan serangan klien",
        "preconditions": ["Header pertahanan tidak ada atau tidak konsisten."],
        "verify": "Baca header respons dan bandingkan dengan baseline kebijakan.",
        "boost": 1,
    },
    "secret": {
        "cwe": "CWE-538",
        "capec": "CAPEC-116",
        "technique": "T1552",
        "technique_name": "Unsecured Credentials",
        "stage": "Credential Access",
        "vector": "File, metadata, atau repositori publik",
        "impact": "Kredensial atau konfigurasi internal terbuka",
        "preconditions": ["Artefak sensitif dapat diakses dari web."],
        "verify": "Periksa keberadaan file dengan satu GET dan jangan membuka isinya bila sensitif.",
        "boost": 10,
    },
    "discovery": {
        "cwe": "CWE-200",
        "capec": "CAPEC-116",
        "technique": "T1592",
        "technique_name": "Gather Victim Host Information",
        "stage": "Reconnaissance",
        "vector": "Permukaan yang dapat dipetakan",
        "impact": "Memperluas pengetahuan penyerang dan jalur serangan",
        "preconditions": ["Halaman atau endpoint terbuka tanpa kebutuhan bisnis."],
        "verify": "Petakan path dengan GET tunggal dan catat status; jangan brute force.",
        "boost": 3,
    },
    "config": {
        "cwe": "CWE-16",
        "capec": "",
        "technique": "T1592",
        "technique_name": "Gather Victim Host Information",
        "stage": "Reconnaissance",
        "vector": "Konfigurasi aplikasi",
        "impact": "Kontrol yang lemah atau tidak konsisten",
        "preconditions": ["Konfigurasi menyimpang dari baseline."],
        "verify": "Bandingkan konfigurasi dengan baseline dan dokumentasi vendor.",
        "boost": 1,
    },
    "cache": {
        "cwe": "CWE-524",
        "capec": "",
        "technique": "T1530",
        "technique_name": "Data from Information Repositories",
        "stage": "Collection",
        "vector": "Cache bersama",
        "impact": "Kebocoran respons terautentikasi ke pengguna lain",
        "preconditions": ["Cache menyimpan respons sensitif tanpa pembeda."],
        "verify": "Periksa header cache dan perilaku kunci cache; jangan mengotori cache produksi.",
        "boost": 3,
    },
    "integrity": {
        "cwe": "CWE-345",
        "capec": "",
        "technique": "T1195",
        "technique_name": "Supply Chain Compromise",
        "stage": "Initial Access",
        "vector": "Aset pihak ketiga",
        "impact": "Eksekusi konten dari sumber yang tidak terverifikasi",
        "preconditions": ["Aset eksternal dimuat tanpa integritas."],
        "verify": "Periksa atribut integrity dan sumber aset.",
        "boost": 3,
    },
    "edge": {
        "cwe": "CWE-693",
        "capec": "",
        "technique": "T1592",
        "technique_name": "Gather Victim Host Information",
        "stage": "Reconnaissance",
        "vector": "Lapisan edge",
        "impact": "Informasi pertahanan dan celah konsistensi",
        "preconditions": ["Konfigurasi edge dapat dipetakan."],
        "verify": "Amati header dan status edge; jangan mencoba bypass.",
        "boost": 2,
    },
    "generic": {
        "cwe": "CWE-693",
        "capec": "",
        "technique": "T1592",
        "technique_name": "Gather Victim Host Information",
        "stage": "Reconnaissance",
        "vector": "Konfigurasi umum",
        "impact": "Postur pertahanan yang perlu ditinjau",
        "preconditions": ["Temuan perlu validasi manual."],
        "verify": "Tinjau temuan dan reproduksi secara manual dengan izin.",
        "boost": 0,
    },
}

SECRET_MODULES = {
    "env_exposure",
    "git_exposure",
    "backup_exposure",
    "secret_leakage",
    "source_map_exposure",
    "package_metadata",
    "ci_config_exposure",
    "editor_backup_files",
    "log_exposure",
}
DISCOVERY_MODULES = {
    "dir_fuzz",
    "robots_disclosure",
    "sitemap_exposure",
    "directory_listing",
    "admin_surface",
    "debug_exposure",
    "api_docs_exposure",
    "swagger_ui",
    "graphql_introspection",
    "metrics_exposure",
    "server_status_page",
    "database_admin",
    "docker_registry",
    "kubernetes_api",
    "trace_axd",
    "server_signature",
    "error_disclosure",
    "waf_detection",
}

TECH_PATTERNS = (
    (r"cloudflare", "Cloudflare"),
    (r"\bnginx\b", "Nginx"),
    (r"\bapache\b", "Apache HTTP Server"),
    (r"microsoft-iis|\biis\b", "Microsoft IIS"),
    (r"wordpress|wp-content|wp-admin", "WordPress"),
    (r"drupal", "Drupal"),
    (r"joomla", "Joomla"),
    (r"laravel", "Laravel"),
    (r"django", "Django"),
    (r"rails|ruby on rails", "Ruby on Rails"),
    (r"express\.js|\bexpress\b", "Express"),
    (r"next\.js", "Next.js"),
    (r"react", "React"),
    (r"angular", "Angular"),
    (r"vue\.js|\bvue\b", "Vue.js"),
    (r"php", "PHP"),
    (r"asp\.net", "ASP.NET"),
    (r"tomcat", "Apache Tomcat"),
    (r"spring", "Spring"),
    (r"jenkins", "Jenkins"),
    (r"graphql", "GraphQL"),
    (r"swagger|openapi", "OpenAPI/Swagger"),
    (r"kubernetes", "Kubernetes"),
    (r"docker", "Docker"),
    (r"jenkins", "Jenkins"),
    (r"gitlab", "GitLab"),
    (r"github", "GitHub"),
    (r"amazon|aws", "AWS"),
    (r"azure", "Azure"),
    (r"google cloud|\bgcp\b", "Google Cloud"),
    (r"keycloak", "Keycloak"),
    (r"elasticsearch", "Elasticsearch"),
    (r"redis", "Redis"),
    (r"mysql", "MySQL"),
    (r"postgres", "PostgreSQL"),
    (r"sqlite", "SQLite"),
)

PATH_SPECS = (
    {
        "id": "credentials",
        "name": "Panen kredensial menuju panel",
        "trigger": SECRET_MODULES,
        "stages": [
            ("Eksposur artefak", "File konfigurasi, cadangan, atau metadata terbuka."),
            ("Panen kredensial", "Kredensial atau token internal dapat dipulihkan."),
            ("Akses panel", "Kredensial dipakai pada permukaan administratif."),
        ],
        "breakpoint": "Hapus artefak dari web root, rotasi kredensial, lalu batasi panel dengan jaringan tepercaya.",
        "impact": "Kontrol penuh atas panel atau data",
    },
    {
        "id": "injection",
        "name": "Injeksi menuju akses data",
        "trigger": {"sql", "nosql", "ldap", "xpath", "template", "xxe"},
        "stages": [
            ("Validasi lemah", "Input mencapai interpreter tanpa parameterisasi."),
            ("Injeksi", "Marker menghasilkan error atau perubahan perilaku."),
            ("Akses data", "Data atau perintah dapat dibaca di luar batas aplikasi."),
        ],
        "breakpoint": "Parameterisasi kueri, normalisasi input, dan cabut hak database yang berlebihan.",
        "impact": "Kebocoran atau perubahan data",
    },
    {
        "id": "browser",
        "name": "Pengambilalihan sesi browser",
        "trigger": {"xss"},
        "stages": [
            ("Refleksi skrip", "Marker muncul verbatim di respons HTML."),
            ("Eksekusi klien", "Skrip berjalan pada konteks pengguna."),
            ("Penyalahgunaan sesi", "Token atau aksi pengguna dapat diambil alih."),
        ],
        "breakpoint": "Terapkan encoding sesuai konteks, CSP ketat, dan cookie HttpOnly.",
        "impact": "Pengambilalihan sesi pengguna",
    },
    {
        "id": "transport",
        "name": "Intersepsi transport",
        "trigger": {"transport"},
        "stages": [
            ("Konfigurasi lemah", "TLS, HSTS, atau DNS belum dipaksakan."),
            ("Intersepsi", "Lalu lintas dapat dibaca atau diarahkan ulang."),
            ("Penyalahgunaan kredensial", "Sesi atau kredensial dapat dipakai ulang."),
        ],
        "breakpoint": "Paksakan TLS modern, HSTS preload, dan DNSSEC pada zona yang mendukung.",
        "impact": "Kebocoran kredensial dan data",
    },
    {
        "id": "content",
        "name": "Eksploitasi konten yang dapat ditemukan",
        "trigger": DISCOVERY_MODULES,
        "stages": [
            ("Pemetaan", "Path atau endpoint tambahan dapat ditemukan."),
            ("Konten sensitif", "Konten internal atau dokumentasi terbuka."),
            ("Akses tidak sah", "Permukaan baru dipakai untuk langkah berikutnya."),
        ],
        "breakpoint": "Terapkan deny-by-default, autentikasi pada dokumentasi, dan hapus konten yang tidak dipakai.",
        "impact": "Perluasan permukaan serangan",
    },
)

ADVICE_RULES = (
    {
        "groups": {"sql", "nosql", "ldap", "xpath", "template", "xxe"},
        "title": "Tutup jalur injeksi terlebih dahulu",
        "why": "Injeksi memberi penyerang akses langsung ke data atau interpreter.",
        "action": "Parameterisasi kueri, validasi tipe, matikan pesan error database, dan uji ulang dengan marker yang sama.",
        "owner": "Tim aplikasi",
        "window": "0–7 hari",
    },
    {
        "groups": {"secret"},
        "title": "Rotasi kredensial yang terpapar",
        "why": "Artefak konfigurasi atau cadangan dapat memuat kredensial yang masih berlaku.",
        "action": "Hapus artefak, rotasi kredensial dan token, lalu audit akses panel.",
        "owner": "Tim operasi",
        "window": "0–7 hari",
    },
    {
        "groups": {"xss"},
        "title": "Hentikan eksekusi skrip di browser",
        "why": "Refleksi tanpa encoding memungkinkan pencurian sesi dan aksi atas nama pengguna.",
        "action": "Terapkan encoding kontekstual, CSP berbasis nonce, dan cookie HttpOnly/SameSite.",
        "owner": "Tim aplikasi",
        "window": "0–7 hari",
    },
    {
        "groups": {"path"},
        "title": "Kunci akses file",
        "why": "Traversal membuka file di luar direktori yang diizinkan.",
        "action": "Gunakan allowlist nama file, normalisasi path, dan pindahkan file sensitif dari web root.",
        "owner": "Tim aplikasi",
        "window": "0–7 hari",
    },
    {
        "groups": {"transport"},
        "title": "Perkuat transport dan DNS",
        "why": "Konfigurasi transport yang lemah memudahkan intersepsi dan downgrade.",
        "action": "Aktifkan TLS 1.2+, HSTS, dan periksa rantai sertifikat serta record email.",
        "owner": "Tim infrastruktur",
        "window": "8–30 hari",
    },
    {
        "groups": {"discovery"},
        "title": "Pangkas permukaan yang dapat dipetakan",
        "why": "Dokumentasi, metrik, dan path cadangan mempercepat langkah penyerang.",
        "action": "Terapkan deny-by-default, autentikasi pada dokumentasi, dan hapus path yang tidak dipakai.",
        "owner": "Tim operasi",
        "window": "8–30 hari",
    },
    {
        "groups": {"headers", "cors", "cookie", "cache", "config", "edge", "integrity", "redirect", "header", "csrf", "email"},
        "title": "Rapikan kontrol pertahanan berlapis",
        "why": "Kontrol yang tidak konsisten menurunkan efektivitas pertahanan lain.",
        "action": "Samakan kebijakan header, cookie, CORS, dan cache di seluruh layanan.",
        "owner": "Tim platform",
        "window": "31–90 hari",
    },
)


def _group(module_id: str, category: str) -> str:
    mid = (module_id or "").lower()
    if mid == "cookie_reflection":
        return "xss"
    if mid.startswith(("sql_", "sqli")) or mid == "sql_injection":
        return "sql"
    if mid.startswith("nosql_"):
        return "nosql"
    if mid.startswith("ldap_"):
        return "ldap"
    if mid.startswith("xpath_"):
        return "xpath"
    if "xss" in mid or mid in {"csti_expression", "svg_script", "markdown_injection"}:
        return "xss"
    if mid == "ssti":
        return "template"
    if "xxe" in mid:
        return "xxe"
    if "path_traversal" in mid or "lfi" in mid:
        return "path"
    if mid == "redirect_chain":
        return "transport"
    if "redirect" in mid:
        return "redirect"
    if "crlf" in mid or "host_header" in mid or "hpp" in mid:
        return "header"
    if "csrf" in mid:
        return "csrf"
    if "cors" in mid:
        return "cors"
    if mid.startswith("cookie") or mid.startswith("referrer") or mid == "password_autocomplete":
        return "cookie"
    if mid in SECRET_MODULES:
        return "secret"
    if mid in DISCOVERY_MODULES:
        return "discovery"
    if mid.startswith(("tls_", "https_", "hsts", "caa", "dnssec", "dns_", "wildcard_dns", "ipv6", "http2", "http3", "mixed_content")):
        return "transport"
    if "email" in mid:
        return "email"
    if mid in {"security_headers", "csp_quality", "permissions_policy", "framing_defense", "iframe_sandbox", "security_header_consistency"}:
        return "headers"
    if "cache" in mid or "compression" in mid:
        return "cache"
    if "sri" in mid or "integrity" in mid:
        return "integrity"
    if "waf" in mid or "bot_management" in mid:
        return "edge"
    if mid in {"http_methods", "cross_origin_isolation", "security_txt", "crossdomain_policy", "admin_surface"}:
        return "config"
    fallback = {
        "Transport & DNS": "transport",
        "Session & Browser": "cookie",
        "Exposure & Discovery": "discovery",
        "Injection & Input": "sql",
        "Edge & Defense": "edge",
    }
    return fallback.get(category, "generic")


def _score(finding: dict[str, Any]) -> dict[str, Any]:
    module_id = str(finding.get("module_id", ""))
    category = str(finding.get("category", ""))
    severity = str(finding.get("severity", "info")).lower()
    group = _group(module_id, category)
    profile = GROUPS[group]
    evidence = str(finding.get("evidence") or "")
    title = str(finding.get("title") or "")
    passive = PASSIVE.get(module_id, False)

    exploit = SEVERITY_EXPLOIT.get(severity, 8) + profile["boost"]
    impact = SEVERITY_IMPACT.get(severity, 10)
    confidence = 55
    if evidence:
        exploit += 6
        confidence += 18
    if title:
        confidence += 8
    if passive:
        exploit -= 12
    if "public" in (evidence + title).lower() or "tanpa autentikasi" in (evidence + title).lower():
        exploit += 4
    if group in {"secret", "path", "template", "xxe", "sql"}:
        impact += 4

    exploit = max(5, min(98, exploit))
    impact = max(5, min(100, impact))
    confidence = max(30, min(95, confidence))
    risk = round(exploit * 0.5 + impact * 0.35 + confidence * 0.15)

    def label(value: int, high: str, mid: str, low: str) -> str:
        if value >= 80:
            return high
        if value >= 55:
            return mid
        return low

    return {
        "group": group,
        "cwe": profile["cwe"],
        "cwe_name": CWE_NAMES.get(profile["cwe"], ""),
        "capec": profile["capec"],
        "technique": profile["technique"],
        "technique_name": profile["technique_name"],
        "stage": profile["stage"],
        "vector": profile["vector"],
        "impact_note": profile["impact"],
        "preconditions": profile["preconditions"],
        "verify_hint": profile["verify"],
        "exploitability": exploit,
        "exploitability_label": label(exploit, "Siap dieksploitasi", "Mudah", "Perlu kondisi"),
        "impact": impact,
        "impact_label": label(impact, "Dampak berat", "Dampak berarti", "Dampak terbatas"),
        "confidence": confidence,
        "risk": risk,
    }


def _origin(scan: dict[str, Any]) -> str:
    target = str(scan.get("target") or "")
    try:
        parts = urlsplit(target)
        if parts.scheme in {"http", "https"} and parts.netloc:
            netloc = parts.netloc
            if re.fullmatch(r"[A-Za-z0-9.\-:\[\]]{1,255}", netloc):
                return f"{parts.scheme}://{netloc}"
    except ValueError:
        pass
    host = str(scan.get("host") or "example.com")
    if not re.fullmatch(r"[A-Za-z0-9.\-]{1,255}", host):
        host = "example.com"
    return f"https://{host}"


def _safe_path(evidence: str) -> str:
    for marker in ("path=", "url="):
        if marker in evidence:
            candidate = evidence.split(marker, 1)[1].split(";", 1)[0].strip().strip("'\"")
            if candidate.startswith("/"):
                candidate = re.sub(r"[^A-Za-z0-9_./?=&%~\-]", "", candidate)[:300]
                return candidate or "/"
    return "/"


def _field(evidence: str, name: str) -> str:
    match = re.search(rf"(?:^|;\s*){re.escape(name)}=([^;]+)", evidence)
    return match.group(1).strip().strip("'\"") if match else ""


def _clean_token(value: str, extra: str = "") -> str:
    allowed = re.escape(extra)
    return re.sub(rf"[^A-Za-z0-9_.\-\[\]{allowed}]", "", value)[:64]


def _verification(scan: dict[str, Any], finding: dict[str, Any], profile: dict[str, Any]) -> dict[str, Any]:
    origin = _origin(scan)
    evidence = str(finding.get("evidence") or "")
    path = _safe_path(evidence)
    url = f"{origin}{path}"
    group = profile["group"]
    param = _clean_token(_field(evidence, "param")) or "q"
    header = _clean_token(_field(evidence, "header"), "-") or "X-Forwarded-For"

    request = f"curl -sS -D - -o /dev/null --max-time 10 '{url}'"
    summary = profile["verify_hint"]
    expected = "Bandingkan status, header, dan ukuran respons dengan baseline."
    safety = "Non-destruktif: hanya GET tunggal, tanpa brute force, tanpa perubahan data, tanpa dump."

    if group == "sql":
        if _field(evidence, "header"):
            request = (
                "curl -sS -D - -o /dev/null --max-time 10 "
                f"-H \"{header}: cm-sentinel'\" '{url}'"
            )
            summary = f"Bandingkan respons baseline dengan satu marker kutip pada header {header}."
            expected = (
                "Error basis data atau perbedaan respons yang stabil menandakan header "
                "memengaruhi kueri. Jangan lanjut ke UNION, SLEEP, atau dump data."
            )
        else:
            request = (
                "curl -sS -D - -o /dev/null --max-time 10 "
                f"-G --data-urlencode \"{param}=cm-sentinel'\" '{url}'"
            )
            summary = "Bandingkan respons baseline dengan satu tanda kutip pada parameter yang sama."
            expected = (
                "Error basis data atau perbedaan ukuran/status yang stabil menandakan input "
                "memengaruhi kueri. Jangan lanjut ke UNION, SLEEP, atau dump data."
            )
        safety = "Non-destruktif: satu GET dengan satu marker kutip; tanpa UNION, SLEEP, dump, atau perubahan data."
    elif group == "xss":
        if _field(evidence, "header"):
            request = (
                "curl -sS -D - -o /dev/null --max-time 10 "
                f"-H \"{header}: <b>cm-sentinel</b>\" '{url}'"
            )
            summary = f"Kirim satu markup pasif pada header {header} dan periksa pantulan tanpa encoding."
            expected = "Marker <b>cm-sentinel</b> yang muncul verbatim menandakan refleksi HTML dari header. Jangan gunakan skrip atau event handler."
        else:
            request = (
                "curl -sS -D - -o /dev/null --max-time 10 "
                f"-G --data-urlencode \"{param}=<b>cm-sentinel</b>\" '{url}'"
            )
            summary = "Kirim satu markup pasif dan periksa apakah muncul verbatim tanpa encoding."
            expected = "Marker <b>cm-sentinel</b> yang muncul tanpa encoding menandakan refleksi HTML. Jangan gunakan skrip atau event handler."
        safety = "Non-destruktif: satu GET dengan markup pasif; tanpa skrip, event handler, atau exfiltrasi."
    elif group == "header":
        request = (
            "curl -sS -D - -o /dev/null --max-time 10 "
            f"-H \"{header}: cm-sentinel'\" '{url}'"
        )
        summary = f"Kirim satu nilai marker pada header {header} dan periksa pantulan atau perubahan respons."
        expected = "Marker yang tercermin pada header atau body menandakan input header masuk ke respons. Hentikan bila terjadi error 5xx."
    elif group == "redirect":
        request = (
            "curl -sS -D - -o /dev/null --max-time 10 "
            f"-G --data-urlencode \"{param}=https://example.invalid/cm-sentinel\" '{url}'"
        )
        summary = "Kirim satu tujuan domain contoh dan periksa header Location; jangan mengikuti redirect."
        expected = "Location menuju domain contoh menandakan tujuan eksternal diterima tanpa allowlist."
        safety = "Non-destruktif: satu GET tanpa mengikuti redirect dan tanpa mengirim kredensial."
    elif group == "cors":
        request = (
            "curl -sS -D - -o /dev/null --max-time 10 "
            f"-H \"Origin: https://example.invalid\" '{url}'"
        )
        summary = "Kirim satu Origin contoh dan periksa header ACAO/ACAC."
        expected = "ACAO yang memantulkan origin contoh bersama ACAC true menandakan akses lintas domain dengan kredensial."
        safety = "Non-destruktif: satu GET tanpa cookie atau kredensial pengguna."
    elif group == "cookie":
        summary = "Periksa atribut Set-Cookie; jangan menyalin nilai sesi."
        expected = "Atribut Secure, HttpOnly, dan SameSite yang lemah menurunkan perlindungan sesi."
        safety = "Non-destruktif: hanya membaca header respons; nilai sesi tidak disalin."
    elif group == "csrf":
        summary = "Periksa keberadaan token anti-CSRF dan atribut SameSite; jangan mengubah data."
        expected = "Form atau endpoint tanpa token dan tanpa pemeriksaan origin menandakan permintaan lintas situs dapat diterima."
        safety = "Non-destruktif: hanya GET dan pembacaan markup; tidak ada perubahan data."
    elif group == "transport":
        request = f"curl -sS -D - -o /dev/null --max-time 10 --tlsv1.2 '{url}'"
        summary = "Periksa protokol, rantai sertifikat, dan header transport dengan klien standar."
        expected = "Versi TLS lama, sertifikat tidak valid, atau HSTS yang tidak dipaksakan menandakan transport lemah."
        safety = "Non-destruktif: satu koneksi baca; tanpa downgrade atau perubahan konfigurasi."
    elif group == "path":
        summary = "Gunakan satu traversal menuju file uji yang tidak sensitif; jangan baca kredensial."
        expected = "Signature file uji yang muncul menandakan path dapat keluar dari direktori yang diizinkan."
        safety = "Non-destruktif: satu GET menuju file uji non-sensitif; tanpa membaca kredensial."
    elif group in {"secret", "discovery"}:
        expected = "Status 200 dan signature yang sesuai menandakan artefak atau path dapat diakses tanpa autentikasi."

    return {
        "summary": summary,
        "request": request,
        "expected": expected,
        "steps": [
            "Pastikan target berada dalam lingkup izin tertulis dan gunakan akun uji.",
            "Catat baseline status, header, dan ukuran respons sebelum verifikasi.",
            f"Kirim satu permintaan: {request}",
            expected,
            "Hentikan bila muncul error 5xx, perubahan data, atau tanda layanan tidak stabil.",
        ],
        "stop": "Berhenti pada tanda pertama layanan tidak stabil atau data berubah.",
        "safety": safety,
    }


def _enrich(scan: dict[str, Any], finding: dict[str, Any]) -> dict[str, Any]:
    profile = _score(finding)
    return {
        "module_id": finding.get("module_id", ""),
        "title": finding.get("title", ""),
        "severity": str(finding.get("severity", "info")).lower(),
        "detail": finding.get("detail", ""),
        "evidence": finding.get("evidence", ""),
        "remediation": finding.get("remediation", ""),
        "category": finding.get("category", ""),
        "owasp": finding.get("owasp", ""),
        **profile,
    }


def _sort_key(item: dict[str, Any]) -> tuple[Any, ...]:
    severity = item["severity"]
    return (
        SEVERITY_ORDER.index(severity) if severity in SEVERITY_ORDER else 9,
        -item["risk"],
        -item["exploitability"],
        str(item["title"]),
    )


def _components(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    texts: list[str] = []
    for finding in findings:
        texts.append(str(finding.get("title") or ""))
        texts.append(str(finding.get("detail") or ""))
        texts.append(str(finding.get("evidence") or ""))
    blob = "\n".join(texts)
    seen: dict[str, dict[str, Any]] = {}
    for pattern, name in TECH_PATTERNS:
        if name in seen:
            continue
        match_idx = blob.lower().find(name.lower())
        if match_idx < 0:
            match = re.search(pattern, blob, re.I)
            if not match:
                continue
            match_idx = match.start()
        snippet = blob[max(0, match_idx - 40) : match_idx + 80]
        confidence = "Tinggi" if any(
            token in snippet.lower() for token in ("server:", "x-powered-by", "header", "set-cookie")
        ) else "Sedang"
        seen[name] = {
            "name": name,
            "evidence": " ".join(snippet.split())[:180],
            "confidence": confidence,
        }
    return list(seen.values())[:10]


def _attack_paths(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    paths: list[dict[str, Any]] = []
    for spec in PATH_SPECS:
        trigger = spec["trigger"]
        relevant = [
            item
            for item in findings
            if item["group"] in trigger or item["module_id"] in trigger
        ]
        if not relevant:
            continue
        strongest = max(relevant, key=lambda item: item["risk"])
        paths.append(
            {
                "id": spec["id"],
                "name": spec["name"],
                "likelihood": strongest["exploitability_label"],
                "likelihood_score": strongest["exploitability"],
                "impact": spec["impact"],
                "impact_score": strongest["impact"],
                "breakpoint": spec["breakpoint"],
                "stages": [
                    {
                        "name": name,
                        "detail": detail,
                        "state": "indikasi" if index == 0 else "bersyarat",
                    }
                    for index, (name, detail) in enumerate(spec["stages"])
                ],
                "evidence": [
                    {
                        "title": item["title"],
                        "severity": item["severity"],
                        "module_id": item["module_id"],
                    }
                    for item in relevant[:4]
                ],
            }
        )
    paths.sort(key=lambda item: (-item["likelihood_score"], -item["impact_score"], item["name"]))
    return paths[:4]


def _advice(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups = {item["group"] for item in findings}
    advice: list[dict[str, Any]] = []
    for rule in ADVICE_RULES:
        if not (groups & rule["groups"]):
            continue
        related = [item for item in findings if item["group"] in rule["groups"]]
        advice.append(
            {
                "title": rule["title"],
                "why": rule["why"],
                "action": rule["action"],
                "owner": rule["owner"],
                "window": rule["window"],
                "related": len(related),
                "severity": related[0]["severity"] if related else "info",
            }
        )
        if len(advice) >= 4:
            break
    if not advice and findings:
        advice.append(
            {
                "title": "Validasi manual temuan prioritas",
                "why": "Temuan yang tersisa perlu konteks bisnis sebelum perbaikan.",
                "action": "Tinjau bukti, reproduksi dengan izin, lalu pilih perbaikan dengan dampak tertinggi.",
                "owner": "Tim keamanan",
                "window": "8–30 hari",
                "related": len(findings),
                "severity": findings[0]["severity"],
            }
        )
    return advice


def _mitre(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counts = Counter((item["technique"], item["technique_name"]) for item in findings)
    return [
        {"id": technique, "name": name, "findings": count}
        for (technique, name), count in sorted(
            counts.items(), key=lambda pair: (-pair[1], pair[0][0])
        )
    ]


def _coverage_gaps(scan: dict[str, Any]) -> list[dict[str, Any]]:
    gaps: list[dict[str, Any]] = []
    for module in scan.get("modules") or []:
        status = str(module.get("status") or "")
        if status not in {"skipped", "error"}:
            continue
        gaps.append(
            {
                "module_id": module.get("module_id", ""),
                "name": module.get("name", ""),
                "status": status,
                "reason": module.get("summary", ""),
            }
        )
    return gaps[:12]


def _posture(findings: list[dict[str, Any]], gaps: list[dict[str, Any]]) -> dict[str, Any]:
    top = findings[0] if findings else None
    exploit = top["exploitability"] if top else 0
    surface = min(100, round(15 + len(findings) * 2.5 + sum(1 for item in findings if item["severity"] in {"critical", "high"}) * 5))
    if exploit >= 80:
        label = "Siap dieksploitasi"
        note = "Satu temuan dapat langsung dipakai bila prasyarat terpenuhi."
    elif exploit >= 60:
        label = "Mudah"
        note = "Temuan utama dapat dicoba dengan usaha rendah."
    elif exploit >= 40:
        label = "Perlu kondisi"
        note = "Eksploitasi bergantung pada konteks dan kontrol yang ada."
    elif findings:
        label = "Terbatas"
        note = "Belum ada jalur eksploitasi langsung dari temuan ini."
    else:
        label = "Bersih"
        note = "Tidak ada temuan pada cakupan modul yang berjalan."
    return {
        "exploitability": exploit,
        "label": label,
        "note": note,
        "attack_surface": surface,
        "surface_label": "Luas" if surface >= 70 else "Sedang" if surface >= 40 else "Sempit",
        "operator_note": (
            f"{len(findings)} temuan dianalisis; {len(gaps)} modul tidak selesai sehingga sebagian permukaan belum terbaca."
            if gaps
            else f"{len(findings)} temuan dianalisis dan seluruh modul terpilih selesai."
        ),
    }


def _latest_completed_scan() -> dict[str, Any] | None:
    for scan in db.list_scans(limit=200):
        if scan.get("status") == "completed" and scan.get("score") is not None:
            return scan
    return None


def build_intel(scan_id: str | None = None) -> dict[str, Any] | None:
    scan = None
    if scan_id:
        scan = db.scan_detail(scan_id)
    else:
        latest = _latest_completed_scan()
        if latest:
            scan = db.scan_detail(latest["id"])
    if not scan:
        return None

    modules = scan.get("modules") or []
    categories = {
        str(item.get("module_id")): str(item.get("category") or "")
        for item in modules
    }
    from .analysis import owasp_for

    findings = []
    for finding in scan.get("findings") or []:
        module_id = str(finding.get("module_id", ""))
        finding["category"] = categories.get(module_id, "")
        enriched = _enrich(scan, finding)
        enriched["owasp"] = owasp_for(module_id, finding["category"])
        findings.append(enriched)
    findings.sort(key=_sort_key)

    unique: list[dict[str, Any]] = []
    seen: dict[tuple[str, str], dict[str, Any]] = {}
    for item in findings:
        key = (str(item.get("module_id", "")), str(item.get("title", "")))
        if key in seen:
            seen[key]["occurrences"] = int(seen[key].get("occurrences", 1)) + 1
            continue
        item["occurrences"] = 1
        seen[key] = item
        unique.append(item)

    gaps = _coverage_gaps(scan)
    posture = _posture(findings, gaps)
    edge = build_edge_profile(scan)
    best = [
        {**item, "verification": _verification(scan, item, item)}
        for item in unique[:8]
    ]
    components = _components(findings)
    paths = _attack_paths(findings)
    advice = _advice(findings)
    mitre = _mitre(findings)

    toolkit = [
        {
            "title": item["title"],
            "severity": item["severity"],
            "cwe": item["cwe"],
            "cwe_name": item.get("cwe_name", ""),
            "module_id": item["module_id"],
            "verification": item["verification"],
        }
        for item in best[:5]
    ]

    return {
        "scan": {
            "id": scan.get("id"),
            "target": scan.get("target"),
            "host": scan.get("host"),
            "status": scan.get("status"),
            "score": scan.get("score"),
            "grade": scan.get("grade"),
            "created_at": scan.get("created_at"),
            "finished_at": scan.get("finished_at"),
            "requested_by": scan.get("requested_by"),
            "note": scan.get("authorization_note", ""),
            "requests": (scan.get("summary") or {}).get("requests", 0),
            "elapsed_ms": (scan.get("summary") or {}).get("elapsed_ms", 0),
        },
        "posture": posture,
        "edge": edge,
        "best_findings": best,
        "attack_paths": paths,
        "components": components,
        "mitre": mitre,
        "advice": advice,
        "coverage_gaps": gaps,
        "toolkit": {
            "disclaimer": (
                "Toolkit ini hanya untuk asesmen yang diizinkan. Semua resep bersifat "
                "non-destruktif: satu permintaan GET, tanpa brute force, tanpa perubahan data, "
                "dan tanpa upaya menembus autentikasi."
            ),
            "items": toolkit,
        },
        "summary": {
            "findings": len(findings),
            "stages": dict(Counter(item["stage"] for item in findings)),
            "cwe": dict(Counter(item["cwe"] for item in findings)),
            "mitre": len(mitre),
            "paths": len(paths),
            "components": len(components),
            "gaps": len(gaps),
        },
    }

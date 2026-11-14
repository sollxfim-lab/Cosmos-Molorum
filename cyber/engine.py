from __future__ import annotations

import hashlib
import html
import ipaddress
import re
import socket
import ssl
import threading
import time
import warnings
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any
from urllib.parse import (
    parse_qsl,
    urlencode,
    urljoin,
    urlsplit,
    urlunsplit,
)

import httpx

from .config import (
    BLOCKED_HOSTS,
    BLOCKED_NETWORKS,
    MAX_REDIRECTS,
    MAX_RESPONSE_BYTES,
    REQUEST_DELAY_SECONDS,
    REQUEST_TIMEOUT_SECONDS,
    RESOLVE_CACHE_TTL_SECONDS,
    SCAN_REQUEST_BUDGET,
)

warnings.filterwarnings("ignore", message="Unverified HTTPS request")

REDIRECT_STATUSES = {301, 302, 303, 307, 308}
SENSITIVE_ACTION_RE = re.compile(
    r"(logout|log-out|signout|delete|remove|destroy|unsubscribe|checkout|payment|"
    r"purchase|transfer|withdraw|reset|deactivate|disable)",
    re.IGNORECASE,
)
AUTH_ACTION_RE = re.compile(
    r"(login|log-in|signin|sign-in|auth|register|signup|password|forgot|reset)",
    re.IGNORECASE,
)
TEXT_INPUT_TYPES = {
    "",
    "text",
    "search",
    "email",
    "url",
    "tel",
    "number",
    "textarea",
    "select",
}


class TargetError(ValueError):
    pass


class BudgetExceeded(RuntimeError):
    pass


class ScanStopped(RuntimeError):
    pass


def normalize_target(raw: str) -> str:
    value = (raw or "").strip()
    if not value:
        raise TargetError("Target URL is required.")
    if "://" not in value:
        value = "https://" + value
    try:
        parts = urlsplit(value)
    except ValueError as exc:
        raise TargetError(f"Invalid target URL: {exc}") from exc
    if parts.scheme not in {"http", "https"}:
        raise TargetError("Only http:// and https:// targets are supported.")
    if parts.username or parts.password:
        raise TargetError("Credentials embedded in the URL are not allowed.")
    host = (parts.hostname or "").strip().lower().rstrip(".")
    if not host:
        raise TargetError("The target URL does not contain a hostname.")
    try:
        port = parts.port
    except ValueError as exc:
        raise TargetError("The target port is invalid.") from exc
    if port is None:
        port = 443 if parts.scheme == "https" else 80
    if not 1 <= port <= 65535:
        raise TargetError("The target port must be between 1 and 65535.")
    netloc = host
    if ":" in host and not host.startswith("["):
        netloc = f"[{host}]"
    default_port = 443 if parts.scheme == "https" else 80
    if port != default_port:
        netloc = f"{netloc}:{port}"
    path = parts.path or "/"
    return urlunsplit((parts.scheme, netloc, path, parts.query, ""))


def _blocked_ip(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    if str(ip) in {"169.254.169.254", "100.100.100.200", "fd00:ec2::254"}:
        return True
    if ip.is_link_local or ip.is_multicast or ip.is_unspecified:
        return True
    for network in BLOCKED_NETWORKS:
        if ip in ipaddress.ip_network(network):
            return True
    return False


def resolve_target(host: str, port: int) -> list[str]:
    if host.lower() in BLOCKED_HOSTS:
        raise TargetError("Target host is a blocked metadata or instance endpoint.")
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise TargetError(f"DNS resolution failed for {host}: {exc}") from exc
    addresses: list[str] = []
    for info in infos:
        address = str(info[4][0]).split("%")[0]
        if address not in addresses:
            addresses.append(address)
    if not addresses:
        raise TargetError("The target host did not resolve to any address.")
    for address in addresses:
        if _blocked_ip(address):
            raise TargetError(
                "The target resolves to a blocked link-local, metadata or multicast address."
            )
    return addresses


def address_is_private(addresses: list[str]) -> bool:
    for address in addresses:
        try:
            if ipaddress.ip_address(address).is_private:
                return True
        except ValueError:
            continue
    return False


@dataclass
class Probe:
    ok: bool
    url: str
    status: int = 0
    headers: httpx.Headers = field(default_factory=httpx.Headers)
    text: str = ""
    raw: bytes = b""
    history: list[str] = field(default_factory=list)
    error: str = ""
    elapsed_ms: int = 0
    truncated: bool = False
    method: str = "GET"

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name, default)

    @property
    def content_type(self) -> str:
        return self.header("content-type").split(";")[0].strip().lower()

    @property
    def is_html(self) -> bool:
        return "html" in self.content_type or self.text.lstrip().lower().startswith(
            "<!doctype html"
        )

    @property
    def is_json(self) -> bool:
        return "json" in self.content_type or self.text.lstrip().startswith(("{", "["))

    @property
    def final_url(self) -> str:
        return self.url


@dataclass
class InputPoint:
    method: str
    url: str
    param: str
    value: str
    form: dict[str, str] | None = None
    source: str = ""


@dataclass
class PageSnapshot:
    url: str
    status: int
    headers: httpx.Headers
    html: str
    title: str = ""
    links: list[str] = field(default_factory=list)
    forms: list[dict[str, Any]] = field(default_factory=list)
    scripts: list[str] = field(default_factory=list)
    inline_scripts: list[str] = field(default_factory=list)
    meta_generator: str = ""
    comments: list[str] = field(default_factory=list)
    base_url: str = ""


class _PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title_parts: list[str] = []
        self._in_title = False
        self.links: list[str] = []
        self.forms: list[dict[str, Any]] = []
        self._form: dict[str, Any] | None = None
        self.scripts: list[str] = []
        self.inline_scripts: list[str] = []
        self._in_script = False
        self._script_buffer: list[str] = []
        self.meta_generator = ""
        self.comments: list[str] = []
        self.base_href = ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key.lower(): (value or "") for key, value in attrs}
        tag = tag.lower()
        if tag == "a" and values.get("href"):
            self.links.append(values["href"])
        elif tag == "area" and values.get("href"):
            self.links.append(values["href"])
        elif tag == "base" and values.get("href") and not self.base_href:
            self.base_href = values["href"]
        elif tag == "meta" and values.get("name", "").lower() == "generator":
            self.meta_generator = values.get("content", "")
        elif tag == "form":
            self._form = {
                "action": values.get("action", ""),
                "method": (values.get("method") or "GET").upper(),
                "enctype": values.get("enctype", ""),
                "fields": [],
            }
        elif tag in {"input", "textarea", "select"} and self._form is not None:
            name = values.get("name", "")
            if not name:
                return
            field_type = values.get("type", tag if tag != "input" else "text").lower()
            self._form["fields"].append(
                {
                    "name": name,
                    "type": field_type,
                    "value": values.get("value", ""),
                }
            )
        elif tag == "script":
            if values.get("src"):
                self.scripts.append(values["src"])
            else:
                self._in_script = True
                self._script_buffer = []
        elif tag == "title":
            self._in_title = True

    def handle_startendtag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == "title":
            self._in_title = False
        elif tag == "form" and self._form is not None:
            if self._form["fields"]:
                self.forms.append(self._form)
            self._form = None
        elif tag == "script" and self._in_script:
            code = "".join(self._script_buffer).strip()
            if code:
                self.inline_scripts.append(code)
            self._in_script = False
            self._script_buffer = []

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title_parts.append(data)
        if self._in_script:
            self._script_buffer.append(data)

    def handle_comment(self, data: str) -> None:
        cleaned = data.strip()
        if cleaned:
            self.comments.append(cleaned)


class ScanContext:
    def __init__(self, target: str, client_ip: str = "") -> None:
        self.target = normalize_target(target)
        parts = urlsplit(self.target)
        self.scheme = parts.scheme
        self.host = (parts.hostname or "").lower()
        self.port = parts.port or (443 if self.scheme == "https" else 80)
        self.origin = urlunsplit((self.scheme, parts.netloc, "", "", ""))
        self.base_url = self.target
        self.client_ip = client_ip
        self.addresses = resolve_target(self.host, self.port)
        self.private_target = address_is_private(self.addresses)
        self.notes: list[str] = []
        self.requests_made = 0
        self.started = time.monotonic()
        self._last_request = 0.0
        self._request_lock = threading.Lock()
        self._stop = threading.Event()
        self._homepage: PageSnapshot | None = None
        self._points: list[InputPoint] | None = None
        self._tls: dict[str, Any] | None = None
        self._dns_cache: dict[tuple[str, str], list[str]] = {}
        self._resolve_cache: dict[tuple[str, int], tuple[float, list[str]]] = {
            (self.host, self.port): (time.monotonic(), self.addresses)
        }
        self._resolve_lock = threading.Lock()
        allowed_hosts = {self.host}
        if self.host.startswith("www."):
            allowed_hosts.add(self.host[4:])
        else:
            allowed_hosts.add("www." + self.host)
        self.allowed_hosts = allowed_hosts
        self.allowed_ports = {80, 443, self.port}
        self.client = httpx.Client(
            verify=False,
            trust_env=False,
            timeout=httpx.Timeout(REQUEST_TIMEOUT_SECONDS),
            limits=httpx.Limits(max_connections=8, max_keepalive_connections=4),
            headers={
                "User-Agent": (
                    "CosmosMolorum-Sentinel/1.0 "
                    "(+authorized-security-assessment; contact=security@cosmosmolorum.local)"
                ),
                "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.8",
            },
            follow_redirects=False,
        )

    def stop(self) -> None:
        self._stop.set()

    def ensure_active(self) -> None:
        if self._stop.is_set():
            raise ScanStopped("Scan was cancelled.")

    def close(self) -> None:
        self.client.close()

    # ------------------------------------------------------------------
    # Scope
    # ------------------------------------------------------------------
    def host_allowed(self, host: str) -> bool:
        return host.lower().rstrip(".") in self.allowed_hosts

    def same_host(self, url: str) -> bool:
        try:
            parts = urlsplit(url)
        except ValueError:
            return False
        if parts.scheme not in {"http", "https"}:
            return False
        if not self.host_allowed(parts.hostname or ""):
            return False
        port = parts.port or (443 if parts.scheme == "https" else 80)
        return port in self.allowed_ports

    def _resolve_cached(self, host: str, port: int) -> list[str]:
        key = (host.lower().rstrip("."), port)
        now = time.monotonic()
        with self._resolve_lock:
            cached = self._resolve_cache.get(key)
            if cached and now - cached[0] < RESOLVE_CACHE_TTL_SECONDS:
                return cached[1]
        addresses = resolve_target(host, port)
        with self._resolve_lock:
            self._resolve_cache[key] = (time.monotonic(), addresses)
        return addresses

    def _check_url(self, url: str) -> bool:
        if not self.same_host(url):
            return False
        try:
            parts = urlsplit(url)
            host = parts.hostname or ""
            port = parts.port or (443 if parts.scheme == "https" else 80)
            self._resolve_cached(host, port)
        except (TargetError, ValueError):
            return False
        return True

    # ------------------------------------------------------------------
    # HTTP
    # ------------------------------------------------------------------
    def fetch(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        data: Any = None,
        content: bytes | None = None,
        follow: bool = True,
        max_bytes: int = MAX_RESPONSE_BYTES,
    ) -> Probe:
        self.ensure_active()
        method = method.upper()
        if method not in {"GET", "HEAD", "POST", "OPTIONS"}:
            raise ValueError(f"Unsupported probe method: {method}")
        current = url
        history: list[str] = []
        started = time.perf_counter()
        for _ in range(MAX_REDIRECTS + 1):
            if not self._check_url(current):
                return Probe(
                    ok=False,
                    url=current,
                    method=method,
                    error="Out-of-scope or blocked target URL.",
                    elapsed_ms=int((time.perf_counter() - started) * 1000),
                    history=history,
                )
            probe = self._request_once(
                method,
                current,
                headers=headers,
                data=data,
                content=content,
                max_bytes=max_bytes,
            )
            if not probe.ok:
                probe.history = history
                return probe
            location = probe.header("location")
            if follow and probe.status in REDIRECT_STATUSES and location:
                target = urljoin(current, location)
                history.append(current)
                if not self.same_host(target):
                    probe.history = history
                    return probe
                current = target
                method = "GET" if probe.status in {301, 302, 303} else method
                data = None
                content = None
                continue
            probe.history = history
            return probe
        return Probe(
            ok=False,
            url=current,
            method=method,
            error="Too many redirects.",
            elapsed_ms=int((time.perf_counter() - started) * 1000),
            history=history,
        )

    def _request_once(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None,
        data: Any,
        content: bytes | None,
        max_bytes: int,
    ) -> Probe:
        with self._request_lock:
            self.ensure_active()
            if self.requests_made >= SCAN_REQUEST_BUDGET:
                return Probe(
                    ok=False,
                    url=url,
                    method=method,
                    error="Scan request budget exhausted.",
                )
            delay = REQUEST_DELAY_SECONDS - (time.monotonic() - self._last_request)
            if delay > 0:
                time.sleep(delay)
            self._last_request = time.monotonic()
            self.requests_made += 1
        started = time.perf_counter()
        try:
            with self.client.stream(
                method,
                url,
                headers=headers,
                data=data,
                content=content,
            ) as response:
                body = b""
                truncated = False
                if method != "HEAD" and response.status_code not in {204, 304}:
                    chunks: list[bytes] = []
                    total = 0
                    for chunk in response.iter_bytes():
                        if not chunk:
                            continue
                        total += len(chunk)
                        if total > max_bytes:
                            chunks.append(chunk[: max(0, max_bytes - (total - len(chunk)))])
                            truncated = True
                            break
                        chunks.append(chunk)
                    body = b"".join(chunks)
                encoding = response.encoding or "utf-8"
                try:
                    text = body.decode(encoding, errors="replace")
                except (LookupError, UnicodeDecodeError):
                    text = body.decode("utf-8", errors="replace")
                return Probe(
                    ok=True,
                    url=str(response.url),
                    status=response.status_code,
                    headers=response.headers,
                    text=text,
                    raw=body,
                    truncated=truncated,
                    elapsed_ms=int((time.perf_counter() - started) * 1000),
                    method=method,
                )
        except httpx.TimeoutException:
            return Probe(
                ok=False,
                url=url,
                method=method,
                error="Request timed out.",
                elapsed_ms=int((time.perf_counter() - started) * 1000),
            )
        except httpx.HTTPError as exc:
            return Probe(
                ok=False,
                url=url,
                method=method,
                error=f"Request failed: {exc.__class__.__name__}.",
                elapsed_ms=int((time.perf_counter() - started) * 1000),
            )
        except (OSError, ValueError) as exc:
            return Probe(
                ok=False,
                url=url,
                method=method,
                error=f"Request failed: {exc.__class__.__name__}.",
                elapsed_ms=int((time.perf_counter() - started) * 1000),
            )

    def get(self, path_or_url: str, **kwargs: Any) -> Probe:
        url = path_or_url if path_or_url.startswith(("http://", "https://")) else urljoin(
            self.origin + "/", path_or_url.lstrip("/")
        )
        return self.fetch("GET", url, **kwargs)

    def post(self, path_or_url: str, **kwargs: Any) -> Probe:
        url = path_or_url if path_or_url.startswith(("http://", "https://")) else urljoin(
            self.origin + "/", path_or_url.lstrip("/")
        )
        return self.fetch("POST", url, **kwargs)

    # ------------------------------------------------------------------
    # Page model and input points
    # ------------------------------------------------------------------
    def homepage(self) -> PageSnapshot:
        if self._homepage is not None:
            return self._homepage
        probe = self.fetch("GET", self.target)
        page = PageSnapshot(
            url=probe.url or self.target,
            status=probe.status,
            headers=probe.headers,
            html=probe.text,
            base_url=probe.url or self.target,
        )
        if probe.ok and probe.text:
            parser = _PageParser()
            try:
                parser.feed(probe.text[:MAX_RESPONSE_BYTES])
                parser.close()
            except Exception:
                pass
            base = urljoin(probe.url or self.target, parser.base_href or "")
            page.title = re.sub(r"\s+", " ", " ".join(parser.title_parts)).strip()
            page.meta_generator = parser.meta_generator
            page.comments = parser.comments
            page.links = [urljoin(base, href) for href in parser.links]
            page.scripts = [urljoin(base, src) for src in parser.scripts]
            page.inline_scripts = parser.inline_scripts
            page.forms = []
            for form in parser.forms:
                item = dict(form)
                item["action"] = urljoin(base, form.get("action") or page.url)
                page.forms.append(item)
            page.base_url = base
        self._homepage = page
        return page

    def _safe_fields(self, form: dict[str, Any]) -> dict[str, str]:
        fields: dict[str, str] = {}
        for field in form.get("fields", []):
            name = str(field.get("name") or "")
            field_type = str(field.get("type") or "text").lower()
            if not name or field_type in {
                "submit",
                "button",
                "reset",
                "file",
                "image",
                "password",
            }:
                continue
            if name.lower() in {"password", "passwd", "pwd"}:
                continue
            fields[name] = str(field.get("value") or "")
        return fields

    def points(self) -> list[InputPoint]:
        if self._points is not None:
            return self._points
        page = self.homepage()
        output: list[InputPoint] = []
        seen: set[tuple[str, str, str]] = set()

        def add(point: InputPoint) -> None:
            key = (point.method, point.url, point.param)
            if key in seen:
                return
            seen.add(key)
            output.append(point)

        target_parts = urlsplit(self.target)
        for name, value in parse_qsl(target_parts.query, keep_blank_values=True):
            add(InputPoint("GET", self.target, name, value, source="Target query"))

        for form in page.forms:
            action = str(form.get("action") or page.url)
            if not self.same_host(action):
                continue
            if SENSITIVE_ACTION_RE.search(action) or AUTH_ACTION_RE.search(action):
                continue
            fields = self._safe_fields(form)
            if not fields:
                continue
            method = str(form.get("method") or "GET").upper()
            enctype = str(form.get("enctype") or "").lower()
            if method == "POST" and "multipart" in enctype:
                continue
            if method not in {"GET", "POST"}:
                continue
            if method == "GET":
                query = urlencode(fields, doseq=True)
                action_url = urlunsplit(
                    (
                        urlsplit(action).scheme,
                        urlsplit(action).netloc,
                        urlsplit(action).path,
                        query,
                        "",
                    )
                )
                for name in fields:
                    add(
                        InputPoint(
                            "GET",
                            action_url,
                            name,
                            fields[name],
                            form=fields,
                            source="GET form",
                        )
                    )
            else:
                for name in fields:
                    add(
                        InputPoint(
                            "POST",
                            action,
                            name,
                            fields[name],
                            form=fields,
                            source="POST form",
                        )
                    )

        link_count = 0
        for link in page.links:
            if not self.same_host(link):
                continue
            parts = urlsplit(link)
            if not parts.query:
                continue
            for name, value in parse_qsl(parts.query, keep_blank_values=True):
                add(
                    InputPoint(
                        "GET",
                        link,
                        name,
                        value,
                        source="Discovered link",
                    )
                )
                link_count += 1
                if link_count >= 14:
                    break
            if link_count >= 14:
                break

        self._points = output
        return output

    def candidate_points(self, limit: int = 4) -> list[InputPoint]:
        points = []
        for point in self.points():
            lower = point.param.lower()
            if lower in {
                "csrf",
                "csrftoken",
                "_csrf",
                "token",
                "_token",
                "authenticity_token",
                "password",
                "passwd",
                "pwd",
            }:
                continue
            if SENSITIVE_ACTION_RE.search(point.url):
                continue
            points.append(point)
            if len(points) >= limit:
                break
        return points

    def with_value(
        self, point: InputPoint, payload: str
    ) -> tuple[str, dict[str, str] | None]:
        if point.method == "POST":
            data = dict(point.form or {})
            data[point.param] = payload
            return point.url, data
        parts = urlsplit(point.url)
        pairs = parse_qsl(parts.query, keep_blank_values=True)
        replaced = False
        updated: list[tuple[str, str]] = []
        for name, value in pairs:
            if name == point.param and not replaced:
                updated.append((name, payload))
                replaced = True
            else:
                updated.append((name, value))
        if not replaced:
            updated.append((point.param, payload))
        return (
            urlunsplit(
                (
                    parts.scheme,
                    parts.netloc,
                    parts.path,
                    urlencode(updated, doseq=True),
                    "",
                )
            ),
            None,
        )

    def send_point(
        self, point: InputPoint, payload: str, *, follow: bool = True
    ) -> Probe:
        url, data = self.with_value(point, payload)
        if point.method == "POST":
            return self.fetch("POST", url, data=data, follow=follow)
        return self.fetch("GET", url, follow=follow)

    # ------------------------------------------------------------------
    # TLS
    # ------------------------------------------------------------------
    def tls_info(self) -> dict[str, Any]:
        if self._tls is not None:
            return self._tls
        info: dict[str, Any] = {
            "ok": False,
            "host": self.host,
            "port": 443 if self.scheme == "https" else 443,
            "error": "",
            "cert": {},
            "cipher": None,
            "version": "",
            "alpn": "",
            "verified": False,
            "verify_error": "",
            "hostname_match": True,
            "fingerprint": "",
        }
        port = self.port if self.scheme == "https" else 443
        info["port"] = port
        sock = None
        tls_sock = None
        try:
            context = ssl._create_unverified_context()
            context.set_alpn_protocols(["h2", "http/1.1"])
            sock = socket.create_connection((self.host, port), timeout=8)
            tls_sock = context.wrap_socket(sock, server_hostname=self.host)
            cert = tls_sock.getpeercert() or {}
            info["ok"] = True
            info["cert"] = cert
            info["cipher"] = tls_sock.cipher()
            info["version"] = tls_sock.version() or ""
            info["alpn"] = tls_sock.selected_alpn_protocol() or ""
            der = tls_sock.getpeercert(binary_form=True)
            if der:
                info["fingerprint"] = hashlib.sha256(der).hexdigest()
            try:
                ssl.match_hostname(cert, self.host)
            except (ssl.CertificateError, ValueError):
                info["hostname_match"] = False
        except (OSError, ssl.SSLError) as exc:
            info["error"] = str(exc)
        finally:
            if tls_sock is not None:
                try:
                    tls_sock.close()
                except OSError:
                    pass
            elif sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
        try:
            verify_context = ssl.create_default_context()
            verify_sock = socket.create_connection((self.host, port), timeout=8)
            wrapped = verify_context.wrap_socket(verify_sock, server_hostname=self.host)
            wrapped.close()
            info["verified"] = True
        except ssl.SSLCertVerificationError as exc:
            info["verify_error"] = exc.verify_message or str(exc)
        except (OSError, ssl.SSLError) as exc:
            info["verify_error"] = str(exc)
        self._tls = info
        return info

    # ------------------------------------------------------------------
    # DNS
    # ------------------------------------------------------------------
    def system_addresses(self) -> list[str]:
        return list(self.addresses)

    def doh_query(self, name: str, record_type: str) -> list[str]:
        key = (name.lower(), record_type.upper())
        if key in self._dns_cache:
            return self._dns_cache[key]
        values: list[str] = []
        try:
            with httpx.Client(
                trust_env=False,
                timeout=httpx.Timeout(6.0),
                headers={"Accept": "application/dns-json"},
            ) as client:
                response = client.get(
                    "https://cloudflare-dns.com/dns-query",
                    params={"name": name, "type": record_type.upper()},
                )
                if response.status_code == 200:
                    payload = response.json()
                    for answer in payload.get("Answer", []):
                        data = str(answer.get("data") or "").strip().strip('"')
                        if data and data not in values:
                            values.append(data)
        except (httpx.HTTPError, ValueError, KeyError):
            values = []
        self._dns_cache[key] = values
        return values

    def txt_records(self, name: str) -> list[str]:
        return [value.strip('"') for value in self.doh_query(name, "TXT")]

    # ------------------------------------------------------------------
    # Fingerprint helpers
    # ------------------------------------------------------------------
    def fingerprint(self) -> list[str]:
        page = self.homepage()
        found: list[str] = []
        candidates = [
            probe_value
            for probe_value in (
                page.headers.get("server", ""),
                page.headers.get("x-powered-by", ""),
                page.headers.get("x-generator", ""),
                page.headers.get("via", ""),
                page.meta_generator,
            )
            if probe_value
        ]
        cookies = " ".join(page.headers.get_list("set-cookie")) if page.headers else ""
        for value in candidates:
            text = value.strip()
            if text and text not in found:
                found.append(text[:160])
        patterns = {
            "WordPress": r"wp-content|wp-includes",
            "Drupal": r"drupal",
            "Joomla": r"joomla",
            "Next.js": r"__NEXT_DATA__|_next/",
            "React": r"react(?:-dom)?",
            "Vue": r"vue(?:\.js)?",
            "Angular": r"ng-version|angular",
            "Laravel": r"laravel_session|XSRF-TOKEN",
            "Django": r"csrfmiddlewaretoken|django",
            "Express": r"express",
            "PHP": r"PHPSESSID|\.php",
            "ASP.NET": r"ASP\.NET|__VIEWSTATE|\.aspx",
            "Cloudflare": r"cloudflare|cf-ray",
            "Nginx": r"nginx",
            "Apache": r"apache",
        }
        haystack = page.html[:400_000] + " " + " ".join(candidates) + " " + cookies
        for label, pattern in patterns.items():
            if re.search(pattern, haystack, re.IGNORECASE) and label not in found:
                found.append(label)
        return found[:14]


def replace_header(headers: dict[str, str] | None, name: str, value: str) -> dict[str, str]:
    output = dict(headers or {})
    output[name] = value
    return output


def redact_secret(value: str) -> str:
    cleaned = value.strip()
    if len(cleaned) <= 8:
        return "*" * len(cleaned)
    return cleaned[:4] + "…" + cleaned[-3:]


def text_contains_any(text: str, patterns: list[re.Pattern[str]]) -> str:
    for pattern in patterns:
        match = pattern.search(text)
        if match:
            return match.group(0)[:180]
    return ""


def html_to_text(value: str) -> str:
    return re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", value))).strip()

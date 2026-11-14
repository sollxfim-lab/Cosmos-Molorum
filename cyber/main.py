from __future__ import annotations

import csv
import io
import threading
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from starlette.middleware.gzip import GZipMiddleware

from . import db, scanner
from .analysis import build_analysis
from .intel import build_intel
from .auth import decode_token, hash_password, sign_token, verify_password
from .config import (
    COMPANY,
    MODULE_COUNT,
    PRODUCT_NAME,
    PRODUCT_SHORT,
    TOKEN_TTL,
    VERSION,
)
from .engine import TargetError, normalize_target, resolve_target
from .registry import MODULES

WEB_DIR = Path(__file__).resolve().parent / "web"
COOKIE_NAME = "cm_sentinel"
CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "base-uri 'none'; "
    "frame-ancestors 'none'; "
    "form-action 'self'"
)

_LOGIN_ATTEMPTS: dict[str, list[float]] = {}
_ATTEMPT_LOCK = threading.Lock()
LOGIN_WINDOW = 600.0
LOGIN_MAX_FAILURES = 5
# Verify against this hash when the account does not exist so response timing
# does not reveal which usernames are valid.
_DUMMY_PASSWORD_HASH = hash_password("sentinel-timing-equalizer")


class LoginPayload(BaseModel):
    username: str
    password: str


class PasswordPayload(BaseModel):
    current_password: str
    new_password: str


class ScanPayload(BaseModel):
    target: str
    modules: list[str] | None = None
    note: str = ""


def _client_ip(request: Request) -> str:
    peer = request.client.host if request.client else ""
    if peer in {"127.0.0.1", "::1", "localhost"}:
        forwarded = request.headers.get("x-forwarded-for", "")
        if forwarded:
            # nginx appends the real peer to the header; use the last hop so a
            # client-supplied value cannot evade login throttling or audit.
            return forwarded.split(",")[-1].strip()[:64] or peer
    return (peer or "")[:64]


def _session_user(request: Request) -> dict[str, Any]:
    token = request.cookies.get(COOKIE_NAME, "")
    if not token:
        header = request.headers.get("authorization", "")
        if header.lower().startswith("bearer "):
            token = header[7:].strip()
    payload = decode_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Sign in to continue.")
    try:
        user_id = int(payload.get("sub", 0))
    except (TypeError, ValueError):
        raise HTTPException(status_code=401, detail="Session is invalid.")
    user = db.get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=401, detail="Session account no longer exists.")
    return user


def _same_origin(request: Request) -> None:
    origin = request.headers.get("origin", "")
    if not origin:
        return
    host = request.headers.get("host", "")
    allowed = {f"https://{host}", f"http://{host}"}
    if origin.rstrip("/") not in allowed:
        raise HTTPException(status_code=403, detail="Cross-origin request rejected.")


def _login_key(request: Request) -> str:
    return _client_ip(request) or "unknown"


def _check_login_limit(key: str) -> None:
    now = time.time()
    with _ATTEMPT_LOCK:
        recent = [stamp for stamp in _LOGIN_ATTEMPTS.get(key, []) if now - stamp < LOGIN_WINDOW]
        _LOGIN_ATTEMPTS[key] = recent
    if len(recent) >= LOGIN_MAX_FAILURES:
        raise HTTPException(
            status_code=429,
            detail="Too many failed sign-in attempts. Try again in a few minutes.",
        )


def _record_login_failure(key: str) -> None:
    with _ATTEMPT_LOCK:
        _LOGIN_ATTEMPTS.setdefault(key, []).append(time.time())


def _clear_login_failures(key: str) -> None:
    with _ATTEMPT_LOCK:
        _LOGIN_ATTEMPTS.pop(key, None)


def _secure_request(request: Request) -> bool:
    proto = request.headers.get("x-forwarded-proto", "").split(",")[0].strip().lower()
    return request.url.scheme == "https" or proto == "https"


def _set_session_cookie(response: Response, token: str, request: Request) -> None:
    response.set_cookie(
        COOKIE_NAME,
        token,
        max_age=TOKEN_TTL,
        httponly=True,
        samesite="lax",
        secure=_secure_request(request),
        path="/",
    )


def _scan_counts() -> dict[str, int]:
    scans = db.list_scans(limit=200)
    active = sum(1 for scan in scans if scan["status"] in {"queued", "running"})
    return {"active": active, "total": len(scans)}


def _fallback_progress(scan: dict[str, Any]) -> dict[str, Any]:
    modules = scan.get("modules") or []
    total = len(scan.get("modules_json") or modules) or MODULE_COUNT
    completed = len(modules)
    return {
        "scan_id": scan["id"],
        "status": scan["status"],
        "total": total,
        "completed": completed,
        "percent": 100 if scan["status"] not in {"queued", "running"} else (
            int(round(completed * 100 / max(1, total)))
        ),
        "requests": sum(int(item.get("requests") or 0) for item in modules),
        "current": "",
        "cancelled": bool(scan.get("cancel_requested")),
        "error": scan.get("error") or "",
    }


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init_db()
    scanner.recover_interrupted_scans()
    yield


app = FastAPI(
    title=f"{PRODUCT_NAME} API",
    version=VERSION,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    lifespan=lifespan,
)
# JSON, HTML, JavaScript and CSS benefit on slow links; static fonts are
# already compressed and fall below the threshold or arrive pre-compressed.
app.add_middleware(GZipMiddleware, minimum_size=1024)


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    try:
        response = await call_next(request)
    except HTTPException as exc:
        response = JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
    asset_path = request.url.path
    if asset_path.startswith("/assets/fonts/"):
        # Font files change very rarely and are the largest static assets.
        response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
    elif asset_path == "/assets/brand.svg" or asset_path.startswith("/assets/posters/"):
        # Brand and poster artwork can change with a release, so revalidate
        # instead of pinning a stale mark in the browser. The files are small
        # and the 304 response is cheap.
        response.headers["Cache-Control"] = "no-cache, must-revalidate"
    elif asset_path.startswith("/assets/"):
        response.headers["Cache-Control"] = "no-cache, must-revalidate"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
    )
    response.headers["Content-Security-Policy"] = CSP
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    if _secure_request(request):
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
    return response


@app.get("/api/health")
def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "product": PRODUCT_NAME,
        "company": COMPANY,
        "version": VERSION,
        "mode": "cyber",
        "modules": len(MODULES) or MODULE_COUNT,
    }


@app.post("/api/auth/login")
def login(payload: LoginPayload, request: Request, response: Response) -> dict[str, Any]:
    _same_origin(request)
    key = _login_key(request)
    _check_login_limit(key)
    username = payload.username.strip()[:80]
    user = db.get_user(username)
    stored = user["password_hash"] if user else _DUMMY_PASSWORD_HASH
    valid = verify_password(payload.password, stored)
    if not user or not valid:
        _record_login_failure(key)
        db.add_audit(
            username or "unknown",
            "auth.login_failed",
            target="sign-in",
            client_ip=_client_ip(request),
            meta={"reason": "invalid_credentials"},
        )
        raise HTTPException(status_code=401, detail="Invalid username or password.")
    _clear_login_failures(key)
    db.touch_login(int(user["id"]))
    token = sign_token(
        {
            "sub": str(user["id"]),
            "usr": user["username"],
            "role": user["role"],
        }
    )
    _set_session_cookie(response, token, request)
    db.add_audit(
        user["username"],
        "auth.login",
        target="sign-in",
        client_ip=_client_ip(request),
        meta={"role": user["role"]},
    )
    return {
        "user": {
            "username": user["username"],
            "role": user["role"],
            "email": user["email"],
        },
        "expires_in": TOKEN_TTL,
    }


@app.post("/api/auth/logout")
def logout(
    request: Request,
    response: Response,
    user: dict[str, Any] = Depends(_session_user),
) -> dict[str, Any]:
    _same_origin(request)
    response.delete_cookie(COOKIE_NAME, path="/")
    db.add_audit(
        user["username"],
        "auth.logout",
        target="sign-in",
        client_ip=_client_ip(request),
    )
    return {"ok": True}


@app.get("/api/auth/me")
def me(user: dict[str, Any] = Depends(_session_user)) -> dict[str, Any]:
    return {
        "username": user["username"],
        "role": user["role"],
        "email": user["email"],
        "last_login_at": user.get("last_login_at"),
        "product": PRODUCT_NAME,
        "version": VERSION,
    }


@app.post("/api/auth/password")
def change_password(
    payload: PasswordPayload,
    request: Request,
    user: dict[str, Any] = Depends(_session_user),
) -> dict[str, Any]:
    _same_origin(request)
    record = db.get_user(user["username"])
    if not record or not verify_password(payload.current_password, record["password_hash"]):
        raise HTTPException(status_code=400, detail="The current password is incorrect.")
    new_password = payload.new_password
    if len(new_password) < 12:
        raise HTTPException(status_code=400, detail="Use at least 12 characters.")
    if new_password == payload.current_password:
        raise HTTPException(status_code=400, detail="Choose a password you have not used here.")
    db.update_password(int(user["id"]), new_password)
    db.add_audit(
        user["username"],
        "auth.password_changed",
        target="account",
        client_ip=_client_ip(request),
    )
    return {"ok": True}


@app.get("/api/dashboard")
def dashboard(user: dict[str, Any] = Depends(_session_user)) -> dict[str, Any]:
    data = db.dashboard()
    recent = []
    for item in data["recent"]:
        entry = dict(item)
        raw = entry.pop("summary_json", None)
        if raw:
            try:
                import json

                entry["summary"] = json.loads(raw)
            except ValueError:
                entry["summary"] = None
        recent.append(entry)
    data["recent"] = recent
    data["modules"] = len(MODULES) or MODULE_COUNT
    data["product"] = PRODUCT_NAME
    data["version"] = VERSION
    data["active_scans"] = _scan_counts()["active"]
    return data


@app.get("/api/modules")
def modules(user: dict[str, Any] = Depends(_session_user)) -> dict[str, Any]:
    catalog = [spec.public() for spec in scanner.module_catalog()]
    categories: list[dict[str, Any]] = []
    for spec in scanner.module_catalog():
        existing = next((item for item in categories if item["name"] == spec.category), None)
        if existing is None:
            existing = {"name": spec.category, "count": 0, "modules": []}
            categories.append(existing)
        existing["count"] += 1
        existing["modules"].append(spec.public())
    return {"count": len(catalog), "categories": categories, "modules": catalog}


@app.get("/api/scans")
def scans(
    limit: int = 60, user: dict[str, Any] = Depends(_session_user)
) -> dict[str, Any]:
    rows = db.list_scans(limit=max(1, min(limit, 500)))
    for row in rows:
        row.pop("summary_json", None)
    return {"scans": rows, "count": len(rows)}


@app.post("/api/scans")
def create_scan(
    payload: ScanPayload,
    request: Request,
    user: dict[str, Any] = Depends(_session_user),
) -> dict[str, Any]:
    _same_origin(request)
    note = payload.note.strip()
    if len(note) > 500:
        raise HTTPException(status_code=400, detail="Catatan pemindaian terlalu panjang.")
    if not note:
        note = "Dijalankan oleh operator terautentikasi melalui konsol Sentinel."
    try:
        target = normalize_target(payload.target[:2048])
    except TargetError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    parts = urlsplit(target)
    host = (parts.hostname or "").lower()
    port = parts.port or (443 if parts.scheme == "https" else 80)
    try:
        resolve_target(host, port)
    except TargetError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    counts = _scan_counts()
    if counts["active"] >= 4:
        raise HTTPException(
            status_code=429,
            detail="Four assessments are already in progress. Wait for one to finish.",
        )
    existing = [
        scan
        for scan in db.list_scans(limit=200)
        if scan["status"] in {"queued", "running"}
        and scan["requested_by"] == user["username"]
    ]
    if len(existing) >= 2:
        raise HTTPException(
            status_code=429,
            detail="You already have two assessments in progress.",
        )
    try:
        specs = scanner.find_modules(payload.modules)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    scan_id = db.create_scan(
        target=target,
        host=host,
        modules=[spec.id for spec in specs],
        requested_by=user["username"],
        client_ip=_client_ip(request),
        authorization_note=note,
    )
    db.add_audit(
        user["username"],
        "scan.created",
        target=target,
        client_ip=_client_ip(request),
        meta={"scan_id": scan_id, "modules": len(specs)},
    )
    try:
        scanner.start_scan(scan_id, target, [spec.id for spec in specs], _client_ip(request))
    except ValueError as exc:
        db.set_scan_finished(scan_id, "failed", None, None, None, str(exc))
        raise HTTPException(status_code=409, detail=str(exc))
    return {"scan_id": scan_id, "status": "queued", "modules": len(specs)}


@app.get("/api/scans/{scan_id}")
def scan_detail(
    scan_id: str, user: dict[str, Any] = Depends(_session_user)
) -> dict[str, Any]:
    scan = db.scan_detail(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Assessment not found.")
    return scan


@app.get("/api/analysis")
def analysis_report(
    scan_id: str | None = None, user: dict[str, Any] = Depends(_session_user)
) -> dict[str, Any]:
    report = build_analysis(scan_id)
    if not report:
        raise HTTPException(
            status_code=404,
            detail="Belum ada asesmen selesai yang dapat dianalisis.",
        )
    return report


@app.get("/api/intel")
def intelligence_report(
    scan_id: str | None = None, user: dict[str, Any] = Depends(_session_user)
) -> dict[str, Any]:
    report = build_intel(scan_id)
    if not report:
        raise HTTPException(
            status_code=404,
            detail="Belum ada asesmen selesai yang dapat dianalisis.",
        )
    return report


@app.get("/api/scans/{scan_id}/progress")
def scan_progress(
    scan_id: str, user: dict[str, Any] = Depends(_session_user)
) -> dict[str, Any]:
    current = scanner.progress(scan_id)
    if current:
        return current
    scan = db.scan_detail(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Assessment not found.")
    return _fallback_progress(scan)


@app.post("/api/scans/{scan_id}/cancel")
def cancel_scan(
    scan_id: str,
    request: Request,
    user: dict[str, Any] = Depends(_session_user),
) -> dict[str, Any]:
    _same_origin(request)
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Assessment not found.")
    if scan["status"] not in {"queued", "running"}:
        raise HTTPException(status_code=409, detail="This assessment has already finished.")
    if not db.request_cancel(scan_id):
        raise HTTPException(status_code=409, detail="Unable to cancel this assessment.")
    db.add_audit(
        user["username"],
        "scan.cancel_requested",
        target=scan["target"],
        client_ip=_client_ip(request),
        meta={"scan_id": scan_id},
    )
    return {"ok": True, "status": "cancelling"}


@app.get("/api/scans/{scan_id}/export")
def export_scan(
    scan_id: str,
    request: Request,
    format: str = "json",
    user: dict[str, Any] = Depends(_session_user),
):
    scan = db.scan_detail(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Assessment not found.")
    fmt = (format or "json").lower()
    if fmt not in {"json", "csv"}:
        raise HTTPException(status_code=400, detail="Supported formats: json, csv.")
    db.add_audit(
        user["username"],
        "scan.exported",
        target=scan["target"],
        client_ip=_client_ip(request) if request else "",
        meta={"scan_id": scan_id, "format": fmt},
    )
    if fmt == "csv":
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(
            [
                "scan_id",
                "target",
                "module",
                "category",
                "title",
                "severity",
                "detail",
                "evidence",
                "remediation",
            ]
        )
        for finding in scan["findings"]:
            module = next(
                (
                    item
                    for item in scan["modules"]
                    if item["module_id"] == finding["module_id"]
                ),
                {},
            )
            writer.writerow(
                [
                    scan_id,
                    scan["target"],
                    finding["module_id"],
                    module.get("category", ""),
                    finding["title"],
                    finding["severity"],
                    finding["detail"],
                    finding["evidence"],
                    finding["remediation"],
                ]
            )
        return Response(
            content=buffer.getvalue(),
            media_type="text/csv; charset=utf-8",
            headers={
                "Content-Disposition": f'attachment; filename="sentinel-{scan_id}.csv"'
            },
        )
    return JSONResponse(
        scan,
        headers={
            "Content-Disposition": f'attachment; filename="sentinel-{scan_id}.json"'
        },
    )


@app.get("/api/audit")
def audit(
    limit: int = 120, user: dict[str, Any] = Depends(_session_user)
) -> dict[str, Any]:
    rows = db.list_audit(limit=max(1, min(limit, 500)))
    return {"entries": rows, "count": len(rows)}


if WEB_DIR.is_dir():
    app.mount("/assets", StaticFiles(directory=str(WEB_DIR / "assets")), name="assets")


@app.get("/")
def index_page():
    target = WEB_DIR / "index.html"
    if not target.is_file():
        return JSONResponse(
            {
                "product": PRODUCT_NAME,
                "message": "Sentinel API is running, but the interface bundle is missing.",
            },
            status_code=503,
        )
    return FileResponse(target)


@app.get("/{path:path}")
def spa_page(path: str):
    if path.startswith("api/"):
        raise HTTPException(status_code=404, detail="Not found.")
    candidate = (WEB_DIR / path).resolve()
    try:
        candidate.relative_to(WEB_DIR.resolve())
    except ValueError:
        raise HTTPException(status_code=404, detail="Not found.")
    if candidate.is_file():
        return FileResponse(candidate)
    target = WEB_DIR / "index.html"
    if target.is_file():
        return FileResponse(target)
    raise HTTPException(status_code=404, detail="Not found.")


if __name__ == "__main__":  # pragma: no cover
    import uvicorn

    uvicorn.run(
        "cyber.main:app",
        host="127.0.0.1",
        port=7998,
        proxy_headers=True,
        forwarded_allow_ips="127.0.0.1",
    )

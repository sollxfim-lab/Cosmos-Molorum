from __future__ import annotations

import json
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Iterator

from .auth import hash_password
from .config import (
    DB_PATH,
    DEFAULT_ADMIN_EMAIL,
    DEFAULT_ADMIN_PASS,
    DEFAULT_ADMIN_USER,
)


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def new_scan_id() -> str:
    return "sc_" + secrets.token_hex(8)


@contextmanager
def connect() -> Iterator[sqlite3.Connection]:
    conn = sqlite3.connect(DB_PATH, timeout=20)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=20000")
    conn.execute("PRAGMA temp_store=MEMORY")
    conn.execute("PRAGMA cache_size=-8000")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with connect() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'admin',
                email TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                last_login_at TEXT
            );

            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                host TEXT NOT NULL,
                status TEXT NOT NULL,
                modules_json TEXT NOT NULL,
                requested_by TEXT NOT NULL,
                client_ip TEXT NOT NULL DEFAULT '',
                authorization_note TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                started_at TEXT,
                finished_at TEXT,
                score INTEGER,
                grade TEXT,
                summary_json TEXT,
                error TEXT,
                cancel_requested INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS module_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                module_id TEXT NOT NULL,
                name TEXT NOT NULL,
                category TEXT NOT NULL,
                status TEXT NOT NULL,
                summary TEXT NOT NULL,
                duration_ms INTEGER NOT NULL DEFAULT 0,
                requests INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                UNIQUE(scan_id, module_id)
            );

            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                module_id TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                detail TEXT NOT NULL,
                evidence TEXT NOT NULL DEFAULT '',
                remediation TEXT NOT NULL DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                target TEXT NOT NULL DEFAULT '',
                client_ip TEXT NOT NULL DEFAULT '',
                meta_json TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_scans_created
                ON scans(created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_module_results_scan
                ON module_results(scan_id);
            CREATE INDEX IF NOT EXISTS idx_findings_scan
                ON findings(scan_id, severity);
            CREATE INDEX IF NOT EXISTS idx_audit_ts
                ON audit(ts DESC);
            """
        )
        existing = conn.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]
        if not existing:
            conn.execute(
                "INSERT INTO users (username, password_hash, role, email, created_at)"
                " VALUES (?, ?, 'admin', ?, ?)",
                (
                    DEFAULT_ADMIN_USER,
                    hash_password(DEFAULT_ADMIN_PASS),
                    DEFAULT_ADMIN_EMAIL,
                    utcnow(),
                ),
            )
            conn.execute(
                "INSERT INTO audit (ts, actor, action, target, client_ip, meta_json)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (
                    utcnow(),
                    DEFAULT_ADMIN_USER,
                    "account.seed",
                    "",
                    "",
                    json.dumps({"role": "admin"}),
                ),
            )
        # Refresh planner statistics after schema/seed changes. This is cheap
        # and keeps the list/dashboard queries predictable as data grows.
        conn.execute("PRAGMA optimize")


# ---------------------------------------------------------------------------
# Accounts
# ---------------------------------------------------------------------------


def get_user(username: str) -> dict[str, Any] | None:
    with connect() as conn:
        row = conn.execute(
            "SELECT id, username, password_hash, role, email, created_at, last_login_at"
            " FROM users WHERE lower(username) = lower(?)",
            (username,),
        ).fetchone()
    return dict(row) if row else None


def get_user_by_id(user_id: int) -> dict[str, Any] | None:
    with connect() as conn:
        row = conn.execute(
            "SELECT id, username, role, email, created_at, last_login_at"
            " FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
    return dict(row) if row else None


def touch_login(user_id: int) -> None:
    with connect() as conn:
        conn.execute(
            "UPDATE users SET last_login_at = ? WHERE id = ?", (utcnow(), user_id)
        )


def update_password(user_id: int, password: str) -> None:
    with connect() as conn:
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (hash_password(password), user_id),
        )


# ---------------------------------------------------------------------------
# Scans
# ---------------------------------------------------------------------------


def create_scan(
    target: str,
    host: str,
    modules: list[str],
    requested_by: str,
    client_ip: str,
    authorization_note: str,
) -> str:
    scan_id = new_scan_id()
    with connect() as conn:
        conn.execute(
            "INSERT INTO scans (id, target, host, status, modules_json, requested_by,"
            " client_ip, authorization_note, created_at)"
            " VALUES (?, ?, ?, 'queued', ?, ?, ?, ?, ?)",
            (
                scan_id,
                target,
                host,
                json.dumps(modules),
                requested_by,
                client_ip,
                authorization_note,
                utcnow(),
            ),
        )
    return scan_id


def get_scan(scan_id: str) -> dict[str, Any] | None:
    with connect() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    return dict(row) if row else None


def set_scan_running(scan_id: str) -> None:
    with connect() as conn:
        conn.execute(
            "UPDATE scans SET status = 'running', started_at = ? WHERE id = ?",
            (utcnow(), scan_id),
        )


def set_scan_finished(
    scan_id: str,
    status: str,
    score: int | None,
    grade: str | None,
    summary: dict[str, Any] | None,
    error: str | None = None,
) -> None:
    with connect() as conn:
        conn.execute(
            "UPDATE scans SET status = ?, finished_at = ?, score = ?, grade = ?,"
            " summary_json = ?, error = ? WHERE id = ?",
            (
                status,
                utcnow(),
                score,
                grade,
                json.dumps(summary) if summary is not None else None,
                error,
                scan_id,
            ),
        )


def request_cancel(scan_id: str) -> bool:
    with connect() as conn:
        cur = conn.execute(
            "UPDATE scans SET cancel_requested = 1 WHERE id = ?"
            " AND status IN ('queued', 'running')",
            (scan_id,),
        )
        return cur.rowcount > 0


def is_cancelled(scan_id: str) -> bool:
    with connect() as conn:
        row = conn.execute(
            "SELECT cancel_requested FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()
    return bool(row and row["cancel_requested"])


def save_module_result(scan_id: str, result: dict[str, Any]) -> None:
    with connect() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO module_results"
            " (scan_id, module_id, name, category, status, summary, duration_ms,"
            " requests, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                scan_id,
                result["module_id"],
                result["name"],
                result["category"],
                result["status"],
                result["summary"],
                int(result.get("duration_ms", 0)),
                int(result.get("requests", 0)),
                utcnow(),
            ),
        )
        for finding in result.get("findings", []):
            conn.execute(
                "INSERT INTO findings (scan_id, module_id, title, severity, detail,"
                " evidence, remediation) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    scan_id,
                    result["module_id"],
                    finding["title"],
                    finding["severity"],
                    finding["detail"],
                    finding.get("evidence", ""),
                    finding.get("remediation", ""),
                ),
            )


def list_scans(limit: int = 60) -> list[dict[str, Any]]:
    limit = max(1, min(limit, 200))
    with connect() as conn:
        rows = conn.execute(
            "SELECT s.*,"
            " (SELECT COUNT(*) FROM findings f WHERE f.scan_id = s.id) AS finding_count,"
            " (SELECT COUNT(*) FROM findings f WHERE f.scan_id = s.id"
            "  AND f.severity IN ('critical','high')) AS urgent_count,"
            " (SELECT COUNT(*) FROM module_results m WHERE m.scan_id = s.id) AS module_count"
            " FROM scans s ORDER BY s.created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def scan_detail(scan_id: str) -> dict[str, Any] | None:
    scan = get_scan(scan_id)
    if not scan:
        return None
    with connect() as conn:
        modules = conn.execute(
            "SELECT module_id, name, category, status, summary, duration_ms, requests"
            " FROM module_results WHERE scan_id = ?"
            " ORDER BY id ASC",
            (scan_id,),
        ).fetchall()
        findings = conn.execute(
            "SELECT module_id, title, severity, detail, evidence, remediation"
            " FROM findings WHERE scan_id = ?"
            " ORDER BY CASE severity"
            "  WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2"
            "  WHEN 'low' THEN 3 ELSE 4 END, id ASC",
            (scan_id,),
        ).fetchall()
    scan["modules"] = [dict(row) for row in modules]
    scan["findings"] = [dict(row) for row in findings]
    scan["modules_json"] = json.loads(scan["modules_json"] or "[]")
    scan["summary"] = json.loads(scan["summary_json"]) if scan["summary_json"] else None
    scan.pop("summary_json", None)
    scan["authorization_note"] = scan["authorization_note"]
    scan["cancel_requested"] = bool(scan["cancel_requested"])
    return scan


def dashboard() -> dict[str, Any]:
    with connect() as conn:
        totals = conn.execute(
            "SELECT COUNT(*) AS scans,"
            " COALESCE(AVG(score), 0) AS avg_score,"
            " SUM(CASE WHEN status = 'running' THEN 1 ELSE 0 END) AS running"
            " FROM scans"
        ).fetchone()
        findings = conn.execute(
            "SELECT severity, COUNT(*) AS n FROM findings GROUP BY severity"
        ).fetchall()
        recent = conn.execute(
            "SELECT s.id, s.target, s.host, s.status, s.score, s.grade, s.created_at,"
            " s.finished_at, s.summary_json,"
            " (SELECT COUNT(*) FROM findings f WHERE f.scan_id = s.id)"
            " AS finding_count"
            " FROM scans s ORDER BY s.created_at DESC LIMIT 8"
        ).fetchall()
        week = conn.execute(
            "SELECT COUNT(*) AS n FROM scans"
            " WHERE created_at >= ?",
            ((datetime.now(timezone.utc) - timedelta(days=7)).isoformat(timespec="seconds"),),
        ).fetchone()
    severity = {row["severity"]: row["n"] for row in findings}
    return {
        "scans": totals["scans"],
        "avg_score": round(float(totals["avg_score"] or 0)),
        "running": totals["running"] or 0,
        "week": week["n"],
        "severity": {
            "critical": severity.get("critical", 0),
            "high": severity.get("high", 0),
            "medium": severity.get("medium", 0),
            "low": severity.get("low", 0),
            "info": severity.get("info", 0),
        },
        "recent": [dict(row) for row in recent],
    }


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------


def add_audit(
    actor: str,
    action: str,
    target: str = "",
    client_ip: str = "",
    meta: dict[str, Any] | None = None,
) -> None:
    with connect() as conn:
        conn.execute(
            "INSERT INTO audit (ts, actor, action, target, client_ip, meta_json)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (
                utcnow(),
                actor,
                action,
                target,
                client_ip,
                json.dumps(meta or {}),
            ),
        )


def list_audit(limit: int = 120) -> list[dict[str, Any]]:
    limit = max(1, min(limit, 500))
    with connect() as conn:
        rows = conn.execute(
            "SELECT id, ts, actor, action, target, client_ip, meta_json"
            " FROM audit ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    output = []
    for row in rows:
        item = dict(row)
        try:
            item["meta"] = json.loads(item.pop("meta_json") or "{}")
        except json.JSONDecodeError:
            item["meta"] = {}
        output.append(item)
    return output

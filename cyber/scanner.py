from __future__ import annotations

import logging
import threading
import time
from collections import Counter
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from typing import Any, Iterable

from . import db
from .config import MODULE_WORKERS, SCAN_TIMEOUT_SECONDS
from .engine import ScanContext, ScanStopped, TargetError
from .models import SEVERITY_ORDER, SEVERITY_WEIGHT, ModuleResult, ModuleSpec, Outcome
from .registry import MODULES, ordered_modules
from . import modules as _modules  # noqa: F401  (populates the registry)

logger = logging.getLogger("sentinel.scanner")

SEVERITY_LABELS = ("critical", "high", "medium", "low", "info")
GRADE_BANDS = (
    (92, "A"),
    (84, "B"),
    (74, "C"),
    (62, "D"),
    (45, "E"),
    (0, "F"),
)

_PROGRESS: dict[str, dict[str, Any]] = {}
_PROGRESS_LOCK = threading.Lock()
_ACTIVE: set[str] = set()
_ACTIVE_LOCK = threading.Lock()


def module_catalog() -> list[ModuleSpec]:
    return ordered_modules()


def find_modules(ids: Iterable[str] | None) -> list[ModuleSpec]:
    catalog = ordered_modules()
    if not ids:
        return catalog
    wanted = {str(item) for item in ids if str(item)}
    selected = [spec for spec in catalog if spec.id in wanted]
    if not selected:
        raise ValueError("Select at least one scan module.")
    return selected


def score_from_findings(findings: list[dict[str, Any]]) -> tuple[int, str]:
    penalty = 0
    for finding in findings:
        penalty += SEVERITY_WEIGHT.get(str(finding.get("severity")), 0)
    score = max(0, min(100, 100 - penalty))
    for floor, grade in GRADE_BANDS:
        if score >= floor:
            return score, grade
    return 0, "F"


def _new_progress(scan_id: str, total: int) -> dict[str, Any]:
    return {
        "scan_id": scan_id,
        "status": "queued",
        "total": total,
        "completed": 0,
        "percent": 0,
        "requests": 0,
        "current": "",
        "started_at": time.time(),
        "updated_at": time.time(),
        "cancelled": False,
        "error": "",
    }


def _set_progress(scan_id: str, **values: Any) -> None:
    with _PROGRESS_LOCK:
        entry = _PROGRESS.get(scan_id)
        if entry is None:
            return
        entry.update(values)
        entry["updated_at"] = time.time()
        total = max(1, int(entry.get("total") or 1))
        entry["percent"] = min(
            100, int(round(int(entry.get("completed") or 0) * 100 / total))
        )


def progress(scan_id: str) -> dict[str, Any]:
    with _PROGRESS_LOCK:
        entry = _PROGRESS.get(scan_id)
        return dict(entry) if entry else {}


def _drop_progress(scan_id: str) -> None:
    with _PROGRESS_LOCK:
        _PROGRESS.pop(scan_id, None)


def _summarize(
    results: list[ModuleResult],
    score: int,
    grade: str,
    elapsed_ms: int,
    requests: int,
    cancelled: bool,
) -> dict[str, Any]:
    severity: Counter[str] = Counter()
    statuses: Counter[str] = Counter()
    categories: Counter[str] = Counter()
    for result in results:
        statuses[result.status] += 1
        categories[result.category] += 1
        for finding in result.findings:
            severity[finding.severity] += 1
    return {
        "score": score,
        "grade": grade,
        "elapsed_ms": elapsed_ms,
        "requests": requests,
        "modules_total": len(results),
        "cancelled": cancelled,
        "severity": {label: severity.get(label, 0) for label in SEVERITY_LABELS},
        "statuses": {
            "pass": statuses.get("pass", 0),
            "warn": statuses.get("warn", 0),
            "fail": statuses.get("fail", 0),
            "info": statuses.get("info", 0),
            "skipped": statuses.get("skipped", 0),
            "error": statuses.get("error", 0),
        },
        "categories": dict(categories),
    }


def _execute_module(ctx: ScanContext, spec: ModuleSpec) -> ModuleResult:
    started = time.perf_counter()
    before = ctx.requests_made
    try:
        outcome = spec.run(ctx)
        if not isinstance(outcome, Outcome):
            raise TypeError("module returned an invalid result")
    except ScanStopped:
        outcome = Outcome("skipped", "Scan was cancelled before the module finished.")
    except Exception as exc:  # a single module must never abort the scan
        logger.exception("module %s failed", spec.id)
        outcome = Outcome(
            "error",
            f"Module raised {exc.__class__.__name__}; the remaining modules continued.",
        )
    duration = int((time.perf_counter() - started) * 1000)
    requests = max(0, ctx.requests_made - before)
    findings = sorted(
        outcome.findings,
        key=lambda item: (
            SEVERITY_ORDER.get(item.severity.lower(), 9),
            item.title.lower(),
        ),
    )
    return ModuleResult(
        module_id=spec.id,
        name=spec.name,
        category=spec.category,
        status=outcome.status if outcome.status in {
            "pass",
            "warn",
            "fail",
            "info",
            "skipped",
            "error",
        } else "info",
        summary=outcome.summary,
        findings=findings[:12],
        duration_ms=duration,
        requests=requests,
    )


def _run_scan(scan_id: str, target: str, specs: list[ModuleSpec], client_ip: str) -> None:
    started = time.perf_counter()
    results: list[ModuleResult] = []
    ctx: ScanContext | None = None
    cancelled = False
    error_message = ""
    try:
        db.set_scan_running(scan_id)
        _set_progress(scan_id, status="running")
        try:
            ctx = ScanContext(target, client_ip=client_ip)
        except TargetError as exc:
            error_message = str(exc)
            _set_progress(scan_id, status="failed", error=error_message)
            db.set_scan_finished(scan_id, "failed", None, None, None, error_message)
            return
        deadline = started + SCAN_TIMEOUT_SECONDS
        pending = list(specs)
        running: dict[Future[ModuleResult], ModuleSpec] = {}
        executor = ThreadPoolExecutor(
            max_workers=max(1, min(MODULE_WORKERS, len(specs))),
            thread_name_prefix="sentinel",
        )
        try:
            while pending or running:
                while pending and len(running) < MODULE_WORKERS:
                    if time.monotonic() > deadline:
                        break
                    if db.is_cancelled(scan_id):
                        cancelled = True
                        break
                    spec = pending.pop(0)
                    _set_progress(scan_id, current=spec.name)
                    running[executor.submit(_execute_module, ctx, spec)] = spec
                if cancelled:
                    break
                if not running:
                    break
                done, _ = wait(running.keys(), timeout=1.0, return_when=FIRST_COMPLETED)
                if db.is_cancelled(scan_id):
                    cancelled = True
                if not done:
                    if time.monotonic() > deadline:
                        break
                    continue
                for future in done:
                    spec = running.pop(future)
                    try:
                        result = future.result()
                    except Exception as exc:
                        result = ModuleResult(
                            module_id=spec.id,
                            name=spec.name,
                            category=spec.category,
                            status="error",
                            summary=(
                                f"Module failed with {exc.__class__.__name__}; "
                                "the remaining modules continued."
                            ),
                            findings=[],
                            duration_ms=0,
                            requests=0,
                        )
                    results.append(result)
                    db.save_module_result(scan_id, result.as_dict())
                    _set_progress(
                        scan_id,
                        completed=len(results),
                        requests=ctx.requests_made,
                    )
                if cancelled or time.monotonic() > deadline:
                    break
        finally:
            if cancelled or time.monotonic() > deadline:
                ctx.stop()
                for future in running:
                    future.cancel()
            executor.shutdown(wait=True, cancel_futures=True)
        for spec in running.values():
            result = ModuleResult(
                module_id=spec.id,
                name=spec.name,
                category=spec.category,
                status="skipped",
                summary=(
                    "Scan was cancelled before this module finished."
                    if cancelled
                    else "Scan time limit reached before this module finished."
                ),
                findings=[],
                duration_ms=0,
                requests=0,
            )
            results.append(result)
            db.save_module_result(scan_id, result.as_dict())
        running.clear()
        for spec in pending:
            result = ModuleResult(
                module_id=spec.id,
                name=spec.name,
                category=spec.category,
                status="skipped",
                summary=(
                    "Scan was cancelled before this module ran."
                    if cancelled
                    else "Scan time limit reached before this module ran."
                ),
                findings=[],
                duration_ms=0,
                requests=0,
            )
            results.append(result)
            db.save_module_result(scan_id, result.as_dict())
        findings_flat: list[dict[str, Any]] = []
        for result in results:
            findings_flat.extend(finding.as_dict() for finding in result.findings)
        score, grade = score_from_findings(findings_flat)
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        requests = ctx.requests_made if ctx else 0
        summary = _summarize(
            results, score, grade, elapsed_ms, requests, cancelled
        )
        final_status = "cancelled" if cancelled else "completed"
        db.set_scan_finished(scan_id, final_status, score, grade, summary, None)
        _set_progress(
            scan_id,
            status=final_status,
            completed=len(results),
            requests=requests,
            current="",
            cancelled=cancelled,
        )
    except Exception as exc:  # pragma: no cover - defensive fallback
        error_message = f"Scan failed: {exc.__class__.__name__}"
        try:
            db.set_scan_finished(scan_id, "failed", None, None, None, error_message)
        except Exception:
            pass
        _set_progress(scan_id, status="failed", error=error_message)
    finally:
        if ctx is not None:
            try:
                ctx.close()
            except Exception:
                pass
        with _ACTIVE_LOCK:
            _ACTIVE.discard(scan_id)
        timer = threading.Timer(900.0, _drop_progress, args=(scan_id,))
        timer.daemon = True
        timer.start()


def start_scan(
    scan_id: str, target: str, module_ids: Iterable[str] | None, client_ip: str = ""
) -> list[ModuleSpec]:
    specs = find_modules(module_ids)
    with _ACTIVE_LOCK:
        if scan_id in _ACTIVE:
            raise ValueError("This scan is already running.")
        _ACTIVE.add(scan_id)
    with _PROGRESS_LOCK:
        _PROGRESS[scan_id] = _new_progress(scan_id, len(specs))
    worker = threading.Thread(
        target=_run_scan,
        args=(scan_id, target, specs, client_ip),
        name=f"sentinel-scan-{scan_id}",
        daemon=True,
    )
    worker.start()
    return specs


def recover_interrupted_scans() -> int:
    """Mark scans abandoned by a previous process as failed on startup."""
    count = 0
    for scan in db.list_scans(limit=200):
        if scan["status"] in {"queued", "running"}:
            db.set_scan_finished(
                scan["id"],
                "failed",
                scan.get("score"),
                scan.get("grade"),
                None,
                "The service restarted before this scan finished.",
            )
            count += 1
    return count

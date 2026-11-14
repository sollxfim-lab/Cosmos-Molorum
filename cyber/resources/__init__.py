"""Wordlists used by Sentinel security probes.

Each loader reads a plain-text file of one entry per line, skips comment
lines (starting with #) and blank lines, and strips whitespace. All entries
are benign, non-destructive probes designed to detect insecure handling of
input; no exploit payloads are executed and no sensitive files are read.
"""

from __future__ import annotations

import pathlib


def _load(path: str) -> list[str]:
    p = pathlib.Path(path)
    if not p.exists():
        return []
    lines: list[str] = []
    for raw in p.read_text(encoding="utf-8", errors="replace").splitlines():
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        lines.append(s)
    return lines


ROOT = pathlib.Path(__file__).parent

SQL_PAYLOADS = _load(ROOT / "sql_payloads.txt")
LFI_PAYLOADS = _load(ROOT / "lfi_payloads.txt")
DIR_FUZZ = _load(ROOT / "dir_fuzz.txt")
XSS_PAYLOADS = _load(ROOT / "xss_payloads.txt")
REDIRECT_TARGETS = _load(ROOT / "redirect_targets.txt")
PATH_TRAVERSAL = LFI_PAYLOADS


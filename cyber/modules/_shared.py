"""Small shared helpers for the extended module set."""

from __future__ import annotations

import re
from typing import Iterable

from ..engine import Probe

SPA_RE = re.compile(
    r"(<div[^>]+id=[\"'](?:root|app|__next)[\"']|__NEXT_DATA__|"
    r"ng-version=|data-reactroot)",
    re.IGNORECASE,
)


def looks_like_spa(probe: Probe) -> bool:
    if not probe.ok or not probe.text:
        return False
    body = probe.text[:120_000]
    if not body.lstrip().startswith("<"):
        return False
    return bool(SPA_RE.search(body))


def plain(probe: Probe) -> bool:
    """Return True for a real, non-SPA 200 response."""
    return probe.ok and probe.status == 200 and not looks_like_spa(probe)


def contains_any(text: str, patterns: Iterable[str]) -> str:
    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return match.group(0)[:180]
    return ""


def excerpt(text: str, limit: int = 220) -> str:
    value = re.sub(r"\s+", " ", text or "").strip()
    return value[:limit]

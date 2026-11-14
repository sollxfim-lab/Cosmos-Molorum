from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable


SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}

SEVERITY_WEIGHT = {
    "critical": 15,
    "high": 8,
    "medium": 3,
    "low": 1,
    "info": 0,
}


@dataclass
class Finding:
    title: str
    severity: str
    detail: str
    evidence: str = ""
    remediation: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity,
            "detail": self.detail,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }


@dataclass
class Outcome:
    status: str
    summary: str
    findings: list[Finding] = field(default_factory=list)


@dataclass(frozen=True)
class ModuleSpec:
    id: str
    name: str
    category: str
    description: str
    severity: str
    passive: bool
    run: Callable[["ScanContext"], Outcome]

    def public(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "category": self.category,
            "description": self.description,
            "severity": self.severity,
            "passive": self.passive,
        }


@dataclass
class ModuleResult:
    module_id: str
    name: str
    category: str
    status: str
    summary: str
    findings: list[Finding]
    duration_ms: int
    requests: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "module_id": self.module_id,
            "name": self.name,
            "category": self.category,
            "status": self.status,
            "summary": self.summary,
            "findings": [f.as_dict() for f in self.findings],
            "duration_ms": self.duration_ms,
            "requests": self.requests,
        }

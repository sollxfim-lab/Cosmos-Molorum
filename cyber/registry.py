from __future__ import annotations

from .models import Finding, ModuleSpec, Outcome

MODULES: list[ModuleSpec] = []

CATEGORY_ORDER = [
    "Transport & DNS",
    "Session & Browser",
    "Exposure & Discovery",
    "Injection & Input",
    "Edge & Defense",
]

CATEGORY_DESCRIPTIONS = {
    "Transport & DNS": "TLS, DNS, email authentication and protocol posture.",
    "Session & Browser": "Cookies, CORS, caching, framing and mixed content.",
    "Exposure & Discovery": "Files, metadata, debug surfaces, APIs and secret leakage.",
    "Injection & Input": "Non-destructive probes for injection and input handling flaws.",
    "Edge & Defense": "Edge protection and defensive control detection.",
}


def module(
    module_id: str,
    name: str,
    category: str,
    description: str,
    severity: str = "medium",
    passive: bool = False,
):
    def register(fn):
        MODULES.append(
            ModuleSpec(
                id=module_id,
                name=name,
                category=category,
                description=description,
                severity=severity,
                passive=passive,
                run=fn,
            )
        )
        return fn

    return register


def verdict(findings: list[Finding]) -> str:
    if any(f.severity in {"critical", "high"} for f in findings):
        return "fail"
    if any(f.severity in {"medium", "low"} for f in findings):
        return "warn"
    if findings:
        return "info"
    return "pass"


def ordered_modules() -> list[ModuleSpec]:
    return sorted(
        MODULES,
        key=lambda item: (
            CATEGORY_ORDER.index(item.category)
            if item.category in CATEGORY_ORDER
            else 99,
            MODULES.index(item),
        ),
    )

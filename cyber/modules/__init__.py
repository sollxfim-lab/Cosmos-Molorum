"""Import every module package so decorators populate the registry."""

from . import (  # noqa: F401
    disclosure,
    edge_ext,
    exposure_ext,
    injection,
    injection_ext,
    session,
    session_ext,
    transport,
    transport_ext,
    wordlist_ext,
)

__all__ = [
    "transport",
    "transport_ext",
    "session",
    "session_ext",
    "disclosure",
    "exposure_ext",
    "injection",
    "injection_ext",
    "edge_ext",
    "wordlist_ext",
]

from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _data_dir() -> Path:
    explicit = os.environ.get("VITESTL_CYBER_DATA_DIR")
    if explicit:
        return Path(explicit).expanduser().resolve()
    base = os.environ.get("VITESTL_DATA_DIR") or os.environ.get("KESTREL_DATA_DIR")
    if base:
        return (Path(base).expanduser().resolve() / "cyber")
    return ROOT / "data" / "cyber"


DATA = _data_dir()
DATA.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA / "cyber.db"

SECRET = os.environ.get("KESTREL_SECRET", "cosmos-molorum-sentinel-development-secret")
TOKEN_TTL = 12 * 60 * 60
PRODUCT_NAME = "Cosmos Molorum Sentinel"
PRODUCT_SHORT = "Sentinel"
COMPANY = "Cosmos Molorum"
VERSION = "2.2.0"
MODULE_COUNT = 105
PUBLIC_PORT = int(os.environ.get("CM_CYBER_PORT", "7999"))

DEFAULT_ADMIN_USER = os.environ.get("KESTREL_ADMIN_USER", "Yanxzyx")
DEFAULT_ADMIN_PASS = os.environ.get("KESTREL_ADMIN_PASS", "Kestrel.admin1")
DEFAULT_ADMIN_EMAIL = os.environ.get("KESTREL_ADMIN_EMAIL", "yanxzyx@cosmosmolorum.local")

# Scanner guard rails. These are deliberately conservative so that a scan
# remains a lightweight assessment rather than a stress test.
SCAN_REQUEST_BUDGET = 900
SCAN_TIMEOUT_SECONDS = 480
MODULE_WORKERS = 6
REQUEST_TIMEOUT_SECONDS = 9.0
REQUEST_DELAY_SECONDS = 0.05
MAX_RESPONSE_BYTES = 1_500_000
MAX_REDIRECTS = 5
MAX_FINDINGS_PER_MODULE = 12
# Scope validation resolves the target for every request. A short cache keeps
# the scan fast while still re-checking DNS often enough to notice rebinding.
RESOLVE_CACHE_TTL_SECONDS = 15.0

BLOCKED_NETWORKS = (
    "169.254.0.0/16",
    "224.0.0.0/4",
    "0.0.0.0/32",
    "255.255.255.255/32",
)
BLOCKED_HOSTS = {
    "metadata.google.internal",
    "metadata.goog",
    "instance-data",
}

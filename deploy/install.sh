#!/usr/bin/env bash
set -euo pipefail

# Cosmos Molorum Debian installer.
#
# Supported targets: Debian 12/13 and Debian derivatives with systemd + nginx.
# The panel and its workloads run on this host; there is no remote agent to
# install. This script installs the Python/Node build dependencies, builds the
# frontend, creates the service account and data directory, and enables the
# systemd unit and nginx reverse proxy.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_DIR="${VITESTL_APP_DIR:-/opt/vitestl}"
DATA_DIR="${VITESTL_DATA_DIR:-/var/lib/vitestl}"
ENV_FILE="/etc/vitestl.env"
SERVICE_NAME="vitestl"
SENTINEL_SERVICE="cosmos-sentinel"
DOMAIN="_"
LISTEN_PORT="80"
CYBER_PORT="7999"
MODE=""
ASSUME_YES=0
ADMIN_PASS=""
WITH_DOCKER=0
NO_BUILD=0
NO_NGINX=0
FORCE=0

log()  { printf '\033[1;34m[vitestl]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[vitestl]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[vitestl]\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
Usage: sudo bash deploy/install.sh [options]

Options:
  --mode MODE         hosting panel or cybersecurity suite
                      (interactive chooser is shown when omitted)
  --domain NAME       nginx server_name (default: _)
  --port PORT         nginx listen port for the hosting panel (default: 80)
  --cyber-port PORT   public port for the Sentinel console (default: 7999)
  --app-dir PATH      application directory (default: /opt/vitestl)
  --data-dir PATH     writable data directory (default: /var/lib/vitestl)
  --admin-pass PASS   initial admin password for a fresh install
  --with-docker       install Docker and allow Docker-backed eggs
  --no-build          reuse an existing frontend/dist build
  --no-nginx          skip nginx installation
  --yes               skip the cybersecurity confirmation prompt
  --force             continue on a non-Debian distribution
  -h, --help          show this help

Modes:
  hosting             Cosmos Molorum hosting panel plus Sentinel (default)
  cyber               Cosmos Molorum Sentinel security console only

Examples:
  sudo bash deploy/install.sh --domain panel.example.com
  sudo bash deploy/install.sh --with-docker --domain panel.example.com
  sudo bash deploy/install.sh --mode cyber --domain sentinel.example.com
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode) MODE="${2:-}"; shift 2 ;;
    --domain) DOMAIN="${2:-}"; shift 2 ;;
    --port) LISTEN_PORT="${2:-80}"; shift 2 ;;
    --cyber-port) CYBER_PORT="${2:-7999}"; shift 2 ;;
    --app-dir) APP_DIR="${2:-}"; shift 2 ;;
    --data-dir) DATA_DIR="${2:-}"; shift 2 ;;
    --admin-pass) ADMIN_PASS="${2:-}"; shift 2 ;;
    --with-docker) WITH_DOCKER=1; shift ;;
    --no-build) NO_BUILD=1; shift ;;
    --no-nginx) NO_NGINX=1; shift ;;
    --yes) ASSUME_YES=1; shift ;;
    --force) FORCE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "Unknown option: $1 (use --help)" ;;
  esac
done

[[ "$EUID" -eq 0 ]] || die "Run this installer as root: sudo bash deploy/install.sh"
[[ -n "$DOMAIN" ]] || die "--domain cannot be empty"
[[ "$LISTEN_PORT" =~ ^[0-9]+$ ]] || die "--port must be numeric"
[[ "$CYBER_PORT" =~ ^[0-9]+$ ]] || die "--cyber-port must be numeric"
[[ "$CYBER_PORT" -ge 1 && "$CYBER_PORT" -le 65535 ]] || die "--cyber-port must be between 1 and 65535"
case "$MODE" in
  ""|hosting|cyber) ;;
  *) die "--mode must be hosting or cyber" ;;
esac
[[ -f "$ROOT/backend/requirements.txt" ]] || die "Run the installer from the repository root"

if [[ -r /etc/os-release ]]; then
  # shellcheck disable=SC1091
  . /etc/os-release
fi

case "${ID:-}" in
  debian|ubuntu|raspbian|linuxmint|pop) ;;
  *)
    if [[ "$FORCE" -ne 1 ]]; then
      die "This installer targets Debian/Ubuntu (detected: ${PRETTY_NAME:-unknown}). Use --force to continue."
    fi
    warn "Continuing on ${PRETTY_NAME:-an unsupported distribution} because --force was supplied."
    ;;
esac

banner() {
  printf '\n\033[1;36m'
  cat <<'EOF'
  ============================================================
             C O S M O S   M O L O R U M
       hosting control plane  ·  security workspace
  ============================================================
EOF
  printf '\033[0m\n'
}

select_mode() {
  local choice=""
  local confirm=""
  banner
  if [[ -z "$MODE" ]]; then
    if [[ ! -t 0 && ! -r /dev/tty ]]; then
      MODE="hosting"
      warn "No interactive terminal detected; defaulting to hosting mode."
      warn "Use --mode cyber to install Cosmos Molorum Sentinel."
      return
    fi
    printf '  Pilih mode instalasi:\n\n'
    printf '  \033[1;37m1)\033[0m Hosting Panel\n'
    printf '     Panel hosting Cosmos Molorum, workload, dan administrasi server.\n'
    printf '     Sentinel ikut terpasang sebagai mode keamanan di port %s.\n\n' "$CYBER_PORT"
    printf '  \033[1;37m2)\033[0m Cybersecurity Suite\n'
    printf '     Cosmos Molorum Sentinel: login, 105 modul asesmen keamanan,\n'
    printf '     analisis temuan, dan audit operator di port %s.\n\n' "$CYBER_PORT"
    while [[ -z "$MODE" ]]; do
      printf '  Masukkan pilihan [1/2]: '
      read -r choice || die "Input tidak tersedia."
      case "$choice" in
        1|hosting|Hosting) MODE="hosting" ;;
        2|cyber|Cybersecurity|cybersecurity) MODE="cyber" ;;
        *) warn "Pilihan tidak dikenal. Masukkan 1 atau 2." ;;
      esac
    done
  else
    printf '  Mode: %s\n\n' "$MODE"
  fi
  if [[ "$MODE" == "cyber" && "$ASSUME_YES" -ne 1 ]]; then
    printf '  \033[1;33mKonfirmasi Cybersecurity Suite\033[0m\n'
    printf '  Sentinel dipasang sebagai layanan terpisah, berjalan publik di port %s,\n' "$CYBER_PORT"
    printf '  dengan halaman login dan 105 modul pemindaian. Data disimpan di\n'
    printf '  %s/cyber dan setiap aktivitas operator dicatat pada jejak audit.\n\n' "$DATA_DIR"
    if [[ -t 0 ]]; then
      printf '  Ketik Y untuk melanjutkan: '
      read -r confirm
    elif [[ -r /dev/tty ]]; then
      printf '  Ketik Y untuk melanjutkan: ' >/dev/tty
      read -r confirm </dev/tty
    else
      die "Konfirmasi diperlukan. Jalankan ulang dengan --yes untuk instalasi non-interaktif."
    fi
    case "$confirm" in
      y|Y|ya|YA|Ya) ;;
      *) die "Instalasi dibatalkan." ;;
    esac
    printf '\n'
  fi
}

select_mode
if [[ "$MODE" == "cyber" ]]; then
  SERVICE_NAME="cosmos-sentinel"
  LISTEN_PORT="$CYBER_PORT"
else
  [[ -f "$ROOT/frontend/package.json" ]] || die "frontend/package.json is missing"
fi

if [[ "$NO_NGINX" -eq 1 ]]; then
  SENTINEL_PUBLIC_PORT="7998"
else
  SENTINEL_PUBLIC_PORT="$CYBER_PORT"
fi

# Address shown to the operator in credentials and the final summary.
if [[ "$NO_NGINX" -eq 1 ]]; then
  ACCESS_HOST="127.0.0.1"
  if [[ "$MODE" == "cyber" ]]; then
    ACCESS_PORT="7998"
  else
    ACCESS_PORT="8000"
  fi
else
  ACCESS_HOST="$DOMAIN"
  if [[ "$ACCESS_HOST" == "_" ]]; then
    ACCESS_HOST="$(hostname -I 2>/dev/null | awk '{print $1}')"
    ACCESS_HOST="${ACCESS_HOST:-127.0.0.1}"
  fi
  ACCESS_PORT="$LISTEN_PORT"
fi

log "Installing system packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
  python3 python3-venv python3-pip \
  nginx sqlite3 curl ca-certificates tar gnupg

python3 - <<'PY' || die "Python 3.10 or newer is required"
import sys
raise SystemExit(0 if sys.version_info >= (3, 10) else 1)
PY

node_major() {
  node -p "process.versions.node.split('.')[0]" 2>/dev/null || echo 0
}

if [[ "$MODE" == "hosting" ]]; then
  if ! command -v node >/dev/null 2>&1; then
    log "Installing Node.js from Debian repositories"
    apt-get install -y --no-install-recommends nodejs npm
  fi

  if [[ "$(node_major)" -lt 18 ]]; then
    log "Installing Node.js 20 from NodeSource"
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
    apt-get install -y --no-install-recommends nodejs
    [[ "$(node_major)" -ge 18 ]] || die "Node.js 18+ is required to build the interface"
  fi

  if ! command -v npm >/dev/null 2>&1; then
    log "Installing npm"
    apt-get install -y --no-install-recommends npm
  fi
else
  log "Cybersecurity mode: skipping the Node.js frontend build"
fi

if ! id vitestl >/dev/null 2>&1; then
  log "Creating the vitestl service account"
  useradd --system --home-dir "$APP_DIR" --shell /usr/sbin/nologin --no-create-home vitestl
fi

if [[ "$ROOT" != "$APP_DIR" ]]; then
  log "Copying the application to $APP_DIR"
  mkdir -p "$APP_DIR"
  tar -C "$ROOT" \
    --exclude='./.git' \
    --exclude='./.venv' \
    --exclude='./data' \
    --exclude='./frontend/node_modules' \
    -cf - . | tar -C "$APP_DIR" -xf -
fi

install -d -o vitestl -g vitestl -m 0750 "$DATA_DIR"
if [[ "$MODE" == "hosting" ]]; then
  install -d -o root -g root -m 0755 "$APP_DIR/frontend"
fi
# Sentinel static assets and wordlists are served or read by the service.
chmod -R a+rX "$APP_DIR/cyber/web"
chmod -R a+rX "$APP_DIR/cyber/resources"

log "Creating the Python environment"
python3 -m venv "$APP_DIR/.venv"
"$APP_DIR/.venv/bin/python" -m pip install --quiet --upgrade pip wheel
"$APP_DIR/.venv/bin/pip" install --quiet --no-cache-dir -r "$APP_DIR/backend/requirements.txt"

if [[ "$MODE" == "hosting" ]]; then
  if [[ "$NO_BUILD" -eq 1 ]]; then
    [[ -f "$APP_DIR/frontend/dist/index.html" ]] || \
      die "frontend/dist is missing; run without --no-build or build it first"
    log "Reusing the existing frontend build"
  else
    log "Building the interface with Node $(node -v)"
    rm -rf "$APP_DIR/frontend/dist"
    cd "$APP_DIR/frontend"
    if [[ -f package-lock.json ]]; then
      npm ci --no-audit --no-fund --prefer-offline || {
        warn "npm ci failed; retrying with npm install"
        npm install --no-audit --no-fund --prefer-offline
      }
    else
      npm install --no-audit --no-fund --prefer-offline
    fi
    [[ -x node_modules/.bin/vite ]] || \
      die "Vite is missing after npm install; remove frontend/node_modules and retry"
    npm run build
    cd "$ROOT"
  fi

  chmod -R a+rX "$APP_DIR/frontend/dist"
else
  log "Cybersecurity interface is served from cyber/web"
fi

if [[ ! -f "$ENV_FILE" ]]; then
  log "Writing $ENV_FILE"
  SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
  if [[ -z "$ADMIN_PASS" ]]; then
    ADMIN_PASS="$(python3 -c 'import secrets, string; a=string.ascii_letters+string.digits; print("CM-" + "".join(secrets.choice(a) for _ in range(20)))')"
  fi
  cat > "$ENV_FILE" <<EOF
KESTREL_SECRET=$SECRET
KESTREL_ADMIN_USER=Yanxzyx
KESTREL_ADMIN_PASS=$ADMIN_PASS
KESTREL_ADMIN_EMAIL=yanxzyx@cosmosmolorum.local
VITESTL_DATA_DIR=$DATA_DIR
EOF
  printf 'CM_CYBER_PORT=%s\n' "$SENTINEL_PUBLIC_PORT" >> "$ENV_FILE"
  chmod 600 "$ENV_FILE"
  if [[ "$MODE" == "cyber" ]]; then
    cat > /root/vitestl-credentials.txt <<EOF
Cosmos Molorum Sentinel initial credentials
URL:      http://${ACCESS_HOST}:${ACCESS_PORT}/
Username: Yanxzyx
Password: ${ADMIN_PASS}
Env file: ${ENV_FILE}
Product:  Cosmos Molorum Sentinel 2.2.0
Change the password after the first sign-in.
EOF
  else
    cat > /root/vitestl-credentials.txt <<EOF
Cosmos Molorum initial credentials
URL:      http://${ACCESS_HOST}:${ACCESS_PORT}/
Sentinel: http://${ACCESS_HOST}:${SENTINEL_PUBLIC_PORT}/
Username: Yanxzyx
Password: ${ADMIN_PASS}
Env file: ${ENV_FILE}
Change the password after the first sign-in.
EOF
  fi
  chmod 600 /root/vitestl-credentials.txt
  if [[ "$MODE" == "cyber" ]]; then
    cp /root/vitestl-credentials.txt /root/sentinel-credentials.txt
    chmod 600 /root/sentinel-credentials.txt
  fi
  log "Initial credentials saved to /root/vitestl-credentials.txt"
else
  log "Keeping the existing $ENV_FILE"
  if ! grep -q '^VITESTL_DATA_DIR=' "$ENV_FILE"; then
    printf 'VITESTL_DATA_DIR=%s\n' "$DATA_DIR" >> "$ENV_FILE"
  fi
  if ! grep -q '^CM_CYBER_PORT=' "$ENV_FILE"; then
    printf 'CM_CYBER_PORT=%s\n' "$SENTINEL_PUBLIC_PORT" >> "$ENV_FILE"
  fi
fi

if [[ "$ROOT" != "$APP_DIR" ]]; then
  chown -R root:root "$APP_DIR"
fi
chown root:root "$ENV_FILE"
chmod 600 "$ENV_FILE"

log "Installing systemd units"
install_unit() {
  local template="$1"
  local unit="$2"
  sed -e "s|@APP_DIR@|$APP_DIR|g" -e "s|@DATA_DIR@|$DATA_DIR|g" \
    "$APP_DIR/deploy/${template}" > "/etc/systemd/system/${unit}.service"
  chmod 0644 "/etc/systemd/system/${unit}.service"
}

if [[ "$MODE" == "hosting" ]]; then
  install_unit "vitestl.service" "$SERVICE_NAME"
  install_unit "cyber.service" "$SENTINEL_SERVICE"
else
  install_unit "cyber.service" "$SERVICE_NAME"
fi

if [[ "$WITH_DOCKER" -eq 1 && "$MODE" == "hosting" ]]; then
  log "Installing Docker"
  apt-get install -y --no-install-recommends docker.io
  systemctl enable --now docker
  getent group docker >/dev/null && usermod -aG docker vitestl
  install -d -m 0755 "/etc/systemd/system/${SERVICE_NAME}.service.d"
  cat > "/etc/systemd/system/${SERVICE_NAME}.service.d/10-docker.conf" <<'EOF'
[Service]
SupplementaryGroups=docker
EOF
elif [[ "$WITH_DOCKER" -eq 1 ]]; then
  warn "--with-docker only applies to hosting mode; skipping Docker."
fi

systemctl daemon-reload
if [[ "$MODE" == "hosting" ]]; then
  systemctl enable "$SERVICE_NAME" "$SENTINEL_SERVICE"
  systemctl restart "$SERVICE_NAME"
  systemctl restart "$SENTINEL_SERVICE"
else
  systemctl enable "$SERVICE_NAME"
  systemctl restart "$SERVICE_NAME"
fi

wait_health() {
  local label="$1"
  local url="$2"
  local unit="$3"
  local ready=0
  log "Waiting for the ${label} API"
  for _ in $(seq 1 60); do
    if curl -fsS "$url" >/dev/null 2>&1; then
      ready=1
      break
    fi
    sleep 0.5
  done
  if [[ "$ready" -ne 1 ]]; then
    journalctl -u "$unit" -n 40 --no-pager || true
    die "The ${label} did not become healthy. Inspect: journalctl -u $unit"
  fi
}

if [[ "$MODE" == "hosting" ]]; then
  wait_health "panel" "http://127.0.0.1:8000/api/health" "$SERVICE_NAME"
  wait_health "Sentinel" "http://127.0.0.1:7998/api/health" "$SENTINEL_SERVICE"
else
  wait_health "Sentinel" "http://127.0.0.1:7998/api/health" "$SERVICE_NAME"
fi

if [[ "$NO_NGINX" -eq 0 ]]; then
  if [[ "$MODE" == "cyber" ]]; then
    log "Configuring nginx on port $LISTEN_PORT"
    sed -e "s|@APP_DIR@|$APP_DIR|g" \
        -e "s|@SERVER_NAME@|$DOMAIN|g" \
        -e "s|@LISTEN_PORT@|$LISTEN_PORT|g" \
        "$APP_DIR/deploy/nginx-cyber.conf" > "/etc/nginx/sites-available/${SERVICE_NAME}"
    ln -sf "/etc/nginx/sites-available/${SERVICE_NAME}" "/etc/nginx/sites-enabled/${SERVICE_NAME}"
  else
    log "Configuring the panel site on port $LISTEN_PORT"
    sed -e "s|@APP_DIR@|$APP_DIR|g" \
        -e "s|@SERVER_NAME@|$DOMAIN|g" \
        -e "s|@LISTEN_PORT@|$LISTEN_PORT|g" \
        "$APP_DIR/deploy/nginx.conf" > "/etc/nginx/sites-available/${SERVICE_NAME}"
    ln -sf "/etc/nginx/sites-available/${SERVICE_NAME}" "/etc/nginx/sites-enabled/${SERVICE_NAME}"

    log "Configuring the Sentinel site on port $CYBER_PORT"
    sed -e "s|@APP_DIR@|$APP_DIR|g" \
        -e "s|@SERVER_NAME@|$DOMAIN|g" \
        -e "s|@LISTEN_PORT@|$CYBER_PORT|g" \
        "$APP_DIR/deploy/nginx-cyber.conf" > "/etc/nginx/sites-available/${SENTINEL_SERVICE}"
    ln -sf "/etc/nginx/sites-available/${SENTINEL_SERVICE}" "/etc/nginx/sites-enabled/${SENTINEL_SERVICE}"
  fi
  if [[ "$MODE" == "hosting" && -L /etc/nginx/sites-enabled/default ]]; then
    mv /etc/nginx/sites-enabled/default /etc/nginx/sites-enabled/default.disabled
    log "Disabled the default nginx site"
  fi
  nginx -t
  systemctl reload nginx
fi

log "Installation complete"
printf '\n'
if [[ "$MODE" == "cyber" ]]; then
  printf '  Product:  Cosmos Molorum Sentinel 2.2.0\n'
  printf '  Mode:     Cybersecurity Suite\n'
  printf '  Modules:  105 security assessment modules\n'
  printf '  URL:      http://%s:%s/\n' "$ACCESS_HOST" "$ACCESS_PORT"
  printf '  Service:  systemctl status %s\n' "$SERVICE_NAME"
  printf '  Logs:     journalctl -u %s -f\n' "$SERVICE_NAME"
else
  printf '  Product:  Cosmos Molorum hosting control plane\n'
  printf '  Mode:     Hosting Panel + Sentinel\n'
  printf '  Panel:    http://%s:%s/\n' "$ACCESS_HOST" "$ACCESS_PORT"
  printf '  Sentinel: http://%s:%s/\n' "$ACCESS_HOST" "$SENTINEL_PUBLIC_PORT"
  printf '  Services: systemctl status %s %s\n' "$SERVICE_NAME" "$SENTINEL_SERVICE"
  printf '  Logs:     journalctl -u %s -f\n' "$SERVICE_NAME"
  printf '            journalctl -u %s -f\n' "$SENTINEL_SERVICE"
fi
if [[ "$NO_NGINX" -eq 1 ]]; then
  printf '  Note:     --no-nginx was used, so these are the local upstreams only.\n'
fi
printf '  Data:     %s\n' "$DATA_DIR"
if [[ -f /root/vitestl-credentials.txt ]]; then
  printf '  Login:    /root/vitestl-credentials.txt\n\n'
else
  printf '  Login:    credentials were preserved from the previous install\n\n'
fi
if [[ "$MODE" == "cyber" ]]; then
  printf 'Next: sign in and start an assessment. Sentinel records every operator action in the audit trail.\n'
else
  printf 'Next: sign in, open Administration → Nodes, and run Auto-install node.\n'
  printf 'The Sentinel security mode is available from the sidebar and the dashboard.\n'
fi

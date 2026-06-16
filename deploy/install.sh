#!/usr/bin/env bash
#
# Install / upgrade mikromon as a systemd service on Ubuntu 22.04 / 24.04 / 26.04+.
# Safe to re-run — idempotent at every step.
# Run as root from the project root:  sudo bash deploy/install.sh
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
APP_DIR=/opt/mikromon
SERVICE_USER=mikromon
SYSTEMD_UNIT=/etc/systemd/system/mikromon.service
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WEB_PORT=8080

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log()  { echo "  $*"; }
step() { echo; echo ">> $*"; }
die()  { echo "ERROR: $*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# 1. Sanity checks
# ---------------------------------------------------------------------------
step "Pre-flight checks"

[[ "${EUID}" -eq 0 ]] || die "Must be run as root.  Use: sudo bash deploy/install.sh"

if ! command -v systemctl &>/dev/null; then
    die "systemctl not found — systemd is required to register the service."
fi

log "Source : ${SRC_DIR}"
log "Install: ${APP_DIR}"

# ---------------------------------------------------------------------------
# 2. System packages  (apt is idempotent by design)
# ---------------------------------------------------------------------------
step "Installing system packages (apt)"

apt-get update -qq

# python3-full  →  python3 + python3-venv + standard-library extras (Ubuntu 22+)
# python3-dev   →  headers for building C extensions (e.g. PyYAML's C backend)
# build-essential libssl-dev libffi-dev libyaml-dev  →  C-extension build toolchain
# ca-certificates curl  →  trusted roots for pip HTTPS downloads
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    python3-full \
    python3-pip \
    python3-dev \
    build-essential \
    libssl-dev \
    libffi-dev \
    libyaml-dev \
    ca-certificates \
    curl

PYTHON_BIN="$(command -v python3)"
PYTHON_VER="$("${PYTHON_BIN}" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
log "Python ${PYTHON_VER} at ${PYTHON_BIN}"

# ---------------------------------------------------------------------------
# 3. Dedicated unprivileged system user  (skip if already exists)
# ---------------------------------------------------------------------------
step "Creating service user"

if ! id -u "${SERVICE_USER}" &>/dev/null; then
    useradd --system --home "${APP_DIR}" --shell /usr/sbin/nologin "${SERVICE_USER}"
    log "Created system user '${SERVICE_USER}'"
else
    log "System user '${SERVICE_USER}' already exists — skipping"
fi

# ---------------------------------------------------------------------------
# 4. Application files
# ---------------------------------------------------------------------------
step "Copying application files"

mkdir -p "${APP_DIR}"

# rsync with --delete keeps the destination in sync with the source and
# removes stale files from previous installs.  Falls back to cp on minimal
# images that don't have rsync.
if command -v rsync &>/dev/null; then
    rsync -a --delete \
        --exclude='__pycache__/' \
        --exclude='*.pyc' \
        --exclude='*.pyo' \
        "${SRC_DIR}/mikromon/" "${APP_DIR}/mikromon/"
else
    rm -rf "${APP_DIR}/mikromon"
    cp -r "${SRC_DIR}/mikromon" "${APP_DIR}/"
    find "${APP_DIR}/mikromon" -type d -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true
    find "${APP_DIR}/mikromon" \( -name '*.pyc' -o -name '*.pyo' \) -delete 2>/dev/null || true
fi

# Always overwrite requirements.txt so pip can detect changes on upgrade.
cp "${SRC_DIR}/requirements.txt" "${APP_DIR}/"

# example config — overwrite so it stays current with the source.
cp "${SRC_DIR}/config.example.yaml" "${APP_DIR}/config.example.yaml"

# Live config — only create on first install; never overwrite user's edits.
if [[ ! -f "${APP_DIR}/config.yaml" ]]; then
    cp "${SRC_DIR}/config.example.yaml" "${APP_DIR}/config.yaml"
    log "Created ${APP_DIR}/config.yaml  — EDIT THIS before starting the service!"
else
    log "${APP_DIR}/config.yaml already exists — not overwritten"
fi

# ---------------------------------------------------------------------------
# 5. Python virtual environment + dependencies
# ---------------------------------------------------------------------------
step "Building Python virtual environment"

# Re-use existing venv if present; --upgrade-deps keeps pip current.
if [[ -d "${APP_DIR}/.venv" ]]; then
    log "Virtual environment already exists — reusing"
else
    "${PYTHON_BIN}" -m venv "${APP_DIR}/.venv"
    log "Created new virtual environment"
fi

PIP="${APP_DIR}/.venv/bin/pip"

log "Upgrading pip / setuptools / wheel..."
"${PIP}" install --quiet --upgrade pip setuptools wheel

log "Installing / upgrading requirements.txt..."
"${PIP}" install --quiet --upgrade -r "${APP_DIR}/requirements.txt"

echo
"${PIP}" list --format=columns
echo

# ---------------------------------------------------------------------------
# 6. File ownership and permissions
# ---------------------------------------------------------------------------
step "Setting file permissions"

chown -R "${SERVICE_USER}:${SERVICE_USER}" "${APP_DIR}"
chmod 640 "${APP_DIR}/config.yaml"
chmod 755 "${APP_DIR}"

# ---------------------------------------------------------------------------
# 7. Web dashboard network binding
# ---------------------------------------------------------------------------
step "Configuring web dashboard (host 0.0.0.0, port ${WEB_PORT})"

CONFIG_FILE="${APP_DIR}/config.yaml"

# Idempotent: patches only the web: block's host/port lines.
# Uses a state-machine so it never touches smtp.port or api_port.
"${PYTHON_BIN}" - "${CONFIG_FILE}" "${WEB_PORT}" <<'PYEOF'
import sys

config_path = sys.argv[1]
port        = int(sys.argv[2])

with open(config_path) as fh:
    lines = fh.readlines()

original = list(lines)
in_web   = False

for i, line in enumerate(lines):
    stripped = line.lstrip()
    indent   = len(line) - len(stripped)

    # Detect entering / leaving the top-level "web:" block.
    if line.startswith("web:"):
        in_web = True
        continue
    if in_web and indent == 0 and not line.startswith(" ") and line.strip():
        in_web = False

    if in_web:
        if stripped.startswith("host:"):
            lines[i] = line.replace("127.0.0.1", "0.0.0.0")
        elif stripped.startswith("port:"):
            key = line[: line.index("port:") + 5]
            rest = line[len(key):]
            current = rest.strip().split()[0] if rest.strip() else ""
            if current != str(port):
                lines[i] = f"{key} {port}\n"

if lines != original:
    with open(config_path, "w") as fh:
        fh.writelines(lines)
    print(f"  web.host → 0.0.0.0, web.port → {port}")
else:
    print(f"  web binding already correct (0.0.0.0:{port}) — no change")
PYEOF

# ---------------------------------------------------------------------------
# 8. Firewall — open the dashboard port  (ufw is idempotent)
# ---------------------------------------------------------------------------
step "Opening firewall port ${WEB_PORT}/tcp"

if command -v ufw &>/dev/null; then
    ufw allow "${WEB_PORT}/tcp" comment "mikromon dashboard" || true
    log "UFW rule present for port ${WEB_PORT}/tcp"
else
    log "ufw not found — skipping (open port ${WEB_PORT} manually if needed)"
fi

# ---------------------------------------------------------------------------
# 9. systemd service units (monitor + web dashboard)
# ---------------------------------------------------------------------------
step "Registering systemd services"

WEB_UNIT=/etc/systemd/system/mikromon-web.service

# Stop running services before replacing their unit files.
for svc in mikromon-web mikromon; do
    if systemctl is-active --quiet "${svc}" 2>/dev/null; then
        systemctl stop "${svc}"
        log "Stopped ${svc} for upgrade"
    fi
done

cp "${SRC_DIR}/deploy/mikromon.service"     "${SYSTEMD_UNIT}"
cp "${SRC_DIR}/deploy/mikromon-web.service" "${WEB_UNIT}"
chmod 644 "${SYSTEMD_UNIT}" "${WEB_UNIT}"
systemctl daemon-reload

log "Monitor unit : ${SYSTEMD_UNIT}"
log "Web unit     : ${WEB_UNIT}"

# ---------------------------------------------------------------------------
# SSTP dial-home server (accel-ppp) — lets routers connect BACK to this box.
# mikromon writes each device's credentials to ${SSTP_SECRETS}; accel-ppp reads
# that file, and a path-unit reloads accel-ppp whenever it changes. Best-effort:
# if accel-ppp isn't available the core install still succeeds.
# ---------------------------------------------------------------------------
step "Setting up the SSTP dial-home server (accel-ppp)"
SSTP_SECRETS="${APP_DIR}/sstp-secrets"
set +e
(
  set -e
  # secrets file lives under APP_DIR so the (hardened) web service can write it
  [ -f "${SSTP_SECRETS}" ] || install -o "${SERVICE_USER}" -g "${SERVICE_USER}" \
      -m 640 /dev/null "${SSTP_SECRETS}"
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      accel-ppp openssl
  mkdir -p /etc/accel-ppp /var/log/accel-ppp
  if [ ! -f /etc/accel-ppp/sstp.pem ]; then
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
      -subj "/CN=mikromon-sstp" \
      -keyout /etc/accel-ppp/sstp.key -out /etc/accel-ppp/sstp.crt
    cat /etc/accel-ppp/sstp.crt /etc/accel-ppp/sstp.key > /etc/accel-ppp/sstp.pem
    chmod 600 /etc/accel-ppp/sstp.pem
  fi
  cat > /etc/accel-ppp.conf <<CONF
[modules]
log_file
sstp
chap-secrets
ippool

[core]
thread-count=2

[sstp]
verbose=1
accept=ssl
ssl-pemfile=/etc/accel-ppp/sstp.pem
port=443

[ppp]
verbose=1
mtu=1400
ipv4=require

[ip-pool]
gw-ip-address=10.10.0.1
10.10.0.2-10.10.0.254

[chap-secrets]
chap-secrets=${SSTP_SECRETS}

[log]
log-file=/var/log/accel-ppp/accel-ppp.log
level=3
CONF
  # reload accel-ppp whenever mikromon rewrites the secrets file
  cat > /etc/systemd/system/mikromon-sstp-reload.service <<UNIT
[Unit]
Description=Reload accel-ppp after mikromon updates SSTP secrets
[Service]
Type=oneshot
ExecStart=/bin/systemctl reload-or-restart accel-ppp
UNIT
  cat > /etc/systemd/system/mikromon-sstp-reload.path <<UNIT
[Unit]
Description=Watch the mikromon SSTP secrets file
[Path]
PathModified=${SSTP_SECRETS}
Unit=mikromon-sstp-reload.service
[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable --now accel-ppp
  systemctl enable --now mikromon-sstp-reload.path
  command -v ufw >/dev/null 2>&1 && ufw allow 443/tcp || true
)
SSTP_OK=$?
set -e
if [ "${SSTP_OK}" -eq 0 ]; then
  log "SSTP server up (accel-ppp on :443); secrets: ${SSTP_SECRETS}"
else
  log "WARN: SSTP server step failed/skipped (accel-ppp may be unavailable here)."
  log "      The dashboard still generates router scripts; set up an SSTP server"
  log "      manually and point its chap-secrets at ${SSTP_SECRETS}."
fi

# Resolve the server's primary IP for the final message.
SERVER_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
SERVER_IP="${SERVER_IP:-<your-server-ip>}"

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
cat <<EOF

============================================================
  mikromon installed / upgraded successfully!
============================================================

Dashboard will be available at:
  http://${SERVER_IP}:${WEB_PORT}

Next steps:

  1. Edit the config (SMTP credentials, devices, etc.):
       sudo -u ${SERVICE_USER} nano ${APP_DIR}/config.yaml

  2. Test the router connection:
       sudo -u ${SERVICE_USER} \\
         ${APP_DIR}/.venv/bin/python -m mikromon test-connection \\
         -c ${APP_DIR}/config.yaml

  3. Test email delivery:
       sudo -u ${SERVICE_USER} \\
         ${APP_DIR}/.venv/bin/python -m mikromon test-email \\
         -c ${APP_DIR}/config.yaml

  4. Enable and start both services:
       sudo systemctl enable --now mikromon mikromon-web

  5. Watch the logs:
       journalctl -u mikromon -f
       journalctl -u mikromon-web -f

============================================================
EOF

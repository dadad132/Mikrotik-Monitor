#!/usr/bin/env bash
#
# Install mikromon as a systemd service on Ubuntu 22.04 / 24.04 / 26.04+.
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

# Confirm we are on a systemd system before doing any real work.
if ! command -v systemctl &>/dev/null; then
    die "systemctl not found — systemd is required to register the service."
fi

log "Source : ${SRC_DIR}"
log "Install: ${APP_DIR}"

# ---------------------------------------------------------------------------
# 2. System packages
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
# 3. Dedicated unprivileged system user
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

# Copy the Python package, skipping compiled cache artefacts.
rsync -a --delete \
    --exclude='__pycache__/' \
    --exclude='*.pyc' \
    --exclude='*.pyo' \
    "${SRC_DIR}/mikromon/" "${APP_DIR}/mikromon/"  || {
    # rsync may not be installed on minimal images — fall back to cp + cleanup.
    cp -r "${SRC_DIR}/mikromon" "${APP_DIR}/"
    find "${APP_DIR}/mikromon" -type d -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true
    find "${APP_DIR}/mikromon" -name '*.pyc' -o -name '*.pyo' -delete 2>/dev/null || true
}

cp "${SRC_DIR}/requirements.txt" "${APP_DIR}/"
cp -n "${SRC_DIR}/config.example.yaml" "${APP_DIR}/config.example.yaml" 2>/dev/null || true

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

"${PYTHON_BIN}" -m venv "${APP_DIR}/.venv"
PIP="${APP_DIR}/.venv/bin/pip"

log "Upgrading pip / setuptools / wheel..."
"${PIP}" install --quiet --upgrade pip setuptools wheel

log "Installing requirements.txt..."
"${PIP}" install --quiet --upgrade -r "${APP_DIR}/requirements.txt"

# Show what got installed so the log is auditable.
echo
"${PIP}" list --format=columns
echo

# ---------------------------------------------------------------------------
# 6. File ownership and permissions
# ---------------------------------------------------------------------------
step "Setting file permissions"

chown -R "${SERVICE_USER}:${SERVICE_USER}" "${APP_DIR}"
# config.yaml may contain SMTP credentials — restrict reads to the service user.
chmod 640 "${APP_DIR}/config.yaml"
# The directory must be traversable by root (for journalctl / systemd).
chmod 755 "${APP_DIR}"

# ---------------------------------------------------------------------------
# 7. Web dashboard network binding
# ---------------------------------------------------------------------------
step "Configuring web dashboard (host 0.0.0.0, port 8080)"

WEB_PORT=8080
CONFIG_FILE="${APP_DIR}/config.yaml"

# Patch host and port in-place if the file already exists.
# Uses Python so we don't need yq or any extra tool.
"${PYTHON_BIN}" - "${CONFIG_FILE}" "${WEB_PORT}" <<'PYEOF'
import sys, re

config_path = sys.argv[1]
port        = int(sys.argv[2])

with open(config_path) as fh:
    text = fh.read()

# Replace  host: <anything>  inside the web: block.
text = re.sub(r'(?m)^(\s*host:\s*)127\.0\.0\.1(\s*)$', r'\g<1>0.0.0.0\2', text)
# Replace  port: <anything>  inside the web: block (simple numeric replace).
text = re.sub(r'(?m)^(\s*port:\s*)\d+(\s*)$', lambda m: f"{m.group(1)}{port}{m.group(2)}", text)

with open(config_path, 'w') as fh:
    fh.write(text)

print(f"  web.host set to 0.0.0.0, web.port set to {port}")
PYEOF

# ---------------------------------------------------------------------------
# 8. Firewall — open the dashboard port
# ---------------------------------------------------------------------------
step "Opening firewall port ${WEB_PORT}/tcp"

if command -v ufw &>/dev/null; then
    ufw allow "${WEB_PORT}/tcp" comment "mikromon dashboard" || true
    log "UFW rule added for port ${WEB_PORT}/tcp"
else
    log "ufw not found — skipping firewall rule (open port ${WEB_PORT} manually if needed)"
fi

# ---------------------------------------------------------------------------
# 9. systemd service unit
# ---------------------------------------------------------------------------
step "Registering systemd service"

cp "${SRC_DIR}/deploy/mikromon.service" "${SYSTEMD_UNIT}"
chmod 644 "${SYSTEMD_UNIT}"
systemctl daemon-reload

log "Service unit installed at ${SYSTEMD_UNIT}"

# Resolve the server's primary IP for the final message.
SERVER_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
SERVER_IP="${SERVER_IP:-<your-server-ip>}"

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
cat <<EOF

============================================================
  mikromon installed successfully!
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

  4. Enable and start the service:
       sudo systemctl enable --now mikromon

  5. Watch the logs:
       journalctl -u mikromon -f

============================================================
EOF

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

# Tee all output to a log file from this point on.
LOG_FILE="/tmp/mikromon-install.log"
exec > >(tee "${LOG_FILE}") 2>&1
echo "Install log: ${LOG_FILE}  (also saved to ${APP_DIR}/last-install.log after step 4)"

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
# ZeroTier dial-home hub — lets routers behind NAT/CGNAT connect back to this
# box without port-forwarding. Much simpler than WireGuard: no key management,
# no peers file, NAT traversal is automatic. Requires a free account at
# my.zerotier.com and a network_id in config.yaml (zerotier.network_id).
# ---------------------------------------------------------------------------
step "Setting up ZeroTier dial-home"
ZT_LOG="${APP_DIR}/zt-install-error.log"
set +e
(
  set -e
  # Install zerotier-one via the official apt installer script.
  if ! command -v zerotier-one &>/dev/null; then
    curl -fsSL https://install.zerotier.com | bash
  fi
  systemctl enable --now zerotier-one

  # Read zerotier.network_id from config.yaml if yaml is available.
  ZT_NETWORK=""
  if [[ -f "${APP_DIR}/config.yaml" ]] && [[ -x "${APP_DIR}/.venv/bin/python" ]]; then
    ZT_NETWORK="$("${APP_DIR}/.venv/bin/python" - "${APP_DIR}/config.yaml" <<'PY'
import sys
try:
    import yaml
    with open(sys.argv[1]) as f:
        c = yaml.safe_load(f) or {}
    print((c.get("zerotier") or {}).get("network_id", ""))
except Exception:
    pass
PY
    )" || ZT_NETWORK=""
  fi

  # Open ZeroTier's UDP port so peers can make direct connections to this server.
  if command -v ufw >/dev/null 2>&1; then
    ufw allow 9993/udp comment "ZeroTier" || true
  fi

  if [[ -n "${ZT_NETWORK}" ]]; then
    zerotier-cli join "${ZT_NETWORK}" || true
    log "Joined ZeroTier network ${ZT_NETWORK}"
  fi

  ZT_NODE="$(zerotier-cli info 2>/dev/null | awk '{print $3}' || echo '')"

  # Save ZeroTier info to hub.json so the dashboard fills the router script.
  "${APP_DIR}/.venv/bin/python" - "${APP_DIR}/hub.json" \
      "${ZT_NETWORK:-}" "${ZT_NODE:-}" <<'PY'
import json, sys
path, zt_net, zt_node = sys.argv[1:4]
try:
    with open(path) as f: data = json.load(f)
except Exception:
    data = {}
if zt_net:  data["zt_network_id"] = zt_net
if zt_node: data["zt_node_id"]    = zt_node
with open(path, "w") as f: json.dump(data, f, indent=2)
PY
  chown "${SERVICE_USER}:${SERVICE_USER}" "${APP_DIR}/hub.json"
)
ZT_OK=$?
set -e
if [ "${ZT_OK}" -eq 0 ]; then
  ZT_NODE_ID="$(zerotier-cli info 2>/dev/null | awk '{print $3}' || echo 'unknown')"
  log "ZeroTier installed. Node ID: ${ZT_NODE_ID}"
  log "Go to my.zerotier.com → your network → authorize this node."
  log "Then update hub_ip in ${APP_DIR}/hub.json to this server's ZeroTier IP."
else
  log "WARN: ZeroTier setup failed. Check: cat ${ZT_LOG}"
  log "      Install manually: curl -s https://install.zerotier.com | bash"
  log "      Then: zerotier-cli join <your-network-id>"
  log "      Add network_id under zerotier: in ${APP_DIR}/config.yaml"
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

# ---------------------------------------------------------------------------
# Post-install: copy log, write status summary
# ---------------------------------------------------------------------------
cp "${LOG_FILE}" "${APP_DIR}/last-install.log" 2>/dev/null || true

{
  echo "Date   : $(date)"
  echo "Commit : $(git -C "${SRC_DIR}" log --oneline -1 2>/dev/null || echo unknown)"
  echo "ZeroTier (zerotier-one)   : $(systemctl is-active zerotier-one   2>/dev/null || echo unknown)"
  echo "mikromon                  : $(systemctl is-active mikromon        2>/dev/null || echo unknown)"
  echo "mikromon-web              : $(systemctl is-active mikromon-web    2>/dev/null || echo unknown)"
} | tee "${APP_DIR}/install-status.txt"

echo ""
echo "Full log  : cat ${APP_DIR}/last-install.log"
echo "Status    : cat ${APP_DIR}/install-status.txt"

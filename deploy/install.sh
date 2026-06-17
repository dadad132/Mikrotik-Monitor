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
# WireGuard dial-home hub — lets routers connect BACK to this box. The hub key
# is generated here; mikromon (Provision tab) generates each device's keypair,
# writes the peers into ${WG_PEERS}, and a path-unit applies them with
# `wg syncconf`. The hub public key + IP are written to ${APP_DIR}/hub.json so
# the dashboard fills the router script automatically. Best-effort/guarded.
# ---------------------------------------------------------------------------
step "Setting up the WireGuard dial-home hub"
WG_PEERS="${APP_DIR}/wg-peers.conf"
WG_PORT=51820
WG_SUBNET="10.10.0.0/24"
set +e
(
  set -e
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      wireguard wireguard-tools
  mkdir -p /etc/wireguard
  # peers file lives under APP_DIR so the (hardened) web service can write it
  [ -f "${WG_PEERS}" ] || install -o "${SERVICE_USER}" -g "${SERVICE_USER}" \
      -m 640 /dev/null "${WG_PEERS}"
  if [ ! -f /etc/wireguard/wg0.key ]; then
    umask 077
    wg genkey | tee /etc/wireguard/wg0.key | wg pubkey > /etc/wireguard/wg0.pub
  fi
  HUB_PRIV="$(cat /etc/wireguard/wg0.key)"
  HUB_PUB="$(cat /etc/wireguard/wg0.pub)"
  cat > /etc/wireguard/wg0.conf <<CONF
[Interface]
PrivateKey = ${HUB_PRIV}
Address = 10.10.0.1/24
ListenPort = ${WG_PORT}
# On startup, load any peers that mikromon has already registered.
# wg addconf silently succeeds even if the peers file is empty.
PostUp = wg addconf wg0 ${WG_PEERS}
CONF
  chmod 600 /etc/wireguard/wg0.conf
  # Whenever mikromon rewrites the peers file, sync the live interface.
  # wg syncconf feeds the full merged config so peers removed from the file
  # are also removed from the live interface.
  cat > /etc/systemd/system/mikromon-wg-reload.service <<UNIT
[Unit]
Description=Apply mikromon WireGuard peers to wg0
After=wg-quick@wg0.service
Requires=wg-quick@wg0.service
[Service]
Type=oneshot
ExecStart=/usr/bin/bash -c 'wg syncconf wg0 <(cat /etc/wireguard/wg0.conf ${WG_PEERS})'
UNIT
  cat > /etc/systemd/system/mikromon-wg-reload.path <<UNIT
[Unit]
Description=Watch the mikromon WireGuard peers file
[Path]
PathModified=${WG_PEERS}
Unit=mikromon-wg-reload.service
[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable --now wg-quick@wg0
  systemctl enable --now mikromon-wg-reload.path
  command -v ufw >/dev/null 2>&1 && ufw allow ${WG_PORT}/udp || true
  # publish the hub's public key + IP so the dashboard fills the router script
  HUB_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
  "${APP_DIR}/.venv/bin/python" - "${APP_DIR}/hub.json" "${HUB_PUB}" \
      "${WG_PORT}" "${WG_PEERS}" "${WG_SUBNET}" "${HUB_IP}" <<'PY'
import json, sys
path, pub, port, peers, subnet, ip = sys.argv[1:7]
try:
    with open(path) as f: data = json.load(f)
except Exception:
    data = {}
data.update({"hub_pubkey": pub, "listen_port": port, "wg_peers": peers,
             "subnet": subnet})
data.setdefault("hub_ip", ip)
with open(path, "w") as f: json.dump(data, f, indent=2)
PY
  chown "${SERVICE_USER}:${SERVICE_USER}" "${APP_DIR}/hub.json"
)
WG_OK=$?
set -e
if [ "${WG_OK}" -eq 0 ]; then
  log "WireGuard hub up (wg0 on :${WG_PORT}/udp); peers: ${WG_PEERS}"
  log "Hub public key: $(cat /etc/wireguard/wg0.pub 2>/dev/null)"
else
  log "WARN: WireGuard hub step failed/skipped. The dashboard still generates"
  log "      router scripts; set up WireGuard manually and put the hub public"
  log "      key + IP into ${APP_DIR}/hub.json."
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

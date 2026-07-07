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
    log "Created ${APP_DIR}/config.yaml  — edit smtp: and billing: before starting"
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
# Quarantine a corrupted auth.db, if there is one. Both the dashboard and any
# CLI command open this file at startup — if it's corrupted (e.g. from an
# earlier bug that wrote to it as a different OS user than the running
# service), EVERYTHING that touches it crashes, including the service itself.
# Detect that here, before anything else tries to open it, and move it aside
# so a fresh, empty, valid one gets created automatically. Restore a backup
# afterward (Platform -> Server backup -> Restore) to get real data back.
# ---------------------------------------------------------------------------
AUTH_DB_CHECK="${APP_DIR}/auth.db"
if [[ -f "${AUTH_DB_CHECK}" ]]; then
  step "Checking auth.db integrity"
  if ! "${APP_DIR}/.venv/bin/python" - "${AUTH_DB_CHECK}" <<'PY'
import sqlite3, sys
path = sys.argv[1]
try:
    conn = sqlite3.connect(path)
    ok = conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    conn.close()
except Exception:
    ok = False
sys.exit(0 if ok else 1)
PY
  then
    BAD="${AUTH_DB_CHECK}.corrupted-$(date +%Y%m%d-%H%M%S).bak"
    mv "${AUTH_DB_CHECK}" "${BAD}"
    rm -f "${AUTH_DB_CHECK}-wal" "${AUTH_DB_CHECK}-shm"
    chown "${SERVICE_USER}:${SERVICE_USER}" "$(dirname "${AUTH_DB_CHECK}")" 2>/dev/null || true
    log "auth.db was corrupted — moved to $(basename "${BAD}"), a fresh one will"
    log "be created automatically. Restore a backup afterward to get your"
    log "accounts/companies back (Platform -> Server backup -> Restore)."
  else
    log "auth.db integrity OK"
  fi
fi

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
# SMTP email relay — optional, env-var driven so credentials never live in
# this script or in git. Set SMTP_HOST/SMTP_USER/SMTP_PASS (and optionally
# SMTP_PORT/SMTP_FROM/SMTP_USE_TLS/SMTP_USE_SSL) before running the installer,
# e.g.:
#   SMTP_HOST=mail-eu.smtp2go.com SMTP_PORT=2525 \
#   SMTP_USER=noreply@yourdomain.com SMTP_PASS='...' \
#   sudo -E bash deploy/install.sh
# Safe to re-run — only touches the smtp: block, and only when all three
# required vars are set. Existing smtp: settings are left alone otherwise.
# ---------------------------------------------------------------------------
if [[ -n "${SMTP_HOST:-}" && -n "${SMTP_USER:-}" && -n "${SMTP_PASS:-}" ]]; then
  step "Writing smtp: settings to config.yaml"
  "${APP_DIR}/.venv/bin/python" - "${CONFIG_FILE}" \
      "${SMTP_HOST}" "${SMTP_PORT:-2525}" "${SMTP_USER}" "${SMTP_PASS}" \
      "${SMTP_FROM:-${SMTP_USER}}" \
      "${SMTP_USE_TLS:-true}" "${SMTP_USE_SSL:-false}" <<'PY'
import sys, yaml
path, host, port, user, pw, from_addr, use_tls, use_ssl = sys.argv[1:9]
try:
    with open(path) as f: data = yaml.safe_load(f) or {}
except Exception:
    data = {}
smtp = data.get("smtp") or {}
smtp.update({"host": host, "port": int(port), "username": user, "password": pw,
             "from_addr": from_addr,
             "use_tls": use_tls.lower() == "true",
             "use_ssl": use_ssl.lower() == "true"})
smtp.setdefault("to_addrs", [])
smtp.setdefault("subject_prefix", "[EasyMikrotik]")
smtp.setdefault("min_severity", "WARNING")
data["smtp"] = smtp
with open(path, "w") as f: yaml.safe_dump(data, f, sort_keys=False)
print("smtp config written to", path, "(host:", host, "port:", port, ")")
PY
  log "SMTP relay configured (credentials not stored in this script or git)."
else
  log "SMTP not set via env vars — leaving config.yaml's smtp: block as-is."
  log "To (re)configure it non-interactively next time:"
  log "  SMTP_HOST=... SMTP_USER=... SMTP_PASS=... sudo -E bash deploy/install.sh"
fi

# ---------------------------------------------------------------------------
# TEMPORARY — one-off superadmin grant for this migration. Remove this block
# on the next push; new installs don't need it (signup now grants the first
# superadmin automatically). Best-effort: does nothing if the account doesn't
# exist yet or auth: isn't configured, so it never fails the install.
# ---------------------------------------------------------------------------
if [[ -f "${CONFIG_FILE}" ]]; then
  # Must run as the mikromon user, not root (this whole script runs under
  # sudo) — writing auth.db as root here leaves root-owned bits behind
  # (WAL/SHM sidecar files in particular) that the actual mikromon-web
  # service, running unprivileged, can then fail to read/write correctly.
  # Also must run FROM ${APP_DIR}: `python -m mikromon` finds the package
  # via the current directory (it's never pip-installed), and this script's
  # own cwd is wherever it was invoked from (e.g. a clone under /root),
  # which the unprivileged mikromon user can't traverse into — that
  # produces a confusing "No module named mikromon" rather than a
  # permission error.
  (cd "${APP_DIR}" && sudo -u "${SERVICE_USER}" "${APP_DIR}/.venv/bin/python" -m mikromon \
      set-superadmin --user barnard.juanpierre@gmail.com -c "${CONFIG_FILE}") \
      && log "Granted superadmin to barnard.juanpierre@gmail.com" \
      || log "Skipped superadmin grant (account may not exist yet — sign up first, then re-run)"
fi

# ---------------------------------------------------------------------------
# TEMPORARY — one-off cleanup for this migration. Remove this block on the
# next push; new migrations don't need it (restore now strips hub_ip
# automatically). hub.json restored from the old server's backup has the
# OLD server's IP cached in hub_ip forever (unlike hub_pubkey/listen_port/
# subnet, which install.sh already refreshes every run) — this clears just
# that one field so the Provision page re-detects this server's real
# address. Everything else in hub.json (hub_pubkey, leases, subnet) is left
# untouched. Best-effort: does nothing if hub.json doesn't exist yet or has
# no cached hub_ip, so it never fails the install.
# ---------------------------------------------------------------------------
HUB_JSON="${APP_DIR}/hub.json"
if [[ -f "${HUB_JSON}" ]]; then
  sudo -u "${SERVICE_USER}" "${APP_DIR}/.venv/bin/python" -c "
import json
path = '${HUB_JSON}'
with open(path) as f:
    data = json.load(f)
if data.pop('hub_ip', None) is not None:
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)
    print('Cleared stale hub_ip from hub.json — will re-detect')
else:
    print('hub.json has no cached hub_ip — nothing to clear')
" && log "hub.json hub_ip check complete" \
    || log "WARN: could not check/clear hub_ip in hub.json"
fi

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

# Stop running services before replacing their unit files so the new code
# is fully in place before anything restarts. Tolerate a failed/canceled stop
# (e.g. racing an in-flight Restart=always cycle if the service was already
# crash-looping) — the "Enabling and starting" step below re-checks and
# fixes the end state regardless, so this must not abort the whole install.
for svc in mikromon-web mikromon; do
    if systemctl is-active --quiet "${svc}" 2>/dev/null; then
        systemctl stop "${svc}" || log "WARN: stop ${svc} did not complete cleanly — continuing"
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
WG_PEERS="/etc/wireguard/wg-peers.conf"
WG_PORT=51820
WG_SUBNET="10.10.0.0/16"
WG_LOG="${APP_DIR}/wg-install-error.log"
set +e
(
  set -e
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      wireguard wireguard-tools

  # On many VPS providers (OVHcloud, Hetzner, etc.) the WireGuard kernel module
  # ships in linux-modules-extra rather than the base kernel package.
  KVER="$(uname -r)"
  EXTRA_PKG="linux-modules-extra-${KVER}"
  if apt-cache show "${EXTRA_PKG}" &>/dev/null; then
      DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
          "${EXTRA_PKG}" || true
  fi
  # Load the module now (wireguard may be a loadable module or built-in).
  modprobe wireguard 2>/dev/null || true
  # Use a direct kernel capability test: try to create a probe interface.
  # This works for both loadable modules AND built-in kernels (where modinfo
  # finds no .ko file and returns 1 even though wireguard is available).
  if ! ip link add wg-probe type wireguard 2>/dev/null; then
      echo "WireGuard kernel support not available for kernel ${KVER}."
      echo "Reboot into a stock Ubuntu kernel and re-run the installer."
      exit 1
  fi
  ip link delete wg-probe 2>/dev/null || true

  # IP forwarding must be on for the hub to relay packets between peers.
  echo "net.ipv4.ip_forward=1"  > /etc/sysctl.d/99-wireguard.conf
  echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.d/99-wireguard.conf
  sysctl -p /etc/sysctl.d/99-wireguard.conf >/dev/null

  mkdir -p /etc/wireguard
  # The wireguard package sets /etc/wireguard to 700 root:root.  Grant the
  # service user traverse + read so it can write wg-peers.conf inside.
  chmod 750 /etc/wireguard
  chgrp "${SERVICE_USER}" /etc/wireguard
  [ -f "${WG_PEERS}" ] || install -o "${SERVICE_USER}" -g "${SERVICE_USER}" \
      -m 640 /dev/null "${WG_PEERS}"

  # Stop the wg-quick service first so systemd doesn't immediately respawn
  # the interface while we reconfigure (handles re-runs cleanly).
  systemctl stop wg-quick@wg0 2>/dev/null || true

  # Tear down any leftover wg0 interface.
  if ip link show wg0 &>/dev/null; then
    ip link delete wg0 2>/dev/null || true
  fi

  # Migrating from another server: preserve the OLD hub's identity instead of
  # generating a new one, so already-provisioned routers don't need to be
  # touched at all (they already trust this exact public key). Env-var
  # driven so the private key never sits in this script or in git — set it
  # once for this run only, e.g.:
  #   WG_PRIVATE_KEY='...' sudo -E bash deploy/install.sh
  if [[ -n "${WG_PRIVATE_KEY:-}" && ! -f /etc/wireguard/wg0.key ]]; then
    umask 077
    echo "${WG_PRIVATE_KEY}" > /etc/wireguard/wg0.key
    wg pubkey < /etc/wireguard/wg0.key > /etc/wireguard/wg0.pub
    echo "Seeded wg0.key from WG_PRIVATE_KEY (preserving the old hub's identity)."
  fi

  if [ ! -f /etc/wireguard/wg0.key ]; then
    umask 077
    wg genkey | tee /etc/wireguard/wg0.key | wg pubkey > /etc/wireguard/wg0.pub
  fi
  HUB_PRIV="$(cat /etc/wireguard/wg0.key)"
  HUB_PUB="$(cat /etc/wireguard/wg0.pub)"

  # Plain WireGuard config — no PostUp.  Peers are loaded by
  # mikromon-wg-reload.service AFTER wg-quick starts so we never run
  # under wg-quick's restrictive AppArmor confinement.
  cat > /etc/wireguard/wg0.conf <<CONF
[Interface]
PrivateKey = ${HUB_PRIV}
Address = 10.10.0.1/16
ListenPort = ${WG_PORT}
CONF
  chmod 600 /etc/wireguard/wg0.conf

  # This service runs as a plain systemd unit (not under wg-quick's AppArmor).
  # bash can open /etc/wireguard/* freely; wg sees only an inherited fd.
  # Enabled at boot so initial peers load after wg0 comes up.
  # Also triggered by the path unit whenever mikromon writes new peers.
  #
  # IMPORTANT: `wg syncconf` speaks the low-level wg config format, which does
  # NOT understand wg-quick-only directives (Address/DNS/MTU/Table/Pre*/Post*/
  # SaveConfig). wg0.conf has `Address = 10.10.0.1/16`, so feeding it raw makes
  # `wg syncconf` reject the WHOLE config and load NO peers — the hub then
  # silently drops every router handshake (router dials, server never replies).
  # Strip those wg-quick-only lines first, keeping PrivateKey/ListenPort + peers.
  #
  # After syncing peers, also ensure the /16 kernel route exists.  wg syncconf
  # updates the WireGuard peer table but does NOT add kernel IP routes, so
  # devices allocated outside 10.10.0.0/24 would otherwise be unreachable.
  cat > /etc/systemd/system/mikromon-wg-reload.service <<UNIT
[Unit]
Description=Apply mikromon WireGuard peers to wg0
After=wg-quick@wg0.service
PartOf=wg-quick@wg0.service
[Service]
Type=oneshot
ExecStart=/usr/bin/bash -c 'wg syncconf wg0 <(grep -vE "^[[:space:]]*(Address|DNS|MTU|Table|PreUp|PostUp|PreDown|PostDown|SaveConfig)[[:space:]]*=" /etc/wireguard/wg0.conf; cat ${WG_PEERS} 2>/dev/null || true); ip -4 route replace ${WG_SUBNET} dev wg0 2>/dev/null || true'
[Install]
WantedBy=multi-user.target
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
  # Enable the service at boot, then (re)start it so it always picks up the
  # freshly-written wg0.conf regardless of whether it was already running.
  systemctl enable wg-quick@wg0
  if ! systemctl restart wg-quick@wg0; then
    journalctl -n 60 -u wg-quick@wg0 --no-pager > "${WG_LOG}" 2>&1 || true
    echo ""
    echo "WireGuard failed to start. Full error saved to: ${WG_LOG}"
    echo "Run: cat ${WG_LOG}"
    exit 1
  fi
  # Load any already-registered peers immediately, then enable path watcher.
  # Report the outcome instead of swallowing it — if this step fails, peers are
  # NOT on wg0 and routers can't connect, which is otherwise invisible.
  systemctl enable mikromon-wg-reload.service
  systemctl enable --now mikromon-wg-reload.path
  if systemctl start mikromon-wg-reload.service; then
    PEER_COUNT="$(wg show wg0 peers 2>/dev/null | grep -c . || true)"
    echo "WireGuard peers applied to wg0 (currently ${PEER_COUNT:-0} peer(s))."
  else
    journalctl -n 30 -u mikromon-wg-reload.service --no-pager > "${WG_LOG}" 2>&1 || true
    echo ""
    echo "WARNING: applying WireGuard peers to wg0 FAILED — routers will not be"
    echo "able to connect until this is fixed. Error saved to: ${WG_LOG}"
    echo "Run: cat ${WG_LOG}"
  fi
  if command -v ufw >/dev/null 2>&1; then
    ufw allow ${WG_PORT}/udp          # WireGuard handshake port
    ufw allow in  on wg0              # traffic arriving from tunnel peers
    ufw allow out on wg0              # responses going back through the tunnel
  fi
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
# Guarantee the peers file is accessible regardless of WG install outcome.
# (The wireguard package sets /etc/wireguard to 700; fix it unconditionally.)
mkdir -p /etc/wireguard
chmod 750 /etc/wireguard
chgrp "${SERVICE_USER}" /etc/wireguard
[ -f "${WG_PEERS}" ] || install -o "${SERVICE_USER}" -g "${SERVICE_USER}" \
    -m 640 /dev/null "${WG_PEERS}"
if [ "${WG_OK}" -eq 0 ]; then
  log "WireGuard hub up (wg0 on :${WG_PORT}/udp); peers: ${WG_PEERS}"
  log "Hub public key: $(cat /etc/wireguard/wg0.pub 2>/dev/null)"
else
  log "WARN: WireGuard hub step failed/skipped. The dashboard still generates"
  log "      router scripts; set up WireGuard manually and put the hub public"
  log "      key + IP into ${APP_DIR}/hub.json."
  log ""
  log "      WireGuard error log : cat ${WG_LOG}"
  log "      Full install log    : cat ${APP_DIR}/last-install.log"
fi

# ---------------------------------------------------------------------------
# On-demand WebFig/Winbox remote access (Option A) — an nginx reverse proxy on
# the hub. ACCESS_HOST is auto-detected from the server's public IP if not set
# explicitly. Set ACCESS_HOST=your.domain to use a hostname instead of an IP.
# ---------------------------------------------------------------------------
if [[ -z "${ACCESS_HOST:-}" ]]; then
  # Try public IP first (works on OVHcloud, Hetzner, etc.), fall back to local.
  ACCESS_HOST="$(curl -4 -s --max-time 5 https://api.ipify.org 2>/dev/null \
    || hostname -I 2>/dev/null | awk '{print $1}')"
  ACCESS_HOST="${ACCESS_HOST:-}"
fi
if [[ -n "${ACCESS_HOST}" ]]; then
  step "Setting up remote access (nginx) for ${ACCESS_HOST}"
  ACCESS_LOG="${APP_DIR}/access-install-error.log"
  set +e
  (
    set -e
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        nginx libnginx-mod-stream openssl
    # Remove the default nginx welcome page so it never shows instead of the dashboard.
    rm -f /etc/nginx/sites-enabled/default
    mkdir -p /etc/nginx/streams.d /etc/nginx/conf.d
    # Ensure nginx loads the stream include (WebFig uses http/conf.d, already
    # included by default; Winbox needs a top-level stream{} block).
    if ! grep -q "streams.d/\*.conf" /etc/nginx/nginx.conf; then
      cat >> /etc/nginx/nginx.conf <<'NGX'

# easymikrotik on-demand Winbox proxies (raw TCP)
stream {
    include /etc/nginx/streams.d/*.conf;
}
NGX
    fi
    # Empty include files so `nginx -t` passes before any grant exists.
    : > /etc/nginx/conf.d/easymikrotik-access.conf
    : > /etc/nginx/streams.d/easymikrotik-access.conf

    # TLS for the WebFig leg. Try Let's Encrypt; fall back to a self-signed cert
    # so nginx still starts (replace it with a real cert later).
    CERT="/etc/letsencrypt/live/${ACCESS_HOST}/fullchain.pem"
    KEY="/etc/letsencrypt/live/${ACCESS_HOST}/privkey.pem"
    if [[ ! -f "${CERT}" ]]; then
      if command -v certbot >/dev/null 2>&1 || \
         DEBIAN_FRONTEND=noninteractive apt-get install -y certbot >/dev/null 2>&1; then
        certbot certonly --nginx -d "${ACCESS_HOST}" --non-interactive \
            --agree-tos -m "admin@${ACCESS_HOST}" || true
      fi
    fi
    if [[ ! -f "${CERT}" ]]; then
      CERT="/etc/ssl/easymikrotik-${ACCESS_HOST}.crt"
      KEY="/etc/ssl/easymikrotik-${ACCESS_HOST}.key"
      [[ -f "${CERT}" ]] || openssl req -x509 -newkey rsa:2048 -nodes \
          -keyout "${KEY}" -out "${CERT}" -days 825 \
          -subj "/CN=${ACCESS_HOST}" >/dev/null 2>&1
      echo "NOTE: using a self-signed cert for ${ACCESS_HOST} (browser will warn)."
    fi

    # Write the access: block into config.yaml (PyYAML ships in the venv).
    "${APP_DIR}/.venv/bin/python" - "${CONFIG_FILE}" "${ACCESS_HOST}" \
        "${APP_DIR}/access-grants.json" "${CERT}" "${KEY}" <<'PY'
import sys, yaml
path, host, grants, cert, key = sys.argv[1:6]
try:
    with open(path) as f: data = yaml.safe_load(f) or {}
except Exception:
    data = {}
data["access"] = {
    "hub_host": host, "ttl_minutes": 15, "grants_file": grants,
    "tls_cert": cert, "tls_key": key,
    "nginx_http_conf": "/etc/nginx/conf.d/easymikrotik-access.conf",
    "nginx_stream_conf": "/etc/nginx/streams.d/easymikrotik-access.conf"}
with open(path, "w") as f: yaml.safe_dump(data, f, sort_keys=False)
print("access config written to", path)
PY

    # Grants file (owned by the web service so it can record open/close).
    [ -f "${APP_DIR}/access-grants.json" ] || echo '{"grants":{}}' \
        > "${APP_DIR}/access-grants.json"
    chown "${SERVICE_USER}:${SERVICE_USER}" "${APP_DIR}/access-grants.json"

    # Reload units: .path applies on open/close, .timer expires grants (auto-close).
    cp "${SRC_DIR}/deploy/easymikrotik-access-reload."* /etc/systemd/system/
    systemctl daemon-reload
    systemctl enable --now easymikrotik-access-reload.path
    systemctl enable --now easymikrotik-access-reload.timer

    if command -v ufw >/dev/null 2>&1; then
      ufw allow 20000:24999/tcp comment 'easymikrotik WebFig'
      ufw allow 25000:29999/tcp comment 'easymikrotik Winbox'
    fi
    nginx -t && { systemctl reload nginx || systemctl restart nginx; }
    "${APP_DIR}/.venv/bin/python" -m mikromon access-apply -c "${CONFIG_FILE}"
  ) >"${ACCESS_LOG}" 2>&1
  if [ $? -eq 0 ]; then
    log "Remote access ready on ${ACCESS_HOST} (per-device WebFig/Winbox)."
  else
    log "WARN: remote-access (nginx) setup failed — see ${ACCESS_LOG} and"
    log "      deploy/REMOTE-ACCESS.md. The rest of the install is unaffected."
  fi
  set -e
else
  log "Remote access (WebFig/Winbox) not configured — re-run with"
  log "ACCESS_HOST=your.public.hostname to enable it (see deploy/REMOTE-ACCESS.md)."
fi

# ---------------------------------------------------------------------------
# Domain reverse proxy — point easymikrotik.com (or any domain) at this box.
# Set DOMAIN= as an env var, e.g.:
#   DOMAIN=easymikrotik.com sudo bash deploy/install.sh
# Or add  web.domain: easymikrotik.com  to config.yaml and re-run.
# The installer: installs nginx, gets a Let's Encrypt TLS cert for the domain,
# writes an HTTPS reverse-proxy config (port 443 → localhost:8080), redirects
# HTTP 80 → HTTPS, and sets web.secure_cookies: true in config.yaml.
# Safe to re-run — idempotent.
# ---------------------------------------------------------------------------
DOMAIN="${DOMAIN:-easymikrotik.com}"
if [[ -z "${DOMAIN}" ]] && [[ -f "${APP_DIR}/config.yaml" ]] \
   && [[ -x "${APP_DIR}/.venv/bin/python" ]]; then
  DOMAIN="$("${APP_DIR}/.venv/bin/python" - "${APP_DIR}/config.yaml" <<'PY'
import sys
try:
    import yaml
    with open(sys.argv[1]) as f:
        c = yaml.safe_load(f) or {}
    print((c.get("web") or {}).get("domain", ""))
except Exception:
    pass
PY
  )" || DOMAIN=""
fi

if [[ -n "${DOMAIN}" ]]; then
  step "Setting up HTTPS domain: ${DOMAIN}"
  DOMAIN_LOG="${APP_DIR}/domain-install-error.log"
  set +e
  (
    set -e
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        nginx certbot python3-certbot-nginx

    # UFW: allow HTTP and HTTPS so certbot and the browser can reach the server.
    if command -v ufw &>/dev/null; then
      ufw allow 80/tcp  comment "HTTP (Let's Encrypt + redirect)"  || true
      ufw allow 443/tcp comment "HTTPS (${DOMAIN})"               || true
    fi

    # Minimal HTTP-only server block so certbot's HTTP-01 challenge works.
    NGINX_CONF="/etc/nginx/sites-available/easymikrotik"
    cat > "${NGINX_CONF}" <<NGX
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN} www.${DOMAIN};
    location / { return 301 https://\$host\$request_uri; }
    location /.well-known/acme-challenge/ { root /var/www/html; }
}
NGX
    ln -sf "${NGINX_CONF}" /etc/nginx/sites-enabled/easymikrotik 2>/dev/null || true
    # Remove the default site so it doesn't conflict on port 80.
    rm -f /etc/nginx/sites-enabled/default
    nginx -t && { systemctl reload nginx || systemctl restart nginx; }

    # Obtain/renew the TLS cert.  --nginx plugin handles the verification.
    certbot certonly --nginx \
        -d "${DOMAIN}" -d "www.${DOMAIN}" \
        --non-interactive --agree-tos \
        -m "admin@${DOMAIN}" \
        --deploy-hook "systemctl reload nginx" || true

    CERT="/etc/letsencrypt/live/${DOMAIN}/fullchain.pem"
    KEY="/etc/letsencrypt/live/${DOMAIN}/privkey.pem"
    if [[ ! -f "${CERT}" ]]; then
      echo "Let's Encrypt cert not obtained — using self-signed (browser will warn)."
      CERT="/etc/ssl/easymikrotik-${DOMAIN}.crt"
      KEY="/etc/ssl/easymikrotik-${DOMAIN}.key"
      [[ -f "${CERT}" ]] || openssl req -x509 -newkey rsa:2048 -nodes \
          -keyout "${KEY}" -out "${CERT}" -days 825 \
          -subj "/CN=${DOMAIN}" >/dev/null 2>&1
    fi

    # Full HTTPS reverse-proxy config.
    cat > "${NGINX_CONF}" <<NGX
# HTTP → HTTPS redirect
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN} www.${DOMAIN};
    location /.well-known/acme-challenge/ { root /var/www/html; }
    location / { return 301 https://\$host\$request_uri; }
}

# HTTPS dashboard proxy
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name ${DOMAIN} www.${DOMAIN};

    ssl_certificate     ${CERT};
    ssl_certificate_key ${KEY};
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;
    ssl_session_cache   shared:SSL:10m;

    # Security headers
    add_header X-Frame-Options        SAMEORIGIN;
    add_header X-Content-Type-Options nosniff;
    add_header Referrer-Policy        strict-origin-when-cross-origin;

    # Proxy to the Python dashboard
    location / {
        proxy_pass         http://127.0.0.1:${WEB_PORT};
        proxy_http_version 1.1;
        proxy_set_header   Host              \$host;
        proxy_set_header   X-Real-IP         \$remote_addr;
        proxy_set_header   X-Forwarded-For   \$proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto \$scheme;
        proxy_read_timeout 120s;
        proxy_buffering    off;
    }
}
NGX
    nginx -t && { systemctl reload nginx || systemctl restart nginx; }

    # Save domain to config.yaml.
    # Only enable secure_cookies when we have a real Let's Encrypt cert —
    # a self-signed cert still serves HTTPS but the browser won't trust it
    # for cookie purposes until the user explicitly accepts it, so keeping
    # secure_cookies=false until a real cert is in place avoids a login loop.
    LE_CERT="/etc/letsencrypt/live/${DOMAIN}/fullchain.pem"
    REAL_CERT="false"
    [[ -f "${LE_CERT}" ]] && REAL_CERT="true"
    "${APP_DIR}/.venv/bin/python" - "${APP_DIR}/config.yaml" "${DOMAIN}" "${REAL_CERT}" <<'PY'
import sys
try:
    import yaml
    path, domain, real_cert = sys.argv[1], sys.argv[2], sys.argv[3]
    with open(path) as f:
        data = yaml.safe_load(f) or {}
    web = data.setdefault("web", {})
    web["domain"] = domain
    web["secure_cookies"] = (real_cert == "true")
    with open(path, "w") as f:
        yaml.safe_dump(data, f, sort_keys=False)
    status = "true" if real_cert == "true" else "false (self-signed cert — re-run after DNS propagates)"
    print(f"config.yaml updated: web.domain={domain}, secure_cookies={status}")
except Exception as e:
    print(f"config.yaml update failed: {e}")
PY
    chown "${SERVICE_USER}:${SERVICE_USER}" "${APP_DIR}/config.yaml"
  ) >"${DOMAIN_LOG}" 2>&1
  DOM_OK=$?
  set -e
  if [[ ${DOM_OK} -eq 0 ]]; then
    log "HTTPS domain ready: https://${DOMAIN}"
    log "HTTP redirects to HTTPS automatically."
    log "Cert auto-renews via certbot systemd timer."
  else
    log "WARN: domain setup failed. Check: cat ${DOMAIN_LOG}"
    log "      Make sure ${DOMAIN} DNS A record points to this server first."
  fi
else
  log "Domain proxy not configured. To enable HTTPS on your domain:"
  log "  DOMAIN=easymikrotik.com sudo bash deploy/install.sh"
  log "  (DNS A record must already point to this server)"
fi

# ---------------------------------------------------------------------------
# Auto-correct secure_cookies in config.yaml.
# Rule: true only when a real Let's Encrypt cert exists for the domain.
# This self-heals on every re-run so the user never has to edit the file.
# ---------------------------------------------------------------------------
step "Checking secure_cookies setting"
"${APP_DIR}/.venv/bin/python" - "${APP_DIR}/config.yaml" <<'PY'
import sys, os
try:
    import yaml
    path = sys.argv[1]
    with open(path) as f:
        data = yaml.safe_load(f) or {}
    web    = data.get("web") or {}
    domain = web.get("domain", "")
    current = web.get("secure_cookies", False)
    # A real cert exists when certbot put it here.
    le_cert = f"/etc/letsencrypt/live/{domain}/fullchain.pem" if domain else ""
    should_be = bool(domain and le_cert and os.path.isfile(le_cert))
    if current != should_be:
        web["secure_cookies"] = should_be
        data["web"] = web
        with open(path, "w") as f:
            yaml.safe_dump(data, f, sort_keys=False)
        print(f"  secure_cookies: {current} → {should_be}" +
              ("" if should_be else
               "  (no Let's Encrypt cert yet — login will work over HTTP)"))
    else:
        print(f"  secure_cookies already correct ({current})")
except Exception as e:
    print(f"  WARNING: could not check secure_cookies: {e}")
PY

# ---------------------------------------------------------------------------
# Enable and start both services — always, not just on upgrade.
# mikromon first (monitor daemon), then mikromon-web (dashboard).
# ---------------------------------------------------------------------------
step "Enabling and starting mikromon services"
for svc in mikromon mikromon-web; do
    systemctl enable "${svc}" 2>/dev/null || true
    if systemctl is-active --quiet "${svc}" 2>/dev/null; then
        systemctl restart "${svc}" && log "Restarted ${svc}" \
            || log "WARN: could not restart ${svc} — check: journalctl -u ${svc} -e"
    else
        systemctl start "${svc}" && log "Started ${svc}" \
            || log "WARN: could not start ${svc} — check: journalctl -u ${svc} -e"
    fi
done

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
$(if [[ -n "${DOMAIN}" ]]; then
    echo "  https://${DOMAIN}  (landing: https://${DOMAIN}/landing)"
  else
    echo "  http://${SERVER_IP}:${WEB_PORT}  (landing preview: http://${SERVER_IP}:${WEB_PORT}/landing)"
  fi)

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
  echo "WireGuard (wg-quick@wg0)  : $(systemctl is-active wg-quick@wg0  2>/dev/null || echo unknown)"
  echo "mikromon                  : $(systemctl is-active mikromon        2>/dev/null || echo unknown)"
  echo "mikromon-web              : $(systemctl is-active mikromon-web    2>/dev/null || echo unknown)"
} | tee "${APP_DIR}/install-status.txt"

echo ""
echo "Full log  : cat ${APP_DIR}/last-install.log"
echo "Status    : cat ${APP_DIR}/install-status.txt"

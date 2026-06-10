#!/usr/bin/env bash
#
# Install mikromon as a systemd service on a Linux server.
# Run as root from the project directory:  sudo bash deploy/install.sh
#
set -euo pipefail

APP_DIR=/opt/mikromon
SERVICE_USER=mikromon
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo ">> Installing mikromon to ${APP_DIR}"

# 1) Dedicated unprivileged system user.
if ! id -u "${SERVICE_USER}" >/dev/null 2>&1; then
  useradd --system --home "${APP_DIR}" --shell /usr/sbin/nologin "${SERVICE_USER}"
  echo "   created system user '${SERVICE_USER}'"
fi

# 2) Copy the application (code only; never overwrite an existing config.yaml).
mkdir -p "${APP_DIR}"
cp -r "${SRC_DIR}/mikromon" "${APP_DIR}/"
cp "${SRC_DIR}/requirements.txt" "${APP_DIR}/"
cp -n "${SRC_DIR}/config.example.yaml" "${APP_DIR}/config.example.yaml"
if [[ ! -f "${APP_DIR}/config.yaml" ]]; then
  cp "${SRC_DIR}/config.example.yaml" "${APP_DIR}/config.yaml"
  echo "   created ${APP_DIR}/config.yaml  (EDIT THIS before starting!)"
fi

# 3) Python virtualenv + dependencies.
python3 -m venv "${APP_DIR}/.venv"
"${APP_DIR}/.venv/bin/pip" install --quiet --upgrade pip
"${APP_DIR}/.venv/bin/pip" install --quiet -r "${APP_DIR}/requirements.txt"

# 4) Permissions: config may hold credentials -> lock it down.
chown -R "${SERVICE_USER}:${SERVICE_USER}" "${APP_DIR}"
chmod 640 "${APP_DIR}/config.yaml"

# 5) systemd unit.
cp "${SRC_DIR}/deploy/mikromon.service" /etc/systemd/system/mikromon.service
systemctl daemon-reload

cat <<EOF

Done. Next steps:
  1. Edit the config:        sudo -u ${SERVICE_USER} nano ${APP_DIR}/config.yaml
  2. Test the connection:    sudo -u ${SERVICE_USER} ${APP_DIR}/.venv/bin/python -m mikromon test-connection -c ${APP_DIR}/config.yaml
  3. Test email delivery:    sudo -u ${SERVICE_USER} ${APP_DIR}/.venv/bin/python -m mikromon test-email -c ${APP_DIR}/config.yaml
  4. Enable + start:         sudo systemctl enable --now mikromon
  5. Watch the logs:         journalctl -u mikromon -f
EOF

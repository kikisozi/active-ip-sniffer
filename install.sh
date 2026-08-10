#!/usr/bin/env bash
set -euo pipefail

REPO="kikisozi/active-ip-sniffer"
BRANCH="main"
APP_DIR="/opt/active-ip-sniffer"
SERVICE="active-ip-sniffer"
WEB_PORT="${1:-${WEB_PORT:-8766}}"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Please run as root (for example: sudo bash)." >&2
  exit 1
fi

if ! [[ "${WEB_PORT}" =~ ^[0-9]+$ ]] || (( WEB_PORT < 1 || WEB_PORT > 65535 )); then
  echo "Invalid port: ${WEB_PORT}" >&2
  exit 2
fi

export DEBIAN_FRONTEND=noninteractive
if command -v apt-get >/dev/null 2>&1; then
  apt-get update -y
  apt-get install -y python3 curl ca-certificates
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y python3 curl ca-certificates
elif command -v yum >/dev/null 2>&1; then
  yum install -y python3 curl ca-certificates
else
  echo "Supported package manager not found (apt/dnf/yum)." >&2
  exit 3
fi

install -d -m 0755 "${APP_DIR}"
curl -fsSL "https://raw.githubusercontent.com/${REPO}/${BRANCH}/active_sniffer.py" -o "${APP_DIR}/active_sniffer.py"
chmod 0755 "${APP_DIR}/active_sniffer.py"

cat > "/etc/systemd/system/${SERVICE}.service" <<EOF
[Unit]
Description=Active IP Sniffer WebUI
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 ${APP_DIR}/active_sniffer.py --host 0.0.0.0 --port ${WEB_PORT}
Restart=on-failure
RestartSec=2
User=root
WorkingDirectory=${APP_DIR}

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "${SERVICE}" >/dev/null
systemctl restart "${SERVICE}"

if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi '^Status: active'; then
  ufw allow "${WEB_PORT}/tcp" >/dev/null
elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
  firewall-cmd --permanent --add-port="${WEB_PORT}/tcp" >/dev/null
  firewall-cmd --reload >/dev/null
fi

PUBLIC_IP="$(curl -4fsS --max-time 5 https://api.ipify.org 2>/dev/null || true)"
echo
echo "Installed Active IP Sniffer."
echo "Service: systemctl status ${SERVICE}"
echo "Listen: 0.0.0.0:${WEB_PORT}"
if [[ -n "${PUBLIC_IP}" ]]; then
  echo "Open: http://${PUBLIC_IP}:${WEB_PORT}"
else
  echo "Open: http://<server-ip>:${WEB_PORT}"
fi

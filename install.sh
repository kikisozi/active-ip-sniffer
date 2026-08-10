#!/usr/bin/env bash
set -euo pipefail

REPO="kikisozi/active-ip-sniffer"
BRANCH="main"
APP_DIR="/opt/active-ip-sniffer"
DATA_DIR="/var/lib/active-ip-sniffer/results"
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

case "$(uname -m)" in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) echo "Unsupported CPU architecture: $(uname -m)" >&2; exit 3 ;;
esac

if ! command -v curl >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -y
    apt-get install -y curl ca-certificates
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y curl ca-certificates
  elif command -v yum >/dev/null 2>&1; then
    yum install -y curl ca-certificates
  else
    echo "curl is required and no supported package manager was found." >&2
    exit 4
  fi
fi

install -d -m 0755 "${APP_DIR}"
install -d -m 0750 "${DATA_DIR}"

BINARY_URL="https://raw.githubusercontent.com/${REPO}/${BRANCH}/dist/active-ip-sniffer-linux-${ARCH}"
TMP_BINARY="$(mktemp)"
trap 'rm -f "${TMP_BINARY}"' EXIT
curl -fL --retry 3 --connect-timeout 10 "${BINARY_URL}" -o "${TMP_BINARY}"
install -m 0755 "${TMP_BINARY}" "${APP_DIR}/active-ip-sniffer"

cat > "/etc/systemd/system/${SERVICE}.service" <<EOF
[Unit]
Description=Active IP Sniffer Go WebUI（低内存流式 TCP 探测）
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${APP_DIR}/active-ip-sniffer -host 0.0.0.0 -port ${WEB_PORT} -data-dir ${DATA_DIR}
Restart=on-failure
RestartSec=2
User=root
WorkingDirectory=${APP_DIR}
Environment=GOMEMLIMIT=80MiB
Environment=GOGC=50
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${DATA_DIR}

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "${SERVICE}" >/dev/null
systemctl restart "${SERVICE}"

if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi '^Status: active'; then
  ufw allow "${WEB_PORT}/tcp" comment 'Active IP Sniffer WebUI' >/dev/null
elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
  firewall-cmd --permanent --add-port="${WEB_PORT}/tcp" >/dev/null
  firewall-cmd --reload >/dev/null
fi

PUBLIC_IP="$(curl -4fsS --max-time 5 https://api.ipify.org 2>/dev/null || true)"
echo
echo "Installed Active IP Sniffer Go edition."
echo "Service: systemctl status ${SERVICE}"
echo "Listen: 0.0.0.0:${WEB_PORT}"
echo "Binary: ${APP_DIR}/active-ip-sniffer"
echo "Results: ${DATA_DIR} (files older than 24h are cleaned automatically)"
if [[ -n "${PUBLIC_IP}" ]]; then
  echo "Open: http://${PUBLIC_IP}:${WEB_PORT}"
else
  echo "Open: http://<server-ip>:${WEB_PORT}"
fi

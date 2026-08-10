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

REF="$(curl -fsSL --retry 3 --connect-timeout 10 "https://api.github.com/repos/${REPO}/commits/${BRANCH}?cb=$(date +%s%N)" \
  | sed -n 's/^[[:space:]]*"sha": "\([0-9a-f]\{40\}\)",*$/\1/p' \
  | head -n 1)"
if [[ ! "${REF}" =~ ^[0-9a-f]{40}$ ]]; then
  echo "Cannot resolve the current GitHub commit for ${REPO}:${BRANCH}." >&2
  exit 5
fi

BINARY_URL="https://raw.githubusercontent.com/${REPO}/${REF}/dist/active-ip-sniffer-linux-${ARCH}"
SUMS_URL="https://raw.githubusercontent.com/${REPO}/${REF}/dist/SHA256SUMS"
TMP_BINARY="$(mktemp)"
TMP_SUMS="$(mktemp)"
trap 'rm -f "${TMP_BINARY}" "${TMP_SUMS}"' EXIT
CACHE_BUST="$(date +%s%N)"
curl -fL --retry 3 --connect-timeout 10 "${BINARY_URL}?cb=${CACHE_BUST}" -o "${TMP_BINARY}"
curl -fsSL --retry 3 --connect-timeout 10 "${SUMS_URL}?cb=${CACHE_BUST}" -o "${TMP_SUMS}"
EXPECTED_SHA="$(awk -v file="dist/active-ip-sniffer-linux-${ARCH}" '$2 == file {print $1}' "${TMP_SUMS}")"
if [[ -z "${EXPECTED_SHA}" ]]; then
  echo "Cannot find checksum for linux-${ARCH}." >&2
  exit 6
fi
ACTUAL_SHA="$(sha256sum "${TMP_BINARY}" | awk '{print $1}')"
if [[ "${ACTUAL_SHA}" != "${EXPECTED_SHA}" ]]; then
  echo "Binary checksum mismatch; refusing installation." >&2
  echo "Expected: ${EXPECTED_SHA}" >&2
  echo "Actual:   ${ACTUAL_SHA}" >&2
  exit 7
fi
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

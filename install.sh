#!/usr/bin/env bash
set -euo pipefail

REPO="kikisozi/active-ip-sniffer"
BRANCH="main"
APP_DIR="/opt/active-ip-sniffer"
APP_BIN="${APP_DIR}/active-ip-sniffer"
V_CMD="/usr/local/bin/v"

if [[ "${EUID}" -ne 0 ]]; then
  echo "请使用 root 运行，例如：curl ... | sudo bash" >&2
  exit 1
fi

case "$(uname -m)" in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) echo "不支持的 CPU 架构: $(uname -m)" >&2; exit 2 ;;
esac

ensure_curl() {
  command -v curl >/dev/null 2>&1 && return 0
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -y && apt-get install -y curl ca-certificates
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y curl ca-certificates
  elif command -v yum >/dev/null 2>&1; then
    yum install -y curl ca-certificates
  else
    echo "需要 curl，但没有找到可支持的包管理器。" >&2
    exit 3
  fi
}

ensure_curl
install -d -m 0755 "${APP_DIR}"

REF="$(curl -fsSL --retry 3 --connect-timeout 10 "https://api.github.com/repos/${REPO}/commits/${BRANCH}?cb=$(date +%s%N)" \
  | sed -n 's/^[[:space:]]*"sha": "\([0-9a-f]\{40\}\)",*$/\1/p' | head -n 1)"
if [[ ! "${REF}" =~ ^[0-9a-f]{40}$ ]]; then
  echo "无法解析 ${REPO}:${BRANCH} 当前 commit。" >&2
  exit 4
fi

BINARY="dist/active-ip-sniffer-linux-${ARCH}"
BINARY_URL="https://raw.githubusercontent.com/${REPO}/${REF}/${BINARY}"
SUMS_URL="https://raw.githubusercontent.com/${REPO}/${REF}/dist/SHA256SUMS"
TMP_BINARY="$(mktemp)"
TMP_SUMS="$(mktemp)"
trap 'rm -f "${TMP_BINARY}" "${TMP_SUMS}"' EXIT
CACHE_BUST="$(date +%s%N)"

echo "下载 Go 单二进制 (${ARCH})..."
curl -fL --retry 3 --connect-timeout 10 "${BINARY_URL}?cb=${CACHE_BUST}" -o "${TMP_BINARY}"
curl -fsSL --retry 3 --connect-timeout 10 "${SUMS_URL}?cb=${CACHE_BUST}" -o "${TMP_SUMS}"
EXPECTED_SHA="$(awk -v file="${BINARY}" '$2 == file {print $1}' "${TMP_SUMS}")"
ACTUAL_SHA="$(sha256sum "${TMP_BINARY}" | awk '{print $1}')"
if [[ -z "${EXPECTED_SHA}" || "${ACTUAL_SHA}" != "${EXPECTED_SHA}" ]]; then
  echo "二进制 SHA256 校验失败，拒绝安装。" >&2
  echo "Expected: ${EXPECTED_SHA:-<missing>}" >&2
  echo "Actual:   ${ACTUAL_SHA}" >&2
  exit 5
fi

install -m 0755 "${TMP_BINARY}" "${APP_BIN}"

cat > "${V_CMD}" <<'EOF'
#!/usr/bin/env sh
set -e
APP="/opt/active-ip-sniffer/active-ip-sniffer"
if [ "$(id -u)" -ne 0 ]; then
  if command -v sudo >/dev/null 2>&1; then
    exec sudo "$APP" setup "$@"
  fi
  echo "配置常驻服务需要 root，请执行 sudo v。" >&2
  exit 1
fi
exec "$APP" setup "$@"
EOF
chmod 0755 "${V_CMD}"

echo
echo "Active IP Sniffer 已部署。以后直接输入 v 即可重新进入配置界面。"
echo "Binary: ${APP_BIN}"
echo "Command: ${V_CMD}"
echo

# curl | sudo bash 时 stdin 属于管道，交互必须显式连接当前终端。
if [[ -r /dev/tty && -w /dev/tty ]]; then
  exec "${APP_BIN}" setup </dev/tty >/dev/tty 2>/dev/tty
fi

echo "当前环境没有交互终端。安装已完成，请稍后运行 v 进行配置。"

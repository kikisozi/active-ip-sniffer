#!/bin/sh
set -eu

REPO="kikisozi/active-ip-sniffer"
BRANCH="main"
APP_DIR="/opt/active-ip-sniffer"
APP_BIN="${APP_DIR}/active-ip-sniffer"
WARP_HELPER="${APP_DIR}/warp-helper.sh"
V_CMD="/usr/local/bin/v"

if [ "$(id -u)" -ne 0 ]; then
  echo "请使用 root 运行，例如：curl ... | sudo sh" >&2
  exit 1
fi

case "$(uname -m)" in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) echo "不支持的 CPU 架构: $(uname -m)" >&2; exit 2 ;;
esac

ensure_curl() {
  if command -v curl >/dev/null 2>&1; then
    return 0
  fi
  if command -v apk >/dev/null 2>&1; then
    apk add --no-cache curl ca-certificates
  elif command -v apt-get >/dev/null 2>&1; then
    apt-get update -y && apt-get install -y curl ca-certificates
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y curl ca-certificates
  elif command -v yum >/dev/null 2>&1; then
    yum install -y curl ca-certificates
  elif command -v zypper >/dev/null 2>&1; then
    zypper --non-interactive install curl ca-certificates
  elif command -v pacman >/dev/null 2>&1; then
    pacman -Sy --noconfirm curl ca-certificates
  else
    echo "需要 curl，但没有找到受支持的包管理器。" >&2
    exit 3
  fi
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  elif command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 "$1" | awk '{print $NF}'
  else
    echo "缺少 SHA256 校验工具。" >&2
    exit 4
  fi
}

ensure_curl
mkdir -p "${APP_DIR}"
chmod 0755 "${APP_DIR}"

CACHE_BUST="$(date +%s)-$$"
REF="$(curl -fsSL --retry 3 --connect-timeout 10 "https://api.github.com/repos/${REPO}/commits/${BRANCH}?cb=${CACHE_BUST}" \
  | sed -n 's/^[[:space:]]*"sha": "\([0-9a-f]\{40\}\)",*$/\1/p' | head -n 1)"
case "${REF}" in
  ???????*) ;;
  *) echo "无法解析 ${REPO}:${BRANCH} 当前 commit。" >&2; exit 5 ;;
esac
if [ "${#REF}" -ne 40 ]; then
  echo "无法解析 ${REPO}:${BRANCH} 当前 commit。" >&2
  exit 5
fi

BINARY="dist/active-ip-sniffer-linux-${ARCH}"
BINARY_URL="https://raw.githubusercontent.com/${REPO}/${REF}/${BINARY}"
WARP_HELPER_PATH="warp-helper.sh"
WARP_HELPER_URL="https://raw.githubusercontent.com/${REPO}/${REF}/${WARP_HELPER_PATH}"
SUMS_URL="https://raw.githubusercontent.com/${REPO}/${REF}/dist/SHA256SUMS"
TMP_BINARY="$(mktemp)"
TMP_WARP_HELPER="$(mktemp)"
TMP_SUMS="$(mktemp)"
NEW_BINARY="${APP_BIN}.new.$$"
trap 'rm -f "${TMP_BINARY}" "${TMP_WARP_HELPER}" "${TMP_SUMS}" "${NEW_BINARY}"' EXIT INT TERM

echo "下载 Go 单二进制 (${ARCH})..."
curl -fL --retry 3 --connect-timeout 10 "${BINARY_URL}?cb=${CACHE_BUST}" -o "${TMP_BINARY}"
curl -fsSL --retry 3 --connect-timeout 10 "${WARP_HELPER_URL}?cb=${CACHE_BUST}" -o "${TMP_WARP_HELPER}"
curl -fsSL --retry 3 --connect-timeout 10 "${SUMS_URL}?cb=${CACHE_BUST}" -o "${TMP_SUMS}"
EXPECTED_SHA="$(awk -v file="${BINARY}" '$2 == file {print $1}' "${TMP_SUMS}")"
ACTUAL_SHA="$(sha256_file "${TMP_BINARY}")"
if [ -z "${EXPECTED_SHA}" ] || [ "${ACTUAL_SHA}" != "${EXPECTED_SHA}" ]; then
  echo "二进制 SHA256 校验失败，拒绝安装。" >&2
  echo "Expected: ${EXPECTED_SHA:-<missing>}" >&2
  echo "Actual:   ${ACTUAL_SHA}" >&2
	exit 6
fi
EXPECTED_WARP_SHA="$(awk -v file="${WARP_HELPER_PATH}" '$2 == file {print $1}' "${TMP_SUMS}")"
ACTUAL_WARP_SHA="$(sha256_file "${TMP_WARP_HELPER}")"
if [ -z "${EXPECTED_WARP_SHA}" ] || [ "${ACTUAL_WARP_SHA}" != "${EXPECTED_WARP_SHA}" ]; then
  echo "WARP helper SHA256 校验失败，拒绝安装。" >&2
  exit 7
fi

# Do not copy directly over a running executable: some Linux filesystems return
# ETXTBSY. Stage the new file beside the target and atomically rename it.
cp "${TMP_BINARY}" "${NEW_BINARY}"
chmod 0755 "${NEW_BINARY}"
mv -f "${NEW_BINARY}" "${APP_BIN}"
cp "${TMP_WARP_HELPER}" "${WARP_HELPER}"
chmod 0755 "${WARP_HELPER}"

cat > "${V_CMD}" <<'EOF'
#!/bin/sh
set -eu
APP="/opt/active-ip-sniffer/active-ip-sniffer"
WARP_HELPER="/opt/active-ip-sniffer/warp-helper.sh"

if [ "${1:-}" = "probe" ]; then
  exec "$APP" "$@"
fi
if [ "${1:-}" = "warp" ]; then
  shift
  exec "$WARP_HELPER" "${1:-status}"
fi

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
echo "本地探针：v probe"
echo "WARP Local Proxy：v warp on（端口 40099）；v warp status；v warp off"
echo "Binary: ${APP_BIN}"
echo "Command: ${V_CMD}"
echo

if [ "${AIS_INSTALL_WARP:-0}" = "1" ]; then
  echo "按 AIS_INSTALL_WARP=1 启用 WARP Local Proxy 40099..."
  "${WARP_HELPER}" on || echo "WARP 启用失败；应用 Auto 模式会自动回落 Direct。" >&2
fi

# curl | sudo sh 时 stdin 属于管道；仅在真实交互终端中自动进入向导。
if [ -t 1 ] && [ -r /dev/tty ] && [ -w /dev/tty ]; then
  exec "${APP_BIN}" setup </dev/tty >/dev/tty 2>/dev/tty
fi

echo "当前环境没有交互终端。安装已完成，请稍后运行 v 进行配置，或运行 v probe 启动本地探针。"

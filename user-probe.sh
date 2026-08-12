#!/bin/sh
set -eu

WEB_URL="__AIS_USER_WEB_URL__"
REPO="kikisozi/active-ip-sniffer"
BRANCH="main"

command -v curl >/dev/null 2>&1 || {
  echo "需要 curl。Android/Termux 请先执行: pkg install curl -y" >&2
  exit 2
}

case "$(uname -s)" in
  Darwin) OS="darwin" ;;
  Linux)
    if command -v getprop >/dev/null 2>&1 && [ -n "$(getprop ro.build.version.sdk 2>/dev/null || true)" ]; then
      OS="android"
    else
      OS="linux"
    fi
    ;;
  *) echo "当前脚本仅支持 Linux/macOS/Android Termux。" >&2; exit 2 ;;
esac

case "$(uname -m)" in
  x86_64|amd64) ARCH="amd64" ;;
  arm64|aarch64) ARCH="arm64" ;;
  *) echo "不支持的 CPU 架构: $(uname -m)" >&2; exit 2 ;;
esac

if [ "$OS" = "android" ] && [ "$ARCH" != "arm64" ]; then
  echo "Android 用户探针当前仅提供 arm64。" >&2
  exit 2
fi

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}'
  else echo "缺少 SHA256 校验工具。" >&2; exit 3
  fi
}

FILE="dist/active-ip-user-probe-${OS}-${ARCH}"
if [ "$OS" = "darwin" ]; then
  BASE_DIR="${HOME}/Library/Caches/ActiveIPUserProbe"
else
  BASE_DIR="${XDG_CACHE_HOME:-${HOME}/.cache}/active-ip-user-probe"
fi
mkdir -p "$BASE_DIR"
SUMS="${BASE_DIR}/SHA256SUMS.$$"
TMP=""
trap 'rm -f "${TMP:-}" "$SUMS"' EXIT INT TERM

attempt=1
while [ "$attempt" -le 3 ]; do
  CACHE_BUST="$(date +%s)-$$-${attempt}"
  curl -fsSL --retry 3 --connect-timeout 10 "https://raw.githubusercontent.com/${REPO}/${BRANCH}/dist/SHA256SUMS?cb=${CACHE_BUST}" -o "$SUMS"
  EXPECTED="$(awk -v file="$FILE" '$2 == file {print $1}' "$SUMS")"
  case "$EXPECTED" in
    ''|*[!0-9a-fA-F]*)
      if [ "$attempt" -lt 3 ]; then attempt=$((attempt+1)); sleep 2; continue; fi
      echo "无法获取用户探针 SHA256。" >&2
      exit 4
      ;;
  esac
  [ "${#EXPECTED}" -eq 64 ] || { echo "无效的用户探针 SHA256。" >&2; exit 4; }
  BIN="${BASE_DIR}/active-ip-user-probe-${EXPECTED}"
  if [ -f "$BIN" ] && [ "$(sha256_file "$BIN")" = "$EXPECTED" ]; then
    break
  fi
  TMP="${BIN}.new.$$"
  echo "下载轻量用户探针 ${OS}/${ARCH}..."
  curl -fL --retry 3 --connect-timeout 10 "https://raw.githubusercontent.com/${REPO}/${BRANCH}/${FILE}?cb=${CACHE_BUST}" -o "$TMP"
  ACTUAL="$(sha256_file "$TMP")"
  if [ "$EXPECTED" = "$ACTUAL" ]; then
    chmod 0755 "$TMP"
    mv -f "$TMP" "$BIN"
    TMP=""
    break
  fi
  rm -f "$TMP"
  TMP=""
  if [ "$attempt" -ge 3 ]; then echo "用户探针 SHA256 校验失败。" >&2; exit 5; fi
  attempt=$((attempt+1))
  sleep 2
done

echo "用户探针已就绪。即将自动打开测速网页。"
exec "$BIN" --web-url "$WEB_URL"

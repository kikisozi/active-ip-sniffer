#!/bin/sh
set -eu

PORT=40099
PROXY="127.0.0.1:${PORT}"
TRACE_URL="https://www.cloudflare.com/cdn-cgi/trace"
MDM_FILE="/var/lib/cloudflare-warp/mdm.xml"
MARKER="ActiveIPSniffer managed Local Proxy"
ACTION="${1:-status}"

say() { printf '%s\n' "$*"; }
fail() { say "ERROR: $*" >&2; exit 1; }

need_root() {
  if [ "$(id -u)" -eq 0 ]; then return 0; fi
  if command -v sudo >/dev/null 2>&1; then exec sudo "$0" "$ACTION"; fi
  fail "此操作需要 root；请使用 sudo v warp ${ACTION}"
}

install_warp() {
  command -v warp-cli >/dev/null 2>&1 && return 0
  need_root
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -y
    apt-get install -y ca-certificates curl gnupg lsb-release
    curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg | gpg --yes --dearmor --output /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg
    codename="$(. /etc/os-release 2>/dev/null; printf '%s' "${VERSION_CODENAME:-}")"
    [ -n "$codename" ] || codename="$(lsb_release -cs 2>/dev/null || true)"
    [ -n "$codename" ] || fail "无法识别 Debian/Ubuntu 发行版代号"
    printf 'deb [signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ %s main\n' "$codename" > /etc/apt/sources.list.d/cloudflare-client.list
    apt-get update -y
    apt-get install -y cloudflare-warp
  elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
    pm=dnf; command -v dnf >/dev/null 2>&1 || pm=yum
    curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg -o /tmp/cloudflare-warp-pubkey.gpg
    rpm --import /tmp/cloudflare-warp-pubkey.gpg || true
    rm -f /tmp/cloudflare-warp-pubkey.gpg
    curl -fsSL https://pkg.cloudflareclient.com/cloudflare-warp-ascii.repo -o /etc/yum.repos.d/cloudflare-warp.repo
    if [ "$pm" = dnf ]; then dnf install -y epel-release >/dev/null 2>&1 || true; fi
    "$pm" install -y cloudflare-warp
  else
    fail "Cloudflare 官方 Linux 客户端当前需要受支持的 APT/YUM/DNF 发行版；此系统请保持 Auto/Direct"
  fi
  command -v warp-cli >/dev/null 2>&1 || fail "cloudflare-warp 安装完成但未找到 warp-cli"
}

start_service() {
  if command -v systemctl >/dev/null 2>&1; then
    systemctl enable --now warp-svc >/dev/null 2>&1 || systemctl restart warp-svc >/dev/null 2>&1 || true
  fi
}

register_warp() {
  warp-cli registration show >/dev/null 2>&1 && return 0
  warp-cli --accept-tos registration new >/dev/null 2>&1 || warp-cli registration new >/dev/null 2>&1 || fail "WARP 注册失败"
}

write_mdm_fallback() {
  need_root
  if [ -e "$MDM_FILE" ] && ! grep -q "$MARKER" "$MDM_FILE" 2>/dev/null; then
    fail "检测到已有 $MDM_FILE，拒绝覆盖现有 Cloudflare 管理策略；请手动把 service_mode=proxy、proxy_port=${PORT} 写入现有策略"
  fi
  mkdir -p /var/lib/cloudflare-warp
  cat > "$MDM_FILE" <<EOF
<!-- $MARKER -->
<dict>
  <key>service_mode</key>
  <string>proxy</string>
  <key>proxy_port</key>
  <integer>${PORT}</integer>
</dict>
EOF
  chmod 600 "$MDM_FILE"
  warp-cli mdm refresh >/dev/null 2>&1 || { command -v systemctl >/dev/null 2>&1 && systemctl restart warp-svc >/dev/null 2>&1 || true; }
}

configure_proxy() {
  warp-cli tunnel protocol set MASQUE >/dev/null 2>&1 || true
  if warp-cli mode proxy >/dev/null 2>&1; then
    if warp-cli proxy port "$PORT" >/dev/null 2>&1 || warp-cli proxy port set "$PORT" >/dev/null 2>&1; then
      return 0
    fi
  fi
  write_mdm_fallback
}

trace_proxy() {
  curl -fsS --max-time 8 --socks5-hostname "$PROXY" "$TRACE_URL" 2>/dev/null || return 1
}

proxy_ok() {
  trace_proxy | grep -Eq '^warp=(on|plus)$'
}

show_status() {
  if command -v warp-cli >/dev/null 2>&1; then
    warp-cli status 2>/dev/null || true
    warp-cli settings 2>/dev/null | grep -Ei 'mode|proxy|protocol' || true
  else
    say "WARP client: not installed"
  fi
  if proxy_ok; then
    say "WARP Local Proxy: READY ${PROXY}"
    trace_proxy | grep -E '^(ip|warp|colo)=' || true
    return 0
  fi
  say "WARP Local Proxy: unavailable ${PROXY}; Active IP Sniffer Auto will use Direct"
  return 1
}

case "$ACTION" in
  on|install)
    need_root
    install_warp
    start_service
    register_warp
    configure_proxy
    warp-cli connect >/dev/null 2>&1 || fail "warp-cli connect 失败"
    i=0
    while [ "$i" -lt 15 ]; do
      if proxy_ok; then
        say "WARP Local Proxy 已启用：${PROXY}"
        trace_proxy | grep -E '^(ip|warp|colo)=' || true
        exit 0
      fi
      i=$((i + 1)); sleep 1
    done
    fail "${PROXY} 未通过 warp=on/plus 验证；Active IP Sniffer Auto 会回落 Direct"
    ;;
  off|disconnect)
    need_root
    command -v warp-cli >/dev/null 2>&1 || exit 0
    warp-cli disconnect >/dev/null 2>&1 || true
    say "WARP 已断开；Active IP Sniffer Auto 将使用 Direct"
    ;;
  status)
    show_status
    ;;
  *)
    say "Usage: v warp on|off|status"
    exit 2
    ;;
esac

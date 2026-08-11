# Active IP Sniffer

一个面向低内存 VPS 的主动 TCP 可达性探测 WebUI。v2 已从 Python 重构为 Go，扫描目标采用紧凑 IPv4 数值区间表示并流式送入固定 worker pool，不再将几十万条 IP 字符串一次性展开到内存。

> 仅扫描你拥有或明确获准测试的地址范围。

## v2 主要变化

- Go 单二进制运行；目标机不需要 Python、Go 或第三方运行库。
- 单 IP、CIDR、起止 IP 范围可以任意混合，重叠范围会先合并去重。
- IPv4 数量没有固定 65,536 上限；仍保留 **2,000,000 次连接尝试**的总任务保护限制。
- 固定大小 channel + worker pool，目标数量增加不会线性扩大任务队列内存。
- WebUI 只保留最近 500 个命中 IP；全量命中结果实时追加到磁盘。
- CSV 全量导出字段为 `ip,port`；“复制全部 IP”从落盘 TXT 读取完整去重 IP 列表。
- 结果文件超过 24 小时会自动清理，避免小磁盘 VPS 长期堆积。
- 默认 worker 从 256 降到 64，更适合 128 MB RAM 的 VPS。

## v2.1：VLESS Endpoint Bench

WebUI 现在附带一个独立的 **VLESS TLS+WS 候选 IP 实测**模块，用于对 TCP 扫描得到的少量候选 IP 做二次验证和测速。

TCP 扫描结果区提供“填入 VLESS 测试”按钮，会读取本次任务的完整命中 IP 列表并直接送入候选框，不需要手工复制页面里最近 500 条结果。

测试链路不是只看 443 端口或 TLS 是否能握手，而是按顺序执行：

1. 对候选 IP 的 VLESS 端口做 3 次 TCP 连接，记录启动中位数。
2. 使用 VLESS 链接原本的 `SNI`、`Host`、`Path` 对候选 IP 完成 TLS + WebSocket `101 Switching Protocols`。
3. 发送真实 VLESS TCP 请求，并通过该 VLESS 连接与 `speed.cloudflare.com:443` 完成第二层 TLS 握手。
4. 通过该 VLESS 连接下载 Cloudflare speed 测试数据，记录前 1 秒、前 3 秒、稳定阶段和短窗口峰值 Mbps。

候选 IP **只替换 VLESS URI 的连接地址**；UUID、端口、SNI、Host、Path 都保持原值。因此一个 IP 只有在完整 VLESS 出站也成功后才会标记为“通过”，可以排除“443 可达但节点实际不能用”的误判。

测速默认每个成功 IP 下载 30 MB，且候选 IP 串行测试，避免多个测速任务同时抢占 VPS 带宽而影响排名。最多一次提交 128 个候选 IP；每个候选下载量可设置为 1-100 MB。

VLESS URI 仅用于当前内存任务：不会写入扫描结果文件、不会出现在测速 CSV、程序也不会主动把 URI 写入日志。测速 CSV 只包含候选 IP、各阶段延迟、吞吐量和失败阶段。

## 资源建议

对于 **128 MB RAM**：

- 推荐 worker：`32-64`
- 推荐速率：`200-1000` 次连接尝试/秒
- 推荐单次端口数：`1-4`
- 程序采用流式目标生成，扫描几万 IP 不需要预先保存几万条字符串。
- systemd 安装配置默认设置 `GOMEMLIMIT=80MiB` 和 `GOGC=50`，为系统本身保留内存余量。

512 MB **可用**磁盘空间足够运行本项目。程序二进制约数 MB；实际磁盘消耗主要取决于命中结果文件数量。

## 一键安装

默认 WebUI 端口 `8766`：

```bash
curl -fsSL "https://github.com/kikisozi/active-ip-sniffer/raw/refs/heads/main/install.sh?cb=$(date +%s)" | sudo bash
```

指定端口，例如 `18080`：

```bash
curl -fsSL "https://github.com/kikisozi/active-ip-sniffer/raw/refs/heads/main/install.sh?cb=$(date +%s)" | sudo bash -s -- 18080
```

安装脚本根据 CPU 自动下载：

- `dist/active-ip-sniffer-linux-amd64`
- `dist/active-ip-sniffer-linux-arm64`

因此低配 VPS **不会现场安装 Go 或进行编译**。

安装脚本会先通过 GitHub API 解析 `main` 当前精确 commit SHA，再从同一个 commit 下载二进制和 `SHA256SUMS` 并强制校验，从而避免分支 raw CDN 短时缓存造成版本混用。

安装位置：

```text
/opt/active-ip-sniffer/active-ip-sniffer
/var/lib/active-ip-sniffer/results/
```

常用命令：

```bash
systemctl status active-ip-sniffer
systemctl restart active-ip-sniffer
journalctl -u active-ip-sniffer -f
```

## 扫描限制

- 最多 32 个 TCP 端口。
- 单次最多 2,000,000 次 TCP 连接尝试。
- 最大 512 worker；低内存主机不建议使用这么高的值。
- 最大 5,000 次连接尝试/秒。
- 单次连接超时限制在 0.05-5 秒。

例如：

- 1 个端口最多约 2,000,000 个 IP。
- 2 个端口最多约 1,000,000 个 IP。
- 4 个端口最多约 500,000 个 IP。

## 本地构建

需要 Go 1.19+：

```bash
go test ./...
go build -trimpath -ldflags="-s -w" -o active-ip-sniffer .
./active-ip-sniffer -host 127.0.0.1 -port 8766
```

## CSV 导出

全量结果实时写入磁盘，每个开放端口一行：

```csv
ip,port
103.117.100.8,80
103.117.100.8,443
103.117.101.20,443
```

WebUI 的表格只显示最近 500 个命中 IP，这是为了让大量结果时浏览器和服务器内存保持稳定；CSV 和“复制全部 IP”仍使用完整结果。

VLESS Endpoint Bench 的 CSV 字段包括：

```text
ip,tcp_passed,tcp_attempts,tcp_median_ms,transport_ok,transport_ms,vless_ok,startup_ms,first_1s_mbps,first_3s_mbps,stable_mbps,peak_mbps,downloaded_bytes,download_seconds,status,failure_stage,error
```

## GitHub 自动构建

`.github/workflows/build.yml` 会在 `main` 上源码变化时构建 Linux amd64/arm64 二进制，并将生成文件提交到 `dist/`。自动生成二进制的提交包含 `[skip ci]`，不会形成循环构建。

## 卸载

```bash
sudo systemctl disable --now active-ip-sniffer
sudo rm -f /etc/systemd/system/active-ip-sniffer.service
sudo systemctl daemon-reload
sudo rm -rf /opt/active-ip-sniffer /var/lib/active-ip-sniffer
```

如果安装脚本曾自动放行防火墙端口，请按实际端口删除对应 UFW/firewalld 规则。

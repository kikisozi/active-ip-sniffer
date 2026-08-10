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
curl -fsSL https://raw.githubusercontent.com/kikisozi/active-ip-sniffer/main/install.sh | sudo bash
```

指定端口，例如 `18080`：

```bash
curl -fsSL https://raw.githubusercontent.com/kikisozi/active-ip-sniffer/main/install.sh | sudo bash -s -- 18080
```

安装脚本根据 CPU 自动下载：

- `dist/active-ip-sniffer-linux-amd64`
- `dist/active-ip-sniffer-linux-arm64`

因此低配 VPS **不会现场安装 Go 或进行编译**。

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

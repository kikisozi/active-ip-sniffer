# Active IP Sniffer

从 VLESS Endpoint Bench 中独立出来的主动 TCP 可达性探测 WebUI。它只做 TCP `connect()` 探测，不发送漏洞利用载荷，也不依赖 Mihomo、Xray 或 FOFA。

> 仅扫描你拥有或明确获准测试的地址范围。

## 功能

- WebUI 直接使用 `IP:端口` 访问，默认监听 `0.0.0.0:8766`。
- 安装时可自定义 WebUI 端口。
- 扫描目标支持任意混合：单个 IPv4、CIDR、起止 IP 范围。
- 一次可指定 1-32 个 TCP 端口。
- 可配置连接超时、扫描并发、每秒连接尝试速率。
- 实时显示扫描进度、发现 IP 和对应开放端口。
- 一键导出 CSV，字段为 `ip,port`。
- 无第三方 Python 依赖，Python 3.10+ 即可运行。

## 一键安装

默认使用 `8766` 作为 WebUI 端口：

```bash
curl -fsSL https://raw.githubusercontent.com/kikisozi/active-ip-sniffer/main/install.sh | sudo bash
```

指定 WebUI 端口，例如 `18080`：

```bash
curl -fsSL https://raw.githubusercontent.com/kikisozi/active-ip-sniffer/main/install.sh | sudo bash -s -- 18080
```

安装后访问：

```text
http://服务器IP:18080
```

安装脚本会：

1. 安装 Python 3、curl 与 CA 证书（支持 apt/dnf/yum）。
2. 将程序放到 `/opt/active-ip-sniffer/active_sniffer.py`。
3. 创建并启动 `active-ip-sniffer.service`。
4. 若检测到已启用的 UFW 或 firewalld，则开放所选 TCP 端口。

常用命令：

```bash
systemctl status active-ip-sniffer
systemctl restart active-ip-sniffer
journalctl -u active-ip-sniffer -f
```

## 手动运行

```bash
python3 active_sniffer.py --host 0.0.0.0 --port 8766
```

## 扫描范围限制

为避免误操作，程序保留硬限制：

- 最多 65,536 个唯一 IPv4。
- 最多 32 个 TCP 端口。
- 单次最多 2,000,000 次连接尝试。
- 最大 512 并发。
- 最大 5,000 次连接尝试/秒。
- 单次连接超时限制在 0.05-5 秒。

## CSV 导出

扫描期间和完成后都可以点击 **导出 CSV**。输出示例：

```csv
ip,port
103.117.100.8,80
103.117.100.8,443
103.117.101.20,443
```

每个开放端口占一行，方便继续用 Excel、Python、Shell 或其他筛选工具处理。

## 卸载

```bash
sudo systemctl disable --now active-ip-sniffer
sudo rm -f /etc/systemd/system/active-ip-sniffer.service
sudo systemctl daemon-reload
sudo rm -rf /opt/active-ip-sniffer
```

如果安装脚本曾自动放行防火墙端口，请按你实际使用的端口自行删除对应 UFW/firewalld 规则。

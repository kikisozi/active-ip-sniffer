# Active IP Sniffer

一个面向低内存 VPS / Windows 的 Go 单二进制 IP 优选 WebUI。除了原有的流式 TCP 扫描，v3 还整合了 Cloudflare 两阶段直连测速、Top 20 排名、IP 地区/ASN/IDC 展示与缓存、CSV 候选导入、Cloudflare DNS 一键更新，以及不依赖 Xray 的原生 VLESS TLS+WS 端到端测试。

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

## v3.4.1：探针兼容修复 / Auto WARP 40099

- 修复旧版 `v probe` 对 `/api/egress/check` 返回纯文本 404 时，浏览器错误显示 `Unexpected non-whitespace character after JSON` 的问题。现在会识别非 JSON/404，并明确提示本地探针版本过旧。
- 出口新增 **Auto（默认）**：在当前检测来源（服务器后端或本地探针）上先验证 `127.0.0.1:40099`，仅当 Cloudflare Trace 返回 `warp=on/plus` 才使用 WARP；否则自动回落 Direct。每个任务只在启动时解析一次出口，不会中途切换。
- Linux/Windows 安装器附带 WARP helper：`v warp on` 一键安装/配置 Cloudflare One Client Local Proxy 到 `40099`，`v warp status` 检查，`v warp off` 断开。新装时也可使用 `AIS_INSTALL_WARP=1` 自动启用。
- WARP Local Proxy 仍是可选能力；不支持官方 WARP 客户端的平台会保持 Direct。由于 Cloudflare Local proxy 单请求有超时限制，慢线路上的大文件精测仍建议使用 Direct 做运营商排名。

## v3.4：WARP 可选出口 / 用户测速 / 智能 DNS

- 服务器后端与本地 `v probe` 都支持 **Direct / WARP Local Proxy** 两种测试出口。WARP 模式使用本机 SOCKS5 Local Proxy（默认 `127.0.0.1:40099`），只代理本程序发起的 TCP/CF/VLESS 外层连接，不强制修改整机默认路由。
- 新增独立用户测速 WebUI，默认端口 `18768`，与总控管理端口分离。总控可以把当前 CF Top 候选发布给用户；用户网页连接自己电脑上的 `v probe`，从用户真实网络出口运行 1 MB / 2 秒快筛和较轻量的 20 MB 精测，然后仅把 Top 5 回传总控。
- 总控“用户测速 / 智能 DNS”页按提交者 IP 的地区/ASN/ISP 展示结果，点击提交者可展开其 Top 5。
- 最近 7 天用户提交会按电信、联通、移动和默认线路聚合，自动计算每个候选 IP 的峰值速度中位数、峰值均值、平均速度中位数与样本数；智能 DNS 计划优先按峰值中位数排序，降低单次异常峰值的影响。WARP/系统 WARP 提交不会进入自动 DNS 计划，只保留供人工比较。
- 集成 DNSPod 智能解析：支持每线路 Top 1-5、最少提交者门槛、TTL、手动应用，以及 5-1440 分钟的可选自动更新。程序只修改带 `active-ip-sniffer smart dns` 备注的托管 A 记录；遇到同主机/同线路的未托管 A 记录会拒绝覆盖。
- 建议 Cloudflare 主域继续保留在 Cloudflare，把一个独立子域委派给 DNSPod，业务域名再 CNAME 到该智能解析名称，从而使用 DNSPod 的电信/联通/移动线路返回不同的优选 IP 集合。

## v3.3：CF Direct 两阶段测速 / CSV / 元数据筛选

- **CF Direct 两阶段测速**：候选 IP 直接承载 `speed.cloudflare.com` 的 TLS SNI / HTTP Host，不经过 VLESS 或 Xray。
- 所有候选先做 TCP 可达性初筛；TCP 可达后先下载 **1,000,000 bytes**，必须在 **2 秒内完整完成**并通过 TLS/HTTP 验证才进入精测。
- 1 MB 快筛通过者再串行下载 **80,000,000 bytes** 一次；串行精测避免多个候选同时抢宿主机带宽。
- 80 MB 阶段记录 TCP、TLS 握手、TLS 完成、TTFB、下载平均 Mbps、全程有效 Mbps、250 ms 窗口峰值 Mbps、下载传输耗时、完整总耗时和 HTTP 状态。
- 最终排名改为 **成功 → 峰值速度 → 平均速度 → TTFB → TCP**，运行中与最终结果最多保留 Top 20。
- 候选输入支持单 IP、`IP:端口`、CIDR、起止 IPv4 范围；默认 443，也可选择 Cloudflare 常见 HTTPS 端口 `2053/2083/2087/2096/8443`。
- CF / VLESS 候选区支持直接导入 CSV。可识别 `ip`、`port`，以及 `country_code/country/region/city/asn/idc/org/isp` 等常见列；CSV 自带元数据时会直接写入本地缓存并优先使用，不再重复向公共接口查询这些 IP。
- IP 元数据使用本地持久缓存：成功查询默认保留 7 天，CSV 导入元数据默认保留 30 天，失败查询负缓存 15 分钟；同一 IP 的并发查询会合并。
- 公共查询以 `ipwho.is` 为主，失败时回退 `ip-api.com`；结果页支持按地区缩写（如 `HK`）、ASN、IDC/云厂商筛选，并可导出当前筛选结果。
- Cloudflare API Token + 多域名可以在 WebUI 或 `v` 配置向导中验证后保存；页面完整显示当前 DNS 记录。测速结果可直接选择目标域名/A 记录并更新到优选 IP，更新后会再次从 Cloudflare API 回读验证。
- CF Top 20 可一键送入 VLESS End-to-End 测试；单个结果也可以直接进入 VLESS 测试。
- Cloudflare Token 保存在服务器配置文件，不回传明文给 WebUI，也不会写入测速 CSV。

## v3.1：本地探针 / 当前出口 / Alpine

- WebUI 顶部显示访问者 IP、服务器默认公网出口、当前检测/测速出口，以及 Cloudflare Trace 返回的 WARP/Colo 状态。
- 检测来源可在 **服务器后端** 与 **本地探针**之间切换。服务器模式的 TCP、CF 1 MB / 80 MB、VLESS 测试由服务器发起；本地探针模式则从用户自己的 Windows/Linux/Alpine 机器发起。
- 本地探针仅监听 `127.0.0.1:18767`，每次启动随机生成 Probe Token；浏览器必须携带 Token 才能调用扫描/测速 API。Token 只保存在当前浏览器标签页的 `sessionStorage`，不会提交给中央 WebUI。
- 浏览器访问 WebUI 后点击“本地探针配置教程”即可看到 Linux/Alpine、Windows 的完整安装与连接步骤。
- Linux 安装脚本改为 POSIX `sh`，增加 `apk`、`zypper`、`pacman` 包管理器支持；常驻模式自动检测 systemd 或 OpenRC，Alpine 可使用 OpenRC 常驻。

> 顶部“当前检测 / 测速出口”来自当前机器访问外部网络时的默认公网出口。若 WARP/VPN 对特定目标设置了 Split Tunnel，某个目标的实际路由仍可能与默认出口不同。

## 资源建议

对于 **128 MB RAM**：

- 推荐 worker：`32-64`
- 推荐速率：`200-1000` 次连接尝试/秒
- 推荐单次端口数：`1-4`
- 程序采用流式目标生成，扫描几万 IP 不需要预先保存几万条字符串。
- systemd 安装配置默认设置 `GOMEMLIMIT=80MiB` 和 `GOGC=50`，为系统本身保留内存余量。

512 MB **可用**磁盘空间足够运行本项目。程序二进制约数 MB；实际磁盘消耗主要取决于命中结果文件数量。

## Linux 一键安装 / `v` 配置界面

首次只需要一条命令：

```bash
curl -fsSL "https://raw.githubusercontent.com/kikisozi/active-ip-sniffer/main/install.sh?cb=$(date +%s)" | sudo sh
```

安装脚本只负责下载并校验 Go 单二进制，随后进入 **Go 编写的交互配置界面**。可交互选择：

- WebUI 监听地址与端口；
- WebUI 管理密码（启用后使用 HTTP Basic Auth，用户名固定为 `admin`；配置 Cloudflare DNS 写入能力时必须启用）；
- 是否立即配置 Cloudflare Token / 一个或多个优选域名，并联网验证；
- Linux 选择 **常驻 systemd 守护进程** 或 **单次前台运行**；
- 常驻模式下是否自动放行 WebUI TCP 端口。

安装完成后不需要再次执行安装脚本，之后直接输入：

```bash
v
```

即可重新进入完整配置界面。普通用户执行 `v` 时会自动尝试通过 `sudo` 进入需要 root 权限的 Linux 配置流程。

Linux 安装脚本根据 CPU 自动下载：

- `dist/active-ip-sniffer-linux-amd64`
- `dist/active-ip-sniffer-linux-arm64`

因此低配 VPS **不会现场安装 Go 或进行编译**。

安装脚本会先通过 GitHub API 解析 `main` 当前精确 commit SHA，再从同一个 commit 下载二进制和 `SHA256SUMS` 并强制校验，从而避免分支 raw CDN 短时缓存造成版本混用。

安装位置：

```text
/opt/active-ip-sniffer/active-ip-sniffer
/usr/local/bin/v
/etc/active-ip-sniffer/config.json
/var/lib/active-ip-sniffer/results/
```

常用命令：

```bash
systemctl status active-ip-sniffer
systemctl restart active-ip-sniffer
journalctl -u active-ip-sniffer -f
```

Alpine/OpenRC 使用：

```sh
rc-service active-ip-sniffer status
rc-service active-ip-sniffer restart
rc-update show | grep active-ip-sniffer
```

如果 Alpine 系统没有 `sudo`，以 root 登录后可直接执行：

```sh
curl -fsSL "https://raw.githubusercontent.com/kikisozi/active-ip-sniffer/main/install.sh?cb=$(date +%s)" | sh
```

## 本地探针模式

已安装本项目后，在**需要承担实际扫描/测速流量的那台机器**运行：

```text
v probe
```

探针会输出：

```text
Active IP Sniffer 3.4.0 local probe: http://127.0.0.1:18767
Local probe token: <随机 Token>
```

保持终端运行，在中央 WebUI 点击“本地探针配置教程”，把 Token 粘贴进去并连接。连接成功后，将“检测来源”切换为“本地探针”。此时：

- TCP 扫描连接由本地探针发出；
- CF Direct 的 1 MB 快筛与 80 MB 精测都由本地探针下载；
- VLESS Endpoint Bench 的 TCP/TLS/WS/VLESS/下载全部由本地探针执行；
- Cloudflare DNS Token 与 DNS 更新仍由中央 WebUI 服务器管理，不会传给本地探针。

因此，**测速一定会消耗执行测速那台机器的网络流量**。服务器模式会消耗服务器/VPS 的月流量；本地探针模式会消耗用户本机或本地 VPS 的流量。WARP/VPN 只改变出口路径，不能把这些字节从宿主机流量统计中“消失”。

### CSV 候选导入

CF Direct 与 VLESS 候选区都提供“导入 CSV”。最简单的文件只需要：

```csv
ip,port
47.242.162.186,443
43.99.56.133,443
```

如果已有地区/ASN/IDC 数据，可以直接带入：

```csv
ip,port,country_code,region,asn,idc
47.242.162.186,443,HK,Hong Kong,AS45102,Alibaba Cloud
43.99.56.133,443,HK,Hong Kong,45102,Alibaba Cloud
```

这些元数据会优先进入本地缓存，并直接用于页面展示、地区/ASN/IDC 筛选和 CSV 导出。

## Windows PowerShell 一键安装

Windows 也使用预编译 Go 单二进制，不要求本机安装 Go。PowerShell 中执行一次：

```powershell
irm https://raw.githubusercontent.com/kikisozi/active-ip-sniffer/main/install.ps1 | iex
```

脚本会校验 GitHub 当前 commit 对应 Windows 二进制的 SHA256，安装到当前用户的 `%LOCALAPPDATA%\ActiveIPSniffer`，把目录加入用户 `PATH`，并创建 `v.cmd`。之后 PowerShell 或 CMD 中直接输入：

```powershell
v
```

即可进入同一个 Go 配置界面。Windows 按要求使用**单次前台模式**：配置完成后启动 WebUI，关闭进程即停止，不创建 Windows Service。

> Cloudflare Token 仅保存在本机配置文件中，Linux 配置文件权限为 `0600`；WebUI 不会回传 Token 明文。为避免公开 WebUI 获得 DNS 写权限，保存 Cloudflare Token 前必须通过 `v` 配置 WebUI 管理密码。

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
./active-ip-sniffer serve -host 127.0.0.1 -port 8766
```

## CSV 导出

全量结果实时写入磁盘，每个开放端口一行：

```csv
ip,port
103.117.100.8,80
103.117.100.8,443
103.117.101.20,443
```

TCP 扫描后端内存环形区最多保留最近 500 个命中 IP，新 UI 表格只渲染最近 50 条并查询地区/ASN/IDC，以避免浏览器和外部元数据查询被大量结果拖慢；CSV 和“复制全部 IP”仍使用完整落盘结果。

VLESS Endpoint Bench 的 CSV 字段包括：

```text
ip,tcp_passed,tcp_attempts,tcp_median_ms,transport_ok,transport_ms,vless_ok,startup_ms,first_1s_mbps,first_3s_mbps,stable_mbps,peak_mbps,downloaded_bytes,download_seconds,status,failure_stage,error
```

## GitHub 自动构建

`.github/workflows/build.yml` 会在 `main` 上源码变化时执行 `go test` / `go vet`，并构建 Linux amd64/arm64 与 Windows amd64/arm64 四个静态 Go 二进制，统一生成 `dist/SHA256SUMS` 后提交到 `dist/`。自动生成二进制的提交包含 `[skip ci]`，不会形成循环构建。

## 卸载

```bash
sudo systemctl disable --now active-ip-sniffer
sudo rm -f /etc/systemd/system/active-ip-sniffer.service
sudo systemctl daemon-reload
sudo rm -f /usr/local/bin/v
sudo rm -rf /opt/active-ip-sniffer /etc/active-ip-sniffer /var/lib/active-ip-sniffer
```

如果安装脚本曾自动放行防火墙端口，请按实际端口删除对应 UFW/firewalld 规则。

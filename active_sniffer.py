#!/usr/bin/env python3
"""Standalone, rate-limited TCP reachability scanner with a small WebUI.

Use only on networks you own or are explicitly authorized to assess.
"""

from __future__ import annotations

import argparse
import csv
import io
import ipaddress
import json
import re
import socket
import threading
import time
import urllib.parse
import uuid
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


APP_VERSION = "1.0.1"
MAX_PORTS = 32
MAX_ATTEMPTS = 2_000_000
MAX_WORKERS = 512
MAX_RATE = 5_000.0
JOBS: dict[str, "ScanJob"] = {}


HTML = r'''<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Active IP Sniffer</title>
<style>
:root{color-scheme:light;--bg:#f4f6f8;--card:#fff;--ink:#17202a;--muted:#667085;--line:#d8dee6;--accent:#087f5b;--danger:#c92a2a}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 system-ui,"Segoe UI",sans-serif}header{height:58px;background:#17202a;color:white;display:flex;align-items:center;justify-content:space-between;padding:0 22px}.app{max-width:980px;margin:0 auto;padding:18px}.card{background:var(--card);border:1px solid var(--line);border-radius:8px;margin-bottom:14px}.card h2{font-size:14px;margin:0;padding:12px 14px;border-bottom:1px solid var(--line)}.body{padding:14px}.grid{display:grid;grid-template-columns:repeat(12,1fr);gap:12px}.s12{grid-column:span 12}.s6{grid-column:span 6}.s4{grid-column:span 4}.s3{grid-column:span 3}.field label{display:block;font-size:12px;font-weight:700;color:#475467;margin:0 0 6px}.field input,.field textarea{width:100%;border:1px solid #cbd3dd;border-radius:5px;padding:9px 10px;background:white;min-height:38px}.field textarea{min-height:130px;resize:vertical;font-family:ui-monospace,Consolas,monospace}.row{display:flex;gap:9px;align-items:center;flex-wrap:wrap}.actions{display:flex;justify-content:space-between;gap:10px;align-items:center}.btn{border:1px solid transparent;border-radius:5px;padding:9px 14px;font-weight:700;cursor:pointer}.primary{background:var(--accent);color:#fff}.secondary{background:#fff;border-color:#b8c1cc}.danger{background:#fff;border-color:#ffa8a8;color:var(--danger)}.btn:disabled{opacity:.45;cursor:not-allowed}.metric{display:grid;grid-template-columns:150px 1fr 75px;align-items:center;gap:12px}.track{height:9px;background:#e9ecef;border-radius:5px;overflow:hidden}.fill{height:100%;width:0;background:var(--accent);transition:width .2s}.muted{color:var(--muted)}.notice{padding:9px 11px;background:#edf8fa;border-left:3px solid #0b7285;font-size:12px;color:#38515a}.table-wrap{max-height:430px;overflow:auto}table{width:100%;border-collapse:collapse;font-variant-numeric:tabular-nums}th,td{padding:9px 11px;border-bottom:1px solid #e9edf2;text-align:left;white-space:nowrap}th{position:sticky;top:0;background:#f8f9fa;font-size:11px;text-transform:uppercase;color:#596579}.num{text-align:right}.ok{color:#087f5b}.hidden{display:none!important}@media(max-width:720px){.s6,.s4,.s3{grid-column:span 12}.actions{flex-direction:column;align-items:stretch}.metric{grid-template-columns:105px 1fr 55px}}
</style></head><body>
<header><strong>Active IP Sniffer</strong><span id="version">v1.0.1</span></header>
<main class="app">
  <section class="card"><h2>扫描参数</h2><div class="body grid">
    <div class="field s6"><label>目标（单 IP / CIDR / 起止范围，可混合）</label><textarea id="targets" placeholder="103.117.100.0/22&#10;203.0.113.10-203.0.113.50&#10;198.51.100.8"></textarea></div>
    <div class="field s6"><label>TCP 端口</label><input id="ports" value="80,443"><div style="height:10px"></div><label>说明</label><div class="notice">只做 TCP connect 可达性探测，不发送漏洞利用载荷。IPv4 数量不设固定上限；一次最多 32 个端口、2,000,000 次连接尝试。</div></div>
    <div class="field s3"><label>超时（秒）</label><input id="timeout" type="number" min="0.05" max="5" step="0.05" value="0.8"></div>
    <div class="field s3"><label>并发</label><input id="workers" type="number" min="1" max="512" value="256"></div>
    <div class="field s3"><label>速率（连接/秒）</label><input id="rate" type="number" min="1" max="5000" value="500"></div>
    <div class="s3 actions"><button id="cancel" class="btn danger" disabled>停止</button><button id="start" class="btn primary">开始扫描</button></div>
  </div></section>

  <section id="progressCard" class="card hidden"><h2>进度</h2><div class="body">
    <div class="metric"><strong id="found">发现 0 个 IP</strong><div class="track"><div id="fill" class="fill"></div></div><span id="pct">0%</span></div>
    <div id="status" class="muted" style="margin-top:10px">等待扫描</div>
  </div></section>

  <section id="resultCard" class="card hidden"><h2>结果</h2><div class="body actions"><span id="resultMeta" class="muted"></span><div class="row"><button id="copy" class="btn secondary" disabled>复制 IP</button><button id="export" class="btn secondary" disabled>导出 CSV</button></div></div>
    <div class="table-wrap"><table><thead><tr><th>#</th><th>IP</th><th>开放端口</th></tr></thead><tbody id="rows"></tbody></table></div>
  </section>
</main>
<script>
const $=s=>document.querySelector(s);let job=null,poller=null,last=[];
function value(id){return $(id).value.trim()}function number(id){return Number(value(id))}
function render(items){last=items;$('#rows').innerHTML=items.map((r,i)=>`<tr><td>${i+1}</td><td class="ok">${r.ip}</td><td>${r.ports.join(', ')}</td></tr>`).join('');$('#copy').disabled=!items.length;$('#export').disabled=!items.length;$('#resultMeta').textContent=`${items.length} 个 IP / ${items.reduce((n,r)=>n+r.ports.length,0)} 个开放端口`}
$('#start').onclick=async()=>{const targets=value('#targets').split(/[\s,;]+/).filter(Boolean);const ports=value('#ports').split(/[\s,;]+/).filter(Boolean).map(Number);if(!targets.length)return alert('请输入目标');if(!ports.length)return alert('请输入端口');const body={targets,ports,timeout:number('#timeout'),workers:number('#workers'),rate:number('#rate')};const r=await fetch('/api/scan/start',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});const x=await r.json();if(!r.ok)return alert(x.error||'启动失败');job=x.id;$('#start').disabled=true;$('#cancel').disabled=false;$('#progressCard').classList.remove('hidden');$('#resultCard').classList.remove('hidden');render([]);$('#status').textContent=`已展开 ${x.hosts} 个 IPv4，共 ${x.attempts} 次连接尝试`;poller=setInterval(poll,500);poll()};
$('#cancel').onclick=async()=>{if(job)await fetch('/api/scan/cancel?id='+encodeURIComponent(job),{method:'POST'})};
async function poll(){if(!job)return;const r=await fetch('/api/scan/job?id='+encodeURIComponent(job));if(!r.ok)return;const x=await r.json();const p=x.total?Math.round(x.done*100/x.total):0;$('#fill').style.width=p+'%';$('#pct').textContent=p+'%';$('#found').textContent=`发现 ${x.results.length} 个 IP`;$('#status').textContent=`${x.done}/${x.total} 次连接尝试 · ${x.status}${x.message?' · '+x.message:''}`;render(x.results);if(['complete','failed','cancelled'].includes(x.status)){clearInterval(poller);$('#start').disabled=false;$('#cancel').disabled=true}}
$('#export').onclick=()=>{if(job)location.href='/api/scan/export.csv?id='+encodeURIComponent(job)};
$('#copy').onclick=async()=>{await navigator.clipboard.writeText(last.map(x=>x.ip).join('\n'));$('#copy').textContent='已复制';setTimeout(()=>$('#copy').textContent='复制 IP',1000)};
fetch('/api/info').then(r=>r.json()).then(x=>$('#version').textContent='v'+x.version);
</script></body></html>'''


def tcp_reachable(ip: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def parse_scan_targets(values: list[Any], max_addresses: int | None = None) -> list[str]:
    addresses: set[ipaddress.IPv4Address] = set()

    def add(address: ipaddress.IPv4Address) -> None:
        addresses.add(address)
        if max_addresses is not None and len(addresses) > max_addresses:
            raise ValueError(
                f"scan target count exceeds {max_addresses:,} IPv4 addresses for the selected ports; "
                f"the limit is {MAX_ATTEMPTS:,} total connection attempts"
            )

    for raw in values:
        value = str(raw).strip()
        if not value:
            continue

        range_match = re.fullmatch(
            r"(\d{1,3}(?:\.\d{1,3}){3})\s*-\s*(\d{1,3}(?:\.\d{1,3}){3})", value
        )
        if range_match:
            start = ipaddress.ip_address(range_match.group(1))
            end = ipaddress.ip_address(range_match.group(2))
            if not isinstance(start, ipaddress.IPv4Address) or not isinstance(end, ipaddress.IPv4Address):
                raise ValueError(f"only IPv4 ranges are supported: {value}")
            if int(start) > int(end):
                raise ValueError(f"IP range start is greater than end: {value}")
            if max_addresses is not None and int(end) - int(start) + 1 > max_addresses:
                raise ValueError(
                    f"IP range contains more than {max_addresses:,} addresses for the selected ports; "
                    f"the limit is {MAX_ATTEMPTS:,} total connection attempts"
                )
            for number in range(int(start), int(end) + 1):
                add(ipaddress.IPv4Address(number))
            continue

        if "/" in value:
            try:
                network = ipaddress.ip_network(value, strict=False)
            except ValueError as exc:
                raise ValueError(f"invalid CIDR target: {value}") from exc
            if not isinstance(network, ipaddress.IPv4Network):
                raise ValueError(f"only IPv4 CIDR is supported: {value}")
            usable_addresses = network.num_addresses - 2 if network.prefixlen < 31 else network.num_addresses
            if max_addresses is not None and usable_addresses > max_addresses:
                raise ValueError(
                    f"CIDR contains more than {max_addresses:,} usable addresses for the selected ports; "
                    f"the limit is {MAX_ATTEMPTS:,} total connection attempts"
                )
            for address in network.hosts():
                add(address)
            continue

        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError(f"invalid IPv4 target: {value}") from exc
        if not isinstance(address, ipaddress.IPv4Address):
            raise ValueError(f"only IPv4 addresses are supported: {value}")
        add(address)

    if not addresses:
        raise ValueError("provide at least one valid scan target")
    return [str(address) for address in sorted(addresses)]


@dataclass
class ScanJob:
    id: str
    addresses: list[str]
    ports: list[int]
    timeout: float
    workers: int
    rate: float
    status: str = "queued"
    done: int = 0
    total: int = 0
    found: dict[str, set[int]] = field(default_factory=dict)
    cancelled: bool = False
    message: str = ""
    started_at: float = field(default_factory=time.time)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            ips = sorted(self.found, key=lambda value: int(ipaddress.ip_address(value)))
            return {
                "id": self.id,
                "status": self.status,
                "done": self.done,
                "total": self.total,
                "message": self.message,
                "results": [{"ip": ip, "ports": sorted(self.found[ip])} for ip in ips],
            }

    def cancel(self) -> None:
        self.cancelled = True
        self.status = "cancelled"
        self.message = "scan cancelled"

    def csv_bytes(self) -> bytes:
        output = io.StringIO(newline="")
        writer = csv.writer(output)
        writer.writerow(["ip", "port"])
        with self.lock:
            for ip in sorted(self.found, key=lambda value: int(ipaddress.ip_address(value))):
                for port in sorted(self.found[ip]):
                    writer.writerow([ip, port])
        return output.getvalue().encode("utf-8-sig")


def execute_scan(job: ScanJob) -> None:
    try:
        job.status = "running"
        job.total = len(job.addresses) * len(job.ports)
        task_iterator = iter((ip, port) for ip in job.addresses for port in job.ports)
        iterator_lock = threading.Lock()
        rate_lock = threading.Lock()
        next_attempt = [time.monotonic()]

        def get_task() -> tuple[str, int] | None:
            with iterator_lock:
                try:
                    return next(task_iterator)
                except StopIteration:
                    return None

        def throttle() -> None:
            with rate_lock:
                now = time.monotonic()
                scheduled = max(now, next_attempt[0])
                next_attempt[0] = scheduled + 1.0 / job.rate
            delay = scheduled - now
            if delay > 0:
                time.sleep(delay)

        def worker() -> None:
            while not job.cancelled:
                task = get_task()
                if task is None:
                    return
                ip, port = task
                throttle()
                is_open = tcp_reachable(ip, port, job.timeout)
                with job.lock:
                    job.done += 1
                    if is_open:
                        job.found.setdefault(ip, set()).add(port)

        threads = [
            threading.Thread(target=worker, daemon=True)
            for _ in range(min(job.workers, max(1, job.total)))
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        if not job.cancelled:
            job.status = "complete"
            job.message = f"found {len(job.found)} IPs with at least one open port"
    except Exception as exc:
        job.status = "failed"
        job.message = str(exc)


class Handler(BaseHTTPRequestHandler):
    server_version = "ActiveSniffer/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def send_bytes(
        self,
        data: bytes,
        content_type: str,
        status: int = 200,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)

    def send_json(self, value: Any, status: int = 200) -> None:
        self.send_bytes(
            json.dumps(value, ensure_ascii=False).encode("utf-8"),
            "application/json; charset=utf-8",
            status,
        )

    def query(self) -> dict[str, list[str]]:
        return urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)

    def do_GET(self) -> None:
        path = urllib.parse.urlsplit(self.path).path
        if path == "/":
            self.send_bytes(HTML.encode("utf-8"), "text/html; charset=utf-8")
            return
        if path == "/api/info":
            self.send_json({"version": APP_VERSION})
            return
        if path == "/api/scan/job":
            job = JOBS.get(self.query().get("id", [""])[0])
            self.send_json(job.snapshot() if job else {"error": "job not found"}, 200 if job else 404)
            return
        if path == "/api/scan/export.csv":
            job = JOBS.get(self.query().get("id", [""])[0])
            if not job:
                self.send_json({"error": "job not found"}, 404)
                return
            name = f"active-sniffer-{time.strftime('%Y%m%d-%H%M%S')}.csv"
            self.send_bytes(
                job.csv_bytes(),
                "text/csv; charset=utf-8",
                headers={"Content-Disposition": f'attachment; filename="{name}"'},
            )
            return
        self.send_json({"error": "not found"}, 404)

    def do_POST(self) -> None:
        path = urllib.parse.urlsplit(self.path).path
        if path == "/api/scan/cancel":
            job = JOBS.get(self.query().get("id", [""])[0])
            if not job:
                self.send_json({"error": "job not found"}, 404)
            else:
                job.cancel()
                self.send_json({"ok": True})
            return
        if path != "/api/scan/start":
            self.send_json({"error": "not found"}, 404)
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 100_000:
                raise ValueError("request is empty or too large")
            payload = json.loads(self.rfile.read(length))
            targets = list(
                dict.fromkeys(str(value).strip() for value in payload.get("targets", []) if str(value).strip())
            )
            ports = sorted(set(int(port) for port in payload.get("ports", [])))
            if not ports or len(ports) > MAX_PORTS or any(port < 1 or port > 65535 for port in ports):
                raise ValueError(f"provide 1 to {MAX_PORTS} valid TCP ports")
            max_addresses = MAX_ATTEMPTS // len(ports)
            addresses = parse_scan_targets(targets, max_addresses=max_addresses)
            attempts = len(addresses) * len(ports)
            if attempts > MAX_ATTEMPTS:
                raise ValueError(f"scan exceeds {MAX_ATTEMPTS:,} connection attempts")
            timeout = max(0.05, min(5.0, float(payload.get("timeout", 0.8))))
            workers = max(1, min(MAX_WORKERS, int(payload.get("workers", 256))))
            rate = max(1.0, min(MAX_RATE, float(payload.get("rate", 500))))
            job = ScanJob(uuid.uuid4().hex, addresses, ports, timeout, workers, rate)
            JOBS[job.id] = job
            threading.Thread(target=execute_scan, args=(job,), daemon=True).start()
            self.send_json(
                {"id": job.id, "hosts": len(addresses), "attempts": attempts},
                HTTPStatus.ACCEPTED,
            )
        except Exception as exc:
            self.send_json({"error": str(exc)}, 400)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="0.0.0.0", help="listen address; default 0.0.0.0")
    parser.add_argument("--port", type=int, default=8766, help="WebUI listen port")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"Active IP Sniffer {APP_VERSION}: http://{args.host}:{server.server_address[1]}")
    print("Use only on networks you own or are explicitly authorized to assess.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        for job in list(JOBS.values()):
            job.cancel()
        server.server_close()


if __name__ == "__main__":
    main()

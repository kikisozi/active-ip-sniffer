from pathlib import Path


def read(path):
    return Path(path).read_text(encoding="utf-8")


def write(path, text):
    Path(path).write_text(text, encoding="utf-8")


def replace(path, old, new, count=1):
    text = read(path)
    actual = text.count(old)
    if actual < count:
        raise SystemExit(f"{path}: expected at least {count} occurrence(s), found {actual}: {old[:120]!r}")
    text = text.replace(old, new, count)
    write(path, text)


def replace_all(path, old, new):
    text = read(path)
    if old not in text:
        raise SystemExit(f"{path}: missing {old!r}")
    write(path, text.replace(old, new))


# egress.go: Auto prefers a verified WARP Local Proxy and otherwise falls back to Direct.
replace("egress.go", 'const defaultWARPProxy = "127.0.0.1:40000"', 'const defaultWARPProxy = "127.0.0.1:40099"')
replace("egress.go", '''\tif mode == "" {\n\t\tmode = "direct"\n\t}\n\tif mode != "direct" && mode != "warp" {\n\t\treturn egressConfig{}, fmt.Errorf("unsupported egress mode: %s", mode)\n\t}\n''', '''\tif mode == "" {\n\t\tmode = "auto"\n\t}\n\tif mode != "auto" && mode != "direct" && mode != "warp" {\n\t\treturn egressConfig{}, fmt.Errorf("unsupported egress mode: %s", mode)\n\t}\n''')
replace("egress.go", '''\tif mode == "warp" {\n\t\thost, portText, err := net.SplitHostPort(proxy)\n''', '''\tif mode == "warp" || mode == "auto" {\n\t\thost, portText, err := net.SplitHostPort(proxy)\n''')
replace("egress.go", '''\treturn egressConfig{Mode: mode, WARPProxy: proxy}, nil\n}\n\nfunc (e egressConfig) dialContext''', '''\treturn egressConfig{Mode: mode, WARPProxy: proxy}, nil\n}\n\nfunc warpTraceActive(info egressInfo) bool {\n\twarp := strings.ToLower(strings.TrimSpace(info.WARP))\n\treturn info.IP != "" && (warp == "on" || warp == "plus")\n}\n\n// resolveEgress resolves Auto once at task start so a single benchmark never\n// switches routes halfway through. Explicit WARP is accepted only when the\n// configured SOCKS5 endpoint actually produces a Cloudflare WARP trace.\nfunc resolveEgress(ctx context.Context, requested egressConfig) (egressConfig, egressInfo, error) {\n\tswitch requested.Mode {\n\tcase "direct":\n\t\tdirect := egressConfig{Mode: "direct", WARPProxy: requested.WARPProxy}\n\t\treturn direct, queryCloudflareTrace(ctx, direct), nil\n\tcase "warp":\n\t\tinfo := queryCloudflareTrace(ctx, requested)\n\t\tif info.IP == "" {\n\t\t\treturn requested, info, fmt.Errorf("WARP Local Proxy %s is not reachable or cannot reach Cloudflare", requested.WARPProxy)\n\t\t}\n\t\tif !warpTraceActive(info) {\n\t\t\treturn requested, info, fmt.Errorf("proxy %s is reachable but Cloudflare trace reports warp=%s", requested.WARPProxy, strings.TrimSpace(info.WARP))\n\t\t}\n\t\treturn requested, info, nil\n\tcase "auto":\n\t\twarp := egressConfig{Mode: "warp", WARPProxy: requested.WARPProxy}\n\t\tif info := queryCloudflareTrace(ctx, warp); warpTraceActive(info) {\n\t\t\treturn warp, info, nil\n\t\t}\n\t\tdirect := egressConfig{Mode: "direct", WARPProxy: requested.WARPProxy}\n\t\treturn direct, queryCloudflareTrace(ctx, direct), nil\n\tdefault:\n\t\treturn requested, egressInfo{}, fmt.Errorf("unsupported egress mode: %s", requested.Mode)\n\t}\n}\n\nfunc (e egressConfig) dialContext''')

# network_info.go: report requested and resolved modes; explicit WARP may fail, Auto may fall back.
replace("network_info.go", '''\t\tegress, err := normalizeEgress(request.Mode, request.WARPProxy)\n\t\tif err != nil {\n\t\t\twriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})\n\t\t\treturn\n\t\t}\n\t\tinfo := queryCloudflareTrace(r.Context(), egress)\n\t\tif info.IP == "" {\n\t\t\twriteJSON(w, http.StatusBadGateway, map[string]string{"error": "cannot reach Cloudflare trace through selected egress"})\n\t\t\treturn\n\t\t}\n\t\twriteJSON(w, http.StatusOK, map[string]any{"role": role, "mode": egress.Mode, "proxy": egress.WARPProxy, "egress": info})\n''', '''\t\trequested, err := normalizeEgress(request.Mode, request.WARPProxy)\n\t\tif err != nil {\n\t\t\twriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})\n\t\t\treturn\n\t\t}\n\t\tselected, info, err := resolveEgress(r.Context(), requested)\n\t\tif err != nil {\n\t\t\twriteJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})\n\t\t\treturn\n\t\t}\n\t\tif info.IP == "" {\n\t\t\twriteJSON(w, http.StatusBadGateway, map[string]string{"error": "cannot reach Cloudflare trace through selected egress"})\n\t\t\treturn\n\t\t}\n\t\twriteJSON(w, http.StatusOK, map[string]any{\n\t\t\t"role":           role,\n\t\t\t"requested_mode": requested.Mode,\n\t\t\t"mode":           selected.Mode,\n\t\t\t"proxy":          selected.WARPProxy,\n\t\t\t"auto_fallback":  requested.Mode == "auto" && selected.Mode == "direct",\n\t\t\t"egress":         info,\n\t\t})\n''')

# main.go: version/capabilities and resolved task egress.
replace("main.go", 'appVersion        = "3.4.0"', 'appVersion        = "3.4.1"')
replace("main.go", '''\t\t"cf_https_ports":      []int{443, 2053, 2083, 2087, 2096, 8443},\n\t}\n''', '''\t\t"cf_https_ports":       []int{443, 2053, 2083, 2087, 2096, 8443},\n\t\t"probe_port":           defaultProbePort,\n\t\t"default_egress_mode": "auto",\n\t\t"warp_proxy":          defaultWARPProxy,\n\t\t"egress_auto":         true,\n\t}\n''')
replace("main.go", '''\tegress, err := normalizeEgress(request.EgressMode, request.WARPProxy)\n\tif err != nil {\n\t\twriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})\n\t\treturn\n\t}\n''', '''\trequestedEgress, err := normalizeEgress(request.EgressMode, request.WARPProxy)\n\tif err != nil {\n\t\twriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})\n\t\treturn\n\t}\n\tegress, _, err := resolveEgress(r.Context(), requestedEgress)\n\tif err != nil {\n\t\twriteJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})\n\t\treturn\n\t}\n''')
replace("main.go", '''\twriteJSON(w, http.StatusAccepted, map[string]any{"id": id, "hosts": hostCount, "attempts": attempts})\n''', '''\twriteJSON(w, http.StatusAccepted, map[string]any{"id": id, "hosts": hostCount, "attempts": attempts, "requested_egress_mode": requestedEgress.Mode, "egress_mode": egress.Mode})\n''')

# CF and VLESS task starts resolve Auto before launching the job.
replace("cf_speed.go", '''\tegress, err := normalizeEgress(request.EgressMode, request.WARPProxy)\n\tif err != nil {\n\t\twriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})\n\t\treturn\n\t}\n''', '''\trequestedEgress, err := normalizeEgress(request.EgressMode, request.WARPProxy)\n\tif err != nil {\n\t\twriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})\n\t\treturn\n\t}\n\tegress, _, err := resolveEgress(r.Context(), requestedEgress)\n\tif err != nil {\n\t\twriteJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})\n\t\treturn\n\t}\n''')
replace("cf_speed.go", '''\t\t"egress_mode":       egress.Mode,\n''', '''\t\t"requested_egress_mode": requestedEgress.Mode,\n\t\t"egress_mode":           egress.Mode,\n''')
replace("vless_bench.go", '''\tegress, err := normalizeEgress(request.EgressMode, request.WARPProxy)\n\tif err != nil {\n\t\twriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})\n\t\treturn\n\t}\n''', '''\trequestedEgress, err := normalizeEgress(request.EgressMode, request.WARPProxy)\n\tif err != nil {\n\t\twriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})\n\t\treturn\n\t}\n\tegress, _, err := resolveEgress(r.Context(), requestedEgress)\n\tif err != nil {\n\t\twriteJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})\n\t\treturn\n\t}\n''')
replace("vless_bench.go", '''\t\t"egress_mode": egress.Mode,\n''', '''\t\t"requested_egress_mode": requestedEgress.Mode,\n\t\t"egress_mode":           egress.Mode,\n''')

# Admin UI: Auto by default, robust non-JSON handling and probe capability/version display.
replace_all("ui.go", "127.0.0.1:40000", "127.0.0.1:40099")
replace("ui.go", '''<select id="egressMode" style="min-width:155px;padding:7px 9px;border:1px solid #cbd3dd;border-radius:7px"><option value="direct">Direct</option><option value="warp">WARP Local Proxy</option></select>''', '''<select id="egressMode" style="min-width:185px;padding:7px 9px;border:1px solid #cbd3dd;border-radius:7px"><option value="auto">Auto（优先 WARP）</option><option value="direct">Direct</option><option value="warp">WARP Local Proxy</option></select>''')
replace("ui.go", '''TCP、CF 1 MB 快筛 / 80 MB 精测和 VLESS 都使用这里选择的出口。WARP 模式只把本程序的测试 TCP 连接送入本机 WARP SOCKS5 Local Proxy，不要求把整台机器默认路由切到 WARP。''', '''TCP、CF 1 MB 快筛 / 80 MB 精测和 VLESS 都使用这里选择的出口。Auto 会在当前检测来源（服务器或本地探针）上验证 127.0.0.1:40099：只有 Cloudflare Trace 确认 warp=on/plus 才使用 WARP，否则自动 Direct。''')
replace("ui.go", '''<h4>可选 WARP 出口</h4><p>如果本机已经安装 Cloudflare One Client / WARP，可在客户端 Advanced 中启用 <b>Local proxy</b>，默认建议监听 <code>127.0.0.1:40099</code>。总控顶部把“出口”切为 <b>WARP Local Proxy</b> 后，本程序的扫描/测速 TCP 才经过该代理；其他系统流量仍保持原路由。</p>''', '''<h4>可选 WARP 出口</h4><p>更新到本版安装脚本后可运行 <code>v warp on</code> 一键安装/启用 WARP Local Proxy（固定 <code>127.0.0.1:40099</code>），<code>v warp status</code> 查看状态，<code>v warp off</code> 断开。顶部保持 <b>Auto</b> 即可：WARP 实际可用就自动使用，否则自动 Direct。</p><p class="muted">若看到“探针接口不存在/版本过旧”，请重新执行项目安装命令更新本机程序，关闭旧 <code>v probe</code> 后重新启动。</p>''')
replace("ui.go", '''let probeConnected=false,probeInfo=null,serverNet=null,selectedEgress=null,appInfo=null;''', '''let probeConnected=false,probeInfo=null,probeAppInfo=null,serverNet=null,selectedEgress=null,appInfo=null;''')
replace("ui.go", '''const val=id=>q(id).value.trim(), num=id=>Number(val(id));\n''', '''const val=id=>q(id).value.trim(), num=id=>Number(val(id));\nasync function readJSONResponse(r,label){const text=await r.text();let x={};if(text.trim()){try{x=JSON.parse(text)}catch(e){const raw=text.trim().replace(/\\s+/g,' ').slice(0,180);if(r.status===404)throw new Error(label+'接口不存在，本机 v probe 版本过旧。请重新运行安装命令更新，并关闭旧探针后重新执行 v probe');throw new Error(label+'返回非 JSON（HTTP '+r.status+'）：'+(raw||'<empty>'))}}if(!r.ok)throw new Error(x.error||label+'失败（HTTP '+r.status+'）');return x}\n''')
replace("ui.go", '''function egressBody(){return {egress_mode:val('#egressMode')||'direct',warp_proxy:val('#warpProxy')||'127.0.0.1:40099'}}''', '''function egressBody(){return {egress_mode:val('#egressMode')||'auto',warp_proxy:val('#warpProxy')||'127.0.0.1:40099'}}''')
replace("ui.go", '''async function refreshSelectedEgress(){if(q('#sourceMode').value==='local'&&!probeConnected)return;selectedEgress=null;q('#egressState').textContent='正在验证所选测试出口...';try{const r=await fetch('/api/egress/check',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(egressBody())}),x=await r.json();if(!r.ok)throw new Error(x.error||'出口验证失败');selectedEgress=x.egress||null;q('#egressState').className='note blue';q('#egressState').textContent='已验证 '+(x.mode||'direct')+'：'+(selectedEgress&&selectedEgress.ip||'未知')+' · '+(selectedEgress&&selectedEgress.warp||'unknown')+(selectedEgress&&selectedEgress.colo?' · '+selectedEgress.colo:'');renderNetwork()}catch(e){q('#egressState').className='note';q('#egressState').textContent='出口验证失败：'+e.message;renderNetwork()}}''', '''async function refreshSelectedEgress(rethrow=false){if(q('#sourceMode').value==='local'&&!probeConnected)return;selectedEgress=null;q('#egressState').textContent='正在验证所选测试出口...';try{const r=await fetch('/api/egress/check',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(egressBody())}),x=await readJSONResponse(r,'出口验证');selectedEgress=x.egress||null;const fallback=x.auto_fallback?' · WARP 不可用，已自动 Direct':'';q('#egressState').className='note blue';q('#egressState').textContent='已验证 '+(x.requested_mode||x.mode||'auto')+' → '+(x.mode||'direct')+'：'+(selectedEgress&&selectedEgress.ip||'未知')+' · '+(selectedEgress&&selectedEgress.warp||'unknown')+(selectedEgress&&selectedEgress.colo?' · '+selectedEgress.colo:'')+fallback;renderNetwork();return x}catch(e){q('#egressState').className='note';q('#egressState').textContent='出口验证失败：'+e.message;renderNetwork();if(rethrow)throw e}}''')
replace("ui.go", '''async function connectProbe(){const token=val('#probeToken')||probeToken;if(token.length<16){q('#probeConnectStatus').textContent='请输入 v probe 输出的 Token。';return}q('#probeConnectStatus').textContent='正在连接 127.0.0.1:18767 ...';try{const headers={'X-Probe-Token':token};const r=await nativeFetch(probeBase+'/api/network-info',{headers});const x=await r.json();if(!r.ok)throw new Error(x.error||'连接失败');probeToken=token;probeInfo=x;probeConnected=true;sessionStorage.setItem('active-ip-sniffer-probe-token',token);q('#sourceMode').value='local';q('#probeConnectStatus').textContent='连接成功：检测出口 '+egressText(x)+' · '+warpText(x);await refreshSelectedEgress();renderNetwork();setTimeout(()=>q('#probeModal').classList.add('hidden'),350)}catch(e){probeConnected=false;q('#sourceMode').value='server';q('#probeConnectStatus').textContent='连接失败：'+e.message+'。请确认 v probe 正在本机运行、Token 正确，并允许浏览器访问 localhost。';renderNetwork()}}''', '''async function connectProbe(){const token=val('#probeToken')||probeToken;if(token.length<16){q('#probeConnectStatus').textContent='请输入 v probe 输出的 Token。';return}q('#probeConnectStatus').textContent='正在连接 127.0.0.1:18767 ...';try{const headers={'X-Probe-Token':token};const infoResp=await nativeFetch(probeBase+'/api/info',{headers}),papp=await readJSONResponse(infoResp,'本地探针信息');const r=await nativeFetch(probeBase+'/api/network-info',{headers}),x=await readJSONResponse(r,'本地探针');probeToken=token;probeInfo=x;probeAppInfo=papp;probeConnected=true;sessionStorage.setItem('active-ip-sniffer-probe-token',token);q('#sourceMode').value='local';q('#probeConnectStatus').textContent='连接成功：探针 v'+(papp.version||'?')+' · 检测出口 '+egressText(x)+' · '+warpText(x);await refreshSelectedEgress(true);renderNetwork();setTimeout(()=>q('#probeModal').classList.add('hidden'),350)}catch(e){probeConnected=false;probeAppInfo=null;q('#sourceMode').value='server';q('#probeConnectStatus').textContent='连接失败：'+e.message+'。请确认 v probe 正在本机运行、Token 正确，并允许浏览器访问 localhost。';renderNetwork()}}''')

# Public user benchmark page: Auto, 40099, robust old-probe diagnostics, submit actual resolved mode.
replace_all("public_web.go", "127.0.0.1:40000", "127.0.0.1:40099")
replace("public_web.go", '''writeJSON(w, http.StatusOK, map[string]any{"items": a.public.candidates(), "precision_mb": publicPrecisionMB, "quick_mb": 1, "quick_timeout_s": 2})''', '''writeJSON(w, http.StatusOK, map[string]any{"items": a.public.candidates(), "precision_mb": publicPrecisionMB, "quick_mb": 1, "quick_timeout_s": 2, "app_version": appVersion, "probe_port": defaultProbePort, "default_egress_mode": "auto", "warp_proxy": defaultWARPProxy})''')
replace("public_web.go", '''<select id="egress"><option value="direct">Direct 本地出口</option><option value="warp">WARP Local Proxy</option></select>''', '''<select id="egress"><option value="auto">Auto（优先 WARP）</option><option value="direct">Direct 本地出口</option><option value="warp">WARP Local Proxy</option></select>''')
replace("public_web.go", '''const $=s=>document.querySelector(s),probe='http://127.0.0.1:18767';let token='',candidates=[],job='',probeEgress={};\nasync function pfetch(path,init={}){const h=new Headers(init.headers||{});h.set('X-Probe-Token',token);return fetch(probe+path,{...init,headers:h})}\n''', '''const $=s=>document.querySelector(s),probe='http://127.0.0.1:18767';let token='',candidates=[],job='',probeEgress={},resolvedMode='direct',probeVersion='';\nasync function pfetch(path,init={}){const h=new Headers(init.headers||{});h.set('X-Probe-Token',token);return fetch(probe+path,{...init,headers:h})}\nasync function readJSON(r,label){const text=await r.text();let x={};if(text.trim()){try{x=JSON.parse(text)}catch(e){const raw=text.trim().replace(/\\s+/g,' ').slice(0,180);if(r.status===404)throw new Error(label+'接口不存在，本机 v probe 版本过旧；请重新运行安装命令更新并重启 v probe');throw new Error(label+'返回非 JSON（HTTP '+r.status+'）：'+(raw||'<empty>'))}}if(!r.ok)throw new Error(x.error||label+'失败（HTTP '+r.status+'）');return x}\n''')
replace("public_web.go", '''$('#connect').onclick=async()=>{token=$('#token').value.trim();if(token.length<16)return;const body={egress_mode:$('#egress').value,warp_proxy:$('#proxy').value.trim()};try{const r=await pfetch('/api/egress/check',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}),x=await r.json();if(!r.ok)throw new Error(x.error||'连接失败');probeEgress=x.egress||{};$('#state').className='note good';$('#state').textContent='探针已连接，当前测速出口 '+(probeEgress.ip||'?')+' · '+(probeEgress.warp||'unknown')+' · '+(probeEgress.colo||'');$('#start').disabled=!candidates.length}catch(e){$('#state').className='note bad';$('#state').textContent='连接失败：'+e.message}};''', '''$('#connect').onclick=async()=>{token=$('#token').value.trim();if(token.length<16)return;const body={egress_mode:$('#egress').value,warp_proxy:$('#proxy').value.trim()};try{const ir=await pfetch('/api/info'),pi=await readJSON(ir,'本地探针信息');probeVersion=pi.version||'';const r=await pfetch('/api/egress/check',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}),x=await readJSON(r,'出口验证');probeEgress=x.egress||{};resolvedMode=x.mode||'direct';$('#state').className='note good';$('#state').textContent='探针 v'+(probeVersion||'?')+' 已连接，'+(x.requested_mode||body.egress_mode)+' → '+resolvedMode+'，当前测速出口 '+(probeEgress.ip||'?')+' · '+(probeEgress.warp||'unknown')+' · '+(probeEgress.colo||'')+(x.auto_fallback?' · WARP 不可用，已自动 Direct':'');$('#start').disabled=!candidates.length}catch(e){$('#state').className='note bad';$('#state').textContent='连接失败：'+e.message;$('#start').disabled=true}};''')
replace("public_web.go", '''const r=await pfetch('/api/cf-speed/start',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}),x=await r.json();if(!r.ok)throw new Error(x.error||'启动失败');job=x.id;poll()''', '''const r=await pfetch('/api/cf-speed/start',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}),x=await readJSON(r,'测速启动');resolvedMode=x.egress_mode||resolvedMode;job=x.id;poll()''')
replace("public_web.go", '''async function poll(){const r=await pfetch('/api/cf-speed/job?id='+encodeURIComponent(job)),x=await r.json();''', '''async function poll(){const r=await pfetch('/api/cf-speed/job?id='+encodeURIComponent(job)),x=await readJSON(r,'测速任务');''')
replace("public_web.go", '''body:JSON.stringify({egress_mode:$('#egress').value,probe_egress:probeEgress,results:top})''', '''body:JSON.stringify({egress_mode:resolvedMode,probe_egress:probeEgress,results:top})''')

# Tests for new defaults and trace classification.
replace("egress_test.go", '''func TestWARPSOCKS5Dial(t *testing.T) {''', '''func TestNormalizeEgressAutoDefault(t *testing.T) {\n\tegress, err := normalizeEgress("", "")\n\tif err != nil {\n\t\tt.Fatal(err)\n\t}\n\tif egress.Mode != "auto" || egress.WARPProxy != "127.0.0.1:40099" {\n\t\tt.Fatalf("unexpected auto egress: %#v", egress)\n\t}\n\tif !warpTraceActive(egressInfo{IP: "198.51.100.1", WARP: "on"}) || warpTraceActive(egressInfo{IP: "198.51.100.1", WARP: "off"}) {\n\t\tt.Fatal("unexpected WARP trace classification")\n\t}\n}\n\nfunc TestWARPSOCKS5Dial(t *testing.T) {''')

# Linux installer: ship verified WARP helper and expose v warp on/off/status.
replace("install.sh", '''APP_BIN="${APP_DIR}/active-ip-sniffer"\nV_CMD="/usr/local/bin/v"\n''', '''APP_BIN="${APP_DIR}/active-ip-sniffer"\nWARP_HELPER="${APP_DIR}/warp-helper.sh"\nV_CMD="/usr/local/bin/v"\n''')
replace("install.sh", '''BINARY_URL="https://raw.githubusercontent.com/${REPO}/${REF}/${BINARY}"\nSUMS_URL="https://raw.githubusercontent.com/${REPO}/${REF}/dist/SHA256SUMS"\nTMP_BINARY="$(mktemp)"\nTMP_SUMS="$(mktemp)"\nNEW_BINARY="${APP_BIN}.new.$$"\ntrap 'rm -f "${TMP_BINARY}" "${TMP_SUMS}" "${NEW_BINARY}"' EXIT INT TERM\n''', '''BINARY_URL="https://raw.githubusercontent.com/${REPO}/${REF}/${BINARY}"\nWARP_HELPER_PATH="warp-helper.sh"\nWARP_HELPER_URL="https://raw.githubusercontent.com/${REPO}/${REF}/${WARP_HELPER_PATH}"\nSUMS_URL="https://raw.githubusercontent.com/${REPO}/${REF}/dist/SHA256SUMS"\nTMP_BINARY="$(mktemp)"\nTMP_WARP_HELPER="$(mktemp)"\nTMP_SUMS="$(mktemp)"\nNEW_BINARY="${APP_BIN}.new.$$"\ntrap 'rm -f "${TMP_BINARY}" "${TMP_WARP_HELPER}" "${TMP_SUMS}" "${NEW_BINARY}"' EXIT INT TERM\n''')
replace("install.sh", '''curl -fL --retry 3 --connect-timeout 10 "${BINARY_URL}?cb=${CACHE_BUST}" -o "${TMP_BINARY}"\ncurl -fsSL --retry 3 --connect-timeout 10 "${SUMS_URL}?cb=${CACHE_BUST}" -o "${TMP_SUMS}"\nEXPECTED_SHA="$(awk -v file="${BINARY}" '$2 == file {print $1}' "${TMP_SUMS}")"\nACTUAL_SHA="$(sha256_file "${TMP_BINARY}")"\nif [ -z "${EXPECTED_SHA}" ] || [ "${ACTUAL_SHA}" != "${EXPECTED_SHA}" ]; then\n''', '''curl -fL --retry 3 --connect-timeout 10 "${BINARY_URL}?cb=${CACHE_BUST}" -o "${TMP_BINARY}"\ncurl -fsSL --retry 3 --connect-timeout 10 "${WARP_HELPER_URL}?cb=${CACHE_BUST}" -o "${TMP_WARP_HELPER}"\ncurl -fsSL --retry 3 --connect-timeout 10 "${SUMS_URL}?cb=${CACHE_BUST}" -o "${TMP_SUMS}"\nEXPECTED_SHA="$(awk -v file="${BINARY}" '$2 == file {print $1}' "${TMP_SUMS}")"\nACTUAL_SHA="$(sha256_file "${TMP_BINARY}")"\nif [ -z "${EXPECTED_SHA}" ] || [ "${ACTUAL_SHA}" != "${EXPECTED_SHA}" ]; then\n''')
replace("install.sh", '''\texit 6\nfi\n\n# Do not copy directly over a running executable''', '''\texit 6\nfi\nEXPECTED_WARP_SHA="$(awk -v file="${WARP_HELPER_PATH}" '$2 == file {print $1}' "${TMP_SUMS}")"\nACTUAL_WARP_SHA="$(sha256_file "${TMP_WARP_HELPER}")"\nif [ -z "${EXPECTED_WARP_SHA}" ] || [ "${ACTUAL_WARP_SHA}" != "${EXPECTED_WARP_SHA}" ]; then\n  echo "WARP helper SHA256 校验失败，拒绝安装。" >&2\n  exit 7\nfi\n\n# Do not copy directly over a running executable''')
replace("install.sh", '''mv -f "${NEW_BINARY}" "${APP_BIN}"\n\ncat > "${V_CMD}"''', '''mv -f "${NEW_BINARY}" "${APP_BIN}"\ncp "${TMP_WARP_HELPER}" "${WARP_HELPER}"\nchmod 0755 "${WARP_HELPER}"\n\ncat > "${V_CMD}"''')
replace("install.sh", '''APP="/opt/active-ip-sniffer/active-ip-sniffer"\n\nif [ "${1:-}" = "probe" ]; then\n  exec "$APP" "$@"\nfi\n''', '''APP="/opt/active-ip-sniffer/active-ip-sniffer"\nWARP_HELPER="/opt/active-ip-sniffer/warp-helper.sh"\n\nif [ "${1:-}" = "probe" ]; then\n  exec "$APP" "$@"\nfi\nif [ "${1:-}" = "warp" ]; then\n  shift\n  exec "$WARP_HELPER" "${1:-status}"\nfi\n''')
replace("install.sh", '''echo "本地探针：v probe"\necho "Binary: ${APP_BIN}"''', '''echo "本地探针：v probe"\necho "WARP Local Proxy：v warp on（端口 40099）；v warp status；v warp off"\necho "Binary: ${APP_BIN}"''')
replace("install.sh", '''# curl | sudo sh 时 stdin 属于管道；仅在真实交互终端中自动进入向导。\n''', '''if [ "${AIS_INSTALL_WARP:-0}" = "1" ]; then\n  echo "按 AIS_INSTALL_WARP=1 启用 WARP Local Proxy 40099..."\n  "${WARP_HELPER}" on || echo "WARP 启用失败；应用 Auto 模式会自动回落 Direct。" >&2\nfi\n\n# curl | sudo sh 时 stdin 属于管道；仅在真实交互终端中自动进入向导。\n''')

# Windows installer: verified helper + v warp command + optional AIS_INSTALL_WARP=1.
replace("install.ps1", '''$Exe = Join-Path $AppDir "active-ip-sniffer.exe"\n$VCmd = Join-Path $AppDir "v.cmd"\n''', '''$Exe = Join-Path $AppDir "active-ip-sniffer.exe"\n$WarpHelper = Join-Path $AppDir "warp-helper.ps1"\n$VCmd = Join-Path $AppDir "v.cmd"\n''')
replace("install.ps1", '''$sumsUrl = "https://raw.githubusercontent.com/$Repo/$ref/dist/SHA256SUMS`?cb=$cacheBust"\n$tmpBinary = Join-Path $env:TEMP ("active-ip-sniffer-" + [guid]::NewGuid().ToString("N") + ".exe")\n$tmpSums = Join-Path $env:TEMP ("active-ip-sniffer-" + [guid]::NewGuid().ToString("N") + ".sha256")\n''', '''$sumsUrl = "https://raw.githubusercontent.com/$Repo/$ref/dist/SHA256SUMS`?cb=$cacheBust"\n$warpHelperName = "warp-helper.ps1"\n$warpHelperUrl = "https://raw.githubusercontent.com/$Repo/$ref/$warpHelperName`?cb=$cacheBust"\n$tmpBinary = Join-Path $env:TEMP ("active-ip-sniffer-" + [guid]::NewGuid().ToString("N") + ".exe")\n$tmpWarpHelper = Join-Path $env:TEMP ("active-ip-sniffer-warp-" + [guid]::NewGuid().ToString("N") + ".ps1")\n$tmpSums = Join-Path $env:TEMP ("active-ip-sniffer-" + [guid]::NewGuid().ToString("N") + ".sha256")\n''')
replace("install.ps1", '''Invoke-WebRequest -UseBasicParsing -Headers $headers -Uri $binaryUrl -OutFile $tmpBinary\n    Invoke-WebRequest -UseBasicParsing -Headers $headers -Uri $sumsUrl -OutFile $tmpSums\n''', '''Invoke-WebRequest -UseBasicParsing -Headers $headers -Uri $binaryUrl -OutFile $tmpBinary\n    Invoke-WebRequest -UseBasicParsing -Headers $headers -Uri $warpHelperUrl -OutFile $tmpWarpHelper\n    Invoke-WebRequest -UseBasicParsing -Headers $headers -Uri $sumsUrl -OutFile $tmpSums\n''')
replace("install.ps1", '''if (-not $expected) { throw "Checksum for $binaryName not found" }\n    $actual = (Get-FileHash -Algorithm SHA256 -Path $tmpBinary).Hash.ToLowerInvariant()\n    if ($actual -ne $expected) { throw "Binary SHA256 mismatch" }\n\n    Copy-Item -Force $tmpBinary $Exe\n''', '''if (-not $expected) { throw "Checksum for $binaryName not found" }\n    $actual = (Get-FileHash -Algorithm SHA256 -Path $tmpBinary).Hash.ToLowerInvariant()\n    if ($actual -ne $expected) { throw "Binary SHA256 mismatch" }\n    $expectedWarp = $null\n    foreach ($line in Get-Content $tmpSums) {\n        if ($line -match '^([0-9a-fA-F]{64})\\s+(.+)$' -and $Matches[2] -eq $warpHelperName) { $expectedWarp = $Matches[1].ToLowerInvariant(); break }\n    }\n    if (-not $expectedWarp) { throw "Checksum for $warpHelperName not found" }\n    $actualWarp = (Get-FileHash -Algorithm SHA256 -Path $tmpWarpHelper).Hash.ToLowerInvariant()\n    if ($actualWarp -ne $expectedWarp) { throw "WARP helper SHA256 mismatch" }\n\n    Copy-Item -Force $tmpBinary $Exe\n    Copy-Item -Force $tmpWarpHelper $WarpHelper\n''')
replace("install.ps1", '''Remove-Item -Force -ErrorAction SilentlyContinue $tmpBinary, $tmpSums\n''', '''Remove-Item -Force -ErrorAction SilentlyContinue $tmpBinary, $tmpWarpHelper, $tmpSums\n''')
replace("install.ps1", '''if /I "%~1"=="probe" (\n  "%~dp0active-ip-sniffer.exe" %*\n) else (\n  "%~dp0active-ip-sniffer.exe" setup %*\n)\n''', '''if /I "%~1"=="probe" (\n  "%~dp0active-ip-sniffer.exe" %*\n) else if /I "%~1"=="warp" (\n  powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0warp-helper.ps1" "%~2"\n) else (\n  "%~dp0active-ip-sniffer.exe" setup %*\n)\n''')
replace("install.ps1", '''Write-Host "Run v probe to start the localhost probe used by the remote WebUI."\n''', '''Write-Host "Run v probe to start the localhost probe used by the remote WebUI."\nWrite-Host "Optional WARP Local Proxy: v warp on (127.0.0.1:40099), v warp status, v warp off."\n''')
replace("install.ps1", '''Write-Host ""\n\n& $Exe setup\n''', '''Write-Host ""\n\nif ($env:AIS_INSTALL_WARP -eq "1") {\n    & powershell -NoProfile -ExecutionPolicy Bypass -File $WarpHelper on\n}\n\n& $Exe setup\n''')

# Build checksum now covers helper scripts too.
replace(".github/workflows/build.yml", '''sha256sum dist/active-ip-sniffer-linux-* dist/active-ip-sniffer-windows-* > dist/SHA256SUMS''', '''sha256sum dist/active-ip-sniffer-linux-* dist/active-ip-sniffer-windows-* warp-helper.sh warp-helper.ps1 > dist/SHA256SUMS''')

# README: v3.4.1 behavior and commands.
replace("README.md", '''## v3.4：WARP 可选出口 / 用户测速 / 智能 DNS\n''', '''## v3.4.1：探针兼容修复 / Auto WARP 40099\n\n- 修复旧版 `v probe` 对 `/api/egress/check` 返回纯文本 404 时，浏览器错误显示 `Unexpected non-whitespace character after JSON` 的问题。现在会识别非 JSON/404，并明确提示本地探针版本过旧。\n- 出口新增 **Auto（默认）**：在当前检测来源（服务器后端或本地探针）上先验证 `127.0.0.1:40099`，仅当 Cloudflare Trace 返回 `warp=on/plus` 才使用 WARP；否则自动回落 Direct。每个任务只在启动时解析一次出口，不会中途切换。\n- Linux/Windows 安装器附带 WARP helper：`v warp on` 一键安装/配置 Cloudflare One Client Local Proxy 到 `40099`，`v warp status` 检查，`v warp off` 断开。新装时也可使用 `AIS_INSTALL_WARP=1` 自动启用。\n- WARP Local Proxy 仍是可选能力；不支持官方 WARP 客户端的平台会保持 Direct。由于 Cloudflare Local proxy 单请求有超时限制，慢线路上的大文件精测仍建议使用 Direct 做运营商排名。\n\n## v3.4：WARP 可选出口 / 用户测速 / 智能 DNS\n''')
replace_all("README.md", "127.0.0.1:40000", "127.0.0.1:40099")
replace("README.md", '''本地探针：v probe\n''', '''本地探针：v probe\nWARP Local Proxy：v warp on / v warp status / v warp off\n''') if '本地探针：v probe\n' in read('README.md') else None

# Write permanent WARP helpers.
write("warp-helper.sh", r'''#!/bin/sh
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
''')

write("warp-helper.ps1", r'''param(
    [ValidateSet("on", "off", "status", "install", "disconnect")]
    [string]$Action = "status"
)
$ErrorActionPreference = "Stop"
$Port = 40099
$Proxy = "127.0.0.1:$Port"
$TraceUrl = "https://www.cloudflare.com/cdn-cgi/trace"
$Marker = "ActiveIPSniffer managed Local Proxy"
$MdmFile = Join-Path $env:ProgramData "Cloudflare\mdm.xml"

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Ensure-Admin {
    if (Test-Admin) { return }
    $arg = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $Action"
    $proc = Start-Process powershell.exe -Verb RunAs -ArgumentList $arg -Wait -PassThru
    exit $proc.ExitCode
}

function Find-WarpCli {
    $cmd = Get-Command warp-cli.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $paths = @(
        (Join-Path $env:ProgramFiles "Cloudflare\Cloudflare WARP\warp-cli.exe"),
        (Join-Path ${env:ProgramFiles(x86)} "Cloudflare\Cloudflare WARP\warp-cli.exe")
    ) | Where-Object { $_ -and (Test-Path $_) }
    if ($paths.Count -gt 0) { return $paths[0] }
    return $null
}

function Install-Warp {
    $cli = Find-WarpCli
    if ($cli) { return $cli }
    Ensure-Admin
    $tmp = Join-Path $env:TEMP ("cloudflare-warp-" + [guid]::NewGuid().ToString("N") + ".msi")
    try {
        Write-Host "Downloading Cloudflare One Client..."
        Invoke-WebRequest -UseBasicParsing -Uri "https://downloads.cloudflareclient.com/v1/download/windows/ga" -OutFile $tmp
        $p = Start-Process msiexec.exe -ArgumentList "/i `"$tmp`" /qn /norestart" -Wait -PassThru
        if ($p.ExitCode -notin 0, 3010) { throw "Cloudflare WARP MSI install failed: $($p.ExitCode)" }
    }
    finally { Remove-Item -Force -ErrorAction SilentlyContinue $tmp }
    Start-Sleep -Seconds 2
    $cli = Find-WarpCli
    if (-not $cli) { throw "cloudflare-warp installed but warp-cli.exe was not found" }
    return $cli
}

function Invoke-Warp([string]$Cli, [string[]]$Args) {
    & $Cli @Args
    return $LASTEXITCODE
}

function Ensure-Registration([string]$Cli) {
    & $Cli registration show *> $null
    if ($LASTEXITCODE -eq 0) { return }
    & $Cli --accept-tos registration new *> $null
    if ($LASTEXITCODE -ne 0) {
        & $Cli registration new *> $null
        if ($LASTEXITCODE -ne 0) { throw "WARP registration failed" }
    }
}

function Write-MdmFallback([string]$Cli) {
    Ensure-Admin
    if (Test-Path $MdmFile) {
        $existing = Get-Content -Raw $MdmFile
        if ($existing -notmatch [regex]::Escape($Marker)) {
            throw "Existing $MdmFile detected; refusing to overwrite Cloudflare policy. Configure service_mode=proxy and proxy_port=$Port manually."
        }
    }
    New-Item -ItemType Directory -Force -Path (Split-Path $MdmFile) | Out-Null
    @"
<!-- $Marker -->
<dict>
  <key>service_mode</key>
  <string>proxy</string>
  <key>proxy_port</key>
  <integer>$Port</integer>
</dict>
"@ | Set-Content -Encoding UTF8 -Path $MdmFile
    & $Cli mdm refresh *> $null
    if ($LASTEXITCODE -ne 0) {
        $svc = Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'Cloudflare|warp' } | Select-Object -First 1
        if ($svc) { Restart-Service -Force $svc.Name -ErrorAction SilentlyContinue }
    }
}

function Configure-Proxy([string]$Cli) {
    & $Cli tunnel protocol set MASQUE *> $null
    & $Cli mode proxy *> $null
    $modeOk = ($LASTEXITCODE -eq 0)
    if ($modeOk) {
        & $Cli proxy port $Port *> $null
        if ($LASTEXITCODE -eq 0) { return }
        & $Cli proxy port set $Port *> $null
        if ($LASTEXITCODE -eq 0) { return }
    }
    Write-MdmFallback $Cli
}

function Get-ProxyTrace {
    $curl = Get-Command curl.exe -ErrorAction SilentlyContinue
    if (-not $curl) { return $null }
    $text = & $curl.Source -fsS --max-time 8 --socks5-hostname $Proxy $TraceUrl 2>$null
    if ($LASTEXITCODE -ne 0) { return $null }
    return ($text -join "`n")
}

function Test-Proxy {
    $trace = Get-ProxyTrace
    return ($trace -match '(?m)^warp=(on|plus)$')
}

function Show-Status {
    $cli = Find-WarpCli
    if ($cli) {
        & $cli status 2>$null
        & $cli settings 2>$null | Select-String -Pattern 'mode|proxy|protocol'
    } else { Write-Host "WARP client: not installed" }
    $trace = Get-ProxyTrace
    if ($trace -and $trace -match '(?m)^warp=(on|plus)$') {
        Write-Host "WARP Local Proxy: READY $Proxy"
        $trace -split "`n" | Where-Object { $_ -match '^(ip|warp|colo)=' }
        return $true
    }
    Write-Host "WARP Local Proxy: unavailable $Proxy; Active IP Sniffer Auto will use Direct"
    return $false
}

switch ($Action) {
    { $_ -in @("on", "install") } {
        Ensure-Admin
        $cli = Install-Warp
        Ensure-Registration $cli
        Configure-Proxy $cli
        & $cli connect *> $null
        if ($LASTEXITCODE -ne 0) { throw "warp-cli connect failed" }
        for ($i=0; $i -lt 15; $i++) {
            if (Test-Proxy) { [void](Show-Status); exit 0 }
            Start-Sleep -Seconds 1
        }
        throw "$Proxy did not pass warp=on/plus verification; Active IP Sniffer Auto will use Direct"
    }
    { $_ -in @("off", "disconnect") } {
        Ensure-Admin
        $cli = Find-WarpCli
        if ($cli) { & $cli disconnect *> $null }
        Write-Host "WARP disconnected; Active IP Sniffer Auto will use Direct"
    }
    "status" { if (Show-Status) { exit 0 } else { exit 1 } }
}
''')

print("v3.4.1 patch applied")

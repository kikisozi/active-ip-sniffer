package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	publicCandidateLimit  = 20
	publicSubmissionLimit = 500
	publicPrecisionMB     = 20
)

type publicCandidate struct {
	IP   string     `json:"ip"`
	Port int        `json:"port"`
	Meta ipMetadata `json:"meta,omitempty"`
}

type publicSubmission struct {
	ID          string          `json:"id"`
	SubmittedAt time.Time       `json:"submitted_at"`
	ClientIP    string          `json:"client_ip"`
	ClientMeta  ipMetadata      `json:"client_meta"`
	EgressMode  string          `json:"egress_mode"`
	ProbeEgress egressInfo      `json:"probe_egress"`
	Results     []cfSpeedResult `json:"results"`
}

type smartDNSCandidate struct {
	IP          string  `json:"ip"`
	Port        int     `json:"port"`
	Samples     int     `json:"samples"`
	MedianPeak  float64 `json:"median_peak_mbps"`
	AveragePeak float64 `json:"average_peak_mbps"`
	MedianAvg   float64 `json:"median_average_mbps"`
}

type smartDNSLinePlan struct {
	Line       string              `json:"line"`
	Submitters int                 `json:"submitters"`
	Candidates []smartDNSCandidate `json:"candidates"`
}

type publicStoreState struct {
	Candidates  []publicCandidate  `json:"candidates"`
	Submissions []publicSubmission `json:"submissions"`
}

type publicBenchmarkStore struct {
	mu       sync.RWMutex
	path     string
	state    publicStoreState
	lastPost map[string]time.Time
}

func newPublicBenchmarkStore(dataDir string) *publicBenchmarkStore {
	store := &publicBenchmarkStore{path: filepath.Join(dataDir, "public-benchmark.json"), lastPost: make(map[string]time.Time)}
	data, err := os.ReadFile(store.path)
	if err == nil {
		_ = json.Unmarshal(data, &store.state)
	}
	if len(store.state.Candidates) > publicCandidateLimit {
		store.state.Candidates = store.state.Candidates[:publicCandidateLimit]
	}
	if len(store.state.Submissions) > publicSubmissionLimit {
		store.state.Submissions = store.state.Submissions[len(store.state.Submissions)-publicSubmissionLimit:]
	}
	return store
}

func (s *publicBenchmarkStore) persistLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o750); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return err
	}
	_ = os.Chmod(tmp, 0o600)
	return os.Rename(tmp, s.path)
}

func (s *publicBenchmarkStore) publish(items []publicCandidate) error {
	seen := make(map[string]struct{})
	clean := make([]publicCandidate, 0, len(items))
	for _, item := range items {
		ip := net.ParseIP(strings.TrimSpace(item.IP))
		if ip == nil || ip.To4() == nil {
			continue
		}
		if !validCFHTTPSPort(item.Port) {
			item.Port = 443
		}
		item.IP = ip.To4().String()
		key := fmt.Sprintf("%s:%d", item.IP, item.Port)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		if item.Meta.IP == "" {
			item.Meta.IP = item.IP
		}
		clean = append(clean, item)
		if len(clean) >= publicCandidateLimit {
			break
		}
	}
	if len(clean) == 0 {
		return errors.New("no valid public benchmark candidates")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.Candidates = clean
	return s.persistLocked()
}

func (s *publicBenchmarkStore) candidates() []publicCandidate {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]publicCandidate(nil), s.state.Candidates...)
}

func (s *publicBenchmarkStore) submissions() []publicSubmission {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := append([]publicSubmission(nil), s.state.Submissions...)
	for i := range result {
		result[i].Results = append([]cfSpeedResult(nil), result[i].Results...)
	}
	sort.SliceStable(result, func(i, j int) bool { return result[i].SubmittedAt.After(result[j].SubmittedAt) })
	return result
}

func classifyCarrier(meta ipMetadata) string {
	text := strings.ToLower(strings.Join([]string{meta.ISP, meta.Org, meta.IDC}, " "))
	switch {
	case strings.Contains(text, "telecom"), strings.Contains(text, "chinanet"), strings.Contains(text, "ctg"), strings.Contains(text, "电信"):
		return "电信"
	case strings.Contains(text, "unicom"), strings.Contains(text, "china169"), strings.Contains(text, "cnc"), strings.Contains(text, "联通"):
		return "联通"
	case strings.Contains(text, "mobile"), strings.Contains(text, "cmi"), strings.Contains(text, "cmin2"), strings.Contains(text, "移动"):
		return "移动"
	default:
		return "其他"
	}
}

func medianFloat(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	copyValues := append([]float64(nil), values...)
	sort.Float64s(copyValues)
	mid := len(copyValues) / 2
	if len(copyValues)%2 == 1 {
		return roundFloat(copyValues[mid], 1)
	}
	return roundFloat((copyValues[mid-1]+copyValues[mid])/2, 1)
}

func (s *publicBenchmarkStore) smartPlan(topN int) []smartDNSLinePlan {
	if topN < 1 {
		topN = 3
	}
	if topN > 5 {
		topN = 5
	}
	type metricSet struct {
		peaks []float64
		avgs  []float64
		port  int
	}
	type lineAggregate struct {
		submitters map[string]struct{}
		metrics    map[string]*metricSet
	}
	aggregates := map[string]*lineAggregate{}
	ensureLine := func(line string) *lineAggregate {
		if aggregates[line] == nil {
			aggregates[line] = &lineAggregate{submitters: make(map[string]struct{}), metrics: make(map[string]*metricSet)}
		}
		return aggregates[line]
	}
	cutoff := time.Now().Add(-7 * 24 * time.Hour)
	s.mu.RLock()
	for _, submission := range s.state.Submissions {
		if submission.SubmittedAt.Before(cutoff) {
			continue
		}
		mode := strings.ToLower(strings.TrimSpace(submission.EgressMode))
		warp := strings.ToLower(strings.TrimSpace(submission.ProbeEgress.WARP))
		if (mode != "" && mode != "direct") || warp == "on" || warp == "plus" {
			continue
		}
		lines := []string{"默认"}
		carrier := classifyCarrier(submission.ClientMeta)
		if carrier != "其他" {
			lines = append(lines, carrier)
		}
		for _, line := range lines {
			agg := ensureLine(line)
			agg.submitters[submission.ClientIP] = struct{}{}
			for _, result := range submission.Results {
				if result.Status != "ok" || result.PeakMbps <= 0 {
					continue
				}
				key := result.IP
				metrics := agg.metrics[key]
				if metrics == nil {
					metrics = &metricSet{port: result.Port}
					agg.metrics[key] = metrics
				}
				metrics.peaks = append(metrics.peaks, result.PeakMbps)
				metrics.avgs = append(metrics.avgs, result.AverageMbps)
			}
		}
	}
	s.mu.RUnlock()

	order := []string{"电信", "联通", "移动", "默认"}
	plans := make([]smartDNSLinePlan, 0, len(order))
	for _, line := range order {
		agg := aggregates[line]
		if agg == nil {
			continue
		}
		candidates := make([]smartDNSCandidate, 0, len(agg.metrics))
		for ip, metrics := range agg.metrics {
			var totalPeak float64
			for _, value := range metrics.peaks {
				totalPeak += value
			}
			candidates = append(candidates, smartDNSCandidate{IP: ip, Port: metrics.port, Samples: len(metrics.peaks), MedianPeak: medianFloat(metrics.peaks), AveragePeak: roundFloat(totalPeak/float64(len(metrics.peaks)), 1), MedianAvg: medianFloat(metrics.avgs)})
		}
		sort.SliceStable(candidates, func(i, j int) bool {
			if candidates[i].MedianPeak != candidates[j].MedianPeak {
				return candidates[i].MedianPeak > candidates[j].MedianPeak
			}
			if candidates[i].Samples != candidates[j].Samples {
				return candidates[i].Samples > candidates[j].Samples
			}
			if candidates[i].MedianAvg != candidates[j].MedianAvg {
				return candidates[i].MedianAvg > candidates[j].MedianAvg
			}
			return candidates[i].IP < candidates[j].IP
		})
		if len(candidates) > topN {
			candidates = candidates[:topN]
		}
		plans = append(plans, smartDNSLinePlan{Line: line, Submitters: len(agg.submitters), Candidates: candidates})
	}
	return plans
}

func (s *publicBenchmarkStore) addSubmission(remoteIP string, submission publicSubmission) error {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if last := s.lastPost[remoteIP]; !last.IsZero() && now.Sub(last) < 30*time.Second {
		return errors.New("submission rate limit: wait 30 seconds")
	}
	s.lastPost[remoteIP] = now
	submission.ID = newJobID()
	submission.SubmittedAt = now
	submission.ClientIP = remoteIP
	s.state.Submissions = append(s.state.Submissions, submission)
	if len(s.state.Submissions) > publicSubmissionLimit {
		s.state.Submissions = s.state.Submissions[len(s.state.Submissions)-publicSubmissionLimit:]
	}
	return s.persistLocked()
}

func (a *app) handlePublicPublish(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 256_000)
	defer r.Body.Close()
	var request struct {
		Items []publicCandidate `json:"items"`
	}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request: " + err.Error()})
		return
	}
	if err := a.public.publish(request.Items); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "count": len(a.public.candidates())})
}

func (a *app) handlePublicSubmissions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": a.public.submissions(), "candidates": a.public.candidates()})
}

func (a *app) handleSmartDNSPlan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	topN := 3
	if value := strings.TrimSpace(r.URL.Query().Get("top")); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil {
			topN = parsed
		}
	}
	if topN < 1 {
		topN = 1
	}
	if topN > 5 {
		topN = 5
	}
	writeJSON(w, http.StatusOK, map[string]any{"window_days": 7, "top_n": topN, "lines": a.public.smartPlan(topN)})
}

func (a *app) publicRoutes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		_, _ = w.Write([]byte(publicIndexHTML))
	})
	mux.HandleFunc("/api/candidates", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": a.public.candidates(), "precision_mb": publicPrecisionMB, "quick_mb": 1, "quick_timeout_s": 2, "app_version": appVersion, "probe_port": defaultProbePort, "default_egress_mode": "auto", "warp_proxy": defaultWARPProxy})
	})
	mux.HandleFunc("/api/submit", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 256_000)
		defer r.Body.Close()
		var request struct {
			EgressMode  string          `json:"egress_mode"`
			ProbeEgress egressInfo      `json:"probe_egress"`
			Results     []cfSpeedResult `json:"results"`
		}
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&request); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request: " + err.Error()})
			return
		}
		allowed := make(map[string]struct{})
		for _, candidate := range a.public.candidates() {
			allowed[fmt.Sprintf("%s:%d", candidate.IP, candidate.Port)] = struct{}{}
		}
		clean := make([]cfSpeedResult, 0, 5)
		for _, result := range request.Results {
			if result.Status != "ok" || result.HTTPStatus != http.StatusOK || result.DownloadedBytes < int64(publicPrecisionMB)*1_000_000 || result.PeakMbps <= 0 || result.PeakMbps > 100_000 || result.AverageMbps < 0 || result.AverageMbps > 100_000 {
				continue
			}
			if _, ok := allowed[fmt.Sprintf("%s:%d", result.IP, result.Port)]; !ok {
				continue
			}
			result.Meta = ipMetadata{}
			result.Error = ""
			result.FailureStage = ""
			clean = append(clean, result)
		}
		clean = rankCFResults(clean)
		if len(clean) > 5 {
			clean = clean[:5]
		}
		if len(clean) == 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no valid benchmark result to submit"})
			return
		}
		remoteIP := requestClientIP(r)
		metaCtx, cancel := context.WithTimeout(r.Context(), 6*time.Second)
		clientMeta := lookupIPMetadata(metaCtx, remoteIP)
		cancel()
		mode := strings.ToLower(strings.TrimSpace(request.EgressMode))
		if mode != "warp" {
			mode = "direct"
		}
		if err := a.public.addSubmission(remoteIP, publicSubmission{ClientMeta: clientMeta, EgressMode: mode, ProbeEgress: request.ProbeEgress, Results: clean}); err != nil {
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "top": clean})
	})
	return mux
}

const publicIndexHTML = `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>优选 IP 用户测速</title><style>
body{margin:0;background:#f4f6f9;color:#18202b;font:14px/1.5 system-ui,"Segoe UI","Microsoft YaHei",sans-serif}.wrap{max-width:900px;margin:auto;padding:18px}.card{background:#fff;border:1px solid #dfe4eb;border-radius:10px;margin-bottom:14px;padding:16px}.row{display:flex;gap:9px;align-items:center;flex-wrap:wrap}input,select,button{font:inherit;padding:9px 11px;border:1px solid #cbd3dd;border-radius:7px}button{font-weight:700;cursor:pointer;background:#2563eb;color:white;border-color:#2563eb}button:disabled{opacity:.45}.note{font-size:12px;color:#667085}.good{color:#087f5b}.bad{color:#c24141}.bar{height:9px;background:#e8edf3;border-radius:99px;overflow:hidden}.fill{height:100%;background:#2563eb;width:0}table{width:100%;border-collapse:collapse}th,td{padding:8px;border-bottom:1px solid #edf0f4;text-align:left}</style></head><body><div class="wrap">
<div class="card"><h2>优选 IP 用户本地测速</h2><p>该页面把候选 IP 交给你电脑上的 <code>v probe</code>，真正的 TCP/TLS/下载流量从你的网络出口发出。浏览器本身不能把 TLS 的 SNI/Host 强制连接到任意候选 IP，因此准确模式需要本地探针。</p><div class="row"><input id="token" type="password" placeholder="Local probe token" style="min-width:300px"><select id="egress"><option value="auto">Auto（优先 WARP）</option><option value="direct">Direct 本地出口</option><option value="warp">WARP Local Proxy</option></select><input id="proxy" value="127.0.0.1:40099" placeholder="WARP SOCKS5 地址"><button id="connect">连接探针</button></div><p id="state" class="note">先在本机执行 <code>v probe</code>，再粘贴 Token。</p></div>
<div class="card"><div class="row"><button id="start" disabled>开始本地测速并提交 Top 5</button><span id="progress" class="note">候选加载中…</span></div><div class="bar"><div id="fill" class="fill"></div></div></div>
<div class="card"><h3>本次 Top 5</h3><table><thead><tr><th>#</th><th>IP</th><th>峰值</th><th>平均</th><th>TTFB</th></tr></thead><tbody id="rows"></tbody></table></div>
</div><script>
const $=s=>document.querySelector(s),probe='http://127.0.0.1:18767';let token='',candidates=[],job='',probeEgress={},resolvedMode='direct',probeVersion='';
async function pfetch(path,init={}){const h=new Headers(init.headers||{});h.set('X-Probe-Token',token);return fetch(probe+path,{...init,headers:h})}
async function readJSON(r,label){const text=await r.text();let x={};if(text.trim()){try{x=JSON.parse(text)}catch(e){const raw=text.trim().replace(/\s+/g,' ').slice(0,180);if(r.status===404)throw new Error(label+'接口不存在，本机 v probe 版本过旧；请重新运行安装命令更新并重启 v probe');throw new Error(label+'返回非 JSON（HTTP '+r.status+'）：'+(raw||'<empty>'))}}if(!r.ok)throw new Error(x.error||label+'失败（HTTP '+r.status+'）');return x}
fetch('/api/candidates').then(r=>r.json()).then(x=>{candidates=x.items||[];$('#progress').textContent=candidates.length?'已发布 '+candidates.length+' 个候选；精测 '+(x.precision_mb||20)+' MB':'当前没有发布候选';$('#start').dataset.mb=x.precision_mb||20}).catch(()=>$('#progress').textContent='候选读取失败');
$('#connect').onclick=async()=>{token=$('#token').value.trim();if(token.length<16)return;const body={egress_mode:$('#egress').value,warp_proxy:$('#proxy').value.trim()};try{const ir=await pfetch('/api/info'),pi=await readJSON(ir,'本地探针信息');probeVersion=pi.version||'';const r=await pfetch('/api/egress/check',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}),x=await readJSON(r,'出口验证');probeEgress=x.egress||{};resolvedMode=x.mode||'direct';$('#state').className='note good';$('#state').textContent='探针 v'+(probeVersion||'?')+' 已连接，'+(x.requested_mode||body.egress_mode)+' → '+resolvedMode+'，当前测速出口 '+(probeEgress.ip||'?')+' · '+(probeEgress.warp||'unknown')+' · '+(probeEgress.colo||'')+(x.auto_fallback?' · WARP 不可用，已自动 Direct':'');$('#start').disabled=!candidates.length}catch(e){$('#state').className='note bad';$('#state').textContent='连接失败：'+e.message;$('#start').disabled=true}};
$('#start').onclick=async()=>{if(!candidates.length)return;$('#start').disabled=true;const body={targets:candidates.map(x=>x.ip+':'+x.port),port:443,timeout:1.5,workers:32,quick_workers:4,precision_mb:Number($('#start').dataset.mb||20),egress_mode:$('#egress').value,warp_proxy:$('#proxy').value.trim(),metadata:Object.fromEntries(candidates.filter(x=>x.meta).map(x=>[x.ip,x.meta]))};try{const r=await pfetch('/api/cf-speed/start',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}),x=await readJSON(r,'测速启动');resolvedMode=x.egress_mode||resolvedMode;job=x.id;poll()}catch(e){$('#progress').textContent=e.message;$('#start').disabled=false}};
async function poll(){const r=await pfetch('/api/cf-speed/job?id='+encodeURIComponent(job)),x=await readJSON(r,'测速任务');const den=x.phase==='quick'?(x.prefilter_done||1):x.phase==='download'?(x.selected||1):(x.input_total||1),done=x.phase==='quick'?(x.quick_done||0):x.phase==='download'?(x.download_done||0):(x.prefilter_done||0),pct=x.status==='complete'?100:Math.min(99,Math.round(done*100/den));$('#fill').style.width=pct+'%';$('#progress').textContent=(x.message||x.status)+' · '+pct+'%';if(x.status==='complete'){const top=(x.results||[]).filter(y=>y.status==='ok').slice(0,5);$('#rows').innerHTML=top.map((y,i)=>'<tr><td>'+(i+1)+'</td><td>'+y.ip+':'+y.port+'</td><td>'+y.peak_mbps+' Mbps</td><td>'+y.average_mbps+' Mbps</td><td>'+y.ttfb_ms+' ms</td></tr>').join('');const s=await fetch('/api/submit',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({egress_mode:resolvedMode,probe_egress:probeEgress,results:top})}),z=await s.json();$('#progress').textContent=s.ok?'测速完成，Top 5 已提交':'测速完成，但提交失败：'+(z.error||'未知错误');$('#start').disabled=false;return}if(['failed','cancelled'].includes(x.status)){ $('#progress').textContent=x.message||x.status;$('#start').disabled=false;return}setTimeout(poll,700)}
</script></body></html>`

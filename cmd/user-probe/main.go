package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	version                = "3.5.1"
	defaultPort            = 18767
	maxCandidates          = 32
	quickBytes       int64 = 1_000_000
	quickTimeout           = 2 * time.Second
	precisionBytes   int64 = 30_000_000
	precisionTimeout       = 5 * time.Second
	windowDuration         = 250 * time.Millisecond
)

type endpoint struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

type result struct {
	Rank            int     `json:"rank"`
	IP              string  `json:"ip"`
	Port            int     `json:"port"`
	TCPMS           float64 `json:"tcp_ms"`
	TLSHandshakeMS  float64 `json:"tls_handshake_ms"`
	TLSCompleteMS   float64 `json:"tls_complete_ms"`
	TTFBMS          float64 `json:"ttfb_ms"`
	TotalSeconds    float64 `json:"total_seconds"`
	TransferSeconds float64 `json:"transfer_seconds"`
	AverageMbps     float64 `json:"average_mbps"`
	EffectiveMbps   float64 `json:"effective_mbps"`
	PeakMbps        float64 `json:"peak_mbps"`
	DownloadedBytes int64   `json:"downloaded_bytes"`
	HTTPStatus      int     `json:"http_status"`
	Status          string  `json:"status"`
	FailureStage    string  `json:"failure_stage,omitempty"`
	Error           string  `json:"error,omitempty"`
}

type traceTimes struct {
	connectStart time.Time
	connectDone  time.Time
	tlsStart     time.Time
	tlsDone      time.Time
	firstByte    time.Time
}

type job struct {
	id        string
	startedAt time.Time
	ctx       context.Context
	cancel    context.CancelFunc

	mu       sync.RWMutex
	status   string
	phase    string
	message  string
	selected int
	results  []result

	quickDone    atomic.Uint64
	quickPassed  atomic.Uint64
	downloadDone atomic.Uint64
}

func (j *job) snapshot(total int) map[string]any {
	j.mu.RLock()
	status, phase, message, selected := j.status, j.phase, j.message, j.selected
	results := append([]result(nil), j.results...)
	j.mu.RUnlock()
	return map[string]any{
		"id": j.id, "status": status, "phase": phase, "message": message,
		"input_total": total, "quick_done": j.quickDone.Load(), "quick_passed": j.quickPassed.Load(),
		"selected": selected, "download_done": j.downloadDone.Load(), "results": results,
		"download_bytes": precisionBytes, "precision_timeout_s": precisionTimeout.Seconds(),
	}
}

func (j *job) setState(status, phase, message string) {
	j.mu.Lock()
	j.status, j.phase, j.message = status, phase, message
	j.mu.Unlock()
}

func (j *job) addResult(value result) {
	j.mu.Lock()
	j.results = rankResults(append(j.results, value))
	if len(j.results) > 5 {
		j.results = j.results[:5]
	}
	j.mu.Unlock()
}

type jobStore struct {
	sync.RWMutex
	jobs   map[string]*job
	totals map[string]int
}

var jobs = &jobStore{jobs: make(map[string]*job), totals: make(map[string]int)}

func generateHex(bytes int) string {
	buf := make([]byte, bytes)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return hex.EncodeToString(buf)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func tokenMatches(got, want string) bool {
	return len(got) == len(want) && len(want) >= 16 && subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func authMiddleware(token string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Probe-Token")
		w.Header().Set("Access-Control-Max-Age", "600")
		if strings.EqualFold(r.Header.Get("Access-Control-Request-Private-Network"), "true") {
			w.Header().Set("Access-Control-Allow-Private-Network", "true")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if !tokenMatches(r.Header.Get("X-Probe-Token"), token) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid local probe token"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func parseEndpoint(raw string, defaultPort int) (endpoint, error) {
	raw = strings.TrimSpace(raw)
	if ip := net.ParseIP(raw); ip != nil && ip.To4() != nil {
		return endpoint{IP: ip.To4().String(), Port: defaultPort}, nil
	}
	host, portText, err := net.SplitHostPort(raw)
	if err != nil {
		return endpoint{}, fmt.Errorf("invalid candidate %q", raw)
	}
	ip := net.ParseIP(host)
	port, portErr := strconv.Atoi(portText)
	if ip == nil || ip.To4() == nil || portErr != nil || port < 1 || port > 65535 {
		return endpoint{}, fmt.Errorf("invalid candidate %q", raw)
	}
	return endpoint{IP: ip.To4().String(), Port: port}, nil
}

func round(value float64, digits int) float64 {
	p := math.Pow10(digits)
	return math.Round(value*p) / p
}

func mbps(bytes int64, d time.Duration) float64 {
	if bytes <= 0 || d <= 0 {
		return 0
	}
	return float64(bytes*8) / d.Seconds() / 1_000_000
}

func fillTimings(out *result, requestStart time.Time, t *traceTimes) {
	if !t.connectStart.IsZero() && !t.connectDone.IsZero() {
		out.TCPMS = round(float64(t.connectDone.Sub(t.connectStart))/float64(time.Millisecond), 1)
	}
	if !t.tlsStart.IsZero() && !t.tlsDone.IsZero() {
		out.TLSHandshakeMS = round(float64(t.tlsDone.Sub(t.tlsStart))/float64(time.Millisecond), 1)
		out.TLSCompleteMS = round(float64(t.tlsDone.Sub(requestStart))/float64(time.Millisecond), 1)
	}
	if !t.firstByte.IsZero() {
		out.TTFBMS = round(float64(t.firstByte.Sub(requestStart))/float64(time.Millisecond), 1)
	}
}

func measure(parent context.Context, ep endpoint, bytesWanted int64, transferLimit time.Duration) result {
	out := result{IP: ep.IP, Port: ep.Port, Status: "failed"}
	requestStart := time.Now()
	times := &traceTimes{}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(dialCtx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 4 * time.Second, KeepAlive: 15 * time.Second}).DialContext(dialCtx, "tcp", net.JoinHostPort(ep.IP, strconv.Itoa(ep.Port)))
		},
		TLSClientConfig:   &tls.Config{ServerName: "speed.cloudflare.com", MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}},
		ForceAttemptHTTP2: false, DisableCompression: true, MaxIdleConns: 1, IdleConnTimeout: 3 * time.Second,
		TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 6 * time.Second,
	}
	defer transport.CloseIdleConnections()
	host := "speed.cloudflare.com"
	if ep.Port != 443 {
		host += ":" + strconv.Itoa(ep.Port)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host+"/__down?bytes="+strconv.FormatInt(bytesWanted, 10), nil)
	if err != nil {
		out.FailureStage, out.Error = "request", err.Error()
		return out
	}
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("User-Agent", "Active-IP-User-Probe/"+version)
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{
		ConnectStart: func(_, _ string) { times.connectStart = time.Now() }, ConnectDone: func(_, _ string, _ error) { times.connectDone = time.Now() },
		TLSHandshakeStart: func() { times.tlsStart = time.Now() }, TLSHandshakeDone: func(_ tls.ConnectionState, _ error) { times.tlsDone = time.Now() },
		GotFirstResponseByte: func() { times.firstByte = time.Now() },
	}))
	resp, err := (&http.Client{Transport: transport}).Do(req)
	if err != nil {
		out.FailureStage, out.Error = "connect", err.Error()
		fillTimings(&out, requestStart, times)
		return out
	}
	defer resp.Body.Close()
	out.HTTPStatus = resp.StatusCode
	fillTimings(&out, requestStart, times)
	if resp.StatusCode != http.StatusOK {
		out.FailureStage, out.Error = "http", fmt.Sprintf("HTTP %d", resp.StatusCode)
		return out
	}

	bodyStart := time.Now()
	var timedOut atomic.Bool
	timer := time.AfterFunc(transferLimit, func() { timedOut.Store(true); cancel() })
	defer timer.Stop()
	windowStart := bodyStart
	buffer := make([]byte, 64*1024)
	var total, windowBytes int64
	var peak float64
	for total < bytesWanted {
		n, readErr := resp.Body.Read(buffer)
		if n > 0 {
			total += int64(n)
			windowBytes += int64(n)
			now := time.Now()
			if elapsed := now.Sub(windowStart); elapsed >= windowDuration {
				peak = math.Max(peak, mbps(windowBytes, elapsed))
				windowStart, windowBytes = now, 0
			}
		}
		if readErr != nil {
			if !errors.Is(readErr, io.EOF) {
				if timedOut.Load() {
					out.FailureStage, out.Error = "download_timeout", fmt.Sprintf("download exceeded %.0f seconds", transferLimit.Seconds())
				} else {
					out.FailureStage, out.Error = "download", readErr.Error()
				}
			}
			break
		}
	}
	finish := time.Now()
	elapsed := finish.Sub(bodyStart)
	if windowBytes > 0 {
		peak = math.Max(peak, mbps(windowBytes, finish.Sub(windowStart)))
	}
	out.DownloadedBytes = total
	out.TransferSeconds = round(elapsed.Seconds(), 3)
	out.TotalSeconds = round(finish.Sub(requestStart).Seconds(), 3)
	out.PeakMbps = round(peak, 1)
	out.AverageMbps = round(mbps(total, elapsed), 1)
	out.EffectiveMbps = round(mbps(total, finish.Sub(requestStart)), 1)
	if (timedOut.Load() || elapsed > transferLimit) && out.Error == "" && (total < bytesWanted || elapsed > transferLimit) {
		out.FailureStage, out.Error = "download_timeout", fmt.Sprintf("download exceeded %.0f seconds", transferLimit.Seconds())
	}
	if out.Error == "" && total == bytesWanted && elapsed <= transferLimit {
		out.Status = "ok"
	} else if out.Error == "" {
		out.FailureStage, out.Error = "download", fmt.Sprintf("downloaded %d bytes, expected %d", total, bytesWanted)
	}
	return out
}

func rankResults(values []result) []result {
	values = append([]result(nil), values...)
	sort.SliceStable(values, func(i, j int) bool {
		if values[i].Status != values[j].Status {
			return values[i].Status == "ok"
		}
		if values[i].PeakMbps != values[j].PeakMbps {
			return values[i].PeakMbps > values[j].PeakMbps
		}
		if values[i].AverageMbps != values[j].AverageMbps {
			return values[i].AverageMbps > values[j].AverageMbps
		}
		return values[i].TTFBMS < values[j].TTFBMS
	})
	for i := range values {
		values[i].Rank = i + 1
	}
	return values
}

func execute(j *job, endpoints []endpoint) {
	j.setState("running", "quick", "1 MB / 2s quick screening")
	tasks := make(chan endpoint)
	passed := make(chan endpoint, len(endpoints))
	var wg sync.WaitGroup
	workers := 4
	if len(endpoints) < workers {
		workers = len(endpoints)
	}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ep := range tasks {
				ctx, cancel := context.WithTimeout(j.ctx, quickTimeout)
				value := measure(ctx, ep, quickBytes, quickTimeout)
				cancel()
				j.quickDone.Add(1)
				if value.Status == "ok" {
					j.quickPassed.Add(1)
					passed <- ep
				}
			}
		}()
	}
	go func() {
		defer close(tasks)
		for _, ep := range endpoints {
			select {
			case tasks <- ep:
			case <-j.ctx.Done():
				return
			}
		}
	}()
	wg.Wait()
	close(passed)
	survivors := make([]endpoint, 0, len(endpoints))
	for ep := range passed {
		survivors = append(survivors, ep)
	}
	if j.ctx.Err() != nil {
		j.setState("cancelled", "cancelled", "benchmark cancelled")
		return
	}
	j.mu.Lock()
	j.selected = len(survivors)
	j.mu.Unlock()
	if len(survivors) == 0 {
		j.setState("complete", "complete", "no candidate survived 1 MB / 2s screening")
		return
	}
	j.setState("running", "download", fmt.Sprintf("%d candidate(s) survived; 30 MB / 5s precision benchmark", len(survivors)))
	for _, ep := range survivors {
		if j.ctx.Err() != nil {
			j.setState("cancelled", "cancelled", "benchmark cancelled")
			return
		}
		ctx, cancel := context.WithTimeout(j.ctx, 12*time.Second)
		value := measure(ctx, ep, precisionBytes, precisionTimeout)
		cancel()
		j.downloadDone.Add(1)
		if value.Status == "ok" {
			j.addResult(value)
		}
	}
	j.setState("complete", "complete", "user benchmark complete")
}

func cloudflareTrace(ctx context.Context) map[string]string {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.cloudflare.com/cdn-cgi/trace", nil)
	transport := &http.Transport{Proxy: nil, ForceAttemptHTTP2: false, DisableCompression: true, TLSHandshakeTimeout: 4 * time.Second, ResponseHeaderTimeout: 4 * time.Second}
	defer transport.CloseIdleConnections()
	resp, err := (&http.Client{Transport: transport, Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return map[string]string{}
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
	values := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			values[k] = v
		}
	}
	return values
}

func routes(token string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/info", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"version": version, "role": "user-probe", "precision_mb": 30, "precision_timeout_s": 5})
	})
	mux.HandleFunc("/api/network-info", func(w http.ResponseWriter, r *http.Request) {
		values := cloudflareTrace(r.Context())
		writeJSON(w, http.StatusOK, map[string]any{"role": "user-probe", "egress": map[string]string{"ip": values["ip"], "warp": values["warp"], "colo": values["colo"]}})
	})
	mux.HandleFunc("/api/cf-speed/start", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		var request struct {
			Targets []string `json:"targets"`
			Port    int      `json:"port"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&request); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		if request.Port == 0 {
			request.Port = 443
		}
		if len(request.Targets) == 0 || len(request.Targets) > maxCandidates {
			writeJSON(w, 400, map[string]string{"error": "candidate count must be 1..32"})
			return
		}
		endpoints := make([]endpoint, 0, len(request.Targets))
		seen := map[string]struct{}{}
		for _, raw := range request.Targets {
			ep, err := parseEndpoint(raw, request.Port)
			if err != nil {
				continue
			}
			key := fmt.Sprintf("%s:%d", ep.IP, ep.Port)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			endpoints = append(endpoints, ep)
		}
		if len(endpoints) == 0 {
			writeJSON(w, 400, map[string]string{"error": "no valid IPv4 candidate"})
			return
		}
		ctx, cancel := context.WithCancel(context.Background())
		id := generateHex(12)
		j := &job{id: id, startedAt: time.Now(), ctx: ctx, cancel: cancel, status: "queued", phase: "queued"}
		jobs.Lock()
		jobs.jobs[id] = j
		jobs.totals[id] = len(endpoints)
		jobs.Unlock()
		go execute(j, endpoints)
		writeJSON(w, http.StatusAccepted, map[string]any{"id": id, "input_total": len(endpoints), "precision_mb": 30, "precision_timeout_s": 5, "egress_mode": "direct"})
	})
	mux.HandleFunc("/api/cf-speed/job", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		jobs.RLock()
		j, ok := jobs.jobs[id]
		total := jobs.totals[id]
		jobs.RUnlock()
		if !ok {
			writeJSON(w, 404, map[string]string{"error": "job not found"})
			return
		}
		writeJSON(w, 200, j.snapshot(total))
	})
	mux.HandleFunc("/api/cf-speed/cancel", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		jobs.RLock()
		j, ok := jobs.jobs[id]
		jobs.RUnlock()
		if !ok {
			writeJSON(w, 404, map[string]string{"error": "job not found"})
			return
		}
		j.cancel()
		j.setState("cancelled", "cancelled", "benchmark cancelled")
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
	return authMiddleware(token, mux)
}

func listenLoopback(preferred int) (net.Listener, int, error) {
	if preferred < 1 {
		preferred = defaultPort
	}
	for port := preferred; port < preferred+40 && port <= 65535; port++ {
		listener, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err == nil {
			return listener, port, nil
		}
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, 0, err
	}
	return listener, listener.Addr().(*net.TCPAddr).Port, nil
}

func openBrowser(target string) error {
	var command *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		command = exec.Command("rundll32", "url.dll,FileProtocolHandler", target)
	case "darwin":
		command = exec.Command("open", target)
	default:
		if path, err := exec.LookPath("termux-open-url"); err == nil {
			command = exec.Command(path, target)
		} else if path, err := exec.LookPath("xdg-open"); err == nil {
			command = exec.Command(path, target)
		} else {
			return errors.New("no browser opener found")
		}
	}
	return command.Start()
}

func main() {
	webURL := ""
	preferredPort := defaultPort
	for i := 1; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "--web-url":
			if i+1 < len(os.Args) {
				i++
				webURL = os.Args[i]
			}
		case "--port":
			if i+1 < len(os.Args) {
				i++
				preferredPort, _ = strconv.Atoi(os.Args[i])
			}
		}
	}
	if strings.TrimSpace(webURL) == "" {
		fmt.Fprintln(os.Stderr, "Usage: active-ip-user-probe --web-url http://server:18768")
		os.Exit(2)
	}
	parsed, err := url.Parse(webURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		fmt.Fprintln(os.Stderr, "invalid --web-url")
		os.Exit(2)
	}
	listener, port, err := listenLoopback(preferredPort)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	token := generateHex(24)
	fragment := url.Values{"probe_port": {strconv.Itoa(port)}, "probe_token": {token}, "probe_version": {version}}.Encode()
	launch := strings.TrimRight(webURL, "/#") + "/#" + fragment
	server := &http.Server{Handler: routes(token), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: 45 * time.Second}
	fmt.Printf("Active IP User Probe %s\n", version)
	fmt.Printf("Local Probe: http://127.0.0.1:%d\n", port)
	fmt.Printf("User Web:    %s\n", webURL)
	fmt.Println("Mode:        Direct only")
	fmt.Println("Keep this window open. Press Ctrl+C to stop.")
	go func() {
		time.Sleep(200 * time.Millisecond)
		if err := openBrowser(launch); err != nil {
			fmt.Printf("Browser auto-open unavailable. Open this URL manually:\n%s\n", launch)
		}
	}()
	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

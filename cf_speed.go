package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	cfQuickBytes          int64  = 1_000_000
	cfQuickTimeout               = 2 * time.Second
	cfSpeedBytes          int64  = 80_000_000
	cfSpeedTopLimit              = 20
	cfSpeedMaxInput       uint64 = 2_000_000
	cfSpeedDefaultWorkers        = 64
	cfSpeedMaxWorkers            = 256
	cfQuickDefaultWorkers        = 4
	cfQuickMaxWorkers            = 8
	cfSpeedWindow                = 250 * time.Millisecond
)

var cfHTTPSPorts = map[int]struct{}{
	443: {}, 2053: {}, 2083: {}, 2087: {}, 2096: {}, 8443: {},
}

type benchEndpointRange struct {
	rng  ipRange
	port int
}

type benchEndpoint struct {
	IP      string        `json:"ip"`
	Port    int           `json:"port"`
	TCPHint time.Duration `json:"-"`
}

type ipMetadata struct {
	IP          string `json:"ip"`
	Country     string `json:"country,omitempty"`
	CountryCode string `json:"country_code,omitempty"`
	Region      string `json:"region,omitempty"`
	City        string `json:"city,omitempty"`
	ASN         int    `json:"asn,omitempty"`
	Org         string `json:"org,omitempty"`
	ISP         string `json:"isp,omitempty"`
	IDC         string `json:"idc,omitempty"`
	Source      string `json:"source,omitempty"`
}

type cfSpeedResult struct {
	Rank            int        `json:"rank"`
	IP              string     `json:"ip"`
	Port            int        `json:"port"`
	Meta            ipMetadata `json:"meta"`
	TCPMS           float64    `json:"tcp_ms"`
	TLSHandshakeMS  float64    `json:"tls_handshake_ms"`
	TLSCompleteMS   float64    `json:"tls_complete_ms"`
	TTFBMS          float64    `json:"ttfb_ms"`
	TotalSeconds    float64    `json:"total_seconds"`
	TransferSeconds float64    `json:"transfer_seconds"`
	AverageMbps     float64    `json:"average_mbps"`
	EffectiveMbps   float64    `json:"effective_mbps"`
	PeakMbps        float64    `json:"peak_mbps"`
	DownloadedBytes int64      `json:"downloaded_bytes"`
	HTTPStatus      int        `json:"http_status"`
	Status          string     `json:"status"`
	FailureStage    string     `json:"failure_stage,omitempty"`
	Error           string     `json:"error,omitempty"`
}

type cfSpeedStartRequest struct {
	Targets      []string              `json:"targets"`
	Port         int                   `json:"port"`
	Timeout      float64               `json:"timeout"`
	Workers      int                   `json:"workers"`
	QuickWorkers int                   `json:"quick_workers"`
	PrecisionMB  int                   `json:"precision_mb,omitempty"`
	EgressMode   string                `json:"egress_mode,omitempty"`
	WARPProxy    string                `json:"warp_proxy,omitempty"`
	Metadata     map[string]ipMetadata `json:"metadata,omitempty"`
}

type cfSpeedJob struct {
	id             string
	startedAt      time.Time
	ctx            context.Context
	cancel         context.CancelFunc
	total          uint64
	egress         egressConfig
	precisionBytes int64

	prefilterDone atomic.Uint64
	quickDone     atomic.Uint64
	quickPassed   atomic.Uint64
	downloadDone  atomic.Uint64
	passed        atomic.Uint64
	failed        atomic.Uint64

	mu            sync.RWMutex
	status        string
	phase         string
	message       string
	selectedCount int
	results       []cfSpeedResult
}

func (j *cfSpeedJob) setState(status, phase, message string) {
	j.mu.Lock()
	j.status = status
	j.phase = phase
	j.message = message
	j.mu.Unlock()
}

func (j *cfSpeedJob) setSelected(count int) {
	j.mu.Lock()
	j.selectedCount = count
	j.mu.Unlock()
}

func (j *cfSpeedJob) addResult(result cfSpeedResult) {
	j.mu.Lock()
	j.results = rankCFResults(append(j.results, result))
	j.mu.Unlock()
}

func rankCFResults(values []cfSpeedResult) []cfSpeedResult {
	result := append([]cfSpeedResult(nil), values...)
	sort.SliceStable(result, func(i, j int) bool {
		a, b := result[i], result[j]
		if (a.Status == "ok") != (b.Status == "ok") {
			return a.Status == "ok"
		}
		if a.PeakMbps != b.PeakMbps {
			return a.PeakMbps > b.PeakMbps
		}
		if a.AverageMbps != b.AverageMbps {
			return a.AverageMbps > b.AverageMbps
		}
		if a.TTFBMS != b.TTFBMS {
			return a.TTFBMS < b.TTFBMS
		}
		if a.TCPMS != b.TCPMS {
			return a.TCPMS < b.TCPMS
		}
		if a.IP != b.IP {
			return a.IP < b.IP
		}
		return a.Port < b.Port
	})
	if len(result) > cfSpeedTopLimit {
		result = result[:cfSpeedTopLimit]
	}
	for i := range result {
		result[i].Rank = i + 1
	}
	return result
}

func (j *cfSpeedJob) snapshot() map[string]any {
	j.mu.RLock()
	status := j.status
	phase := j.phase
	message := j.message
	selected := j.selectedCount
	results := rankCFResults(j.results)
	j.mu.RUnlock()
	passed := 0
	for _, item := range results {
		if item.Status == "ok" {
			passed++
		}
	}
	return map[string]any{
		"id":              j.id,
		"status":          status,
		"phase":           phase,
		"message":         message,
		"input_total":     j.total,
		"prefilter_done":  j.prefilterDone.Load(),
		"quick_done":      j.quickDone.Load(),
		"quick_passed":    j.quickPassed.Load(),
		"selected":        selected,
		"download_done":   j.downloadDone.Load(),
		"passed":          j.passed.Load(),
		"failed":          j.failed.Load(),
		"top20_passed":    passed,
		"quick_bytes":     cfQuickBytes,
		"quick_timeout_s": cfQuickTimeout.Seconds(),
		"download_bytes":  j.precisionBytes,
		"results":         results,
	}
}

type cfSpeedJobStore struct {
	mu   sync.RWMutex
	jobs map[string]*cfSpeedJob
}

func newCFSpeedJobStore() *cfSpeedJobStore {
	return &cfSpeedJobStore{jobs: make(map[string]*cfSpeedJob)}
}

func (s *cfSpeedJobStore) put(job *cfSpeedJob) {
	s.mu.Lock()
	s.jobs[job.id] = job
	s.mu.Unlock()
}

func (s *cfSpeedJobStore) get(id string) (*cfSpeedJob, bool) {
	s.mu.RLock()
	job, ok := s.jobs[id]
	s.mu.RUnlock()
	return job, ok
}

func (s *cfSpeedJobStore) cleanupOld(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, job := range s.jobs {
		if now.Sub(job.startedAt) < jobRetention {
			continue
		}
		job.cancel()
		delete(s.jobs, id)
	}
}

func (s *cfSpeedJobStore) cancelAll() {
	s.mu.RLock()
	jobs := make([]*cfSpeedJob, 0, len(s.jobs))
	for _, job := range s.jobs {
		jobs = append(jobs, job)
	}
	s.mu.RUnlock()
	for _, job := range jobs {
		job.cancel()
	}
}

var cfSpeedJobs = newCFSpeedJobStore()

func validCFHTTPSPort(port int) bool {
	_, ok := cfHTTPSPorts[port]
	return ok
}

func splitEndpointPort(value string, defaultPort int) (string, int, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", 0, errors.New("empty endpoint")
	}
	if strings.Count(value, ":") == 1 && !strings.Contains(value, "/") && !strings.Contains(value, "-") {
		host, portText, err := net.SplitHostPort(value)
		if err == nil {
			port, err := strconv.Atoi(portText)
			if err != nil || !validCFHTTPSPort(port) {
				return "", 0, fmt.Errorf("unsupported Cloudflare HTTPS port: %s", portText)
			}
			return host, port, nil
		}
	}
	if !validCFHTTPSPort(defaultPort) {
		return "", 0, fmt.Errorf("unsupported Cloudflare HTTPS port: %d", defaultPort)
	}
	return value, defaultPort, nil
}

func parseCFSpeedTargets(values []string, defaultPort int) ([]benchEndpointRange, uint64, error) {
	if !validCFHTTPSPort(defaultPort) {
		return nil, 0, fmt.Errorf("unsupported Cloudflare HTTPS port: %d", defaultPort)
	}
	ranges := make([]benchEndpointRange, 0, len(values))
	var total uint64
	for _, raw := range values {
		value, port, err := splitEndpointPort(raw, defaultPort)
		if err != nil {
			return nil, 0, err
		}
		rng, err := parseTarget(value)
		if err != nil {
			return nil, 0, err
		}
		count := uint64(rng.end) - uint64(rng.start) + 1
		if count > cfSpeedMaxInput || total > cfSpeedMaxInput-count {
			return nil, 0, fmt.Errorf("CF speed input exceeds %d endpoints", cfSpeedMaxInput)
		}
		total += count
		ranges = append(ranges, benchEndpointRange{rng: rng, port: port})
	}
	if total == 0 {
		return nil, 0, errors.New("provide at least one candidate endpoint")
	}
	return ranges, total, nil
}

func streamBenchEndpoints(ctx context.Context, ranges []benchEndpointRange, out chan<- benchEndpoint) {
	defer close(out)
	for _, item := range ranges {
		for raw := item.rng.start; ; raw++ {
			endpoint := benchEndpoint{IP: uint32ToAddr(raw).String(), Port: item.port}
			select {
			case <-ctx.Done():
				return
			case out <- endpoint:
			}
			if raw == item.rng.end {
				break
			}
		}
	}
}

func prefilterCFSpeedEndpoints(job *cfSpeedJob, ranges []benchEndpointRange, total uint64, workers int, tcpTimeout time.Duration) (string, int, error) {
	job.setState("running", "prefilter", fmt.Sprintf("TCP prefiltering %d endpoint(s); every reachable endpoint will receive one download test", total))
	spool, err := os.CreateTemp("", "active-ip-sniffer-cf-*.csv")
	if err != nil {
		return "", 0, fmt.Errorf("create CF prefilter spool: %w", err)
	}
	spoolPath := spool.Name()
	cleanupOnError := func(err error) (string, int, error) {
		_ = spool.Close()
		_ = os.Remove(spoolPath)
		return "", 0, err
	}

	tasks := make(chan benchEndpoint, maxInt(64, workers*4))
	reachable := make(chan benchEndpoint, maxInt(32, workers*2))
	go streamBenchEndpoints(job.ctx, ranges, tasks)

	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for endpoint := range tasks {
				if job.ctx.Err() != nil {
					return
				}
				started := time.Now()
				conn, dialErr := job.egress.dialContext(job.ctx, "tcp", net.JoinHostPort(endpoint.IP, strconv.Itoa(endpoint.Port)), tcpTimeout)
				job.prefilterDone.Add(1)
				if dialErr != nil {
					continue
				}
				endpoint.TCPHint = time.Since(started)
				_ = conn.Close()
				select {
				case <-job.ctx.Done():
					return
				case reachable <- endpoint:
				}
			}
		}()
	}
	go func() {
		wg.Wait()
		close(reachable)
	}()

	writer := bufio.NewWriterSize(spool, 64*1024)
	reachableCount := 0
	for endpoint := range reachable {
		if _, err := fmt.Fprintf(writer, "%s,%d\n", endpoint.IP, endpoint.Port); err != nil {
			return cleanupOnError(fmt.Errorf("write CF prefilter spool: %w", err))
		}
		reachableCount++
	}
	if err := writer.Flush(); err != nil {
		return cleanupOnError(fmt.Errorf("flush CF prefilter spool: %w", err))
	}
	if err := spool.Close(); err != nil {
		_ = os.Remove(spoolPath)
		return "", 0, fmt.Errorf("close CF prefilter spool: %w", err)
	}
	if job.ctx.Err() != nil {
		_ = os.Remove(spoolPath)
		return "", 0, job.ctx.Err()
	}
	return spoolPath, reachableCount, nil
}

func readBenchEndpoint(line string) (benchEndpoint, error) {
	parts := strings.SplitN(strings.TrimSpace(line), ",", 2)
	if len(parts) != 2 || net.ParseIP(parts[0]) == nil {
		return benchEndpoint{}, errors.New("invalid CF spool endpoint")
	}
	port, err := strconv.Atoi(parts[1])
	if err != nil || !validCFHTTPSPort(port) {
		return benchEndpoint{}, errors.New("invalid CF spool port")
	}
	return benchEndpoint{IP: parts[0], Port: port}, nil
}

func quickFilterCFSpeedEndpoints(job *cfSpeedJob, spoolPath string, inputCount, workers int) (string, int, error) {
	job.setState("running", "quick", fmt.Sprintf("1 MB / %.0fs quick screening %d TCP-reachable endpoint(s)", cfQuickTimeout.Seconds(), inputCount))
	in, err := os.Open(spoolPath)
	if err != nil {
		return "", 0, fmt.Errorf("open CF quick-filter input: %w", err)
	}
	defer in.Close()
	out, err := os.CreateTemp("", "active-ip-sniffer-cf-quick-*.csv")
	if err != nil {
		return "", 0, fmt.Errorf("create CF quick-filter spool: %w", err)
	}
	outPath := out.Name()
	cleanupOnError := func(err error) (string, int, error) {
		_ = out.Close()
		_ = os.Remove(outPath)
		return "", 0, err
	}

	workers = clampInt(workers, 1, cfQuickMaxWorkers, cfQuickDefaultWorkers)
	tasks := make(chan benchEndpoint, workers*2)
	passed := make(chan benchEndpoint, workers*2)
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for endpoint := range tasks {
				if job.ctx.Err() != nil {
					return
				}
				ctx, cancel := context.WithTimeout(job.ctx, cfQuickTimeout)
				result := runDirectCFSpeed(ctx, endpoint, cfQuickBytes, job.egress)
				cancel()
				job.quickDone.Add(1)
				if result.Status != "ok" {
					job.failed.Add(1)
					continue
				}
				job.quickPassed.Add(1)
				select {
				case <-job.ctx.Done():
					return
				case passed <- endpoint:
				}
			}
		}()
	}

	go func() {
		scanner := bufio.NewScanner(in)
		for scanner.Scan() {
			endpoint, parseErr := readBenchEndpoint(scanner.Text())
			if parseErr != nil {
				job.quickDone.Add(1)
				job.failed.Add(1)
				continue
			}
			select {
			case <-job.ctx.Done():
				close(tasks)
				return
			case tasks <- endpoint:
			}
		}
		close(tasks)
	}()
	go func() {
		wg.Wait()
		close(passed)
	}()

	writer := bufio.NewWriterSize(out, 64*1024)
	passedCount := 0
	for endpoint := range passed {
		if _, err := fmt.Fprintf(writer, "%s,%d\n", endpoint.IP, endpoint.Port); err != nil {
			return cleanupOnError(fmt.Errorf("write CF quick-filter spool: %w", err))
		}
		passedCount++
	}
	if err := writer.Flush(); err != nil {
		return cleanupOnError(fmt.Errorf("flush CF quick-filter spool: %w", err))
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(outPath)
		return "", 0, fmt.Errorf("close CF quick-filter spool: %w", err)
	}
	if job.ctx.Err() != nil {
		_ = os.Remove(outPath)
		return "", 0, job.ctx.Err()
	}
	return outPath, passedCount, nil
}

type speedTraceTimes struct {
	connectStart time.Time
	connectDone  time.Time
	tlsStart     time.Time
	tlsDone      time.Time
	firstByte    time.Time
}

func runDirectCFSpeed(ctx context.Context, endpoint benchEndpoint, bytesWanted int64, egress egressConfig) cfSpeedResult {
	result := cfSpeedResult{IP: endpoint.IP, Port: endpoint.Port, Status: "failed"}
	requestStart := time.Now()
	traceTimes := &speedTraceTimes{}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(dialCtx context.Context, _, _ string) (net.Conn, error) {
			return egress.dialContext(dialCtx, "tcp", net.JoinHostPort(endpoint.IP, strconv.Itoa(endpoint.Port)), 6*time.Second)
		},
		TLSClientConfig: &tls.Config{
			ServerName: "speed.cloudflare.com",
			MinVersion: tls.VersionTLS12,
			NextProtos: []string{"http/1.1"},
		},
		ForceAttemptHTTP2:     false,
		DisableCompression:    true,
		MaxIdleConns:          1,
		IdleConnTimeout:       5 * time.Second,
		TLSHandshakeTimeout:   8 * time.Second,
		ResponseHeaderTimeout: 12 * time.Second,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	host := "speed.cloudflare.com"
	if endpoint.Port != 443 {
		host += ":" + strconv.Itoa(endpoint.Port)
	}
	requestURL := "https://" + host + "/__down?bytes=" + strconv.FormatInt(bytesWanted, 10)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		result.Error = err.Error()
		result.FailureStage = "request"
		return result
	}
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("User-Agent", "Active-IP-Sniffer/"+appVersion)
	trace := &httptrace.ClientTrace{
		ConnectStart:         func(_, _ string) { traceTimes.connectStart = time.Now() },
		ConnectDone:          func(_, _ string, _ error) { traceTimes.connectDone = time.Now() },
		TLSHandshakeStart:    func() { traceTimes.tlsStart = time.Now() },
		TLSHandshakeDone:     func(_ tls.ConnectionState, _ error) { traceTimes.tlsDone = time.Now() },
		GotFirstResponseByte: func() { traceTimes.firstByte = time.Now() },
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
	resp, err := client.Do(req)
	if err != nil {
		result.FailureStage = inferSpeedFailureStage(traceTimes)
		result.Error = err.Error()
		fillSpeedTiming(&result, requestStart, traceTimes)
		return result
	}
	defer resp.Body.Close()
	result.HTTPStatus = resp.StatusCode
	fillSpeedTiming(&result, requestStart, traceTimes)
	if resp.StatusCode != http.StatusOK {
		result.FailureStage = "http"
		result.Error = fmt.Sprintf("speed.cloudflare.com returned HTTP %d", resp.StatusCode)
		return result
	}

	bodyStart := time.Now()
	windowStart := bodyStart
	buffer := make([]byte, 64*1024)
	var total int64
	var windowBytes int64
	var peak float64
	for {
		n, readErr := resp.Body.Read(buffer)
		if n > 0 {
			total += int64(n)
			windowBytes += int64(n)
			now := time.Now()
			windowElapsed := now.Sub(windowStart)
			if windowElapsed >= cfSpeedWindow {
				peak = math.Max(peak, bitsPerSecondMbps(windowBytes, windowElapsed))
				windowStart = now
				windowBytes = 0
			}
		}
		if readErr != nil {
			if !errors.Is(readErr, io.EOF) {
				result.FailureStage = "download"
				result.Error = readErr.Error()
			}
			break
		}
	}
	finish := time.Now()
	transferElapsed := finish.Sub(bodyStart)
	if finalWindow := finish.Sub(windowStart); windowBytes > 0 && finalWindow >= 100*time.Millisecond {
		peak = math.Max(peak, bitsPerSecondMbps(windowBytes, finalWindow))
	}
	result.DownloadedBytes = total
	result.TransferSeconds = roundFloat(transferElapsed.Seconds(), 3)
	result.TotalSeconds = roundFloat(finish.Sub(requestStart).Seconds(), 3)
	result.PeakMbps = roundFloat(peak, 1)
	result.AverageMbps = roundFloat(bitsPerSecondMbps(total, transferElapsed), 1)
	result.EffectiveMbps = roundFloat(bitsPerSecondMbps(total, finish.Sub(requestStart)), 1)
	if result.Error == "" && total == bytesWanted {
		result.Status = "ok"
		return result
	}
	if result.Error == "" {
		result.FailureStage = "download"
		result.Error = fmt.Sprintf("downloaded %d bytes, expected %d", total, bytesWanted)
	}
	return result
}

func fillSpeedTiming(result *cfSpeedResult, requestStart time.Time, trace *speedTraceTimes) {
	if !trace.connectStart.IsZero() && !trace.connectDone.IsZero() {
		result.TCPMS = durationMS(trace.connectDone.Sub(trace.connectStart))
	}
	if !trace.tlsStart.IsZero() && !trace.tlsDone.IsZero() {
		result.TLSHandshakeMS = durationMS(trace.tlsDone.Sub(trace.tlsStart))
		result.TLSCompleteMS = durationMS(trace.tlsDone.Sub(requestStart))
	}
	if !trace.firstByte.IsZero() {
		result.TTFBMS = durationMS(trace.firstByte.Sub(requestStart))
	}
}

func inferSpeedFailureStage(trace *speedTraceTimes) string {
	if trace.connectDone.IsZero() {
		return "tcp"
	}
	if trace.tlsDone.IsZero() {
		return "tls"
	}
	if trace.firstByte.IsZero() {
		return "ttfb"
	}
	return "download"
}

func executeCFSpeedJob(job *cfSpeedJob, ranges []benchEndpointRange, total uint64, workers, quickWorkers int, tcpTimeout time.Duration) {
	spoolPath, reachableCount, err := prefilterCFSpeedEndpoints(job, ranges, total, workers, tcpTimeout)
	if err != nil {
		if job.ctx.Err() != nil {
			job.setState("cancelled", "cancelled", "CF speed test cancelled")
		} else {
			job.setState("failed", "failed", err.Error())
		}
		return
	}
	defer os.Remove(spoolPath)
	if job.ctx.Err() != nil {
		job.setState("cancelled", "cancelled", "CF speed test cancelled")
		return
	}
	if reachableCount == 0 {
		job.setState("complete", "complete", "No TCP-reachable candidate survived the prefilter")
		return
	}
	quickPath, quickPassed, err := quickFilterCFSpeedEndpoints(job, spoolPath, reachableCount, quickWorkers)
	if err != nil {
		if job.ctx.Err() != nil {
			job.setState("cancelled", "cancelled", "CF speed test cancelled")
		} else {
			job.setState("failed", "failed", err.Error())
		}
		return
	}
	defer os.Remove(quickPath)
	job.setSelected(quickPassed)
	if quickPassed == 0 {
		job.setState("complete", "complete", "No endpoint completed the 1 MB quick screen within 2 seconds")
		return
	}
	job.setState("running", "download", fmt.Sprintf("%d endpoint(s) survived 1 MB / 2s screening; running one %.0f MB precision test each; ranking by peak speed", quickPassed, float64(job.precisionBytes)/1_000_000))
	spool, err := os.Open(quickPath)
	if err != nil {
		job.setState("failed", "failed", "open CF prefilter spool: "+err.Error())
		return
	}
	defer spool.Close()
	scanner := bufio.NewScanner(spool)
	for scanner.Scan() {
		if job.ctx.Err() != nil {
			job.setState("cancelled", "cancelled", "CF speed test cancelled")
			return
		}
		endpoint, parseErr := readBenchEndpoint(scanner.Text())
		if parseErr != nil {
			job.failed.Add(1)
			job.downloadDone.Add(1)
			continue
		}
		ctx, cancel := context.WithTimeout(job.ctx, 180*time.Second)
		result := runDirectCFSpeed(ctx, endpoint, job.precisionBytes, job.egress)
		cancel()
		if meta, ok := cachedIPMetadata(endpoint.IP); ok {
			result.Meta = meta
		}
		job.addResult(result)
		job.downloadDone.Add(1)
		if result.Status == "ok" {
			job.passed.Add(1)
		} else {
			job.failed.Add(1)
		}
	}
	if err := scanner.Err(); err != nil {
		job.setState("failed", "failed", "read CF prefilter spool: "+err.Error())
		return
	}
	if job.ctx.Err() != nil {
		job.setState("cancelled", "cancelled", "CF speed test cancelled")
		return
	}
	job.mu.Lock()
	top := append([]cfSpeedResult(nil), job.results...)
	job.mu.Unlock()
	for i := range top {
		metaCtx, metaCancel := context.WithTimeout(job.ctx, 6*time.Second)
		top[i].Meta = lookupIPMetadata(metaCtx, top[i].IP)
		metaCancel()
	}
	job.mu.Lock()
	job.results = top
	job.mu.Unlock()
	job.setState("complete", "complete", "CF direct speed test complete")
}

func handleCFSpeedStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 12<<20)
	defer r.Body.Close()
	var request cfSpeedStartRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request: " + err.Error()})
		return
	}
	if request.Port == 0 {
		request.Port = 443
	}
	ranges, total, err := parseCFSpeedTargets(request.Targets, request.Port)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	workers := clampInt(request.Workers, 1, cfSpeedMaxWorkers, cfSpeedDefaultWorkers)
	quickWorkers := clampInt(request.QuickWorkers, 1, cfQuickMaxWorkers, cfQuickDefaultWorkers)
	precisionMB := request.PrecisionMB
	if precisionMB == 0 {
		precisionMB = int(cfSpeedBytes / 1_000_000)
	}
	if precisionMB < 5 || precisionMB > 80 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "precision_mb must be between 5 and 80"})
		return
	}
	requestedEgress, err := normalizeEgress(request.EgressMode, request.WARPProxy)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	egress, _, err := resolveEgress(r.Context(), requestedEgress)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	tcpTimeoutSeconds := clampFloat(request.Timeout, 0.2, 5, 1.5)
	tcpTimeout := time.Duration(tcpTimeoutSeconds * float64(time.Second))
	cfSpeedJobs.cleanupOld(time.Now())
	ctx, cancel := context.WithCancel(context.Background())
	for ip, meta := range request.Metadata {
		if meta.IP == "" {
			meta.IP = ip
		}
		seedIPMetadata(meta, metadataImportedTTL)
	}
	job := &cfSpeedJob{id: newJobID(), startedAt: time.Now(), ctx: ctx, cancel: cancel, total: total, egress: egress, precisionBytes: int64(precisionMB) * 1_000_000, status: "queued", phase: "queued"}
	cfSpeedJobs.put(job)
	go executeCFSpeedJob(job, ranges, total, workers, quickWorkers, tcpTimeout)
	writeJSON(w, http.StatusAccepted, map[string]any{
		"id":                    job.id,
		"input_total":           total,
		"top_limit":             cfSpeedTopLimit,
		"quick_bytes":           cfQuickBytes,
		"quick_timeout_s":       cfQuickTimeout.Seconds(),
		"download_bytes":        job.precisionBytes,
		"requested_egress_mode": requestedEgress.Mode,
		"egress_mode":           egress.Mode,
		"default_port":          request.Port,
		"prefilter_workers":     workers,
		"quick_workers":         quickWorkers,
	})
}

func handleCFSpeedJob(w http.ResponseWriter, r *http.Request) {
	job, ok := cfSpeedJobs.get(r.URL.Query().Get("id"))
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "CF speed job not found"})
		return
	}
	writeJSON(w, http.StatusOK, job.snapshot())
}

func handleCFSpeedCancel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	job, ok := cfSpeedJobs.get(r.URL.Query().Get("id"))
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "CF speed job not found"})
		return
	}
	job.cancel()
	job.setState("cancelled", "cancelled", "CF speed test cancelled")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func handleCFSpeedExportCSV(w http.ResponseWriter, r *http.Request) {
	job, ok := cfSpeedJobs.get(r.URL.Query().Get("id"))
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "CF speed job not found"})
		return
	}
	job.mu.RLock()
	results := rankCFResults(job.results)
	job.mu.RUnlock()
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", "cf-direct-speed-"+time.Now().Format("20060102-150405")+".csv"))
	writer := csv.NewWriter(w)
	_ = writer.Write([]string{"rank", "ip", "port", "country_code", "country", "region", "city", "asn", "idc", "org", "isp", "metadata_source", "tcp_ms", "tls_handshake_ms", "tls_complete_ms", "ttfb_ms", "average_mbps", "effective_mbps", "peak_mbps", "transfer_seconds", "total_seconds", "downloaded_bytes", "http_status", "status", "failure_stage", "error"})
	for _, item := range results {
		_ = writer.Write([]string{
			strconv.Itoa(item.Rank), item.IP, strconv.Itoa(item.Port), item.Meta.CountryCode, item.Meta.Country, item.Meta.Region, item.Meta.City, strconv.Itoa(item.Meta.ASN), item.Meta.IDC, item.Meta.Org, item.Meta.ISP, item.Meta.Source,
			fmt.Sprintf("%.1f", item.TCPMS), fmt.Sprintf("%.1f", item.TLSHandshakeMS), fmt.Sprintf("%.1f", item.TLSCompleteMS), fmt.Sprintf("%.1f", item.TTFBMS),
			fmt.Sprintf("%.1f", item.AverageMbps), fmt.Sprintf("%.1f", item.EffectiveMbps), fmt.Sprintf("%.1f", item.PeakMbps), fmt.Sprintf("%.3f", item.TransferSeconds), fmt.Sprintf("%.3f", item.TotalSeconds),
			strconv.FormatInt(item.DownloadedBytes, 10), strconv.Itoa(item.HTTPStatus), item.Status, item.FailureStage, item.Error,
		})
	}
	writer.Flush()
}

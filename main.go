package main

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"math"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	appVersion        = "3.5.1"
	maxPorts          = 32
	maxAttempts       = uint64(2_000_000)
	maxWorkers        = 512
	maxRate           = 5_000.0
	defaultWorkers    = 64
	defaultRate       = 500.0
	recentResultLimit = 500
	jobRetention      = 24 * time.Hour
)

type ipRange struct {
	start uint32
	end   uint32
}

type scanResult struct {
	IP    string `json:"ip"`
	Ports []int  `json:"ports"`
}

type scanJob struct {
	id        string
	ranges    []ipRange
	hostCount uint64
	ports     []int
	timeout   time.Duration
	workers   int
	rate      float64
	egress    egressConfig
	startedAt time.Time
	csvPath   string
	ipsPath   string

	ctx    context.Context
	cancel context.CancelFunc

	mu         sync.RWMutex
	status     string
	message    string
	recent     []scanResult
	recentNext int
	recentUsed int

	done      atomic.Uint64
	foundIPs  atomic.Uint64
	openPorts atomic.Uint64
}

func (j *scanJob) recordResult(result scanResult) {
	j.foundIPs.Add(1)
	j.openPorts.Add(uint64(len(result.Ports)))
	j.mu.Lock()
	defer j.mu.Unlock()
	if len(j.recent) == 0 {
		j.recent = make([]scanResult, recentResultLimit)
	}
	j.recent[j.recentNext] = result
	j.recentNext = (j.recentNext + 1) % recentResultLimit
	if j.recentUsed < recentResultLimit {
		j.recentUsed++
	}
}

func (j *scanJob) setState(status, message string) {
	j.mu.Lock()
	j.status = status
	j.message = message
	j.mu.Unlock()
}

func (j *scanJob) snapshot() map[string]any {
	j.mu.RLock()
	status := j.status
	message := j.message
	used := j.recentUsed
	next := j.recentNext
	recent := make([]scanResult, 0, used)
	if used > 0 {
		start := 0
		if used == recentResultLimit {
			start = next
		}
		for i := 0; i < used; i++ {
			idx := (start + i) % recentResultLimit
			item := j.recent[idx]
			item.Ports = append([]int(nil), item.Ports...)
			recent = append(recent, item)
		}
	}
	j.mu.RUnlock()
	return map[string]any{
		"id":         j.id,
		"status":     status,
		"done":       j.done.Load(),
		"total":      j.hostCount * uint64(len(j.ports)),
		"found_ips":  j.foundIPs.Load(),
		"open_ports": j.openPorts.Load(),
		"message":    message,
		"results":    recent,
		"truncated":  j.foundIPs.Load() > recentResultLimit,
	}
}

type jobStore struct {
	mu   sync.RWMutex
	jobs map[string]*scanJob
}

func newJobStore() *jobStore {
	return &jobStore{jobs: make(map[string]*scanJob)}
}

func (s *jobStore) put(job *scanJob) {
	s.mu.Lock()
	s.jobs[job.id] = job
	s.mu.Unlock()
}

func (s *jobStore) get(id string) (*scanJob, bool) {
	s.mu.RLock()
	job, ok := s.jobs[id]
	s.mu.RUnlock()
	return job, ok
}

func (s *jobStore) cleanupOld(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, job := range s.jobs {
		if now.Sub(job.startedAt) < jobRetention {
			continue
		}
		job.cancel()
		_ = os.Remove(job.csvPath)
		_ = os.Remove(job.ipsPath)
		delete(s.jobs, id)
	}
}

func cleanupResultDirectory(dataDir string, now time.Time) {
	entries, err := os.ReadDir(dataDir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil || now.Sub(info.ModTime()) < jobRetention {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".csv") || strings.HasSuffix(name, ".txt") {
			_ = os.Remove(filepath.Join(dataDir, name))
		}
	}
}

func (s *jobStore) cancelAll() {
	s.mu.RLock()
	jobs := make([]*scanJob, 0, len(s.jobs))
	for _, job := range s.jobs {
		jobs = append(jobs, job)
	}
	s.mu.RUnlock()
	for _, job := range jobs {
		job.cancel()
	}
}

type app struct {
	store    *jobStore
	dataDir  string
	settings *settingsStore
	public   *publicBenchmarkStore
}

type startRequest struct {
	Targets    []string `json:"targets"`
	Ports      []int    `json:"ports"`
	Timeout    float64  `json:"timeout"`
	Workers    int      `json:"workers"`
	Rate       float64  `json:"rate"`
	EgressMode string   `json:"egress_mode,omitempty"`
	WARPProxy  string   `json:"warp_proxy,omitempty"`
}

type attemptLimiter struct {
	mu       sync.Mutex
	next     time.Time
	interval time.Duration
}

func newAttemptLimiter(rate float64) *attemptLimiter {
	interval := time.Duration(float64(time.Second) / rate)
	if interval < time.Microsecond {
		interval = time.Microsecond
	}
	return &attemptLimiter{interval: interval}
}

func (l *attemptLimiter) wait(ctx context.Context) bool {
	l.mu.Lock()
	now := time.Now()
	if l.next.IsZero() || l.next.Before(now) {
		l.next = now
	}
	scheduled := l.next
	l.next = l.next.Add(l.interval)
	l.mu.Unlock()

	delay := time.Until(scheduled)
	if delay <= 0 {
		return true
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func parseIPv4(value string) (uint32, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil || !addr.Is4() {
		return 0, fmt.Errorf("invalid IPv4 address: %s", value)
	}
	b := addr.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3]), nil
}

func uint32ToAddr(value uint32) netip.Addr {
	b := [4]byte{byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)}
	return netip.AddrFrom4(b)
}

func parseTarget(value string) (ipRange, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return ipRange{}, errors.New("empty target")
	}

	if strings.Contains(value, "/") {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || !prefix.Addr().Is4() {
			return ipRange{}, fmt.Errorf("invalid IPv4 CIDR target: %s", value)
		}
		prefix = prefix.Masked()
		start, _ := parseIPv4(prefix.Addr().String())
		bits := prefix.Bits()
		size := uint64(1) << uint(32-bits)
		start64 := uint64(start)
		end64 := start64 + size - 1
		if bits <= 30 {
			start64++
			end64--
		}
		return ipRange{start: uint32(start64), end: uint32(end64)}, nil
	}

	if strings.Contains(value, "-") {
		parts := strings.SplitN(value, "-", 2)
		start, err := parseIPv4(parts[0])
		if err != nil {
			return ipRange{}, fmt.Errorf("invalid IP range %q: %w", value, err)
		}
		end, err := parseIPv4(parts[1])
		if err != nil {
			return ipRange{}, fmt.Errorf("invalid IP range %q: %w", value, err)
		}
		if start > end {
			return ipRange{}, fmt.Errorf("IP range start is greater than end: %s", value)
		}
		return ipRange{start: start, end: end}, nil
	}

	address, err := parseIPv4(value)
	if err != nil {
		return ipRange{}, err
	}
	return ipRange{start: address, end: address}, nil
}

func parseTargetRanges(values []string) ([]ipRange, uint64, error) {
	ranges := make([]ipRange, 0, len(values))
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if value == "" {
			continue
		}
		rng, err := parseTarget(value)
		if err != nil {
			return nil, 0, err
		}
		ranges = append(ranges, rng)
	}
	if len(ranges) == 0 {
		return nil, 0, errors.New("provide at least one valid scan target")
	}

	sort.Slice(ranges, func(i, j int) bool {
		if ranges[i].start == ranges[j].start {
			return ranges[i].end < ranges[j].end
		}
		return ranges[i].start < ranges[j].start
	})
	merged := make([]ipRange, 0, len(ranges))
	for _, current := range ranges {
		if len(merged) == 0 {
			merged = append(merged, current)
			continue
		}
		last := &merged[len(merged)-1]
		if uint64(current.start) <= uint64(last.end)+1 {
			if current.end > last.end {
				last.end = current.end
			}
			continue
		}
		merged = append(merged, current)
	}

	var count uint64
	for _, rng := range merged {
		count += uint64(rng.end) - uint64(rng.start) + 1
	}
	return merged, count, nil
}

func normalizePorts(values []int) ([]int, error) {
	if len(values) == 0 {
		return nil, errors.New("provide at least one TCP port")
	}
	set := make(map[int]struct{}, len(values))
	for _, port := range values {
		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("invalid TCP port: %d", port)
		}
		set[port] = struct{}{}
	}
	if len(set) > maxPorts {
		return nil, fmt.Errorf("provide at most %d TCP ports", maxPorts)
	}
	ports := make([]int, 0, len(set))
	for port := range set {
		ports = append(ports, port)
	}
	sort.Ints(ports)
	return ports, nil
}

func clampFloat(value, low, high, fallback float64) float64 {
	if math.IsNaN(value) || math.IsInf(value, 0) || value == 0 {
		value = fallback
	}
	if value < low {
		return low
	}
	if value > high {
		return high
	}
	return value
}

func clampInt(value, low, high, fallback int) int {
	if value == 0 {
		value = fallback
	}
	if value < low {
		return low
	}
	if value > high {
		return high
	}
	return value
}

func tcpReachable(ctx context.Context, ip string, port int, timeout time.Duration, egress egressConfig) bool {
	conn, err := egress.dialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)), timeout)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func streamTargets(ctx context.Context, ranges []ipRange, out chan<- uint32) {
	defer close(out)
	for _, rng := range ranges {
		for value := rng.start; ; value++ {
			select {
			case <-ctx.Done():
				return
			case out <- value:
			}
			if value == rng.end {
				break
			}
		}
	}
}

func writeResults(job *scanJob, results <-chan scanResult) error {
	csvFile, err := os.OpenFile(job.csvPath, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer csvFile.Close()
	ipsFile, err := os.OpenFile(job.ipsPath, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer ipsFile.Close()

	csvWriter := csv.NewWriter(csvFile)
	ipWriter := bufio.NewWriterSize(ipsFile, 16*1024)
	flush := func() error {
		csvWriter.Flush()
		if err := csvWriter.Error(); err != nil {
			return err
		}
		return ipWriter.Flush()
	}

	pending := 0
	for result := range results {
		for _, port := range result.Ports {
			if err := csvWriter.Write([]string{result.IP, strconv.Itoa(port)}); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintln(ipWriter, result.IP); err != nil {
			return err
		}
		job.recordResult(result)
		pending++
		if pending >= 32 {
			if err := flush(); err != nil {
				return err
			}
			pending = 0
		}
	}
	return flush()
}

func executeScan(job *scanJob) {
	job.setState("running", "scan running")
	tasks := make(chan uint32, maxInt(128, job.workers*4))
	results := make(chan scanResult, maxInt(64, job.workers*2))
	limiter := newAttemptLimiter(job.rate)

	go streamTargets(job.ctx, job.ranges, tasks)
	writerDone := make(chan error, 1)
	go func() { writerDone <- writeResults(job, results) }()

	var workers sync.WaitGroup
	workers.Add(job.workers)
	for i := 0; i < job.workers; i++ {
		go func() {
			defer workers.Done()
			for {
				select {
				case <-job.ctx.Done():
					return
				case rawIP, ok := <-tasks:
					if !ok {
						return
					}
					ip := uint32ToAddr(rawIP).String()
					open := make([]int, 0, len(job.ports))
					for _, port := range job.ports {
						if !limiter.wait(job.ctx) {
							return
						}
						if tcpReachable(job.ctx, ip, port, job.timeout, job.egress) {
							open = append(open, port)
						}
						job.done.Add(1)
					}
					if len(open) > 0 {
						result := scanResult{IP: ip, Ports: open}
						select {
						case <-job.ctx.Done():
							return
						case results <- result:
						}
					}
				}
			}
		}()
	}

	workers.Wait()
	close(results)
	if err := <-writerDone; err != nil {
		job.setState("failed", "result writer failed: "+err.Error())
		return
	}
	if job.ctx.Err() != nil {
		job.setState("cancelled", "scan cancelled")
		return
	}
	job.setState("complete", fmt.Sprintf("found %d IPs with at least one open port", job.foundIPs.Load()))
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func newJobID() string {
	return fmt.Sprintf("%x%x", time.Now().UnixNano(), atomic.AddUint64(&jobCounter, 1))
}

var jobCounter uint64

func createResultFiles(dataDir, id string) (string, string, error) {
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		return "", "", err
	}
	csvPath := filepath.Join(dataDir, id+".csv")
	ipsPath := filepath.Join(dataDir, id+".txt")
	csvFile, err := os.OpenFile(csvPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", "", err
	}
	writer := csv.NewWriter(csvFile)
	err = writer.Write([]string{"ip", "port"})
	writer.Flush()
	if err == nil {
		err = writer.Error()
	}
	closeErr := csvFile.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(csvPath)
		return "", "", err
	}
	if err := os.WriteFile(ipsPath, nil, 0o600); err != nil {
		_ = os.Remove(csvPath)
		return "", "", err
	}
	return csvPath, ipsPath, nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func (a *app) serveFile(w http.ResponseWriter, r *http.Request, path, filename, contentType string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	http.ServeFile(w, r, path)
}

func (a *app) handleInfo(w http.ResponseWriter, _ *http.Request) {
	info := map[string]any{
		"version":                  appVersion,
		"runtime":                  "go",
		"recent_result_limit":      recentResultLimit,
		"cf_quick_bytes":           cfQuickBytes,
		"cf_quick_timeout_s":       cfQuickTimeout.Seconds(),
		"cf_speed_bytes":           cfSpeedBytes,
		"cf_precision_timeout_s":   cfPrecisionTimeout.Seconds(),
		"user_precision_bytes":     int64(publicPrecisionMB) * 1_000_000,
		"user_precision_timeout_s": cfUserPrecisionTimeout.Seconds(),
		"vless_bytes":              int64(vlessBenchDefaultMB) * 1_000_000,
		"vless_download_timeout_s": vlessBenchDownloadTimeout.Seconds(),
		"cf_top_limit":             cfSpeedTopLimit,
		"cf_https_ports":           []int{443, 2053, 2083, 2087, 2096, 8443},
		"probe_port":               defaultProbePort,
		"default_egress_mode":      "auto",
		"warp_proxy":               defaultWARPProxy,
		"egress_auto":              true,
	}
	if a.settings != nil {
		cfg := a.settings.snapshot()
		info["public_enabled"] = cfg.PublicEnabled
		info["public_port"] = cfg.PublicPort
	}
	writeJSON(w, http.StatusOK, info)
}

func (a *app) handleStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 100_000)
	defer r.Body.Close()
	var request startRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request: " + err.Error()})
		return
	}

	ranges, hostCount, err := parseTargetRanges(request.Targets)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	ports, err := normalizePorts(request.Ports)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	requestedEgress, err := normalizeEgress(request.EgressMode, request.WARPProxy)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	egress, _, err := resolveScanEgress(r.Context(), requestedEgress)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	attempts := hostCount * uint64(len(ports))
	if attempts > maxAttempts {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("scan contains %d connection attempts; limit is %d", attempts, maxAttempts)})
		return
	}

	id := newJobID()
	csvPath, ipsPath, err := createResultFiles(a.dataDir, id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "cannot create result files: " + err.Error()})
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	job := &scanJob{id: id, ranges: ranges, hostCount: hostCount, ports: ports, timeout: time.Duration(clampFloat(request.Timeout, 0.05, 5, 0.8) * float64(time.Second)), workers: clampInt(request.Workers, 1, maxWorkers, defaultWorkers), rate: clampFloat(request.Rate, 1, maxRate, defaultRate), egress: egress, startedAt: time.Now(), csvPath: csvPath, ipsPath: ipsPath, ctx: ctx, cancel: cancel, status: "queued", recent: make([]scanResult, recentResultLimit)}
	a.store.put(job)
	go executeScan(job)
	writeJSON(w, http.StatusAccepted, map[string]any{"id": id, "hosts": hostCount, "attempts": attempts, "requested_egress_mode": requestedEgress.Mode, "egress_mode": egress.Mode})
}

func (a *app) handleJob(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	job, ok := a.store.get(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "job not found"})
		return
	}
	writeJSON(w, http.StatusOK, job.snapshot())
}

func (a *app) handleCancel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	id := r.URL.Query().Get("id")
	job, ok := a.store.get(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "job not found"})
		return
	}
	job.cancel()
	job.setState("cancelled", "scan cancelled")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (a *app) handleExportCSV(w http.ResponseWriter, r *http.Request) {
	job, ok := a.store.get(r.URL.Query().Get("id"))
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "job not found"})
		return
	}
	a.serveFile(w, r, job.csvPath, "active-sniffer-"+time.Now().Format("20060102-150405")+".csv", "text/csv; charset=utf-8")
}

func (a *app) handleExportTXT(w http.ResponseWriter, r *http.Request) {
	job, ok := a.store.get(r.URL.Query().Get("id"))
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "job not found"})
		return
	}
	a.serveFile(w, r, job.ipsPath, "active-sniffer-ips-"+time.Now().Format("20060102-150405")+".txt", "text/plain; charset=utf-8")
}

func (a *app) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		_, _ = w.Write([]byte(indexHTML))
	})
	mux.HandleFunc("/api/info", a.handleInfo)
	mux.HandleFunc("/api/network-info", handleNetworkInfo("server"))
	mux.HandleFunc("/api/egress/check", handleEgressCheck("server"))
	mux.HandleFunc("/api/scan/start", a.handleStart)
	mux.HandleFunc("/api/scan/job", a.handleJob)
	mux.HandleFunc("/api/scan/cancel", a.handleCancel)
	mux.HandleFunc("/api/scan/export.csv", a.handleExportCSV)
	mux.HandleFunc("/api/scan/export.txt", a.handleExportTXT)
	mux.HandleFunc("/api/vless/start", handleVLESSBenchStart)
	mux.HandleFunc("/api/vless/job", handleVLESSBenchJob)
	mux.HandleFunc("/api/vless/cancel", handleVLESSBenchCancel)
	mux.HandleFunc("/api/vless/export.csv", handleVLESSBenchExportCSV)
	mux.HandleFunc("/api/cf-speed/start", handleCFSpeedStart)
	mux.HandleFunc("/api/cf-speed/job", handleCFSpeedJob)
	mux.HandleFunc("/api/cf-speed/cancel", handleCFSpeedCancel)
	mux.HandleFunc("/api/cf-speed/export.csv", handleCFSpeedExportCSV)
	mux.HandleFunc("/api/cloudflare/config", a.handleCloudflareConfig)
	mux.HandleFunc("/api/cloudflare/update", a.handleCloudflareUpdate)
	mux.HandleFunc("/api/ip/meta", handleIPMetadata)
	mux.HandleFunc("/api/candidates/import", handleCandidateCSVImport)
	mux.HandleFunc("/api/public/publish", a.handlePublicPublish)
	mux.HandleFunc("/api/public/submissions", a.handlePublicSubmissions)
	mux.HandleFunc("/api/public/smart-plan", a.handleSmartDNSPlan)
	mux.HandleFunc("/api/dnspod/config", a.handleDNSPodConfig)
	mux.HandleFunc("/api/dnspod/apply", a.handleDNSPodApply)
	return a.authMiddleware(mux)
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "probe" {
		flags := flag.NewFlagSet("active-ip-sniffer probe", flag.ExitOnError)
		host := flags.String("host", "127.0.0.1", "local probe listen address; loopback only")
		port := flags.Int("port", defaultProbePort, "local probe listen port")
		token := flags.String("token", "", "optional local probe token; generated when empty")
		_ = flags.Parse(os.Args[2:])
		if err := runProbeServer(*host, *port, *token); err != nil {
			log.Fatal(err)
		}
		return
	}
	if isSetupInvocation(os.Args) {
		if err := runSetupWizard(); err != nil {
			log.Fatal(err)
		}
		return
	}
	args := os.Args[1:]
	if len(args) > 0 && args[0] == "serve" {
		args = args[1:]
	}
	flags := flag.NewFlagSet("active-ip-sniffer", flag.ExitOnError)
	host := flags.String("host", defaultListenHost, "listen address")
	port := flags.Int("port", defaultListenPort, "WebUI listen port")
	dataDir := flags.String("data-dir", defaultDataDir(), "result directory")
	configPath := flags.String("config", defaultConfigPath(), "persistent configuration file")
	_ = flags.Parse(args)
	if err := runServer(*host, *port, *dataDir, *configPath); err != nil {
		log.Fatal(err)
	}
}

func runServer(host string, port int, dataDir, configPath string) error {
	if port < 1 || port > 65535 {
		return errors.New("--port must be between 1 and 65535")
	}
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		return fmt.Errorf("create data directory: %w", err)
	}
	configureIPMetadataCache(dataDir)
	cleanupResultDirectory(dataDir, time.Now())
	settings, err := newSettingsStore(configPath)
	if err != nil {
		return fmt.Errorf("load config %s: %w", configPath, err)
	}
	application := &app{store: newJobStore(), dataDir: dataDir, settings: settings, public: newPublicBenchmarkStore(dataDir)}
	cleanupStop := make(chan struct{})
	go func() {
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-cleanupStop:
				return
			case now := <-ticker.C:
				application.store.cleanupOld(now)
				vlessBenchJobs.cleanupOld(now)
				cfSpeedJobs.cleanupOld(now)
				cleanupResultDirectory(dataDir, now)
			}
		}
	}()
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		var lastAttempt time.Time
		for {
			select {
			case <-cleanupStop:
				return
			case now := <-ticker.C:
				cfg := settings.snapshot().DNSPod
				if !cfg.AutoApply || !cfg.configured() || (!lastAttempt.IsZero() && now.Sub(lastAttempt) < time.Duration(cfg.IntervalMinutes)*time.Minute) {
					continue
				}
				lastAttempt = now
				plans := application.public.smartPlan(cfg.TopN)
				ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
				changes, applyErr := applyDNSPodPlan(ctx, cfg, plans)
				cancel()
				if applyErr != nil {
					log.Printf("DNSPod auto apply skipped/failed: %v", applyErr)
					continue
				}
				log.Printf("DNSPod smart DNS auto apply: %d change(s)", len(changes))
			}
		}
	}()
	address := net.JoinHostPort(host, strconv.Itoa(port))
	adminServer := &http.Server{Addr: address, Handler: application.routes(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second}
	cfg := settings.snapshot()
	var publicServer *http.Server
	if cfg.PublicEnabled {
		if cfg.PublicPort == port {
			close(cleanupStop)
			return errors.New("public benchmark port must differ from admin WebUI port")
		}
		publicAddress := net.JoinHostPort(host, strconv.Itoa(cfg.PublicPort))
		publicServer = &http.Server{Addr: publicAddress, Handler: application.publicRoutes(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second}
		log.Printf("Public benchmark WebUI: http://%s", publicAddress)
	}
	log.Printf("Active IP Sniffer %s (Go): http://%s", appVersion, address)
	log.Printf("results: %s", dataDir)
	log.Printf("config: %s", configPath)
	log.Printf("Use only on networks you own or are explicitly authorized to assess.")
	errCh := make(chan error, 2)
	serve := func(name string, server *http.Server) {
		err := server.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		if err != nil {
			err = fmt.Errorf("%s listener: %w", name, err)
		}
		errCh <- err
	}
	go serve("admin", adminServer)
	if publicServer != nil {
		go serve("public", publicServer)
	}
	serverErr := <-errCh
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 3*time.Second)
	_ = adminServer.Shutdown(shutdownCtx)
	if publicServer != nil {
		_ = publicServer.Shutdown(shutdownCtx)
	}
	shutdownCancel()
	close(cleanupStop)
	application.store.cancelAll()
	vlessBenchJobs.cancelAll()
	cfSpeedJobs.cancelAll()
	return serverErr
}

const legacyIndexHTML = `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Active IP Sniffer</title>
<style>
:root{color-scheme:light;--bg:#f4f6f8;--card:#fff;--ink:#17202a;--muted:#667085;--line:#d8dee6;--accent:#087f5b;--danger:#c92a2a}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 system-ui,"Segoe UI",sans-serif}header{height:58px;background:#17202a;color:white;display:flex;align-items:center;justify-content:space-between;padding:0 22px}.app{max-width:1180px;margin:0 auto;padding:18px}.card{background:var(--card);border:1px solid var(--line);border-radius:8px;margin-bottom:14px}.card h2{font-size:14px;margin:0;padding:12px 14px;border-bottom:1px solid var(--line)}.body{padding:14px}.grid{display:grid;grid-template-columns:repeat(12,1fr);gap:12px}.s12{grid-column:span 12}.s6{grid-column:span 6}.s3{grid-column:span 3}.field label{display:block;font-size:12px;font-weight:700;color:#475467;margin:0 0 6px}.field input,.field textarea{width:100%;border:1px solid #cbd3dd;border-radius:5px;padding:9px 10px;background:white;min-height:38px}.field textarea{min-height:130px;resize:vertical;font-family:ui-monospace,Consolas,monospace}.row{display:flex;gap:9px;align-items:center;flex-wrap:wrap}.actions{display:flex;justify-content:space-between;gap:10px;align-items:center}.btn{border:1px solid transparent;border-radius:5px;padding:9px 14px;font-weight:700;cursor:pointer}.primary{background:var(--accent);color:#fff}.secondary{background:#fff;border-color:#b8c1cc}.danger{background:#fff;border-color:#ffa8a8;color:var(--danger)}.btn:disabled{opacity:.45;cursor:not-allowed}.metric{display:grid;grid-template-columns:150px 1fr 75px;align-items:center;gap:12px}.track{height:9px;background:#e9ecef;border-radius:5px;overflow:hidden}.fill{height:100%;width:0;background:var(--accent);transition:width .2s}.muted{color:var(--muted)}.notice{padding:9px 11px;background:#edf8fa;border-left:3px solid #0b7285;font-size:12px;color:#38515a}.table-wrap{max-height:430px;overflow:auto}table{width:100%;border-collapse:collapse;font-variant-numeric:tabular-nums}th,td{padding:9px 11px;border-bottom:1px solid #e9edf2;text-align:left;white-space:nowrap}th{position:sticky;top:0;background:#f8f9fa;font-size:11px;text-transform:uppercase;color:#596579}.ok{color:#087f5b}.bad{color:#c92a2a}.hidden{display:none!important}@media(max-width:720px){.s12,.s6,.s3{grid-column:span 12}.actions{flex-direction:column;align-items:stretch}.metric{grid-template-columns:105px 1fr 55px}}
</style></head><body>
<header><strong>Active IP Sniffer</strong><span id="version">Go v2.1.0</span></header>
<main class="app">
  <section class="card"><h2>扫描参数</h2><div class="body grid">
    <div class="field s6"><label>目标（单 IP / CIDR / 起止范围，可混合）</label><textarea id="targets" placeholder="103.117.100.0/22&#10;203.0.113.10-203.0.113.50&#10;198.51.100.8"></textarea></div>
    <div class="field s6"><label>TCP 端口</label><input id="ports" value="80,443"><div style="height:10px"></div><label>说明</label><div class="notice">Go 流式扫描：不会把全部 IPv4 一次性展开到内存。IPv4 数量不设固定硬上限；一次最多 32 个端口、2,000,000 次连接尝试。页面仅保留最近 500 个命中 IP，全量结果直接落盘并可导出。</div></div>
    <div class="field s3"><label>超时（秒）</label><input id="timeout" type="number" min="0.05" max="5" step="0.05" value="0.8"></div>
    <div class="field s3"><label>并发</label><input id="workers" type="number" min="1" max="512" value="64"></div>
    <div class="field s3"><label>速率（连接/秒）</label><input id="rate" type="number" min="1" max="5000" value="500"></div>
    <div class="s3 actions"><button id="cancel" class="btn danger" disabled>停止</button><button id="start" class="btn primary">开始扫描</button></div>
  </div></section>
  <section id="progressCard" class="card hidden"><h2>进度</h2><div class="body"><div class="metric"><strong id="found">发现 0 个 IP</strong><div class="track"><div id="fill" class="fill"></div></div><span id="pct">0%</span></div><div id="status" class="muted" style="margin-top:10px">等待扫描</div></div></section>
  <section id="resultCard" class="card hidden"><h2>结果</h2><div class="body actions"><span id="resultMeta" class="muted"></span><div class="row"><button id="sendToBench" class="btn secondary" disabled>填入 VLESS 测试</button><button id="copy" class="btn secondary" disabled>复制全部 IP</button><button id="export" class="btn secondary" disabled>导出 CSV</button></div></div><div class="table-wrap"><table><thead><tr><th>#</th><th>IP</th><th>开放端口</th></tr></thead><tbody id="rows"></tbody></table></div></section>
  <section class="card"><h2>VLESS Endpoint Bench</h2><div class="body grid">
    <div class="field s6"><label>候选 IPv4（每行或逗号分隔）</label><textarea id="benchTargets" placeholder="8.217.238.203&#10;8.210.214.167&#10;47.242.87.115"></textarea></div>
    <div class="field s6"><label>VLESS TLS+WS 连接</label><input id="benchURI" type="password" autocomplete="off" placeholder="vless://UUID@IP:443?...&security=tls&type=ws&host=...&path=..."><div style="height:10px"></div><div class="notice">候选 IP 只替换连接地址；UUID、端口、SNI、Host、Path 全部沿用 VLESS 链接。测试依次验证 TCP → TLS/WS 101 → VLESS 实际出站 → speed.cloudflare.com 下载。测速串行执行，避免多个候选同时抢带宽。VLESS 链接仅保存在本次任务内存中，不写 CSV、不写日志。</div></div>
    <div class="field s3"><label>每个 IP 下载（MB）</label><input id="benchMB" type="number" min="1" max="100" value="30"></div>
    <div class="field s3"><label>阶段超时（秒）</label><input id="benchTimeout" type="number" min="2" max="20" step="1" value="12"></div>
    <div class="s6 actions"><span class="muted">最多 128 个候选；TCP 启动取 3 次中位数。</span><div class="row"><button id="benchCancel" class="btn danger" disabled>停止测试</button><button id="benchStart" class="btn primary">开始测试</button></div></div>
  </div></section>
  <section id="benchProgressCard" class="card hidden"><h2>VLESS 测试进度</h2><div class="body"><div class="metric"><strong id="benchPassed">通过 0 个 IP</strong><div class="track"><div id="benchFill" class="fill"></div></div><span id="benchPct">0%</span></div><div id="benchStatus" class="muted" style="margin-top:10px">等待测试</div></div></section>
  <section id="benchResultCard" class="card hidden"><h2>VLESS 测试结果</h2><div class="body actions"><span id="benchMeta" class="muted"></span><button id="benchExport" class="btn secondary" disabled>导出测速 CSV</button></div><div class="table-wrap"><table><thead><tr><th>#</th><th>IP</th><th>TCP</th><th>TCP 中位</th><th>TLS/WS</th><th>VLESS 启动</th><th>前 1s</th><th>前 3s</th><th>稳定</th><th>峰值</th><th>结果</th></tr></thead><tbody id="benchRows"></tbody></table></div></section>
</main>
<script>
const $=s=>document.querySelector(s);let job=null,poller=null,benchJob=null,benchPoller=null;
function value(id){return $(id).value.trim()}function number(id){return Number(value(id))}
function render(x){const items=x.results||[];$('#rows').innerHTML=items.map((r,i)=>'<tr><td>'+(i+1)+'</td><td class="ok">'+r.ip+'</td><td>'+r.ports.join(', ')+'</td></tr>').join('');$('#copy').disabled=!(x.found_ips>0);$('#sendToBench').disabled=!(x.found_ips>0);$('#export').disabled=!(x.open_ports>0);$('#resultMeta').textContent=(x.found_ips||0)+' 个 IP / '+(x.open_ports||0)+' 个开放端口'+(x.truncated?' · 页面显示最近 500 个':'')}
$('#start').onclick=async()=>{const targets=value('#targets').split(/[\s,;]+/).filter(Boolean);const ports=value('#ports').split(/[\s,;]+/).filter(Boolean).map(Number);if(!targets.length)return alert('请输入目标');if(!ports.length)return alert('请输入端口');const body={targets,ports,timeout:number('#timeout'),workers:number('#workers'),rate:number('#rate')};const r=await fetch('/api/scan/start',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});const x=await r.json();if(!r.ok)return alert(x.error||'启动失败');job=x.id;$('#start').disabled=true;$('#cancel').disabled=false;$('#progressCard').classList.remove('hidden');$('#resultCard').classList.remove('hidden');$('#status').textContent='目标包含 '+x.hosts.toLocaleString()+' 个 IPv4，共 '+x.attempts.toLocaleString()+' 次连接尝试';poller=setInterval(poll,500);poll()};
$('#cancel').onclick=async()=>{if(job)await fetch('/api/scan/cancel?id='+encodeURIComponent(job),{method:'POST'})};
async function poll(){if(!job)return;const r=await fetch('/api/scan/job?id='+encodeURIComponent(job));if(!r.ok)return;const x=await r.json();const p=x.total?Math.round(x.done*100/x.total):0;$('#fill').style.width=p+'%';$('#pct').textContent=p+'%';$('#found').textContent='发现 '+(x.found_ips||0).toLocaleString()+' 个 IP';$('#status').textContent=x.done.toLocaleString()+'/'+x.total.toLocaleString()+' 次连接尝试 · '+x.status+(x.message?' · '+x.message:'');render(x);if(['complete','failed','cancelled'].includes(x.status)){clearInterval(poller);$('#start').disabled=false;$('#cancel').disabled=true}}
$('#export').onclick=()=>{if(job)location.href='/api/scan/export.csv?id='+encodeURIComponent(job)};
$('#copy').onclick=async()=>{if(!job)return;const r=await fetch('/api/scan/export.txt?id='+encodeURIComponent(job));if(!r.ok)return alert('读取结果失败');await navigator.clipboard.writeText(await r.text());$('#copy').textContent='已复制';setTimeout(()=>$('#copy').textContent='复制全部 IP',1000)};
$('#sendToBench').onclick=async()=>{if(!job)return;const r=await fetch('/api/scan/export.txt?id='+encodeURIComponent(job));if(!r.ok)return alert('读取结果失败');$('#benchTargets').value=(await r.text()).trim();$('#benchTargets').scrollIntoView({behavior:'smooth',block:'center'})};
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const mbps=n=>(Number(n)||0).toFixed(1)+' Mbps';const ms=n=>(Number(n)||0).toFixed(1)+' ms';
function renderBench(x){const items=x.results||[];$('#benchRows').innerHTML=items.map((r,i)=>{const good=r.status==='ok';const detail=good?'通过':((r.failure_stage?esc(r.failure_stage)+': ':'')+esc(r.error||'失败'));return '<tr><td>'+(i+1)+'</td><td class="'+(good?'ok':'bad')+'">'+esc(r.ip)+'</td><td>'+r.tcp_passed+'/'+r.tcp_attempts+'</td><td>'+ms(r.tcp_median_ms)+'</td><td>'+(r.transport_ok?ms(r.transport_ms):'失败')+'</td><td>'+(r.vless_ok?ms(r.startup_ms):'失败')+'</td><td>'+mbps(r.first_1s_mbps)+'</td><td>'+mbps(r.first_3s_mbps)+'</td><td>'+mbps(r.stable_mbps)+'</td><td>'+mbps(r.peak_mbps)+'</td><td class="'+(good?'ok':'bad')+'">'+detail+'</td></tr>'}).join('');$('#benchExport').disabled=!items.length;$('#benchMeta').textContent=(x.passed||0)+'/'+(x.total||0)+' 个 IP 通过完整 VLESS+下载验证'}
$('#benchStart').onclick=async()=>{const candidates=value('#benchTargets').split(/[\s,;]+/).filter(Boolean);const vless=value('#benchURI');if(!candidates.length)return alert('请输入候选 IP');if(!vless)return alert('请输入 VLESS 连接');const body={vless,candidates,bytes_mb:number('#benchMB'),timeout:number('#benchTimeout')};const r=await fetch('/api/vless/start',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});const x=await r.json();if(!r.ok)return alert(x.error||'VLESS 测试启动失败');benchJob=x.id;$('#benchStart').disabled=true;$('#benchCancel').disabled=false;$('#benchProgressCard').classList.remove('hidden');$('#benchResultCard').classList.remove('hidden');$('#benchStatus').textContent='正在串行测试 '+x.candidates+' 个候选；每个成功候选下载 '+x.bytes_mb+' MB';benchPoller=setInterval(pollBench,700);pollBench()};
$('#benchCancel').onclick=async()=>{if(benchJob)await fetch('/api/vless/cancel?id='+encodeURIComponent(benchJob),{method:'POST'})};
async function pollBench(){if(!benchJob)return;const r=await fetch('/api/vless/job?id='+encodeURIComponent(benchJob));if(!r.ok)return;const x=await r.json();const p=x.total?Math.round(x.done*100/x.total):0;$('#benchFill').style.width=p+'%';$('#benchPct').textContent=p+'%';$('#benchPassed').textContent='通过 '+(x.passed||0)+' 个 IP';$('#benchStatus').textContent=x.done+'/'+x.total+' · '+x.status+(x.message?' · '+x.message:'');renderBench(x);if(['complete','cancelled','failed'].includes(x.status)){clearInterval(benchPoller);$('#benchStart').disabled=false;$('#benchCancel').disabled=true}}
$('#benchExport').onclick=()=>{if(benchJob)location.href='/api/vless/export.csv?id='+encodeURIComponent(benchJob)};
fetch('/api/info').then(r=>r.json()).then(x=>$('#version').textContent='Go v'+x.version);
</script></body></html>`

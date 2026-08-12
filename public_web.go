package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	publicPrecisionMB     = 30
)

func publicRequestBaseURL(r *http.Request) (string, bool) {
	host := strings.TrimSpace(r.Host)
	if host == "" {
		return "", false
	}
	for _, ch := range host {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || strings.ContainsRune(".-:[]", ch) {
			continue
		}
		return "", false
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	} else if strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https") {
		scheme = "https"
	}
	return scheme + "://" + host, true
}

type publicCandidate struct {
	IP   string     `json:"ip"`
	Port int        `json:"port"`
	Meta ipMetadata `json:"meta,omitempty"`
}

type publicCandidateHealth struct {
	IP        string     `json:"ip"`
	Port      int        `json:"port"`
	Meta      ipMetadata `json:"meta,omitempty"`
	Reachable bool       `json:"reachable"`
	TCPMs     float64    `json:"tcp_ms,omitempty"`
	Error     string     `json:"error,omitempty"`
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

func publicCandidateKey(ip string, port int) string {
	return net.JoinHostPort(strings.TrimSpace(ip), strconv.Itoa(port))
}

func normalizePublicCandidate(item publicCandidate) (publicCandidate, bool) {
	ip := net.ParseIP(strings.TrimSpace(item.IP))
	if ip == nil || ip.To4() == nil {
		return publicCandidate{}, false
	}
	if !validCFHTTPSPort(item.Port) {
		item.Port = 443
	}
	item.IP = ip.To4().String()
	item.Meta = normalizeMetadata(item.Meta)
	item.Meta.IP = item.IP
	return item, true
}

func parsePublicCandidateTargets(targets []string) ([]publicCandidate, error) {
	items := make([]publicCandidate, 0, len(targets))
	seen := make(map[string]struct{})
	for _, raw := range targets {
		host, port, err := splitEndpointPort(raw, 443)
		if err != nil {
			return nil, err
		}
		ip := net.ParseIP(strings.TrimSpace(host))
		if ip == nil || ip.To4() == nil {
			return nil, fmt.Errorf("invalid public benchmark IPv4: %s", raw)
		}
		item, _ := normalizePublicCandidate(publicCandidate{IP: ip.To4().String(), Port: port})
		key := publicCandidateKey(item.IP, item.Port)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		items = append(items, item)
		if len(items) > publicCandidateLimit {
			return nil, fmt.Errorf("public benchmark candidates exceed %d", publicCandidateLimit)
		}
	}
	if len(items) == 0 {
		return nil, errors.New("provide at least one public benchmark IPv4")
	}
	return items, nil
}

func (s *publicBenchmarkStore) publish(items []publicCandidate) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing := make(map[string]publicCandidate, len(s.state.Candidates))
	for _, item := range s.state.Candidates {
		existing[publicCandidateKey(item.IP, item.Port)] = item
	}
	seen := make(map[string]struct{})
	clean := make([]publicCandidate, 0, len(items))
	for _, raw := range items {
		item, ok := normalizePublicCandidate(raw)
		if !ok {
			continue
		}
		key := publicCandidateKey(item.IP, item.Port)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		if old, ok := existing[key]; ok && !metadataMeaningful(item.Meta) && metadataMeaningful(old.Meta) {
			item.Meta = old.Meta
		}
		clean = append(clean, item)
		if len(clean) >= publicCandidateLimit {
			break
		}
	}
	if len(clean) == 0 {
		return errors.New("no valid public benchmark candidates")
	}
	s.state.Candidates = clean
	return s.persistLocked()
}

func (s *publicBenchmarkStore) appendCandidates(items []publicCandidate) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	clean := append([]publicCandidate(nil), s.state.Candidates...)
	index := make(map[string]int, len(clean))
	for i, item := range clean {
		index[publicCandidateKey(item.IP, item.Port)] = i
	}
	added := 0
	for _, raw := range items {
		item, ok := normalizePublicCandidate(raw)
		if !ok {
			continue
		}
		key := publicCandidateKey(item.IP, item.Port)
		if i, ok := index[key]; ok {
			if metadataMeaningful(item.Meta) {
				clean[i].Meta = item.Meta
			}
			continue
		}
		if len(clean) >= publicCandidateLimit {
			return added, fmt.Errorf("public benchmark candidates exceed %d", publicCandidateLimit)
		}
		index[key] = len(clean)
		clean = append(clean, item)
		added++
	}
	if added == 0 {
		return 0, nil
	}
	s.state.Candidates = clean
	return added, s.persistLocked()
}

func (s *publicBenchmarkStore) deleteCandidate(ip string, port int) (bool, error) {
	item, ok := normalizePublicCandidate(publicCandidate{IP: ip, Port: port})
	if !ok {
		return false, errors.New("invalid public benchmark candidate")
	}
	key := publicCandidateKey(item.IP, item.Port)
	s.mu.Lock()
	defer s.mu.Unlock()
	clean := make([]publicCandidate, 0, len(s.state.Candidates))
	removed := false
	for _, current := range s.state.Candidates {
		if publicCandidateKey(current.IP, current.Port) == key {
			removed = true
			continue
		}
		clean = append(clean, current)
	}
	if !removed {
		return false, nil
	}
	s.state.Candidates = clean
	return true, s.persistLocked()
}

func (s *publicBenchmarkStore) removeCandidateKeys(keys map[string]struct{}) (int, error) {
	if len(keys) == 0 {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	clean := make([]publicCandidate, 0, len(s.state.Candidates))
	removed := 0
	for _, item := range s.state.Candidates {
		if _, ok := keys[publicCandidateKey(item.IP, item.Port)]; ok {
			removed++
			continue
		}
		clean = append(clean, item)
	}
	if removed == 0 {
		return 0, nil
	}
	s.state.Candidates = clean
	return removed, s.persistLocked()
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

func checkPublicCandidateHealth(ctx context.Context, candidates []publicCandidate, egress egressConfig, timeout time.Duration) []publicCandidateHealth {
	results := make([]publicCandidateHealth, len(candidates))
	workers := 8
	if len(candidates) < workers {
		workers = len(candidates)
	}
	if workers < 1 {
		return results
	}
	tasks := make(chan int)
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for idx := range tasks {
				candidate := candidates[idx]
				result := publicCandidateHealth{IP: candidate.IP, Port: candidate.Port, Meta: candidate.Meta}
				started := time.Now()
				conn, err := egress.dialContext(ctx, "tcp", net.JoinHostPort(candidate.IP, strconv.Itoa(candidate.Port)), timeout)
				if err != nil {
					result.Error = err.Error()
					results[idx] = result
					continue
				}
				result.Reachable = true
				result.TCPMs = roundFloat(float64(time.Since(started).Microseconds())/1000, 1)
				_ = conn.Close()
				results[idx] = result
			}
		}()
	}
	for idx := range candidates {
		select {
		case <-ctx.Done():
			close(tasks)
			wg.Wait()
			return results
		case tasks <- idx:
		}
	}
	close(tasks)
	wg.Wait()
	return results
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

func (a *app) handlePublicCandidatesAdmin(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"items": a.public.candidates(), "limit": publicCandidateLimit})
	case http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, 128_000)
		defer r.Body.Close()
		var request struct {
			Targets []string `json:"targets"`
			Mode    string   `json:"mode"`
		}
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&request); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request: " + err.Error()})
			return
		}
		items, err := parsePublicCandidateTargets(request.Targets)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		mode := strings.ToLower(strings.TrimSpace(request.Mode))
		if mode == "" {
			mode = "append"
		}
		switch mode {
		case "append":
			added, err := a.public.appendCandidates(items)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"ok": true, "added": added, "count": len(a.public.candidates()), "items": a.public.candidates()})
		case "replace":
			if err := a.public.publish(items); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"ok": true, "count": len(a.public.candidates()), "items": a.public.candidates()})
		default:
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "mode must be append or replace"})
		}
	case http.MethodDelete:
		r.Body = http.MaxBytesReader(w, r.Body, 32_000)
		defer r.Body.Close()
		var request struct {
			IP   string `json:"ip"`
			Port int    `json:"port"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request: " + err.Error()})
			return
		}
		removed, err := a.public.deleteCandidate(request.IP, request.Port)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "removed": removed, "count": len(a.public.candidates()), "items": a.public.candidates()})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

func (a *app) handlePublicCandidateCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 32_000)
	defer r.Body.Close()
	var request struct {
		Prune      bool    `json:"prune"`
		Timeout    float64 `json:"timeout"`
		EgressMode string  `json:"egress_mode"`
		WARPProxy  string  `json:"warp_proxy"`
	}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request: " + err.Error()})
		return
	}
	candidates := a.public.candidates()
	if len(candidates) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "items": []publicCandidateHealth{}, "removed": 0, "count": 0})
		return
	}
	requested, err := normalizeEgress(request.EgressMode, request.WARPProxy)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	selected, info, err := resolveScanEgress(ctx, requested)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	timeout := time.Duration(clampFloat(request.Timeout, 0.2, 5, 1.5) * float64(time.Second))
	health := checkPublicCandidateHealth(ctx, candidates, selected, timeout)
	removed := 0
	if request.Prune {
		unreachable := make(map[string]struct{})
		for _, item := range health {
			if !item.Reachable {
				unreachable[publicCandidateKey(item.IP, item.Port)] = struct{}{}
			}
		}
		removed, err = a.public.removeCandidateKeys(unreachable)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                    true,
		"items":                 health,
		"removed":               removed,
		"count":                 len(a.public.candidates()),
		"requested_egress_mode": requested.Mode,
		"egress_mode":           selected.Mode,
		"egress":                info,
	})
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
	mux.HandleFunc("/probe.sh", func(w http.ResponseWriter, r *http.Request) {
		base, ok := publicRequestBaseURL(r)
		if !ok {
			http.Error(w, "invalid host", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = io.WriteString(w, strings.ReplaceAll(userProbeShellScript, "__AIS_USER_WEB_URL__", base))
	})
	mux.HandleFunc("/probe.ps1", func(w http.ResponseWriter, r *http.Request) {
		base, ok := publicRequestBaseURL(r)
		if !ok {
			http.Error(w, "invalid host", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = io.WriteString(w, strings.ReplaceAll(userProbePowerShellScript, "__AIS_USER_WEB_URL__", base))
	})
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
		writeJSON(w, http.StatusOK, map[string]any{"items": a.public.candidates(), "precision_mb": publicPrecisionMB, "quick_mb": 1, "quick_timeout_s": 2, "precision_timeout_s": 5, "app_version": appVersion, "probe_port": defaultProbePort, "default_egress_mode": "direct"})
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
body{margin:0;background:#f4f6f9;color:#18202b;font:14px/1.55 system-ui,"Segoe UI","Microsoft YaHei",sans-serif}.wrap{max-width:940px;margin:auto;padding:18px}.card{background:#fff;border:1px solid #dfe4eb;border-radius:12px;margin-bottom:14px;padding:17px}.row{display:flex;gap:9px;align-items:center;flex-wrap:wrap}button{font:inherit;padding:9px 12px;border:1px solid #2563eb;border-radius:7px;font-weight:700;cursor:pointer;background:#2563eb;color:#fff}button.secondary{background:#fff;color:#1f2937;border-color:#cbd3dd}button:disabled{opacity:.45}.note{font-size:12px;color:#667085}.good{color:#087f5b}.bad{color:#c24141}.warn{background:#fff7ed;border:1px solid #fed7aa;border-radius:9px;padding:12px;color:#9a3412}.code{display:flex;align-items:center;gap:8px;background:#101827;color:#e5edf8;border-radius:8px;padding:10px;margin-top:7px;overflow:auto}.code code{flex:1;white-space:nowrap}.code button{padding:5px 9px;background:#fff;color:#111827;border:0}.bar{height:9px;background:#e8edf3;border-radius:99px;overflow:hidden;margin-top:10px}.fill{height:100%;background:#2563eb;width:0}table{width:100%;border-collapse:collapse}th,td{padding:9px;border-bottom:1px solid #edf0f4;text-align:left}.pill{display:inline-block;padding:3px 8px;border-radius:99px;background:#eef2ff;color:#3730a3;font-size:12px}</style></head><body><div class="wrap">
<div class="card"><h2>优选 IP 用户本地测速</h2><div class="warn"><b>测速前请关闭 VPN、系统 WARP、代理软件和浏览器代理插件。</b><br>测速必须走你的真实 Wi-Fi / 家宽 / 蜂窝网络，否则提交结果代表 VPN/代理出口，而不是你的运营商线路。测速会消耗本机流量。</div><p>用户测速固定使用 <b>Direct</b>：1 MB 必须在 2 秒内完成，随后 30 MB 必须在 5 秒内完成；超时直接淘汰。候选 IP 在页面中仅显示前两个 IPv4 段。</p><p id="state" class="note">尚未连接本地用户探针。执行下面与你系统对应的一条命令即可；脚本会自动下载轻量探针、启动 localhost 服务、打印本地端口并重新打开本页面，Token 会自动配置。</p></div>
<div id="install" class="card"><h3>一键启动用户探针</h3><b>Windows PowerShell</b><div class="code"><code id="cmdWin"></code><button data-copy="cmdWin">复制</button></div><br><b>Linux / macOS</b><div class="code"><code id="cmdUnix"></code><button data-copy="cmdUnix">复制</button></div><br><b>Android（Termux）</b><div class="code"><code id="cmdAndroid"></code><button data-copy="cmdAndroid">复制</button></div><p class="note">Android 首次使用需要 Termux；命令会安装 curl 后下载 arm64 用户探针。iOS 暂不在本版范围内。</p></div>
<div class="card"><div class="row"><span id="probeBadge" class="pill">探针未连接</span><button id="start" disabled>开始测速并提交 Top 5</button><span id="progress" class="note">候选加载中…</span></div><div class="bar"><div id="fill" class="fill"></div></div></div>
<div class="card"><h3>本次 Top 5</h3><table><thead><tr><th>#</th><th>候选 IP</th><th>峰值</th><th>平均</th><th>TTFB</th></tr></thead><tbody id="rows"></tbody></table></div>
</div><script>
const $=s=>document.querySelector(s);let probe='',token='',candidates=[],job='',probeEgress={},probeVersion='';
function maskIP(ip){const p=String(ip||'').split('.');if(p.length===4)return p[0]+'.'+p[1]+'.*.*';const h=String(ip||'').split(':');return h.slice(0,2).join(':')+':****'}
function setCommands(){const o=location.origin;$('#cmdWin').textContent='irm '+o+'/probe.ps1 | iex';$('#cmdUnix').textContent='curl -fsSL '+o+'/probe.sh | sh';$('#cmdAndroid').textContent='pkg install curl -y && curl -fsSL '+o+'/probe.sh | sh'}
function legacyCopy(text){const area=document.createElement('textarea');area.value=text;area.setAttribute('readonly','');area.style.position='fixed';area.style.left='-9999px';area.style.top='0';document.body.appendChild(area);area.focus();area.select();area.setSelectionRange(0,area.value.length);let ok=false;try{ok=document.execCommand('copy')}catch(e){}area.remove();return ok}
async function copyCode(id,button){const text=$('#'+id).textContent;let ok=false;try{if(navigator.clipboard&&window.isSecureContext){await navigator.clipboard.writeText(text);ok=true}}catch(e){}if(!ok)ok=legacyCopy(text);if(ok){button.textContent='已复制';setTimeout(()=>button.textContent='复制',900);return}window.prompt('浏览器禁止自动复制，请复制下面命令：',text)}
document.addEventListener('click',e=>{const b=e.target.closest('[data-copy]');if(b)copyCode(b.dataset.copy,b)});
function importLaunch(){const p=new URLSearchParams(location.hash.replace(/^#/,'')),port=p.get('probe_port'),t=p.get('probe_token');if(port&&t){sessionStorage.setItem('ais_user_probe_port',port);sessionStorage.setItem('ais_user_probe_token',t);history.replaceState(null,'',location.pathname+location.search)}const savedPort=port||sessionStorage.getItem('ais_user_probe_port'),savedToken=t||sessionStorage.getItem('ais_user_probe_token');if(savedPort&&savedToken){probe='http://127.0.0.1:'+savedPort;token=savedToken}}
async function pfetch(path,init={}){const h=new Headers(init.headers||{});h.set('X-Probe-Token',token);return fetch(probe+path,{...init,headers:h})}
async function readJSON(r,label){const text=await r.text();let x={};if(text.trim()){try{x=JSON.parse(text)}catch(e){const raw=text.trim().replace(/\s+/g,' ').slice(0,180);throw new Error(label+'返回非 JSON（HTTP '+r.status+'）：'+raw)}}if(!r.ok)throw new Error(x.error||label+'失败（HTTP '+r.status+'）');return x}
async function connectProbe(){if(!probe||token.length<16)return;try{const info=await readJSON(await pfetch('/api/info'),'本地探针信息');probeVersion=info.version||'';const net=await readJSON(await pfetch('/api/network-info'),'本地网络信息');probeEgress=net.egress||{};const warp=String(probeEgress.warp||'').toLowerCase();$('#probeBadge').textContent='探针 v'+probeVersion+' · '+maskIP(probeEgress.ip||'?')+' · '+(probeEgress.colo||'');if(warp==='on'||warp==='plus'){$('#state').className='note bad';$('#state').textContent='检测到本机系统 WARP 正在生效。请关闭 WARP/VPN 后再测速，避免结果污染。';$('#start').disabled=true;return}$('#state').className='note good';$('#state').textContent='本地用户探针已自动连接：'+probe+'。当前真实出口 '+maskIP(probeEgress.ip||'?')+' · '+(probeEgress.colo||'')+'。';$('#install').style.display='none';$('#start').disabled=!candidates.length}catch(e){$('#state').className='note bad';$('#state').textContent='本地探针连接失败：'+e.message+'。请重新执行一键命令。';$('#start').disabled=true}}
async function loadCandidates(){try{const x=await (await fetch('/api/candidates')).json();candidates=x.items||[];$('#progress').textContent=candidates.length?'已发布 '+candidates.length+' 个候选 · 1MB/2秒 → '+(x.precision_mb||30)+'MB/'+(x.precision_timeout_s||5)+'秒':'当前没有发布候选';if(probe&&token)await connectProbe()}catch(e){$('#progress').textContent='候选读取失败'}}
$('#start').onclick=async()=>{if(!candidates.length||!probe)return;$('#start').disabled=true;$('#rows').innerHTML='';const body={targets:candidates.map(x=>x.ip+':'+x.port),port:443,precision_mb:30,egress_mode:'direct'};try{const x=await readJSON(await pfetch('/api/cf-speed/start',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}),'测速启动');job=x.id;poll()}catch(e){$('#progress').textContent=e.message;$('#start').disabled=false}};
async function poll(){try{const x=await readJSON(await pfetch('/api/cf-speed/job?id='+encodeURIComponent(job)),'测速任务');let den=x.input_total||1,done=0;if(x.phase==='quick'){done=x.quick_done||0}else if(x.phase==='download'){den=x.selected||1;done=x.download_done||0}else if(x.phase==='prefilter'){done=x.prefilter_done||0}const pct=x.status==='complete'?100:Math.min(99,Math.round(done*100/den));$('#fill').style.width=pct+'%';$('#progress').textContent=(x.message||x.status)+' · '+pct+'%';if(x.status==='complete'){const top=(x.results||[]).filter(y=>y.status==='ok').slice(0,5);$('#rows').innerHTML=top.map((y,i)=>'<tr><td>'+(i+1)+'</td><td>'+maskIP(y.ip)+'</td><td>'+Number(y.peak_mbps||0).toFixed(1)+' Mbps</td><td>'+Number(y.average_mbps||0).toFixed(1)+' Mbps</td><td>'+Number(y.ttfb_ms||0).toFixed(1)+' ms</td></tr>').join('');if(!top.length){$('#progress').textContent='没有候选在规定时间内完成测速';$('#start').disabled=false;return}const s=await fetch('/api/submit',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({egress_mode:'direct',probe_egress:probeEgress,results:top})}),z=await s.json();$('#progress').textContent=s.ok?'测速完成，脱敏 Top 5 已显示，完整结果已提交总控':'测速完成，但提交失败：'+(z.error||'未知错误');$('#start').disabled=false;return}if(['failed','cancelled'].includes(x.status)){ $('#progress').textContent=x.message||x.status;$('#start').disabled=false;return}setTimeout(poll,600)}catch(e){$('#progress').textContent=e.message;$('#start').disabled=false}}
setCommands();importLaunch();loadCandidates();if(probe&&token)connectProbe();
</script></body></html>`

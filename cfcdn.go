package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	cfCDNDefaultIntervalSec         = 600
	cfCDNDefaultProbeBytes          = 500000
	cfCDNDefaultProbeTimeoutSec     = 10
	cfCDNDefaultRecoveryRounds      = 3
	cfCDNDefaultRecoveryIntervalSec = 60
	cfCDNMaxCandidates              = 256
)

type cfCDNSettings struct {
	Entries             []cfCDNEntry `json:"entries,omitempty"`
	IntervalSec         int          `json:"interval_s,omitempty"`
	ProbeBytes          int64        `json:"probe_bytes,omitempty"`
	ProbeTimeoutSec     int          `json:"probe_timeout_s,omitempty"`
	RecoveryRounds      int          `json:"recovery_rounds,omitempty"`
	RecoveryIntervalSec int          `json:"recovery_interval_s,omitempty"`
}

type cfCDNEntry struct {
	ID            string          `json:"id,omitempty"`
	ZoneID        string          `json:"zone_id,omitempty"`
	Zone          string          `json:"zone,omitempty"`
	RecordID      string          `json:"record_id,omitempty"`
	Domain        string          `json:"domain"`
	VLESS         string          `json:"vless"`
	Candidates    []string        `json:"candidates"`
	ActiveIP      string          `json:"active_ip,omitempty"`
	MaxLatencyMS  float64         `json:"max_latency_ms"`
	Enabled       bool            `json:"enabled"`
	CreatedAt     string          `json:"created_at,omitempty"`
	UpdatedAt     string          `json:"updated_at,omitempty"`
	LastCheckedAt string          `json:"last_checked_at,omitempty"`
	LastStatus    string          `json:"last_status,omitempty"`
	LastOriginal  json.RawMessage `json:"last_original,omitempty"`
	LastRound     json.RawMessage `json:"last_round,omitempty"`
	LastSwitch    json.RawMessage `json:"last_switch,omitempty"`
}

type cfCDNProbeView struct {
	IP           string  `json:"ip"`
	OK           bool    `json:"ok"`
	LatencyMS    float64 `json:"latency_ms,omitempty"`
	TCPMedianMS  float64 `json:"tcp_median_ms,omitempty"`
	TransportMS  float64 `json:"transport_ms,omitempty"`
	StartupMS    float64 `json:"startup_ms,omitempty"`
	StableMbps   float64 `json:"stable_mbps,omitempty"`
	PeakMbps     float64 `json:"peak_mbps,omitempty"`
	Status       string  `json:"status,omitempty"`
	FailureStage string  `json:"failure_stage,omitempty"`
	Error        string  `json:"error,omitempty"`
}

type cfCDNRoundView struct {
	Round   int              `json:"round"`
	Results []cfCDNProbeView `json:"results"`
}

type cfCDNSwitchView struct {
	At       string  `json:"at"`
	FromIP   string  `json:"from_ip,omitempty"`
	ToIP     string  `json:"to_ip,omitempty"`
	Reason   string  `json:"reason,omitempty"`
	Latency  float64 `json:"latency_ms,omitempty"`
	RecordID string  `json:"record_id,omitempty"`
}

type cfCDNMonitor struct {
	settings *settingsStore
	mu       sync.Mutex
	running  map[string]bool
}

func cfCDNID() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("cfcdn-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

func normalizeCFCDNSettings(cfg cfCDNSettings) cfCDNSettings {
	if cfg.IntervalSec <= 0 {
		cfg.IntervalSec = cfCDNDefaultIntervalSec
	}
	if cfg.ProbeBytes <= 0 {
		cfg.ProbeBytes = cfCDNDefaultProbeBytes
	}
	if cfg.ProbeTimeoutSec <= 0 {
		cfg.ProbeTimeoutSec = cfCDNDefaultProbeTimeoutSec
	}
	if cfg.RecoveryRounds <= 0 {
		cfg.RecoveryRounds = cfCDNDefaultRecoveryRounds
	}
	if cfg.RecoveryIntervalSec <= 0 {
		cfg.RecoveryIntervalSec = cfCDNDefaultRecoveryIntervalSec
	}
	seen := map[string]bool{}
	out := make([]cfCDNEntry, 0, len(cfg.Entries))
	for _, e := range cfg.Entries {
		n, err := normalizeCFCDNEntry(e, false)
		if err != nil || seen[n.Domain] {
			continue
		}
		seen[n.Domain] = true
		out = append(out, n)
	}
	cfg.Entries = out
	return cfg
}

func normalizeCFCDNEntry(e cfCDNEntry, requireCandidates bool) (cfCDNEntry, error) {
	e.VLESS = strings.TrimSpace(e.VLESS)
	if e.VLESS == "" {
		return e, errors.New("VLESS URL is required")
	}
	u, err := url.Parse(e.VLESS)
	if err != nil || !strings.EqualFold(u.Scheme, "vless") || strings.TrimSpace(u.Hostname()) == "" {
		return e, errors.New("invalid VLESS URL")
	}
	e.Domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(u.Hostname()), "."))
	if e.Domain == "" {
		return e, errors.New("invalid CFCDN domain")
	}
	if _, err := parseVLESSEndpoint(e.VLESS); err != nil {
		return e, err
	}
	ips, err := normalizeBenchCandidates(e.Candidates)
	if err != nil {
		if requireCandidates {
			return e, err
		}
		ips = nil
	}
	if len(ips) > cfCDNMaxCandidates {
		return e, fmt.Errorf("CFCDN candidates exceed %d", cfCDNMaxCandidates)
	}
	e.Candidates = ips
	if e.MaxLatencyMS <= 0 {
		e.MaxLatencyMS = 500
	}
	if ip := net.ParseIP(strings.TrimSpace(e.ActiveIP)); ip != nil && ip.To4() != nil {
		e.ActiveIP = ip.To4().String()
	} else {
		e.ActiveIP = ""
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if e.ID == "" {
		e.ID = cfCDNID()
	}
	if e.CreatedAt == "" {
		e.CreatedAt = now
	}
	if e.UpdatedAt == "" {
		e.UpdatedAt = e.CreatedAt
	}
	return e, nil
}

func cloneRaw(v json.RawMessage) json.RawMessage { return append(json.RawMessage(nil), v...) }
func cloneCFCDNEntry(e cfCDNEntry) cfCDNEntry {
	e.Candidates = append([]string(nil), e.Candidates...)
	e.LastOriginal = cloneRaw(e.LastOriginal)
	e.LastRound = cloneRaw(e.LastRound)
	e.LastSwitch = cloneRaw(e.LastSwitch)
	return e
}
func cloneCFCDNSettings(c cfCDNSettings) cfCDNSettings {
	c.Entries = append([]cfCDNEntry(nil), c.Entries...)
	for i := range c.Entries {
		c.Entries[i] = cloneCFCDNEntry(c.Entries[i])
	}
	return c
}

func cfCDNEntryIndex(entries []cfCDNEntry, domain string) int {
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	for i := range entries {
		if entries[i].Domain == domain {
			return i
		}
	}
	return -1
}

func (s *settingsStore) upsertCFCDNEntries(values []cfCDNEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.cfg
	next.CFCDN = cloneCFCDNSettings(next.CFCDN)
	for _, raw := range values {
		e, err := normalizeCFCDNEntry(raw, true)
		if err != nil {
			return err
		}
		e.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
		i := cfCDNEntryIndex(next.CFCDN.Entries, e.Domain)
		if i >= 0 {
			old := next.CFCDN.Entries[i]
			if e.ID == "" {
				e.ID = old.ID
			}
			if e.CreatedAt == "" {
				e.CreatedAt = old.CreatedAt
			}
			if e.ZoneID == "" {
				e.ZoneID = old.ZoneID
			}
			if e.Zone == "" {
				e.Zone = old.Zone
			}
			if e.RecordID == "" {
				e.RecordID = old.RecordID
			}
			if e.ActiveIP == "" {
				e.ActiveIP = old.ActiveIP
			}
			if len(e.LastOriginal) == 0 {
				e.LastOriginal = cloneRaw(old.LastOriginal)
			}
			if len(e.LastRound) == 0 {
				e.LastRound = cloneRaw(old.LastRound)
			}
			if len(e.LastSwitch) == 0 {
				e.LastSwitch = cloneRaw(old.LastSwitch)
			}
			if e.LastCheckedAt == "" {
				e.LastCheckedAt = old.LastCheckedAt
			}
			if e.LastStatus == "" {
				e.LastStatus = old.LastStatus
			}
			next.CFCDN.Entries[i] = e
		} else {
			next.CFCDN.Entries = append(next.CFCDN.Entries, e)
		}
	}
	next.CFCDN = normalizeCFCDNSettings(next.CFCDN)
	if err := savePersistedConfig(s.path, next); err != nil {
		return err
	}
	s.cfg = next
	return nil
}

func (s *settingsStore) replaceCFCDNEntry(domain string, mutate func(*cfCDNEntry) error) (cfCDNEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.cfg
	next.CFCDN = cloneCFCDNSettings(next.CFCDN)
	i := cfCDNEntryIndex(next.CFCDN.Entries, domain)
	if i < 0 {
		return cfCDNEntry{}, errors.New("CFCDN entry not found")
	}
	if err := mutate(&next.CFCDN.Entries[i]); err != nil {
		return cfCDNEntry{}, err
	}
	n, err := normalizeCFCDNEntry(next.CFCDN.Entries[i], true)
	if err != nil {
		return cfCDNEntry{}, err
	}
	next.CFCDN.Entries[i] = n
	if err := savePersistedConfig(s.path, next); err != nil {
		return cfCDNEntry{}, err
	}
	s.cfg = next
	return cloneCFCDNEntry(n), nil
}

func (s *settingsStore) deleteCFCDNEntry(domain string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.cfg
	next.CFCDN = cloneCFCDNSettings(next.CFCDN)
	i := cfCDNEntryIndex(next.CFCDN.Entries, domain)
	if i < 0 {
		return errors.New("CFCDN entry not found")
	}
	next.CFCDN.Entries = append(next.CFCDN.Entries[:i], next.CFCDN.Entries[i+1:]...)
	if err := savePersistedConfig(s.path, next); err != nil {
		return err
	}
	s.cfg = next
	return nil
}

func newCFCDNMonitor(settings *settingsStore) *cfCDNMonitor {
	return &cfCDNMonitor{settings: settings, running: map[string]bool{}}
}
func (m *cfCDNMonitor) start(stop <-chan struct{}) {
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case now := <-t.C:
				m.runDue(now)
			}
		}
	}()
}
func (m *cfCDNMonitor) runDue(now time.Time) {
	if m == nil || m.settings == nil {
		return
	}
	cfg := m.settings.snapshot().CFCDN
	for _, e := range cfg.Entries {
		if !e.Enabled || !cfCDNEntryDue(e, now, cfg.IntervalSec) {
			continue
		}
		_ = m.startEntry(e.Domain, false)
	}
}
func cfCDNEntryDue(e cfCDNEntry, now time.Time, intervalSec int) bool {
	if !e.Enabled {
		return false
	}
	if intervalSec <= 0 {
		intervalSec = cfCDNDefaultIntervalSec
	}
	t, err := time.Parse(time.RFC3339, e.LastCheckedAt)
	return err != nil || now.Sub(t) >= time.Duration(intervalSec)*time.Second
}
func (m *cfCDNMonitor) startEntry(domain string, manual bool) error {
	if m == nil {
		return errors.New("CFCDN monitor is unavailable")
	}
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	cfg := m.settings.snapshot().CFCDN
	i := cfCDNEntryIndex(cfg.Entries, domain)
	if i < 0 {
		return errors.New("CFCDN entry not found")
	}
	if !cfg.Entries[i].Enabled {
		return errors.New("CFCDN entry is disabled")
	}
	m.mu.Lock()
	if m.running[domain] {
		m.mu.Unlock()
		return errors.New("CFCDN check already running")
	}
	m.running[domain] = true
	m.mu.Unlock()
	go func() {
		defer func() { m.mu.Lock(); delete(m.running, domain); m.mu.Unlock() }()
		if err := m.runEntry(domain, manual); err != nil {
			_ = m.updateStatus(domain, "check_failed", err.Error(), nil, nil, nil)
		}
	}()
	return nil
}

func probeView(r vlessBenchResult) cfCDNProbeView {
	return cfCDNProbeView{IP: r.IP, OK: r.Status == "ok", LatencyMS: r.StartupMS, TCPMedianMS: r.TCPMedianMS, TransportMS: r.TransportMS, StartupMS: r.StartupMS, StableMbps: r.StableMbps, PeakMbps: r.PeakMbps, Status: r.Status, FailureStage: r.FailureStage, Error: r.Error}
}
func marshalRaw(v any) json.RawMessage { b, _ := json.Marshal(v); return b }

func (m *cfCDNMonitor) resolveEntry(e cfCDNEntry) (cfCDNEntry, cloudflareDomainStatus, cloudflareDNSRecord, error) {
	cfg := m.settings.snapshot()
	if strings.TrimSpace(cfg.Cloudflare.Token) == "" {
		return e, cloudflareDomainStatus{}, cloudflareDNSRecord{}, errors.New("Cloudflare token is not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	ss, err := resolveCloudflareDomains(ctx, cfg.Cloudflare.Token, []string{e.Domain})
	if err != nil || len(ss) != 1 {
		return e, cloudflareDomainStatus{}, cloudflareDNSRecord{}, fmt.Errorf("resolve managed A: %w", err)
	}
	st := ss[0]
	var rec cloudflareDNSRecord
	if e.RecordID != "" {
		for _, x := range st.A {
			if x.ID == e.RecordID {
				rec = x
				break
			}
		}
	}
	if rec.ID == "" {
		if len(st.A) != 1 {
			return e, st, rec, fmt.Errorf("CFCDN domain must have exactly one managed A record (got %d)", len(st.A))
		}
		rec = st.A[0]
	}
	e.ZoneID = st.ZoneID
	e.Zone = st.Zone
	e.RecordID = rec.ID
	e.ActiveIP = rec.Content
	return e, st, rec, nil
}

func runCFCDNRound(endpoint vlessEndpointConfig, candidates []string, activeIP string, bytes int64, timeout time.Duration, direct egressConfig) cfCDNRoundView {
	ips := make([]string, 0, len(candidates))
	for _, ip := range candidates {
		if ip != activeIP {
			ips = append(ips, ip)
		}
	}
	results := make([]cfCDNProbeView, len(ips))
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for i, ip := range ips {
		i, ip := i, ip
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			ctx, cancel := context.WithTimeout(context.Background(), timeout+15*time.Second)
			defer cancel()
			results[i] = probeView(runVLESSBenchCandidate(ctx, endpoint, ip, bytes, timeout, direct))
		}()
	}
	wg.Wait()
	return cfCDNRoundView{Results: results}
}

func (m *cfCDNMonitor) runEntry(domain string, manual bool) error {
	cfg := m.settings.snapshot()
	ci := cfCDNEntryIndex(cfg.CFCDN.Entries, domain)
	if ci < 0 {
		return errors.New("CFCDN entry not found")
	}
	e := cfg.CFCDN.Entries[ci]
	if !e.Enabled {
		return errors.New("CFCDN entry is disabled")
	}
	var err error
	e, cfStatus, _, err := m.resolveEntry(e)
	if err != nil {
		return err
	}
	endpoint, err := parseVLESSEndpoint(e.VLESS)
	if err != nil {
		return err
	}
	timeout := time.Duration(cfg.CFCDN.ProbeTimeoutSec) * time.Second
	direct := egressConfig{Mode: "direct", WARPProxy: defaultWARPProxy}
	ctx, cancel := context.WithTimeout(context.Background(), timeout+15*time.Second)
	active := runVLESSBenchCandidate(ctx, endpoint, e.ActiveIP, cfg.CFCDN.ProbeBytes, timeout, direct)
	cancel()
	original := probeView(active)
	activeGood := active.Status == "ok" && active.StartupMS > 0 && active.StartupMS <= e.MaxLatencyMS
	if activeGood {
		return m.updateStatusResolved(e, "within_threshold", "", original, nil, nil)
	}
	rounds := make([]cfCDNRoundView, 0, cfg.CFCDN.RecoveryRounds)
	pass := map[string]int{}
	latency := map[string]float64{}
	for round := 1; round <= cfg.CFCDN.RecoveryRounds; round++ {
		if round > 1 {
			time.Sleep(time.Duration(cfg.CFCDN.RecoveryIntervalSec) * time.Second)
		}
		rv := runCFCDNRound(endpoint, e.Candidates, e.ActiveIP, cfg.CFCDN.ProbeBytes, timeout, direct)
		rv.Round = round
		for _, v := range rv.Results {
			if v.OK && v.StartupMS > 0 && v.StartupMS <= e.MaxLatencyMS {
				pass[v.IP]++
				latency[v.IP] += v.StartupMS
			}
		}
		rounds = append(rounds, rv)
	}
	best, bestLatency := selectCFCDNCandidate(pass, latency, cfg.CFCDN.RecoveryRounds)
	if best == "" {
		return m.updateStatusResolved(e, "no_candidate_passed_all_rounds", "", original, rounds, nil)
	}
	// Re-probe active immediately before DNS mutation. If it recovered, keep the current A record.
	rctx, rcancel := context.WithTimeout(context.Background(), timeout+15*time.Second)
	recovered := runVLESSBenchCandidate(rctx, endpoint, e.ActiveIP, cfg.CFCDN.ProbeBytes, timeout, direct)
	rcancel()
	if recovered.Status == "ok" && recovered.StartupMS > 0 && recovered.StartupMS <= e.MaxLatencyMS {
		return m.updateStatusResolved(e, "active_ip_recovered", "", probeView(recovered), rounds, nil)
	}
	cfCfg := m.settings.snapshot().Cloudflare
	ctx2, cancel2 := context.WithTimeout(context.Background(), 20*time.Second)
	updated, err := updateCloudflareARecord(ctx2, cfCfg.Token, cfStatus, e.RecordID, best)
	cancel2()
	if err != nil {
		return m.updateStatusResolved(e, "no_recovery_switch", err.Error(), original, rounds, nil)
	}
	sw := cfCDNSwitchView{At: time.Now().UTC().Format(time.RFC3339), FromIP: e.ActiveIP, ToIP: updated.Content, Reason: "candidate", Latency: bestLatency, RecordID: e.RecordID}
	e.ActiveIP = updated.Content
	return m.updateStatusResolved(e, "candidate", "", original, rounds, &sw)
}

func selectCFCDNCandidate(pass map[string]int, latency map[string]float64, rounds int) (string, float64) {
	type item struct {
		ip  string
		avg float64
	}
	var xs []item
	for ip, n := range pass {
		if n == rounds && rounds > 0 {
			xs = append(xs, item{ip: ip, avg: latency[ip] / float64(rounds)})
		}
	}
	sort.Slice(xs, func(i, j int) bool {
		if xs[i].avg == xs[j].avg {
			return xs[i].ip < xs[j].ip
		}
		return xs[i].avg < xs[j].avg
	})
	if len(xs) == 0 {
		return "", 0
	}
	return xs[0].ip, xs[0].avg
}

func (m *cfCDNMonitor) updateStatus(domain, status, errText string, original *cfCDNProbeView, rounds []cfCDNRoundView, sw *cfCDNSwitchView) error {
	_, err := m.settings.replaceCFCDNEntry(domain, func(e *cfCDNEntry) error {
		e.LastCheckedAt = time.Now().UTC().Format(time.RFC3339)
		e.LastStatus = status
		if original != nil {
			e.LastOriginal = marshalRaw(original)
		}
		if rounds != nil {
			e.LastRound = marshalRaw(rounds)
		}
		if sw != nil {
			e.LastSwitch = marshalRaw(sw)
		}
		if errText != "" {
			e.LastRound = marshalRaw(map[string]any{"error": errText, "rounds": rounds})
		}
		return nil
	})
	return err
}
func (m *cfCDNMonitor) updateStatusResolved(e cfCDNEntry, status, errText string, original cfCDNProbeView, rounds []cfCDNRoundView, sw *cfCDNSwitchView) error {
	_, err := m.settings.replaceCFCDNEntry(e.Domain, func(x *cfCDNEntry) error {
		x.ZoneID = e.ZoneID
		x.Zone = e.Zone
		x.RecordID = e.RecordID
		x.ActiveIP = e.ActiveIP
		x.LastCheckedAt = time.Now().UTC().Format(time.RFC3339)
		x.LastStatus = status
		x.LastOriginal = marshalRaw(original)
		if rounds != nil {
			x.LastRound = marshalRaw(rounds)
		}
		if sw != nil {
			x.LastSwitch = marshalRaw(sw)
		}
		if errText != "" {
			x.LastRound = marshalRaw(map[string]any{"error": errText, "rounds": rounds})
		}
		return nil
	})
	return err
}

func (a *app) handleCFCDNConfig(w http.ResponseWriter, r *http.Request) {
	if a.settings == nil {
		writeJSON(w, 500, map[string]string{"error": "settings store unavailable"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		c := a.settings.snapshot().CFCDN
		writeJSON(w, 200, c)
	case http.MethodPost:
		var q struct {
			Entries []cfCDNEntry `json:"entries"`
		}
		if err := decodeJSONLimited(w, r, 512_000, &q); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		if len(q.Entries) == 0 {
			writeJSON(w, 400, map[string]string{"error": "no CFCDN entries"})
			return
		}
		prepared := make([]cfCDNEntry, 0, len(q.Entries))
		for _, raw := range q.Entries {
			e, err := normalizeCFCDNEntry(raw, true)
			if err != nil {
				writeJSON(w, 400, map[string]string{"error": err.Error()})
				return
			}
			e, _, _, err = a.cfcdn.resolveEntry(e)
			if err != nil {
				writeJSON(w, 400, map[string]string{"error": err.Error()})
				return
			}
			prepared = append(prepared, e)
		}
		if err := a.settings.upsertCFCDNEntries(prepared); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true})
	case http.MethodDelete:
		d := strings.TrimSpace(r.URL.Query().Get("domain"))
		if err := a.settings.deleteCFCDNEntry(d); err != nil {
			writeJSON(w, 404, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true})
	default:
		writeJSON(w, 405, map[string]string{"error": "method not allowed"})
	}
}
func (a *app) handleCFCDNUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]string{"error": "method not allowed"})
		return
	}
	domain := strings.TrimSpace(r.URL.Query().Get("domain"))
	var q struct {
		VLESS        string   `json:"vless"`
		Candidates   []string `json:"candidates"`
		MaxLatencyMS float64  `json:"max_latency_ms"`
		Enabled      bool     `json:"enabled"`
	}
	if err := decodeJSONLimited(w, r, 512_000, &q); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	_, err := a.settings.replaceCFCDNEntry(domain, func(e *cfCDNEntry) error {
		e.VLESS = q.VLESS
		e.Candidates = q.Candidates
		e.MaxLatencyMS = q.MaxLatencyMS
		e.Enabled = q.Enabled
		e.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
		return nil
	})
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}
func (a *app) handleCFCDNCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]string{"error": "method not allowed"})
		return
	}
	if a.cfcdn == nil {
		writeJSON(w, 500, map[string]string{"error": "CFCDN monitor is unavailable"})
		return
	}
	err := a.cfcdn.startEntry(r.URL.Query().Get("domain"), true)
	if err != nil {
		code := 409
		if strings.Contains(err.Error(), "not found") {
			code = 404
		}
		writeJSON(w, code, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 202, map[string]any{"ok": true, "started": true})
}

func decodeJSONLimited(w http.ResponseWriter, r *http.Request, max int64, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, max)
	defer r.Body.Close()
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(dst); err != nil {
		return fmt.Errorf("invalid request: %w", err)
	}
	return nil
}

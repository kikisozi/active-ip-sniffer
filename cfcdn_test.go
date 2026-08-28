package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testCFCDNVLESS() string {
	return "vless://11111111-2222-4333-8444-555555555555@example.invalid:443?encryption=none&security=tls&type=ws&host=edge.example.invalid&path=%2Fws"
}

func TestCFCDNDefaultsMatchV360(t *testing.T) {
	c := normalizeCFCDNSettings(cfCDNSettings{})
	if c.IntervalSec != 600 || c.ProbeBytes != 500000 || c.ProbeTimeoutSec != 10 || c.RecoveryRounds != 3 || c.RecoveryIntervalSec != 60 {
		t.Fatalf("defaults=%+v", c)
	}
}
func TestCFCDNEntryDerivesDomainAndDedupes(t *testing.T) {
	e, err := normalizeCFCDNEntry(cfCDNEntry{VLESS: testCFCDNVLESS(), Candidates: []string{"192.0.2.1", "192.0.2.1", "198.51.100.2"}}, true)
	if err != nil {
		t.Fatal(err)
	}
	if e.Domain != "example.invalid" || len(e.Candidates) != 2 || e.MaxLatencyMS != 500 || e.ID == "" {
		t.Fatalf("entry=%+v", e)
	}
}
func TestSelectCFCDNRequiresAllRounds(t *testing.T) {
	ip, lat := selectCFCDNCandidate(map[string]int{"192.0.2.1": 3, "198.51.100.2": 2, "203.0.113.3": 3}, map[string]float64{"192.0.2.1": 450, "198.51.100.2": 100, "203.0.113.3": 300}, 3)
	if ip != "203.0.113.3" || lat != 100 {
		t.Fatalf("ip=%s lat=%f", ip, lat)
	}
}
func TestCFCDNDisabledCheck409(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.json")
	cfg := persistedConfig{CFCDN: normalizeCFCDNSettings(cfCDNSettings{Entries: []cfCDNEntry{{VLESS: testCFCDNVLESS(), Candidates: []string{"192.0.2.1"}, Enabled: false}}})}
	if err := savePersistedConfig(p, cfg); err != nil {
		t.Fatal(err)
	}
	store, err := newSettingsStore(p)
	if err != nil {
		t.Fatal(err)
	}
	a := &app{settings: store}
	a.cfcdn = newCFCDNMonitor(store)
	r := httptest.NewRequest(http.MethodPost, "/api/cfcdn/check?domain=example.invalid", nil)
	w := httptest.NewRecorder()
	a.handleCFCDNCheck(w, r)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "disabled") {
		t.Fatalf("code=%d body=%s", w.Code, w.Body.String())
	}
}
func TestCFCDNLegacyConfigRoundTripPreservesRawState(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.json")
	raw := `{"host":"127.0.0.1","port":18766,"saved_vless":["one","two"],"cfcdn":{"entries":[{"id":"x","domain":"example.invalid","vless":"` + testCFCDNVLESS() + `","candidates":["192.0.2.1"],"enabled":false,"max_latency_ms":500,"last_original":{"ok":true,"latency_ms":123},"last_round":[{"round":1}],"last_switch":{"reason":"candidate"}}]}}`
	if err := os.WriteFile(p, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	store, err := newSettingsStore(p)
	if err != nil {
		t.Fatal(err)
	}
	snap := store.snapshot()
	if len(snap.SavedVLESS) != 2 || len(snap.CFCDN.Entries) != 1 {
		t.Fatalf("snapshot=%+v", snap)
	}
	e := snap.CFCDN.Entries[0]
	var o map[string]any
	if json.Unmarshal(e.LastOriginal, &o) != nil || o["ok"] != true {
		t.Fatalf("last_original=%s", e.LastOriginal)
	}
	if err := store.updateDNSPod(snap.DNSPod); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var after map[string]json.RawMessage
	if json.Unmarshal(b, &after) != nil {
		t.Fatal("bad saved json")
	}
	if _, ok := after["saved_vless"]; !ok {
		t.Fatal("saved_vless lost")
	}
	if _, ok := after["cfcdn"]; !ok {
		t.Fatal("cfcdn lost")
	}
}

func TestCFCDNNormalizePreservesUpdatedAt(t *testing.T) {
	in := cfCDNEntry{VLESS: testCFCDNVLESS(), Candidates: []string{"192.0.2.1"}, CreatedAt: "2026-08-15T00:00:00Z", UpdatedAt: "2026-08-16T00:00:00Z"}
	out, err := normalizeCFCDNEntry(in, true)
	if err != nil {
		t.Fatal(err)
	}
	if out.UpdatedAt != in.UpdatedAt || out.CreatedAt != in.CreatedAt {
		t.Fatalf("timestamps changed: %+v", out)
	}
}

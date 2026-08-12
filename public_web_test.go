package main

import (
	"context"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSmartDNSPlanUsesCarrierAndMedianPeak(t *testing.T) {
	now := time.Now()
	store := &publicBenchmarkStore{lastPost: make(map[string]time.Time)}
	store.state.Submissions = []publicSubmission{
		{SubmittedAt: now, ClientIP: "198.51.100.1", ClientMeta: ipMetadata{ISP: "China Telecom"}, Results: []cfSpeedResult{{IP: "47.242.1.1", Port: 443, Status: "ok", PeakMbps: 100, AverageMbps: 70}, {IP: "47.242.1.2", Port: 443, Status: "ok", PeakMbps: 55, AverageMbps: 50}}},
		{SubmittedAt: now, ClientIP: "198.51.100.2", ClientMeta: ipMetadata{Org: "CHINANET"}, Results: []cfSpeedResult{{IP: "47.242.1.1", Port: 443, Status: "ok", PeakMbps: 20, AverageMbps: 18}, {IP: "47.242.1.2", Port: 443, Status: "ok", PeakMbps: 50, AverageMbps: 45}}},
		{SubmittedAt: now, ClientIP: "198.51.100.3", ClientMeta: ipMetadata{ISP: "China Unicom"}, Results: []cfSpeedResult{{IP: "47.243.2.1", Port: 443, Status: "ok", PeakMbps: 80, AverageMbps: 60}}},
	}
	plans := store.smartPlan(3)
	var telecom, unicom *smartDNSLinePlan
	for i := range plans {
		switch plans[i].Line {
		case "电信":
			telecom = &plans[i]
		case "联通":
			unicom = &plans[i]
		}
	}
	if telecom == nil || telecom.Submitters != 2 || len(telecom.Candidates) != 2 {
		t.Fatalf("unexpected telecom plan: %#v", telecom)
	}
	if telecom.Candidates[0].IP != "47.242.1.1" || telecom.Candidates[0].MedianPeak != 60 {
		t.Fatalf("unexpected telecom ranking: %#v", telecom.Candidates)
	}
	if unicom == nil || unicom.Submitters != 1 || unicom.Candidates[0].IP != "47.243.2.1" {
		t.Fatalf("unexpected unicom plan: %#v", unicom)
	}
}

func TestPlanLinesForDNSPodMinimumSubmitters(t *testing.T) {
	plans := []smartDNSLinePlan{
		{Line: "电信", Submitters: 2, Candidates: []smartDNSCandidate{{IP: "1.1.1.1"}}},
		{Line: "联通", Submitters: 1, Candidates: []smartDNSCandidate{{IP: "2.2.2.2"}}},
	}
	desired := planLinesForDNSPod(plans, 2)
	if len(desired) != 1 || len(desired["电信"]) != 1 || desired["电信"][0] != "1.1.1.1" {
		t.Fatalf("unexpected desired lines: %#v", desired)
	}
}

func TestPublicProbeScriptsUseCurrentPublicOrigin(t *testing.T) {
	dir := t.TempDir()
	a := &app{public: newPublicBenchmarkStore(dir)}
	server := httptest.NewServer(a.publicRoutes())
	defer server.Close()
	for _, path := range []string{"/probe.sh", "/probe.ps1"} {
		response, err := server.Client().Get(server.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		data := make([]byte, 256*1024)
		n, readErr := response.Body.Read(data)
		_ = response.Body.Close()
		if readErr != nil && n == 0 {
			t.Fatalf("read %s: %v", path, readErr)
		}
		text := string(data[:n])
		if strings.Contains(text, "__AIS_USER_WEB_URL__") || !strings.Contains(text, server.URL) {
			t.Fatalf("%s did not embed server URL", path)
		}
	}
}

func TestPublicPowerShellProbeUsesSafeVariableBoundaries(t *testing.T) {
	if strings.Contains(userProbePowerShellScript, "$Branch?cb") || strings.Contains(userProbePowerShellScript, "$Ref/") || strings.Contains(userProbePowerShellScript, "$File?cb") {
		t.Fatal("PowerShell probe still contains ambiguous variable interpolation")
	}
	if !strings.Contains(userProbePowerShellScript, `"https://raw.githubusercontent.com/{0}/{1}/dist/SHA256SUMS?cb={2}" -f $Repo, $Branch, $CacheBust`) {
		t.Fatal("PowerShell probe is not using safe format-string URL construction")
	}
}

func TestPublicCandidateStoreAppendDelete(t *testing.T) {
	store := newPublicBenchmarkStore(t.TempDir())
	if err := store.publish([]publicCandidate{{IP: "192.0.2.1", Port: 443}}); err != nil {
		t.Fatal(err)
	}
	added, err := store.appendCandidates([]publicCandidate{{IP: "192.0.2.2", Port: 443}, {IP: "192.0.2.1", Port: 443}})
	if err != nil {
		t.Fatal(err)
	}
	if added != 1 || len(store.candidates()) != 2 {
		t.Fatalf("unexpected append: added=%d count=%d", added, len(store.candidates()))
	}
	removed, err := store.deleteCandidate("192.0.2.1", 443)
	if err != nil || !removed || len(store.candidates()) != 1 {
		t.Fatalf("unexpected delete: removed=%v err=%v count=%d", removed, err, len(store.candidates()))
	}
}

func TestCheckPublicCandidateHealth(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			_ = conn.Close()
		}
	}()
	port := listener.Addr().(*net.TCPAddr).Port
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	items := checkPublicCandidateHealth(ctx, []publicCandidate{{IP: "127.0.0.1", Port: port}}, egressConfig{Mode: "direct"}, time.Second)
	if len(items) != 1 || !items[0].Reachable || items[0].TCPMs < 0 {
		t.Fatalf("unexpected health result: %#v", items)
	}
}

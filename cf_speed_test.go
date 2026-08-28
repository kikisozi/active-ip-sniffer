package main

import "testing"

func TestParseCFSpeedTargets(t *testing.T) {
	ranges, total, err := parseCFSpeedTargets([]string{"8.8.8.8", "1.1.1.1:8443", "192.0.2.0/30"}, 443)
	if err != nil {
		t.Fatalf("parseCFSpeedTargets: %v", err)
	}
	// /30 follows the scanner behavior and excludes network/broadcast => 2 hosts.
	if total != 4 {
		t.Fatalf("total=%d, want 4", total)
	}
	if len(ranges) != 3 || ranges[0].port != 443 || ranges[1].port != 8443 || ranges[2].port != 443 {
		t.Fatalf("unexpected ranges: %#v", ranges)
	}
}

func TestParseCFSpeedTargetsRejectsUnsupportedPort(t *testing.T) {
	_, _, err := parseCFSpeedTargets([]string{"1.1.1.1:444"}, 443)
	if err == nil {
		t.Fatal("expected unsupported port error")
	}
}

func TestRankCFResults(t *testing.T) {
	values := []cfSpeedResult{
		{IP: "192.0.2.1", Status: "ok", AverageMbps: 80, PeakMbps: 100, TTFBMS: 300},
		{IP: "192.0.2.2", Status: "failed", AverageMbps: 0},
		{IP: "192.0.2.3", Status: "ok", AverageMbps: 100, PeakMbps: 90, TTFBMS: 400},
	}
	ranked := rankCFResults(values)
	if len(ranked) != 3 || ranked[0].IP != "192.0.2.1" || ranked[1].IP != "192.0.2.3" || ranked[2].IP != "192.0.2.2" {
		t.Fatalf("unexpected rank order: %#v", ranked)
	}
	for i := range ranked {
		if ranked[i].Rank != i+1 {
			t.Fatalf("rank[%d]=%d", i, ranked[i].Rank)
		}
	}
}

func TestRankCFResultsCapsAt20(t *testing.T) {
	values := make([]cfSpeedResult, 0, 25)
	for i := 0; i < 25; i++ {
		values = append(values, cfSpeedResult{IP: "192.0.2.1", Port: 443, Status: "ok", AverageMbps: float64(i), PeakMbps: float64(i)})
	}
	ranked := rankCFResults(values)
	if got := len(ranked); got != cfSpeedTopLimit {
		t.Fatalf("len=%d, want %d", got, cfSpeedTopLimit)
	}
	if ranked[0].PeakMbps != 24 || ranked[len(ranked)-1].PeakMbps != 5 {
		t.Fatalf("unexpected retained speed range: first=%.1f last=%.1f", ranked[0].AverageMbps, ranked[len(ranked)-1].AverageMbps)
	}
}

func TestCFSpeedJobKeepsOnlyCurrentTop20(t *testing.T) {
	job := &cfSpeedJob{}
	for i := 0; i < 35; i++ {
		job.addResult(cfSpeedResult{
			IP:          "192.0.2.1",
			Port:        443,
			Status:      "ok",
			AverageMbps: float64(i),
			PeakMbps:    float64(i + 10),
		})
	}
	if len(job.results) != cfSpeedTopLimit {
		t.Fatalf("job retained %d top results, want %d", len(job.results), cfSpeedTopLimit)
	}
	if len(job.usable) != 35 {
		t.Fatalf("job retained %d usable results, want 35", len(job.usable))
	}
	if job.results[0].PeakMbps != 44 || job.results[len(job.results)-1].PeakMbps != 25 {
		t.Fatalf("unexpected retained results: first=%.1f last=%.1f", job.results[0].AverageMbps, job.results[len(job.results)-1].AverageMbps)
	}
	all := job.exportResults("usable")
	if len(all) != 35 || all[0].PeakMbps != 44 || all[len(all)-1].PeakMbps != 10 {
		t.Fatalf("unexpected usable export: len=%d first=%.1f last=%.1f", len(all), all[0].PeakMbps, all[len(all)-1].PeakMbps)
	}
	if top := job.exportResults("top20"); len(top) != cfSpeedTopLimit {
		t.Fatalf("top export len=%d", len(top))
	}
}

func TestReadBenchEndpoint(t *testing.T) {
	endpoint, err := readBenchEndpoint("47.238.0.131,8443")
	if err != nil {
		t.Fatalf("readBenchEndpoint: %v", err)
	}
	if endpoint.IP != "47.238.0.131" || endpoint.Port != 8443 {
		t.Fatalf("unexpected endpoint: %#v", endpoint)
	}
	if _, err := readBenchEndpoint("47.238.0.131,444"); err == nil {
		t.Fatal("expected unsupported port error")
	}
}

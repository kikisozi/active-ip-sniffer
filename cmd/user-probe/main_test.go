package main

import "testing"

func TestParseEndpoint(t *testing.T) {
	ep, err := parseEndpoint("47.242.162.186:8443", 443)
	if err != nil {
		t.Fatal(err)
	}
	if ep.IP != "47.242.162.186" || ep.Port != 8443 {
		t.Fatalf("unexpected endpoint: %#v", ep)
	}
	ep, err = parseEndpoint("8.217.238.203", 443)
	if err != nil || ep.Port != 443 {
		t.Fatalf("default port failed: %#v %v", ep, err)
	}
}

func TestRankResultsPeakFirst(t *testing.T) {
	values := []result{
		{IP: "1.1.1.1", Status: "ok", PeakMbps: 100, AverageMbps: 90},
		{IP: "2.2.2.2", Status: "ok", PeakMbps: 120, AverageMbps: 60},
		{IP: "3.3.3.3", Status: "failed", PeakMbps: 900},
	}
	ranked := rankResults(values)
	if ranked[0].IP != "2.2.2.2" || ranked[1].IP != "1.1.1.1" || ranked[2].Status != "failed" {
		t.Fatalf("unexpected ranking: %#v", ranked)
	}
}

func TestUserBenchmarkPolicy(t *testing.T) {
	if quickBytes != 1_000_000 || quickTimeout.Seconds() != 2 {
		t.Fatalf("unexpected quick policy: %d %.0f", quickBytes, quickTimeout.Seconds())
	}
	if precisionBytes != 30_000_000 || precisionTimeout.Seconds() != 5 {
		t.Fatalf("unexpected precision policy: %d %.0f", precisionBytes, precisionTimeout.Seconds())
	}
}

package main

import (
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

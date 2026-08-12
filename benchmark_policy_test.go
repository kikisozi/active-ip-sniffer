package main

import "testing"

func TestBenchmarkTimeoutPolicy(t *testing.T) {
	if cfQuickBytes != 1_000_000 || cfQuickTimeout.Seconds() != 2 {
		t.Fatalf("unexpected CF quick policy: %d %.0f", cfQuickBytes, cfQuickTimeout.Seconds())
	}
	if cfSpeedBytes != 80_000_000 || cfPrecisionTimeout.Seconds() != 8 {
		t.Fatalf("unexpected CF precision policy: %d %.0f", cfSpeedBytes, cfPrecisionTimeout.Seconds())
	}
	if publicPrecisionMB != 30 || cfUserPrecisionTimeout.Seconds() != 5 {
		t.Fatalf("unexpected public benchmark policy: %d %.0f", publicPrecisionMB, cfUserPrecisionTimeout.Seconds())
	}
	if vlessBenchDefaultMB != 30 || vlessBenchDownloadTimeout.Seconds() != 5 {
		t.Fatalf("unexpected VLESS policy: %d %.0f", vlessBenchDefaultMB, vlessBenchDownloadTimeout.Seconds())
	}
}

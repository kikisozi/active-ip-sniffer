package main

import (
	"strings"
	"testing"
	"time"
)

func TestDNSPodTC3Authorization(t *testing.T) {
	cfg := dnsPodSettings{SecretID: "TEST-DNSPOD-ID", SecretKey: "TEST-DNSPOD-KEY"}
	payload := []byte(`{"Domain":"example.com"}`)
	auth, timestamp := dnsPodAuthorization(cfg, "DescribeRecordList", payload, time.Unix(1551113065, 0).UTC())
	if timestamp != 1551113065 {
		t.Fatalf("timestamp=%d", timestamp)
	}
	wantSignature := "1dd4765cf08dde02b53b74d4d9d84c2bce209edbb145bfe6a43a8e57fdcc10f5"
	if !strings.Contains(auth, "SignedHeaders=content-type;host") || !strings.HasSuffix(auth, "Signature="+wantSignature) {
		t.Fatalf("unexpected authorization: %s", auth)
	}
}

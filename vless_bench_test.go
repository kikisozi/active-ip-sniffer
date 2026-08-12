package main

import (
	"bytes"
	"fmt"
	"testing"
	"time"
)

func TestParseVLESSEndpoint(t *testing.T) {
	config, err := parseVLESSEndpoint("vless://5131de20-7aa2-448c-b4b3-127cb2c2b3a0@192.0.2.10:443?encryption=none&security=tls&sni=edge.example.com&allowInsecure=1&type=ws&host=edge.example.com&path=%2Fws")
	if err != nil {
		t.Fatalf("parseVLESSEndpoint: %v", err)
	}
	if config.Port != 443 || config.SNI != "edge.example.com" || config.WSHost != "edge.example.com" || config.WSPath != "/ws" || !config.Insecure {
		t.Fatalf("unexpected parsed config: %+v", config)
	}
}

func TestParseVLESSEndpointRejectsUnsupportedTransport(t *testing.T) {
	_, err := parseVLESSEndpoint("vless://5131de20-7aa2-448c-b4b3-127cb2c2b3a0@192.0.2.10:443?security=tls&sni=edge.example.com&type=grpc")
	if err == nil {
		t.Fatal("expected unsupported transport error")
	}
}

func TestNormalizeBenchCandidates(t *testing.T) {
	values, err := normalizeBenchCandidates([]string{"8.8.8.8", " 8.8.8.8 ", "1.1.1.1"})
	if err != nil {
		t.Fatalf("normalizeBenchCandidates: %v", err)
	}
	if len(values) != 2 || values[0] != "8.8.8.8" || values[1] != "1.1.1.1" {
		t.Fatalf("unexpected values: %#v", values)
	}
}

func TestNormalizeBenchCandidatesAllowsMoreThan128(t *testing.T) {
	input := make([]string, 0, 300)
	for i := 0; i < 300; i++ {
		input = append(input, fmt.Sprintf("10.0.%d.%d", i/254, i%254+1))
	}
	values, err := normalizeBenchCandidates(input)
	if err != nil {
		t.Fatalf("normalizeBenchCandidates(300): %v", err)
	}
	if len(values) != 300 {
		t.Fatalf("expected 300 candidates, got %d", len(values))
	}
}

func TestMakeVLESSRequestDomain(t *testing.T) {
	config, err := parseVLESSEndpoint("vless://5131de20-7aa2-448c-b4b3-127cb2c2b3a0@192.0.2.10:443?security=tls&sni=edge.example.com&type=ws&host=edge.example.com&path=%2Fws")
	if err != nil {
		t.Fatal(err)
	}
	request, err := makeVLESSRequest(config.UUID, "speed.cloudflare.com", 443)
	if err != nil {
		t.Fatalf("makeVLESSRequest: %v", err)
	}
	if len(request) < 24 {
		t.Fatalf("request too short: %d", len(request))
	}
	if request[0] != 0 || !bytes.Equal(request[1:17], config.UUID[:]) || request[17] != 0 || request[18] != 1 {
		t.Fatalf("unexpected VLESS request prefix: %x", request[:19])
	}
	if request[19] != 0x01 || request[20] != 0xbb || request[21] != 0x02 {
		t.Fatalf("unexpected VLESS target header: %x", request[19:22])
	}
	if int(request[22]) != len("speed.cloudflare.com") || string(request[23:]) != "speed.cloudflare.com" {
		t.Fatalf("unexpected domain encoding: %x", request[22:])
	}
}

func TestMedianDuration(t *testing.T) {
	values := []time.Duration{300 * time.Millisecond, 100 * time.Millisecond, 200 * time.Millisecond}
	if got := medianDuration(values); got != 200*time.Millisecond {
		t.Fatalf("median=%v", got)
	}
	values = []time.Duration{400 * time.Millisecond, 100 * time.Millisecond, 200 * time.Millisecond, 300 * time.Millisecond}
	if got := medianDuration(values); got != 250*time.Millisecond {
		t.Fatalf("even median=%v", got)
	}
}

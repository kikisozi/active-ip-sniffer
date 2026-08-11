package main

import "testing"

func TestZoneForDomainUsesLongestMatch(t *testing.T) {
	zones := []cloudflareZone{{ID: "1", Name: "example.com"}, {ID: "2", Name: "sub.example.com"}}
	zone, ok := zoneForDomain("edge.sub.example.com", zones)
	if !ok || zone.ID != "2" {
		t.Fatalf("unexpected zone: %#v, ok=%v", zone, ok)
	}
}

func TestNormalizeDomainList(t *testing.T) {
	got := normalizeDomainList([]string{" A.Example.com. ", "a.example.com", "b.example.com"})
	if len(got) != 2 || got[0] != "a.example.com" || got[1] != "b.example.com" {
		t.Fatalf("unexpected domains: %#v", got)
	}
}

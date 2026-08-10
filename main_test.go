package main

import "testing"

func TestParseTargetRangesMergesWithoutExpansion(t *testing.T) {
	ranges, count, err := parseTargetRanges([]string{
		"10.0.0.0/16",
		"10.0.1.1",
		"10.0.255.250-10.1.0.10",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(ranges) != 1 {
		t.Fatalf("expected one merged range, got %d", len(ranges))
	}
	if count != 65_546 {
		t.Fatalf("unexpected host count: %d", count)
	}
}

func TestLargeCIDRIsRepresentedAsOneRange(t *testing.T) {
	ranges, count, err := parseTargetRanges([]string{"10.0.0.0/12"})
	if err != nil {
		t.Fatal(err)
	}
	if len(ranges) != 1 {
		t.Fatalf("expected one range, got %d", len(ranges))
	}
	if count != 1_048_574 {
		t.Fatalf("expected 1,048,574 hosts, got %d", count)
	}
}

func TestCIDRHostSemantics(t *testing.T) {
	cases := []struct {
		target string
		count  uint64
	}{
		{"192.0.2.0/30", 2},
		{"192.0.2.0/31", 2},
		{"192.0.2.1/32", 1},
	}
	for _, tc := range cases {
		_, count, err := parseTargetRanges([]string{tc.target})
		if err != nil {
			t.Fatalf("%s: %v", tc.target, err)
		}
		if count != tc.count {
			t.Fatalf("%s: expected %d, got %d", tc.target, tc.count, count)
		}
	}
}

func TestNormalizePorts(t *testing.T) {
	ports, err := normalizePorts([]int{443, 80, 443})
	if err != nil {
		t.Fatal(err)
	}
	if len(ports) != 2 || ports[0] != 80 || ports[1] != 443 {
		t.Fatalf("unexpected ports: %#v", ports)
	}
}

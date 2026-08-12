package main

import (
	"strings"
	"testing"
)

func TestParseCandidateCSVWithMetadata(t *testing.T) {
	input := "ip,port,country_code,region,asn,idc\n47.242.162.186,443,HK,Hong Kong,AS45102,Alibaba Cloud\n8.218.184.207,8443,HK,Hong Kong,45102,Alibaba Cloud\n"
	result, err := parseCandidateCSV(strings.NewReader(input))
	if err != nil {
		t.Fatalf("parseCandidateCSV: %v", err)
	}
	if len(result.Targets) != 2 || result.Targets[0] != "47.242.162.186:443" || result.Targets[1] != "8.218.184.207:8443" {
		t.Fatalf("unexpected targets: %#v", result.Targets)
	}
	meta := result.Metadata["47.242.162.186"]
	if meta.CountryCode != "HK" || meta.Region != "Hong Kong" || meta.ASN != 45102 || meta.IDC != "Alibaba Cloud" || meta.Source != "csv" {
		t.Fatalf("unexpected metadata: %#v", meta)
	}
}

func TestParseCandidateCSVNoHeader(t *testing.T) {
	result, err := parseCandidateCSV(strings.NewReader("47.238.0.131,443\n47.242.87.115,8443\n"))
	if err != nil {
		t.Fatalf("parseCandidateCSV: %v", err)
	}
	if len(result.Targets) != 2 || result.Targets[1] != "47.242.87.115:8443" {
		t.Fatalf("unexpected targets: %#v", result.Targets)
	}
}

func TestParseCandidateCSVSkipsInvalidRows(t *testing.T) {
	result, err := parseCandidateCSV(strings.NewReader("ip,port\nnot-an-ip,443\n47.238.0.131,443\n"))
	if err != nil {
		t.Fatalf("parseCandidateCSV: %v", err)
	}
	if result.Skipped != 1 || len(result.Targets) != 1 {
		t.Fatalf("unexpected result: %#v", result)
	}
}

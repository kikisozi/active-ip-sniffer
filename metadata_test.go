package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestImportedMetadataPersists(t *testing.T) {
	dir := t.TempDir()
	configureIPMetadataCache(dir)
	seedIPMetadata(ipMetadata{IP: "47.242.162.186", CountryCode: "HK", Region: "Hong Kong", ASN: 45102, IDC: "Alibaba Cloud", Source: "csv"}, time.Hour)
	path := filepath.Join(dir, "ip-metadata-cache.json")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat metadata cache: %v", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("metadata cache permissions too broad: %v", info.Mode().Perm())
	}
	configureIPMetadataCache(dir)
	meta, ok := cachedIPMetadata("47.242.162.186")
	if !ok || meta.CountryCode != "HK" || meta.ASN != 45102 || meta.IDC != "Alibaba Cloud" || meta.Source != "csv" {
		t.Fatalf("unexpected restored metadata: ok=%v meta=%#v", ok, meta)
	}
}

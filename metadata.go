package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	metadataPositiveTTL = 7 * 24 * time.Hour
	metadataImportedTTL = 30 * 24 * time.Hour
	metadataNegativeTTL = 15 * time.Minute
)

type ipMetadataCacheEntry struct {
	Value     ipMetadata `json:"value"`
	ExpiresAt time.Time  `json:"expires_at"`
}

type metadataLookupCall struct {
	done chan struct{}
}

var ipMetadataCache = struct {
	sync.RWMutex
	items    map[string]ipMetadataCacheEntry
	inflight map[string]*metadataLookupCall
	path     string
}{
	items:    make(map[string]ipMetadataCacheEntry),
	inflight: make(map[string]*metadataLookupCall),
}

func configureIPMetadataCache(dataDir string) {
	path := filepath.Join(dataDir, "ip-metadata-cache.json")
	ipMetadataCache.Lock()
	ipMetadataCache.path = path
	ipMetadataCache.items = make(map[string]ipMetadataCacheEntry)
	data, err := os.ReadFile(path)
	if err == nil {
		var stored map[string]ipMetadataCacheEntry
		if json.Unmarshal(data, &stored) == nil {
			now := time.Now()
			for ip, entry := range stored {
				if entry.ExpiresAt.After(now) {
					ipMetadataCache.items[ip] = entry
				}
			}
		}
	}
	ipMetadataCache.Unlock()
}

func persistIPMetadataCacheLocked() {
	if ipMetadataCache.path == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(ipMetadataCache.path), 0o700); err != nil {
		return
	}
	data, err := json.Marshal(ipMetadataCache.items)
	if err != nil {
		return
	}
	tmp := ipMetadataCache.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return
	}
	_ = os.Chmod(tmp, 0o600)
	_ = os.Rename(tmp, ipMetadataCache.path)
}

func metadataMeaningful(meta ipMetadata) bool {
	return meta.CountryCode != "" || meta.Country != "" || meta.Region != "" || meta.City != "" || meta.ASN != 0 || meta.Org != "" || meta.ISP != "" || meta.IDC != ""
}

func normalizeMetadata(meta ipMetadata) ipMetadata {
	meta.IP = strings.TrimSpace(meta.IP)
	meta.CountryCode = strings.ToUpper(strings.TrimSpace(meta.CountryCode))
	meta.Country = strings.TrimSpace(meta.Country)
	meta.Region = strings.TrimSpace(meta.Region)
	meta.City = strings.TrimSpace(meta.City)
	meta.Org = strings.TrimSpace(meta.Org)
	meta.ISP = strings.TrimSpace(meta.ISP)
	meta.IDC = strings.TrimSpace(meta.IDC)
	meta.Source = strings.TrimSpace(meta.Source)
	if meta.IDC == "" {
		meta.IDC = meta.Org
	}
	if meta.IDC == "" {
		meta.IDC = meta.ISP
	}
	return meta
}

func cachedIPMetadata(ip string) (ipMetadata, bool) {
	now := time.Now()
	ipMetadataCache.RLock()
	entry, ok := ipMetadataCache.items[ip]
	ipMetadataCache.RUnlock()
	if !ok || !entry.ExpiresAt.After(now) {
		return ipMetadata{}, false
	}
	return entry.Value, true
}

func seedIPMetadata(meta ipMetadata, ttl time.Duration) {
	meta = normalizeMetadata(meta)
	parsed := net.ParseIP(meta.IP)
	if parsed == nil || parsed.To4() == nil || !metadataMeaningful(meta) {
		return
	}
	if meta.Source == "" {
		meta.Source = "imported"
	}
	ipMetadataCache.Lock()
	ipMetadataCache.items[meta.IP] = ipMetadataCacheEntry{Value: meta, ExpiresAt: time.Now().Add(ttl)}
	persistIPMetadataCacheLocked()
	ipMetadataCache.Unlock()
}

func fetchIPWhoMetadata(ctx context.Context, ip string) (ipMetadata, bool) {
	base := ipMetadata{IP: ip}
	type response struct {
		Success     bool   `json:"success"`
		Country     string `json:"country"`
		CountryCode string `json:"country_code"`
		Region      string `json:"region"`
		City        string `json:"city"`
		Connection  struct {
			ASN int    `json:"asn"`
			Org string `json:"org"`
			ISP string `json:"isp"`
		} `json:"connection"`
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://ipwho.is/"+ip, nil)
	if err != nil {
		return base, false
	}
	req.Header.Set("User-Agent", "Active-IP-Sniffer/"+appVersion)
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return base, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return base, false
	}
	var decoded response
	if err := json.NewDecoder(io.LimitReader(resp.Body, 128<<10)).Decode(&decoded); err != nil || !decoded.Success {
		return base, false
	}
	base.Country = decoded.Country
	base.CountryCode = decoded.CountryCode
	base.Region = decoded.Region
	base.City = decoded.City
	base.ASN = decoded.Connection.ASN
	base.Org = decoded.Connection.Org
	base.ISP = decoded.Connection.ISP
	base.IDC = decoded.Connection.Org
	base.Source = "ipwho.is"
	return normalizeMetadata(base), metadataMeaningful(base)
}

func fetchIPAPIMetadata(ctx context.Context, ip string) (ipMetadata, bool) {
	base := ipMetadata{IP: ip}
	type response struct {
		Status      string `json:"status"`
		Country     string `json:"country"`
		CountryCode string `json:"countryCode"`
		RegionName  string `json:"regionName"`
		City        string `json:"city"`
		AS          string `json:"as"`
		ASName      string `json:"asname"`
		Org         string `json:"org"`
		ISP         string `json:"isp"`
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://ip-api.com/json/"+ip+"?fields=status,country,countryCode,regionName,city,as,asname,org,isp", nil)
	if err != nil {
		return base, false
	}
	req.Header.Set("User-Agent", "Active-IP-Sniffer/"+appVersion)
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return base, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return base, false
	}
	var decoded response
	if err := json.NewDecoder(io.LimitReader(resp.Body, 128<<10)).Decode(&decoded); err != nil || decoded.Status != "success" {
		return base, false
	}
	base.Country = decoded.Country
	base.CountryCode = decoded.CountryCode
	base.Region = decoded.RegionName
	base.City = decoded.City
	base.Org = decoded.ASName
	if base.Org == "" {
		base.Org = decoded.Org
	}
	base.ISP = decoded.ISP
	base.IDC = decoded.ASName
	if fields := strings.Fields(decoded.AS); len(fields) > 0 {
		asText := strings.TrimPrefix(strings.ToUpper(fields[0]), "AS")
		base.ASN, _ = strconv.Atoi(asText)
	}
	base.Source = "ip-api.com"
	return normalizeMetadata(base), metadataMeaningful(base)
}

func lookupIPMetadata(ctx context.Context, ip string) ipMetadata {
	base := ipMetadata{IP: ip}
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() == nil || parsed.IsPrivate() || parsed.IsLoopback() {
		return base
	}
	if cached, ok := cachedIPMetadata(ip); ok {
		return cached
	}

	ipMetadataCache.Lock()
	if call, ok := ipMetadataCache.inflight[ip]; ok {
		done := call.done
		ipMetadataCache.Unlock()
		select {
		case <-ctx.Done():
			return base
		case <-done:
			if cached, ok := cachedIPMetadata(ip); ok {
				return cached
			}
			return base
		}
	}
	call := &metadataLookupCall{done: make(chan struct{})}
	ipMetadataCache.inflight[ip] = call
	ipMetadataCache.Unlock()

	meta, ok := fetchIPWhoMetadata(ctx, ip)
	if !ok {
		meta, ok = fetchIPAPIMetadata(ctx, ip)
	}
	if imported, cached := cachedIPMetadata(ip); cached && imported.Source == "csv" {
		meta, ok = imported, true
	}
	if !ok {
		meta = base
		meta.Source = "negative-cache"
	}
	ttl := metadataPositiveTTL
	if !ok {
		ttl = metadataNegativeTTL
	}

	ipMetadataCache.Lock()
	ipMetadataCache.items[ip] = ipMetadataCacheEntry{Value: meta, ExpiresAt: time.Now().Add(ttl)}
	delete(ipMetadataCache.inflight, ip)
	close(call.done)
	persistIPMetadataCacheLocked()
	ipMetadataCache.Unlock()
	return meta
}

func handleIPMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64_000)
	defer r.Body.Close()
	var request struct {
		IPs []string `json:"ips"`
	}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request: " + err.Error()})
		return
	}
	seen := make(map[string]struct{})
	values := make([]ipMetadata, 0, len(request.IPs))
	for _, raw := range request.IPs {
		ip := strings.TrimSpace(raw)
		if _, ok := seen[ip]; ok || net.ParseIP(ip) == nil {
			continue
		}
		seen[ip] = struct{}{}
		if len(values) >= 100 {
			break
		}
		values = append(values, lookupIPMetadata(r.Context(), ip))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": values})
}

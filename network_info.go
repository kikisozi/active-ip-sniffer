package main

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type egressInfo struct {
	IP     string `json:"ip"`
	WARP   string `json:"warp"`
	Colo   string `json:"colo,omitempty"`
	Source string `json:"source,omitempty"`
}

type cachedEgress struct {
	mu      sync.Mutex
	value   egressInfo
	expires time.Time
}

var egressCache cachedEgress

func requestClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err == nil {
		return host
	}
	return strings.TrimSpace(r.RemoteAddr)
}

func currentEgressInfo(ctx context.Context) egressInfo {
	now := time.Now()
	egressCache.mu.Lock()
	defer egressCache.mu.Unlock()
	if now.Before(egressCache.expires) && egressCache.value.IP != "" {
		return egressCache.value
	}

	value := queryCloudflareTrace(ctx, egressConfig{Mode: "direct"})
	if value.IP == "" {
		value = queryPublicIPv4(ctx)
	}
	if value.WARP == "" {
		value.WARP = "unknown"
	}
	egressCache.value = value
	egressCache.expires = now.Add(45 * time.Second)
	return value
}

func queryCloudflareTrace(ctx context.Context, egress egressConfig) egressInfo {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.cloudflare.com/cdn-cgi/trace", nil)
	if err != nil {
		return egressInfo{}
	}
	req.Header.Set("User-Agent", "Active-IP-Sniffer/"+appVersion)
	transport := &http.Transport{
		Proxy:                 nil,
		ForceAttemptHTTP2:     false,
		DisableCompression:    true,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
		DialContext: func(dialCtx context.Context, network, address string) (net.Conn, error) {
			return egress.dialContext(dialCtx, network, address, 5*time.Second)
		},
	}
	defer transport.CloseIdleConnections()
	resp, err := (&http.Client{Transport: transport, Timeout: 6 * time.Second}).Do(req)
	if err != nil {
		return egressInfo{}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
		return egressInfo{}
	}
	info := egressInfo{Source: "cloudflare-trace"}
	scanner := bufio.NewScanner(io.LimitReader(resp.Body, 16*1024))
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(key) {
		case "ip":
			info.IP = strings.TrimSpace(value)
		case "warp":
			info.WARP = strings.TrimSpace(value)
		case "colo":
			info.Colo = strings.TrimSpace(value)
		}
	}
	return info
}

func handleEgressCheck(role string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 8_000)
		defer r.Body.Close()
		var request egressConfig
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&request); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request: " + err.Error()})
			return
		}
		requested, err := normalizeEgress(request.Mode, request.WARPProxy)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		selected, info, err := resolveEgress(r.Context(), requested)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
			return
		}
		if info.IP == "" {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": "cannot reach Cloudflare trace through selected egress"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"role":           role,
			"requested_mode": requested.Mode,
			"mode":           selected.Mode,
			"proxy":          selected.WARPProxy,
			"auto_fallback":  requested.Mode == "auto" && selected.Mode == "direct",
			"egress":         info,
		})
	}
}

func queryPublicIPv4(ctx context.Context) egressInfo {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api4.ipify.org", nil)
	if err != nil {
		return egressInfo{}
	}
	req.Header.Set("User-Agent", "Active-IP-Sniffer/"+appVersion)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return egressInfo{}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256))
	if err != nil || resp.StatusCode != http.StatusOK {
		return egressInfo{}
	}
	ip := strings.TrimSpace(string(body))
	if net.ParseIP(ip) == nil {
		return egressInfo{}
	}
	return egressInfo{IP: ip, WARP: "unknown", Source: "ipify"}
}

func handleNetworkInfo(role string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		info := currentEgressInfo(r.Context())
		writeJSON(w, http.StatusOK, map[string]any{
			"role":       role,
			"visitor_ip": requestClientIP(r),
			"egress":     info,
		})
	}
}

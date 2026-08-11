package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const cloudflareAPIBase = "https://api.cloudflare.com/client/v4"

type cloudflareAPIError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type cloudflareResultInfo struct {
	Page       int `json:"page"`
	PerPage    int `json:"per_page"`
	TotalPages int `json:"total_pages"`
}

type cloudflareEnvelope[T any] struct {
	Success    bool                 `json:"success"`
	Errors     []cloudflareAPIError `json:"errors"`
	Messages   []cloudflareAPIError `json:"messages"`
	Result     T                    `json:"result"`
	ResultInfo cloudflareResultInfo `json:"result_info"`
}

type cloudflareZone struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

type cloudflareDNSRecord struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Name     string `json:"name"`
	Content  string `json:"content"`
	Proxied  bool   `json:"proxied"`
	TTL      int    `json:"ttl"`
	Comment  string `json:"comment,omitempty"`
	Modified string `json:"modified_on,omitempty"`
}

type cloudflareDomainStatus struct {
	Domain  string                    `json:"domain"`
	ZoneID  string                    `json:"zone_id"`
	Zone    string                    `json:"zone"`
	Records []cloudflareDNSRecord     `json:"records"`
	A       []cloudflareDNSRecord     `json:"a_records"`
	Other   []cloudflareDNSRecord     `json:"other_records,omitempty"`
	Meta    map[string]map[string]any `json:"meta,omitempty"`
}

type cloudflareConfigRequest struct {
	Token   string   `json:"token"`
	Domains []string `json:"domains"`
}

type cloudflareUpdateRequest struct {
	Domain   string `json:"domain"`
	RecordID string `json:"record_id"`
	IP       string `json:"ip"`
}

func cfHTTPClient() *http.Client {
	return &http.Client{Timeout: 15 * time.Second}
}

func doCloudflareRequest[T any](ctx context.Context, client *http.Client, token, method, endpoint string, query url.Values, body any) (cloudflareEnvelope[T], error) {
	var envelope cloudflareEnvelope[T]
	if strings.TrimSpace(token) == "" {
		return envelope, errors.New("Cloudflare token is empty")
	}
	requestURL := cloudflareAPIBase + endpoint
	if len(query) > 0 {
		requestURL += "?" + query.Encode()
	}
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return envelope, err
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, requestURL, reader)
	if err != nil {
		return envelope, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return envelope, err
	}
	defer resp.Body.Close()
	limited := io.LimitReader(resp.Body, 4<<20)
	if err := json.NewDecoder(limited).Decode(&envelope); err != nil {
		return envelope, fmt.Errorf("Cloudflare HTTP %d returned invalid JSON: %w", resp.StatusCode, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || !envelope.Success {
		parts := make([]string, 0, len(envelope.Errors))
		for _, item := range envelope.Errors {
			parts = append(parts, fmt.Sprintf("%d %s", item.Code, item.Message))
		}
		if len(parts) == 0 {
			parts = append(parts, resp.Status)
		}
		return envelope, errors.New(strings.Join(parts, "; "))
	}
	return envelope, nil
}

func verifyCloudflareToken(ctx context.Context, token string) error {
	type verifyResult struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	envelope, err := doCloudflareRequest[verifyResult](ctx, cfHTTPClient(), token, http.MethodGet, "/user/tokens/verify", nil, nil)
	if err != nil {
		return err
	}
	if envelope.Result.Status != "active" {
		return fmt.Errorf("token status is %q", envelope.Result.Status)
	}
	return nil
}

func listCloudflareZones(ctx context.Context, client *http.Client, token string) ([]cloudflareZone, error) {
	zones := make([]cloudflareZone, 0, 16)
	for page := 1; page <= 20; page++ {
		query := url.Values{"page": {fmt.Sprint(page)}, "per_page": {"50"}}
		envelope, err := doCloudflareRequest[[]cloudflareZone](ctx, client, token, http.MethodGet, "/zones", query, nil)
		if err != nil {
			return nil, err
		}
		zones = append(zones, envelope.Result...)
		if envelope.ResultInfo.TotalPages <= page || len(envelope.Result) == 0 {
			break
		}
	}
	return zones, nil
}

func zoneForDomain(domain string, zones []cloudflareZone) (cloudflareZone, bool) {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	var best cloudflareZone
	for _, zone := range zones {
		name := strings.ToLower(strings.TrimSuffix(zone.Name, "."))
		if domain != name && !strings.HasSuffix(domain, "."+name) {
			continue
		}
		if len(name) > len(best.Name) {
			best = zone
		}
	}
	return best, best.ID != ""
}

func listCloudflareDNSRecords(ctx context.Context, client *http.Client, token string, zone cloudflareZone, domain string) ([]cloudflareDNSRecord, error) {
	query := url.Values{"name": {domain}, "per_page": {"100"}}
	envelope, err := doCloudflareRequest[[]cloudflareDNSRecord](ctx, client, token, http.MethodGet, "/zones/"+url.PathEscape(zone.ID)+"/dns_records", query, nil)
	if err != nil {
		return nil, err
	}
	records := envelope.Result
	sort.SliceStable(records, func(i, j int) bool {
		if records[i].Type == records[j].Type {
			return records[i].Content < records[j].Content
		}
		if records[i].Type == "A" {
			return true
		}
		if records[j].Type == "A" {
			return false
		}
		return records[i].Type < records[j].Type
	})
	return records, nil
}

func resolveCloudflareDomains(ctx context.Context, token string, domains []string) ([]cloudflareDomainStatus, error) {
	domains = normalizeDomainList(domains)
	if len(domains) == 0 {
		return nil, errors.New("no Cloudflare domains configured")
	}
	if err := verifyCloudflareToken(ctx, token); err != nil {
		return nil, fmt.Errorf("token verify: %w", err)
	}
	client := cfHTTPClient()
	zones, err := listCloudflareZones(ctx, client, token)
	if err != nil {
		return nil, fmt.Errorf("list zones: %w", err)
	}
	statuses := make([]cloudflareDomainStatus, 0, len(domains))
	for _, domain := range domains {
		zone, ok := zoneForDomain(domain, zones)
		if !ok {
			return nil, fmt.Errorf("cannot find a readable Cloudflare zone for %s", domain)
		}
		records, err := listCloudflareDNSRecords(ctx, client, token, zone, domain)
		if err != nil {
			return nil, fmt.Errorf("read DNS %s: %w", domain, err)
		}
		if len(records) == 0 {
			return nil, fmt.Errorf("no DNS record found for %s", domain)
		}
		status := cloudflareDomainStatus{Domain: domain, ZoneID: zone.ID, Zone: zone.Name, Records: records}
		for _, record := range records {
			if record.Type == "A" {
				status.A = append(status.A, record)
			} else {
				status.Other = append(status.Other, record)
			}
		}
		statuses = append(statuses, status)
	}
	return statuses, nil
}

func summarizeDNSRecords(records []cloudflareDNSRecord) string {
	parts := make([]string, 0, len(records))
	for _, record := range records {
		parts = append(parts, record.Type+" → "+record.Content)
	}
	return strings.Join(parts, ", ")
}

func updateCloudflareARecord(ctx context.Context, token string, status cloudflareDomainStatus, recordID, ip string) (cloudflareDNSRecord, error) {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil || parsed.To4() == nil {
		return cloudflareDNSRecord{}, errors.New("update target must be an IPv4 address")
	}
	var current cloudflareDNSRecord
	for _, record := range status.A {
		if record.ID == recordID {
			current = record
			break
		}
	}
	if current.ID == "" {
		return cloudflareDNSRecord{}, errors.New("selected A record no longer exists")
	}
	client := cfHTTPClient()
	endpoint := "/zones/" + url.PathEscape(status.ZoneID) + "/dns_records/" + url.PathEscape(recordID)
	patch := map[string]any{
		"type":    "A",
		"name":    current.Name,
		"content": parsed.To4().String(),
		"ttl":     current.TTL,
		"proxied": current.Proxied,
	}
	if current.Comment != "" {
		patch["comment"] = current.Comment
	} else {
		patch["comment"] = "active-ip-sniffer：CF 优选 IP 自动更新；域名 " + current.Name
	}
	envelope, err := doCloudflareRequest[cloudflareDNSRecord](ctx, client, token, http.MethodPatch, endpoint, nil, patch)
	if err != nil {
		return cloudflareDNSRecord{}, err
	}
	return envelope.Result, nil
}

func (a *app) handleCloudflareConfig(w http.ResponseWriter, r *http.Request) {
	if a.settings == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "settings store unavailable"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		cfg := a.settings.snapshot()
		response := map[string]any{
			"token_configured": cfg.Cloudflare.Token != "",
			"domains":          cfg.Cloudflare.Domains,
			"records":          []cloudflareDomainStatus{},
		}
		if cfg.Cloudflare.Token != "" && len(cfg.Cloudflare.Domains) > 0 {
			ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
			statuses, err := resolveCloudflareDomains(ctx, cfg.Cloudflare.Token, cfg.Cloudflare.Domains)
			cancel()
			if err != nil {
				response["refresh_error"] = err.Error()
			} else {
				response["records"] = statuses
			}
		}
		writeJSON(w, http.StatusOK, response)
	case http.MethodPost:
		current := a.settings.snapshot()
		if !current.Auth.configured() {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "为保护 Cloudflare DNS 写入权限，请先运行 v 设置 WebUI 管理密码"})
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 128_000)
		defer r.Body.Close()
		var request cloudflareConfigRequest
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&request); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request: " + err.Error()})
			return
		}
		token := strings.TrimSpace(request.Token)
		if token == "" {
			token = current.Cloudflare.Token
		}
		domains := normalizeDomainList(request.Domains)
		ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
		statuses, err := resolveCloudflareDomains(ctx, token, domains)
		cancel()
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if err := a.settings.updateCloudflare(cloudflareSettings{Token: token, Domains: domains}); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "save config: " + err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "token_configured": true, "domains": domains, "records": statuses})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

func (a *app) handleCloudflareUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if a.settings == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "settings store unavailable"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 32_000)
	defer r.Body.Close()
	var request cloudflareUpdateRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request: " + err.Error()})
		return
	}
	cfg := a.settings.snapshot()
	if !cfg.Auth.configured() {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "为保护 Cloudflare DNS 写入权限，请先运行 v 设置 WebUI 管理密码"})
		return
	}
	if cfg.Cloudflare.Token == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Cloudflare token is not configured"})
		return
	}
	domain := strings.ToLower(strings.TrimSpace(request.Domain))
	allowed := false
	for _, configured := range cfg.Cloudflare.Domains {
		if domain == configured {
			allowed = true
			break
		}
	}
	if !allowed {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "domain is not configured"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()
	statuses, err := resolveCloudflareDomains(ctx, cfg.Cloudflare.Token, []string{domain})
	if err != nil || len(statuses) != 1 {
		if err == nil {
			err = errors.New("unexpected Cloudflare response")
		}
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	updated, err := updateCloudflareARecord(ctx, cfg.Cloudflare.Token, statuses[0], request.RecordID, request.IP)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	verified, err := resolveCloudflareDomains(ctx, cfg.Cloudflare.Token, []string{domain})
	if err != nil || len(verified) != 1 {
		if err == nil {
			err = errors.New("cannot verify updated DNS record")
		}
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	wanted := net.ParseIP(request.IP).To4().String()
	confirmed := false
	for _, record := range verified[0].A {
		if record.ID == request.RecordID && record.Content == wanted {
			confirmed = true
			break
		}
	}
	if !confirmed {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "Cloudflare accepted the update but verification did not observe the new IP"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "updated": updated, "records": verified})
}

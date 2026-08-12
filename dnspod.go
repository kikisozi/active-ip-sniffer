package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	dnsPodHost          = "dnspod.tencentcloudapi.com"
	dnsPodService       = "dnspod"
	dnsPodVersion       = "2021-03-23"
	dnsPodManagedRemark = "active-ip-sniffer smart dns"
)

type dnsPodRecord struct {
	RecordID int64  `json:"RecordId"`
	Value    string `json:"Value"`
	Status   string `json:"Status"`
	Name     string `json:"Name"`
	Line     string `json:"Line"`
	Type     string `json:"Type"`
	Remark   string `json:"Remark"`
	TTL      int    `json:"TTL"`
}

type dnsPodApplyChange struct {
	Action string `json:"action"`
	Line   string `json:"line"`
	IP     string `json:"ip,omitempty"`
	ID     int64  `json:"record_id,omitempty"`
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write(data)
	return h.Sum(nil)
}

func dnsPodAuthorization(cfg dnsPodSettings, action string, payload []byte, now time.Time) (string, int64) {
	timestamp := now.Unix()
	date := now.UTC().Format("2006-01-02")
	contentType := "application/json; charset=utf-8"
	canonicalHeaders := "content-type:" + contentType + "\n" + "host:" + dnsPodHost + "\n"
	signedHeaders := "content-type;host"
	canonicalRequest := "POST\n/\n\n" + canonicalHeaders + "\n" + signedHeaders + "\n" + sha256Hex(payload)
	credentialScope := date + "/" + dnsPodService + "/tc3_request"
	stringToSign := "TC3-HMAC-SHA256\n" + strconv.FormatInt(timestamp, 10) + "\n" + credentialScope + "\n" + sha256Hex([]byte(canonicalRequest))
	secretDate := hmacSHA256([]byte("TC3"+cfg.SecretKey), []byte(date))
	secretService := hmacSHA256(secretDate, []byte(dnsPodService))
	secretSigning := hmacSHA256(secretService, []byte("tc3_request"))
	signature := hex.EncodeToString(hmacSHA256(secretSigning, []byte(stringToSign)))
	authorization := "TC3-HMAC-SHA256 Credential=" + cfg.SecretID + "/" + credentialScope + ", SignedHeaders=" + signedHeaders + ", Signature=" + signature
	return authorization, timestamp
}

func dnsPodCall(ctx context.Context, cfg dnsPodSettings, action string, payload any, out any) error {
	cfg = normalizeDNSPodSettings(cfg)
	if !cfg.configured() {
		return errors.New("DNSPod credentials/domain/subdomain are not configured")
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	authorization, timestamp := dnsPodAuthorization(cfg, action, body, now)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+dnsPodHost, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", authorization)
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Host", dnsPodHost)
	req.Header.Set("X-TC-Action", action)
	req.Header.Set("X-TC-Timestamp", strconv.FormatInt(timestamp, 10))
	req.Header.Set("X-TC-Version", dnsPodVersion)
	resp, err := (&http.Client{Timeout: 12 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("DNSPod HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	var base struct {
		Response struct {
			Error *struct {
				Code    string `json:"Code"`
				Message string `json:"Message"`
			} `json:"Error"`
			RequestID string `json:"RequestId"`
		} `json:"Response"`
	}
	if err := json.Unmarshal(data, &base); err != nil {
		return fmt.Errorf("decode DNSPod response: %w", err)
	}
	if base.Response.Error != nil {
		return fmt.Errorf("DNSPod %s: %s", base.Response.Error.Code, base.Response.Error.Message)
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("decode DNSPod %s result: %w", action, err)
		}
	}
	return nil
}

func describeDNSPodRecords(ctx context.Context, cfg dnsPodSettings) ([]dnsPodRecord, error) {
	var response struct {
		Response struct {
			RecordList []dnsPodRecord `json:"RecordList"`
		} `json:"Response"`
	}
	payload := map[string]any{
		"Domain":       cfg.Domain,
		"SubDomain":    cfg.SubDomain,
		"RecordType":   "A",
		"Limit":        3000,
		"ErrorOnEmpty": "no",
	}
	if err := dnsPodCall(ctx, cfg, "DescribeRecordList", payload, &response); err != nil {
		return nil, err
	}
	return response.Response.RecordList, nil
}

func createDNSPodRecord(ctx context.Context, cfg dnsPodSettings, line, ip string) (int64, error) {
	var response struct {
		Response struct {
			RecordID int64 `json:"RecordId"`
		} `json:"Response"`
	}
	payload := map[string]any{"Domain": cfg.Domain, "SubDomain": cfg.SubDomain, "RecordType": "A", "RecordLine": line, "Value": ip, "TTL": cfg.TTL, "Status": "ENABLE", "Remark": dnsPodManagedRemark}
	if err := dnsPodCall(ctx, cfg, "CreateRecord", payload, &response); err != nil {
		return 0, err
	}
	return response.Response.RecordID, nil
}

func modifyDNSPodRecord(ctx context.Context, cfg dnsPodSettings, record dnsPodRecord, line, ip string) error {
	payload := map[string]any{"Domain": cfg.Domain, "SubDomain": cfg.SubDomain, "RecordType": "A", "RecordLine": line, "Value": ip, "TTL": cfg.TTL, "Status": "ENABLE", "RecordId": record.RecordID, "Remark": dnsPodManagedRemark}
	return dnsPodCall(ctx, cfg, "ModifyRecord", payload, nil)
}

func deleteDNSPodRecord(ctx context.Context, cfg dnsPodSettings, recordID int64) error {
	return dnsPodCall(ctx, cfg, "DeleteRecord", map[string]any{"Domain": cfg.Domain, "RecordId": recordID}, nil)
}

func planLinesForDNSPod(plans []smartDNSLinePlan, minSubmitters int) map[string][]string {
	desired := make(map[string][]string)
	for _, plan := range plans {
		if plan.Submitters < minSubmitters || len(plan.Candidates) == 0 {
			continue
		}
		for _, candidate := range plan.Candidates {
			desired[plan.Line] = append(desired[plan.Line], candidate.IP)
		}
	}
	return desired
}

func applyDNSPodPlan(ctx context.Context, cfg dnsPodSettings, plans []smartDNSLinePlan) ([]dnsPodApplyChange, error) {
	cfg = normalizeDNSPodSettings(cfg)
	desired := planLinesForDNSPod(plans, cfg.MinSubmitters)
	if len(desired) == 0 {
		return nil, fmt.Errorf("no smart DNS line has at least %d submitter(s)", cfg.MinSubmitters)
	}
	records, err := describeDNSPodRecords(ctx, cfg)
	if err != nil {
		return nil, err
	}
	byLine := make(map[string][]dnsPodRecord)
	for _, record := range records {
		if !strings.EqualFold(record.Type, "A") || record.Name != cfg.SubDomain {
			continue
		}
		byLine[record.Line] = append(byLine[record.Line], record)
	}
	changes := make([]dnsPodApplyChange, 0)
	lines := make([]string, 0, len(desired))
	for _, line := range []string{"默认", "电信", "联通", "移动"} {
		if len(desired[line]) > 0 {
			lines = append(lines, line)
		}
	}
	remaining := make([]string, 0)
	for line := range desired {
		if line != "默认" && line != "电信" && line != "联通" && line != "移动" {
			remaining = append(remaining, line)
		}
	}
	sort.Strings(remaining)
	lines = append(lines, remaining...)
	for _, line := range lines {
		wanted := desired[line]
		current := byLine[line]
		managed := make([]dnsPodRecord, 0, len(current))
		for _, record := range current {
			if strings.TrimSpace(record.Remark) != dnsPodManagedRemark {
				return nil, fmt.Errorf("DNSPod %s/%s line %s has unmanaged A record %s; use a dedicated smart-DNS hostname or remove the conflict first", cfg.Domain, cfg.SubDomain, line, record.Value)
			}
			managed = append(managed, record)
		}
		sort.Slice(managed, func(i, j int) bool { return managed[i].RecordID < managed[j].RecordID })
		for i, ip := range wanted {
			if i < len(managed) {
				record := managed[i]
				if record.Value != ip || record.TTL != cfg.TTL || !strings.EqualFold(record.Status, "ENABLE") {
					if err := modifyDNSPodRecord(ctx, cfg, record, line, ip); err != nil {
						return changes, err
					}
					changes = append(changes, dnsPodApplyChange{Action: "modify", Line: line, IP: ip, ID: record.RecordID})
					time.Sleep(75 * time.Millisecond)
				}
				continue
			}
			id, err := createDNSPodRecord(ctx, cfg, line, ip)
			if err != nil {
				return changes, err
			}
			changes = append(changes, dnsPodApplyChange{Action: "create", Line: line, IP: ip, ID: id})
			time.Sleep(75 * time.Millisecond)
		}
		for i := len(wanted); i < len(managed); i++ {
			if err := deleteDNSPodRecord(ctx, cfg, managed[i].RecordID); err != nil {
				return changes, err
			}
			changes = append(changes, dnsPodApplyChange{Action: "delete", Line: line, IP: managed[i].Value, ID: managed[i].RecordID})
			time.Sleep(75 * time.Millisecond)
		}
	}
	return changes, nil
}

func (a *app) handleDNSPodConfig(w http.ResponseWriter, r *http.Request) {
	if a.settings == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "settings unavailable"})
		return
	}
	cfg := a.settings.snapshot()
	if r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, map[string]any{"configured": cfg.DNSPod.configured(), "secret_id_configured": cfg.DNSPod.SecretID != "", "secret_key_configured": cfg.DNSPod.SecretKey != "", "domain": cfg.DNSPod.Domain, "subdomain": cfg.DNSPod.SubDomain, "ttl": cfg.DNSPod.TTL, "top_n": cfg.DNSPod.TopN, "min_submitters": cfg.DNSPod.MinSubmitters, "auto_apply": cfg.DNSPod.AutoApply, "interval_minutes": cfg.DNSPod.IntervalMinutes})
		return
	}
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if !cfg.Auth.configured() {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "configure the admin WebUI password before saving DNSPod credentials"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64_000)
	defer r.Body.Close()
	var next dnsPodSettings
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&next); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request: " + err.Error()})
		return
	}
	if strings.TrimSpace(next.SecretID) == "" {
		next.SecretID = cfg.DNSPod.SecretID
	}
	if strings.TrimSpace(next.SecretKey) == "" {
		next.SecretKey = cfg.DNSPod.SecretKey
	}
	next = normalizeDNSPodSettings(next)
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	_, err := describeDNSPodRecords(ctx, next)
	cancel()
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "DNSPod verification failed: " + err.Error()})
		return
	}
	if err := a.settings.updateDNSPod(next); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "configured": true})
}

func (a *app) handleDNSPodApply(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	cfg := a.settings.snapshot().DNSPod
	if !cfg.configured() {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "DNSPod smart DNS is not configured"})
		return
	}
	plans := a.public.smartPlan(cfg.TopN)
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	changes, err := applyDNSPodPlan(ctx, cfg, plans)
	cancel()
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "domain": cfg.Domain, "subdomain": cfg.SubDomain, "changes": changes, "lines": planLinesForDNSPod(plans, cfg.MinSubmitters)})
}

package main

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
)

const candidateCSVMaxBytes = 8 << 20

type candidateCSVImport struct {
	Targets  []string              `json:"targets"`
	Metadata map[string]ipMetadata `json:"metadata"`
	Rows     int                   `json:"rows"`
	Skipped  int                   `json:"skipped"`
}

func normalizeCSVHeader(value string) string {
	value = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(value, "\ufeff")))
	replacer := strings.NewReplacer(" ", "_", "-", "_", "/", "_", ".", "_", "(", "", ")", "")
	value = replacer.Replace(value)
	for strings.Contains(value, "__") {
		value = strings.ReplaceAll(value, "__", "_")
	}
	return strings.Trim(value, "_")
}

func csvColumnIndex(headers []string, aliases ...string) int {
	lookup := make(map[string]struct{}, len(aliases))
	for _, alias := range aliases {
		lookup[normalizeCSVHeader(alias)] = struct{}{}
	}
	for i, header := range headers {
		if _, ok := lookup[normalizeCSVHeader(header)]; ok {
			return i
		}
	}
	return -1
}

func csvCell(row []string, idx int) string {
	if idx < 0 || idx >= len(row) {
		return ""
	}
	return strings.TrimSpace(row[idx])
}

func parseImportedASN(value string) int {
	value = strings.TrimSpace(value)
	if fields := strings.Fields(value); len(fields) > 0 {
		value = fields[0]
	}
	value = strings.TrimPrefix(strings.TrimPrefix(value, "AS"), "as")
	n, _ := strconv.Atoi(value)
	if n < 0 {
		return 0
	}
	return n
}

func splitImportedEndpoint(value string) (string, int, bool) {
	value = strings.TrimSpace(value)
	if ip := net.ParseIP(value); ip != nil && ip.To4() != nil {
		return ip.String(), 0, true
	}
	if strings.Count(value, ":") == 1 {
		host, portText, err := net.SplitHostPort(value)
		if err == nil {
			ip := net.ParseIP(host)
			port, portErr := strconv.Atoi(portText)
			if ip != nil && ip.To4() != nil && portErr == nil && port >= 1 && port <= 65535 {
				return ip.String(), port, true
			}
		}
	}
	return "", 0, false
}

func looksLikeCSVHeader(row []string) bool {
	for _, cell := range row {
		n := normalizeCSVHeader(cell)
		switch n {
		case "ip", "ip_address", "address", "host", "endpoint", "port", "asn", "idc", "country", "country_code", "region", "city", "isp", "org", "organization", "端口", "地区", "国家", "城市", "运营商", "厂家":
			return true
		}
	}
	return false
}

func parseCandidateCSV(reader io.Reader) (candidateCSVImport, error) {
	result := candidateCSVImport{Metadata: make(map[string]ipMetadata)}
	cr := csv.NewReader(io.LimitReader(reader, candidateCSVMaxBytes+1))
	cr.FieldsPerRecord = -1
	cr.TrimLeadingSpace = true
	records, err := cr.ReadAll()
	if err != nil {
		return result, fmt.Errorf("read CSV: %w", err)
	}
	if len(records) == 0 {
		return result, errors.New("CSV is empty")
	}

	headers := []string{"ip", "port"}
	start := 0
	if looksLikeCSVHeader(records[0]) {
		headers = records[0]
		start = 1
	}
	ipIdx := csvColumnIndex(headers, "ip", "ip_address", "address", "host", "endpoint", "server", "server_ip", "node_ip", "ip地址")
	if ipIdx < 0 {
		ipIdx = 0
	}
	portIdx := csvColumnIndex(headers, "port", "endpoint_port", "server_port", "node_port", "端口")
	countryIdx := csvColumnIndex(headers, "country", "country_name", "国家")
	countryCodeIdx := csvColumnIndex(headers, "country_code", "countrycode", "cc", "country_iso")
	regionIdx := csvColumnIndex(headers, "region", "state", "province", "location", "area", "地区", "区域", "省份")
	cityIdx := csvColumnIndex(headers, "city", "城市")
	asnIdx := csvColumnIndex(headers, "asn", "as_number", "asnumber", "as")
	orgIdx := csvColumnIndex(headers, "org", "organization", "asn_org", "as_org", "组织")
	ispIdx := csvColumnIndex(headers, "isp", "carrier", "运营商")
	idcIdx := csvColumnIndex(headers, "idc", "idc_vendor", "vendor", "provider", "cloud", "cloud_provider", "厂家", "idc厂家", "云厂商")

	seen := make(map[string]struct{})
	for _, row := range records[start:] {
		result.Rows++
		ip, embeddedPort, ok := splitImportedEndpoint(csvCell(row, ipIdx))
		if !ok {
			result.Skipped++
			continue
		}
		port := embeddedPort
		if rawPort := csvCell(row, portIdx); rawPort != "" {
			if parsed, err := strconv.Atoi(rawPort); err == nil && parsed >= 1 && parsed <= 65535 {
				port = parsed
			}
		}
		target := ip
		if port > 0 {
			target = net.JoinHostPort(ip, strconv.Itoa(port))
		}
		if _, exists := seen[target]; !exists {
			seen[target] = struct{}{}
			result.Targets = append(result.Targets, target)
		}

		meta := ipMetadata{
			IP:          ip,
			Country:     csvCell(row, countryIdx),
			CountryCode: csvCell(row, countryCodeIdx),
			Region:      csvCell(row, regionIdx),
			City:        csvCell(row, cityIdx),
			ASN:         parseImportedASN(csvCell(row, asnIdx)),
			Org:         csvCell(row, orgIdx),
			ISP:         csvCell(row, ispIdx),
			IDC:         csvCell(row, idcIdx),
			Source:      "csv",
		}
		if meta.IDC == "" {
			meta.IDC = meta.Org
		}
		if meta.IDC == "" {
			meta.IDC = meta.ISP
		}
		if metadataMeaningful(meta) {
			result.Metadata[ip] = normalizeMetadata(meta)
		}
	}
	if len(result.Targets) == 0 {
		return result, errors.New("CSV contains no valid IPv4 candidate")
	}
	return result, nil
}

func handleCandidateCSVImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, candidateCSVMaxBytes+(1<<20))
	if err := r.ParseMultipartForm(candidateCSVMaxBytes); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid CSV upload: " + err.Error()})
		return
	}
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}
	file, _, err := r.FormFile("file")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing CSV file"})
		return
	}
	defer file.Close()
	result, err := parseCandidateCSV(file)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	for _, meta := range result.Metadata {
		seedIPMetadata(meta, metadataImportedTTL)
	}
	writeJSON(w, http.StatusOK, result)
}

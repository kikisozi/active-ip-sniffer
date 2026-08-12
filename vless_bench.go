package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	vlessBenchMaxCandidates   = 128
	vlessBenchTCPAttempts     = 3
	vlessBenchDefaultMB       = 30
	vlessBenchMaxMB           = 100
	vlessBenchDownloadTimeout = 5 * time.Second
	vlessBenchDefaultTarget   = "speed.cloudflare.com"
	vlessBenchTargetPort      = 443
	websocketMagic            = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
)

type vlessEndpointConfig struct {
	UUID     [16]byte
	Port     int
	SNI      string
	WSHost   string
	WSPath   string
	Insecure bool
}

type vlessBenchRequest struct {
	VLESS      string   `json:"vless"`
	Candidates []string `json:"candidates"`
	BytesMB    int      `json:"bytes_mb"`
	Timeout    float64  `json:"timeout"`
	EgressMode string   `json:"egress_mode,omitempty"`
	WARPProxy  string   `json:"warp_proxy,omitempty"`
}

type vlessBenchResult struct {
	IP           string  `json:"ip"`
	TCPPassed    int     `json:"tcp_passed"`
	TCPAttempts  int     `json:"tcp_attempts"`
	TCPMedianMS  float64 `json:"tcp_median_ms"`
	TransportOK  bool    `json:"transport_ok"`
	TransportMS  float64 `json:"transport_ms"`
	VLESSOK      bool    `json:"vless_ok"`
	StartupMS    float64 `json:"startup_ms"`
	First1Mbps   float64 `json:"first_1s_mbps"`
	First3Mbps   float64 `json:"first_3s_mbps"`
	StableMbps   float64 `json:"stable_mbps"`
	PeakMbps     float64 `json:"peak_mbps"`
	Downloaded   int64   `json:"downloaded_bytes"`
	DownloadSec  float64 `json:"download_seconds"`
	Status       string  `json:"status"`
	FailureStage string  `json:"failure_stage,omitempty"`
	Error        string  `json:"error,omitempty"`
}

type vlessBenchJob struct {
	id        string
	startedAt time.Time
	ctx       context.Context
	cancel    context.CancelFunc

	mu      sync.RWMutex
	status  string
	message string
	total   int
	results []vlessBenchResult
}

func (j *vlessBenchJob) setState(status, message string) {
	j.mu.Lock()
	j.status = status
	j.message = message
	j.mu.Unlock()
}

func (j *vlessBenchJob) addResult(result vlessBenchResult) {
	j.mu.Lock()
	j.results = append(j.results, result)
	j.mu.Unlock()
}

func (j *vlessBenchJob) snapshot() map[string]any {
	j.mu.RLock()
	results := append([]vlessBenchResult(nil), j.results...)
	status := j.status
	message := j.message
	total := j.total
	j.mu.RUnlock()
	passed := 0
	for _, result := range results {
		if result.Status == "ok" {
			passed++
		}
	}
	return map[string]any{
		"id":      j.id,
		"status":  status,
		"message": message,
		"done":    len(results),
		"total":   total,
		"passed":  passed,
		"results": results,
	}
}

type vlessBenchJobStore struct {
	mu   sync.RWMutex
	jobs map[string]*vlessBenchJob
}

func newVLESSBenchJobStore() *vlessBenchJobStore {
	return &vlessBenchJobStore{jobs: make(map[string]*vlessBenchJob)}
}

func (s *vlessBenchJobStore) put(job *vlessBenchJob) {
	s.mu.Lock()
	s.jobs[job.id] = job
	s.mu.Unlock()
}

func (s *vlessBenchJobStore) get(id string) (*vlessBenchJob, bool) {
	s.mu.RLock()
	job, ok := s.jobs[id]
	s.mu.RUnlock()
	return job, ok
}

func (s *vlessBenchJobStore) cleanupOld(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, job := range s.jobs {
		if now.Sub(job.startedAt) < jobRetention {
			continue
		}
		job.cancel()
		delete(s.jobs, id)
	}
}

func (s *vlessBenchJobStore) cancelAll() {
	s.mu.RLock()
	jobs := make([]*vlessBenchJob, 0, len(s.jobs))
	for _, job := range s.jobs {
		jobs = append(jobs, job)
	}
	s.mu.RUnlock()
	for _, job := range jobs {
		job.cancel()
	}
}

var vlessBenchJobs = newVLESSBenchJobStore()

func parseVLESSEndpoint(raw string) (vlessEndpointConfig, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || !strings.EqualFold(u.Scheme, "vless") {
		return vlessEndpointConfig{}, errors.New("invalid VLESS URI")
	}
	if u.User == nil || u.User.Username() == "" {
		return vlessEndpointConfig{}, errors.New("VLESS UUID is missing")
	}
	uuidText := strings.ReplaceAll(u.User.Username(), "-", "")
	if len(uuidText) != 32 {
		return vlessEndpointConfig{}, errors.New("invalid VLESS UUID length")
	}
	uuidBytes, err := hex.DecodeString(uuidText)
	if err != nil {
		return vlessEndpointConfig{}, fmt.Errorf("invalid VLESS UUID: %w", err)
	}
	var uuid [16]byte
	copy(uuid[:], uuidBytes)
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return vlessEndpointConfig{}, errors.New("invalid VLESS port")
	}
	q := u.Query()
	if network := q.Get("type"); network != "" && !strings.EqualFold(network, "ws") {
		return vlessEndpointConfig{}, fmt.Errorf("VLESS endpoint bench currently supports type=ws, got %q", network)
	}
	if security := q.Get("security"); security != "" && !strings.EqualFold(security, "tls") {
		return vlessEndpointConfig{}, fmt.Errorf("VLESS endpoint bench currently supports security=tls, got %q", security)
	}
	sni := strings.TrimSpace(q.Get("sni"))
	host := strings.TrimSpace(q.Get("host"))
	if host == "" {
		host = sni
	}
	if sni == "" {
		sni = host
	}
	if sni == "" || host == "" {
		return vlessEndpointConfig{}, errors.New("VLESS SNI/Host is missing")
	}
	path := q.Get("path")
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	insecure := q.Get("insecure") == "1" || q.Get("allowInsecure") == "1" || strings.EqualFold(q.Get("allowInsecure"), "true")
	return vlessEndpointConfig{UUID: uuid, Port: port, SNI: sni, WSHost: host, WSPath: path, Insecure: insecure}, nil
}

func normalizeBenchCandidates(values []string) ([]string, error) {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if value == "" {
			continue
		}
		ip := net.ParseIP(value)
		if ip == nil || ip.To4() == nil {
			return nil, fmt.Errorf("invalid IPv4 candidate: %s", value)
		}
		value = ip.To4().String()
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	if len(result) == 0 {
		return nil, errors.New("provide at least one IPv4 candidate")
	}
	if len(result) > vlessBenchMaxCandidates {
		return nil, fmt.Errorf("provide at most %d VLESS candidates", vlessBenchMaxCandidates)
	}
	return result, nil
}

func tcpMedian(ctx context.Context, ip string, port, attempts int, timeout time.Duration, egress egressConfig) (int, time.Duration) {
	values := make([]time.Duration, 0, attempts)
	for i := 0; i < attempts; i++ {
		select {
		case <-ctx.Done():
			return len(values), medianDuration(values)
		default:
		}
		started := time.Now()
		conn, err := egress.dialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)), timeout)
		if err != nil {
			continue
		}
		values = append(values, time.Since(started))
		_ = conn.Close()
	}
	return len(values), medianDuration(values)
}

func medianDuration(values []time.Duration) time.Duration {
	if len(values) == 0 {
		return 0
	}
	copyValues := append([]time.Duration(nil), values...)
	sort.Slice(copyValues, func(i, j int) bool { return copyValues[i] < copyValues[j] })
	mid := len(copyValues) / 2
	if len(copyValues)%2 == 1 {
		return copyValues[mid]
	}
	return (copyValues[mid-1] + copyValues[mid]) / 2
}

type websocketStreamConn struct {
	net.Conn
	reader *bufio.Reader

	writeMu sync.Mutex
	readMu  sync.Mutex
	remain  int64
	masked  bool
	mask    [4]byte
	maskPos int
}

func newWebsocketStreamConn(conn net.Conn, reader *bufio.Reader) *websocketStreamConn {
	return &websocketStreamConn{Conn: conn, reader: reader}
}

func (w *websocketStreamConn) Write(p []byte) (int, error) {
	w.writeMu.Lock()
	defer w.writeMu.Unlock()
	if err := w.writeFrameLocked(0x2, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (w *websocketStreamConn) writeFrameLocked(opcode byte, p []byte) error {
	header := make([]byte, 0, 14)
	header = append(header, 0x80|(opcode&0x0f))
	n := len(p)
	switch {
	case n < 126:
		header = append(header, 0x80|byte(n))
	case n <= 65535:
		header = append(header, 0x80|126, byte(n>>8), byte(n))
	default:
		length := uint64(n)
		header = append(header, 0x80|127,
			byte(length>>56), byte(length>>48), byte(length>>40), byte(length>>32),
			byte(length>>24), byte(length>>16), byte(length>>8), byte(length))
	}
	var mask [4]byte
	if _, err := rand.Read(mask[:]); err != nil {
		return err
	}
	header = append(header, mask[:]...)
	if _, err := w.Conn.Write(header); err != nil {
		return err
	}
	masked := make([]byte, len(p))
	for i := range p {
		masked[i] = p[i] ^ mask[i&3]
	}
	_, err := w.Conn.Write(masked)
	return err
}

func (w *websocketStreamConn) Read(p []byte) (int, error) {
	w.readMu.Lock()
	defer w.readMu.Unlock()
	for {
		if w.remain > 0 {
			want := len(p)
			if int64(want) > w.remain {
				want = int(w.remain)
			}
			n, err := io.ReadFull(w.reader, p[:want])
			if w.masked {
				for i := 0; i < n; i++ {
					p[i] ^= w.mask[w.maskPos&3]
					w.maskPos++
				}
			}
			w.remain -= int64(n)
			if err != nil {
				return n, err
			}
			return n, nil
		}

		opcode, payloadLen, masked, mask, err := w.readFrameHeader()
		if err != nil {
			return 0, err
		}
		switch opcode {
		case 0x0, 0x2:
			w.remain = payloadLen
			w.masked = masked
			w.mask = mask
			w.maskPos = 0
			if payloadLen == 0 {
				continue
			}
		case 0x8:
			if payloadLen > 0 {
				_, _ = io.CopyN(io.Discard, w.reader, payloadLen)
			}
			return 0, io.EOF
		case 0x9:
			payload := make([]byte, payloadLen)
			if _, err := io.ReadFull(w.reader, payload); err != nil {
				return 0, err
			}
			if masked {
				for i := range payload {
					payload[i] ^= mask[i&3]
				}
			}
			w.writeMu.Lock()
			err := w.writeFrameLocked(0xA, payload)
			w.writeMu.Unlock()
			if err != nil {
				return 0, err
			}
		case 0xA:
			if payloadLen > 0 {
				_, _ = io.CopyN(io.Discard, w.reader, payloadLen)
			}
		default:
			return 0, fmt.Errorf("unsupported websocket opcode 0x%x", opcode)
		}
	}
}

func (w *websocketStreamConn) readFrameHeader() (byte, int64, bool, [4]byte, error) {
	var mask [4]byte
	header := make([]byte, 2)
	if _, err := io.ReadFull(w.reader, header); err != nil {
		return 0, 0, false, mask, err
	}
	opcode := header[0] & 0x0f
	masked := header[1]&0x80 != 0
	length := uint64(header[1] & 0x7f)
	if length == 126 {
		extended := make([]byte, 2)
		if _, err := io.ReadFull(w.reader, extended); err != nil {
			return 0, 0, false, mask, err
		}
		length = uint64(extended[0])<<8 | uint64(extended[1])
	} else if length == 127 {
		extended := make([]byte, 8)
		if _, err := io.ReadFull(w.reader, extended); err != nil {
			return 0, 0, false, mask, err
		}
		length = 0
		for _, value := range extended {
			length = length<<8 | uint64(value)
		}
	}
	if length > math.MaxInt64 {
		return 0, 0, false, mask, errors.New("websocket frame is too large")
	}
	if masked {
		if _, err := io.ReadFull(w.reader, mask[:]); err != nil {
			return 0, 0, false, mask, err
		}
	}
	return opcode, int64(length), masked, mask, nil
}

func dialVLESSWebsocket(ctx context.Context, cfg vlessEndpointConfig, candidate string, timeout time.Duration, egress egressConfig) (*websocketStreamConn, time.Duration, error) {
	started := time.Now()
	raw, err := egress.dialContext(ctx, "tcp", net.JoinHostPort(candidate, strconv.Itoa(cfg.Port)), timeout)
	if err != nil {
		return nil, 0, err
	}
	keep := false
	defer func() {
		if !keep {
			_ = raw.Close()
		}
	}()
	_ = raw.SetDeadline(time.Now().Add(timeout))
	tlsConn := tls.Client(raw, &tls.Config{
		ServerName:         cfg.SNI,
		InsecureSkipVerify: cfg.Insecure, // URI explicitly controls this probe behavior.
		MinVersion:         tls.VersionTLS12,
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, 0, fmt.Errorf("TLS: %w", err)
	}
	keyBytes := make([]byte, 16)
	if _, err := rand.Read(keyBytes); err != nil {
		return nil, 0, err
	}
	key := base64.StdEncoding.EncodeToString(keyBytes)
	request := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\nUser-Agent: Active-IP-Sniffer/%s\r\n\r\n", cfg.WSPath, cfg.WSHost, key, appVersion)
	if _, err := io.WriteString(tlsConn, request); err != nil {
		return nil, 0, fmt.Errorf("websocket request: %w", err)
	}
	reader := bufio.NewReaderSize(tlsConn, 32*1024)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err != nil {
		return nil, 0, fmt.Errorf("websocket response: %w", err)
	}
	if response.StatusCode != http.StatusSwitchingProtocols {
		if response.Body != nil {
			_ = response.Body.Close()
		}
		return nil, 0, fmt.Errorf("websocket HTTP status %d", response.StatusCode)
	}
	if !strings.EqualFold(strings.TrimSpace(response.Header.Get("Upgrade")), "websocket") {
		return nil, 0, errors.New("websocket upgrade header is missing")
	}
	wantHash := sha1.Sum([]byte(key + websocketMagic))
	wantAccept := base64.StdEncoding.EncodeToString(wantHash[:])
	if strings.TrimSpace(response.Header.Get("Sec-WebSocket-Accept")) != wantAccept {
		return nil, 0, errors.New("invalid Sec-WebSocket-Accept")
	}
	_ = tlsConn.SetDeadline(time.Time{})
	keep = true
	return newWebsocketStreamConn(tlsConn, reader), time.Since(started), nil
}

type vlessStreamConn struct {
	net.Conn
	readMu     sync.Mutex
	responseOK bool
}

func (v *vlessStreamConn) Read(p []byte) (int, error) {
	v.readMu.Lock()
	defer v.readMu.Unlock()
	if !v.responseOK {
		header := make([]byte, 2)
		if _, err := io.ReadFull(v.Conn, header); err != nil {
			return 0, fmt.Errorf("VLESS response header: %w", err)
		}
		if header[0] != 0 {
			return 0, fmt.Errorf("unexpected VLESS response version %d", header[0])
		}
		if header[1] > 0 {
			if _, err := io.CopyN(io.Discard, v.Conn, int64(header[1])); err != nil {
				return 0, fmt.Errorf("VLESS response addon: %w", err)
			}
		}
		v.responseOK = true
	}
	return v.Conn.Read(p)
}

func makeVLESSRequest(uuid [16]byte, targetHost string, targetPort int) ([]byte, error) {
	if targetPort < 1 || targetPort > 65535 {
		return nil, errors.New("invalid target port")
	}
	request := make([]byte, 0, 64)
	request = append(request, 0x00)
	request = append(request, uuid[:]...)
	request = append(request, 0x00) // addon length
	request = append(request, 0x01) // TCP command
	request = append(request, byte(targetPort>>8), byte(targetPort))
	if ip := net.ParseIP(targetHost); ip != nil {
		if ipv4 := ip.To4(); ipv4 != nil {
			request = append(request, 0x01)
			request = append(request, ipv4...)
		} else {
			ipv6 := ip.To16()
			if ipv6 == nil {
				return nil, errors.New("invalid target IP")
			}
			request = append(request, 0x03)
			request = append(request, ipv6...)
		}
	} else {
		if len(targetHost) == 0 || len(targetHost) > 255 {
			return nil, errors.New("invalid target hostname length")
		}
		request = append(request, 0x02, byte(len(targetHost)))
		request = append(request, targetHost...)
	}
	return request, nil
}

func dialVLESS(ctx context.Context, cfg vlessEndpointConfig, candidate, targetHost string, targetPort int, timeout time.Duration, egress egressConfig) (net.Conn, time.Duration, error) {
	websocketConn, transportTime, err := dialVLESSWebsocket(ctx, cfg, candidate, timeout, egress)
	if err != nil {
		return nil, 0, err
	}
	request, err := makeVLESSRequest(cfg.UUID, targetHost, targetPort)
	if err != nil {
		_ = websocketConn.Close()
		return nil, transportTime, err
	}
	_ = websocketConn.SetWriteDeadline(time.Now().Add(timeout))
	if _, err := websocketConn.Write(request); err != nil {
		_ = websocketConn.Close()
		return nil, transportTime, fmt.Errorf("send VLESS request: %w", err)
	}
	_ = websocketConn.SetWriteDeadline(time.Time{})
	return &vlessStreamConn{Conn: websocketConn}, transportTime, nil
}

func runVLESSBenchCandidate(ctx context.Context, cfg vlessEndpointConfig, candidate string, bytesWanted int64, timeout time.Duration, egress egressConfig) vlessBenchResult {
	result := vlessBenchResult{IP: candidate, TCPAttempts: vlessBenchTCPAttempts, Status: "failed"}
	tcpTimeout := timeout
	if tcpTimeout > 3*time.Second {
		tcpTimeout = 3 * time.Second
	}
	result.TCPPassed, result.TCPMedianMS = 0, 0
	passed, median := tcpMedian(ctx, candidate, cfg.Port, vlessBenchTCPAttempts, tcpTimeout, egress)
	result.TCPPassed = passed
	result.TCPMedianMS = durationMS(median)
	if passed == 0 {
		result.FailureStage = "tcp"
		result.Error = "TCP unreachable"
		return result
	}

	startupStarted := time.Now()
	conn, transportTime, err := dialVLESS(ctx, cfg, candidate, vlessBenchDefaultTarget, vlessBenchTargetPort, timeout, egress)
	result.TransportMS = durationMS(transportTime)
	result.TransportOK = transportTime > 0
	if err != nil {
		result.FailureStage = "transport"
		result.Error = err.Error()
		return result
	}
	defer conn.Close()

	watchDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-watchDone:
		}
	}()
	defer close(watchDone)

	innerTLS := tls.Client(conn, &tls.Config{ServerName: vlessBenchDefaultTarget, MinVersion: tls.VersionTLS12})
	_ = innerTLS.SetDeadline(time.Now().Add(timeout))
	if err := innerTLS.HandshakeContext(ctx); err != nil {
		result.FailureStage = "vless"
		result.Error = "VLESS target TLS: " + err.Error()
		return result
	}
	result.VLESSOK = true
	result.StartupMS = durationMS(time.Since(startupStarted))
	_ = innerTLS.SetDeadline(time.Time{})

	path := fmt.Sprintf("/__down?bytes=%d", bytesWanted)
	request := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Active-IP-Sniffer/%s\r\nAccept: */*\r\nConnection: close\r\n\r\n", path, vlessBenchDefaultTarget, appVersion)
	_ = innerTLS.SetDeadline(time.Now().Add(timeout + 30*time.Second))
	if _, err := io.WriteString(innerTLS, request); err != nil {
		result.FailureStage = "download"
		result.Error = "speed request: " + err.Error()
		return result
	}
	reader := bufio.NewReaderSize(innerTLS, 64*1024)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err != nil {
		result.FailureStage = "download"
		result.Error = "speed response: " + err.Error()
		return result
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		result.FailureStage = "download"
		result.Error = fmt.Sprintf("speed HTTP status %d", response.StatusCode)
		return result
	}

	bodyStarted := time.Now()
	_ = innerTLS.SetReadDeadline(bodyStarted.Add(vlessBenchDownloadTimeout))
	windowStarted := bodyStarted
	buffer := make([]byte, 64*1024)
	var total int64
	var bytesAt1 int64
	var bytesAt3 int64
	var windowBytes int64
	var peakMbps float64
	for total < bytesWanted {
		n, readErr := response.Body.Read(buffer)
		if n > 0 {
			total += int64(n)
			windowBytes += int64(n)
			now := time.Now()
			elapsed := now.Sub(bodyStarted)
			if bytesAt1 == 0 && elapsed >= time.Second {
				bytesAt1 = total
			}
			if bytesAt3 == 0 && elapsed >= 3*time.Second {
				bytesAt3 = total
			}
			windowElapsed := now.Sub(windowStarted)
			if windowElapsed >= 250*time.Millisecond {
				peakMbps = math.Max(peakMbps, bitsPerSecondMbps(windowBytes, windowElapsed))
				windowStarted = now
				windowBytes = 0
			}
		}
		if readErr != nil {
			if !errors.Is(readErr, io.EOF) {
				if netErr, ok := readErr.(net.Error); ok && netErr.Timeout() {
					result.FailureStage = "download_timeout"
					result.Error = fmt.Sprintf("30 MB download did not complete within %.0f seconds", vlessBenchDownloadTimeout.Seconds())
				} else {
					result.FailureStage = "download"
					result.Error = "speed body: " + readErr.Error()
				}
			}
			break
		}
	}
	_ = innerTLS.SetReadDeadline(time.Time{})
	elapsed := time.Since(bodyStarted)
	if finalWindow := time.Since(windowStarted); windowBytes > 0 && finalWindow >= 100*time.Millisecond {
		peakMbps = math.Max(peakMbps, bitsPerSecondMbps(windowBytes, finalWindow))
	}
	if bytesAt1 == 0 {
		bytesAt1 = total
	}
	if bytesAt3 == 0 {
		bytesAt3 = total
	}
	result.Downloaded = total
	result.DownloadSec = roundFloat(elapsed.Seconds(), 3)
	result.First1Mbps = roundFloat(bitsPerSecondMbps(bytesAt1, minBenchDuration(elapsed, time.Second)), 1)
	result.First3Mbps = roundFloat(bitsPerSecondMbps(bytesAt3, minBenchDuration(elapsed, 3*time.Second)), 1)
	result.PeakMbps = roundFloat(peakMbps, 1)
	if elapsed > 1500*time.Millisecond && total > bytesAt1 {
		result.StableMbps = roundFloat(bitsPerSecondMbps(total-bytesAt1, elapsed-time.Second), 1)
	} else {
		result.StableMbps = roundFloat(bitsPerSecondMbps(total, elapsed), 1)
	}
	if result.Error == "" && elapsed > vlessBenchDownloadTimeout {
		result.FailureStage = "download_timeout"
		result.Error = fmt.Sprintf("30 MB download did not complete within %.0f seconds", vlessBenchDownloadTimeout.Seconds())
	}
	if result.Error == "" && total == bytesWanted && elapsed <= vlessBenchDownloadTimeout {
		result.Status = "ok"
	} else if result.Error == "" {
		result.FailureStage = "download"
		result.Error = fmt.Sprintf("downloaded %d bytes, expected %d", total, bytesWanted)
	}
	return result
}

func durationMS(value time.Duration) float64 {
	return roundFloat(float64(value)/float64(time.Millisecond), 1)
}

func bitsPerSecondMbps(bytes int64, duration time.Duration) float64 {
	if bytes <= 0 || duration <= 0 {
		return 0
	}
	return float64(bytes*8) / duration.Seconds() / 1_000_000
}

func minBenchDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

func roundFloat(value float64, digits int) float64 {
	pow := math.Pow10(digits)
	return math.Round(value*pow) / pow
}

func executeVLESSBench(job *vlessBenchJob, cfg vlessEndpointConfig, candidates []string, bytesWanted int64, timeout time.Duration, egress egressConfig) {
	job.setState("running", "VLESS endpoint benchmark running sequentially")
	for _, candidate := range candidates {
		select {
		case <-job.ctx.Done():
			job.setState("cancelled", "VLESS endpoint benchmark cancelled")
			return
		default:
		}
		job.addResult(runVLESSBenchCandidate(job.ctx, cfg, candidate, bytesWanted, timeout, egress))
	}
	if job.ctx.Err() != nil {
		job.setState("cancelled", "VLESS endpoint benchmark cancelled")
		return
	}
	job.setState("complete", "VLESS endpoint benchmark complete")
}

func handleVLESSBenchStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 200_000)
	defer r.Body.Close()
	var request vlessBenchRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request: " + err.Error()})
		return
	}
	cfg, err := parseVLESSEndpoint(request.VLESS)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	candidates, err := normalizeBenchCandidates(request.Candidates)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	bytesMB := vlessBenchDefaultMB
	if request.BytesMB != 0 && request.BytesMB != vlessBenchDefaultMB {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("VLESS benchmark is fixed at %d MB", vlessBenchDefaultMB)})
		return
	}
	timeoutSeconds := clampFloat(request.Timeout, 2, 20, 12)
	timeout := time.Duration(timeoutSeconds * float64(time.Second))
	requestedEgress := egressConfig{Mode: "direct", WARPProxy: defaultWARPProxy}
	egress := requestedEgress
	vlessBenchJobs.cleanupOld(time.Now())
	ctx, cancel := context.WithCancel(context.Background())
	id := newJobID()
	job := &vlessBenchJob{id: id, startedAt: time.Now(), ctx: ctx, cancel: cancel, status: "queued", total: len(candidates)}
	vlessBenchJobs.put(job)
	go executeVLESSBench(job, cfg, candidates, int64(bytesMB)*1_000_000, timeout, egress)
	writeJSON(w, http.StatusAccepted, map[string]any{
		"id":                    id,
		"candidates":            len(candidates),
		"bytes_mb":              bytesMB,
		"download_timeout_s":    vlessBenchDownloadTimeout.Seconds(),
		"target":                vlessBenchDefaultTarget,
		"requested_egress_mode": requestedEgress.Mode,
		"egress_mode":           egress.Mode,
	})
}

func handleVLESSBenchJob(w http.ResponseWriter, r *http.Request) {
	job, ok := vlessBenchJobs.get(r.URL.Query().Get("id"))
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "VLESS benchmark job not found"})
		return
	}
	writeJSON(w, http.StatusOK, job.snapshot())
}

func handleVLESSBenchCancel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	job, ok := vlessBenchJobs.get(r.URL.Query().Get("id"))
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "VLESS benchmark job not found"})
		return
	}
	job.cancel()
	job.setState("cancelled", "VLESS endpoint benchmark cancelled")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func handleVLESSBenchExportCSV(w http.ResponseWriter, r *http.Request) {
	job, ok := vlessBenchJobs.get(r.URL.Query().Get("id"))
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "VLESS benchmark job not found"})
		return
	}
	job.mu.RLock()
	results := append([]vlessBenchResult(nil), job.results...)
	job.mu.RUnlock()
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", "vless-endpoint-bench-"+time.Now().Format("20060102-150405")+".csv"))
	writer := csv.NewWriter(w)
	_ = writer.Write([]string{"ip", "tcp_passed", "tcp_attempts", "tcp_median_ms", "transport_ok", "transport_ms", "vless_ok", "startup_ms", "first_1s_mbps", "first_3s_mbps", "stable_mbps", "peak_mbps", "downloaded_bytes", "download_seconds", "status", "failure_stage", "error"})
	for _, result := range results {
		_ = writer.Write([]string{
			result.IP,
			strconv.Itoa(result.TCPPassed), strconv.Itoa(result.TCPAttempts), fmt.Sprintf("%.1f", result.TCPMedianMS),
			strconv.FormatBool(result.TransportOK), fmt.Sprintf("%.1f", result.TransportMS),
			strconv.FormatBool(result.VLESSOK), fmt.Sprintf("%.1f", result.StartupMS),
			fmt.Sprintf("%.1f", result.First1Mbps), fmt.Sprintf("%.1f", result.First3Mbps), fmt.Sprintf("%.1f", result.StableMbps), fmt.Sprintf("%.1f", result.PeakMbps),
			strconv.FormatInt(result.Downloaded, 10), fmt.Sprintf("%.3f", result.DownloadSec), result.Status, result.FailureStage, result.Error,
		})
	}
	writer.Flush()
}

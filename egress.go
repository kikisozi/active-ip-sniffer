package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const defaultWARPProxy = "127.0.0.1:40099"

type egressConfig struct {
	Mode      string `json:"egress_mode,omitempty"`
	WARPProxy string `json:"warp_proxy,omitempty"`
}

func normalizeEgress(mode, proxy string) (egressConfig, error) {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		mode = "auto"
	}
	if mode != "auto" && mode != "direct" && mode != "warp" {
		return egressConfig{}, fmt.Errorf("unsupported egress mode: %s", mode)
	}
	proxy = strings.TrimSpace(proxy)
	if proxy == "" {
		proxy = defaultWARPProxy
	}
	if mode == "warp" || mode == "auto" {
		host, portText, err := net.SplitHostPort(proxy)
		if err != nil || strings.TrimSpace(host) == "" {
			return egressConfig{}, fmt.Errorf("invalid WARP local proxy: %s", proxy)
		}
		port, err := strconv.Atoi(portText)
		if err != nil || port < 1 || port > 65535 {
			return egressConfig{}, fmt.Errorf("invalid WARP proxy port: %s", portText)
		}
	}
	return egressConfig{Mode: mode, WARPProxy: proxy}, nil
}

func warpTraceActive(info egressInfo) bool {
	warp := strings.ToLower(strings.TrimSpace(info.WARP))
	return info.IP != "" && (warp == "on" || warp == "plus")
}

// resolveEgress resolves Auto once at task start so a single benchmark never
// switches routes halfway through. Explicit WARP is accepted only when the
// configured SOCKS5 endpoint actually produces a Cloudflare WARP trace.
func resolveEgress(ctx context.Context, requested egressConfig) (egressConfig, egressInfo, error) {
	switch requested.Mode {
	case "direct":
		direct := egressConfig{Mode: "direct", WARPProxy: requested.WARPProxy}
		return direct, queryCloudflareTrace(ctx, direct), nil
	case "warp":
		info := queryCloudflareTrace(ctx, requested)
		if info.IP == "" {
			return requested, info, fmt.Errorf("WARP Local Proxy %s is not reachable or cannot reach Cloudflare", requested.WARPProxy)
		}
		if !warpTraceActive(info) {
			return requested, info, fmt.Errorf("proxy %s is reachable but Cloudflare trace reports warp=%s", requested.WARPProxy, strings.TrimSpace(info.WARP))
		}
		return requested, info, nil
	case "auto":
		warp := egressConfig{Mode: "warp", WARPProxy: requested.WARPProxy}
		if info := queryCloudflareTrace(ctx, warp); warpTraceActive(info) {
			return warp, info, nil
		}
		direct := egressConfig{Mode: "direct", WARPProxy: requested.WARPProxy}
		return direct, queryCloudflareTrace(ctx, direct), nil
	default:
		return requested, egressInfo{}, fmt.Errorf("unsupported egress mode: %s", requested.Mode)
	}
}

// resolveScanEgress is deliberately used only by active scanning. It may try
// to reconnect an already-installed WARP client before falling back to Direct.
// Benchmark paths do not call this function because speed results must reflect
// the machine's real/direct network path.
func resolveScanEgress(ctx context.Context, requested egressConfig) (egressConfig, egressInfo, error) {
	selected, info, err := resolveEgress(ctx, requested)
	if requested.Mode == "direct" || (err == nil && selected.Mode == "warp") {
		return selected, info, err
	}
	if requested.Mode != "auto" && requested.Mode != "warp" {
		return selected, info, err
	}
	if !tryStartInstalledWARP(ctx) {
		return selected, info, err
	}
	// Give the local proxy a short window to become ready after reconnecting.
	deadline := time.Now().Add(4 * time.Second)
	for {
		selected, info, err = resolveEgress(ctx, requested)
		if err == nil && selected.Mode == "warp" {
			return selected, info, nil
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return selected, info, err
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func tryStartInstalledWARP(ctx context.Context) bool {
	if _, err := exec.LookPath("warp-cli"); err != nil {
		return false
	}
	managed := false
	switch runtime.GOOS {
	case "linux":
		_, err := os.Stat("/var/lib/active-ip-sniffer/warp-local-proxy-managed")
		managed = err == nil
	case "windows":
		if programData := strings.TrimSpace(os.Getenv("ProgramData")); programData != "" {
			_, err := os.Stat(filepath.Join(programData, "ActiveIPSniffer", "warp-local-proxy-managed"))
			managed = err == nil
		}
	}
	if !managed {
		return false
	}
	commandCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	// If the project helper exists and we already have sufficient privilege,
	// prefer it because it also restores MASQUE + proxy port 40099. We never
	// invoke sudo/UAC from a background scan request.
	if runtime.GOOS == "linux" && os.Geteuid() == 0 {
		for _, helper := range []string{"/opt/active-ip-sniffer/warp-helper.sh", filepath.Join(filepath.Dir(os.Args[0]), "warp-helper.sh")} {
			if info, statErr := os.Stat(helper); statErr == nil && !info.IsDir() {
				if exec.CommandContext(commandCtx, helper, "on").Run() == nil {
					return true
				}
				break
			}
		}
	}
	// Reconnecting an existing, already-configured client is safe and does not
	// alter the machine's default route when the client is in Local Proxy mode.
	return exec.CommandContext(commandCtx, "warp-cli", "--accept-tos", "connect").Run() == nil
}

func (e egressConfig) dialContext(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, error) {
	if e.Mode != "warp" {
		return (&net.Dialer{Timeout: timeout, KeepAlive: 15 * time.Second}).DialContext(ctx, network, address)
	}
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("WARP proxy only supports TCP, got %s", network)
	}
	return dialSOCKS5Context(ctx, e.WARPProxy, address, timeout)
}

func dialSOCKS5Context(ctx context.Context, proxyAddress, destination string, timeout time.Duration) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: timeout, KeepAlive: 15 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", proxyAddress)
	if err != nil {
		return nil, fmt.Errorf("connect WARP proxy %s: %w", proxyAddress, err)
	}
	keep := false
	defer func() {
		if !keep {
			_ = conn.Close()
		}
	}()
	deadline := time.Now().Add(timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	_ = conn.SetDeadline(deadline)
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return nil, fmt.Errorf("WARP SOCKS greeting: %w", err)
	}
	response := make([]byte, 2)
	if _, err := io.ReadFull(conn, response); err != nil {
		return nil, fmt.Errorf("WARP SOCKS greeting response: %w", err)
	}
	if response[0] != 0x05 || response[1] != 0x00 {
		return nil, errors.New("WARP SOCKS proxy rejected no-authentication method")
	}

	host, portText, err := net.SplitHostPort(destination)
	if err != nil {
		return nil, fmt.Errorf("invalid SOCKS destination %q: %w", destination, err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("invalid SOCKS destination port %q", portText)
	}
	request := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if ipv4 := ip.To4(); ipv4 != nil {
			request = append(request, 0x01)
			request = append(request, ipv4...)
		} else {
			request = append(request, 0x04)
			request = append(request, ip.To16()...)
		}
	} else {
		if len(host) == 0 || len(host) > 255 {
			return nil, errors.New("invalid SOCKS destination host length")
		}
		request = append(request, 0x03, byte(len(host)))
		request = append(request, host...)
	}
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))
	request = append(request, portBytes...)
	if _, err := conn.Write(request); err != nil {
		return nil, fmt.Errorf("WARP SOCKS connect request: %w", err)
	}
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, fmt.Errorf("WARP SOCKS connect response: %w", err)
	}
	if header[0] != 0x05 || header[1] != 0x00 {
		return nil, fmt.Errorf("WARP SOCKS connect failed with code 0x%02x", header[1])
	}
	var addressBytes int
	switch header[3] {
	case 0x01:
		addressBytes = 4
	case 0x04:
		addressBytes = 16
	case 0x03:
		length := []byte{0}
		if _, err := io.ReadFull(conn, length); err != nil {
			return nil, err
		}
		addressBytes = int(length[0])
	default:
		return nil, fmt.Errorf("WARP SOCKS returned unsupported address type 0x%02x", header[3])
	}
	if _, err := io.CopyN(io.Discard, conn, int64(addressBytes+2)); err != nil {
		return nil, fmt.Errorf("WARP SOCKS response body: %w", err)
	}
	_ = conn.SetDeadline(time.Time{})
	keep = true
	return conn, nil
}

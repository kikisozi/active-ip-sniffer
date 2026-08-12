package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

const defaultWARPProxy = "127.0.0.1:40000"

type egressConfig struct {
	Mode      string `json:"egress_mode,omitempty"`
	WARPProxy string `json:"warp_proxy,omitempty"`
}

func normalizeEgress(mode, proxy string) (egressConfig, error) {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		mode = "direct"
	}
	if mode != "direct" && mode != "warp" {
		return egressConfig{}, fmt.Errorf("unsupported egress mode: %s", mode)
	}
	proxy = strings.TrimSpace(proxy)
	if proxy == "" {
		proxy = defaultWARPProxy
	}
	if mode == "warp" {
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

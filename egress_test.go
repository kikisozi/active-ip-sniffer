package main

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

func TestNormalizeEgressAutoDefault(t *testing.T) {
	egress, err := normalizeEgress("", "")
	if err != nil {
		t.Fatal(err)
	}
	if egress.Mode != "auto" || egress.WARPProxy != "127.0.0.1:40099" {
		t.Fatalf("unexpected auto egress: %#v", egress)
	}
	if !warpTraceActive(egressInfo{IP: "198.51.100.1", WARP: "on"}) || warpTraceActive(egressInfo{IP: "198.51.100.1", WARP: "off"}) {
		t.Fatal("unexpected WARP trace classification")
	}
}

func TestWARPSOCKS5Dial(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	received := make(chan string, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		greeting := make([]byte, 3)
		if _, err := io.ReadFull(conn, greeting); err != nil {
			return
		}
		_, _ = conn.Write([]byte{0x05, 0x00})
		header := make([]byte, 4)
		if _, err := io.ReadFull(conn, header); err != nil || header[3] != 0x01 {
			return
		}
		body := make([]byte, 6)
		if _, err := io.ReadFull(conn, body); err != nil {
			return
		}
		ip := net.IP(body[:4]).String()
		port := binary.BigEndian.Uint16(body[4:])
		received <- net.JoinHostPort(ip, stringInt(int(port)))
		_, _ = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0})
	}()

	egress, err := normalizeEgress("warp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := egress.dialContext(ctx, "tcp", "203.0.113.7:443", time.Second)
	if err != nil {
		t.Fatalf("dial through SOCKS5: %v", err)
	}
	_ = conn.Close()
	select {
	case got := <-received:
		if got != "203.0.113.7:443" {
			t.Fatalf("SOCKS destination=%q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("SOCKS server did not receive destination")
	}
}

func stringInt(v int) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}

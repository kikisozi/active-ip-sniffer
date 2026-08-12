package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProbeMiddlewareRequiresToken(t *testing.T) {
	token := "0123456789abcdef0123456789abcdef"
	h := probeMiddleware(token, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/api/info", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("without token: got %d, want %d", rec.Code, http.StatusUnauthorized)
	}

	req = httptest.NewRequest(http.MethodGet, "http://127.0.0.1/api/info", nil)
	req.Header.Set("X-Probe-Token", token)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("with token: got %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestProbeMiddlewareCORSPreflight(t *testing.T) {
	token := "0123456789abcdef0123456789abcdef"
	h := probeMiddleware(token, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodOptions, "http://127.0.0.1/api/scan/start", nil)
	req.Header.Set("Origin", "https://example.com")
	req.Header.Set("Access-Control-Request-Private-Network", "true")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("preflight: got %d, want %d", rec.Code, http.StatusNoContent)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://example.com" {
		t.Fatalf("allow origin = %q", got)
	}
	if got := rec.Header().Get("Access-Control-Allow-Private-Network"); got != "true" {
		t.Fatalf("allow private network = %q", got)
	}
}

func TestRequestClientIP(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.RemoteAddr = "203.0.113.9:54321"
	if got := requestClientIP(req); got != "203.0.113.9" {
		t.Fatalf("requestClientIP = %q", got)
	}
}

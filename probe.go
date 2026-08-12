package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const defaultProbePort = 18767

func generateProbeToken() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func probeDataDir() string {
	base, err := os.UserCacheDir()
	if err != nil || strings.TrimSpace(base) == "" {
		base = os.TempDir()
	}
	return filepath.Join(base, "ActiveIPSniffer", "probe-results")
}

func probeTokenMatches(got, want string) bool {
	if len(got) != len(want) || len(want) < 16 {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func probeMiddleware(token string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Probe-Token")
		w.Header().Set("Access-Control-Max-Age", "600")
		if strings.EqualFold(r.Header.Get("Access-Control-Request-Private-Network"), "true") {
			w.Header().Set("Access-Control-Allow-Private-Network", "true")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if !probeTokenMatches(r.Header.Get("X-Probe-Token"), token) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid local probe token"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *app) probeRoutes(token string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/info", a.handleInfo)
	mux.HandleFunc("/api/network-info", handleNetworkInfo("local-probe"))
	mux.HandleFunc("/api/scan/start", a.handleStart)
	mux.HandleFunc("/api/scan/job", a.handleJob)
	mux.HandleFunc("/api/scan/cancel", a.handleCancel)
	mux.HandleFunc("/api/scan/export.csv", a.handleExportCSV)
	mux.HandleFunc("/api/scan/export.txt", a.handleExportTXT)
	mux.HandleFunc("/api/vless/start", handleVLESSBenchStart)
	mux.HandleFunc("/api/vless/job", handleVLESSBenchJob)
	mux.HandleFunc("/api/vless/cancel", handleVLESSBenchCancel)
	mux.HandleFunc("/api/vless/export.csv", handleVLESSBenchExportCSV)
	mux.HandleFunc("/api/cf-speed/start", handleCFSpeedStart)
	mux.HandleFunc("/api/cf-speed/job", handleCFSpeedJob)
	mux.HandleFunc("/api/cf-speed/cancel", handleCFSpeedCancel)
	mux.HandleFunc("/api/cf-speed/export.csv", handleCFSpeedExportCSV)
	return probeMiddleware(token, mux)
}

func runProbeServer(host string, port int, token string) error {
	if host != "127.0.0.1" && host != "::1" && host != "localhost" {
		return errors.New("local probe must listen on loopback only")
	}
	if port < 1 || port > 65535 {
		return errors.New("probe port must be between 1 and 65535")
	}
	if token == "" {
		var err error
		token, err = generateProbeToken()
		if err != nil {
			return err
		}
	}
	if len(token) < 16 {
		return errors.New("probe token must be at least 16 characters")
	}
	dataDir := probeDataDir()
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return fmt.Errorf("create probe data directory: %w", err)
	}
	cleanupResultDirectory(dataDir, time.Now())
	application := &app{store: newJobStore(), dataDir: dataDir}
	address := net.JoinHostPort(host, strconv.Itoa(port))
	server := &http.Server{
		Addr:              address,
		Handler:           application.probeRoutes(token),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	log.Printf("Active IP Sniffer %s local probe: http://%s", appVersion, address)
	log.Printf("Local probe token: %s", token)
	log.Printf("Keep this terminal open; paste the token into the WebUI local-probe guide.")
	log.Printf("Probe traffic and speed tests leave from this machine's current network egress.")
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	application.store.cancelAll()
	vlessBenchJobs.cancelAll()
	cfSpeedJobs.cancelAll()
	return nil
}

package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
)

type authSettings struct {
	Salt string `json:"salt,omitempty"`
	Hash string `json:"hash,omitempty"`
}

func (a authSettings) configured() bool {
	return len(a.Salt) == 32 && len(a.Hash) == 64
}

func makeAuthSettings(password string) (authSettings, error) {
	password = strings.TrimSpace(password)
	if len(password) < 8 {
		return authSettings{}, errors.New("WebUI 管理密码至少需要 8 个字符")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return authSettings{}, err
	}
	sum := authDigest(salt, password)
	return authSettings{Salt: hex.EncodeToString(salt), Hash: hex.EncodeToString(sum[:])}, nil
}

func authDigest(salt []byte, password string) [32]byte {
	h := sha256.New()
	_, _ = h.Write(salt)
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(password))
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

func (a authSettings) verify(password string) bool {
	if !a.configured() {
		return false
	}
	salt, err := hex.DecodeString(a.Salt)
	if err != nil || len(salt) != 16 {
		return false
	}
	want, err := hex.DecodeString(a.Hash)
	if err != nil || len(want) != sha256.Size {
		return false
	}
	got := authDigest(salt, password)
	return subtle.ConstantTimeCompare(got[:], want) == 1
}

func (a *app) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.settings == nil {
			next.ServeHTTP(w, r)
			return
		}
		cfg := a.settings.snapshot()
		if !cfg.Auth.configured() {
			next.ServeHTTP(w, r)
			return
		}
		username, password, ok := r.BasicAuth()
		if !ok || username != "admin" || !cfg.Auth.verify(password) {
			w.Header().Set("WWW-Authenticate", `Basic realm="Active IP Sniffer", charset="UTF-8"`)
			w.Header().Set("Cache-Control", "no-store")
			http.Error(w, "需要 WebUI 管理认证", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

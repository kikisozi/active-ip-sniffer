package main

import "testing"

func TestAuthSettingsVerify(t *testing.T) {
	auth, err := makeAuthSettings("strong-pass-123")
	if err != nil {
		t.Fatalf("makeAuthSettings: %v", err)
	}
	if !auth.configured() {
		t.Fatal("expected auth to be configured")
	}
	if !auth.verify("strong-pass-123") {
		t.Fatal("expected correct password to verify")
	}
	if auth.verify("wrong-pass") {
		t.Fatal("wrong password unexpectedly verified")
	}
}

func TestAuthSettingsRejectsShortPassword(t *testing.T) {
	if _, err := makeAuthSettings("short"); err == nil {
		t.Fatal("expected short password error")
	}
}

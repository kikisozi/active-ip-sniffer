package main

import (
	"strings"
	"testing"
)

func adminUIHTMLForTest() string { return indexHTML }

func TestAdminUIHasCFCDNAndAllUsableExport(t *testing.T) {
	for _, marker := range []string{"CFCDN VLESS", "data-tab=\"cfcdn\"", "/api/cfcdn/config", "/api/cfcdn/update", "/api/cfcdn/check", "立即检查", "cfExportScope", "全部可用 IP"} {
		if !strings.Contains(adminUIHTMLForTest(), marker) {
			t.Fatalf("admin UI missing %q", marker)
		}
	}
}

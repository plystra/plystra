package capabilities

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/plystra/contracts/capability"
)

func TestRouteLookup(t *testing.T) {
	manager := NewManager(Options{})
	manifest := capability.Manifest{
		ID:      capability.AuthorizationResource,
		Version: "1.0.0-rc104",
		Runtime: capability.Runtime{Protocol: capability.ProtocolHTTP, Address: "127.0.0.1:19040"},
		Provides: capability.Provides{
			Services: []capability.ServiceRef{{Name: capability.ServiceAuthorization}},
			Routes:   []capability.RouteRef{{Method: http.MethodPost, Path: "/api/v1/authz/check", Service: capability.ServiceAuthorization, Operation: "Check"}},
		},
	}
	manager.register(manifest)
	route, service, ok := manager.Route(http.MethodPost, "/api/v1/authz/check")
	if !ok {
		t.Fatalf("route not registered")
	}
	if route.Operation != "Check" || service.Address != "127.0.0.1:19040" {
		t.Fatalf("unexpected route/service: %#v %#v", route, service)
	}
}

func TestLockfileCreationPinsChecksums(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "capability.exe")
	if err := os.WriteFile(binary, []byte("binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(dir, "capability.yaml")
	if err := os.WriteFile(manifest, []byte(strings.TrimSpace(`
id: audit.explainable
kind: system_capability
name: Audit
version: 1.0.0-rc104
runtime:
  type: process
  protocol: http
  address: 127.0.0.1:19010
requires:
  kernel: ">=0.1.0"
provides:
  services:
    - name: audit.service
  migrations:
    namespace: sys_audit
    path: migrations/
privileged: true
required: true
stability: experimental
`)), 0o644); err != nil {
		t.Fatal(err)
	}
	lock, err := loadOrCreateLockfile(filepath.Join(dir, "plystra.lock"), capability.Config{SystemCapabilities: []capability.ConfiguredCapability{{
		ID: capability.AuditExplainable, Source: capability.SourceLocal, Binary: "capability.exe", Manifest: "capability.yaml", Required: true,
	}}})
	if err != nil {
		t.Fatalf("loadOrCreateLockfile error = %v", err)
	}
	if len(lock.SystemCapabilities) != 1 || !strings.HasPrefix(lock.SystemCapabilities[0].Checksum, "sha256:") {
		t.Fatalf("unexpected lockfile: %#v", lock)
	}
}

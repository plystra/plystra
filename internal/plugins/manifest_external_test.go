package plugins

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExternalPluginManifestsSatisfyCoreGovernance(t *testing.T) {
	repoRoot, ok := findAncestorWithChild(t, "plugin-auth-complete")
	if !ok {
		t.Skip("external plugin manifests are not present in this checkout")
	}
	workspaceRoot := filepath.Dir(repoRoot)
	manifestPaths := []string{
		filepath.Join(repoRoot, "plugin-api-keys", "plugin.json"),
		filepath.Join(repoRoot, "plugin-auth-complete", "plugin.json"),
		filepath.Join(repoRoot, "plugin-email-cloudflare", "plugin.json"),
		filepath.Join(repoRoot, "plugin-email-smtp", "plugin.json"),
		filepath.Join(repoRoot, "plugin-scm-github", "plugin.json"),
		filepath.Join(repoRoot, "plugin-storage-local", "plugin.json"),
	}
	if extra := strings.TrimSpace(os.Getenv("PLYSTRA_CORE_EXTRA_MANIFEST_UNDER_TEST")); extra != "" {
		if !filepath.IsAbs(extra) {
			extra = filepath.Join(workspaceRoot, extra)
		}
		manifestPaths = append(manifestPaths, extra)
	}
	for _, manifestPath := range manifestPaths {
		t.Run(filepath.ToSlash(manifestPath), func(t *testing.T) {
			raw, err := os.ReadFile(manifestPath)
			if err != nil {
				t.Fatalf("read manifest: %v", err)
			}
			var manifest Manifest
			if err := json.Unmarshal(raw, &manifest); err != nil {
				t.Fatalf("decode manifest: %v", err)
			}
			if errors := ValidateManifestForCore(manifest, "0.0.1"); len(errors) > 0 {
				t.Fatalf("ValidateManifestForCore returned errors: %#v", errors)
			}
		})
	}
}

func findAncestorWithChild(t *testing.T, child string) (string, bool) {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}
	dir := wd
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, child)); err == nil {
			return dir, true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", false
}

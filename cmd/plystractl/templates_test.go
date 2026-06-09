package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/plystra/core/internal/templates"
)

func TestCreateTemplateAppGeneratesInspectableAlphaScaffold(t *testing.T) {
	tpl, ok := templates.ByID("auth-ready-saas")
	if !ok {
		t.Fatal("auth-ready-saas template is missing")
	}
	target := filepath.Join(t.TempDir(), "auth-ready-saas")
	result, err := createTemplateApp(tpl, templateCreateOptions{
		OutputDir: target,
		AppName:   "Acme SaaS",
	})
	if err != nil {
		t.Fatalf("createTemplateApp() error = %v", err)
	}
	if result["template_id"] != "auth-ready-saas" {
		t.Fatalf("template_id = %#v", result["template_id"])
	}
	for _, name := range []string{
		"README.md",
		".env.example",
		"docker-compose.yml",
		filepath.FromSlash("plystra/template-installation.json"),
		filepath.FromSlash("plystra/install-explanation.md"),
	} {
		if _, err := os.Stat(filepath.Join(target, name)); err != nil {
			t.Fatalf("generated file %s missing: %v", name, err)
		}
	}
	raw, err := os.ReadFile(filepath.Join(target, filepath.FromSlash("plystra/template-installation.json")))
	if err != nil {
		t.Fatal(err)
	}
	var manifest map[string]any
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatalf("template-installation.json invalid: %v", err)
	}
	if manifest["format"] != "plystra.template.app.v1" {
		t.Fatalf("format = %#v", manifest["format"])
	}
	env := readGeneratedFile(t, filepath.Join(target, ".env.example"))
	for _, want := range []string{
		"SERVER_MODE=production",
		"POSTGRES_PASSWORD=replace-with-strong-postgres-password",
		"PLYSTRA_SESSION_SECRET=replace-me",
		"PLYSTRA_API_KEY_SECRET=replace-me-too",
	} {
		if !strings.Contains(env, want) {
			t.Fatalf(".env.example missing %q", want)
		}
	}
	compose := readGeneratedFile(t, filepath.Join(target, "docker-compose.yml"))
	for _, want := range []string{
		"image: ${PLYSTRA_CORE_IMAGE}",
		"DATABASE_URL: ${DOCKER_DATABASE_URL}",
		"image: postgres:16-alpine",
		"http://127.0.0.1:8080/api/v1/health",
	} {
		if !strings.Contains(compose, want) {
			t.Fatalf("docker-compose.yml missing %q", want)
		}
	}
	if strings.Contains(compose, "auth-complete:") {
		t.Fatal("template compose must not hard-code a concrete auth provider")
	}
	if strings.Contains(compose, "${POSTGRES_PORT:-5432}:5432") {
		t.Fatal("docker-compose.yml should not publish PostgreSQL to the host by default")
	}
	explanation := readGeneratedFile(t, filepath.Join(target, filepath.FromSlash("plystra/install-explanation.md")))
	for _, want := range []string{
		"Required capabilities: auth.identity, email.transactional",
		"migrations never create one automatically",
		"Review generated README, deployment profile, environment example, and install explanation before starting services",
		"production email delivery requires an independent email capability provider",
	} {
		if !strings.Contains(explanation, want) {
			t.Fatalf("install explanation missing %q", want)
		}
	}
}

func TestBackupManifestStaticTableNamesAreSafe(t *testing.T) {
	for _, table := range []string{
		"users",
	} {
		if got := safeTableIdentifier(table); got != table {
			t.Fatalf("safeTableIdentifier(%q) = %q", table, got)
		}
	}

	assertPanics(t, func() { safeTableIdentifier("users;drop_table") })
	assertPanics(t, func() { safeTableIdentifier("public.users") })
}

func TestPluginBackupTableAllowed(t *testing.T) {
	for _, table := range []string{
		"plugin_example_records",
		"plugin_acme_events",
		"plugin_acme_settings",
	} {
		if !pluginBackupTableAllowed(table) {
			t.Fatalf("pluginBackupTableAllowed(%q) = false", table)
		}
	}
	for _, table := range []string{
		"plugins",
		"plugin_admin_menus",
		"plugin_migration_state",
		"plugin_settings_definitions",
		"plugin_settings_values",
		"app_data_records",
		"plugin.bad",
		"plugin_records;drop",
	} {
		if pluginBackupTableAllowed(table) {
			t.Fatalf("pluginBackupTableAllowed(%q) = true", table)
		}
	}
}

func TestProviderBackupTableAllowed(t *testing.T) {
	for _, table := range []string{
		"plg_invoice.invoices",
		"plg_storage.objects",
		"app_acme.tasks",
	} {
		if !providerBackupTableAllowed(table) {
			t.Fatalf("providerBackupTableAllowed(%q) = false", table)
		}
	}
	for _, table := range []string{
		"public.plugins",
		"public.plugin_example_records",
		"core.users",
		"plg_bad.records;drop",
		"bad-schema.records",
	} {
		if providerBackupTableAllowed(table) {
			t.Fatalf("providerBackupTableAllowed(%q) = true", table)
		}
	}
}

func TestCreateTemplateAppRefusesExistingOutputDirectory(t *testing.T) {
	tpl, ok := templates.ByID("blank")
	if !ok {
		t.Fatal("blank template is missing")
	}
	target := t.TempDir()
	if _, err := createTemplateApp(tpl, templateCreateOptions{OutputDir: target}); err == nil {
		t.Fatal("createTemplateApp() succeeded for existing directory")
	}
}

func readGeneratedFile(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func assertPanics(t *testing.T, fn func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic")
		}
	}()
	fn()
}

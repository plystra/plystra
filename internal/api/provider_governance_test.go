package api

import (
	"strings"
	"testing"
)

func TestValidateProviderMigrationRevisionRequest(t *testing.T) {
	valid := providerMigrationRevisionRequest{
		ProviderPluginID:  "app.sample.provider",
		Revision:          "001_create_tables",
		BundleHash:        strings.Repeat("a", 64),
		FromSchemaVersion: 0,
		ToSchemaVersion:   1,
		Steps: []providerMigrationStepRequest{{
			StatementHash: strings.Repeat("b", 64),
			StatementKind: "create_table",
		}},
	}
	if err := validateProviderMigrationRevisionRequest(valid); err != nil {
		t.Fatalf("valid request failed: %v", err)
	}

	secretMetadata := valid
	secretMetadata.Metadata = map[string]any{"api_token": "do-not-store"}
	if err := validateProviderMigrationRevisionRequest(secretMetadata); err == nil || !strings.Contains(err.Error(), "secret-like key") {
		t.Fatalf("secret metadata should fail, got %v", err)
	}

	backfillWithoutReview := valid
	backfillWithoutReview.Steps = []providerMigrationStepRequest{{
		StatementHash: strings.Repeat("c", 64),
		StatementKind: "backfill",
		Backfill:      true,
	}}
	if err := validateProviderMigrationRevisionRequest(backfillWithoutReview); err == nil || !strings.Contains(err.Error(), "tenant_scope_reviewed") {
		t.Fatalf("backfill without tenant review should fail, got %v", err)
	}

	withRawSQLMetadata := valid
	withRawSQLMetadata.Steps[0].Metadata = map[string]any{"statement": "DROP TABLE users"}
	if err := validateProviderMigrationRevisionRequest(withRawSQLMetadata); err == nil || !strings.Contains(err.Error(), "raw SQL") {
		t.Fatalf("raw SQL metadata should fail, got %v", err)
	}
}

func TestProviderDatabaseIdentifiers(t *testing.T) {
	schemaName, migratorRole, runtimeRole := providerDatabaseIdentifiers("plystra.email.smtp", "plugin", "")
	if schemaName != "plg_plystra_email_smtp" {
		t.Fatalf("plugin schema = %q", schemaName)
	}
	if migratorRole != "plg_plystra_email_smtp_migrator_owner" || runtimeRole != "plg_plystra_email_smtp_runtime" {
		t.Fatalf("plugin roles = %q %q", migratorRole, runtimeRole)
	}

	appSchema, appMigrator, appRuntime := providerDatabaseIdentifiers("app.acme.operations", "app_module", "acme")
	if appSchema != "app_acme" {
		t.Fatalf("app module schema = %q", appSchema)
	}
	if !strings.Contains(appMigrator, "app_acme_app_acme_operations") || !strings.HasSuffix(appMigrator, "_migrator_owner") {
		t.Fatalf("app module migrator role = %q", appMigrator)
	}
	if !strings.Contains(appRuntime, "app_acme_app_acme_operations") || !strings.HasSuffix(appRuntime, "_runtime") {
		t.Fatalf("app module runtime role = %q", appRuntime)
	}
}

func TestManifestNeedsProviderInstallation(t *testing.T) {
	if manifestNeedsProviderInstallation(appModuleConvergenceManifest("app.sample.coredata", "x", "runtime.endpoint", "Admin", "/apps/sample/admin")) {
		t.Fatal("core_data_api-only manifest should not require provider installation")
	}
	manifest := appModuleConvergenceManifest("app.sample.directdb", "y", "runtime.endpoint", "Admin", "/apps/sample/admin")
	manifest.LocalCapabilities[0].DataPlane.Allowed = []string{"direct_db"}
	if !manifestNeedsProviderInstallation(manifest) {
		t.Fatal("direct_db manifest should require provider installation")
	}
}

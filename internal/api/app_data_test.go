package api

import (
	"strings"
	"testing"

	coreent "github.com/plystra/core/ent"
)

func TestAppDataMutationPolicyViolation(t *testing.T) {
	if got := appDataMutationPolicyViolation(&coreent.AppDataModel{}, "update", false); got != "" {
		t.Fatalf("model without policy should not be blocked: %q", got)
	}
	model := &coreent.AppDataModel{Metadata: map[string]any{"mutation_policy": appDataMutationPolicyServiceAppendOnly}}
	if got := appDataMutationPolicyViolation(model, "create", true); got != "" {
		t.Fatalf("service append-only create should be allowed: %q", got)
	}
	if got := appDataMutationPolicyViolation(model, "create", false); !strings.Contains(got, "service API key") {
		t.Fatalf("user create should require service key, got %q", got)
	}
	if got := appDataMutationPolicyViolation(model, "update", true); !strings.Contains(got, "only permits create") {
		t.Fatalf("update should be blocked, got %q", got)
	}
	unknown := &coreent.AppDataModel{Metadata: map[string]any{"mutation_policy": "locked"}}
	if got := appDataMutationPolicyViolation(unknown, "create", true); !strings.Contains(got, "not supported") {
		t.Fatalf("unknown policy should be blocked, got %q", got)
	}
}

func TestAppDataBatchOperationServiceAuthorized(t *testing.T) {
	appendOnly := &coreent.AppDataModel{Key: "activity", Metadata: map[string]any{"mutation_policy": appDataMutationPolicyServiceAppendOnly}}
	normal := &coreent.AppDataModel{Key: "customer"}

	if !appDataBatchOperationServiceAuthorized(normal, appDataRecordBatchOperation{Operation: "update"}, appDataBatchServiceAuthorization{PrimaryManageModels: map[string]bool{"customer": true}}) {
		t.Fatal("primary service authorization should allow any batch operation")
	}
	if !appDataBatchOperationServiceAuthorized(appendOnly, appDataRecordBatchOperation{Operation: "CREATE"}, appDataBatchServiceAuthorization{SecondaryAppendOnlyModels: map[string]bool{"activity": true}}) {
		t.Fatal("secondary service authorization should allow append-only creates")
	}
	if appDataBatchOperationServiceAuthorized(appendOnly, appDataRecordBatchOperation{Operation: "update"}, appDataBatchServiceAuthorization{SecondaryAppendOnlyModels: map[string]bool{"activity": true}}) {
		t.Fatal("secondary service authorization must not allow append-only updates")
	}
	if appDataBatchOperationServiceAuthorized(normal, appDataRecordBatchOperation{Operation: "create"}, appDataBatchServiceAuthorization{SecondaryAppendOnlyModels: map[string]bool{"customer": true}}) {
		t.Fatal("secondary service authorization must not allow normal model creates")
	}
	if appDataBatchOperationServiceAuthorized(appendOnly, appDataRecordBatchOperation{Operation: "create"}, appDataBatchServiceAuthorization{SecondaryAppendOnlyModels: map[string]bool{"other": true}}) {
		t.Fatal("secondary service authorization must be model-scoped")
	}
}

func TestAppDataModelGovernanceMetadataReservesOwnershipFields(t *testing.T) {
	out := appDataModelGovernanceMetadata(map[string]any{
		"owner_plugin_key":      "app.other",
		"declared_resource_key": "other_model",
		"ownership_source":      "caller",
		"purpose":               "test",
	}, appDataModelOwnership{
		OwnerPluginKey:      "app.example.module",
		DeclaredResourceKey: "example_record",
		Source:              appDataOwnershipSourceManifest,
	})
	if out["owner_plugin_key"] != "app.example.module" || out["declared_resource_key"] != "example_record" || out["ownership_source"] != appDataOwnershipSourceManifest {
		t.Fatalf("governance metadata was not owned by Core: %#v", out)
	}
	if out["purpose"] != "test" {
		t.Fatalf("non-governance metadata was dropped: %#v", out)
	}
}

func TestReqDeclaresPluginOwnership(t *testing.T) {
	source := "plugin:app.example.module"
	if !reqDeclaresPluginOwnership(&appDataModelMutationRequest{Source: &source}) {
		t.Fatal("plugin source should be treated as plugin ownership")
	}
	if !reqDeclaresPluginOwnership(&appDataModelMutationRequest{Metadata: map[string]any{"owner_plugin_key": "app.example.module"}}) {
		t.Fatal("owner_plugin_key metadata should be reserved")
	}
	if reqDeclaresPluginOwnership(&appDataModelMutationRequest{Metadata: map[string]any{"purpose": "test"}}) {
		t.Fatal("ordinary metadata should not be treated as plugin ownership")
	}
}

func TestAppDataModelOwnedByPluginUsesTrustedOwnershipFields(t *testing.T) {
	if !appDataModelOwnedByPlugin(&coreent.AppDataModel{Source: "plugin:app.example.module"}) {
		t.Fatal("plugin source should mark model as plugin-owned")
	}
	ownerPluginKey := "app.example.module"
	if !appDataModelOwnedByPlugin(&coreent.AppDataModel{OwnerPluginKey: &ownerPluginKey}) {
		t.Fatal("owner_plugin_key column should mark model as plugin-owned")
	}
	if appDataModelOwnedByPlugin(&coreent.AppDataModel{Metadata: map[string]any{"owner_plugin_key": "app.example.module"}}) {
		t.Fatal("caller-controlled metadata alone must not mark model as plugin-owned")
	}
	if appDataModelOwnedByPlugin(&coreent.AppDataModel{Source: appDataSourceApp}) {
		t.Fatal("ordinary app model should not be plugin-owned")
	}
}

func TestPluginStatusAllowsAppDataOwnership(t *testing.T) {
	for _, status := range []string{"validated", "installed", "migrated", "enabled"} {
		if !pluginStatusAllowsAppDataOwnership(status) {
			t.Fatalf("status %s should allow app data ownership", status)
		}
	}
	for _, status := range []string{"disabled", "failed", "uninstalled", "upgrading", "discovered"} {
		if pluginStatusAllowsAppDataOwnership(status) {
			t.Fatalf("status %s should not allow app data ownership", status)
		}
	}
}

func TestValidateGovernedMetadataRejectsSecretLikeKeys(t *testing.T) {
	err := validateGovernedMetadata("metadata", map[string]any{
		"nested": map[string]any{
			"api_token": "do-not-store-here",
		},
	})
	if err == nil || !strings.Contains(err.Error(), "secret-like key") {
		t.Fatalf("expected secret-like metadata rejection, got %v", err)
	}
}

func TestValidateAppDataRecordMutationLimitsDataSize(t *testing.T) {
	err := validateAppDataRecordMutation(appDataRecordMutationRequest{
		Data: map[string]any{
			"description": strings.Repeat("a", maxAppDataRecordDataBytes),
		},
	}, true)
	if err == nil || !strings.Contains(err.Error(), "data must be") {
		t.Fatalf("expected data size validation error, got %v", err)
	}
}

func TestAppDataSearchFieldsUseModelMetadataExtension(t *testing.T) {
	model := &coreent.AppDataModel{Metadata: map[string]any{
		"search_fields": []any{"customer_id", "invoice_id", "bad-field", "name"},
	}}
	fields := appDataSearchFieldsForModel(model)
	seen := map[string]bool{}
	for _, field := range fields {
		seen[field] = true
	}
	if !seen["name"] || !seen["customer_id"] || !seen["invoice_id"] {
		t.Fatalf("expected default and metadata search fields, got %#v", fields)
	}
	if seen["bad-field"] {
		t.Fatalf("invalid metadata search field was accepted: %#v", fields)
	}
}

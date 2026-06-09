package api

import (
	"strings"
	"testing"

	coreent "github.com/plystra/core/ent"
	"github.com/plystra/core/internal/plugins"
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
		"owner_plugin_type":     "plugin",
		"app_id":                "other",
		"trust_bundle_id":       "other.default",
		"owner_module_key":      "app.other.module",
		"tenant_scoped":         false,
		"audit_enforcement":     "grant_only",
		"ownership_source":      "caller",
		"purpose":               "test",
	}, appDataModelOwnership{
		OwnerPluginKey:      "app.example.module",
		DeclaredResourceKey: "example_record",
		OwnerPluginType:     "app_module",
		AppID:               "example",
		TrustBundleID:       "example.default",
		OwnerModuleKey:      "app.example.module",
		TenantScoped:        true,
		AuditEnforcement:    "controlled_action",
		Source:              appDataOwnershipSourceManifest,
	})
	if out["owner_plugin_key"] != "app.example.module" || out["declared_resource_key"] != "example_record" || out["ownership_source"] != appDataOwnershipSourceManifest {
		t.Fatalf("governance metadata was not owned by Core: %#v", out)
	}
	if out["owner_plugin_type"] != "app_module" || out["app_id"] != "example" || out["trust_bundle_id"] != "example.default" || out["owner_module_key"] != "app.example.module" {
		t.Fatalf("app module governance metadata was not owned by Core: %#v", out)
	}
	if out["tenant_scoped"] != true || out["audit_enforcement"] != "controlled_action" {
		t.Fatalf("data-plane governance metadata was not owned by Core: %#v", out)
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
	if !reqDeclaresPluginOwnership(&appDataModelMutationRequest{Metadata: map[string]any{"trust_bundle_id": "example.default"}}) {
		t.Fatal("trust_bundle_id metadata should be reserved")
	}
	if !reqDeclaresPluginOwnership(&appDataModelMutationRequest{Metadata: map[string]any{"audit_enforcement": "controlled_action"}}) {
		t.Fatal("audit_enforcement metadata should be reserved")
	}
	if reqDeclaresPluginOwnership(&appDataModelMutationRequest{Metadata: map[string]any{"purpose": "test"}}) {
		t.Fatal("ordinary metadata should not be treated as plugin ownership")
	}
}

func TestAppDataAuditEnforcementForManifestUsesStrongestCoreDataCapability(t *testing.T) {
	manifest := plugins.Manifest{
		Capabilities: []plugins.CapabilityDefinition{{
			ID:        "billing.invoice",
			Audit:     plugins.CapabilityAuditDefinition{Enforcement: "reported_event"},
			DataPlane: plugins.CapabilityDataPlaneDefinition{Allowed: []string{"core_data_api"}},
		}},
		LocalCapabilities: []plugins.CapabilityDefinition{{
			ID:        "billing.payment",
			Audit:     plugins.CapabilityAuditDefinition{Enforcement: "controlled_action"},
			DataPlane: plugins.CapabilityDataPlaneDefinition{Allowed: []string{"action_gateway", "core_data_api"}},
		}},
	}
	if got := appDataAuditEnforcementForManifest(manifest); got != "controlled_action" {
		t.Fatalf("audit enforcement = %q, want controlled_action", got)
	}
	manifest.Capabilities[0].DataPlane.Allowed = []string{"direct_db"}
	manifest.LocalCapabilities[0].DataPlane.Allowed = []string{"action_gateway"}
	if got := appDataAuditEnforcementForManifest(manifest); got != "" {
		t.Fatalf("manifest without core_data_api should not authorize app data, got %q", got)
	}
}

func TestOwnerModuleKeyForManifestOnlyAppModules(t *testing.T) {
	row := &coreent.Plugin{Key: "app.example.module", Type: "app_module"}
	manifest := plugins.Manifest{ID: "app.example.module", Type: "app_module"}
	if got := ownerModuleKeyForManifest(row, manifest); got != "app.example.module" {
		t.Fatalf("owner module key = %q", got)
	}
	if got := ownerModuleKeyForManifest(&coreent.Plugin{Key: "plystra.email", Type: "plugin"}, plugins.Manifest{ID: "plystra.email", Type: "plugin"}); got != "" {
		t.Fatalf("reusable plugin should not set owner module key, got %q", got)
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

func TestAppDataModelAuthorizationResourceTypeUsesTrustedDeclaredResourceKey(t *testing.T) {
	declaredResourceKey := "order_payment"
	model := &coreent.AppDataModel{
		Key:                 "payment",
		DeclaredResourceKey: &declaredResourceKey,
		Metadata:            map[string]any{"declared_resource_key": "caller_controlled"},
	}
	if got := appDataModelAuthorizationResourceType(model); got != "order_payment" {
		t.Fatalf("authorization resource type = %q, want trusted declared resource key", got)
	}
}

func TestAppDataModelAuthorizationResourceTypeIgnoresMetadataAlias(t *testing.T) {
	model := &coreent.AppDataModel{
		Key:      "customer",
		Metadata: map[string]any{"declared_resource_key": "order_payment"},
	}
	if got := appDataModelAuthorizationResourceType(model); got != "data_customer" {
		t.Fatalf("authorization resource type = %q, want ordinary app data resource", got)
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

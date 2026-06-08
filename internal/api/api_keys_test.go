package api

import (
	"strings"
	"testing"
)

func TestValidateAPIKeyMetadataRejectsProviderRuntimeAliases(t *testing.T) {
	for _, key := range providerRuntimeMetadataKeys {
		err := validateAPIKeyMetadata(map[string]any{key: "app.example.provider"})
		if err == nil || !strings.Contains(err.Error(), "provider_runtime_plugin_id") {
			t.Fatalf("metadata key %s should be rejected as provider runtime identity, got %v", key, err)
		}
	}
}

func TestProviderRuntimePluginStatusActiveRequiresEnabled(t *testing.T) {
	for _, status := range []string{"enabled", " enabled "} {
		if !providerRuntimePluginStatusActive(status) {
			t.Fatalf("status %q should allow provider runtime execution", status)
		}
	}
	for _, status := range []string{"", "validated", "installed", "migrated", "disabled", "failed", "uninstalled", "upgrading", "discovered"} {
		if providerRuntimePluginStatusActive(status) {
			t.Fatalf("status %q should not allow provider runtime execution", status)
		}
	}
}

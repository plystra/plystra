package api

import (
	"strings"
	"testing"

	coreent "github.com/plystra/core/ent"
	"github.com/plystra/core/internal/plugins"
)

func TestValidatePluginSettingValueRejectsSecretLikeKeys(t *testing.T) {
	definition := &coreent.PluginSettingsDefinition{
		Key:       "provider.endpoint",
		ValueType: "string",
		Scope:     "instance",
	}
	err := validatePluginSettingValue(definition, map[string]any{
		"value": "http://provider.internal",
		"token": "do-not-store-here",
	})
	if err == nil || !strings.Contains(err.Error(), "secret-like key") {
		t.Fatalf("expected secret-like key rejection, got %v", err)
	}
}

func TestValidatePluginSettingValueEnforcesDeclaredType(t *testing.T) {
	definition := &coreent.PluginSettingsDefinition{
		Key:       "public_api_enabled",
		ValueType: "boolean",
		Scope:     "instance",
	}
	err := validatePluginSettingValue(definition, map[string]any{"value": "true"})
	if err == nil || !strings.Contains(err.Error(), "must be a boolean") {
		t.Fatalf("expected boolean setting validation error, got %v", err)
	}
}

func TestPluginSettingDefinitionFromManifestUsesDefaultScope(t *testing.T) {
	definition := pluginSettingDefinitionFromManifest("plugin_test", plugins.SettingDefinition{
		Key:       "public_api_enabled",
		ValueType: "boolean",
	}, "")
	if definition.Scope != "space" {
		t.Fatalf("scope = %q, want space", definition.Scope)
	}
}

func TestPluginSettingDefaultValueMapDistinguishesMissingDefault(t *testing.T) {
	withoutDefault := pluginSettingDefaultValueMap(plugins.SettingDefinition{Key: "public_api_enabled", ValueType: "boolean"})
	if len(withoutDefault) != 0 {
		t.Fatalf("missing default should remain empty object, got %#v", withoutDefault)
	}
	withDefault := pluginSettingDefaultValueMap(plugins.SettingDefinition{Key: "public_api_enabled", ValueType: "boolean", Default: false})
	if value, ok := withDefault["value"].(bool); !ok || value {
		t.Fatalf("default bool not wrapped under value: %#v", withDefault)
	}
}

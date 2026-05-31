package plugins

import "testing"

func TestValidateManifestAcceptsCapabilities(t *testing.T) {
	manifest := Manifest{
		ID:               "plystra.email_smtp",
		Name:             "SMTP Email",
		Version:          "0.0.1",
		ManifestVersion:  "1.0",
		PluginAPIVersion: "1.0",
		RequiresCore:     ">=0.0.1 <0.1.0",
		Resources: []ResourceDefinition{{
			Key:         "email_delivery",
			DisplayName: "Email Delivery",
			Actions:     []ActionDefinition{{Key: "create", RiskLevel: "high"}},
		}},
		Permissions:  []PermissionDefinition{{Resource: "email_delivery", Action: "create", Scopes: []string{"space"}}},
		Capabilities: []CapabilityDefinition{{ID: "email.transactional", Version: "0.0.1", Level: "standard"}},
	}
	if errors := ValidateManifestForCore(manifest, "0.0.1"); len(errors) > 0 {
		t.Fatalf("ValidateManifestForCore returned errors: %#v", errors)
	}
}

func TestValidateManifestRejectsInvalidCapabilityLevel(t *testing.T) {
	manifest := Manifest{
		ID:               "plystra.email_smtp",
		Name:             "SMTP Email",
		Version:          "0.0.1",
		ManifestVersion:  "1.0",
		PluginAPIVersion: "1.0",
		RequiresCore:     ">=0.0.1 <0.1.0",
		Resources: []ResourceDefinition{{
			Key:         "email_delivery",
			DisplayName: "Email Delivery",
			Actions:     []ActionDefinition{{Key: "create", RiskLevel: "high"}},
		}},
		Permissions:  []PermissionDefinition{{Resource: "email_delivery", Action: "create", Scopes: []string{"space"}}},
		Capabilities: []CapabilityDefinition{{ID: "email.transactional", Version: "0.0.1", Level: "root"}},
	}
	errors := ValidateManifestForCore(manifest, "0.0.1")
	if len(errors) == 0 {
		t.Fatalf("ValidateManifestForCore accepted invalid capability level")
	}
}

func TestValidateManifestAcceptsCapabilityRequirements(t *testing.T) {
	manifest := Manifest{
		ID:               "plystra.auth_complete",
		Name:             "Complete Auth",
		Version:          "0.0.1",
		ManifestVersion:  "1.0",
		PluginAPIVersion: "1.0",
		RequiresCore:     ">=0.0.1 <0.1.0",
		Resources: []ResourceDefinition{{
			Key:         "auth_challenge",
			DisplayName: "Auth Challenge",
			Actions:     []ActionDefinition{{Key: "create", RiskLevel: "high"}},
		}},
		Permissions: []PermissionDefinition{{Resource: "auth_challenge", Action: "create", Scopes: []string{"space"}}},
		Requires:    []CapabilityRequirement{{ID: "email.transactional", Version: ">=0.0.1 <0.1.0", MinLevel: "standard"}},
	}
	if errors := ValidateManifestForCore(manifest, "0.0.1"); len(errors) > 0 {
		t.Fatalf("ValidateManifestForCore returned errors: %#v", errors)
	}
}

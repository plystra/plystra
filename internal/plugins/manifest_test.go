package plugins

import (
	"strings"
	"testing"
)

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

func TestValidateManifestAcceptsDeclaredCapability(t *testing.T) {
	manifest := Manifest{
		ID:               "plystra.delivery_ops",
		Name:             "Delivery Ops",
		Version:          "0.0.1",
		ManifestVersion:  "1.0",
		PluginAPIVersion: "1.0",
		RequiresCore:     ">=0.0.1 <0.1.0",
		Resources: []ResourceDefinition{{
			Key:         "delivery_task",
			DisplayName: "Delivery Task",
			Actions:     []ActionDefinition{{Key: "read", RiskLevel: "normal"}},
		}},
		Permissions:  []PermissionDefinition{{Resource: "delivery_task", Action: "read", Scopes: []string{"space"}}},
		Capabilities: []CapabilityDefinition{{ID: "delivery.operations", Version: "0.0.1", Level: "declared"}},
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

func TestValidateManifestAcceptsPluginRuntimeDeclarations(t *testing.T) {
	manifest := Manifest{
		ID:               "plystra.email_smtp",
		Name:             "SMTP Email",
		Status:           "enabled",
		Version:          "0.0.1",
		ManifestVersion:  "1.0",
		PluginAPIVersion: "1.0",
		RequiresCore:     ">=0.0.1 <0.1.0",
		Resources: []ResourceDefinition{{
			Key:         "email_delivery",
			DisplayName: "Email Delivery",
			Actions:     []ActionDefinition{{Key: "create", RiskLevel: "high"}},
		}},
		Permissions: []PermissionDefinition{{Resource: "email_delivery", Action: "create", Scopes: []string{"space"}}},
		Routes: []RouteDefinition{{
			Method:       "POST",
			Path:         "/contract/v1/email/send",
			ResourceType: "email_delivery",
			Action:       "create",
			Handler:      "send_email",
		}},
		Events: EventDefinitions{
			Publishes: []string{"email.sent", "email.failed"},
			Consumes:  []string{"member.created"},
		},
		Jobs:            []JobDefinition{{ID: "email_retry", Schedule: "*/5 * * * *"}},
		HealthChecks:    []HealthCheckDefinition{{ID: "ready", Path: "/ready"}},
		Secrets:         []SecretDefinition{{Key: "SMTP_PASSWORD", Required: true}},
		ExternalNetwork: []NetworkDefinition{{Target: "smtp.example.com:587", Purpose: "smtp_delivery", Required: true}},
		Capabilities:    []CapabilityDefinition{{ID: "email.transactional", Version: "0.0.1", Level: "standard"}},
		Requires:        []CapabilityRequirement{},
		AuditEvents:     []AuditEventDefinition{{Key: "email.sent", RiskLevel: "normal"}},
		AdminMenus:      []AdminMenuDefinition{{Label: "SMTP Email", Path: "/plugins/email-smtp"}},
		Settings:        []SettingDefinition{{Key: "default_from", ValueType: "string", Scope: "space"}},
	}
	if errors := ValidateManifestForCore(manifest, "0.0.1"); len(errors) > 0 {
		t.Fatalf("ValidateManifestForCore returned errors: %#v", errors)
	}
}

func TestValidateManifestRejectsInvalidGovernedDeclarations(t *testing.T) {
	manifest := Manifest{
		ID:               "plystra.invoice",
		Name:             "Invoice",
		Status:           "active",
		Version:          "0.0.1",
		ManifestVersion:  "1.0",
		PluginAPIVersion: "1.0",
		RequiresCore:     ">=0.0.1 <0.1.0",
		Resources: []ResourceDefinition{
			{Key: "invoice", DisplayName: "", Actions: nil},
			{Key: "invoice_payment", DisplayName: "Invoice Payment", Actions: []ActionDefinition{{Key: "approve", RiskLevel: "root"}}},
		},
		Permissions: []PermissionDefinition{
			{Resource: "invoice_payment", Action: "approve"},
		},
		AuditEvents: []AuditEventDefinition{{Key: "invoice paid", RiskLevel: "root"}},
		Settings: []SettingDefinition{
			{Key: "smtp_password", ValueType: "string", Scope: "space"},
			{Key: "retention_days", ValueType: "duration", Scope: "tenant"},
		},
	}
	errors := ValidateManifestForCore(manifest, "0.0.1")
	if len(errors) < 8 {
		t.Fatalf("ValidateManifestForCore returned too few errors: %#v", errors)
	}
	assertContainsError(t, errors, "status must be one of")
	assertContainsError(t, errors, "resources[0].display_name is required")
	assertContainsError(t, errors, "resources[0].actions must not be empty")
	assertContainsError(t, errors, "resources[1].actions[0].risk_level")
	assertContainsError(t, errors, "permissions[0].scopes must not be empty")
	assertContainsError(t, errors, "audit_events[0].key is invalid")
	assertContainsError(t, errors, "settings[0].key must not look like a secret")
	assertContainsError(t, errors, "settings[1].type must be one of")
	assertContainsError(t, errors, "settings[1].scope must be instance or space")
}

func TestValidateManifestTreatsEmptySettingScopeAsSpace(t *testing.T) {
	manifest := Manifest{
		ID:               "plystra.invoice",
		Name:             "Invoice",
		Version:          "0.0.1",
		ManifestVersion:  "1.0",
		PluginAPIVersion: "1.0",
		RequiresCore:     ">=0.0.1 <0.1.0",
		Resources: []ResourceDefinition{{
			Key:         "invoice",
			DisplayName: "Invoice",
			Actions:     []ActionDefinition{{Key: "read", RiskLevel: "normal"}},
		}},
		Permissions: []PermissionDefinition{{Resource: "invoice", Action: "read", Scopes: []string{"space"}}},
		Settings: []SettingDefinition{
			{Key: "retention_days", ValueType: "integer"},
			{Key: "retention_days", ValueType: "integer", Scope: "space"},
		},
	}
	errors := ValidateManifestForCore(manifest, "0.0.1")
	assertContainsError(t, errors, `duplicate setting "retention_days" for scope "space"`)
}

func TestValidateManifestRejectsInvalidRuntimeDeclarations(t *testing.T) {
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
		Permissions: []PermissionDefinition{{Resource: "email_delivery", Action: "create", Scopes: []string{"space"}}},
		Routes: []RouteDefinition{{
			Method:       "TRACE",
			Path:         "contract/v1/email/send?debug=true",
			ResourceType: "email_delivery",
			Action:       "delete",
		}},
		Events:          EventDefinitions{Publishes: []string{"bad event"}},
		Jobs:            []JobDefinition{{ID: "retry_email", Schedule: ""}},
		HealthChecks:    []HealthCheckDefinition{{ID: "ready", Path: "ready"}},
		Secrets:         []SecretDefinition{{Key: "smtp_password", Required: true}},
		ExternalNetwork: []NetworkDefinition{{Target: "smtp example", Purpose: ""}},
	}
	errors := ValidateManifestForCore(manifest, "0.0.1")
	if len(errors) < 8 {
		t.Fatalf("ValidateManifestForCore returned too few errors: %#v", errors)
	}
}

func assertContainsError(t *testing.T, errors []string, pattern string) {
	t.Helper()
	for _, err := range errors {
		if strings.Contains(err, pattern) {
			return
		}
	}
	t.Fatalf("expected error containing %q in %#v", pattern, errors)
}

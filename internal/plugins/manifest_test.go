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
		Permissions: []PermissionDefinition{{Resource: "email_delivery", Action: "create", Scopes: []string{"space"}}},
		Capabilities: []CapabilityDefinition{{
			ID:         "email.transactional",
			Version:    "0.0.1",
			Level:      "standard",
			Audit:      CapabilityAuditDefinition{Enforcement: "reported_event"},
			DataPlane:  CapabilityDataPlaneDefinition{Allowed: []string{"direct_db"}},
			Operations: []CapabilityOperationDefinition{standardSendEmailOperation()},
		}},
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
		Permissions: []PermissionDefinition{{Resource: "delivery_task", Action: "read", Scopes: []string{"space"}}},
		Capabilities: []CapabilityDefinition{{
			ID:        "delivery.operations",
			Version:   "0.0.1",
			Level:     "declared",
			Audit:     CapabilityAuditDefinition{Enforcement: "grant_only"},
			DataPlane: CapabilityDataPlaneDefinition{Allowed: []string{"direct_db"}},
		}},
	}
	if errors := ValidateManifestForCore(manifest, "0.0.1"); len(errors) > 0 {
		t.Fatalf("ValidateManifestForCore returned errors: %#v", errors)
	}
}

func TestValidateManifestAcceptsCoreDataAPICapability(t *testing.T) {
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
			Actions:     []ActionDefinition{{Key: "create", RiskLevel: "normal"}},
		}},
		Permissions: []PermissionDefinition{{Resource: "delivery_task", Action: "create", Scopes: []string{"space"}}},
		Capabilities: []CapabilityDefinition{{
			ID:        "delivery.operations",
			Version:   "0.0.1",
			Level:     "declared",
			Audit:     CapabilityAuditDefinition{Enforcement: "reported_event"},
			DataPlane: CapabilityDataPlaneDefinition{Allowed: []string{"core_data_api"}},
		}},
	}
	if errors := ValidateManifestForCore(manifest, "0.0.1"); len(errors) > 0 {
		t.Fatalf("ValidateManifestForCore returned errors: %#v", errors)
	}
}

func TestValidateManifestAcceptsAppModuleWithLocalCapability(t *testing.T) {
	manifest := Manifest{
		ID:               "app.delivery.operations",
		Type:             "app_module",
		Scope:            "app",
		AppID:            "delivery",
		Name:             "Delivery Operations",
		Version:          "0.0.1",
		ManifestVersion:  "1.0",
		PluginAPIVersion: "1.0",
		RequiresCore:     ">=0.0.1 <0.1.0",
		Resources: []ResourceDefinition{{
			Key:         "delivery_task",
			DisplayName: "Delivery Task",
			Actions:     []ActionDefinition{{Key: "read", RiskLevel: "normal"}},
		}},
		Permissions: []PermissionDefinition{{Resource: "delivery_task", Action: "read", Scopes: []string{"space"}}},
		LocalCapabilities: []CapabilityDefinition{{
			ID:        "delivery.operations",
			Version:   "0.0.1",
			Level:     "declared",
			Audit:     CapabilityAuditDefinition{Enforcement: "reported_event"},
			DataPlane: CapabilityDataPlaneDefinition{Allowed: []string{"core_data_api"}},
		}},
		AdminMenus: []AdminMenuDefinition{{Label: "Delivery", Path: "/apps/delivery"}},
		Requires:   []CapabilityRequirement{{ID: "email.transactional", Version: ">=0.0.1 <0.1.0", MinLevel: "standard", Optional: true}},
	}
	if errors := ValidateManifestForCore(manifest, "0.0.1"); len(errors) > 0 {
		t.Fatalf("ValidateManifestForCore returned errors: %#v", errors)
	}
}

func TestValidateManifestRejectsAppModulePluginMenuPath(t *testing.T) {
	manifest := Manifest{
		ID:               "app.delivery.operations",
		Type:             "app_module",
		Scope:            "app",
		AppID:            "delivery",
		Name:             "Delivery Operations",
		Version:          "0.0.1",
		ManifestVersion:  "1.0",
		PluginAPIVersion: "1.0",
		RequiresCore:     ">=0.0.1 <0.1.0",
		Resources: []ResourceDefinition{{
			Key:         "delivery_task",
			DisplayName: "Delivery Task",
			Actions:     []ActionDefinition{{Key: "read", RiskLevel: "normal"}},
		}},
		Permissions: []PermissionDefinition{{Resource: "delivery_task", Action: "read", Scopes: []string{"space"}}},
		LocalCapabilities: []CapabilityDefinition{{
			ID:        "delivery.operations",
			Version:   "0.0.1",
			Level:     "declared",
			Audit:     CapabilityAuditDefinition{Enforcement: "reported_event"},
			DataPlane: CapabilityDataPlaneDefinition{Allowed: []string{"core_data_api"}},
		}},
		AdminMenus: []AdminMenuDefinition{{Label: "Delivery", Path: "/plugins/delivery"}},
	}
	errors := ValidateManifestForCore(manifest, "0.0.1")
	assertContainsError(t, errors, "path must start with /plugins/ for plugins or /apps/ for app_module")
}

func TestValidateManifestRejectsAppModulePublicCapability(t *testing.T) {
	manifest := Manifest{
		ID:               "app.delivery.operations",
		Type:             "app_module",
		Scope:            "app",
		AppID:            "delivery",
		Name:             "Delivery Operations",
		Version:          "0.0.1",
		ManifestVersion:  "1.0",
		PluginAPIVersion: "1.0",
		RequiresCore:     ">=0.0.1 <0.1.0",
		Resources: []ResourceDefinition{{
			Key:         "delivery_task",
			DisplayName: "Delivery Task",
			Actions:     []ActionDefinition{{Key: "read", RiskLevel: "normal"}},
		}},
		Permissions: []PermissionDefinition{{Resource: "delivery_task", Action: "read", Scopes: []string{"space"}}},
		Capabilities: []CapabilityDefinition{{
			ID:        "delivery.operations",
			Version:   "0.0.1",
			Level:     "declared",
			Audit:     CapabilityAuditDefinition{Enforcement: "reported_event"},
			DataPlane: CapabilityDataPlaneDefinition{Allowed: []string{"core_data_api"}},
		}},
	}
	errors := ValidateManifestForCore(manifest, "0.0.1")
	assertContainsError(t, errors, "app_module manifests must declare app-private capabilities under local_capabilities")
}

func TestValidateManifestRejectsAppModuleOutsideAppNamespace(t *testing.T) {
	manifest := Manifest{
		ID:               "app.other.operations",
		Type:             "app_module",
		Scope:            "app",
		AppID:            "delivery",
		Name:             "Delivery Operations",
		Version:          "0.0.1",
		ManifestVersion:  "1.0",
		PluginAPIVersion: "1.0",
		RequiresCore:     ">=0.0.1 <0.1.0",
		Resources: []ResourceDefinition{{
			Key:         "delivery_task",
			DisplayName: "Delivery Task",
			Actions:     []ActionDefinition{{Key: "read", RiskLevel: "normal"}},
		}},
		Permissions: []PermissionDefinition{{Resource: "delivery_task", Action: "read", Scopes: []string{"space"}}},
		LocalCapabilities: []CapabilityDefinition{{
			ID:        "delivery.operations",
			Version:   "0.0.1",
			Level:     "declared",
			Audit:     CapabilityAuditDefinition{Enforcement: "reported_event"},
			DataPlane: CapabilityDataPlaneDefinition{Allowed: []string{"core_data_api"}},
		}},
	}
	errors := ValidateManifestForCore(manifest, "0.0.1")
	assertContainsError(t, errors, "app_module id must be scoped under app.<app_id>.")
}

func TestValidateManifestRejectsLocalCapabilityOutsideAppNamespace(t *testing.T) {
	manifest := Manifest{
		ID:               "app.delivery.operations",
		Type:             "app_module",
		Scope:            "app",
		AppID:            "delivery",
		Name:             "Delivery Operations",
		Version:          "0.0.1",
		ManifestVersion:  "1.0",
		PluginAPIVersion: "1.0",
		RequiresCore:     ">=0.0.1 <0.1.0",
		Resources: []ResourceDefinition{{
			Key:         "delivery_task",
			DisplayName: "Delivery Task",
			Actions:     []ActionDefinition{{Key: "read", RiskLevel: "normal"}},
		}},
		Permissions: []PermissionDefinition{{Resource: "delivery_task", Action: "read", Scopes: []string{"space"}}},
		LocalCapabilities: []CapabilityDefinition{{
			ID:        "other.operations",
			Version:   "0.0.1",
			Level:     "declared",
			Audit:     CapabilityAuditDefinition{Enforcement: "reported_event"},
			DataPlane: CapabilityDataPlaneDefinition{Allowed: []string{"core_data_api"}},
		}},
	}
	errors := ValidateManifestForCore(manifest, "0.0.1")
	assertContainsError(t, errors, `local_capabilities[0].id must be scoped under app_id prefix "delivery."`)
}

func TestValidateManifestRejectsLocalCapabilityOnPublicPlugin(t *testing.T) {
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
		Permissions: []PermissionDefinition{{Resource: "delivery_task", Action: "read", Scopes: []string{"space"}}},
		LocalCapabilities: []CapabilityDefinition{{
			ID:        "delivery.operations",
			Version:   "0.0.1",
			Level:     "declared",
			Audit:     CapabilityAuditDefinition{Enforcement: "reported_event"},
			DataPlane: CapabilityDataPlaneDefinition{Allowed: []string{"core_data_api"}},
		}},
	}
	errors := ValidateManifestForCore(manifest, "0.0.1")
	assertContainsError(t, errors, "local_capabilities are only valid for app_module manifests")
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
		Permissions: []PermissionDefinition{{Resource: "email_delivery", Action: "create", Scopes: []string{"space"}}},
		Capabilities: []CapabilityDefinition{{
			ID:        "email.transactional",
			Version:   "0.0.1",
			Level:     "root",
			Audit:     CapabilityAuditDefinition{Enforcement: "reported_event"},
			DataPlane: CapabilityDataPlaneDefinition{Allowed: []string{"direct_db"}},
		}},
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
			Actions:     []ActionDefinition{{Key: "read", RiskLevel: "normal"}, {Key: "create", RiskLevel: "high"}},
		}},
		Permissions: []PermissionDefinition{
			{Resource: "email_delivery", Action: "read", Scopes: []string{"space"}},
			{Resource: "email_delivery", Action: "create", Scopes: []string{"space"}},
		},
		Routes: []RouteDefinition{{
			Method:       "POST",
			Path:         "/contract/v1/email/send",
			ResourceType: "email_delivery",
			Action:       "create",
			Handler:      "send_email",
		}, {
			Method:       "HEAD",
			Path:         "/contract/v1/email/send/{message_id}",
			ResourceType: "email_delivery",
			Action:       "read",
			Handler:      "head_email",
		}},
		Runtime: ProviderRuntimeDefinition{
			Type:               "external",
			Protocol:           "http_json",
			Version:            "0.0.1",
			EndpointSettingKey: "provider.endpoint",
			SchemaCompatibility: &SchemaCompatibilityDefinition{
				Min:       1,
				Max:       1,
				Preferred: 1,
			},
		},
		Events: EventDefinitions{
			Publishes: []string{"email.sent", "email.failed"},
			Consumes:  []string{"member.created"},
		},
		Jobs:            []JobDefinition{{ID: "email_retry", Schedule: "*/5 * * * *"}},
		HealthChecks:    []HealthCheckDefinition{{ID: "ready", Path: "/ready"}},
		Secrets:         []SecretDefinition{{Key: "SMTP_PASSWORD", Required: true}},
		ExternalNetwork: []NetworkDefinition{{Target: "smtp.example.com:587", Purpose: "smtp_delivery", Required: true}},
		Capabilities: []CapabilityDefinition{{
			ID:         "email.transactional",
			Version:    "0.0.1",
			Level:      "standard",
			Audit:      CapabilityAuditDefinition{Enforcement: "reported_event"},
			DataPlane:  CapabilityDataPlaneDefinition{Allowed: []string{"direct_db"}},
			Operations: []CapabilityOperationDefinition{standardSendEmailOperation()},
		}},
		Requires:    []CapabilityRequirement{},
		AuditEvents: []AuditEventDefinition{{Key: "email.sent", RiskLevel: "normal"}},
		AdminMenus:  []AdminMenuDefinition{{Label: "SMTP Email", Path: "/plugins/email-smtp"}},
		Settings: []SettingDefinition{
			{Key: "default_from", ValueType: "string", Scope: "space", Default: "noreply@example.com"},
			{Key: "provider.endpoint", ValueType: "string", Scope: "instance", Default: "http://smtp-provider.internal"},
		},
	}
	if errors := ValidateManifestForCore(manifest, "0.0.1"); len(errors) > 0 {
		t.Fatalf("ValidateManifestForCore returned errors: %#v", errors)
	}
}

func TestValidateManifestAcceptsDynamicRouteAuthorization(t *testing.T) {
	manifest := Manifest{
		ID:               "plystra.crud",
		Name:             "CRUD",
		Version:          "0.0.1",
		ManifestVersion:  "1.0",
		PluginAPIVersion: "1.0",
		RequiresCore:     ">=0.0.1 <0.1.0",
		Resources: []ResourceDefinition{{
			Key:         "invoice",
			DisplayName: "Invoice",
			Actions:     []ActionDefinition{{Key: "read", RiskLevel: "normal"}, {Key: "create", RiskLevel: "normal"}, {Key: "update", RiskLevel: "high"}},
		}, {
			Key:         "activity_log",
			DisplayName: "Activity Log",
			Actions:     []ActionDefinition{{Key: "read", RiskLevel: "normal"}},
		}},
		Permissions: []PermissionDefinition{
			{Resource: "invoice", Action: "read", Scopes: []string{"space"}},
			{Resource: "invoice", Action: "create", Scopes: []string{"space"}},
			{Resource: "invoice", Action: "update", Scopes: []string{"space"}},
			{Resource: "activity_log", Action: "read", Scopes: []string{"space"}},
		},
		Routes: []RouteDefinition{{
			Method:  "GET",
			Path:    "/api/v1/crud/{resource}",
			Handler: "generic_list",
			Authorization: RouteAuthorizationDefinition{
				Mode:                "dynamic_resource",
				ResourceParam:       "resource",
				ResourceKeyStrategy: "plugin_defined_alias",
				Action:              "read",
			},
		}, {
			Method:  "POST",
			Path:    "/api/v1/crud/{resource}",
			Handler: "generic_create",
			Authorization: RouteAuthorizationDefinition{
				Mode:                "dynamic_resource",
				ResourceParam:       "resource",
				ResourceKeyStrategy: "plugin_defined_alias",
				Action:              "create",
				ExcludedResources:   []string{"activity_log"},
			},
		}},
	}
	if errors := ValidateManifestForCore(manifest, "0.0.1"); len(errors) > 0 {
		t.Fatalf("ValidateManifestForCore returned errors: %#v", errors)
	}
}

func TestValidateManifestRejectsInvalidDynamicRouteAuthorization(t *testing.T) {
	manifest := Manifest{
		ID:               "plystra.crud",
		Name:             "CRUD",
		Version:          "0.0.1",
		ManifestVersion:  "1.0",
		PluginAPIVersion: "1.0",
		RequiresCore:     ">=0.0.1 <0.1.0",
		Resources: []ResourceDefinition{{
			Key:         "invoice",
			DisplayName: "Invoice",
			Actions:     []ActionDefinition{{Key: "read", RiskLevel: "normal"}},
		}, {
			Key:         "activity_log",
			DisplayName: "Activity Log",
			Actions:     []ActionDefinition{{Key: "read", RiskLevel: "normal"}},
		}},
		Permissions: []PermissionDefinition{
			{Resource: "invoice", Action: "read", Scopes: []string{"space"}},
			{Resource: "activity_log", Action: "read", Scopes: []string{"space"}},
		},
		Routes: []RouteDefinition{{
			Method:       "POST",
			Path:         "/api/v1/crud/{resource}",
			ResourceType: "invoice",
			Action:       "read",
			Handler:      "generic_create",
			Authorization: RouteAuthorizationDefinition{
				Mode:                "dynamic_resource",
				ResourceParam:       "missing",
				ResourceKeyStrategy: "plugin_defined_alias",
				Action:              "create",
			},
		}},
	}
	errors := ValidateManifestForCore(manifest, "0.0.1")
	assertContainsError(t, errors, "dynamic_resource cannot be combined")
	assertContainsError(t, errors, "resource_param must reference a parameter in route path")
	assertContainsError(t, errors, `action "create" is not declared`)
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
		Runtime: ProviderRuntimeDefinition{
			Type:               "sidecar",
			Protocol:           "raw_tcp",
			EndpointSettingKey: "missing.endpoint",
			SchemaCompatibility: &SchemaCompatibilityDefinition{
				Min:       3,
				Max:       2,
				Preferred: 4,
			},
		},
	}
	errors := ValidateManifestForCore(manifest, "0.0.1")
	if len(errors) < 8 {
		t.Fatalf("ValidateManifestForCore returned too few errors: %#v", errors)
	}
	assertContainsError(t, errors, "runtime.type")
	assertContainsError(t, errors, "runtime.protocol")
	assertContainsError(t, errors, "runtime.endpoint_setting_key references unknown instance setting")
	assertContainsError(t, errors, "runtime.schema_compatibility")
}

func TestValidateManifestRejectsInvalidSettingDefault(t *testing.T) {
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
		Settings:    []SettingDefinition{{Key: "public_api_enabled", ValueType: "boolean", Scope: "instance", Default: "true"}},
	}
	errors := ValidateManifestForCore(manifest, "0.0.1")
	assertContainsError(t, errors, "settings[0].default must be a boolean")
}

func TestValidateManifestAllowsExternalRuntimeWithoutEndpointSetting(t *testing.T) {
	manifest := Manifest{
		ID:               "plystra.workflow",
		Name:             "Workflow",
		Version:          "0.0.1",
		ManifestVersion:  "1.0",
		PluginAPIVersion: "1.0",
		RequiresCore:     ">=0.0.1 <0.1.0",
		Resources: []ResourceDefinition{{
			Key:         "approval_request",
			DisplayName: "Approval Request",
			Actions:     []ActionDefinition{{Key: "create", RiskLevel: "normal"}},
		}},
		Permissions: []PermissionDefinition{{Resource: "approval_request", Action: "create", Scopes: []string{"space"}}},
		Runtime: ProviderRuntimeDefinition{
			Type:     "external",
			Protocol: "http_json",
			Version:  "0.0.1",
		},
		Capabilities: []CapabilityDefinition{{
			ID:         "workflow.approval",
			Version:    "0.0.1",
			Level:      "standard",
			Audit:      CapabilityAuditDefinition{Enforcement: "reported_event"},
			DataPlane:  CapabilityDataPlaneDefinition{Allowed: []string{"direct_db"}},
			Operations: []CapabilityOperationDefinition{standardWorkflowOperation()},
		}},
		Routes: []RouteDefinition{{
			Method:       "POST",
			Path:         "/contract/v1/workflow/approvals",
			ResourceType: "approval_request",
			Action:       "create",
			Handler:      "create_approval",
		}},
	}
	if errors := ValidateManifestForCore(manifest, "0.0.1"); len(errors) > 0 {
		t.Fatalf("ValidateManifestForCore returned errors: %#v", errors)
	}
}

func TestValidateManifestRejectsCapabilityWithoutGovernance(t *testing.T) {
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
		Capabilities: []CapabilityDefinition{{
			ID:      "billing.invoice",
			Version: "0.0.1",
			Level:   "standard",
		}},
	}
	errors := ValidateManifestForCore(manifest, "0.0.1")
	assertContainsError(t, errors, "capabilities[0].audit.enforcement")
	assertContainsError(t, errors, "capabilities[0].data_plane.allowed")
}

func TestValidateManifestRejectsStandardCapabilityWithoutOperations(t *testing.T) {
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
		Capabilities: []CapabilityDefinition{{
			ID:        "email.transactional",
			Version:   "0.0.1",
			Level:     "standard",
			Audit:     CapabilityAuditDefinition{Enforcement: "reported_event"},
			DataPlane: CapabilityDataPlaneDefinition{Allowed: []string{"direct_db"}},
		}},
	}
	errors := ValidateManifestForCore(manifest, "0.0.1")
	assertContainsError(t, errors, "operations is required for standard and certified capabilities")
}

func TestValidateManifestRejectsIncompleteMediatedOperation(t *testing.T) {
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
		Capabilities: []CapabilityDefinition{{
			ID:        "email.transactional",
			Version:   "0.0.1",
			Level:     "standard",
			Audit:     CapabilityAuditDefinition{Enforcement: "reported_event"},
			DataPlane: CapabilityDataPlaneDefinition{Allowed: []string{"direct_db"}},
			Operations: []CapabilityOperationDefinition{{
				Name:       "send",
				Invocation: CapabilityInvocationDefinition{Mode: "revocable_mediated_grant", GrantTTLMS: 30000},
				Delegation: CapabilityDelegationDefinition{Mode: "plugin_service"},
			}},
		}},
	}
	errors := ValidateManifestForCore(manifest, "0.0.1")
	assertContainsError(t, errors, "introspection=required")
	assertContainsError(t, errors, "outcome_receipt=required")
	assertContainsError(t, errors, "idempotency=required")
}

func TestValidateManifestRejectsGovernanceDataPlaneMismatch(t *testing.T) {
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
			Actions:     []ActionDefinition{{Key: "approve", RiskLevel: "high"}},
		}},
		Permissions: []PermissionDefinition{{Resource: "invoice", Action: "approve", Scopes: []string{"space"}}},
		Capabilities: []CapabilityDefinition{{
			ID:        "billing.invoice",
			Version:   "0.0.1",
			Level:     "standard",
			Audit:     CapabilityAuditDefinition{Enforcement: "controlled_action"},
			DataPlane: CapabilityDataPlaneDefinition{Allowed: []string{"direct_db"}},
		}},
	}
	errors := ValidateManifestForCore(manifest, "0.0.1")
	assertContainsError(t, errors, "controlled_action")
}

func standardSendEmailOperation() CapabilityOperationDefinition {
	return CapabilityOperationDefinition{
		Name: "send",
		Invocation: CapabilityInvocationDefinition{
			Mode:           "revocable_mediated_grant",
			GrantTTLMS:     30000,
			Introspection:  "required",
			OutcomeReceipt: "required",
			Idempotency:    "required",
			TimeoutMS:      10000,
			Cancellation:   "best_effort",
		},
		Delegation: CapabilityDelegationDefinition{Mode: "plugin_service"},
		CallGraph:  CapabilityCallGraphDefinition{MaxDepth: 4},
	}
}

func standardWorkflowOperation() CapabilityOperationDefinition {
	return CapabilityOperationDefinition{
		Name: "create_request",
		Invocation: CapabilityInvocationDefinition{
			Mode:           "revocable_mediated_grant",
			GrantTTLMS:     30000,
			Introspection:  "required",
			OutcomeReceipt: "required",
			Idempotency:    "required",
		},
		Delegation: CapabilityDelegationDefinition{Mode: "preserve_principal"},
		CallGraph:  CapabilityCallGraphDefinition{MaxDepth: 4},
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

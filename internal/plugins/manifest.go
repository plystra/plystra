package plugins

import (
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
)

type Manifest struct {
	ID                string                    `json:"id"`
	Type              string                    `json:"type,omitempty"`
	Scope             string                    `json:"scope,omitempty"`
	AppID             string                    `json:"app_id,omitempty"`
	TrustBundleID     string                    `json:"trust_bundle_id,omitempty"`
	Name              string                    `json:"name"`
	Description       string                    `json:"description"`
	Version           string                    `json:"version"`
	Source            string                    `json:"source"`
	Status            string                    `json:"status"`
	ManifestVersion   string                    `json:"manifest_version"`
	PluginAPIVersion  string                    `json:"plugin_api_version"`
	RequiresCore      string                    `json:"requires_core"`
	Resources         []ResourceDefinition      `json:"resources"`
	Permissions       []PermissionDefinition    `json:"permissions"`
	AuditEvents       []AuditEventDefinition    `json:"audit_events"`
	AdminMenus        []AdminMenuDefinition     `json:"admin_menu"`
	Settings          []SettingDefinition       `json:"settings"`
	Capabilities      []CapabilityDefinition    `json:"capabilities"`
	LocalCapabilities []CapabilityDefinition    `json:"local_capabilities,omitempty"`
	Requires          []CapabilityRequirement   `json:"requires_capabilities"`
	Routes            []RouteDefinition         `json:"routes"`
	Events            EventDefinitions          `json:"events"`
	Jobs              []JobDefinition           `json:"jobs"`
	HealthChecks      []HealthCheckDefinition   `json:"health_checks"`
	Secrets           []SecretDefinition        `json:"secrets"`
	ExternalNetwork   []NetworkDefinition       `json:"external_network"`
	Runtime           ProviderRuntimeDefinition `json:"runtime,omitempty"`
}

type ResourceDefinition struct {
	Key         string             `json:"key"`
	DisplayName string             `json:"display_name"`
	Actions     []ActionDefinition `json:"actions"`
}

type ActionDefinition struct {
	Key       string `json:"key"`
	RiskLevel string `json:"risk_level"`
}

type PermissionDefinition struct {
	Resource string   `json:"resource"`
	Action   string   `json:"action"`
	Scopes   []string `json:"scopes"`
}

type AuditEventDefinition struct {
	Key       string `json:"key"`
	RiskLevel string `json:"risk_level"`
}

type AdminMenuDefinition struct {
	Label              string `json:"label"`
	Path               string `json:"path"`
	RequiredPermission string `json:"required_permission"`
}

type SettingDefinition struct {
	Key         string `json:"key"`
	ValueType   string `json:"type"`
	Scope       string `json:"scope"`
	Default     any    `json:"default,omitempty"`
	Description string `json:"description"`
}

type CapabilityDefinition struct {
	ID          string                          `json:"id"`
	Version     string                          `json:"version"`
	Level       string                          `json:"level"`
	Description string                          `json:"description"`
	Audit       CapabilityAuditDefinition       `json:"audit"`
	DataPlane   CapabilityDataPlaneDefinition   `json:"data_plane"`
	Operations  []CapabilityOperationDefinition `json:"operations,omitempty"`
}

type CapabilityAuditDefinition struct {
	Enforcement     string                     `json:"enforcement"`
	MutationJournal *MutationJournalDefinition `json:"mutation_journal,omitempty"`
}

type MutationJournalDefinition struct {
	Atomic               bool   `json:"atomic"`
	AvailabilityCoupling bool   `json:"availability_coupling"`
	Payload              string `json:"payload"`
	Retention            string `json:"retention"`
	Archival             string `json:"archival"`
}

type CapabilityDataPlaneDefinition struct {
	Allowed    []string `json:"allowed"`
	Disallowed []string `json:"disallowed,omitempty"`
}

type CapabilityOperationDefinition struct {
	Name       string                         `json:"name"`
	Invocation CapabilityInvocationDefinition `json:"invocation"`
	Delegation CapabilityDelegationDefinition `json:"delegation"`
	CallGraph  CapabilityCallGraphDefinition  `json:"call_graph,omitempty"`
}

type CapabilityInvocationDefinition struct {
	Mode                        string `json:"mode"`
	GrantTTLMS                  int    `json:"grant_ttl_ms,omitempty"`
	Introspection               string `json:"introspection,omitempty"`
	OutcomeReceipt              string `json:"outcome_receipt,omitempty"`
	Idempotency                 string `json:"idempotency,omitempty"`
	TimeoutMS                   int    `json:"timeout_ms,omitempty"`
	Cancellation                string `json:"cancellation,omitempty"`
	ResultUnknownReconciliation string `json:"result_unknown_reconciliation,omitempty"`
}

type CapabilityDelegationDefinition struct {
	Mode string `json:"mode"`
}

type CapabilityCallGraphDefinition struct {
	MaxDepth       int      `json:"max_depth,omitempty"`
	Reentrant      bool     `json:"reentrant,omitempty"`
	AllowedCallers []string `json:"allowed_callers,omitempty"`
}

type CapabilityRequirement struct {
	ID       string `json:"id"`
	Version  string `json:"version"`
	MinLevel string `json:"min_level"`
	Optional bool   `json:"optional"`
}

type RouteDefinition struct {
	Method        string                       `json:"method"`
	Path          string                       `json:"path"`
	ResourceType  string                       `json:"resource_type"`
	Action        string                       `json:"action"`
	Handler       string                       `json:"handler"`
	Authorization RouteAuthorizationDefinition `json:"authorization,omitempty"`
}

type RouteAuthorizationDefinition struct {
	Mode                string   `json:"mode,omitempty"`
	ResourceParam       string   `json:"resource_param,omitempty"`
	ResourceKeyStrategy string   `json:"resource_key_strategy,omitempty"`
	Action              string   `json:"action,omitempty"`
	AllowedResources    []string `json:"allowed_resources,omitempty"`
	ExcludedResources   []string `json:"excluded_resources,omitempty"`
}

type EventDefinitions struct {
	Publishes []string `json:"publishes"`
	Consumes  []string `json:"consumes"`
}

type JobDefinition struct {
	ID          string `json:"id"`
	Schedule    string `json:"schedule"`
	Description string `json:"description"`
}

type HealthCheckDefinition struct {
	ID          string `json:"id"`
	Path        string `json:"path"`
	Description string `json:"description"`
}

type SecretDefinition struct {
	Key         string `json:"key"`
	Required    bool   `json:"required"`
	Description string `json:"description"`
}

type NetworkDefinition struct {
	Target      string `json:"target"`
	Purpose     string `json:"purpose"`
	Required    bool   `json:"required"`
	Description string `json:"description"`
}

type ProviderRuntimeDefinition struct {
	Type                string                         `json:"type,omitempty"`
	Protocol            string                         `json:"protocol,omitempty"`
	Version             string                         `json:"version,omitempty"`
	EndpointSettingKey  string                         `json:"endpoint_setting_key,omitempty"`
	SchemaCompatibility *SchemaCompatibilityDefinition `json:"schema_compatibility,omitempty"`
}

type SchemaCompatibilityDefinition struct {
	Min       int `json:"min"`
	Max       int `json:"max"`
	Preferred int `json:"preferred"`
}

var pluginIDPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)
var semverLikePattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9_.-]+)?$`)
var keyPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
var settingKeyPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$`)
var capabilityIDPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)
var eventKeyPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)
var secretKeyPattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

func ValidateManifest(manifest Manifest) []string {
	var errors []string
	if !pluginIDPattern.MatchString(manifest.ID) {
		errors = append(errors, "id must use reverse-DNS style such as plystra.moderation")
	}
	manifestType := firstNonEmpty(manifest.Type, "plugin")
	manifestScope := firstNonEmpty(manifest.Scope, "public")
	if !validManifestType(manifestType) {
		errors = append(errors, "type must be plugin or app_module")
	}
	if !validManifestScope(manifestScope) {
		errors = append(errors, "scope must be public, private, or app")
	}
	if manifestType == "app_module" {
		if manifestScope != "app" {
			errors = append(errors, "type app_module requires scope app")
		}
		if !keyPattern.MatchString(strings.TrimSpace(manifest.AppID)) {
			errors = append(errors, "app_id is required for app_module and must be a valid key")
		}
		if appID := strings.TrimSpace(manifest.AppID); keyPattern.MatchString(appID) && !strings.HasPrefix(manifest.ID, "app."+appID+".") {
			errors = append(errors, "app_module id must be scoped under app.<app_id>.")
		}
		trustBundleID := strings.TrimSpace(manifest.TrustBundleID)
		if !validTrustBundleID(trustBundleID) {
			errors = append(errors, "trust_bundle_id is required for app_module and must be a dotted id scoped under <app_id>.")
		} else if appID := strings.TrimSpace(manifest.AppID); keyPattern.MatchString(appID) && !strings.HasPrefix(trustBundleID, appID+".") {
			errors = append(errors, "trust_bundle_id for app_module must be scoped under <app_id>.")
		}
		if len(manifest.Capabilities) > 0 {
			errors = append(errors, "app_module manifests must declare app-private capabilities under local_capabilities")
		}
	} else {
		if manifestScope == "app" {
			errors = append(errors, "scope app requires type app_module")
		}
		if strings.TrimSpace(manifest.AppID) != "" {
			errors = append(errors, "app_id is only valid for app_module manifests")
		}
		if strings.TrimSpace(manifest.TrustBundleID) != "" {
			errors = append(errors, "trust_bundle_id is only valid for app_module manifests")
		}
		if len(manifest.LocalCapabilities) > 0 {
			errors = append(errors, "local_capabilities are only valid for app_module manifests")
		}
	}
	if strings.TrimSpace(manifest.Name) == "" {
		errors = append(errors, "name is required")
	}
	if !semverLikePattern.MatchString(manifest.Version) {
		errors = append(errors, "version must be semantic version-like")
	}
	if strings.TrimSpace(manifest.Status) != "" && !validPluginStatus(manifest.Status) {
		errors = append(errors, "status must be one of: discovered, validated, installed, migrated, enabled, disabled, upgrading, failed, or uninstalled")
	}
	if manifest.ManifestVersion == "" {
		errors = append(errors, "manifest_version is required")
	} else if manifest.ManifestVersion != "0.1" && manifest.ManifestVersion != "1.0" {
		errors = append(errors, "manifest_version must be one of: 0.1, 1.0")
	}
	if manifest.PluginAPIVersion == "" {
		errors = append(errors, "plugin_api_version is required")
	} else if manifest.PluginAPIVersion != "0.1" && manifest.PluginAPIVersion != "1.0" {
		errors = append(errors, "plugin_api_version must be one of: 0.1, 1.0")
	}
	if strings.TrimSpace(manifest.RequiresCore) == "" {
		errors = append(errors, "requires_core is required")
	}

	resourceActions := map[string]map[string]bool{}
	resourceKeys := map[string]bool{}
	for i, resource := range manifest.Resources {
		if !keyPattern.MatchString(resource.Key) {
			errors = append(errors, fmt.Sprintf("resources[%d].key is invalid", i))
		}
		if strings.TrimSpace(resource.DisplayName) == "" {
			errors = append(errors, fmt.Sprintf("resources[%d].display_name is required", i))
		}
		if resourceKeys[resource.Key] {
			errors = append(errors, fmt.Sprintf("duplicate resource key %q", resource.Key))
		}
		resourceKeys[resource.Key] = true
		resourceActions[resource.Key] = map[string]bool{}
		actionKeys := map[string]bool{}
		if len(resource.Actions) == 0 {
			errors = append(errors, fmt.Sprintf("resources[%d].actions must not be empty", i))
		}
		for j, action := range resource.Actions {
			if !keyPattern.MatchString(action.Key) {
				errors = append(errors, fmt.Sprintf("resources[%d].actions[%d].key is invalid", i, j))
			}
			if strings.TrimSpace(action.RiskLevel) != "" && !validRiskLevel(action.RiskLevel) {
				errors = append(errors, fmt.Sprintf("resources[%d].actions[%d].risk_level must be one of low, normal, high, or critical", i, j))
			}
			if actionKeys[action.Key] {
				errors = append(errors, fmt.Sprintf("duplicate action key %q for resource %q", action.Key, resource.Key))
			}
			actionKeys[action.Key] = true
			resourceActions[resource.Key][action.Key] = true
		}
	}

	for i, permission := range manifest.Permissions {
		if !resourceActions[permission.Resource][permission.Action] {
			errors = append(errors, fmt.Sprintf("permissions[%d] references unknown resource/action %s:%s", i, permission.Resource, permission.Action))
		}
		if len(permission.Scopes) == 0 {
			errors = append(errors, fmt.Sprintf("permissions[%d].scopes must not be empty", i))
		}
		for _, scope := range permission.Scopes {
			if scope == "global" {
				errors = append(errors, fmt.Sprintf("permissions[%d] cannot declare global scope", i))
			}
			if !validScope(scope) {
				errors = append(errors, fmt.Sprintf("permissions[%d] has unknown scope %q", i, scope))
			}
		}
	}

	auditKeys := map[string]bool{}
	for i, event := range manifest.AuditEvents {
		if strings.TrimSpace(event.Key) == "" {
			errors = append(errors, fmt.Sprintf("audit_events[%d].key is required", i))
		}
		if strings.TrimSpace(event.Key) != "" && !eventKeyPattern.MatchString(event.Key) {
			errors = append(errors, fmt.Sprintf("audit_events[%d].key is invalid", i))
		}
		if strings.TrimSpace(event.RiskLevel) != "" && !validRiskLevel(event.RiskLevel) {
			errors = append(errors, fmt.Sprintf("audit_events[%d].risk_level must be one of low, normal, high, or critical", i))
		}
		if auditKeys[event.Key] {
			errors = append(errors, fmt.Sprintf("duplicate audit event key %q", event.Key))
		}
		auditKeys[event.Key] = true
	}

	for i, menu := range manifest.AdminMenus {
		if strings.TrimSpace(menu.Label) == "" {
			errors = append(errors, fmt.Sprintf("admin_menu[%d].label is required", i))
		}
		if !validAdminMenuPath(manifestType, menu.Path) {
			errors = append(errors, fmt.Sprintf("admin_menu[%d].path must start with /plugins/ for plugins or /apps/ for app_module", i))
		}
	}

	settingKeys := map[string]bool{}
	instanceSettingKeys := map[string]bool{}
	for i, setting := range manifest.Settings {
		scope := firstNonEmpty(setting.Scope, "space")
		if !settingKeyPattern.MatchString(setting.Key) {
			errors = append(errors, fmt.Sprintf("settings[%d].key is invalid", i))
		}
		if sensitiveSettingKey(setting.Key) {
			errors = append(errors, fmt.Sprintf("settings[%d].key must not look like a secret; declare secrets under secrets instead", i))
		}
		if settingKeys[scope+":"+setting.Key] {
			errors = append(errors, fmt.Sprintf("duplicate setting %q for scope %q", setting.Key, scope))
		}
		settingKeys[scope+":"+setting.Key] = true
		if strings.TrimSpace(setting.ValueType) == "" {
			errors = append(errors, fmt.Sprintf("settings[%d].type is required", i))
		} else if !validSettingType(setting.ValueType) {
			errors = append(errors, fmt.Sprintf("settings[%d].type must be one of string, integer, number, boolean, string_array, array, object, or json", i))
		} else if setting.Default != nil {
			errors = append(errors, validateSettingDefault(i, setting)...)
		}
		if scope != "instance" && scope != "space" {
			errors = append(errors, fmt.Sprintf("settings[%d].scope must be instance or space", i))
		}
		if scope == "instance" {
			instanceSettingKeys[setting.Key] = true
		}
	}

	for i, route := range manifest.Routes {
		method := strings.ToUpper(strings.TrimSpace(route.Method))
		if !validHTTPMethod(method) {
			errors = append(errors, fmt.Sprintf("routes[%d].method must be GET, HEAD, POST, PUT, PATCH, or DELETE", i))
		}
		if !validPluginPath(route.Path) {
			errors = append(errors, fmt.Sprintf("routes[%d].path must be an absolute API path without query or fragment", i))
		}
		if strings.TrimSpace(route.ResourceType) != "" && !resourceKeys[route.ResourceType] {
			errors = append(errors, fmt.Sprintf("routes[%d].resource_type references unknown resource %q", i, route.ResourceType))
		}
		if strings.TrimSpace(route.Action) != "" {
			if strings.TrimSpace(route.ResourceType) == "" {
				errors = append(errors, fmt.Sprintf("routes[%d].resource_type is required when action is declared", i))
			} else if !resourceActions[route.ResourceType][route.Action] {
				errors = append(errors, fmt.Sprintf("routes[%d].action references unknown resource/action %s:%s", i, route.ResourceType, route.Action))
			}
		}
		if strings.TrimSpace(route.Handler) != "" && !keyPattern.MatchString(route.Handler) {
			errors = append(errors, fmt.Sprintf("routes[%d].handler is invalid", i))
		}
		errors = append(errors, validateRouteAuthorization(i, route, resourceKeys, resourceActions)...)
	}

	validateEventList := func(field string, values []string) {
		seen := map[string]bool{}
		for i, value := range values {
			if !eventKeyPattern.MatchString(value) {
				errors = append(errors, fmt.Sprintf("events.%s[%d] is invalid", field, i))
			}
			if seen[value] {
				errors = append(errors, fmt.Sprintf("events.%s contains duplicate event %q", field, value))
			}
			seen[value] = true
		}
	}
	validateEventList("publishes", manifest.Events.Publishes)
	validateEventList("consumes", manifest.Events.Consumes)

	jobIDs := map[string]bool{}
	for i, job := range manifest.Jobs {
		if !keyPattern.MatchString(job.ID) {
			errors = append(errors, fmt.Sprintf("jobs[%d].id is invalid", i))
		}
		if jobIDs[job.ID] {
			errors = append(errors, fmt.Sprintf("duplicate job id %q", job.ID))
		}
		jobIDs[job.ID] = true
		if strings.TrimSpace(job.Schedule) == "" {
			errors = append(errors, fmt.Sprintf("jobs[%d].schedule is required", i))
		}
	}

	healthIDs := map[string]bool{}
	for i, check := range manifest.HealthChecks {
		if !keyPattern.MatchString(check.ID) {
			errors = append(errors, fmt.Sprintf("health_checks[%d].id is invalid", i))
		}
		if healthIDs[check.ID] {
			errors = append(errors, fmt.Sprintf("duplicate health check id %q", check.ID))
		}
		healthIDs[check.ID] = true
		if !validPluginPath(check.Path) {
			errors = append(errors, fmt.Sprintf("health_checks[%d].path must be an absolute API path without query or fragment", i))
		}
	}

	secretKeys := map[string]bool{}
	for i, secret := range manifest.Secrets {
		if !secretKeyPattern.MatchString(secret.Key) {
			errors = append(errors, fmt.Sprintf("secrets[%d].key must be an uppercase environment-style key", i))
		}
		if secretKeys[secret.Key] {
			errors = append(errors, fmt.Sprintf("duplicate secret key %q", secret.Key))
		}
		secretKeys[secret.Key] = true
	}

	networkTargets := map[string]bool{}
	for i, network := range manifest.ExternalNetwork {
		target := strings.TrimSpace(network.Target)
		if target == "" {
			errors = append(errors, fmt.Sprintf("external_network[%d].target is required", i))
		}
		if strings.ContainsAny(target, "\r\n\t ") {
			errors = append(errors, fmt.Sprintf("external_network[%d].target must not contain whitespace", i))
		}
		if strings.TrimSpace(network.Purpose) == "" {
			errors = append(errors, fmt.Sprintf("external_network[%d].purpose is required", i))
		}
		if networkTargets[target] {
			errors = append(errors, fmt.Sprintf("duplicate external network target %q", target))
		}
		networkTargets[target] = true
	}

	capabilityKeys := map[string]bool{}
	errors = append(errors, validateCapabilityList("capabilities", manifest.Capabilities, capabilityKeys)...)
	errors = append(errors, validateCapabilityList("local_capabilities", manifest.LocalCapabilities, capabilityKeys)...)
	if manifestType == "app_module" && keyPattern.MatchString(strings.TrimSpace(manifest.AppID)) {
		errors = append(errors, validateLocalCapabilityNamespace(manifest.AppID, manifest.LocalCapabilities)...)
	}
	for i, requirement := range manifest.Requires {
		if !capabilityIDPattern.MatchString(requirement.ID) {
			errors = append(errors, fmt.Sprintf("requires_capabilities[%d].id is invalid", i))
		}
		if strings.TrimSpace(requirement.Version) == "" {
			errors = append(errors, fmt.Sprintf("requires_capabilities[%d].version is required", i))
		}
		if requirement.MinLevel != "" && !validCapabilityLevel(requirement.MinLevel) {
			errors = append(errors, fmt.Sprintf("requires_capabilities[%d].min_level must be one of declared, standard, or certified", i))
		}
	}
	errors = append(errors, validateProviderRuntime(manifest.Runtime, instanceSettingKeys)...)

	return errors
}

func validateSettingDefault(i int, setting SettingDefinition) []string {
	var errors []string
	if sensitiveSettingKey(setting.Key) {
		return errors
	}
	switch strings.TrimSpace(setting.ValueType) {
	case "string":
		if _, ok := setting.Default.(string); !ok {
			errors = append(errors, fmt.Sprintf("settings[%d].default must be a string", i))
		}
	case "integer":
		if !jsonNumberIsInteger(setting.Default) {
			errors = append(errors, fmt.Sprintf("settings[%d].default must be an integer", i))
		}
	case "number":
		if !jsonNumberLike(setting.Default) {
			errors = append(errors, fmt.Sprintf("settings[%d].default must be a number", i))
		}
	case "boolean":
		if _, ok := setting.Default.(bool); !ok {
			errors = append(errors, fmt.Sprintf("settings[%d].default must be a boolean", i))
		}
	case "string_array":
		values, ok := setting.Default.([]any)
		if !ok {
			errors = append(errors, fmt.Sprintf("settings[%d].default must be an array of strings", i))
			break
		}
		for j, value := range values {
			if _, ok := value.(string); !ok {
				errors = append(errors, fmt.Sprintf("settings[%d].default[%d] must be a string", i, j))
			}
		}
	case "array":
		if _, ok := setting.Default.([]any); !ok {
			errors = append(errors, fmt.Sprintf("settings[%d].default must be an array", i))
		}
	case "object":
		if _, ok := setting.Default.(map[string]any); !ok {
			errors = append(errors, fmt.Sprintf("settings[%d].default must be an object", i))
		}
	case "json":
		return errors
	}
	return errors
}

func jsonNumberLike(value any) bool {
	switch typed := value.(type) {
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return true
	case float32:
		v := float64(typed)
		return !math.IsNaN(v) && !math.IsInf(v, 0)
	case float64:
		return !math.IsNaN(typed) && !math.IsInf(typed, 0)
	case json.Number:
		v, err := strconv.ParseFloat(typed.String(), 64)
		return err == nil && !math.IsNaN(v) && !math.IsInf(v, 0)
	default:
		return false
	}
}

func jsonNumberIsInteger(value any) bool {
	switch typed := value.(type) {
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return true
	case float32:
		v := float64(typed)
		return !math.IsNaN(v) && !math.IsInf(v, 0) && math.Trunc(v) == v
	case float64:
		return !math.IsNaN(typed) && !math.IsInf(typed, 0) && math.Trunc(typed) == typed
	case json.Number:
		v, err := strconv.ParseFloat(typed.String(), 64)
		return err == nil && !math.IsNaN(v) && !math.IsInf(v, 0) && math.Trunc(v) == v
	default:
		return false
	}
}

func validateCapabilityGovernance(i int, capability CapabilityDefinition) []string {
	var errors []string
	enforcement := strings.TrimSpace(capability.Audit.Enforcement)
	if !validAuditEnforcement(enforcement) {
		errors = append(errors, fmt.Sprintf("capabilities[%d].audit.enforcement must be one of grant_only, reported_event, observed_mutation, or controlled_action", i))
	}
	if len(capability.DataPlane.Allowed) == 0 {
		errors = append(errors, fmt.Sprintf("capabilities[%d].data_plane.allowed must not be empty", i))
	}
	allowed := map[string]bool{}
	for j, plane := range capability.DataPlane.Allowed {
		plane = strings.TrimSpace(plane)
		if !validDataPlane(plane) {
			errors = append(errors, fmt.Sprintf("capabilities[%d].data_plane.allowed[%d] must be one of direct_db, direct_db_with_mutation_journal, action_gateway, or core_data_api", i, j))
			continue
		}
		if allowed[plane] {
			errors = append(errors, fmt.Sprintf("capabilities[%d].data_plane.allowed contains duplicate data plane %q", i, plane))
		}
		allowed[plane] = true
	}
	disallowed := map[string]bool{}
	for j, plane := range capability.DataPlane.Disallowed {
		plane = strings.TrimSpace(plane)
		if !validDataPlane(plane) {
			errors = append(errors, fmt.Sprintf("capabilities[%d].data_plane.disallowed[%d] must be one of direct_db, direct_db_with_mutation_journal, action_gateway, or core_data_api", i, j))
			continue
		}
		if disallowed[plane] {
			errors = append(errors, fmt.Sprintf("capabilities[%d].data_plane.disallowed contains duplicate data plane %q", i, plane))
		}
		disallowed[plane] = true
		if allowed[plane] {
			errors = append(errors, fmt.Sprintf("capabilities[%d].data_plane cannot both allow and disallow %q", i, plane))
		}
	}
	if enforcement != "" && len(allowed) > 0 {
		for plane := range allowed {
			if !auditEnforcementAllowsDataPlane(enforcement, plane) {
				errors = append(errors, fmt.Sprintf("capabilities[%d].audit.enforcement %s does not allow data plane %s", i, enforcement, plane))
			}
		}
	}
	if enforcement == "observed_mutation" {
		if capability.Audit.MutationJournal == nil {
			errors = append(errors, fmt.Sprintf("capabilities[%d].audit.mutation_journal is required for observed_mutation", i))
		} else {
			if !capability.Audit.MutationJournal.Atomic || !capability.Audit.MutationJournal.AvailabilityCoupling {
				errors = append(errors, fmt.Sprintf("capabilities[%d].audit.mutation_journal must declare atomic and availability_coupling true", i))
			}
			if strings.TrimSpace(capability.Audit.MutationJournal.Payload) != "minimal" {
				errors = append(errors, fmt.Sprintf("capabilities[%d].audit.mutation_journal.payload must be minimal", i))
			}
		}
	}
	return errors
}

func validateCapabilityList(field string, capabilities []CapabilityDefinition, capabilityKeys map[string]bool) []string {
	var errors []string
	for i, capability := range capabilities {
		if !capabilityIDPattern.MatchString(capability.ID) {
			errors = append(errors, fmt.Sprintf("%s[%d].id is invalid", field, i))
		}
		if capabilityKeys[capability.ID] {
			errors = append(errors, fmt.Sprintf("duplicate capability %q", capability.ID))
		}
		capabilityKeys[capability.ID] = true
		if capability.Version == "" || !semverLikePattern.MatchString(capability.Version) {
			errors = append(errors, fmt.Sprintf("%s[%d].version must be semantic version-like", field, i))
		}
		if !validCapabilityLevel(capability.Level) {
			errors = append(errors, fmt.Sprintf("%s[%d].level must be one of declared, standard, or certified", field, i))
		}
		errors = append(errors, validateCapabilityGovernanceNamed(field, i, capability)...)
		errors = append(errors, validateCapabilityOperationsNamed(field, i, capability)...)
	}
	return errors
}

func validateLocalCapabilityNamespace(appID string, capabilities []CapabilityDefinition) []string {
	var errors []string
	prefix := strings.TrimSpace(appID) + "."
	for i, capability := range capabilities {
		if !strings.HasPrefix(strings.TrimSpace(capability.ID), prefix) {
			errors = append(errors, fmt.Sprintf("local_capabilities[%d].id must be scoped under app_id prefix %q", i, prefix))
		}
	}
	return errors
}

func validTrustBundleID(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	if !capabilityIDPattern.MatchString(value) {
		return false
	}
	for _, part := range strings.Split(value, ".") {
		if !keyPattern.MatchString(part) {
			return false
		}
	}
	return true
}

func validateCapabilityGovernanceNamed(field string, i int, capability CapabilityDefinition) []string {
	errors := validateCapabilityGovernance(i, capability)
	return renameCapabilityErrors(errors, field)
}

func validateCapabilityOperations(i int, capability CapabilityDefinition) []string {
	return validateCapabilityOperationsNamed("capabilities", i, capability)
}

func validateCapabilityOperationsNamed(field string, i int, capability CapabilityDefinition) []string {
	var errors []string
	if capability.Level != "declared" && len(capability.Operations) == 0 {
		errors = append(errors, fmt.Sprintf("%s[%d].operations is required for standard and certified capabilities", field, i))
	}
	operationKeys := map[string]bool{}
	for j, operation := range capability.Operations {
		name := strings.TrimSpace(operation.Name)
		if name == "" || !keyPattern.MatchString(name) {
			errors = append(errors, fmt.Sprintf("%s[%d].operations[%d].name is required and must be a valid operation key", field, i, j))
		}
		if operationKeys[name] {
			errors = append(errors, fmt.Sprintf("%s[%d].operations contains duplicate operation %q", field, i, name))
		}
		operationKeys[name] = true
		errors = append(errors, renameCapabilityErrors(validateCapabilityInvocation(i, j, capability, operation.Invocation), field)...)
		errors = append(errors, renameCapabilityErrors(validateCapabilityDelegation(i, j, operation.Delegation), field)...)
		if operation.CallGraph.MaxDepth < 0 {
			errors = append(errors, fmt.Sprintf("%s[%d].operations[%d].call_graph.max_depth must be non-negative", field, i, j))
		}
		for k, caller := range operation.CallGraph.AllowedCallers {
			if !capabilityIDPattern.MatchString(strings.TrimSpace(caller)) {
				errors = append(errors, fmt.Sprintf("%s[%d].operations[%d].call_graph.allowed_callers[%d] must be a capability id", field, i, j, k))
			}
		}
	}
	return errors
}

func renameCapabilityErrors(errors []string, field string) []string {
	if field == "capabilities" {
		return errors
	}
	out := make([]string, len(errors))
	for i, err := range errors {
		out[i] = strings.ReplaceAll(err, "capabilities[", field+"[")
	}
	return out
}

func validateCapabilityInvocation(i, j int, capability CapabilityDefinition, invocation CapabilityInvocationDefinition) []string {
	var errors []string
	mode := strings.TrimSpace(invocation.Mode)
	if !validInvocationMode(mode) {
		errors = append(errors, fmt.Sprintf("capabilities[%d].operations[%d].invocation.mode must be event, ephemeral_signed_grant, revocable_mediated_grant, brokered_action_gateway, or query", i, j))
	}
	if invocation.GrantTTLMS < 0 {
		errors = append(errors, fmt.Sprintf("capabilities[%d].operations[%d].invocation.grant_ttl_ms must be non-negative", i, j))
	}
	if invocation.TimeoutMS < 0 {
		errors = append(errors, fmt.Sprintf("capabilities[%d].operations[%d].invocation.timeout_ms must be non-negative", i, j))
	}
	if !validRequiredOptional(invocation.Introspection) {
		errors = append(errors, fmt.Sprintf("capabilities[%d].operations[%d].invocation.introspection must be optional or required", i, j))
	}
	if !validRequiredOptional(invocation.OutcomeReceipt) {
		errors = append(errors, fmt.Sprintf("capabilities[%d].operations[%d].invocation.outcome_receipt must be optional or required", i, j))
	}
	if !validRequiredOptional(invocation.Idempotency) {
		errors = append(errors, fmt.Sprintf("capabilities[%d].operations[%d].invocation.idempotency must be optional or required", i, j))
	}
	if !validRequiredOptional(invocation.ResultUnknownReconciliation) {
		errors = append(errors, fmt.Sprintf("capabilities[%d].operations[%d].invocation.result_unknown_reconciliation must be optional or required", i, j))
	}
	switch mode {
	case "ephemeral_signed_grant":
		if invocation.GrantTTLMS == 0 || invocation.GrantTTLMS > 30000 {
			errors = append(errors, fmt.Sprintf("capabilities[%d].operations[%d].invocation.grant_ttl_ms must be between 1 and 30000 for ephemeral_signed_grant", i, j))
		}
		if capability.Audit.Enforcement == "controlled_action" {
			errors = append(errors, fmt.Sprintf("capabilities[%d].operations[%d].invocation.mode ephemeral_signed_grant cannot be used with controlled_action", i, j))
		}
	case "revocable_mediated_grant":
		if invocation.GrantTTLMS == 0 || invocation.GrantTTLMS > 300000 {
			errors = append(errors, fmt.Sprintf("capabilities[%d].operations[%d].invocation.grant_ttl_ms must be between 1 and 300000 for revocable_mediated_grant", i, j))
		}
		if invocation.Introspection != "required" {
			errors = append(errors, fmt.Sprintf("capabilities[%d].operations[%d].invocation.introspection=required is mandatory for revocable_mediated_grant", i, j))
		}
		if invocation.OutcomeReceipt != "required" {
			errors = append(errors, fmt.Sprintf("capabilities[%d].operations[%d].invocation.outcome_receipt=required is mandatory for revocable_mediated_grant", i, j))
		}
		if invocation.Idempotency != "required" {
			errors = append(errors, fmt.Sprintf("capabilities[%d].operations[%d].invocation.idempotency=required is mandatory for revocable_mediated_grant", i, j))
		}
		if capability.Audit.Enforcement == "controlled_action" {
			errors = append(errors, fmt.Sprintf("capabilities[%d].operations[%d].invocation.mode revocable_mediated_grant cannot be used with controlled_action", i, j))
		}
	case "brokered_action_gateway":
		if invocation.Idempotency != "required" {
			errors = append(errors, fmt.Sprintf("capabilities[%d].operations[%d].invocation.idempotency=required is mandatory for brokered_action_gateway", i, j))
		}
		if invocation.ResultUnknownReconciliation != "required" {
			errors = append(errors, fmt.Sprintf("capabilities[%d].operations[%d].invocation.result_unknown_reconciliation=required is mandatory for brokered_action_gateway", i, j))
		}
		if capability.Audit.Enforcement != "controlled_action" {
			errors = append(errors, fmt.Sprintf("capabilities[%d].operations[%d].invocation.mode brokered_action_gateway requires controlled_action audit enforcement", i, j))
		}
	case "event":
		if invocation.OutcomeReceipt != "" && invocation.OutcomeReceipt != "optional" {
			errors = append(errors, fmt.Sprintf("capabilities[%d].operations[%d].invocation.outcome_receipt must be optional for event mode", i, j))
		}
	}
	return errors
}

func validateCapabilityDelegation(i, j int, delegation CapabilityDelegationDefinition) []string {
	if validDelegationMode(delegation.Mode) {
		return nil
	}
	return []string{fmt.Sprintf("capabilities[%d].operations[%d].delegation.mode must be preserve_principal, plugin_service, or system", i, j)}
}

func validateProviderRuntime(runtime ProviderRuntimeDefinition, instanceSettingKeys map[string]bool) []string {
	var errors []string
	runtimeDeclared := strings.TrimSpace(runtime.Type) != "" ||
		strings.TrimSpace(runtime.Protocol) != "" ||
		strings.TrimSpace(runtime.Version) != "" ||
		strings.TrimSpace(runtime.EndpointSettingKey) != "" ||
		runtime.SchemaCompatibility != nil
	if !runtimeDeclared {
		return errors
	}
	if !validRuntimeType(runtime.Type) {
		errors = append(errors, "runtime.type must be builtin, external, or managed")
	}
	if !validRuntimeProtocol(runtime.Protocol) {
		errors = append(errors, "runtime.protocol must be internal, http_json, connect, or grpc")
	}
	if strings.TrimSpace(runtime.Version) != "" && !semverLikePattern.MatchString(runtime.Version) {
		errors = append(errors, "runtime.version must be semantic version-like")
	}
	if strings.TrimSpace(runtime.EndpointSettingKey) != "" {
		if !settingKeyPattern.MatchString(runtime.EndpointSettingKey) {
			errors = append(errors, "runtime.endpoint_setting_key is invalid")
		}
		if !instanceSettingKeys[runtime.EndpointSettingKey] {
			errors = append(errors, "runtime.endpoint_setting_key references unknown instance setting")
		}
	}
	if runtime.SchemaCompatibility != nil {
		compat := runtime.SchemaCompatibility
		if compat.Min <= 0 || compat.Max <= 0 || compat.Preferred <= 0 || compat.Min > compat.Max || compat.Preferred < compat.Min || compat.Preferred > compat.Max {
			errors = append(errors, "runtime.schema_compatibility must satisfy 0 < min <= preferred <= max")
		}
	}
	return errors
}

func validateRouteAuthorization(i int, route RouteDefinition, resourceKeys map[string]bool, resourceActions map[string]map[string]bool) []string {
	var errors []string
	mode := strings.TrimSpace(route.Authorization.Mode)
	if mode == "" {
		return errors
	}
	switch mode {
	case "none":
		if strings.TrimSpace(route.ResourceType) != "" || strings.TrimSpace(route.Action) != "" {
			errors = append(errors, fmt.Sprintf("routes[%d].authorization.mode none cannot be combined with resource_type or action", i))
		}
		if route.Authorization.ResourceParam != "" || route.Authorization.ResourceKeyStrategy != "" || route.Authorization.Action != "" || len(route.Authorization.AllowedResources) > 0 || len(route.Authorization.ExcludedResources) > 0 {
			errors = append(errors, fmt.Sprintf("routes[%d].authorization.mode none must not declare dynamic authorization fields", i))
		}
	case "static":
		if strings.TrimSpace(route.ResourceType) == "" || strings.TrimSpace(route.Action) == "" {
			errors = append(errors, fmt.Sprintf("routes[%d].authorization.mode static requires route resource_type and action", i))
		}
		if route.Authorization.ResourceParam != "" || route.Authorization.ResourceKeyStrategy != "" || route.Authorization.Action != "" || len(route.Authorization.AllowedResources) > 0 || len(route.Authorization.ExcludedResources) > 0 {
			errors = append(errors, fmt.Sprintf("routes[%d].authorization.mode static must not declare dynamic authorization fields", i))
		}
	case "dynamic_resource":
		errors = append(errors, validateDynamicRouteAuthorization(i, route, resourceKeys, resourceActions)...)
	default:
		errors = append(errors, fmt.Sprintf("routes[%d].authorization.mode must be one of none, static, or dynamic_resource", i))
	}
	return errors
}

func validateDynamicRouteAuthorization(i int, route RouteDefinition, resourceKeys map[string]bool, resourceActions map[string]map[string]bool) []string {
	var errors []string
	if strings.TrimSpace(route.ResourceType) != "" || strings.TrimSpace(route.Action) != "" {
		errors = append(errors, fmt.Sprintf("routes[%d].authorization.mode dynamic_resource cannot be combined with route resource_type or action", i))
	}
	resourceParam := strings.TrimSpace(route.Authorization.ResourceParam)
	if resourceParam == "" || !keyPattern.MatchString(resourceParam) {
		errors = append(errors, fmt.Sprintf("routes[%d].authorization.resource_param is required and must be a valid path parameter name", i))
	} else if !routePathHasParam(route.Path, resourceParam) {
		errors = append(errors, fmt.Sprintf("routes[%d].authorization.resource_param must reference a parameter in route path", i))
	}
	strategy := strings.TrimSpace(route.Authorization.ResourceKeyStrategy)
	if strategy == "" {
		errors = append(errors, fmt.Sprintf("routes[%d].authorization.resource_key_strategy is required", i))
	} else if strategy != "declared_resource_key" && strategy != "plugin_defined_alias" {
		errors = append(errors, fmt.Sprintf("routes[%d].authorization.resource_key_strategy must be declared_resource_key or plugin_defined_alias", i))
	}
	action := strings.TrimSpace(route.Authorization.Action)
	if action == "" || !keyPattern.MatchString(action) {
		errors = append(errors, fmt.Sprintf("routes[%d].authorization.action is required and must be a valid action key", i))
	}
	if len(route.Authorization.AllowedResources) > 0 && len(route.Authorization.ExcludedResources) > 0 {
		errors = append(errors, fmt.Sprintf("routes[%d].authorization cannot declare both allowed_resources and excluded_resources", i))
	}
	targetResources := map[string]bool{}
	if len(route.Authorization.AllowedResources) > 0 {
		for _, resource := range route.Authorization.AllowedResources {
			resource = strings.TrimSpace(resource)
			if !resourceKeys[resource] {
				errors = append(errors, fmt.Sprintf("routes[%d].authorization.allowed_resources references unknown resource %q", i, resource))
				continue
			}
			targetResources[resource] = true
		}
	} else {
		excluded := map[string]bool{}
		for _, resource := range route.Authorization.ExcludedResources {
			resource = strings.TrimSpace(resource)
			if !resourceKeys[resource] {
				errors = append(errors, fmt.Sprintf("routes[%d].authorization.excluded_resources references unknown resource %q", i, resource))
				continue
			}
			excluded[resource] = true
		}
		for resource := range resourceKeys {
			if !excluded[resource] {
				targetResources[resource] = true
			}
		}
	}
	if len(targetResources) == 0 {
		errors = append(errors, fmt.Sprintf("routes[%d].authorization must cover at least one resource", i))
	}
	if action != "" {
		for resource := range targetResources {
			if !resourceActions[resource][action] {
				errors = append(errors, fmt.Sprintf("routes[%d].authorization action %q is not declared for resource %q", i, action, resource))
			}
		}
	}
	return errors
}

func routePathHasParam(path, param string) bool {
	return strings.Contains(path, "{"+param+"}")
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func validPluginStatus(status string) bool {
	switch strings.TrimSpace(status) {
	case "discovered", "validated", "installed", "migrated", "enabled", "disabled", "upgrading", "failed", "uninstalled":
		return true
	default:
		return false
	}
}

func validManifestType(manifestType string) bool {
	switch strings.TrimSpace(manifestType) {
	case "plugin", "app_module":
		return true
	default:
		return false
	}
}

func validManifestScope(scope string) bool {
	switch strings.TrimSpace(scope) {
	case "public", "private", "app":
		return true
	default:
		return false
	}
}

func validAdminMenuPath(manifestType, path string) bool {
	path = strings.TrimSpace(path)
	if manifestType == "app_module" {
		return strings.HasPrefix(path, "/apps/")
	}
	return strings.HasPrefix(path, "/plugins/")
}

func validRiskLevel(level string) bool {
	switch strings.TrimSpace(level) {
	case "low", "normal", "high", "critical":
		return true
	default:
		return false
	}
}

func validSettingType(valueType string) bool {
	switch strings.TrimSpace(valueType) {
	case "string", "integer", "number", "boolean", "string_array", "array", "object", "json":
		return true
	default:
		return false
	}
}

func sensitiveSettingKey(key string) bool {
	normalized := strings.ToLower(strings.TrimSpace(key))
	for _, marker := range []string{"secret", "password", "token", "credential", "api_key", "private_key"} {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}

func ValidateManifestForCore(manifest Manifest, coreVersion string) []string {
	errors := ValidateManifest(manifest)
	if manifest.ManifestVersion != "" && manifest.ManifestVersion != "1.0" {
		errors = append(errors, "manifest_version must be 1.0 for Plystra v1.0")
	}
	if manifest.PluginAPIVersion != "" && manifest.PluginAPIVersion != "1.0" {
		errors = append(errors, "plugin_api_version must be 1.0 for Plystra v1.0")
	}
	if strings.TrimSpace(manifest.RequiresCore) != "" && !VersionSatisfies(coreVersion, manifest.RequiresCore) {
		errors = append(errors, fmt.Sprintf("requires_core %q is not satisfied by Plystra %q", manifest.RequiresCore, coreVersion))
	}
	return errors
}

func validScope(scope string) bool {
	switch scope {
	case "self", "group", "group_tree", "space", "global":
		return true
	default:
		return false
	}
}

func validCapabilityLevel(level string) bool {
	switch level {
	case "declared", "standard", "certified":
		return true
	default:
		return false
	}
}

func validAuditEnforcement(enforcement string) bool {
	switch strings.TrimSpace(enforcement) {
	case "grant_only", "reported_event", "observed_mutation", "controlled_action":
		return true
	default:
		return false
	}
}

func validDataPlane(plane string) bool {
	switch strings.TrimSpace(plane) {
	case "direct_db", "direct_db_with_mutation_journal", "action_gateway", "core_data_api":
		return true
	default:
		return false
	}
}

func validInvocationMode(mode string) bool {
	switch strings.TrimSpace(mode) {
	case "event", "ephemeral_signed_grant", "revocable_mediated_grant", "brokered_action_gateway", "query":
		return true
	default:
		return false
	}
}

func validDelegationMode(mode string) bool {
	switch strings.TrimSpace(mode) {
	case "preserve_principal", "plugin_service", "system":
		return true
	default:
		return false
	}
}

func validRequiredOptional(value string) bool {
	switch strings.TrimSpace(value) {
	case "", "optional", "required":
		return true
	default:
		return false
	}
}

func auditEnforcementAllowsDataPlane(enforcement, plane string) bool {
	switch strings.TrimSpace(enforcement) {
	case "grant_only":
		return plane == "direct_db"
	case "reported_event":
		return plane == "direct_db" || plane == "core_data_api"
	case "observed_mutation":
		return plane == "direct_db_with_mutation_journal" || plane == "action_gateway"
	case "controlled_action":
		return plane == "action_gateway" || plane == "core_data_api"
	default:
		return false
	}
}

func validRuntimeType(runtimeType string) bool {
	switch strings.TrimSpace(runtimeType) {
	case "builtin", "external", "managed":
		return true
	default:
		return false
	}
}

func validRuntimeProtocol(protocol string) bool {
	switch strings.TrimSpace(protocol) {
	case "internal", "http_json", "connect", "grpc":
		return true
	default:
		return false
	}
}

func validHTTPMethod(method string) bool {
	switch method {
	case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE":
		return true
	default:
		return false
	}
}

func validPluginPath(path string) bool {
	path = strings.TrimSpace(path)
	return strings.HasPrefix(path, "/") && !strings.ContainsAny(path, "?#\r\n")
}

func VersionSatisfies(version, constraint string) bool {
	v, ok := parseVersion(version)
	if !ok {
		return false
	}
	for _, part := range strings.Fields(constraint) {
		if part == "" {
			continue
		}
		switch {
		case strings.HasPrefix(part, ">="):
			if compareVersion(v, mustParseConstraint(part[2:])) < 0 {
				return false
			}
		case strings.HasPrefix(part, "<="):
			if compareVersion(v, mustParseConstraint(part[2:])) > 0 {
				return false
			}
		case strings.HasPrefix(part, ">"):
			if compareVersion(v, mustParseConstraint(part[1:])) <= 0 {
				return false
			}
		case strings.HasPrefix(part, "<"):
			if compareVersion(v, mustParseConstraint(part[1:])) >= 0 {
				return false
			}
		case strings.HasPrefix(part, "="):
			if compareVersion(v, mustParseConstraint(part[1:])) != 0 {
				return false
			}
		default:
			if compareVersion(v, mustParseConstraint(part)) != 0 {
				return false
			}
		}
	}
	return true
}

type versionTriple struct {
	major int
	minor int
	patch int
}

func mustParseConstraint(raw string) versionTriple {
	v, ok := parseVersion(raw)
	if !ok {
		return versionTriple{major: 1<<31 - 1}
	}
	return v
}

func parseVersion(raw string) (versionTriple, bool) {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimPrefix(raw, "v")
	if raw == "" {
		return versionTriple{}, false
	}
	raw = strings.SplitN(raw, "-", 2)[0]
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return versionTriple{}, false
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return versionTriple{}, false
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return versionTriple{}, false
	}
	patch, err := strconv.Atoi(parts[2])
	if err != nil {
		return versionTriple{}, false
	}
	return versionTriple{major: major, minor: minor, patch: patch}, true
}

func compareVersion(left, right versionTriple) int {
	if left.major != right.major {
		return left.major - right.major
	}
	if left.minor != right.minor {
		return left.minor - right.minor
	}
	return left.patch - right.patch
}

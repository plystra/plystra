package plugins

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

type Manifest struct {
	ID               string                  `json:"id"`
	Name             string                  `json:"name"`
	Description      string                  `json:"description"`
	Version          string                  `json:"version"`
	Source           string                  `json:"source"`
	Status           string                  `json:"status"`
	ManifestVersion  string                  `json:"manifest_version"`
	PluginAPIVersion string                  `json:"plugin_api_version"`
	RequiresCore     string                  `json:"requires_core"`
	Resources        []ResourceDefinition    `json:"resources"`
	Permissions      []PermissionDefinition  `json:"permissions"`
	AuditEvents      []AuditEventDefinition  `json:"audit_events"`
	AdminMenus       []AdminMenuDefinition   `json:"admin_menu"`
	Settings         []SettingDefinition     `json:"settings"`
	Capabilities     []CapabilityDefinition  `json:"capabilities"`
	Requires         []CapabilityRequirement `json:"requires_capabilities"`
	Routes           []RouteDefinition       `json:"routes"`
	Events           EventDefinitions        `json:"events"`
	Jobs             []JobDefinition         `json:"jobs"`
	HealthChecks     []HealthCheckDefinition `json:"health_checks"`
	Secrets          []SecretDefinition      `json:"secrets"`
	ExternalNetwork  []NetworkDefinition     `json:"external_network"`
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
	Description string `json:"description"`
}

type CapabilityDefinition struct {
	ID          string `json:"id"`
	Version     string `json:"version"`
	Level       string `json:"level"`
	Description string `json:"description"`
}

type CapabilityRequirement struct {
	ID       string `json:"id"`
	Version  string `json:"version"`
	MinLevel string `json:"min_level"`
	Optional bool   `json:"optional"`
}

type RouteDefinition struct {
	Method       string `json:"method"`
	Path         string `json:"path"`
	ResourceType string `json:"resource_type"`
	Action       string `json:"action"`
	Handler      string `json:"handler"`
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

var pluginIDPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)
var semverLikePattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9_.-]+)?$`)
var keyPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
var capabilityIDPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)
var eventKeyPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)
var secretKeyPattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

func ValidateManifest(manifest Manifest) []string {
	var errors []string
	if !pluginIDPattern.MatchString(manifest.ID) {
		errors = append(errors, "id must use reverse-DNS style such as plystra.moderation")
	}
	if strings.TrimSpace(manifest.Name) == "" {
		errors = append(errors, "name is required")
	}
	if !semverLikePattern.MatchString(manifest.Version) {
		errors = append(errors, "version must be semantic version-like")
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
		if resourceKeys[resource.Key] {
			errors = append(errors, fmt.Sprintf("duplicate resource key %q", resource.Key))
		}
		resourceKeys[resource.Key] = true
		resourceActions[resource.Key] = map[string]bool{}
		actionKeys := map[string]bool{}
		for j, action := range resource.Actions {
			if !keyPattern.MatchString(action.Key) {
				errors = append(errors, fmt.Sprintf("resources[%d].actions[%d].key is invalid", i, j))
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
		if auditKeys[event.Key] {
			errors = append(errors, fmt.Sprintf("duplicate audit event key %q", event.Key))
		}
		auditKeys[event.Key] = true
	}

	for i, menu := range manifest.AdminMenus {
		if strings.TrimSpace(menu.Label) == "" {
			errors = append(errors, fmt.Sprintf("admin_menu[%d].label is required", i))
		}
		if !strings.HasPrefix(menu.Path, "/plugins/") {
			errors = append(errors, fmt.Sprintf("admin_menu[%d].path must start with /plugins/", i))
		}
	}

	for i, route := range manifest.Routes {
		method := strings.ToUpper(strings.TrimSpace(route.Method))
		if !validHTTPMethod(method) {
			errors = append(errors, fmt.Sprintf("routes[%d].method must be GET, POST, PUT, PATCH, or DELETE", i))
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
	for i, capability := range manifest.Capabilities {
		if !capabilityIDPattern.MatchString(capability.ID) {
			errors = append(errors, fmt.Sprintf("capabilities[%d].id is invalid", i))
		}
		if capabilityKeys[capability.ID] {
			errors = append(errors, fmt.Sprintf("duplicate capability %q", capability.ID))
		}
		capabilityKeys[capability.ID] = true
		if capability.Version == "" || !semverLikePattern.MatchString(capability.Version) {
			errors = append(errors, fmt.Sprintf("capabilities[%d].version must be semantic version-like", i))
		}
		if !validCapabilityLevel(capability.Level) {
			errors = append(errors, fmt.Sprintf("capabilities[%d].level must be one of declared, standard, or certified", i))
		}
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

	return errors
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

func validHTTPMethod(method string) bool {
	switch method {
	case "GET", "POST", "PUT", "PATCH", "DELETE":
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

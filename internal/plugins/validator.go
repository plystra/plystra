package plugins

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/plystra/plystra/internal/authz"
)

var pluginIDPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)
var semverLikePattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9_.-]+)?$`)
var keyPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

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
			if scope == string(authz.ScopeGlobal) {
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

	return errors
}

func validScope(scope string) bool {
	switch authz.Scope(scope) {
	case authz.ScopeSelf, authz.ScopeGroup, authz.ScopeGroupTree, authz.ScopeSpace, authz.ScopeGlobal:
		return true
	default:
		return false
	}
}

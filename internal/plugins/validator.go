package plugins

import (
	"fmt"
	"regexp"
	"strconv"
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

func ValidateManifestForCore(manifest Manifest, coreVersion string) []string {
	errors := ValidateManifest(manifest)
	if manifest.ManifestVersion != "" && manifest.ManifestVersion != "1.0" {
		errors = append(errors, "manifest_version must be 1.0 for Core v1.0")
	}
	if manifest.PluginAPIVersion != "" && manifest.PluginAPIVersion != "1.0" {
		errors = append(errors, "plugin_api_version must be 1.0 for Core v1.0")
	}
	if strings.TrimSpace(manifest.RequiresCore) != "" && !VersionSatisfies(coreVersion, manifest.RequiresCore) {
		errors = append(errors, fmt.Sprintf("requires_core %q is not satisfied by Core %q", manifest.RequiresCore, coreVersion))
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

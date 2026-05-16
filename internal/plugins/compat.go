package plugins

import kernelplugins "github.com/plystra/kernel/plugins"

type (
	Manifest             = kernelplugins.Manifest
	ResourceDefinition   = kernelplugins.ResourceDefinition
	ActionDefinition     = kernelplugins.ActionDefinition
	PermissionDefinition = kernelplugins.PermissionDefinition
	AuditEventDefinition = kernelplugins.AuditEventDefinition
	AdminMenuDefinition  = kernelplugins.AdminMenuDefinition
	SettingDefinition    = kernelplugins.SettingDefinition
)

func ValidateManifest(manifest Manifest) []string {
	return kernelplugins.ValidateManifest(manifest)
}

func ValidateManifestForCore(manifest Manifest, coreVersion string) []string {
	return kernelplugins.ValidateManifestForCore(manifest, coreVersion)
}

func VersionSatisfies(version, constraint string) bool {
	return kernelplugins.VersionSatisfies(version, constraint)
}

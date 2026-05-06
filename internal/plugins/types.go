package plugins

type Manifest struct {
	ID               string                 `json:"id"`
	Name             string                 `json:"name"`
	Description      string                 `json:"description"`
	Version          string                 `json:"version"`
	Source           string                 `json:"source"`
	Status           string                 `json:"status"`
	ManifestVersion  string                 `json:"manifest_version"`
	PluginAPIVersion string                 `json:"plugin_api_version"`
	RequiresCore     string                 `json:"requires_core"`
	Resources        []ResourceDefinition   `json:"resources"`
	Permissions      []PermissionDefinition `json:"permissions"`
	AuditEvents      []AuditEventDefinition `json:"audit_events"`
	AdminMenus       []AdminMenuDefinition  `json:"admin_menu"`
	Settings         []SettingDefinition    `json:"settings"`
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

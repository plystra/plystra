package templates

import (
	"encoding/json"
)

type Manifest struct {
	ID                   string                  `json:"id"`
	Name                 string                  `json:"name"`
	Description          string                  `json:"description"`
	Version              string                  `json:"version"`
	RequiresCore         string                  `json:"requires_core"`
	RequiredPlugins      []string                `json:"required_plugins"`
	RequiredCapabilities []CapabilityRequirement `json:"required_capabilities"`
	DeploymentProfile    DeploymentProfile       `json:"deployment_profile"`
	Limitations          []string                `json:"limitations"`
	Spaces               []Space                 `json:"spaces"`
	Groups               []Group                 `json:"groups"`
	Roles                []Role                  `json:"roles"`
	Permissions          []Permission            `json:"permissions"`
}

type CapabilityRequirement struct {
	ID       string `json:"id"`
	MinLevel string `json:"min_level,omitempty"`
	Version  string `json:"version,omitempty"`
	Optional bool   `json:"optional,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

type Space struct {
	Key  string `json:"key"`
	Name string `json:"name"`
}

type Group struct {
	Key  string `json:"key"`
	Name string `json:"name"`
}

type Role struct {
	Key string `json:"key"`
}

type Permission struct {
	Role     string `json:"role"`
	Resource string `json:"resource"`
	Action   string `json:"action"`
	Scope    string `json:"scope"`
}

type DeploymentProfile struct {
	ID                       string   `json:"id"`
	Runtime                  string   `json:"runtime"`
	Database                 string   `json:"database"`
	Configuration            []string `json:"configuration"`
	HealthChecks             []string `json:"health_checks"`
	StructuredLogs           bool     `json:"structured_logs"`
	Backup                   []string `json:"backup"`
	Restore                  []string `json:"restore"`
	OneCommandStart          []string `json:"one_command_start"`
	RequiresExternalPostgres bool     `json:"requires_external_postgres"`
}

func alphaDeploymentProfile() DeploymentProfile {
	return DeploymentProfile{
		ID:       "backend-os-alpha-compose",
		Runtime:  "single Plystra Core container plus official plugin sidecars when selected",
		Database: "external PostgreSQL 16+ for production alpha",
		Configuration: []string{
			"environment variables for process bootstrap and secrets",
			"database-backed plugin settings for non-sensitive mutable plugin configuration",
			"versioned migrations before startup",
		},
		HealthChecks: []string{
			"GET /api/v1/health",
			"GET /api/v1/ready",
			"capability provider /health endpoints when provider containers are enabled",
		},
		StructuredLogs: true,
		Backup: []string{
			"pg_dump custom-format PostgreSQL dump",
			"backup manifest from plystractl backup manifest",
			"runtime environment and secret-manager export",
			"governed provider schemas in the same database",
		},
		Restore: []string{
			"restore PostgreSQL dump into an empty database",
			"restore runtime environment and secrets",
			"run plystractl migrate verify",
			"run plystractl doctor",
		},
		OneCommandStart: []string{
			"docker compose --env-file .env up -d",
		},
		RequiresExternalPostgres: true,
	}
}

func Catalog() []Manifest {
	alphaProfile := alphaDeploymentProfile()
	return []Manifest{
		{
			ID:                "blank",
			Name:              "Blank",
			Description:       "Minimal production-alpha Plystra Core baseline with no optional plugin requirements.",
			Version:           "0.0.1",
			RequiresCore:      ">=0.0.1 <0.1.0",
			DeploymentProfile: alphaProfile,
			Limitations: []string{
				"does not install a frontend application",
				"requires an operator-created first instance super admin",
			},
		},
		{
			ID:                   "internal-admin",
			Name:                 "Internal Admin",
			Description:          "Internal operations backend template with API key governance and webhook metadata requirements.",
			Version:              "0.0.1",
			RequiresCore:         ">=0.0.1 <0.1.0",
			RequiredCapabilities: []CapabilityRequirement{{ID: "api_key.credential", MinLevel: "standard", Version: ">=0.0.1 <0.1.0"}, {ID: "webhook.delivery", MinLevel: "standard", Version: ">=0.0.1 <0.1.0"}},
			DeploymentProfile:    alphaProfile,
			Limitations: []string{
				"provider runtime is limited to official metadata and sidecar lifecycle in alpha",
				"generated defaults must be reviewed before production use",
			},
			Spaces: []Space{{Key: "default", Name: "Default Workspace"}},
			Groups: []Group{
				{Key: "operations", Name: "Operations"},
				{Key: "finance", Name: "Finance"},
			},
			Roles: []Role{{Key: "space_owner"}, {Key: "auditor"}, {Key: "operator"}},
			Permissions: []Permission{
				{Role: "space_owner", Resource: "api_key", Action: "read", Scope: "space"},
				{Role: "space_owner", Resource: "webhook_endpoint", Action: "read", Scope: "space"},
			},
		},
		{
			ID:           "community-lite",
			Name:         "Community Lite",
			Description:  "Small community backend template with moderation-oriented groups, roles, and permissions.",
			Version:      "0.0.1",
			RequiresCore: ">=0.0.1 <0.1.0",
			RequiredCapabilities: []CapabilityRequirement{
				{ID: "moderation.report", MinLevel: "standard", Version: ">=0.0.1 <0.1.0"},
			},
			DeploymentProfile: alphaProfile,
			Limitations: []string{
				"moderation capability provider must be installed and operated separately",
				"does not include a hosted frontend or marketplace workflow",
			},
			Spaces: []Space{{Key: "community", Name: "Community"}},
			Groups: []Group{
				{Key: "general", Name: "General"},
				{Key: "moderation", Name: "Moderation"},
			},
			Roles: []Role{{Key: "moderator"}, {Key: "member"}},
			Permissions: []Permission{
				{Role: "moderator", Resource: "report", Action: "resolve", Scope: "group_tree"},
			},
		},
		{
			ID:                   "auth-ready-saas",
			Name:                 "Auth Ready SaaS",
			Description:          "Small SaaS backend template that pairs Plystra Core with auth identity and transactional email capabilities.",
			Version:              "0.0.1",
			RequiresCore:         ">=0.0.1 <0.1.0",
			RequiredCapabilities: []CapabilityRequirement{{ID: "auth.identity", MinLevel: "standard", Version: ">=0.0.1 <0.1.0"}, {ID: "email.transactional", MinLevel: "standard", Version: ">=0.0.1 <0.1.0"}},
			DeploymentProfile:    alphaProfile,
			Limitations: []string{
				"production email delivery requires an independent email capability provider",
				"public registration remains disabled until enabled through auth provider database settings",
				"cloud hosting and marketplace behavior are outside Backend OS Alpha",
			},
			Spaces: []Space{{Key: "default", Name: "Default SaaS Workspace"}},
			Groups: []Group{
				{Key: "admins", Name: "Admins"},
				{Key: "members", Name: "Members"},
			},
			Roles: []Role{{Key: "owner"}, {Key: "support"}, {Key: "member"}},
			Permissions: []Permission{
				{Role: "owner", Resource: "auth_challenge", Action: "read", Scope: "space"},
				{Role: "support", Resource: "auth_challenge", Action: "read", Scope: "space"},
			},
		},
		{
			ID:                   "saas-crm-alpha",
			Name:                 "SaaS CRM Alpha",
			Description:          "Backend OS Alpha reference application with plugin-owned CRM business data, Plystra-governed identity, authorization, resource bindings, audit, backup, and health checks.",
			Version:              "0.0.1",
			RequiresCore:         ">=0.0.1 <0.1.0",
			RequiredCapabilities: []CapabilityRequirement{{ID: "crm.customer", MinLevel: "standard", Version: ">=0.0.1 <0.1.0"}, {ID: "crm.pipeline", MinLevel: "standard", Version: ">=0.0.1 <0.1.0"}, {ID: "project.task", MinLevel: "standard", Version: ">=0.0.1 <0.1.0"}},
			DeploymentProfile:    alphaProfile,
			Limitations: []string{
				"CRM business data is stored only in governed CRM provider PostgreSQL schemas",
				"Core resources are Resource Bindings for authorization context and inspection, not a business data store",
				"provider sidecar lifecycle is Docker Compose based in Backend OS Alpha",
			},
			Spaces: []Space{{Key: "default", Name: "Plystra Demo SaaS"}},
			Groups: []Group{
				{Key: "sales", Name: "Sales"},
				{Key: "success", Name: "Customer Success"},
				{Key: "ops", Name: "Operations"},
			},
			Roles: []Role{{Key: "owner"}, {Key: "operator"}, {Key: "auditor"}},
			Permissions: []Permission{
				{Role: "operator", Resource: "crm_account", Action: "read", Scope: "space"},
				{Role: "operator", Resource: "crm_account", Action: "create", Scope: "space"},
				{Role: "operator", Resource: "crm_account", Action: "update", Scope: "space"},
				{Role: "operator", Resource: "crm_deal", Action: "read", Scope: "space"},
				{Role: "operator", Resource: "crm_deal", Action: "create", Scope: "space"},
				{Role: "operator", Resource: "crm_deal", Action: "update", Scope: "space"},
				{Role: "operator", Resource: "crm_task", Action: "read", Scope: "space"},
				{Role: "operator", Resource: "crm_task", Action: "create", Scope: "space"},
				{Role: "operator", Resource: "crm_task", Action: "update", Scope: "space"},
				{Role: "operator", Resource: "crm_task", Action: "complete", Scope: "space"},
				{Role: "auditor", Resource: "audit_log", Action: "read", Scope: "space"},
			},
		},
	}
}

func ByID(id string) (Manifest, bool) {
	for _, tpl := range Catalog() {
		if tpl.ID == id {
			return tpl, true
		}
	}
	return Manifest{}, false
}

func Preview(tpl Manifest, missingPlugins []string, missingCapabilities []CapabilityRequirement, capabilityProviders map[string]string) map[string]any {
	return map[string]any{
		"template_id":          tpl.ID,
		"missing_plugins":      missingPlugins,
		"missing_capabilities": missingCapabilities,
		"capability_providers": capabilityProviders,
		"install_explanation":  InstallExplanation(tpl, missingPlugins, missingCapabilities, capabilityProviders),
		"changes": map[string]any{
			"spaces":       tpl.Spaces,
			"groups":       tpl.Groups,
			"roles":        tpl.Roles,
			"permissions":  tpl.Permissions,
			"capabilities": tpl.RequiredCapabilities,
		},
	}
}

func InstallExplanation(tpl Manifest, missingPlugins []string, missingCapabilities []CapabilityRequirement, capabilityProviders map[string]string) []string {
	steps := []string{
		"Create an inspectable application directory from the template manifest.",
		"Review generated README, deployment profile, environment example, and install explanation before starting services.",
		"Configure strong secrets, public URL, CORS origins, and external PostgreSQL connection string.",
		"Apply and verify versioned migrations before exposing protected APIs.",
		"Bootstrap the first instance super admin explicitly; migrations never create one automatically.",
	}
	if len(tpl.RequiredCapabilities) > 0 {
		steps = append(steps, "Resolve required capability providers through Core provider bindings and keep provider secrets outside generated files.")
	}
	if len(missingPlugins) > 0 || len(missingCapabilities) > 0 {
		steps = append(steps, "Resolve missing plugins or capabilities before treating the template as production-ready.")
	}
	if len(capabilityProviders) > 0 {
		steps = append(steps, "Capability providers are recorded in the generated manifest for operator review.")
	}
	return steps
}

func ManifestMap(tpl Manifest) (map[string]any, error) {
	raw, err := json.Marshal(tpl)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

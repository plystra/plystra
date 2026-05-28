package templates

import (
	"encoding/json"
)

type Manifest struct {
	ID                   string                  `json:"id"`
	Name                 string                  `json:"name"`
	Version              string                  `json:"version"`
	RequiresCore         string                  `json:"requires_core"`
	RequiredPlugins      []string                `json:"required_plugins"`
	RequiredCapabilities []CapabilityRequirement `json:"required_capabilities"`
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

func Catalog() []Manifest {
	return []Manifest{
		{
			ID:           "blank",
			Name:         "Blank",
			Version:      "1.0.0",
			RequiresCore: ">=1.0.0 <2.0.0",
		},
		{
			ID:                   "internal-admin",
			Name:                 "Internal Admin",
			Version:              "1.0.0",
			RequiresCore:         ">=1.0.0 <2.0.0",
			RequiredPlugins:      []string{"plystra.api_keys", "plystra.webhooks"},
			RequiredCapabilities: []CapabilityRequirement{{ID: "api_key.credential", MinLevel: "standard", Version: ">=1.0.0 <2.0.0"}},
			Spaces:               []Space{{Key: "default", Name: "Default Workspace"}},
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
			ID:              "community-lite",
			Name:            "Community Lite",
			Version:         "1.0.0",
			RequiresCore:    ">=1.0.0 <2.0.0",
			RequiredPlugins: []string{"plystra.moderation"},
			Spaces:          []Space{{Key: "community", Name: "Community"}},
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
			Version:              "1.0.0",
			RequiresCore:         ">=1.0.0 <2.0.0",
			RequiredPlugins:      []string{"plystra.auth_complete"},
			RequiredCapabilities: []CapabilityRequirement{{ID: "email.transactional", MinLevel: "standard", Version: ">=1.0.0 <2.0.0"}},
			Spaces:               []Space{{Key: "default", Name: "Default SaaS Workspace"}},
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
		"changes": map[string]any{
			"spaces":       tpl.Spaces,
			"groups":       tpl.Groups,
			"roles":        tpl.Roles,
			"permissions":  tpl.Permissions,
			"capabilities": tpl.RequiredCapabilities,
		},
	}
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
